/**
 * Fleet membership tools: discover / add / remove / set.
 *
 * All four change (or reveal) who the fleet can control, so they are
 * limited to stdio callers and admin gateway tokens, and every mutation goes
 * through the approval gate, the audit log and a hot reload.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  OnboardError,
  appendServerToConfig,
  defaultKeychainBackend,
  ensureFleetKeyPair,
  keychainAccount,
  knownHostFingerprints,
  listSshConfigAliases,
  onboardServer,
  removeServerFromConfig,
  resolveSshHost,
  setServerFields,
  allowedClasses,
  type AuditEvent,
  type FleetRegistry,
  type MatrixOverride,
  type ServerConfig,
  type ServerPatch,
} from "flotilla-core";
import { canChangeFleet, currentPrincipal } from "./principal.js";
import { CONFIRM_DESCRIPTION } from "./tool-schemas.js";

type TextResult = { isError?: true; content: { type: "text"; text: string }[] };
type GateOutcome = { kind: "approved" } | { kind: "refused"; reason: string };

export interface OnboardingToolDependencies {
  getRegistry(): FleetRegistry | undefined;
  /** [policy.matrix] narrowing, for describing what a role/tier change allows. */
  getMatrix(): MatrixOverride | undefined;
  /** Resolved path of the fleet config file. */
  configPath(): string;
  gate(
    extra: unknown,
    ask: { tool: string; action: string; commandClass: string; hosts: string[]; confirmFlag?: boolean },
  ): Promise<GateOutcome | { kind: string; reason?: string }>;
  audit(event: AuditEvent): void;
  reloadFleet(reason: string): { ok: boolean; message: string };
  /** The client can show Flotilla's one-time local password page (URL elicitation). */
  canAskPassword(): boolean;
  /** Open that page for `name`; resolves true once the password is in the OS keychain. */
  requestPassword(name: string): Promise<boolean>;
  notConfigured(): TextResult;
  errorResult(message: string): TextResult;
}

const NAME = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/);
const sshConfigFile = () => process.env.FLOTILLA_SSH_CONFIG || undefined;
const text = (lines: string[]): TextResult => ({ content: [{ type: "text", text: lines.join("\n") }] });

/** Rewrite the config file (0600), then hot-reload. */
function commitConfig(deps: OnboardingToolDependencies, path: string, next: string, reason: string): string {
  writeFileSync(path, next, "utf8");
  chmodSync(path, 0o600);
  const reload = deps.reloadFleet(reason);
  return reload.ok ? `Config hot-reloaded (${reload.message}).` : `Hot-reload failed (${reload.message}) — restart the MCP server.`;
}

/** What the assistant should tell the user next, per failure code. */
function nextStepHint(err: unknown, name: string, canAsk: boolean): string {
  if (!(err instanceof OnboardError)) return "";
  switch (err.code) {
    case "password-needed":
      return canAsk
        ? "\nNEXT: the user closed or did not finish the secure password page — call fleet-add again to reopen it. Never ask for the password in chat."
        : `\nNEXT: this server needs a password, and this MCP client cannot open Flotilla's secure password page. Ask the user to run \`flotilla add ${name} ...\` in a terminal (it prompts once), or \`flotilla keychain set ${name}\` and then retry fleet-add. Never ask for the password in chat.`;
    case "password-rejected":
      return "\nNEXT: the password (or user name) is wrong — retry fleet-add (the page opens again) or pass the right `user`.";
    case "unreachable":
      return "\nNEXT: check host/port/firewall with the user; servers only reachable through a bastion need `via`.";
    case "host-key-mismatch":
      return "\nNEXT: do NOT work around this. Tell the user the server's identity changed; they must verify the new key out of band and update known_hosts.";
    case "jump-host-missing":
      return `\nNEXT: add the jump host "${String(err.details["jump"])}" first with fleet-add, then retry.`;
    case "duplicate":
      return `\nNEXT: "${name}" is already in the fleet — use fleet-set to change it, or fleet-remove first.`;
    default:
      return "";
  }
}

/** "role: operator → admin; now ALSO allows: destructive, privileged" — escalations must be visible. */
function describePolicyChange(current: ServerConfig, patch: ServerPatch, matrix: MatrixOverride | undefined): string {
  const lines = [`change server "${current.name}":`];
  for (const [field, value] of Object.entries(patch)) {
    if (value === undefined) continue;
    const label = field === "group" ? "tier" : field;
    lines.push(`  ${label}: ${JSON.stringify(current[field as keyof ServerConfig] ?? null)} → ${JSON.stringify(value)}`);
  }
  const allows = (s: Pick<ServerConfig, "role" | "group" | "readOnly">) =>
    s.readOnly ? ["read-only"] : allowedClasses(s.role, s.group, matrix);
  const before = allows(current);
  const after = allows({ role: patch.role ?? current.role, group: patch.group ?? current.group, readOnly: patch.readOnly ?? current.readOnly });
  const gained = after.filter((c) => !before.includes(c));
  const lost = before.filter((c) => !after.includes(c));
  if (gained.length) lines.push(`  ⚠ newly allows: ${gained.join(", ")} commands`);
  if (lost.length) lines.push(`  no longer allows: ${lost.join(", ")} commands`);
  return lines.join("\n");
}

export function registerOnboardingTools(server: McpServer, deps: OnboardingToolDependencies): void {
  const refuseScoped = (): TextResult | undefined =>
    canChangeFleet(currentPrincipal())
      ? undefined
      : deps.errorResult("Refused: changing fleet membership requires an admin token.");

  server.registerTool(
    "fleet-discover",
    {
      description:
        "List hosts from the local ~/.ssh/config that are not in the fleet yet, with the user/host/port, " +
        "credentials and known_hosts status Flotilla would use for each. Read-only; follow up with fleet-add " +
        "(name = the alias, no host needed) to onboard one without a password.",
      inputSchema: {},
    },
    async () => {
      const refused = refuseScoped();
      if (refused) return refused;
      const registry = deps.getRegistry();
      const inFleet = new Set(registry?.servers().map((s) => s.name) ?? []);
      const aliases = listSshConfigAliases(sshConfigFile());
      if (aliases.length === 0) return text(["No concrete Host entries found in your ssh config."]);
      const lines: string[] = [];
      for (const alias of aliases) {
        if (inFleet.has(alias)) {
          lines.push(`= ${alias}: already in the fleet`);
          continue;
        }
        try {
          const eff = resolveSshHost(alias, undefined, sshConfigFile());
          const known = knownHostFingerprints(eff.hostKeyAlias ?? eff.hostname, eff.port, eff.knownHostsFiles);
          const notes = [
            eff.proxyCommand ? "ProxyCommand (unsupported)" : "",
            eff.proxyJump ? `via ${eff.proxyJump}` : "",
            known.length > 0 ? "host key in known_hosts" : "host key unknown (TOFU)",
          ].filter(Boolean);
          lines.push(`+ ${alias}: ${eff.user}@${eff.hostname}:${eff.port} — ${notes.join(", ")}`);
        } catch (err) {
          lines.push(`! ${alias}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      return text(["ssh config hosts (+ = can be added, = = in fleet, ! = problem):", ...lines]);
    },
  );

  server.registerTool(
    "fleet-add",
    {
      description:
        "Add a server to the fleet. Pass just `name` for a host in the user's ~/.ssh/config, or name + host " +
        "(+ user/port). Login is automatic: the user's keys and ssh-agent first; if none works, the user is " +
        "asked for the password ONCE on a secure local page (never in chat), Flotilla installs its own key and " +
        "switches to it; servers that only allow passwords keep password login with the password in the OS " +
        "keychain. The host key is checked against known_hosts and pinned. createUser sets up a dedicated " +
        "low-privilege user. Always requires approval. Never ask the user to type a password into the chat.",
      inputSchema: {
        name: NAME.describe("Server name (unique). Also the ssh config alias when host is omitted"),
        host: z.string().optional().describe("IP or DNS name; omit to use the ssh config alias `name`"),
        sshAlias: z.string().optional().describe("Read ssh settings from this alias instead of name/host"),
        user: z.string().optional().describe("SSH user (default: from ssh config, like `ssh` itself)"),
        port: z.number().int().positive().max(65535).optional().describe("SSH port (default: from ssh config)"),
        auth: z.enum(["agent", "key", "password"]).optional().describe("Force one auth method instead of auto-detection"),
        keyRef: z.string().optional().describe("Private key path; '~' is expanded"),
        tier: z.string().optional().describe("Policy tier (default: inferred from the name; unknown names are prod)"),
        role: z.enum(["viewer", "operator", "admin"]).optional().describe('Policy role (default "operator")'),
        tags: z.array(z.string()).optional().describe('Tags for targeting, e.g. ["web", "arm"]'),
        readOnly: z.boolean().optional().describe("Refuse all non-read-only commands on this server"),
        via: z.string().optional().describe("Jump host (existing fleet server); default from ProxyJump"),
        createUser: z
          .string()
          .regex(/^[a-z_][a-z0-9_-]{0,31}$/)
          .optional()
          .describe('Create this low-privilege user (e.g. "flotilla") with the fleet key and use it from now on'),
        createUserSudo: z.boolean().optional().describe("Give the created user a sudo allowlist for service tools (default true)"),
        passwordOnly: z.boolean().optional().describe("Keep password login (no key install) — for appliances that only allow passwords"),
        confirm: z.boolean().optional().describe(CONFIRM_DESCRIPTION),
      },
    },
    async (args, extra) => {
      const refused = refuseScoped();
      if (refused) return refused;
      const registry = deps.getRegistry();
      if (!registry) return deps.notConfigured();
      const outcome = await deps.gate(extra, {
        tool: "fleet-add",
        action: `add server "${args.name}" (${args.user ? `${args.user}@` : ""}${args.host ?? `ssh alias ${args.sshAlias ?? args.name}`}` +
          `${args.tier ? `, tier=${args.tier}` : ""}${args.role ? `, role=${args.role}` : ""}${args.createUser ? `, create user ${args.createUser}` : ""})`,
        commandClass: "privileged (config change)",
        hosts: [args.name],
        confirmFlag: args.confirm,
      });
      if (outcome.kind !== "approved") return deps.errorResult(("reason" in outcome && outcome.reason) || "Refused");

      const cfgPath = deps.configPath();
      const auditBase = { kind: "execution" as const, tool: "fleet-add", command: `add server "${args.name}"`, hosts: [args.name] };
      const fleetKeyPath = join(dirname(cfgPath), "fleet_ed25519");
      const keychain = await defaultKeychainBackend();
      const loginAccount = keychainAccount(args.name, false);
      let askedOnPage = false;
      let usedStored = false;
      try {
        const result = await onboardServer(
          {
            name: args.name, host: args.host, sshAlias: args.sshAlias, user: args.user, port: args.port,
            auth: args.auth, keyRef: args.keyRef, group: args.tier, role: args.role, tags: args.tags,
            readOnly: args.readOnly, via: args.via,
          },
          {
            fleet: registry.servers(),
            createUser: args.createUser ? { name: args.createUser, sudo: args.createUserSudo ?? true } : undefined,
            fleetKey: () => ensureFleetKeyPair(fleetKeyPath),
            passwordOnly: args.passwordOnly,
            // Passwords never travel through MCP arguments: an existing keychain
            // entry is used as-is, otherwise the secure one-time local page asks.
            password: keychain
              ? {
                  obtain: async ({ retry }) => {
                    if (!retry) {
                      const existing = await keychain.get(loginAccount).catch(() => undefined);
                      if (existing) {
                        usedStored = true;
                        return existing;
                      }
                    }
                    if (!deps.canAskPassword()) return undefined;
                    askedOnPage = true;
                    return (await deps.requestPassword(args.name)) ? keychain.get(loginAccount) : undefined;
                  },
                  // A stale stored password gets one more chance via the page.
                  maxAttempts: deps.canAskPassword() ? 2 : 1,
                }
              : undefined,
            deps: {
              sshG: (alias) => resolveSshHost(alias, undefined, sshConfigFile()),
              extraKeys: existsSync(fleetKeyPath) ? [fleetKeyPath] : [],
            },
          },
        );
        if (keychain) {
          if (result.method === "password" && result.probe.uid !== 0 && result.passwordToStore) {
            // sudo asks for the login user's own password by default.
            await keychain.set(keychainAccount(args.name, true), result.passwordToStore);
          } else if (result.method !== "password") {
            await keychain.remove(loginAccount); // switched to a key: the password is not needed any more
          }
        }
        const next = appendServerToConfig(readFileSync(cfgPath, "utf8"), result.server);
        const reload = commitConfig(deps, cfgPath, next, "fleet-add");
        deps.audit({ ...auditBase, command: `add server "${args.name}" (${result.method})`, outcome: "ok" });
        const how = {
          key: `key ${result.server.keyRef}`,
          agent: "ssh-agent",
          "password→key": `password first contact, switched to the fleet key ${result.server.keyRef} (password not kept)`,
          password: `password (stored in the OS keychain${keychain ? "" : " — UNAVAILABLE: set FLOTILLA_<NAME>_PASSWORD"})`,
        }[result.method];
        return text([
          `Server "${args.name}" added: ${result.server.user}@${result.server.host}:${result.server.port}`,
          `login: ${how}`,
          `probe: hostname=${result.probe.hostname ?? "?"}  uid=${result.probe.uid ?? "?"}  tmux=${result.probe.tmux ? "yes" : "NO (sessions unavailable)"}`,
          `host key pinned (${result.hostKeySource}): ${result.server.trustedHostKey ?? "(not captured)"}`,
          `policy: tier=${result.server.group} role=${result.server.role} — change with fleet-set`,
          ...result.notes.map((n) => `NOTE: ${n.text}`),
          "",
          reload,
        ]);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        // Nothing was added, so a password stored for this attempt must not
        // linger; a stored one that was rejected is stale either way.
        const rejected = err instanceof OnboardError && err.code === "password-rejected";
        if (keychain && (askedOnPage || (usedStored && rejected))) {
          await keychain.remove(loginAccount).catch(() => false);
        }
        deps.audit({ ...auditBase, outcome: "failed", reason });
        return deps.errorResult(`Server NOT added: ${reason}${nextStepHint(err, args.name, deps.canAskPassword())}`);
      }
    },
  );

  server.registerTool(
    "fleet-remove",
    {
      description:
        "Remove a server from the fleet config (its whole [[servers]] block; comments elsewhere are kept). " +
        "Refuses while other servers use it as a jump host. Always requires approval.",
      inputSchema: {
        name: NAME.describe("Server to remove"),
        confirm: z.boolean().optional().describe(CONFIRM_DESCRIPTION),
      },
    },
    async ({ name, confirm }, extra) => {
      const refused = refuseScoped();
      if (refused) return refused;
      if (!deps.getRegistry()) return deps.notConfigured();
      const outcome = await deps.gate(extra, {
        tool: "fleet-remove", action: `remove server "${name}" from the fleet`,
        commandClass: "destructive (config change)", hosts: [name], confirmFlag: confirm,
      });
      if (outcome.kind !== "approved") return deps.errorResult(("reason" in outcome && outcome.reason) || "Refused");
      const cfgPath = deps.configPath();
      try {
        const next = removeServerFromConfig(readFileSync(cfgPath, "utf8"), name);
        const reload = commitConfig(deps, cfgPath, next, "fleet-remove");
        deps.audit({ kind: "execution", tool: "fleet-remove", command: `remove server "${name}"`, hosts: [name], outcome: "ok" });
        return text([`Server "${name}" removed from ${cfgPath}.`, reload]);
      } catch (err) {
        return deps.errorResult(err instanceof Error ? err.message : String(err));
      }
    },
  );

  server.registerTool(
    "fleet-set",
    {
      description:
        "Change one server's role, tier, tags, readOnly flag, user or port in the fleet config, keeping the rest " +
        "of the file (and its comments) intact. Always requires approval.",
      inputSchema: {
        name: NAME.describe("Server to change"),
        role: z.enum(["viewer", "operator", "admin"]).optional(),
        tier: z.string().min(1).optional().describe("Policy tier (prod/staging/dev/...)"),
        tags: z.array(z.string()).optional().describe("Replaces the tag list"),
        readOnly: z.boolean().optional(),
        user: z.string().min(1).optional(),
        port: z.number().int().positive().max(65535).optional(),
        confirm: z.boolean().optional().describe(CONFIRM_DESCRIPTION),
      },
    },
    async ({ name, role, tier, tags, readOnly, user, port, confirm }, extra) => {
      const refused = refuseScoped();
      if (refused) return refused;
      if (!deps.getRegistry()) return deps.notConfigured();
      const patch: ServerPatch = { role, group: tier, tags, readOnly, user, port };
      const changed = Object.entries(patch).filter(([, v]) => v !== undefined);
      if (changed.length === 0) return deps.errorResult("Nothing to change: pass at least one of role, tier, tags, readOnly, user, port.");
      const summary = changed.map(([k, v]) => `${k === "group" ? "tier" : k}=${JSON.stringify(v)}`).join(", ");
      const current = deps.getRegistry()!.getServer(name);
      const outcome = await deps.gate(extra, {
        tool: "fleet-set", action: current ? describePolicyChange(current, patch, deps.getMatrix()) : `set ${summary} on server "${name}"`,
        commandClass: "privileged (config change)", hosts: [name], confirmFlag: confirm,
      });
      if (outcome.kind !== "approved") return deps.errorResult(("reason" in outcome && outcome.reason) || "Refused");
      const cfgPath = deps.configPath();
      try {
        const next = setServerFields(readFileSync(cfgPath, "utf8"), name, patch);
        const reload = commitConfig(deps, cfgPath, next, "fleet-set");
        deps.audit({ kind: "execution", tool: "fleet-set", command: `set ${summary} on "${name}"`, hosts: [name], outcome: "ok" });
        return text([`Server "${name}": ${summary}`, reload]);
      } catch (err) {
        return deps.errorResult(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
