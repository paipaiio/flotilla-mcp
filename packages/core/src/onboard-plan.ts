/**
 * Password-free onboarding: "if `ssh <alias>` works, `flotilla add` works".
 *
 * planServer derives everything it can from the user's own OpenSSH setup
 * (ssh -G: HostName/User/Port/IdentityFile/ProxyJump; known_hosts: trusted
 * host keys) and lists the credentials worth trying. connectPlanned then
 * probes candidates in order — key files first (portable into Docker and
 * gateways), the agent last — and pins the host key, refusing outright when
 * the live key contradicts known_hosts.
 *
 * Explicit flags always win over ssh config. Nothing here asks for a
 * password — the password fallback lives in onboard-flow.ts.
 */
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { inferTier } from "./config.js";
import { OnboardError, isNetworkError, type ProbeResult } from "./onboard.js";
import { checkHostKeyAgainstKnown, knownHostKeys, resolveSshHost, type KnownHostKey, type SshEffectiveConfig } from "./sshconfig.js";
import type { AuthMethod, Role, ServerConfig } from "./types.js";

export interface OnboardRequest {
  name: string;
  /** IP/DNS. Omitted: `name` is looked up as an ssh config alias. */
  host?: string;
  /** Alias to read ssh settings from (default: host ?? name). */
  sshAlias?: string;
  user?: string;
  port?: number;
  auth?: AuthMethod;
  keyRef?: string;
  group?: string;
  role?: Role;
  tags?: string[];
  readOnly?: boolean;
  via?: string;
}

export interface AuthCandidate {
  auth: AuthMethod;
  keyRef?: string;
  label: string;
}

export interface PlanDeps {
  sshG?: (alias: string) => SshEffectiveConfig;
  knownHosts?: (host: string, port: number, files: string[]) => Array<string | KnownHostKey>;
  exists?: (path: string) => boolean;
  env?: Record<string, string | undefined>;
  /** Names already in the fleet (jump-host resolution). */
  fleetServers?: string[];
  /** More private keys to try after the ssh-config ones (e.g. the fleet key). */
  extraKeys?: string[];
  home?: string;
}

export interface PlannedServer {
  server: ServerConfig;
  candidates: AuthCandidate[];
  /** Host keys the user already trusts (fingerprint "SHA256:<hex>", optional type). */
  knownKeys: KnownHostKey[];
  /** Where host/user/port came from. */
  source: "ssh-config" | "flags";
}

/** "user@host:port" → "host"; the jump host must exist in the fleet by name. */
function jumpHostName(proxyJump: string): string {
  const withoutUser = proxyJump.includes("@") ? proxyJump.slice(proxyJump.lastIndexOf("@") + 1) : proxyJump;
  return withoutUser.replace(/:\d+$/, "");
}

function contractHome(path: string, home: string): string {
  return path.startsWith(home + "/") ? `~${path.slice(home.length)}` : path;
}

function authCandidates(req: OnboardRequest, eff: SshEffectiveConfig, deps: PlanDeps, home: string): AuthCandidate[] {
  if (req.auth === "password") return [{ auth: "password", label: "password (keychain/env)" }];
  if (req.keyRef) return [{ auth: "key", keyRef: req.keyRef, label: `key ${req.keyRef}` }];
  if (req.auth === "agent") return [{ auth: "agent", label: "ssh-agent" }];
  const exists = deps.exists ?? existsSync;
  const env = deps.env ?? process.env;
  const out: AuthCandidate[] = [];
  const addKey = (file: string) => {
    if (!exists(file)) return;
    const keyRef = contractHome(file, home);
    if (!out.some((c) => c.keyRef === keyRef)) out.push({ auth: "key", keyRef, label: `key ${file}` });
  };
  // Same order as `ssh`: the keys ssh config names, then the agent...
  eff.identityFiles.forEach(addKey);
  if (env.SSH_AUTH_SOCK && eff.identityAgent !== "none" && !(req.auth === "key")) {
    out.push({ auth: "agent", label: "ssh-agent" });
  }
  // ...then keys ssh would not try on its own (other ~/.ssh keys, the fleet key).
  (deps.extraKeys ?? []).forEach(addKey);
  return out;
}

/** Build the server entry and the credentials to try. Synchronous, no network. */
export function planServer(req: OnboardRequest, deps: PlanDeps = {}): PlannedServer {
  const home = deps.home ?? homedir();
  const alias = req.sshAlias ?? req.host ?? req.name;
  const eff = (deps.sshG ?? ((a) => resolveSshHost(a)))(alias);

  if (eff.proxyCommand && !req.via) {
    throw new OnboardError(
      `ssh config for "${alias}" uses ProxyCommand, which Flotilla cannot reproduce — use ProxyJump, or pass --via <fleet server>`,
      "unsupported-proxy",
      { alias, proxyCommand: eff.proxyCommand },
    );
  }
  let via = req.via;
  if (!via && eff.proxyJump) {
    if (eff.proxyJump.includes(",")) {
      throw new OnboardError(
        `ssh config for "${alias}" chains several jump hosts (${eff.proxyJump}); only one hop is supported`,
        "unsupported-proxy",
        { alias, proxyJump: eff.proxyJump },
      );
    }
    const jump = jumpHostName(eff.proxyJump);
    if (!(deps.fleetServers ?? []).includes(jump)) {
      throw new OnboardError(
        `"${alias}" reaches its target through ProxyJump "${jump}", which is not in the fleet yet — add it first: flotilla import-ssh ${jump}`,
        "jump-host-missing",
        { alias, jump },
      );
    }
    via = jump;
  }

  const server: ServerConfig = {
    name: req.name,
    host: req.host ?? eff.hostname,
    port: req.port ?? eff.port,
    user: req.user ?? eff.user,
    auth: "agent",
    group: req.group ?? inferTier(req.name),
    tags: req.tags ?? [],
    role: req.role ?? "operator",
    readOnly: req.readOnly ?? false,
    ...(via ? { via } : {}),
  };

  // May be empty (no keys, no agent): the flow then falls back to a password.
  const candidates = authCandidates(req, eff, deps, home);

  const lookupHost = eff.hostKeyAlias ?? server.host;
  const knownKeys = (deps.knownHosts ?? knownHostKeys)(lookupHost, server.port, eff.knownHostsFiles).map((k) =>
    typeof k === "string" ? { fingerprint: k } : k,
  );
  return {
    server,
    candidates,
    knownKeys,
    source: req.host ? "flags" : "ssh-config",
  };
}

export interface ConnectedServer {
  server: ServerConfig;
  probe: ProbeResult;
  hostKeySource: "known_hosts" | "tofu";
  /** "label: error" for every candidate that failed before the winner. */
  attempts: string[];
}

/** Throw before trusting a live key that contradicts the user's known_hosts. */
export function assertHostKeyTrusted(
  plan: Pick<PlannedServer, "server" | "knownKeys">,
  live: { fingerprint?: string; type?: string },
): "known_hosts" | "tofu" {
  const verdict = checkHostKeyAgainstKnown(live, plan.knownKeys);
  if (verdict === "mismatch") {
    throw new OnboardError(
      `HOST KEY MISMATCH for ${plan.server.host}:${plan.server.port} — the server presented ${live.fingerprint ?? "no key"}, ` +
        `but your known_hosts trusts ${plan.knownKeys.map((k) => k.fingerprint).join(", ")}. Not adding it. ` +
        `If the server was reinstalled, verify the new key out of band and update known_hosts first.`,
      "host-key-mismatch",
      { host: plan.server.host, port: plan.server.port, presented: live.fingerprint, trusted: plan.knownKeys.map((k) => k.fingerprint) },
    );
  }
  return verdict === "verified" ? "known_hosts" : "tofu";
}

/**
 * Probe candidates in order; pin the host key, cross-checked against
 * known_hosts. A network failure stops immediately (other credentials cannot
 * help, and each attempt would wait out its own timeout).
 */
export async function connectPlanned(
  plan: PlannedServer,
  deps: { probe: (server: ServerConfig) => Promise<ProbeResult> },
): Promise<ConnectedServer> {
  const attempts: string[] = [];
  for (const candidate of plan.candidates) {
    const attempt: ServerConfig = { ...plan.server, auth: candidate.auth };
    if (candidate.keyRef) attempt.keyRef = candidate.keyRef;
    else delete attempt.keyRef;
    const probe = await deps.probe(attempt);
    if (!probe.ok) {
      if (isNetworkError(probe.error)) {
        throw new OnboardError(
          `Cannot reach ${plan.server.host}:${plan.server.port}: ${probe.error}`,
          "unreachable",
          { host: plan.server.host, port: plan.server.port, reason: probe.error },
        );
      }
      attempts.push(`${candidate.label}: ${probe.error ?? "failed"}`);
      continue;
    }
    const hostKeySource = assertHostKeyTrusted(plan, { fingerprint: probe.hostKey, type: probe.hostKeyType });
    return {
      server: { ...attempt, ...(probe.hostKey ? { trustedHostKey: probe.hostKey } : {}) },
      probe,
      hostKeySource,
      attempts,
    };
  }
  throw new OnboardError(
    attempts.length > 0
      ? `Could not authenticate to ${plan.server.user}@${plan.server.host}:${plan.server.port} with any key or agent. Tried:\n` +
          attempts.map((a) => `  - ${a}`).join("\n")
      : `No SSH key or agent is available for ${plan.server.user}@${plan.server.host}:${plan.server.port}`,
    "auth-failed",
    { user: plan.server.user, host: plan.server.host, port: plan.server.port, attempts },
  );
}
