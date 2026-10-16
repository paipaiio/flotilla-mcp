/**
 * The add flow shared by the CLI and the MCP tool — one path for every kind
 * of server:
 *
 *   1. Read the host key without authenticating: an unreachable host fails
 *      fast, and a key that contradicts known_hosts stops everything before
 *      any credential (let alone a password) is offered.
 *   2. Try the user's own SSH setup: key files, then ssh-agent.
 *   3. Nothing works → ask for the password once (terminal prompt or the
 *      MCP secure page), log in, install the fleet key and switch to it.
 *      The password is then forgotten.
 *   4. The server refuses key logins (password-only sshd) → keep password
 *      auth and hand the password back for the caller to store in the OS
 *      keychain. Same password serves sudo for a non-root account.
 *   5. Optionally replace the login with a dedicated low-privilege user.
 */
import { OnboardError, buildKeyInstallCommand, execOnce, isAuthError, isNetworkError, probeServer, scanHostKey, type ProbeResult } from "./onboard.js";
import { assertHostKeyTrusted, connectPlanned, planServer, type ConnectedServer, type OnboardRequest, type PlanDeps } from "./onboard-plan.js";
import { buildCreateUserCommand } from "./onboard-user.js";
import type { FleetKeyPair } from "./setup-repair.js";
import type { ServerConfig } from "./types.js";

type Secrets = { password?: string; sudo?: string };

/** Strongest key type known_hosts holds for the host, in OpenSSH's preference order. */
const KEY_TYPE_PREFERENCE = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"];
function preferredKnownType(known: Array<{ type?: string }>): string | undefined {
  const types = new Set(known.map((k) => k.type).filter((t): t is string => Boolean(t)));
  return KEY_TYPE_PREFERENCE.find((t) => types.has(t));
}

/** The fleet key as ensureFleetKeyPair returns it (only these fields are used). */
type FleetKey = Pick<FleetKeyPair, "publicKey" | "privateKeyPath">;

export interface PasswordTarget {
  name: string;
  user: string;
  host: string;
  port: number;
  /** What was tried before asking ("key ~/.ssh/id_ed25519: ..."). */
  attempts: string[];
  /** True when asking again after a rejected password. */
  retry: boolean;
}

export interface PasswordSource {
  /** Ask for the login password; undefined = unavailable or declined. */
  obtain(target: PasswordTarget): Promise<string | undefined>;
  /** Tries before giving up on a rejected password (default 1). */
  maxAttempts?: number;
}

export interface OnboardOptions {
  /** Servers already in the fleet: duplicate check and jump hosts. */
  fleet: ServerConfig[];
  /** Create this low-privilege user and use it from now on. */
  createUser?: { name: string; sudo: boolean };
  /** Loads (or creates) the fleet key pair; called only when actually needed. */
  fleetKey?: () => FleetKey;
  /** Where a password comes from when no key/agent works. Omit = never ask. */
  password?: PasswordSource;
  /** Skip key/agent attempts and go straight to the password. */
  passwordFirst?: boolean;
  /** Keep password auth; do not install a key. */
  passwordOnly?: boolean;
  deps?: PlanDeps & {
    probe?: (server: ServerConfig, secrets?: Secrets) => Promise<ProbeResult>;
    exec?: (
      server: ServerConfig,
      command: string,
      opts: { sudo?: boolean; secrets?: Secrets },
    ) => Promise<{ ok: boolean; stdout: string; stderr: string; error?: string }>;
    scan?: (server: ServerConfig) => Promise<{ fingerprint: string; type?: string; authMethods?: string[] }>;
  };
}

export type OnboardNoteCode = "tofu" | "root-account" | "uid0-not-root" | "key-not-accepted" | "created-user";

export interface OnboardResult extends ConnectedServer {
  /** How the server will be reached from now on. */
  method: "key" | "agent" | "password→key" | "password";
  createdUser?: string;
  /** Only for method "password": persist this (OS keychain); it is also the sudo password. */
  passwordToStore?: string;
  /** Follow-ups with a stable code (front ends translate) and English text. */
  notes: Array<{ code: OnboardNoteCode; text: string }>;
}

function describeFailure(r: { error?: string; stderr?: string }): string {
  return (r.error || r.stderr?.trim()) ?? "unknown error";
}

export async function onboardServer(req: OnboardRequest, opts: OnboardOptions): Promise<OnboardResult> {
  if (opts.fleet.some((s) => s.name === req.name)) {
    throw new OnboardError(`Server "${req.name}" already exists in the config`, "duplicate", { name: req.name });
  }
  const deps = opts.deps ?? {};
  const probe = deps.probe ?? ((s: ServerConfig, secrets?: Secrets) => probeServer(s, opts.fleet, secrets));
  const exec = deps.exec ?? ((s, cmd, o) => execOnce(s, cmd, { fleet: opts.fleet, ...o }));
  const scan = deps.scan ?? ((s: ServerConfig) => scanHostKey(s, 10_000, { fleet: opts.fleet }));
  let plan = planServer(req, { ...deps, fleetServers: opts.fleet.map((s) => s.name) });

  // Like OpenSSH: when known_hosts knows this host, only negotiate a key type
  // it holds — otherwise a MITM could offer another type and look "unknown".
  const knownType = preferredKnownType(plan.knownKeys);
  if (knownType) plan = { ...plan, server: { ...plan.server, hostKeyAlgorithm: knownType } };

  // 1. Reachability + host key (through the jump host when there is one),
  // before any credential is offered.
  const scanned = await scan(plan.server);
  assertHostKeyTrusted(plan, scanned);
  // Every later connection (key, agent, password) must present this same key.
  plan = {
    ...plan,
    server: {
      ...plan.server,
      trustedHostKey: scanned.fingerprint,
      ...(plan.server.hostKeyAlgorithm || !scanned.type ? {} : { hostKeyAlgorithm: scanned.type }),
    },
  };

  const notes: OnboardResult["notes"] = [];
  let connected: ConnectedServer | undefined;
  let method: OnboardResult["method"] = "key";
  let password: string | undefined;
  let attempts: string[] = [];

  // 2. The user's own SSH setup.
  const wantsPassword = opts.passwordFirst || opts.passwordOnly || req.auth === "password";
  if (!wantsPassword) {
    try {
      connected = await connectPlanned(plan, { probe: (s) => probe(s) });
      method = connected.server.auth === "agent" ? "agent" : "key";
    } catch (err) {
      if (!(err instanceof OnboardError) || err.code !== "auth-failed") throw err;
      // No key/agent works: this server needs a password (step 3 asks, or
      // explains how to give one when nothing can ask).
      attempts = (err.details["attempts"] as string[] | undefined) ?? [];
    }
  }

  // 3./4. Password first contact.
  if (!connected) {
    // The scan learned which methods the server takes: never ask for a password
    // it would refuse — explain the key route (with the fleet public key) instead.
    const methods = scanned.authMethods;
    if (methods && !methods.includes("password") && !methods.includes("keyboard-interactive")) {
      throw new OnboardError(
        `${plan.server.user}@${plan.server.host}:${plan.server.port} only accepts keys (${methods.join(", ")}), and none of the local keys or agent identities is authorized there`,
        "password-not-allowed",
        {
          user: plan.server.user,
          host: plan.server.host,
          port: plan.server.port,
          attempts,
          methods,
          ...(opts.fleetKey ? { fleetPublicKey: opts.fleetKey().publicKey } : {}),
        },
      );
    }
    if (!opts.password) {
      throw new OnboardError(
        `${plan.server.user}@${plan.server.host}:${plan.server.port} needs a password, and none can be asked for here`,
        "password-needed",
        { user: plan.server.user, host: plan.server.host, port: plan.server.port, attempts },
      );
    }
    // Pinned to the scanned (and checked) key: the password is only ever sent
    // after the server proves it holds exactly that key.
    const pwServer: ServerConfig = { ...plan.server, auth: "password", trustedHostKey: scanned.fingerprint };
    const target = { name: plan.server.name, user: plan.server.user, host: plan.server.host, port: plan.server.port, attempts };
    const maxAttempts = Math.max(1, opts.password.maxAttempts ?? 1);
    let pwProbe: ProbeResult | undefined;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const next = await opts.password.obtain({ ...target, retry: attempt > 1 });
      if (!next) {
        if (attempt > 1) break; // gave up after a rejection: report the rejection
        throw new OnboardError("No password was provided", "password-needed", { user: plan.server.user, host: plan.server.host, port: plan.server.port, attempts });
      }
      password = next;
      pwProbe = await probe(pwServer, { password, sudo: password });
      if (pwProbe.ok || !isAuthError(pwProbe.error)) break;
    }
    const secrets: Secrets = { password, sudo: password };
    if (!pwProbe!.ok) {
      if (isAuthError(pwProbe!.error)) {
        throw new OnboardError(`The password for ${plan.server.user}@${plan.server.host} was rejected`, "password-rejected", { user: plan.server.user, host: plan.server.host });
      }
      throw new OnboardError(
        `Password login to ${plan.server.host}:${plan.server.port} failed: ${pwProbe!.error ?? "unknown error"}`,
        isNetworkError(pwProbe!.error) ? "unreachable" : "auth-failed",
        { host: plan.server.host, port: plan.server.port, reason: pwProbe!.error, attempts },
      );
    }
    const okProbe = pwProbe!;
    const hostKeySource = assertHostKeyTrusted(plan, { fingerprint: okProbe.hostKey, type: okProbe.hostKeyType });
    const pinned = okProbe.hostKey ?? scanned.fingerprint;
    connected = { server: { ...pwServer, ...(pinned ? { trustedHostKey: pinned } : {}) }, probe: okProbe, hostKeySource, attempts };
    method = "password";

    if (!opts.passwordOnly && opts.fleetKey) {
      const key = opts.fleetKey();
      const installed = await exec(connected.server, buildKeyInstallCommand(key.publicKey), { secrets });
      const keyServer: ServerConfig = { ...plan.server, auth: "key", keyRef: key.privateKeyPath, ...(pinned ? { trustedHostKey: pinned } : {}) };
      const keyProbe = installed.ok && installed.stdout.includes("INSTALLED") ? await probe(keyServer) : undefined;
      if (keyProbe?.ok) {
        connected = { ...connected, server: keyServer, probe: keyProbe };
        method = "password→key";
      } else {
        notes.push({
          code: "key-not-accepted",
          text: `the server did not accept key login (${keyProbe ? describeFailure(keyProbe) : describeFailure(installed)}) — it stays on password auth`,
        });
      }
    }
  }

  if (connected.hostKeySource === "tofu") {
    notes.push({ code: "tofu", text: "host key was not in your known_hosts — pinned on first contact (TOFU)" });
  }

  // 5. Dedicated low-privilege user.
  if (opts.createUser) {
    if (method === "password") {
      throw new OnboardError(
        `--create-user needs key login, but ${plan.server.host} only accepts passwords`,
        "create-user-failed",
        { host: plan.server.host },
      );
    }
    const key = opts.fleetKey?.();
    if (!key) throw new OnboardError("--create-user needs the fleet key", "create-user-failed");
    const { name, sudo } = opts.createUser;
    const asRoot = connected.probe.uid === 0;
    const created = await exec(connected.server, buildCreateUserCommand(name, key.publicKey, sudo), {
      sudo: !asRoot,
      ...(password ? { secrets: { password, sudo: password } } : {}),
    });
    if (!created.ok || !created.stdout.includes("FLOTILLA_USER_READY")) {
      throw new OnboardError(
        `Could not create user "${name}" on ${plan.server.host}: ${describeFailure(created)}`,
        "create-user-failed",
        { host: plan.server.host, user: name, reason: describeFailure(created), needsSudo: !asRoot },
      );
    }
    const asUser: ServerConfig = { ...connected.server, user: name, auth: "key", keyRef: key.privateKeyPath };
    const second = await probe(asUser);
    if (!second.ok) {
      throw new OnboardError(`User "${name}" was created, but key login as it failed: ${describeFailure(second)}`, "create-user-failed", { user: name });
    }
    if (second.hostKey && connected.server.trustedHostKey && second.hostKey !== connected.server.trustedHostKey) {
      throw new OnboardError(`HOST KEY MISMATCH between connections to ${plan.server.host} — not adding it`, "host-key-mismatch");
    }
    notes.push({
      code: "created-user",
      text: sudo
        ? `created user "${name}"; sudo is limited to systemctl status/start/stop/restart/reload, journal read via group`
        : `created user "${name}" without sudo`,
    });
    return { ...connected, server: asUser, probe: second, method: method === "password→key" ? "password→key" : "key", createdUser: name, notes };
  }

  if (connected.probe.uid === 0) {
    notes.push(
      connected.server.user === "root"
        ? {
            code: "root-account",
            text: "this account is root: Flotilla always asks before destructive commands on it (auto approval and JIT grants do not apply). Re-add with --create-user to use a dedicated low-privilege user instead.",
          }
        : {
            code: "uid0-not-root",
            text: `"${connected.server.user}" has uid 0 (root privileges under another name) — prefer --create-user`,
          },
    );
  }
  return { ...connected, method, ...(method === "password" ? { passwordToStore: password } : {}), notes };
}
