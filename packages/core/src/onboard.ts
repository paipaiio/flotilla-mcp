/**
 * fleet-add: semi-automatic server onboarding.
 *
 * probeServer opens a short-lived SSH connection (its own transport, closed
 * afterwards) and collects facts: hostname, uid, tmux availability, and the
 * host key (TOFU-captured, returned in pinable "SHA256:..." form).
 *
 * buildServerToml / appendServerToConfig handle the config-file side: the
 * new server is appended as a [[servers]] block with its host key pinned —
 * first contact doubles as key enrollment, so later connections are verified
 * against it (the only host-key control that survives restarts).
 */
import { createHash } from "node:crypto";
import { Client, type ClientChannel, type ConnectConfig } from "ssh2";
import { SshTransport, effectiveAlgorithms, hostKeyAlgorithmsFor, hostKeyBlobType } from "./ssh.js";
import { parseFleetConfig } from "./config.js";
import type { ServerConfig } from "./types.js";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Machine-readable reasons, so front ends (Chinese CLI, English MCP) can
 * explain the failure and the next step in their own words.
 */
export type OnboardErrorCode =
  | "unreachable"
  | "auth-failed"
  | "password-rejected"
  | "password-needed"
  | "password-not-allowed"
  | "host-key-mismatch"
  | "jump-host-missing"
  | "unsupported-proxy"
  | "duplicate"
  | "create-user-failed"
  | "invalid";

export class OnboardError extends Error {
  constructor(
    message: string,
    readonly code: OnboardErrorCode = "invalid",
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "OnboardError";
  }
}

/** Transport-level failures: retrying other credentials cannot help. */
export function isNetworkError(message: string | undefined): boolean {
  return /ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|ENOTFOUND|EAI_AGAIN|ECONNRESET|Timed out while waiting for handshake|getaddrinfo/i.test(
    message ?? "",
  );
}

/** ssh2's "every method was refused" — the credential, not the network. */
export function isAuthError(message: string | undefined): boolean {
  return /authentication methods failed|Permission denied/i.test(message ?? "");
}

type HeldSecrets = { password?: string; sudo?: string };

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Only well-formed OpenSSH public key lines may be installed. */
const PUBKEY_RE =
  /^(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|rsa-sha2-(?:256|512)|ssh-rsa) [A-Za-z0-9+/=]{40,}( [^\n]*)?$/;

/**
 * Idempotent authorized_keys install. The public key is validated against a
 * strict format regex AND shell-quoted, so a hostile key string can't inject
 * commands into the remote shell.
 */
/** Validate and normalize one OpenSSH public key line; throws OnboardError otherwise. */
export function assertPublicKeyLine(publicKey: string): string {
  const key = publicKey.trim();
  if (!PUBKEY_RE.test(key)) {
    throw new OnboardError(`Not a valid OpenSSH public key line: ${key.slice(0, 40)}…`);
  }
  return key;
}

export { shellQuote };

export function buildKeyInstallCommand(publicKey: string): string {
  const key = assertPublicKeyLine(publicKey);
  const q = shellQuote(key);
  return (
    `mkdir -p ~/.ssh && chmod 700 ~/.ssh && ` +
    `touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && ` +
    `(grep -qxF ${q} ~/.ssh/authorized_keys || echo ${q} >> ~/.ssh/authorized_keys) && ` +
    `echo INSTALLED`
  );
}

export interface BootstrapResult {
  ok: boolean;
  hostname?: string;
  uid?: number;
  /** Host key captured during the password connection, "SHA256:..." form. */
  hostKey?: string;
  error?: string;
}

/**
 * First-contact bootstrap: connect once with a password, install the control
 * machine's public key into authorized_keys, capture the host key. After this,
 * the server is reachable by key auth and the password is no longer needed.
 *
 * The password is held only in this transport's memory (never env, argv or
 * disk) and dropped with it.
 */
export async function bootstrapKey(
  server: ServerConfig, // name/host/port/user; auth is forced to password here
  password: string,
  publicKey: string,
): Promise<BootstrapResult> {
  const asPassword: ServerConfig = { ...server, auth: "password", keyRef: undefined };
  const transport = new SshTransport(new Map([[server.name, asPassword]]), {
    secrets: new Map([[server.name, { password }]]),
  });
  try {
    const install = await transport.exec(asPassword, buildKeyInstallCommand(publicKey), {
      timeoutMs: 20_000,
    });
    if (!install.ok || !install.stdout.includes("INSTALLED")) {
      return {
        ok: false,
        error: install.error || install.stderr.trim() || `key install failed (exit ${install.exitCode ?? "unknown"})`,
      };
    }
    const host = await transport.exec(asPassword, "hostname && id -u", { timeoutMs: 10_000 });
    const lines = host.stdout.trim().split("\n");
    return {
      ok: true,
      hostname: lines[0],
      uid: lines[1] !== undefined ? Number(lines[1]) : undefined,
      hostKey: transport.hostKeyOf(server.name),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    await transport.close();
  }
}


export interface ProbeResult {
  ok: boolean;
  hostname?: string;
  uid?: number;
  tmux?: boolean;
  /** Pinned host key in "SHA256:..." form, ready for trustedHostKey. */
  hostKey?: string;
  /** Host key algorithm, e.g. "ssh-ed25519" (for known_hosts cross-checks). */
  hostKeyType?: string;
  error?: string;
}

/** Transport for a one-off connection; jump hosts must be in the map for `via`. */
function oneOffTransport(server: ServerConfig, fleet: ServerConfig[], secrets?: HeldSecrets): SshTransport {
  const servers = new Map(fleet.map((s) => [s.name, s]));
  servers.set(server.name, server);
  return new SshTransport(servers, secrets ? { secrets: new Map([[server.name, secrets]]) } : {});
}

/** Run one command on a not-yet-registered server over a short-lived connection. */
export async function execOnce(
  server: ServerConfig,
  command: string,
  opts: { fleet?: ServerConfig[]; timeoutMs?: number; secrets?: HeldSecrets; sudo?: boolean } = {},
): Promise<{ ok: boolean; stdout: string; stderr: string; error?: string }> {
  const transport = oneOffTransport(server, opts.fleet ?? [], opts.secrets);
  try {
    const r = await transport.exec(server, command, { timeoutMs: opts.timeoutMs ?? 60_000, sudo: opts.sudo });
    return { ok: r.ok, stdout: r.stdout, stderr: r.stderr, error: r.error };
  } catch (err) {
    return { ok: false, stdout: "", stderr: "", error: err instanceof Error ? err.message : String(err) };
  } finally {
    await transport.close();
  }
}

/**
 * @param fleet existing servers — needed when `server.via` names a jump host,
 *   otherwise the one-off transport cannot reach the bastion.
 */
export async function probeServer(
  server: ServerConfig,
  fleet: ServerConfig[] = [],
  secrets?: HeldSecrets,
): Promise<ProbeResult> {
  const transport = oneOffTransport(server, fleet, secrets);
  try {
    // One round trip for all facts: onboarding often runs over slow links.
    const facts = await transport.exec(
      server,
      "hostname; id -u; command -v tmux >/dev/null 2>&1 && echo yes || echo no",
      { timeoutMs: 15_000 },
    );
    if (!facts.ok) {
      return { ok: false, error: facts.error || facts.stderr.trim() || `probe failed (exit ${facts.exitCode ?? "unknown"})` };
    }
    const [hostname, uid, tmux] = facts.stdout.trim().split("\n").map((l) => l.trim());
    return {
      ok: true,
      hostname,
      uid: uid !== undefined && /^\d+$/.test(uid) ? Number(uid) : undefined,
      tmux: tmux === "yes",
      hostKey: transport.hostKeyOf(server.name),
      hostKeyType: transport.hostKeyTypeOf(server.name),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    await transport.close();
  }
}

function tomlStr(s: string): string {
  return JSON.stringify(s); // TOML basic strings are JSON-compatible
}

/** Render one [[servers]] block. Only set fields are written. */
export function buildServerToml(s: ServerConfig): string {
  const lines: string[] = ["", "[[servers]]"];
  lines.push(`name = ${tomlStr(s.name)}`);
  lines.push(`host = ${tomlStr(s.host)}`);
  if (s.port !== 22) lines.push(`port = ${s.port}`);
  lines.push(`user = ${tomlStr(s.user)}`);
  lines.push(`auth = ${tomlStr(s.auth)}`);
  if (s.keyRef) lines.push(`keyRef = ${tomlStr(s.keyRef)}`);
  lines.push(`tier = ${tomlStr(s.group)}`);
  if (s.tags.length > 0) lines.push(`tags = [${s.tags.map(tomlStr).join(", ")}]`);
  lines.push(`role = ${tomlStr(s.role)}`);
  if (s.readOnly) lines.push(`readOnly = true`);
  if (s.workdir) lines.push(`workdir = ${tomlStr(s.workdir)}`);
  if (s.via) lines.push(`via = ${tomlStr(s.via)}`);
  if (s.trustedHostKey) lines.push(`trustedHostKey = ${tomlStr(s.trustedHostKey)}`);
  if (s.hostKeyAlgorithm) lines.push(`hostKeyAlgorithm = ${tomlStr(s.hostKeyAlgorithm)}`);
  return lines.join("\n") + "\n";
}

/**
 * Append a server to config text. Validates: no duplicate name, and the
 * result must still parse. Returns the new config text.
 */
export function appendServerToConfig(tomlText: string, server: ServerConfig): string {
  const existing = parseFleetConfig(tomlText);
  if (existing.servers.some((s) => s.name === server.name)) {
    throw new OnboardError(`Server "${server.name}" already exists in the config`);
  }
  if (server.via && !existing.servers.some((s) => s.name === server.via)) {
    throw new OnboardError(`Jump host "${server.via}" not found in the config`);
  }
  const next = tomlText.replace(/\s*$/, "\n") + buildServerToml(server);
  parseFleetConfig(next); // must stay valid
  return next;
}

/**
 * Install a public key into the LOCAL user's authorized_keys — the
 * password-less half of self-onboarding ("flotilla add --local"): we are
 * already on the machine, so granting the fleet key access is a local file
 * append, no SSH password needed. Idempotent; enforces 700/600 perms.
 */
const LOCALHOST_FROM = 'from="127.0.0.1,::1"';

/**
 * Split an authorized_keys line into its options and the "type base64 [comment]"
 * part. Quote-aware: commas, spaces and key text inside command="..." are data.
 */
function parseAuthorizedKeyLine(line: string): { options: string[]; key: string } | undefined {
  if (line === "" || line.startsWith("#")) return undefined;
  if (/^(ssh-|ecdsa-|sk-)/.test(line)) return { options: [], key: line };
  const options: string[] = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === "\\" && quoted && i + 1 < line.length) {
      current += ch + line[++i];
      continue;
    }
    if (ch === '"') quoted = !quoted;
    if (!quoted && ch === ",") {
      options.push(current);
      current = "";
      continue;
    }
    if (!quoted && /\s/.test(ch)) {
      options.push(current);
      return { options, key: line.slice(i).trim() };
    }
    current += ch;
  }
  return undefined;
}

export function installPublicKeyLocally(
  publicKey: string,
  home = homedir(),
  opts: { localhostOnly?: boolean; dryRun?: boolean } = {},
): { authorizedKeysPath: string; appended: boolean; tightened: boolean; restricted: boolean } {
  const key = publicKey.trim();
  if (!PUBKEY_RE.test(key)) {
    throw new OnboardError(`Not a valid OpenSSH public key line: ${key.slice(0, 40)}…`);
  }
  // from= restricts where the key may connect from — for a self-managed
  // gateway host this shrinks the fleet key's blast radius to local sockets.
  const line = opts.localhostOnly ? `${LOCALHOST_FROM} ${key}` : key;
  const sshDir = join(home, ".ssh");
  const akPath = join(sshDir, "authorized_keys");
  const existing = existsSync(akPath) ? readFileSync(akPath, "utf8") : "";
  // Same key = same type + base64 blob; the comment and options do not matter.
  const blob = key.split(/\s+/).slice(0, 2).join(" ");
  const lines = existing.split("\n");
  const parsed = lines.map((l) => parseAuthorizedKeyLine(l.trim()));
  const idx = parsed.findIndex((p) => p !== undefined && (p.key === blob || p.key.startsWith(`${blob} `)));
  const write = (text: string) => {
    if (opts.dryRun) return;
    mkdirSync(sshDir, { recursive: true });
    chmodSync(sshDir, 0o700);
    writeFileSync(akPath, text, { mode: 0o600 });
    chmodSync(akPath, 0o600);
  };
  if (idx >= 0) {
    const { options, key: rest } = parsed[idx]!;
    // Only the exact localhost list counts: from="10.0.0.0/8" or from="*" is not "localhost only".
    const restricted = options.some((o) => o === LOCALHOST_FROM);
    // Never loosen an existing restriction; only tighten when asked (other options such as command= are kept).
    if (opts.localhostOnly && !restricted) {
      const kept = options.filter((o) => !/^from=/i.test(o));
      const tightened = `${[LOCALHOST_FROM, ...kept].join(",")} ${rest}`;
      write(lines.map((l, i) => (i === idx ? tightened : l)).join("\n"));
      return { authorizedKeysPath: akPath, appended: false, tightened: true, restricted: true };
    }
    return { authorizedKeysPath: akPath, appended: false, tightened: false, restricted };
  }
  const prefix = existing === "" || existing.endsWith("\n") ? existing : existing + "\n";
  write(`${prefix}${line}\n`);
  return { authorizedKeysPath: akPath, appended: true, tightened: false, restricted: Boolean(opts.localhostOnly) };
}

/**
 * Learn a server's host key without authenticating: the handshake runs up to
 * host-key verification and is then aborted. Lets a password first contact
 * check the key against known_hosts BEFORE the password is ever sent.
 * Uses the same algorithm preference as the real transport, so the scanned
 * key is the one later connections will see.
 */
export async function scanHostKey(
  server: Pick<ServerConfig, "host" | "port" | "user" | "allowLegacyAlgorithms" | "hostKeyAlgorithm" | "via">,
  timeoutMs = 15_000,
  opts: { fleet?: ServerConfig[] } = {},
): Promise<{ fingerprint: string; type?: string; authMethods?: string[] }> {
  // Behind a jump host the scan runs through a tunnel, so the target's key is
  // verified before any credential travels to it.
  let tunnel: SshTransport | undefined;
  let sock: ClientChannel | undefined;
  if (server.via) {
    tunnel = new SshTransport(new Map((opts.fleet ?? []).map((s) => [s.name, s])));
    try {
      sock = await tunnel.openTunnel(server.via, server.host, server.port);
    } catch (err) {
      await tunnel.close();
      const reason = err instanceof Error ? err.message : String(err);
      throw new OnboardError(`Could not reach ${server.host}:${server.port} through "${server.via}": ${reason}`, "unreachable", {
        host: server.host,
        port: server.port,
        reason,
      });
    }
  }
  try {
    return await new Promise((resolve, reject) => {
      const conn = new Client();
      let found: { fingerprint: string; type?: string; authMethods?: string[] } | undefined;
      let reason = "timed out";
      const finish = () => {
        clearTimeout(timer);
        conn.end();
        if (found) resolve(found);
        else {
          reject(
            new OnboardError(`Could not read the host key of ${server.host}:${server.port}: ${reason}`, "unreachable", {
              host: server.host,
              port: server.port,
              reason,
            }),
          );
        }
      };
      const timer = setTimeout(finish, timeoutMs);
      conn.once("error", (err: Error & { code?: string }) => {
        reason = err.code ?? err.message;
        finish();
      });
      conn.once("close", finish);
      const strict = effectiveAlgorithms(true, server.allowLegacyAlgorithms);
      const algorithms = server.hostKeyAlgorithm
        ? { ...(strict ?? {}), serverHostKey: hostKeyAlgorithmsFor(server.hostKeyAlgorithm, server.allowLegacyAlgorithms) }
        : strict;
      conn.connect({
        ...(sock ? { sock } : { host: server.host, port: server.port }),
        username: server.user,
        readyTimeout: timeoutMs,
        ...(algorithms ? { algorithms: algorithms as ConnectConfig["algorithms"] } : {}),
        hostVerifier: (key: Buffer) => {
          found = { fingerprint: `SHA256:${createHash("sha256").update(key).digest("hex")}`, type: hostKeyBlobType(key) };
          return true;
        },
        // Only the anonymous "none" method is ever sent: the server answers with
        // the methods it accepts (does it take passwords at all?), and we stop.
        // No credential leaves this machine before the key is checked.
        authHandler: ((methodsLeft: string[] | null, _partial: boolean, next: (m: unknown) => void) => {
          if (methodsLeft === null) return next("none");
          if (found) found.authMethods = methodsLeft;
          return next(false);
        }) as unknown as ConnectConfig["authHandler"],
      });
    });
  } finally {
    await tunnel?.close();
  }
}
