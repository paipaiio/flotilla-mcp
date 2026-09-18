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
import { SshTransport } from "./ssh.js";
import { parseFleetConfig } from "./config.js";
import type { ServerConfig } from "./types.js";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export class OnboardError extends Error {}

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
export function buildKeyInstallCommand(publicKey: string): string {
  const key = publicKey.trim();
  if (!PUBKEY_RE.test(key)) {
    throw new OnboardError(`Not a valid OpenSSH public key line: ${key.slice(0, 40)}…`);
  }
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
 * The password is handed to the transport through the sanctioned env channel
 * (process-local FLOTILLA_<NAME>_PASSWORD), never through argv, and is scrubbed
 * from the environment afterwards.
 */
export async function bootstrapKey(
  server: ServerConfig, // name/host/port/user; auth is forced to password here
  password: string,
  publicKey: string,
): Promise<BootstrapResult> {
  const slug = server.name.toUpperCase().replace(/[^A-Z0-9]/g, "_");
  const envName = `FLOTILLA_${slug}_PASSWORD`;
  const previous = process.env[envName];
  process.env[envName] = password;
  const asPassword: ServerConfig = { ...server, auth: "password", keyRef: undefined };
  const transport = new SshTransport(new Map([[server.name, asPassword]]));
  try {
    const install = await transport.exec(asPassword, buildKeyInstallCommand(publicKey), {
      timeoutMs: 20_000,
    });
    if (!install.ok || !install.stdout.includes("INSTALLED")) {
      return {
        ok: false,
        error: install.error ?? install.stderr.trim() ?? "key install failed",
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
    if (previous === undefined) delete process.env[envName];
    else process.env[envName] = previous;
  }
}


export interface ProbeResult {
  ok: boolean;
  hostname?: string;
  uid?: number;
  tmux?: boolean;
  /** Pinned host key in "SHA256:..." form, ready for trustedHostKey. */
  hostKey?: string;
  error?: string;
}

export async function probeServer(server: ServerConfig): Promise<ProbeResult> {
  const transport = new SshTransport(new Map([[server.name, server]]));
  try {
    const host = await transport.exec(server, "hostname", { timeoutMs: 15_000 });
    if (!host.ok) {
      return { ok: false, error: host.error ?? host.stderr.trim() ?? "hostname probe failed" };
    }
    const uid = await transport.exec(server, "id -u", { timeoutMs: 10_000 });
    const tmux = await transport.exec(server, "command -v tmux >/dev/null 2>&1 && echo yes || echo no", {
      timeoutMs: 10_000,
    });
    return {
      ok: true,
      hostname: host.stdout.trim(),
      uid: uid.ok ? Number(uid.stdout.trim()) : undefined,
      tmux: tmux.stdout.trim() === "yes",
      hostKey: transport.hostKeyOf(server.name),
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
  lines.push(`group = ${tomlStr(s.group)}`);
  if (s.tags.length > 0) lines.push(`tags = [${s.tags.map(tomlStr).join(", ")}]`);
  lines.push(`role = ${tomlStr(s.role)}`);
  if (s.readOnly) lines.push(`readOnly = true`);
  if (s.workdir) lines.push(`workdir = ${tomlStr(s.workdir)}`);
  if (s.via) lines.push(`via = ${tomlStr(s.via)}`);
  if (s.trustedHostKey) lines.push(`trustedHostKey = ${tomlStr(s.trustedHostKey)}`);
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
export function installPublicKeyLocally(
  publicKey: string,
  home = homedir(),
): { authorizedKeysPath: string; appended: boolean } {
  const key = publicKey.trim();
  if (!PUBKEY_RE.test(key)) {
    throw new OnboardError(`Not a valid OpenSSH public key line: ${key.slice(0, 40)}…`);
  }
  const sshDir = join(home, ".ssh");
  mkdirSync(sshDir, { recursive: true });
  chmodSync(sshDir, 0o700);
  const akPath = join(sshDir, "authorized_keys");
  const existing = existsSync(akPath) ? readFileSync(akPath, "utf8") : "";
  if (existing.split("\n").some((line) => line.trim() === key)) {
    return { authorizedKeysPath: akPath, appended: false };
  }
  const prefix = existing === "" || existing.endsWith("\n") ? existing : existing + "\n";
  writeFileSync(akPath, `${prefix}${key}\n`, { mode: 0o600 });
  chmodSync(akPath, 0o600);
  return { authorizedKeysPath: akPath, appended: true };
}
