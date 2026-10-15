/**
 * OpenSSH client config integration: reuse what `ssh <alias>` already knows.
 *
 * Effective settings come from `ssh -G <alias>` rather than a hand-rolled
 * parser — OpenSSH itself resolves Include, Match, wildcards and defaults,
 * so Flotilla sees exactly what the user's ssh sees. Host keys come from the
 * user's known_hosts via `ssh-keygen -F`, which also handles hashed entries,
 * so an imported server is pinned against a key the user already trusted
 * instead of trust-on-first-use.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";

/** Runs a program with argv (never a shell); returns stdout, throws on non-zero exit. */
export type CommandRunner = (file: string, args: string[]) => string;

export const defaultRunner: CommandRunner = (file, args) =>
  execFileSync(file, args, { encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "pipe"] });

export interface SshEffectiveConfig {
  alias: string;
  hostname: string;
  user: string;
  port: number;
  /** Candidate private keys in OpenSSH order, tokens expanded; may not exist. */
  identityFiles: string[];
  /** IdentityAgent value ("SSH_AUTH_SOCK", "none", or a socket path). */
  identityAgent?: string;
  /** IdentitiesOnly yes: OpenSSH would not offer arbitrary agent keys. */
  identitiesOnly?: boolean;
  proxyJump?: string;
  proxyCommand?: string;
  hostKeyAlias?: string;
  knownHostsFiles: string[];
}

/** Aliases become a single ssh argv entry: no option injection, no spaces. */
const ALIAS_RE = /^[A-Za-z0-9_.@%:+[\]][A-Za-z0-9_.@%:+[\]-]*$/;

export function assertSafeAlias(alias: string): void {
  if (!ALIAS_RE.test(alias)) {
    throw new Error(`Invalid ssh host alias "${alias}" (letters, digits, . _ - @ : only; must not start with "-")`);
  }
}

interface ExpandContext {
  home: string;
  localUser: string;
  remoteUser?: string;
  hostname?: string;
}

/** Expand ~ and the common ssh_config tokens; undefined when an unsupported token remains. */
function expandPath(raw: string, ctx: ExpandContext): string | undefined {
  let out = raw.replace(/^~(?=$|\/)/, ctx.home);
  let unsupported = false;
  out = out.replace(/%(.)/g, (_m, t: string) => {
    switch (t) {
      case "%": return "%";
      case "d": return ctx.home;
      case "u": return ctx.localUser;
      case "r": return ctx.remoteUser ?? (unsupported = true, "");
      case "h": return ctx.hostname ?? (unsupported = true, "");
      default:
        unsupported = true;
        return "";
    }
  });
  return unsupported ? undefined : out;
}

/** Parse `ssh -G` output (lowercase "key value" lines). */
export function parseSshG(
  alias: string,
  output: string,
  env: { home?: string; localUser?: string } = {},
): SshEffectiveConfig {
  const home = env.home ?? homedir();
  const localUser = env.localUser ?? userInfo().username;
  const single = new Map<string, string>();
  const identityRaw: string[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const space = trimmed.indexOf(" ");
    if (space < 0) continue;
    const key = trimmed.slice(0, space).toLowerCase();
    const value = trimmed.slice(space + 1).trim();
    if (key === "identityfile") identityRaw.push(value);
    else if (!single.has(key)) single.set(key, value);
  }
  const unset = (v: string | undefined) => (v === undefined || v === "none" ? undefined : v);
  const hostname = single.get("hostname") ?? alias;
  const user = single.get("user") ?? localUser;
  const ctx: ExpandContext = { home, localUser, remoteUser: user, hostname };
  const port = Number(single.get("port") ?? "22");
  return {
    alias,
    hostname,
    user,
    port: Number.isInteger(port) && port > 0 ? port : 22,
    identityFiles: identityRaw.map((p) => expandPath(p, ctx)).filter((p): p is string => p !== undefined),
    identityAgent: single.get("identityagent"),
    identitiesOnly: single.get("identitiesonly") === "yes",
    proxyJump: unset(single.get("proxyjump")),
    proxyCommand: unset(single.get("proxycommand")),
    hostKeyAlias: unset(single.get("hostkeyalias")),
    knownHostsFiles: (single.get("userknownhostsfile") ?? "~/.ssh/known_hosts")
      .split(/\s+/)
      .filter(Boolean)
      .map((p) => expandPath(p, ctx))
      .filter((p): p is string => p !== undefined && p !== "/dev/null"),
  };
}

/**
 * Effective OpenSSH settings for one alias (or raw host), via `ssh -G`.
 * `configFile` (e.g. FLOTILLA_SSH_CONFIG) replaces ~/.ssh/config; note that
 * OpenSSH then also skips /etc/ssh/ssh_config, so it is only passed when set.
 */
export function resolveSshHost(
  alias: string,
  run: CommandRunner = defaultRunner,
  configFile?: string,
): SshEffectiveConfig {
  assertSafeAlias(alias);
  // A configured-but-missing file means "no ssh config", not an ssh error.
  const file = configFile && !existsSync(configFile) ? "/dev/null" : configFile;
  return parseSshG(alias, run("ssh", ["-G", ...(file ? ["-F", file] : []), alias]));
}

function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`);
}

/** Expand one Include argument (relative to ~/.ssh) into existing files. */
function includeTargets(arg: string, home: string): string[] {
  const expanded = arg.replace(/^~(?=$|\/)/, home);
  const full = isAbsolute(expanded) ? expanded : join(home, ".ssh", expanded);
  if (!/[*?]/.test(basename(full))) return existsSync(full) ? [full] : [];
  const dir = dirname(full);
  if (!existsSync(dir)) return [];
  const re = globToRegExp(basename(full));
  return readdirSync(dir).filter((f) => re.test(f)).sort().map((f) => join(dir, f));
}

/**
 * Concrete Host aliases from an ssh_config file, in file order with Include
 * followed in place. Patterns (*, ?) and negations are skipped: they describe
 * settings, not machines.
 */
export function listSshConfigAliases(
  configPath: string = join(homedir(), ".ssh", "config"),
  home: string = homedir(),
): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const visit = (path: string, depth: number) => {
    if (depth > 8 || !existsSync(path)) return;
    for (const raw of readFileSync(path, "utf8").split("\n")) {
      const line = raw.replace(/#.*/, "").trim();
      const m = /^(\w+)\s*(?:=|\s)\s*(.+)$/.exec(line);
      if (!m) continue;
      const keyword = m[1]!.toLowerCase();
      const args = m[2]!.split(/\s+/).map((a) => a.replace(/^"(.*)"$/, "$1"));
      if (keyword === "include") {
        for (const arg of args) for (const target of includeTargets(arg, home)) visit(target, depth + 1);
      } else if (keyword === "host") {
        for (const alias of args) {
          if (/[*?!]/.test(alias) || seen.has(alias) || !ALIAS_RE.test(alias)) continue;
          seen.add(alias);
          out.push(alias);
        }
      }
    }
  };
  visit(configPath, 0);
  return out;
}

/** Fingerprint in the transport's pin format ("SHA256:<hex>") from a base64 key blob. */
export function fingerprintFromKeyBlob(base64Blob: string): string {
  return `SHA256:${createHash("sha256").update(Buffer.from(base64Blob, "base64")).digest("hex")}`;
}

/**
 * Compare a configured pin with the transport's hex digest. Pins may be the
 * hex form Flotilla writes or the base64 form `ssh-keygen -l` prints, so a
 * fingerprint copied from OpenSSH output works as-is.
 */
export function hostKeyMatches(pinned: string, hexDigest: string): boolean {
  const value = pinned.startsWith("SHA256:") ? pinned.slice("SHA256:".length) : pinned;
  if (value === hexDigest) return true;
  const b64 = Buffer.from(hexDigest, "hex").toString("base64").replace(/=+$/, "");
  return value.replace(/=+$/, "") === b64;
}

export interface KnownHostKey {
  /** Key algorithm from known_hosts, e.g. "ssh-ed25519". */
  type?: string;
  /** "SHA256:<hex>", the transport's pin format. */
  fingerprint: string;
}

/**
 * Host keys the user already trusts for host:port, from their known_hosts
 * files. Empty when there is no entry (or ssh-keygen is missing).
 * @revoked / @cert-authority lines are never treated as trusted keys.
 */
export function knownHostKeys(
  host: string,
  port: number,
  files: string[],
  run: CommandRunner = defaultRunner,
): KnownHostKey[] {
  const lookup = port === 22 ? host : `[${host}]:${port}`;
  const out = new Map<string, KnownHostKey>();
  for (const file of files) {
    let text: string;
    try {
      text = run("ssh-keygen", ["-F", lookup, "-f", file]);
    } catch {
      continue; // exit 1 = no entry; a missing file is the same answer
    }
    for (const line of text.split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#") || t.startsWith("@")) continue;
      const parts = t.split(/\s+/);
      if (parts.length >= 3 && /^[A-Za-z0-9+/=]+$/.test(parts[2]!)) {
        const fingerprint = fingerprintFromKeyBlob(parts[2]!);
        out.set(fingerprint, { type: parts[1], fingerprint });
      }
    }
  }
  return [...out.values()];
}

/** Fingerprints only — see knownHostKeys. */
export function knownHostFingerprints(
  host: string,
  port: number,
  files: string[],
  run: CommandRunner = defaultRunner,
): string[] {
  return knownHostKeys(host, port, files, run).map((k) => k.fingerprint);
}

export type HostKeyVerdict = "verified" | "mismatch" | "unknown";

/**
 * Compare a live host key with known_hosts. Only entries of the same key type
 * are comparable: a server offering ed25519 while known_hosts holds only its
 * ecdsa key is "unknown" (TOFU), not a mismatch. Entries without a type
 * compare against everything.
 */
export function checkHostKeyAgainstKnown(
  live: { fingerprint?: string; type?: string },
  known: Array<string | KnownHostKey>,
): HostKeyVerdict {
  const entries = known.map((k) => (typeof k === "string" ? { fingerprint: k } : k));
  const comparable = entries.filter((k) => !k.type || !live.type || k.type === live.type);
  if (comparable.length === 0) return "unknown";
  return live.fingerprint && comparable.some((k) => k.fingerprint === live.fingerprint) ? "verified" : "mismatch";
}
