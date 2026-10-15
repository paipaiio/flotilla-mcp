/**
 * Scoped gateway tokens: many bearer tokens, each with a role ceiling and an
 * optional target allowlist, next to the one full-power admin token.
 *
 * The file holds only SHA-256 hashes (a leaked file grants nothing) and is
 * written 0600. It is re-read whenever its mtime changes, so creating or
 * revoking a token takes effect on the next request without a restart.
 * Scoped tokens reach /mcp only; operator routes (enrollment management,
 * audit export) stay behind the admin token.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";

export type TokenRole = "viewer" | "operator" | "admin";

export interface ScopedToken {
  name: string;
  /** Hex SHA-256 of the token; the plaintext is never stored. */
  sha256: string;
  maxRole: TokenRole;
  /** Target expressions this token may see; omitted = whole fleet. */
  targets?: string[];
  createdAt?: string;
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ROLES: TokenRole[] = ["viewer", "operator", "admin"];

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function validate(raw: unknown, path: string): ScopedToken[] {
  const fail = (why: string): never => {
    throw new Error(`Invalid gateway tokens file ${path}: ${why}`);
  };
  const list = (raw as { tokens?: unknown })?.tokens;
  if (!Array.isArray(list)) fail('expected {"tokens": [...]}');
  const names = new Set<string>();
  return (list as unknown[]).map((item, i) => {
    const t = item as Record<string, unknown>;
    if (typeof t.name !== "string" || !NAME_RE.test(t.name)) fail(`tokens[${i}].name is invalid`);
    if (names.has(t.name as string)) fail(`duplicate token name "${t.name}"`);
    names.add(t.name as string);
    if (typeof t.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(t.sha256)) fail(`tokens[${i}].sha256 must be 64 hex chars`);
    if (!ROLES.includes(t.maxRole as TokenRole)) fail(`tokens[${i}].maxRole must be viewer|operator|admin`);
    if (t.targets !== undefined && !(Array.isArray(t.targets) && t.targets.every((x) => typeof x === "string" && x.length > 0))) {
      fail(`tokens[${i}].targets must be a list of target expressions`);
    }
    return {
      name: t.name as string,
      sha256: t.sha256 as string,
      maxRole: t.maxRole as TokenRole,
      ...(t.targets !== undefined ? { targets: t.targets as string[] } : {}),
      ...(typeof t.createdAt === "string" ? { createdAt: t.createdAt } : {}),
    };
  });
}

export function listTokens(path: string): ScopedToken[] {
  if (!existsSync(path)) return [];
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`Invalid gateway tokens file ${path}: not valid JSON`);
  }
  return validate(raw, path);
}

/** Write-then-rename so a concurrently reloading gateway never sees a torn file. */
function save(path: string, tokens: ScopedToken[]): void {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  writeFileSync(tmp, JSON.stringify({ tokens }, null, 2) + "\n", { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

/** Create a token; the plaintext is returned exactly once. */
export function addToken(
  path: string,
  spec: { name: string; maxRole: TokenRole; targets?: string[] },
): { token: string; entry: ScopedToken } {
  if (!NAME_RE.test(spec.name)) throw new Error(`Invalid token name "${spec.name}"`);
  if (!ROLES.includes(spec.maxRole)) throw new Error(`Invalid role "${spec.maxRole}"`);
  if (spec.targets !== undefined && (spec.targets.length === 0 || spec.targets.some((t) => !t.trim()))) {
    // An empty list must never silently become "whole fleet".
    throw new Error("targets was given but is empty — omit it for whole-fleet access");
  }
  const tokens = listTokens(path);
  if (tokens.some((t) => t.name === spec.name)) throw new Error(`Token "${spec.name}" already exists — revoke it first`);
  const token = `flt_gw_${randomBytes(32).toString("base64url")}`;
  const entry: ScopedToken = {
    name: spec.name,
    sha256: hashToken(token),
    maxRole: spec.maxRole,
    ...(spec.targets !== undefined ? { targets: spec.targets } : {}),
    createdAt: new Date().toISOString(),
  };
  save(path, [...tokens, entry]);
  return { token, entry };
}

export function revokeToken(path: string, name: string): boolean {
  const tokens = listTokens(path);
  const next = tokens.filter((t) => t.name !== name);
  if (next.length === tokens.length) return false;
  save(path, next);
  return true;
}

export interface TokenStore {
  /** The scoped token a presented bearer value belongs to, if any. */
  match(presented: string): ScopedToken | undefined;
}

/** File-backed store; reloads when the file's mtime/size change. */
export function createTokenStore(path: string): TokenStore {
  let stamp = "";
  let cached: ScopedToken[] = [];
  const current = (): ScopedToken[] => {
    if (!existsSync(path)) {
      stamp = "";
      cached = [];
      return cached;
    }
    const st = statSync(path);
    const next = `${st.mtimeMs}:${st.size}:${st.ino}`;
    if (next !== stamp) {
      cached = listTokens(path);
      stamp = next;
    }
    return cached;
  };
  return {
    match(presented) {
      const digest = Buffer.from(hashToken(presented), "hex");
      let found: ScopedToken | undefined;
      // Compare against every entry (no early exit) in constant time per entry.
      for (const t of current()) {
        if (timingSafeEqual(digest, Buffer.from(t.sha256, "hex"))) found = t;
      }
      return found;
    },
  };
}
