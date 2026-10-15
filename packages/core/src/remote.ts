/**
 * Remote config pull: fetch the fleet TOML from an HTTP(S) URL and install it
 * locally — the "50 台机器改一处配置" answer for v1.0.
 *
 * Safety properties:
 * - the fetched text must fully validate (parseFleetConfig) before anything
 *   is written — a bad remote payload never reaches disk;
 * - the previous config is backed up next to the destination;
 * - the write is atomic (tmp file + rename) and forced to mode 0600;
 * - the bearer token comes from a named env var and is never logged.
 *
 * Git hosting works through raw-file URLs:
 *   GitHub:  https://raw.githubusercontent.com/<org>/<repo>/<ref>/fleet.toml
 *   GitLab:  https://gitlab.com/<org>/<repo>/-/raw/<ref>/fleet.toml
 */
import { chmodSync, copyFileSync, renameSync, writeFileSync } from "node:fs";
import { parseFleetConfig } from "./config.js";
import type { FleetConfig, RemoteConfig } from "./types.js";

export class RemoteConfigError extends Error {}

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_BYTES = 1_048_576; // a fleet config is kilobytes; 1MB is already absurd

/** Fetch remote TOML text. Throws RemoteConfigError on any failure. */
export async function fetchRemoteConfig(
  remote: RemoteConfig,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<string> {
  const headers: Record<string, string> = { accept: "text/plain, application/toml, */*" };
  if (remote.tokenEnv) {
    const token = process.env[remote.tokenEnv];
    if (!token) {
      throw new RemoteConfigError(
        `remote.tokenEnv names "${remote.tokenEnv}" but that env var is not set`,
      );
    }
    headers.authorization = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(remote.url, {
      headers,
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw new RemoteConfigError(
      `fetch ${remote.url} failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!res.ok) {
    throw new RemoteConfigError(`fetch ${remote.url} returned HTTP ${res.status}`);
  }
  const text = await res.text();
  if (text.length > MAX_BYTES) {
    throw new RemoteConfigError(`remote config is ${text.length} bytes (max ${MAX_BYTES})`);
  }
  return text;
}

export interface PullResult {
  /** Server names in the newly installed config. */
  servers: string[];
  bytes: number;
  /** Where the previous config was backed up (undefined when none existed). */
  backupPath?: string;
}

/**
 * Fetch, validate, and atomically install the remote config at destPath.
 * Throws before touching disk when the payload is invalid.
 */
export async function pullConfigToFile(
  remote: RemoteConfig,
  destPath: string,
): Promise<PullResult> {
  return installConfigText(await fetchRemoteConfig(remote), destPath);
}

/**
 * Validate, back up the current file and atomically install already-fetched
 * config text — so a caller can show the diff, get approval, and install
 * exactly the bytes that were approved.
 */
export function installConfigText(text: string, destPath: string): PullResult {
  // Validate fully (schema + cross-references) before anything hits disk.
  const cfg = parseFleetConfig(text);

  let backupPath: string | undefined;
  try {
    backupPath = `${destPath}.bak-${new Date().toISOString().replace(/[:.]/g, "-")}`;
    copyFileSync(destPath, backupPath);
    chmodSync(backupPath, 0o600);
  } catch {
    backupPath = undefined; // no previous config — first install
  }

  const tmp = `${destPath}.tmp-${process.pid}`;
  try {
    writeFileSync(tmp, text, "utf8");
    chmodSync(tmp, 0o600);
    renameSync(tmp, destPath); // atomic on POSIX
  } catch (err) {
    throw new RemoteConfigError(
      `write ${destPath} failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return { servers: cfg.servers.map((s) => s.name), bytes: text.length, backupPath };
}

/** Human summary of what replacing `before` with `after` changes — for approval prompts. */
export function describeFleetChange(before: FleetConfig | undefined, after: FleetConfig): string[] {
  const old = new Map((before?.servers ?? []).map((s) => [s.name, s]));
  const next = new Map(after.servers.map((s) => [s.name, s]));
  const lines: string[] = [];
  for (const [name, s] of next) {
    const prev = old.get(name);
    if (!prev) {
      lines.push(`+ add ${name}: ${s.user}@${s.host}:${s.port} tier=${s.group} role=${s.role}`);
      continue;
    }
    const changes: string[] = [];
    // Every field, scopes and keyRef included: dropping a scope must be visible.
    const fields = new Set([...Object.keys(prev), ...Object.keys(s)]);
    fields.delete("name");
    for (const field of fields) {
      const a = (prev as unknown as Record<string, unknown>)[field];
      const b = (s as unknown as Record<string, unknown>)[field];
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        changes.push(`${field === "group" ? "tier" : field} ${JSON.stringify(a ?? null)} → ${JSON.stringify(b ?? null)}`);
      }
    }
    if (changes.length) lines.push(`~ change ${name}: ${changes.join(", ")}`);
  }
  for (const name of old.keys()) if (!next.has(name)) lines.push(`- remove ${name}`);
  if (JSON.stringify(before?.defaults) !== JSON.stringify(after.defaults)) lines.push("~ [defaults] changed (approval mode, quotas, ...)");
  if (JSON.stringify(before?.policy) !== JSON.stringify(after.policy)) lines.push("~ [policy] changed");
  if (JSON.stringify(before?.remote) !== JSON.stringify(after.remote)) {
    lines.push(`~ [remote] ${JSON.stringify(before?.remote?.url ?? null)} → ${JSON.stringify(after.remote?.url ?? null)}`);
  }
  if (JSON.stringify(before?.groups) !== JSON.stringify(after.groups)) lines.push("~ [[groups]] changed");
  return lines.length ? lines : ["(no effective change)"];
}
