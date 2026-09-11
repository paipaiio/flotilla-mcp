/**
 * Server-to-server operations: relay copy, directory sync, and cross-host
 * file comparison.
 *
 * All data flows through the control machine's memory (SFTP read piped into
 * SFTP write) — never through local disk, and servers never need to trust or
 * even reach each other. The control machine is the audit and policy point;
 * that is a deliberate security posture, not a limitation.
 *
 * Policy (see checkRelayPolicy):
 * - the SOURCE path must pass the source server's scopes.paths (read side);
 * - the DEST path must pass the dest server's scopes.paths, the dest must not
 *   be readOnly, and its role/tier must permit the destructive class (a relay
 *   overwrites);
 * - cross-tier transfers (src.group !== dst.group, e.g. dev -> prod) ALWAYS
 *   require approval, whatever the approvalMode;
 * - sync removals (the --delete semantic) are destructive and always gated.
 */
import { join as posixJoin } from "node:path/posix";
import { checkPathScope, decide } from "./policy.js";
import type {
  ApprovalMode,
  ExecOptions,
  RelayResult,
  ServerConfig,
  Transport,
} from "./types.js";

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

// ── path probing & checksum commands (fleet-diff-file) ──

export type PathKind = "file" | "dir" | "missing";

/** Read-only probe that prints "dir", "file", or "missing" for a path. */
export function buildPathKindProbe(remotePath: string): string {
  const q = shellQuote(remotePath);
  return `if [ -d ${q} ]; then echo dir; elif [ -f ${q} ]; then echo file; else echo missing; fi`;
}

export function parsePathKind(stdout: string): PathKind {
  const t = stdout.trim();
  if (t === "dir" || t === "file") return t;
  return "missing";
}

/**
 * Checksum command whose stdout is compared across hosts. Built by the tool
 * from a shell-quoted path — never user-supplied shell. Directory mode hashes
 * every regular file with paths relative to the directory, so output is
 * comparable across hosts even when the absolute location differs.
 */
export function buildChecksumCommand(remotePath: string, kind: "file" | "dir"): string {
  const q = shellQuote(remotePath);
  if (kind === "file") return `sha256sum -- ${q}`;
  return `cd ${q} && find . -type f -exec sha256sum {} + 2>/dev/null | sort -k2`;
}

// ── checksum parsing & sync planning ──

export interface ChecksumEntry {
  /** Path as printed by sha256sum ("./app.js" in dir mode). */
  path: string;
  sha256: string;
}

export function parseChecksums(stdout: string): ChecksumEntry[] {
  const out: ChecksumEntry[] = [];
  for (const line of stdout.split("\n")) {
    const m = line.match(/^([0-9a-f]{64}) [ *](.+)$/);
    if (m) out.push({ sha256: m[1]!, path: m[2]!.trimEnd() });
  }
  return out;
}

/** Strip the leading "./" that dir-mode checksums carry. */
export function relPath(p: string): string {
  return p.startsWith("./") ? p.slice(2) : p;
}

export interface SyncPlan {
  /** Relative paths to relay src -> dst (missing or changed on dst). */
  copy: string[];
  /** Relative paths to remove on dst. Empty unless allowDelete. */
  remove: string[];
  /** Files already identical on both sides. */
  unchanged: number;
}

/** Pure diff of two checksum listings — the rsync brain of fleet-sync. */
export function planSync(
  src: ChecksumEntry[],
  dst: ChecksumEntry[],
  allowDelete: boolean,
): SyncPlan {
  const dstHash = new Map(dst.map((e) => [e.path, e.sha256]));
  const srcPaths = new Set(src.map((e) => e.path));
  const copy = src
    .filter((e) => dstHash.get(e.path) !== e.sha256)
    .map((e) => e.path)
    .sort();
  const remove = allowDelete
    ? dst
        .filter((e) => !srcPaths.has(e.path))
        .map((e) => e.path)
        .sort()
    : [];
  return { copy, remove, unchanged: src.length - copy.length };
}

// ── policy ──

export interface RelayPolicyDecision {
  refusals: string[];
  needsApproval: boolean;
  /** True when src and dest sit in different tiers (dev -> prod etc.). */
  crossTier: boolean;
}

/**
 * Both ends are checked, and the stricter side wins. A relay is a read on the
 * source and an overwrite on the destination, so the destination must permit
 * the destructive class. Cross-tier always requires approval.
 */
export function checkRelayPolicy(
  src: ServerConfig,
  srcPath: string,
  dst: ServerConfig,
  dstPath: string,
  approvalMode: ApprovalMode,
): RelayPolicyDecision {
  const refusals: string[] = [];

  const srcScope = checkPathScope(src, srcPath);
  if (srcScope) refusals.push(srcScope);

  if (dst.readOnly) refusals.push(`${dst.name}: server is configured readOnly`);
  const dstScope = checkPathScope(dst, dstPath);
  if (dstScope) refusals.push(dstScope);

  const destDecision = decide("rm -rf <relay-overwrite>", {
    role: dst.role,
    tier: dst.group,
    readOnly: dst.readOnly,
    approvalMode,
  });
  if (!destDecision.allowed) refusals.push(`${dst.name}: ${destDecision.reason}`);

  const crossTier = src.group !== dst.group;
  return {
    refusals,
    crossTier,
    needsApproval: crossTier || destDecision.needsApproval,
  };
}

// ── execution ──

/** Relay one file with transport errors folded into the result. */
export async function relayFile(
  transport: Transport,
  src: ServerConfig,
  srcPath: string,
  dst: ServerConfig,
  dstPath: string,
  opts: ExecOptions = {},
): Promise<RelayResult> {
  const started = Date.now();
  try {
    return await transport.relayCopy(src, srcPath, dst, dstPath, opts);
  } catch (err) {
    return {
      source: src.name,
      dest: dst.name,
      ok: false,
      bytes: 0,
      durationMs: Date.now() - started,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export interface SyncRunResult {
  copied: { path: string; bytes: number }[];
  removed: string[];
  failures: { path: string; error: string }[];
  totalBytes: number;
  durationMs: number;
}

/**
 * Apply a sync plan: relay each file in plan.copy with bounded concurrency,
 * then batch-remove plan.remove on the destination. Callers own the approval
 * gate — runSyncPlan assumes it has already been granted when plan.remove is
 * non-empty.
 */
export async function runSyncPlan(
  transport: Transport,
  src: ServerConfig,
  srcDir: string,
  dst: ServerConfig,
  dstDir: string,
  plan: SyncPlan,
  opts: ExecOptions & { concurrency?: number } = {},
): Promise<SyncRunResult> {
  const started = Date.now();
  const copied: SyncRunResult["copied"] = [];
  const removed: string[] = [];
  const failures: SyncRunResult["failures"] = [];

  // Copies: small concurrency pool over relayCopy.
  const lanes = Math.max(1, Math.min(opts.concurrency ?? 4, plan.copy.length));
  let cursor = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = cursor++;
      if (i >= plan.copy.length) return;
      const rel = relPath(plan.copy[i]!);
      const r = await relayFile(
        transport,
        src,
        posixJoin(srcDir, rel),
        dst,
        posixJoin(dstDir, rel),
        opts,
      );
      if (r.ok) copied.push({ path: rel, bytes: r.bytes });
      else failures.push({ path: rel, error: r.error ?? "relay failed" });
    }
  };
  await Promise.all(Array.from({ length: lanes }, () => worker()));

  // Removals: chunked rm on the destination (quoted, no glob expansion).
  const CHUNK = 50;
  for (let i = 0; i < plan.remove.length; i += CHUNK) {
    const chunk = plan.remove.slice(i, i + CHUNK);
    const cmd = `cd ${shellQuote(dstDir)} && rm -f -- ${chunk.map((p) => shellQuote(relPath(p))).join(" ")}`;
    try {
      const r = await transport.exec(dst, cmd, opts);
      if (r.ok) removed.push(...chunk.map(relPath));
      else failures.push(...chunk.map((p) => ({ path: relPath(p), error: r.stderr.trim() || "rm failed" })));
    } catch (err) {
      failures.push(
        ...chunk.map((p) => ({ path: relPath(p), error: err instanceof Error ? err.message : String(err) })),
      );
    }
  }

  return {
    copied,
    removed,
    failures,
    totalBytes: copied.reduce((n, c) => n + c.bytes, 0),
    durationMs: Date.now() - started,
  };
}

// ── rendering ──

export function formatRelay(r: RelayResult): string {
  const head = `relay ${r.source} -> ${r.dest}`;
  if (!r.ok) return `${head}\nFAIL: ${r.error}`;
  return `${head}\nOK: ${r.bytes} bytes in ${r.durationMs}ms`;
}

export function formatSyncPlan(srcDir: string, dstDir: string, plan: SyncPlan, dryRun: boolean): string {
  const lines = [
    `sync plan ${srcDir} -> ${dstDir}${dryRun ? "  (dry-run, nothing changed)" : ""}`,
    `copy: ${plan.copy.length}  remove: ${plan.remove.length}  unchanged: ${plan.unchanged}`,
  ];
  const show = (label: string, items: string[], max = 20) => {
    if (items.length === 0) return;
    lines.push(`\n${label}:`);
    for (const p of items.slice(0, max)) lines.push(`  ${relPath(p)}`);
    if (items.length > max) lines.push(`  ... and ${items.length - max} more`);
  };
  show("to copy", plan.copy);
  show("to remove", plan.remove);
  return lines.join("\n");
}

export function formatSyncResult(plan: SyncPlan, r: SyncRunResult): string {
  const lines = [
    `sync applied: copied=${r.copied.length} removed=${r.removed.length} unchanged=${plan.unchanged} failed=${r.failures.length}`,
    `transferred ${r.totalBytes} bytes in ${r.durationMs}ms`,
  ];
  if (r.failures.length > 0) {
    lines.push("\nfailures:");
    for (const f of r.failures.slice(0, 20)) lines.push(`  - ${f.path}: ${f.error}`);
    if (r.failures.length > 20) lines.push(`  ... and ${r.failures.length - 20} more`);
  }
  return lines.join("\n");
}
