/**
 * Audit logging (§6.4 layer 1): local append-only JSONL.
 *
 * Every policy decision, approval outcome, and execution result is recorded.
 * Three-layer redaction before anything hits disk:
 *   1. field names whose values are always dropped (password, token, ...)
 *   2. regex patterns (env-style KEY=value, bearer tokens, PEM blocks)
 *   3. optional entropy scan for high-entropy tokens in strings
 *
 * Hash chain (default on): each record carries prevHash and
 * hash = sha256(prevHash + canonical JSON). Deleting or rewriting a line
 * breaks the chain from that point on — verifyChain() detects it.
 */
import { appendFileSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { defaultConfigPath } from "./config.js";

export type AuditKind = "decision" | "approval" | "execution";

export interface AuditEvent {
  kind: AuditKind;
  tool: string;
  /** Config server names, never raw IPs. */
  hosts?: string[];
  command?: string;
  commandClass?: string;
  /** allow | deny | approved | refused | ok | failed */
  outcome: string;
  reason?: string;
  /** human-elicitation | confirm-flag | policy */
  approver?: string;
  /** Execution aggregates — never raw stdout/stderr. */
  results?: { total: number; succeeded: number; failed: number; skipped: number };
  durationMs?: number;
}

interface AuditRecord extends AuditEvent {
  ts: string;
  seq: number;
  prevHash: string;
  hash: string;
}

const REDACTED = "<redacted>";

/** Layer 1: object keys whose values never reach disk. */
const SECRET_KEYS = /password|passwd|secret|token|apikey|api[-_]?key|private[-_]?key|credential/i;

/** Layer 2: secret-shaped substrings inside free text. */
const SECRET_PATTERNS: RegExp[] = [
  /\b[A-Za-z_][A-Za-z0-9_]*(PASSWORD|PASSWD|TOKEN|SECRET|API[-_]?KEY)[A-Za-z0-9_]*\s*=\s*\S+/gi, // KEY=value
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[^]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(sshpass\s+-p|password=)\s*\S+/gi,
];

function redactString(s: string, entropyScan: boolean): string {
  let out = s;
  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, REDACTED);
  }
  if (entropyScan) out = redactHighEntropy(out);
  return out;
}

/** Layer 3: long high-entropy tokens (likely keys/tokens) in free text. */
function redactHighEntropy(s: string): string {
  return s.replace(/\b[A-Za-z0-9+/=_-]{32,}\b/g, (tok) =>
    shannon(tok) >= 4.0 ? REDACTED : tok,
  );
}

function shannon(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function redactValue(value: unknown, entropyScan: boolean): unknown {
  if (typeof value === "string") return redactString(value, entropyScan);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, entropyScan));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEYS.test(k) ? REDACTED : redactValue(v, entropyScan);
    }
    return out;
  }
  return value;
}

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

export class AuditLogger {
  private seq = 0;
  private prevHash = "GENESIS";
  private readonly entropyScan: boolean;
  private readonly hashChain: boolean;

  constructor(
    readonly path: string,
    opts: { hashChain?: boolean; entropyScan?: boolean } = {},
  ) {
    this.hashChain = opts.hashChain ?? true;
    this.entropyScan = opts.entropyScan ?? false;
    mkdirSync(dirname(path), { recursive: true });
    // Resume the chain across restarts: the last record's hash is the anchor.
    try {
      const existing = readFileSync(path, "utf8").trim().split("\n").filter(Boolean);
      if (existing.length > 0) {
        const last = JSON.parse(existing[existing.length - 1]!) as AuditRecord;
        this.seq = last.seq;
        this.prevHash = last.hash;
      }
    } catch {
      /* fresh log */
    }
  }

  /** Append one event. Never throws — audit must not break operations. */
  log(event: AuditEvent): void {
    try {
      const redacted = redactValue(event, this.entropyScan) as AuditEvent;
      const base = {
        ts: new Date().toISOString(),
        seq: this.seq + 1,
        prevHash: this.hashChain ? this.prevHash : "",
        ...redacted,
      };
      const hash = this.hashChain ? sha256(base.prevHash + JSON.stringify(base)) : "";
      const record: AuditRecord = { ...base, hash };
      appendFileSync(this.path, JSON.stringify(record) + "\n", "utf8");
      this.seq = base.seq;
      if (this.hashChain) this.prevHash = hash;
    } catch {
      /* audit write failure must never break the operation being audited */
    }
  }

  /** Verify the on-disk chain. Returns the first broken seq, or null. */
  static verifyChain(path: string): { ok: boolean; brokenAt?: number; total: number } {
    let lines: string[];
    try {
      lines = readFileSync(path, "utf8").trim().split("\n").filter(Boolean);
    } catch {
      return { ok: false, total: 0 };
    }
    let prevHash = "GENESIS";
    for (const line of lines) {
      const rec = JSON.parse(line) as AuditRecord;
      if (rec.prevHash !== prevHash) return { ok: false, brokenAt: rec.seq, total: lines.length };
      const { hash, ...rest } = rec;
      if (hash !== sha256(prevHash + JSON.stringify(rest))) {
        return { ok: false, brokenAt: rec.seq, total: lines.length };
      }
      prevHash = hash;
    }
    return { ok: true, total: lines.length };
  }
}

/** Default audit path next to the config file. */
export function defaultAuditPath(configPath?: string): string {
  return join(dirname(resolve(configPath ?? defaultConfigPath())), "audit.jsonl");
}

/** Resolve an explicit audit path relative to its config file, or use the platform default. */
export function resolveAuditPath(configPath: string, configuredPath?: string): string {
  if (!configuredPath) return defaultAuditPath(configPath);
  return isAbsolute(configuredPath) ? configuredPath : resolve(dirname(resolve(configPath)), configuredPath);
}

/** File size guard used by callers that warn about unbounded growth. */
export function auditFileSize(path: string): number {
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}
