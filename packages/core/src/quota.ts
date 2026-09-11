/**
 * Daily command quota (rolling 24h window) — the tripwire against a runaway
 * agent loop. When defaults.commandQuotaPerDay is set, every command-bearing
 * tool call (exec / exec-read / exec-sudo) consumes one unit; once the window
 * is full the call is refused before anything touches SSH.
 *
 * State lives in a tiny JSON file next to the config so the quota survives
 * MCP server restarts — an in-memory counter would reset exactly when the
 * loop-causing client reconnects. Writes are atomic (tmp + rename).
 *
 * Deliberately simple: one counter per control machine, not per server. The
 * threat model is "agent goes into a hot loop", not per-host fairness.
 */
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const WINDOW_MS = 24 * 60 * 60 * 1000;
/** Never keep more than this many timestamps on disk, whatever happens. */
const HARD_CAP = 100_000;

export interface QuotaStatus {
  /** Configured limit; 0/undefined means unlimited (quota disabled). */
  limit: number;
  /** Calls recorded inside the current 24h window. */
  used: number;
  allowed: boolean;
  /** When the oldest in-window call ages out (only meaningful when !allowed). */
  resetAtMs?: number;
}

export class QuotaCounter {
  private timestamps: number[] = [];
  private loaded = false;

  constructor(
    private readonly statePath: string,
    private readonly limit: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Quota disabled when limit is 0 or negative. */
  get enabled(): boolean {
    return this.limit > 0;
  }

  check(): QuotaStatus {
    if (!this.enabled) return { limit: 0, used: 0, allowed: true };
    this.load();
    this.prune();
    const used = this.timestamps.length;
    const allowed = used < this.limit;
    return {
      limit: this.limit,
      used,
      allowed,
      resetAtMs: allowed ? undefined : this.timestamps[0]! + WINDOW_MS,
    };
  }

  /** Record one consumed unit. No-op when the quota is disabled. */
  record(): void {
    if (!this.enabled) return;
    this.load();
    this.prune();
    this.timestamps.push(this.now());
    this.save();
  }

  private prune(): void {
    const cutoff = this.now() - WINDOW_MS;
    this.timestamps = this.timestamps.filter((t) => t > cutoff);
    if (this.timestamps.length > HARD_CAP) {
      this.timestamps = this.timestamps.slice(-HARD_CAP);
    }
  }

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const data = JSON.parse(readFileSync(this.statePath, "utf8"));
      if (Array.isArray(data?.t)) {
        this.timestamps = data.t.filter((x: unknown) => typeof x === "number" && Number.isFinite(x));
      }
    } catch {
      this.timestamps = []; // missing or corrupt state starts fresh
    }
  }

  private save(): void {
    try {
      mkdirSync(dirname(this.statePath), { recursive: true });
      const tmp = `${this.statePath}.tmp-${process.pid}`;
      writeFileSync(tmp, JSON.stringify({ t: this.timestamps }), "utf8");
      renameSync(tmp, this.statePath);
    } catch {
      /* quota persistence must never break the actual command path */
    }
  }
}

export function formatQuotaRefusal(status: QuotaStatus): string {
  const reset = status.resetAtMs ? new Date(status.resetAtMs).toISOString() : "unknown";
  return (
    `Refused: daily command quota exhausted (${status.used}/${status.limit} in the rolling 24h window). ` +
    `Oldest call ages out at ${reset}. Raise defaults.commandQuotaPerDay or wait.`
  );
}
