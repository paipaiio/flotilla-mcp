/**
 * JIT grants (ssh-mcp style): when a human approves an action interactively,
 * they may tick "don't ask again for N minutes" — an identical request (same
 * tool, same action, same hosts) then sails through the gate until the grant
 * expires.
 *
 * In-memory on purpose: a restart clears all grants, so a forgotten
 * "remember me" can never outlive the session it was born in. Persistence
 * would trade exactly the wrong way for a feature whose entire value is
 * being short-lived.
 *
 * The confirm-flag channel never creates grants: that flag is filled in by
 * the model itself, and letting it mint standing exemptions would be
 * self-approval with extra steps.
 */

/** Identity of "the same request": tool + action text + sorted host set. */
export function grantKey(tool: string, action: string, hosts: string[]): string {
  return `${tool} ${action} ${[...hosts].sort().join(",")}`;
}

export interface GrantEntry {
  key: string;
  grantedAtMs: number;
  expiresAtMs: number;
}

export class GrantStore {
  private readonly grants = new Map<string, GrantEntry>();

  constructor(
    private readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** Grants disabled when ttl is 0 or negative. */
  get enabled(): boolean {
    return this.ttlMs > 0;
  }

  /** True when a live grant covers this key. Expired entries are reaped lazily. */
  check(key: string): boolean {
    if (!this.enabled) return false;
    const g = this.grants.get(key);
    if (!g) return false;
    if (g.expiresAtMs <= this.now()) {
      this.grants.delete(key);
      return false;
    }
    return true;
  }

  grant(key: string): void {
    if (!this.enabled) return;
    const t = this.now();
    this.grants.set(key, { key, grantedAtMs: t, expiresAtMs: t + this.ttlMs });
  }

  revoke(key: string): boolean {
    return this.grants.delete(key);
  }

  clear(): number {
    const n = this.grants.size;
    this.grants.clear();
    return n;
  }

  /** Live grants only, for the fleet-grants inspection tool. */
  list(): GrantEntry[] {
    const t = this.now();
    const live: GrantEntry[] = [];
    for (const g of this.grants.values()) {
      if (g.expiresAtMs > t) live.push(g);
      else this.grants.delete(g.key);
    }
    return live.sort((a, b) => a.expiresAtMs - b.expiresAtMs);
  }
}
