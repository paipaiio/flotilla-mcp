/**
 * Bounded log tailing ("logs-tail").
 *
 * MCP stdio has no streaming story a client can rely on, so tailing is a
 * bounded collection: run `timeout N <follower>` remotely, return whatever
 * was captured in that window. Exit 124 (timeout's "time's up") is the
 * expected ending and is normalized to exit 0 remotely.
 *
 * Grep filtering happens LOCALLY after collection, not in a remote pipeline:
 * a pipe would mask timeout's exit code, and for sudo journal tails a
 * pipeline would change what the sudoers whitelist matches.
 */

const MAX_SECONDS = 300;

function q(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function clampSeconds(seconds: number): number {
  return Math.max(1, Math.min(seconds, MAX_SECONDS));
}

/** Normalize timeout's exit 124 to 0 so the fan-out marks the host OK. */
function withTimeoutExitNormalization(cmd: string): string {
  return `${cmd}; c=$?; if [ $c -eq 124 ]; then exit 0; else exit $c; fi`;
}

/**
 * Follow a unit's journal for `seconds`. With sudo, `sudo -n` is baked into
 * the command (NOT the transport's sudo wrapper): the sudoers whitelist must
 * match `journalctl`, not `timeout`. sudo tails therefore require NOPASSWD.
 */
export function buildJournalTailCommand(
  unit: string,
  seconds: number,
  opts: { sudo?: boolean } = {},
): string {
  const n = clampSeconds(seconds);
  const inner = opts.sudo
    ? `sudo -n -p '' journalctl -u ${q(unit)} -f -n 0 --no-pager`
    : `journalctl -u ${q(unit)} -f -n 0 --no-pager`;
  return withTimeoutExitNormalization(`timeout ${n} ${inner} 2>&1`);
}

/** Follow a file for `seconds` (tail -F: survives rotation/truncation). */
export function buildFileTailCommand(path: string, seconds: number): string {
  const n = clampSeconds(seconds);
  return withTimeoutExitNormalization(`timeout ${n} tail -F -n 0 ${q(path)} 2>&1`);
}

export interface TailFilterResult {
  /** Lines matching the grep pattern (or all lines when no pattern). */
  lines: string[];
  matched: number;
  total: number;
  /** Set when the grep pattern itself is invalid. */
  grepError?: string;
}

/** Local line filter. Returns all lines when pattern is undefined. */
export function filterTailOutput(raw: string, pattern?: string): TailFilterResult {
  const lines = raw.split("\n").filter((l) => l.length > 0);
  if (!pattern) return { lines, matched: lines.length, total: lines.length };
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch (err) {
    return {
      lines: [],
      matched: 0,
      total: lines.length,
      grepError: `Invalid grep pattern: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  const matched = lines.filter((l) => re.test(l));
  return { lines: matched, matched: matched.length, total: lines.length };
}
