/**
 * tmux-backed persistent sessions.
 *
 * A Flotilla session is a tmux session named `flotilla-<name>` on the remote
 * host. It survives SSH disconnects: start a long-running command, drop the
 * connection, come back later and capture the output. All operations are
 * ordinary SSH exec calls building tmux commands — no agent on the server
 * beyond tmux itself.
 */

export const SESSION_PREFIX = "flotilla-";

const NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$/;

export interface SessionInfo {
  host: string;
  /** Session name without the flotilla- prefix. */
  name: string;
  createdAt: string;
  windows: number;
  attached: boolean;
}

/**
 * Validate a user-supplied session name and return the full tmux session
 * name (with prefix). tmux forbids '.' and ':' in session names; we also
 * reject anything that could break shell quoting.
 */
export function validateSessionName(name: string): string {
  if (!NAME_RE.test(name)) {
    throw new Error(
      `Invalid session name "${name}": 1-48 chars, letters/digits/'_'/'-', must start with a letter or digit`,
    );
  }
  return SESSION_PREFIX + name;
}

function q(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * Create a detached session (optionally in workdir), enlarge its scrollback,
 * then — when a command is given — type it into the shell and press Enter.
 * The session is a plain shell, so it stays alive after the command exits:
 * output remains capturable and follow-up input is possible.
 */
export function buildSessionStartCommand(
  fullName: string,
  opts: { workdir?: string; command?: string } = {},
): string {
  const parts = [
    `tmux new-session -d -s ${q(fullName)}${opts.workdir ? ` -c ${q(opts.workdir)}` : ""}`,
    // Applies to panes created later; the initial pane keeps tmux's default.
    `tmux set-option -t ${q(fullName)} history-limit 50000`,
  ];
  if (opts.command) {
    parts.push(buildSessionSendCommand(fullName, opts.command));
  }
  return parts.join(" && ");
}

/** List all tmux sessions; exits 0 even when no tmux server is running. */
export function buildSessionListCommand(): string {
  return (
    `tmux list-sessions -F '#{session_name}\t#{session_created}\t#{session_windows}\t#{session_attached}'` +
    ` 2>/dev/null || true`
  );
}

/** Capture the last `lines` of scrollback (-J joins wrapped lines). */
export function buildSessionCaptureCommand(fullName: string, lines = 100): string {
  const n = Math.max(1, Math.min(lines, 10_000));
  return `tmux capture-pane -p -J -t ${q(fullName)} -S -${n}`;
}

/**
 * Send literal text (-l disables key-name lookup, so the text can't be
 * interpreted as tmux key names) followed by Enter.
 */
export function buildSessionSendCommand(fullName: string, text: string): string {
  return `tmux send-keys -t ${q(fullName)} -l ${q(text)} && tmux send-keys -t ${q(fullName)} Enter`;
}

export function buildSessionKillCommand(fullName: string): string {
  return `tmux kill-session -t ${q(fullName)}`;
}

/** Parse `tmux list-sessions` output, keeping only flotilla- sessions. */
export function parseSessionList(host: string, stdout: string): SessionInfo[] {
  const out: SessionInfo[] = [];
  for (const line of stdout.split("\n")) {
    if (!line.trim()) continue;
    const [name, created, windows, attached] = line.split("\t");
    if (!name || !name.startsWith(SESSION_PREFIX)) continue;
    out.push({
      host,
      name: name.slice(SESSION_PREFIX.length),
      createdAt: created ? new Date(Number(created) * 1000).toISOString() : "unknown",
      windows: Number(windows) || 0,
      attached: attached === "1",
    });
  }
  return out;
}
