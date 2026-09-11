/**
 * signal-process: send a signal to a remote PID.
 *
 * Deliberately narrow: numeric PIDs only (no pkill pattern matching — a
 * pattern can hit processes you didn't intend), four signal names, and the
 * tool layer always gates approval. `kill` matches the destructive class in
 * the policy engine; sudo escalates to privileged.
 */

export const SIGNALS = ["INT", "TERM", "KILL", "HUP"] as const;
export type SignalName = (typeof SIGNALS)[number];

export class SignalError extends Error {}

export function buildSignalCommand(pid: number, signal: SignalName): string {
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new SignalError(`Invalid PID: ${pid}`);
  }
  if (!SIGNALS.includes(signal)) {
    throw new SignalError(`Invalid signal "${signal}": allowed ${SIGNALS.join(", ")}`);
  }
  return `kill -${signal} ${pid}`;
}
