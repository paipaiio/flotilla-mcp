/**
 * High-level systemd service tools (v0.5).
 *
 * "restart myapp" instead of raw systemctl — with unit-name validation
 * (no shell metacharacters can reach the command line) and the
 * scopes.services authorization layer.
 */

/** A systemd unit name: letters, digits, and the unit-name punctuation set. Nothing else. */
const UNIT_RE = /^[a-zA-Z0-9@._:\-]+(\.(service|socket|timer|target|mount|path|slice|scope|device|swap|automount))?$/;

export type ServiceAction = "start" | "stop" | "restart" | "reload";

export const SERVICE_ACTIONS: ServiceAction[] = ["start", "stop", "restart", "reload"];

/**
 * Validate a unit name. Returns the normalized name (with .service suffix)
 * or throws — the caller must treat a throw as a refusal, never fall through.
 */
export function validateUnit(unit: string): string {
  const trimmed = unit.trim();
  if (!UNIT_RE.test(trimmed)) {
    throw new ServiceError(
      `Invalid unit name "${unit}": only [a-zA-Z0-9@._:-] plus an optional unit suffix are allowed`,
    );
  }
  return trimmed.includes(".") ? trimmed : `${trimmed}.service`;
}

export class ServiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ServiceError";
  }
}

/**
 * scopes.services authorization: exact unit match. A server without
 * scopes.services is unrestricted at this layer (narrowing, never widening).
 */
export function checkServiceScope(
  server: { name: string; scopes?: { services?: string[] } },
  unit: string,
): string | null {
  const allowed = server.scopes?.services;
  if (!allowed || allowed.length === 0) return null;
  if (allowed.includes(unit)) return null;
  return `Unit "${unit}" is outside server "${server.name}" scopes.services: [${allowed.join(", ")}]`;
}

/** systemctl status probe (read-only). */
export function buildStatusCommand(unit: string): string {
  return `systemctl status ${unit} --no-pager -l`;
}

/** journalctl tail for a unit (read-only). -q silences the permissions hint. */
export function buildLogsCommand(unit: string, lines: number): string {
  const n = Math.max(1, Math.min(1000, Math.floor(lines)));
  return `journalctl -q -u ${unit} -n ${n} --no-pager`;
}

/** systemctl mutation (destructive — goes through the approval gate). */
export function buildControlCommand(unit: string, action: ServiceAction): string {
  if (!SERVICE_ACTIONS.includes(action)) {
    throw new ServiceError(`Unknown service action "${action}"`);
  }
  return `systemctl ${action} ${unit}`;
}
