/**
 * High-level service tools for systemd and OpenRC.
 *
 * "restart myapp" instead of raw systemctl — with unit-name validation
 * (no shell metacharacters can reach the command line) and the
 * scopes.services authorization layer.
 */

/** A systemd unit name: letters, digits, and the unit-name punctuation set. Nothing else. */
const UNIT_RE = /^[a-zA-Z0-9@._:\-]+(\.(service|socket|timer|target|mount|path|slice|scope|device|swap|automount))?$/;

export type ServiceAction = "start" | "stop" | "restart" | "reload";

export const SERVICE_ACTIONS: ServiceAction[] = ["start", "stop", "restart", "reload"];

export type ResolvedServiceManager = "systemd" | "openrc";

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

/** Fixed, read-only target probe. It never includes user-supplied material. */
export function buildServiceManagerProbeCommand(): string {
  return "if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then printf 'systemd\\n'; elif command -v rc-service >/dev/null 2>&1; then printf 'openrc\\n'; else printf 'unknown\\n'; fi";
}

export function parseServiceManager(stdout: string): ResolvedServiceManager {
  const detected = stdout.trim().split(/\s+/)[0];
  if (detected === "systemd" || detected === "openrc") return detected;
  throw new ServiceError(
    `Could not detect a supported service manager (probe returned "${detected || "empty"}"); set serviceManager to "systemd" or "openrc" for this server`,
  );
}

function openRcServiceName(unit: string): string {
  if (unit.endsWith(".service")) return unit.slice(0, -".service".length);
  if (unit.includes(".")) {
    throw new ServiceError(`OpenRC supports service names, not systemd unit type "${unit}"`);
  }
  return unit;
}

/** Service status probe (read-only). */
export function buildStatusCommand(
  unit: string,
  manager: ResolvedServiceManager = "systemd",
): string {
  if (manager === "openrc") return `rc-service ${openRcServiceName(unit)} status`;
  return `systemctl status ${unit} --no-pager -l`;
}

/** Service log tail where a generic service journal exists. */
export function buildLogsCommand(
  unit: string,
  lines: number,
  manager: ResolvedServiceManager = "systemd",
): string {
  if (manager === "openrc") {
    throw new ServiceError(
      `OpenRC has no generic per-service journal for "${openRcServiceName(unit)}"; use logs-tail --path with that service's configured log file`,
    );
  }
  const n = Math.max(1, Math.min(1000, Math.floor(lines)));
  return `journalctl -q -u ${unit} -n ${n} --no-pager`;
}

/** Service mutation (destructive — goes through the approval gate). */
export function buildControlCommand(
  unit: string,
  action: ServiceAction,
  manager: ResolvedServiceManager = "systemd",
): string {
  if (!SERVICE_ACTIONS.includes(action)) {
    throw new ServiceError(`Unknown service action "${action}"`);
  }
  if (manager === "openrc") return `rc-service ${openRcServiceName(unit)} ${action}`;
  return `systemctl ${action} ${unit}`;
}
