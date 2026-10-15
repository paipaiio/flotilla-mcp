/**
 * Caller identity for multi-token deployments (the HTTP gateway).
 *
 * The gateway authenticates a bearer token and attaches a principal to the
 * MCP request's authInfo. Every tool call runs inside that principal via
 * AsyncLocalStorage, and server resolution applies it in one place: servers
 * outside the token's targets become invisible, and each server's role is
 * capped at the token's maxRole. Policy then runs unchanged on the capped
 * servers, so a token can only ever narrow what the fleet config allows.
 *
 * stdio callers have no principal and keep the full fleet config authority.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { resolveTarget, type FleetRegistry, type Role, type ServerConfig } from "flotilla-core";

export interface Principal {
  /** Token name, for audit lines. */
  name: string;
  /** Highest role this caller may exercise on any server. */
  maxRole: Role;
  /** Target expressions the caller may see; omitted = whole fleet. */
  targets?: string[];
}

const ROLE_RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };
const storage = new AsyncLocalStorage<Principal | undefined>();

export function runWithPrincipal<T>(principal: Principal | undefined, fn: () => T): T {
  return storage.run(principal, fn);
}

export function currentPrincipal(): Principal | undefined {
  return storage.getStore();
}

function isRole(value: unknown): value is Role {
  return value === "viewer" || value === "operator" || value === "admin";
}

/**
 * Extract the principal the gateway attached. Anything malformed fails
 * closed: a viewer that sees no servers.
 */
export function principalFromAuthInfo(authInfo: unknown): Principal | undefined {
  const extra = (authInfo as { extra?: Record<string, unknown> } | undefined)?.extra;
  const raw = extra?.["flotillaPrincipal"] as Record<string, unknown> | undefined;
  if (!raw) return undefined;
  const name = typeof raw["name"] === "string" ? raw["name"] : "unknown";
  const targets = raw["targets"];
  if (!isRole(raw["maxRole"]) || (targets !== undefined && !(Array.isArray(targets) && targets.every((t) => typeof t === "string")))) {
    return { name, maxRole: "viewer", targets: [] };
  }
  return targets === undefined ? { name, maxRole: raw["maxRole"] } : { name, maxRole: raw["maxRole"], targets: targets as string[] };
}

/** Filter to the principal's visible servers and cap each server's role. */
export function scopeServers(
  servers: ServerConfig[],
  registry: FleetRegistry,
  principal: Principal | undefined,
): ServerConfig[] {
  if (!principal) return servers;
  let visible: Set<string> | undefined;
  if (principal.targets !== undefined) {
    visible = new Set();
    for (const expr of principal.targets) {
      try {
        for (const s of resolveTarget(registry, expr)) visible.add(s.name);
      } catch {
        // An expression that no longer resolves grants nothing.
      }
    }
  }
  const cap = ROLE_RANK[principal.maxRole];
  return servers
    .filter((s) => !visible || visible.has(s.name))
    .map((s) => (ROLE_RANK[s.role] > cap ? { ...s, role: principal.maxRole } : s));
}

/**
 * Changing who the fleet controls (add/remove/set/reload/grants) needs a
 * whole-fleet admin token: a target-limited admin could otherwise touch
 * servers outside its targets, or re-tag servers into its own scope.
 */
export function canChangeFleet(principal: Principal | undefined): boolean {
  return !principal || (principal.maxRole === "admin" && principal.targets === undefined);
}
