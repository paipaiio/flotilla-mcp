import { describe, expect, it } from "vitest";
import { FleetRegistry, parseFleetConfig } from "flotilla-core";
import {
  canChangeFleet,
  currentPrincipal,
  principalFromAuthInfo,
  runWithPrincipal,
  scopeServers,
} from "../src/principal.js";

const registry = new FleetRegistry(
  parseFleetConfig(`
[[servers]]
name = "web-1"
host = "10.0.0.1"
user = "deploy"
group = "prod"
tags = ["web"]
role = "admin"

[[servers]]
name = "web-2"
host = "10.0.0.2"
user = "deploy"
group = "staging"
tags = ["web"]
role = "viewer"

[[servers]]
name = "db-1"
host = "10.0.0.3"
user = "deploy"
group = "prod"
role = "operator"
`),
);

describe("principal scoping", () => {
  it("leaves stdio callers (no principal) untouched", () => {
    const all = registry.servers();
    expect(scopeServers(all, registry, undefined)).toEqual(all);
    expect(canChangeFleet(undefined)).toBe(true);
  });

  it("hides servers outside the token's targets and caps roles", () => {
    const principal = { name: "ci", maxRole: "operator" as const, targets: ["tag:web"] };
    const scoped = scopeServers(registry.servers(), registry, principal);
    expect(scoped.map((s) => [s.name, s.role])).toEqual([
      ["web-1", "operator"],
      ["web-2", "viewer"],
    ]);
    expect(canChangeFleet(principal)).toBe(false);
    expect(canChangeFleet({ name: "ops", maxRole: "admin" })).toBe(true);
    // A target-limited admin is not a fleet admin.
    expect(canChangeFleet({ name: "web-admin", maxRole: "admin", targets: ["tag:web"] })).toBe(false);
  });

  it("carries the principal through async work", async () => {
    const p = { name: "ro", maxRole: "viewer" as const };
    const seen = await runWithPrincipal(p, async () => {
      await new Promise((r) => setTimeout(r, 1));
      return currentPrincipal();
    });
    expect(seen).toEqual(p);
    expect(currentPrincipal()).toBeUndefined();
  });

  it("reads only well-formed principals from MCP authInfo", () => {
    expect(principalFromAuthInfo(undefined)).toBeUndefined();
    expect(
      principalFromAuthInfo({ token: "x", clientId: "ci", scopes: [], extra: { flotillaPrincipal: { name: "ci", maxRole: "viewer", targets: ["all"] } } }),
    ).toEqual({ name: "ci", maxRole: "viewer", targets: ["all"] });
    // A malformed principal must fail closed to the most restrictive role.
    expect(
      principalFromAuthInfo({ token: "x", clientId: "ci", scopes: [], extra: { flotillaPrincipal: { name: "ci", maxRole: "god" } } }),
    ).toEqual({ name: "ci", maxRole: "viewer", targets: [] });
  });
});
