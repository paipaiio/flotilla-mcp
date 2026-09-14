import { describe, expect, it } from "vitest";
import { createChangeSet, decideChangeSet } from "../src/change-set.js";
import type { ServerConfig } from "../src/types.js";

const server = (overrides: Partial<ServerConfig> = {}): ServerConfig => ({
  name: "prod-1",
  host: "127.0.0.1",
  port: 22,
  user: "deploy",
  auth: "agent",
  group: "prod",
  tags: [],
  role: "operator",
  readOnly: false,
  scopes: { paths: ["/etc/app/**"], services: ["app.service"] },
  ...overrides,
});

describe("scoped change sets", () => {
  const change = createChangeSet({
    tool: "config-apply",
    summary: "update app config",
    targets: ["prod-1"],
    paths: ["/etc/app/config.json"],
    services: ["app.service"],
    operations: ["set /server/port", "restart app.service"],
    rollback: "restore backup and restart",
    risk: "destructive",
    payloadFingerprints: ["sha256:abc"],
  });

  it("creates a stable, canonical identifier that binds payload fingerprints", () => {
    const reordered = createChangeSet({
      tool: "config-apply",
      summary: "update app config",
      targets: ["prod-1", "prod-1"],
      paths: ["/etc/app/config.json"],
      services: ["app.service"],
      operations: ["set /server/port", "restart app.service"],
      rollback: "restore backup and restart",
      risk: "destructive",
      payloadFingerprints: ["sha256:abc"],
    });
    expect(reordered.id).toBe(change.id);
    expect(change.id).toMatch(/^cs_[a-f0-9]{16}$/);
    expect(createChangeSet({ ...change, payloadFingerprints: ["sha256:different"] }).id).not.toBe(change.id);
    expect(() => createChangeSet({ ...change, paths: ["relative"] })).toThrow(/absolute/);
    expect(() => createChangeSet({ ...change, paths: ["/etc/app\nServices: fake"] })).toThrow(/single-line/);
  });

  it("allows an operator to submit a scoped production mutation but always requires approval", () => {
    expect(decideChangeSet(change, server(), "auto")).toEqual({
      allowed: true,
      needsApproval: true,
      risk: "destructive",
    });
  });

  it("keeps viewer, readOnly, deny mode, target, path, and service boundaries closed", () => {
    expect(decideChangeSet(change, server({ role: "viewer" }), "ask-destructive").allowed).toBe(false);
    expect(decideChangeSet(change, server({ readOnly: true }), "ask-destructive").allowed).toBe(false);
    expect(decideChangeSet(change, server(), "deny").allowed).toBe(false);
    expect(decideChangeSet(change, server({ name: "prod-2" }), "ask-destructive").allowed).toBe(false);
    expect(decideChangeSet(change, server({ scopes: { paths: ["/srv/**"], services: ["app.service"] } }), "ask-destructive").allowed).toBe(false);
    expect(decideChangeSet(change, server({ scopes: { paths: ["/etc/app/**"], services: ["other.service"] } }), "ask-destructive").allowed).toBe(false);
  });

  it("does not widen privileged production access", () => {
    const privileged = createChangeSet({ ...change, risk: "privileged" });
    expect(decideChangeSet(privileged, server(), "ask-destructive").allowed).toBe(false);
    expect(decideChangeSet(privileged, server({ role: "admin" }), "ask-destructive").allowed).toBe(false);
    expect(decideChangeSet(privileged, server({ role: "admin", group: "dev" }), "ask-destructive")).toMatchObject({ allowed: true, needsApproval: true });
  });
});
