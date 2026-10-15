import { describe, expect, it } from "vitest";
import { ConfigError, decide, decideForServer, isRootAccount, parseFleetConfig } from "../src/index.js";

const server = (over: Record<string, unknown> = {}) => ({
  name: "web-1",
  user: "deploy",
  role: "operator" as const,
  group: "staging",
  readOnly: false,
  ...over,
});

describe("policy.matrix overrides", () => {
  it("can narrow the built-in role x tier matrix", () => {
    const matrix = { operator: { staging: ["read-only" as const, "safe" as const] } };
    expect(decideForServer("rm -rf /tmp/x", server(), "ask-destructive").allowed).toBe(true);
    const narrowed = decideForServer("rm -rf /tmp/x", server(), "ask-destructive", { matrix });
    expect(narrowed.allowed).toBe(false);
    expect(narrowed.reason).toMatch(/does not permit destructive/);
  });

  it("never widens: a wildcard override is intersected with the built-in row", () => {
    const matrix = { operator: { "*": ["read-only" as const, "safe" as const, "unknown" as const, "destructive" as const] } };
    const prod = decideForServer("rm -rf /tmp/x", server({ group: "prod" }), "ask-destructive", { matrix });
    expect(prod.allowed).toBe(false);
  });

  it("rejects widening overrides at config load time", () => {
    expect(() =>
      parseFleetConfig(`[policy.matrix.operator]\nprod = ["read-only", "destructive"]\n`),
    ).toThrow(ConfigError);
    const ok = parseFleetConfig(`[policy.matrix.operator]\nprod = ["read-only"]\n`);
    expect(ok.policy?.matrix?.operator?.prod).toEqual(["read-only"]);
  });
});

describe("root accounts", () => {
  it("are detected by user name", () => {
    expect(isRootAccount({ user: "root" })).toBe(true);
    expect(isRootAccount({ user: "deploy" })).toBe(false);
  });

  it("never run destructive commands without approval, even in auto mode", () => {
    expect(decideForServer("rm -rf /tmp/x", server(), "auto").needsApproval).toBe(false);
    const root = decideForServer("rm -rf /tmp/x", server({ user: "root" }), "auto");
    expect(root.allowed).toBe(true);
    expect(root.needsApproval).toBe(true);
    expect(decide("ls", { role: "operator", tier: "staging", readOnly: false, approvalMode: "auto", rootAccount: true }).needsApproval).toBe(false);
  });
});

describe("tier alias", () => {
  it("accepts tier as the clearer name for a server's policy tier", () => {
    const cfg = parseFleetConfig(`[[servers]]\nname = "a"\nhost = "h"\nuser = "u"\ntier = "staging"\n`);
    expect(cfg.servers[0]!.group).toBe("staging");
  });

  it("refuses conflicting tier and group", () => {
    expect(() =>
      parseFleetConfig(`[[servers]]\nname = "a"\nhost = "h"\nuser = "u"\ntier = "staging"\ngroup = "prod"\n`),
    ).toThrow(/tier/);
  });
});
