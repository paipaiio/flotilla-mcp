import { describe, expect, it } from "vitest";
import { FleetRegistry, parseFleetConfig } from "../src/index.js";
import { parseTarget, resolveTarget, TargetError } from "../src/target.js";

const TOML = `
[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
group = "prod"
tags = ["web", "cn-east"]

[[servers]]
name = "web-2"
host = "10.0.1.12"
user = "deploy"
group = "prod"
tags = ["web", "cn-east"]

[[servers]]
name = "web-3"
host = "10.0.1.13"
user = "deploy"
group = "prod"
tags = ["web", "eu"]

[[servers]]
name = "db-1"
host = "10.0.2.11"
user = "deploy"
group = "prod"
tags = ["db"]

[[servers]]
name = "build-box"
host = "192.168.1.5"
user = "builder"
group = "dev"
tags = ["ci"]

[[groups]]
name = "web-prod"
match = { group = "prod", tags = ["web"] }
`;

function registry(): FleetRegistry {
  return new FleetRegistry(parseFleetConfig(TOML));
}

describe("parseTarget", () => {
  it("parses a bare server name", () => {
    expect(parseTarget("web-1")).toEqual({
      include: [{ kind: "server", name: "web-1" }],
      exclude: [],
    });
  });

  it("parses unions and exclusions", () => {
    expect(parseTarget("group:prod, tag:db !web-3")).toEqual({
      include: [
        { kind: "group", name: "prod" },
        { kind: "tag", tag: "db" },
      ],
      exclude: [{ kind: "server", name: "web-3" }],
    });
  });

  it("accepts an explicit array", () => {
    const expr = parseTarget(["web-1", "web-2"]);
    expect(expr.include).toHaveLength(2);
  });

  it("rejects exclude-only expressions", () => {
    expect(() => parseTarget("!web-1")).toThrow(TargetError);
  });

  it("rejects unknown prefixes", () => {
    expect(() => parseTarget("zone:eu")).toThrow(TargetError);
  });
});

describe("resolveTarget", () => {
  it("resolves a configured group", () => {
    const names = resolveTarget(registry(), "group:web-prod").map((s) => s.name);
    expect(names).toEqual(["web-1", "web-2", "web-3"]);
  });

  it("resolves a bare tier name through group:", () => {
    const names = resolveTarget(registry(), "group:dev").map((s) => s.name);
    expect(names).toEqual(["build-box"]);
  });

  it("resolves tags", () => {
    const names = resolveTarget(registry(), "tag:cn-east").map((s) => s.name);
    expect(names).toEqual(["web-1", "web-2"]);
  });

  it("resolves all", () => {
    expect(resolveTarget(registry(), "all")).toHaveLength(5);
  });

  it("applies exclusions", () => {
    const names = resolveTarget(registry(), "group:web-prod !web-3").map((s) => s.name);
    expect(names).toEqual(["web-1", "web-2"]);
  });

  it("dedupes overlapping includes and sorts by name", () => {
    const names = resolveTarget(registry(), "tag:web, group:web-prod").map((s) => s.name);
    expect(names).toEqual(["web-1", "web-2", "web-3"]);
  });

  it("suggests a close match for unknown servers", () => {
    expect(() => resolveTarget(registry(), "web-9")).toThrow(/did you mean/);
  });

  it("throws on unknown groups", () => {
    expect(() => resolveTarget(registry(), "group:nope")).toThrow(TargetError);
  });

  it("throws when nothing matches", () => {
    expect(() => resolveTarget(registry(), "group:web-prod !web-1 !web-2 !web-3")).toThrow(
      /matched no servers/,
    );
  });
});
