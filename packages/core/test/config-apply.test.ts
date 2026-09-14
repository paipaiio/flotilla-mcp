import { describe, expect, it, vi } from "vitest";
import {
  ConfigApplyError,
  applyStructuredChanges,
  runConfigTransaction,
  type ConfigTransactionAdapter,
} from "../src/config-apply.js";

describe("structured config changes", () => {
  it("sets, creates, appends, and deletes JSON Pointer paths", () => {
    const result = applyStructuredChanges(
      '{"server":{"port":80,"legacy":true},"peers":["a"]}\n',
      "json",
      [
        { op: "set", path: "/server/port", value: 443 },
        { op: "set", path: "/server/tls/enabled", value: true },
        { op: "set", path: "/peers/-", value: "b" },
        { op: "delete", path: "/server/legacy" },
      ],
    );
    expect(JSON.parse(result.text)).toEqual({
      server: { port: 443, tls: { enabled: true } },
      peers: ["a", "b"],
    });
    expect(result.changes).toEqual([
      { op: "set", path: "/server/port", source: "literal" },
      { op: "set", path: "/server/tls/enabled", source: "literal" },
      { op: "set", path: "/peers/-", source: "literal" },
      { op: "delete", path: "/server/legacy" },
    ]);
  });

  it("round-trips YAML and TOML and resolves an environment value without reporting it", () => {
    const yaml = applyStructuredChanges("server:\n  port: 80\n", "yaml", [
      { op: "set", path: "/server/token", valueFromEnv: "APP_TOKEN" },
    ], { APP_TOKEN: "very-secret-token" });
    expect(yaml.text).toContain("very-secret-token");
    expect(JSON.stringify(yaml.changes)).not.toContain("very-secret-token");

    const toml = applyStructuredChanges("[server]\nport = 80\n", "toml", [
      { op: "set", path: "/server/port", value: 443 },
    ]);
    expect(toml.text).toMatch(/port\s*=\s*443/);
  });

  it("rejects malformed operations and prototype-pollution paths", () => {
    expect(() => applyStructuredChanges("{}", "json", [
      { op: "set", path: "/__proto__/polluted", value: true },
    ])).toThrow(ConfigApplyError);
    expect(() => applyStructuredChanges("{}", "json", [
      { op: "set", path: "/token", valueFromEnv: "MISSING" },
    ], {})).toThrow(/MISSING/);
    expect(() => applyStructuredChanges("{}", "json", [
      { op: "delete", path: "/missing" },
    ])).toThrow(/does not exist/);
  });
});

function adapter(events: string[], failures: Partial<Record<string, string>> = {}): ConfigTransactionAdapter {
  const action = (name: string) => vi.fn(async () => {
    events.push(name);
    if (failures[name]) {
      const message = failures[name]!;
      delete failures[name];
      throw new Error(message);
    }
  });
  return {
    backup: action("backup"),
    stage: action("stage"),
    validate: action("validate"),
    install: action("install"),
    restart: action("restart"),
    health: action("health"),
    rollback: action("rollback"),
    cleanup: action("cleanup"),
  };
}

describe("config transaction state machine", () => {
  it("runs the successful transaction in strict order", async () => {
    const events: string[] = [];
    const result = await runConfigTransaction(adapter(events));
    expect(result).toMatchObject({ ok: true, installed: true, rolledBack: false });
    expect(events).toEqual(["backup", "stage", "validate", "install", "restart", "health", "cleanup"]);
  });

  it("does not restart or roll back when validation fails before install", async () => {
    const events: string[] = [];
    const result = await runConfigTransaction(adapter(events, { validate: "bad syntax" }));
    expect(result).toMatchObject({ ok: false, failedStage: "validate", installed: false, rolledBack: false });
    expect(events).toEqual(["backup", "stage", "validate", "cleanup"]);
  });

  it.each(["restart", "health"])("restores and verifies the old config when %s fails", async (failed) => {
    const events: string[] = [];
    const failures = { [failed]: "new version unhealthy" };
    const result = await runConfigTransaction(adapter(events, failures));
    expect(result).toMatchObject({ ok: false, failedStage: failed, installed: true, rolledBack: true });
    expect(events).toContain("rollback");
    expect(events.slice(-4)).toEqual(["rollback", "restart", "health", "cleanup"]);
  });

  it("reports a failed rollback without hiding the original stage", async () => {
    const events: string[] = [];
    const result = await runConfigTransaction(adapter(events, {
      health: "new version unhealthy",
      rollback: "restore failed",
    }));
    expect(result).toMatchObject({
      ok: false,
      failedStage: "health",
      rolledBack: false,
      rollbackError: "restore failed",
    });
  });
});
