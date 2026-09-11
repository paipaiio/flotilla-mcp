import { describe, expect, it } from "vitest";
import { Executor } from "../src/executor.js";
import type {
  DefaultsConfig,
  ExecOptions,
  ExecResult,
  ServerConfig,
  Transport,
} from "../src/types.js";

const DEFAULTS: DefaultsConfig = {
  approvalMode: "ask-destructive",
  commandTimeoutMs: 1000,
  maxConcurrency: 16,
  rollingBatchSize: 2,
  rollingMaxBatchFailures: 0,
};

function server(name: string): ServerConfig {
  return {
    name,
    host: name,
    port: 22,
    user: "u",
    auth: "agent",
    group: "dev",
    tags: [],
    role: "admin",
    readOnly: false,
  };
}

/** Mock transport: hosts listed in failing reject/fail, others succeed. */
class MockTransport implements Transport {
  calls: string[] = [];
  constructor(protected failing: Set<string> = new Set()) {}
  async exec(s: ServerConfig, _cmd: string, _opts: ExecOptions): Promise<ExecResult> {
    this.calls.push(s.name);
    const base = { host: s.name, stdout: "", stderr: "", durationMs: 1 };
    if (this.failing.has(s.name)) {
      return { ...base, ok: false, exitCode: 1, stderr: "boom" };
    }
    return { ...base, ok: true, exitCode: 0, stdout: "ok" };
  }
  async close(): Promise<void> {}
}

/** Mock transport that throws transport-level errors for failing hosts. */
class ThrowingTransport extends MockTransport {
  override async exec(s: ServerConfig, cmd: string, opts: ExecOptions): Promise<ExecResult> {
    this.calls.push(s.name);
    if (this.failing.has(s.name)) throw new Error("connection refused");
    return super.exec(s, cmd, opts);
  }
}

const fleet = ["a", "b", "c", "d", "e"].map(server);

describe("Executor parallel", () => {
  it("runs every host and aggregates", async () => {
    const t = new MockTransport(new Set(["c"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.run(fleet, "uptime", { kind: "parallel" });
    expect(r.summary).toMatchObject({
      total: 5,
      succeeded: 4,
      failed: 1,
      skipped: 0,
      halted: false,
      strategy: "parallel",
    });
    expect(t.calls.sort()).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("converts transport errors into per-host failures", async () => {
    const t = new ThrowingTransport(new Set(["b"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.run(fleet, "uptime", { kind: "parallel" });
    const b = r.results.find((x) => x.host === "b")!;
    expect(b.ok).toBe(false);
    expect(b.error).toBe("connection refused");
    expect(r.summary.failed).toBe(1);
  });
});

describe("Executor serial", () => {
  it("preserves order", async () => {
    const t = new MockTransport();
    const ex = new Executor(t, DEFAULTS);
    await ex.run(fleet, "uptime", { kind: "serial" });
    expect(t.calls).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("stopOnError marks the rest skipped", async () => {
    const t = new MockTransport(new Set(["b"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.run(fleet, "uptime", { kind: "serial", stopOnError: true });
    expect(t.calls).toEqual(["a", "b"]);
    expect(r.summary).toMatchObject({ succeeded: 1, failed: 1, skipped: 3, halted: true });
  });
});

describe("Executor rolling", () => {
  it("halts when a batch exceeds maxBatchFailures and skips the rest", async () => {
    // batch1 = a,b both fail -> circuit breaker -> c,d,e skipped
    const t = new MockTransport(new Set(["a", "b"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.run(fleet, "systemctl restart app", { kind: "rolling" });
    expect(t.calls.sort()).toEqual(["a", "b"]);
    expect(r.summary).toMatchObject({
      total: 5,
      failed: 2,
      skipped: 3,
      halted: true,
      strategy: "rolling",
    });
  });

  it("continues while batches stay within the failure budget", async () => {
    const t = new MockTransport(new Set(["b"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.run(fleet, "cmd", { kind: "rolling", batchSize: 2, maxBatchFailures: 1 });
    expect(t.calls.sort()).toEqual(["a", "b", "c", "d", "e"]);
    expect(r.summary.halted).toBe(false);
    expect(r.summary.failed).toBe(1);
  });

  it("halts mid-fleet, not at the end", async () => {
    // batch1 ok (a,b), batch2 has both failing (c,d) -> e skipped
    const t = new MockTransport(new Set(["c", "d"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.run(fleet, "cmd", { kind: "rolling" });
    expect(t.calls.sort()).toEqual(["a", "b", "c", "d"]);
    expect(r.results.find((x) => x.host === "e")!.skipped).toBe(true);
  });
});
