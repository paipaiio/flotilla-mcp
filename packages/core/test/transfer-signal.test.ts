import { describe, expect, it } from "vitest";
import { Executor, resolveLocalPath } from "../src/executor.js";
import { buildSignalCommand, SignalError } from "../src/signal.js";
import type {
  DefaultsConfig,
  ExecOptions,
  ExecResult,
  RelayResult,
  ServerConfig,
  TransferResult,
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

class MockTransport implements Transport {
  downloads: { host: string; remotePath: string; localPath: string }[] = [];
  constructor(private readonly failing: Set<string> = new Set()) {}
  async exec(s: ServerConfig): Promise<ExecResult> {
    return { host: s.name, ok: !this.failing.has(s.name), exitCode: 0, stdout: "", stderr: "", durationMs: 1 };
  }
  async upload(s: ServerConfig): Promise<TransferResult> {
    return { host: s.name, ok: true, bytes: 1, durationMs: 1 };
  }
  async download(s: ServerConfig, remotePath: string, localPath: string): Promise<TransferResult> {
    this.downloads.push({ host: s.name, remotePath, localPath });
    if (this.failing.has(s.name)) {
      return { host: s.name, ok: false, bytes: 0, durationMs: 1, error: "no such file" };
    }
    return { host: s.name, ok: true, bytes: 512, durationMs: 1 };
  }
  async relayCopy(src: ServerConfig, _s: string, dst: ServerConfig): Promise<RelayResult> {
    const base = { source: src.name, dest: dst.name, durationMs: 1 };
    if (this.failing.has(src.name) || this.failing.has(dst.name)) {
      return { ...base, ok: false, bytes: 0, error: "relay failed" };
    }
    return { ...base, ok: true, bytes: 64 };
  }
  async close(): Promise<void> {}
}

describe("resolveLocalPath", () => {
  it("single host without placeholder keeps the path", () => {
    expect(resolveLocalPath("./out.log", "web-1", false)).toBe("./out.log");
  });
  it("{host} placeholder is replaced", () => {
    expect(resolveLocalPath("./logs/{host}.log", "web-1", true)).toBe("./logs/web-1.log");
  });
  it("multi-host without placeholder inserts -<host> before the extension", () => {
    expect(resolveLocalPath("./out.log", "web-1", true)).toBe("./out-web-1.log");
    expect(resolveLocalPath("./out", "web-1", true)).toBe("./out-web-1");
  });
});

describe("Executor pull", () => {
  it("downloads from every host to distinct local paths", async () => {
    const t = new MockTransport();
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.pull([server("a"), server("b")], "/var/log/app.log", "./dl/app.log", { kind: "parallel" });
    expect(r.summary).toMatchObject({ total: 2, succeeded: 2 });
    expect(t.downloads.map((d) => d.localPath).sort()).toEqual(["./dl/app-a.log", "./dl/app-b.log"]);
  });

  it("rolling circuit breaker applies to pulls", async () => {
    const t = new MockTransport(new Set(["a"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.pull([server("a"), server("b"), server("c")], "/x", "./x", {
      kind: "rolling",
      batchSize: 1,
    });
    expect(r.summary).toMatchObject({ failed: 1, skipped: 2, halted: true });
  });
});

describe("buildSignalCommand", () => {
  it("builds kill -SIGNAL pid", () => {
    expect(buildSignalCommand(1234, "TERM")).toBe("kill -TERM 1234");
    expect(buildSignalCommand(1, "KILL")).toBe("kill -KILL 1");
  });
  it("rejects non-integer / non-positive PIDs and unknown signals", () => {
    expect(() => buildSignalCommand(0, "TERM")).toThrow(SignalError);
    expect(() => buildSignalCommand(1.5, "TERM")).toThrow(SignalError);
    expect(() => buildSignalCommand(-3, "TERM")).toThrow(SignalError);
    expect(() => buildSignalCommand(1, "USR1" as never)).toThrow(SignalError);
  });
});

describe("SshTransport idle reap", () => {
  it("reapIdle closes connections idle beyond the limit", async () => {
    const { SshTransport } = await import("../src/ssh.js");
    const t = new SshTransport(new Map(), { idleReapMs: 1000 });
    // Inject fake pooled connections.
    const closed: string[] = [];
    const fakeConn = (name: string) => ({ end: () => closed.push(name) });
    (t as never as { pool: Map<string, unknown> }).pool.set("stale", fakeConn("stale"));
    (t as never as { pool: Map<string, unknown> }).pool.set("fresh", fakeConn("fresh"));
    const lastUsed = (t as never as { lastUsed: Map<string, number> }).lastUsed;
    const now = Date.now();
    lastUsed.set("stale", now - 5000);
    lastUsed.set("fresh", now - 100);
    expect(t.reapIdle(now)).toBe(1);
    expect(closed).toEqual(["stale"]);
    await t.close();
  });

  it("drainAndClose waits for active work before closing pooled connections", async () => {
    const { SshTransport } = await import("../src/ssh.js");
    const t = new SshTransport(new Map());
    const closed: string[] = [];
    (t as never as { pool: Map<string, unknown> }).pool.set("active", { end: () => closed.push("active") });
    let release!: () => void;
    const active = (t as never as { operations: { run<T>(fn: () => Promise<T>): Promise<T> } }).operations.run(
      () => new Promise<void>((resolve) => { release = resolve; }),
    );
    const draining = t.drainAndClose(1000);
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(closed).toEqual([]);
    release();
    await active;
    await expect(draining).resolves.toEqual({ drained: true, activeAtClose: 0 });
    expect(closed).toEqual(["active"]);
  });
});
