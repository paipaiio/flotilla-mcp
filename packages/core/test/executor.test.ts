import { describe, expect, it } from "vitest";
import { Executor } from "../src/executor.js";
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

/** Mock transport: hosts listed in failing reject/fail, others succeed. */
class MockTransport implements Transport {
  calls: string[] = [];
  commands: { host: string; command: string }[] = [];
  uploads: { host: string; remotePath: string }[] = [];
  options: ExecOptions[] = [];
  constructor(protected failing: Set<string> = new Set()) {}
  async exec(s: ServerConfig, command: string, opts: ExecOptions): Promise<ExecResult> {
    this.calls.push(s.name);
    this.commands.push({ host: s.name, command });
    this.options.push(opts);
    const base = { host: s.name, stdout: "", stderr: "", durationMs: 1 };
    if (this.failing.has(s.name)) {
      return { ...base, ok: false, exitCode: 1, stderr: "boom" };
    }
    return { ...base, ok: true, exitCode: 0, stdout: "ok" };
  }
  async upload(s: ServerConfig, _l: string, remotePath: string, opts: ExecOptions): Promise<TransferResult> {
    this.uploads.push({ host: s.name, remotePath });
    this.options.push(opts);
    if (this.failing.has(s.name)) {
      return { host: s.name, ok: false, bytes: 0, durationMs: 1, error: "sftp failed" };
    }
    return { host: s.name, ok: true, bytes: 123, durationMs: 1 };
  }
  async download(s: ServerConfig, _r: string, _l: string, opts: ExecOptions): Promise<TransferResult> {
    this.options.push(opts);
    if (this.failing.has(s.name)) {
      return { host: s.name, ok: false, bytes: 0, durationMs: 1, error: "sftp get failed" };
    }
    return { host: s.name, ok: true, bytes: 42, durationMs: 1 };
  }
  async relayCopy(src: ServerConfig, _s: string, dst: ServerConfig, _d: string): Promise<RelayResult> {
    const base = { source: src.name, dest: dst.name, durationMs: 1 };
    if (this.failing.has(src.name) || this.failing.has(dst.name)) {
      return { ...base, ok: false, bytes: 0, error: "relay failed" };
    }
    return { ...base, ok: true, bytes: 64 };
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

  it("runs a host-specific command map through the same fan-out machinery", async () => {
    const t = new MockTransport();
    const ex = new Executor(t, DEFAULTS);
    const result = await ex.runMapped(
      [server("a"), server("b")],
      (s) => `service-manager-for-${s.name}`,
      { kind: "parallel" },
    );
    expect(t.commands).toEqual([
      { host: "a", command: "service-manager-for-a" },
      { host: "b", command: "service-manager-for-b" },
    ]);
    expect(result.command).toBe("<host-specific command>");
  });

  it("enforces scopes.commands at the final executor boundary", async () => {
    const t = new MockTransport();
    const ex = new Executor(t, DEFAULTS);
    const scoped = { ...server("a"), scopes: { commands: ["^uptime$"] } };
    const refused = await ex.run([scoped], "cat /etc/passwd", { kind: "parallel" });
    expect(refused.results[0]).toMatchObject({ ok: false });
    expect(refused.results[0]?.error).toMatch(/scopes\.commands/);
    expect(t.calls).toEqual([]);
    expect((await ex.run([scoped], "uptime", { kind: "parallel" })).results[0]?.ok).toBe(true);
  });

  it("matches command scopes against the effective sudo command", async () => {
    const t = new MockTransport();
    const ex = new Executor(t, DEFAULTS);
    const scoped = { ...server("a"), scopes: { commands: ["^sudo systemctl restart nginx$"] } };
    expect((await ex.run([scoped], "systemctl restart nginx", { kind: "parallel" }, { sudo: true })).results[0]?.ok).toBe(true);
    expect((await ex.run([scoped], "systemctl restart nginx", { kind: "parallel" })).results[0]?.ok).toBe(false);
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

describe("Executor push (SFTP fan-out)", () => {
  it("uploads to every host and aggregates bytes", async () => {
    const t = new MockTransport();
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.push(fleet, "/tmp/app.tar.gz", "/opt/app/app.tar.gz", { kind: "parallel" });
    expect(r.summary).toMatchObject({ total: 5, succeeded: 5, failed: 0, strategy: "parallel" });
    expect(r.results[0]).toMatchObject({ ok: true, bytes: 123 });
    expect(r.localPath).toBe("/tmp/app.tar.gz");
    expect(r.remotePath).toBe("/opt/app/app.tar.gz");
  });

  it("forwards AbortSignal through command, upload, and download boundaries", async () => {
    const t = new MockTransport();
    const ex = new Executor(t, DEFAULTS);
    const signal = new AbortController().signal;
    await ex.run([server("a")], "uptime", { kind: "parallel" }, { signal });
    await ex.push([server("a")], "/tmp/x", "/opt/x", { kind: "parallel" }, { signal });
    await ex.pull([server("a")], "/opt/x", "/tmp/x", { kind: "parallel" }, { signal });
    expect(t.options).toHaveLength(3);
    expect(t.options.every((opts) => opts.signal === signal)).toBe(true);
  });

  it("rolling circuit breaker skips remaining hosts after a failed batch", async () => {
    const t = new MockTransport(new Set(["a"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.push(fleet, "/tmp/x", "/opt/x", { kind: "rolling", batchSize: 1 });
    expect(t.uploads.map((u) => u.host)).toEqual(["a"]);
    expect(r.summary).toMatchObject({ failed: 1, skipped: 4, halted: true });
  });

  it("converts transport errors into per-host transfer failures", async () => {
    class ThrowUpload extends MockTransport {
      override async upload(s: ServerConfig): Promise<TransferResult> {
        if (this.failing.has(s.name)) throw new Error("disk full");
        return { host: s.name, ok: true, bytes: 1, durationMs: 1 };
      }
    }
    const t = new ThrowUpload(new Set(["d"]));
    const ex = new Executor(t, DEFAULTS);
    const r = await ex.push(fleet, "/tmp/x", "/opt/x", { kind: "parallel" });
    const d = r.results.find((x) => x.host === "d")!;
    expect(d).toMatchObject({ ok: false, error: "disk full" });
    expect(r.summary.failed).toBe(1);
  });
});

describe("Executor sudo passthrough", () => {
  it("forwards opts.sudo to the transport", async () => {
    class OptsRecorder extends MockTransport {
      seen: (boolean | undefined)[] = [];
      override async exec(s: ServerConfig, _cmd: string, opts: ExecOptions): Promise<ExecResult> {
        this.seen.push(opts.sudo);
        return { host: s.name, ok: true, exitCode: 0, stdout: "", stderr: "", durationMs: 1 };
      }
    }
    const t = new OptsRecorder();
    const ex = new Executor(t, DEFAULTS);
    await ex.run([server("a")], "id -u", { kind: "parallel" }, { sudo: true });
    await ex.run([server("a")], "id -u", { kind: "parallel" });
    expect(t.seen).toEqual([true, undefined]);
  });
});

describe("SshTransport sudo", () => {
  it("does not require a password env (NOPASSWD setups use sudo -n)", async () => {
    const { SshTransport } = await import("../src/ssh.js");
    const s = { ...server("nopw"), host: "127.0.0.1", port: 1 };
    const t = new SshTransport(new Map([[s.name, s]]));
    delete process.env.FLOTILLA_SUDO_PASSWORD;
    delete process.env.FLOTILLA_NOPW_SUDO_PASSWORD;
    // Must NOT fail fast with a "no sudo password" error; it proceeds to the
    // connection (which fails here because port 1 is closed).
    await expect(t.exec(s, "id -u", { sudo: true, timeoutMs: 500 })).rejects.not.toThrow(
      /no sudo password/i,
    );
  });
});
