import { describe, expect, it, vi } from "vitest";
import type { Executor, FanoutResult, ServerConfig } from "flotilla-core";
import { registerCommandTools } from "../src/command-tools.js";
import type { ExecutionPipeline } from "../src/execution-pipeline.js";

type Handler = (input: Record<string, any>, extra: { signal: AbortSignal }) => Promise<any>;

const host = (name: string): ServerConfig => ({
  name, host: name, port: 22, user: "u", auth: "agent", group: "dev", tags: [], role: "admin", readOnly: false,
});

function fanout(command: string, failed = 0): FanoutResult {
  return {
    command,
    results: [{ host: "a", ok: failed === 0, exitCode: failed === 0 ? 0 : 1, stdout: "up", stderr: "", durationMs: 1 }],
    summary: { total: 1, succeeded: failed === 0 ? 1 : 0, failed, skipped: 0, halted: false, strategy: "parallel" },
  };
}

const inputs: Record<string, Record<string, unknown>> = {
  "exec-read": { target: "all", command: "uptime", timeoutMs: 500 },
  "fleet-diff": { target: "all", command: "uname -a", timeoutMs: 500 },
  exec: { target: "all", command: "deploy app", confirm: true, timeoutMs: 500 },
  "exec-sudo": { target: "all", command: "id", confirm: true, timeoutMs: 500 },
  "signal-process": { target: "all", pid: 123, signal: "TERM", confirm: true, timeoutMs: 500 },
};

function setup(options: { executor?: boolean; failed?: number; commandClass?: "read-only" | "unknown" } = {}) {
  const handlers = new Map<string, Handler>();
  const server = {
    registerTool: vi.fn((name: string, _definition: unknown, handler: Handler) => handlers.set(name, handler)),
  };
  const pipeline = {
    prepare: vi.fn(async () => ({
      ok: true as const,
      servers: [host("a"), host("b")],
      commandClass: options.commandClass ?? "read-only",
    })),
    auditExecution: vi.fn(),
  };
  const executor = { run: vi.fn(async (_servers, command: string) => fanout(command, options.failed ?? 0)) };
  const notConfigured = vi.fn(() => ({ isError: true as const, content: [{ type: "text" as const, text: "missing" }] }));
  const errorResult = vi.fn((message: string) => ({ isError: true as const, content: [{ type: "text" as const, text: message }] }));

  registerCommandTools(server as never, {
    getExecutor: () => options.executor === false ? undefined : executor as unknown as Executor,
    pipeline: pipeline as unknown as ExecutionPipeline,
    notConfigured,
    errorResult,
    formatFanout: () => "formatted",
  });
  return { handlers, pipeline, executor, notConfigured, errorResult };
}

describe("registerCommandTools", () => {
  it("registers the complete command tool pack", () => {
    expect([...setup().handlers.keys()]).toEqual(["exec-read", "fleet-diff", "exec", "exec-sudo", "signal-process"]);
  });

  it("routes exec-read through the shared pipeline and forwards cancellation", async () => {
    const h = setup();
    const signal = new AbortController().signal;
    const result = await h.handlers.get("exec-read")!(inputs["exec-read"]!, { signal });
    expect(result.content[0].text).toBe("formatted");
    expect(h.pipeline.prepare).toHaveBeenCalledWith(expect.objectContaining({
      tool: "exec-read", target: "all", command: "uptime", requiredClass: "read-only", quota: true,
    }));
    expect(h.executor.run).toHaveBeenCalledWith(expect.any(Array), "uptime", { kind: "parallel" }, { timeoutMs: 500, signal });
    expect(h.pipeline.auditExecution).toHaveBeenCalledWith("exec-read", "uptime", expect.any(Object));
  });

  it("executes fleet-diff and formats a consistent report", async () => {
    const h = setup();
    const result = await h.handlers.get("fleet-diff")!(inputs["fleet-diff"]!, { signal: new AbortController().signal });
    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toMatch(/CONSISTENT/);
    expect(h.pipeline.prepare).toHaveBeenCalledWith(expect.objectContaining({ tool: "fleet-diff", requiredClass: "read-only" }));
  });

  it("uses rolling execution for risky multi-host exec and marks fanout failure", async () => {
    const h = setup({ failed: 1, commandClass: "unknown" });
    const result = await h.handlers.get("exec")!(inputs.exec!, { signal: new AbortController().signal });
    expect(result.isError).toBe(true);
    expect(h.executor.run).toHaveBeenCalledWith(expect.any(Array), "deploy app", { kind: "rolling" }, expect.objectContaining({ timeoutMs: 500 }));
    expect(h.pipeline.prepare).toHaveBeenCalledWith(expect.objectContaining({ confirmFlag: true, quota: true }));
  });

  it("forces sudo approval semantics and sudo transport execution", async () => {
    const h = setup();
    await h.handlers.get("exec-sudo")!(inputs["exec-sudo"]!, { signal: new AbortController().signal });
    expect(h.pipeline.prepare).toHaveBeenCalledWith(expect.objectContaining({
      tool: "exec-sudo", command: "sudo id", approval: "always", approvalClass: "privileged (sudo)", quota: true,
    }));
    expect(h.executor.run).toHaveBeenCalledWith(expect.any(Array), "id", { kind: "rolling" }, expect.objectContaining({ sudo: true }));
  });

  it("builds a validated signal command and defaults multi-host dispatch to serial", async () => {
    const h = setup();
    await h.handlers.get("signal-process")!(inputs["signal-process"]!, { signal: new AbortController().signal });
    expect(h.pipeline.prepare).toHaveBeenCalledWith(expect.objectContaining({
      tool: "signal-process", command: "kill -TERM 123", approval: "always",
    }));
    expect(h.executor.run).toHaveBeenCalledWith(expect.any(Array), "kill -TERM 123", { kind: "serial" }, expect.objectContaining({ sudo: undefined }));
  });

  it("returns the not-configured result from every handler before pipeline work", async () => {
    const h = setup({ executor: false });
    for (const [name, input] of Object.entries(inputs)) {
      const result = await h.handlers.get(name)!(input, { signal: new AbortController().signal });
      expect(result.content[0].text).toBe("missing");
    }
    expect(h.notConfigured).toHaveBeenCalledTimes(5);
    expect(h.pipeline.prepare).not.toHaveBeenCalled();
  });

  it("returns audited pipeline refusals without reaching the executor", async () => {
    const h = setup();
    h.pipeline.prepare.mockResolvedValue({ ok: false, message: "policy denied" } as never);
    for (const [name, input] of Object.entries(inputs)) {
      const result = await h.handlers.get(name)!(input, { signal: new AbortController().signal });
      expect(result.content[0].text).toBe("policy denied");
    }
    expect(h.executor.run).not.toHaveBeenCalled();
  });

  it("normalizes thrown values through the common error result", async () => {
    const h = setup();
    h.pipeline.prepare.mockRejectedValue(new Error("pipeline exploded"));
    for (const [name, input] of Object.entries(inputs)) {
      const result = await h.handlers.get(name)!(input, { signal: new AbortController().signal });
      expect(result.content[0].text).toBe("pipeline exploded");
    }
    expect(h.errorResult).toHaveBeenCalledTimes(5);
  });
});
