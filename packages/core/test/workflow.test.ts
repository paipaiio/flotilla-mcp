import { describe, expect, it } from "vitest";
import { Executor } from "../src/executor.js";
import { FleetRegistry } from "../src/registry.js";
import {
  interpolate,
  parseWorkflow,
  WorkflowError,
  WorkflowRunner,
  type StepOutcome,
} from "../src/workflow.js";
import type {
  DefaultsConfig,
  ExecOptions,
  ExecResult,
  FleetConfig,
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

function makeConfig(names: string[]): FleetConfig {
  return { defaults: DEFAULTS, servers: names.map(server), groups: [] };
}

class MockTransport implements Transport {
  commands: string[] = [];
  constructor(
    private readonly failing: Set<string> = new Set(),
    private readonly failOnCommand?: RegExp,
  ) {}
  async exec(s: ServerConfig, cmd: string, _opts: ExecOptions): Promise<ExecResult> {
    this.commands.push(cmd);
    const base = { host: s.name, stdout: "", stderr: "", durationMs: 1 };
    if (this.failOnCommand?.test(cmd) || this.failing.has(s.name)) {
      return { ...base, ok: false, exitCode: 1, stderr: "boom" };
    }
    return { ...base, ok: true, exitCode: 0, stdout: `out-${s.name}\n` };
  }
  async upload(s: ServerConfig): Promise<TransferResult> {
    return { host: s.name, ok: true, bytes: 1, durationMs: 1 };
  }
  async download(s: ServerConfig): Promise<TransferResult> {
    return { host: s.name, ok: true, bytes: 1, durationMs: 1 };
  }
  async close(): Promise<void> {}
}

const allowAll = () => null;

function runner(transport: Transport, names = ["a", "b"]): WorkflowRunner {
  return new WorkflowRunner(
    new FleetRegistry(makeConfig(names)),
    new Executor(transport, DEFAULTS),
    DEFAULTS,
    allowAll,
  );
}

describe("parseWorkflow", () => {
  it("parses a valid workflow", () => {
    const def = parseWorkflow(`
name: demo
steps:
  - name: check
    type: exec
    target: all
    command: uptime
  - name: restart
    type: service
    target: a
    unit: myapp
    action: restart
    onError: rollback
    rollback:
      - name: revert
        type: exec
        target: a
        command: echo revert
`);
    expect(def.name).toBe("demo");
    expect(def.steps).toHaveLength(2);
    expect(def.steps[1]!.rollback).toHaveLength(1);
  });

  it("rejects duplicate step names and missing fields", () => {
    expect(() =>
      parseWorkflow(`name: x\nsteps:\n  - {name: a, type: exec, target: all, command: ls}\n  - {name: a, type: exec, target: all, command: ls}`),
    ).toThrow(WorkflowError);
    expect(() => parseWorkflow(`name: x\nsteps:\n  - {name: a, type: push, target: all}`)).toThrow(
      /requires localPath and remotePath/,
    );
    expect(() => parseWorkflow(`name: x\nsteps:\n  - {name: a, type: service, target: all, unit: "bad;rm", action: restart}`)).toThrow();
  });
});

describe("interpolate", () => {
  const outcomes: StepOutcome[] = [
    { name: "gather", ok: true, stdout: "v1.2.3", hosts: "a,b" },
  ];
  it("substitutes stdout and hosts", () => {
    expect(interpolate("deploy {{ steps.gather.stdout }}", outcomes)).toBe("deploy v1.2.3");
    expect(interpolate("{{ steps.gather.hosts }}", outcomes)).toBe("a,b");
  });
  it("throws on unknown step or missing field", () => {
    expect(() => interpolate("{{ steps.nope.stdout }}", outcomes)).toThrow(/unknown step/);
    expect(() => interpolate("{{ steps.gather.stdout }}", [{ name: "gather", ok: false }])).toThrow(
      /no stdout/,
    );
  });
});

describe("WorkflowRunner", () => {
  it("runs steps in order and aggregates", async () => {
    const t = new MockTransport();
    const r = runner(t);
    const result = await r.run(
      parseWorkflow(`
name: demo
steps:
  - {name: s1, type: exec, target: all, command: uptime}
  - {name: s2, type: exec, target: a, command: hostname}
`),
    );
    expect(result.ok).toBe(true);
    expect(result.steps.map((s) => s.ok)).toEqual([true, true]);
    expect(result.steps[0]!.hosts).toBe("a,b");
  });

  it("feeds earlier stdout into later commands", async () => {
    const t = new MockTransport();
    const r = runner(t);
    const result = await r.run(
      parseWorkflow(`
name: demo
steps:
  - {name: s1, type: exec, target: a, command: cat version.txt}
  - {name: s2, type: exec, target: a, command: "deploy {{ steps.s1.stdout }}"}
`),
    );
    expect(result.ok).toBe(true);
    expect(t.commands).toContain("deploy out-a");
  });

  it("stop onError halts the run", async () => {
    const t = new MockTransport(new Set(), /failme/);
    const r = runner(t);
    const result = await r.run(
      parseWorkflow(`
name: demo
steps:
  - {name: bad, type: exec, target: a, command: failme}
  - {name: after, type: exec, target: a, command: echo never}
`),
    );
    expect(result.halted).toBe(true);
    expect(result.haltedAt).toBe("bad");
    expect(t.commands).not.toContain("echo never");
  });

  it("continue onError records and moves on", async () => {
    const t = new MockTransport(new Set(), /failme/);
    const r = runner(t);
    const result = await r.run(
      parseWorkflow(`
name: demo
steps:
  - {name: bad, type: exec, target: a, command: failme, onError: continue}
  - {name: after, type: exec, target: a, command: echo ran}
`),
    );
    expect(result.halted).toBe(false);
    expect(t.commands).toContain("echo ran");
    expect(result.ok).toBe(false); // completed, but with a failed step
  });

  it("rollback onError runs failed step's rollback then previous steps' in reverse", async () => {
    const t = new MockTransport(new Set(), /failme/);
    const r = runner(t);
    const result = await r.run(
      parseWorkflow(`
name: demo
steps:
  - name: one
    type: exec
    target: a
    command: echo one
    rollback:
      - {name: r1, type: exec, target: a, command: echo undo-one}
  - name: two
    type: exec
    target: a
    command: failme
    onError: rollback
    rollback:
      - {name: r2, type: exec, target: a, command: echo undo-two}
`),
    );
    expect(result.rolledBack).toBe(true);
    const undoOrder = t.commands.filter((c) => c.startsWith("echo undo"));
    expect(undoOrder).toEqual(["echo undo-two", "echo undo-one"]);
    expect(result.steps.map((s) => s.name)).toEqual(["one", "two", "rollback:r2", "rollback:r1"]);
  });

  it("policy refusals fail the step without executing", async () => {
    const t = new MockTransport();
    const denyAll = () => "denied by test";
    const r = new WorkflowRunner(
      new FleetRegistry(makeConfig(["a"])),
      new Executor(t, DEFAULTS),
      DEFAULTS,
      denyAll,
    );
    const result = await r.run(
      parseWorkflow(`name: x\nsteps:\n  - {name: s, type: exec, target: a, command: ls}`),
    );
    expect(result.ok).toBe(false);
    expect(result.steps[0]!.error).toMatch(/Refused by policy/);
    expect(t.commands).toHaveLength(0);
  });

  it("plan() reports classes and approval needs without executing", () => {
    const t = new MockTransport();
    const r = runner(t);
    const plan = r.plan(
      parseWorkflow(`
name: demo
steps:
  - {name: ro, type: exec, target: all, command: uptime}
  - {name: svc, type: service, target: all, unit: app, action: restart}
  - {name: priv, type: exec-sudo, target: all, command: id}
`),
    );
    expect(plan.map((p) => p.commandClass)).toEqual(["read-only", "destructive", "privileged"]);
    expect(plan.map((p) => p.needsApproval)).toEqual([false, true, true]);
    expect(plan.every((p) => p.refusals.length === 0)).toBe(true);
    expect(t.commands).toHaveLength(0);
  });
});
