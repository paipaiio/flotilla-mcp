/**
 * Declarative linear workflows (v1).
 *
 * A workflow is a YAML document of ordered steps. Each step fans out to its
 * own target expression, so a single run can hop across machines. Steps may
 * reference earlier steps' output with {{ steps.<name>.stdout }} (first
 * successful host, trimmed) and {{ steps.<name>.hosts }} (comma-separated
 * successful host names — usable as a later step's target).
 *
 * Failure handling per step (onError):
 *   stop     (default) halt the run
 *   continue record the failure, move on
 *   rollback run this step's rollback block, then the rollback blocks of
 *            previously succeeded steps in reverse order, then halt
 *
 * The engine never calls decide() itself — the caller injects checkPolicy so
 * the MCP/CLI front-ends keep owning the role x tier matrix and approval.
 */
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { buildControlCommand, checkServiceScope, validateUnit, type ServiceAction } from "./service.js";
import { checkPathScope, classifyCommand } from "./policy.js";
import { resolveTarget } from "./target.js";
import type { Executor, Strategy } from "./executor.js";
import type { FleetRegistry } from "./registry.js";
import type { DefaultsConfig, FanoutResult, ServerConfig, TransferFanoutResult } from "./types.js";

const stepSchema = z.object({
  name: z.string().min(1).max(64),
  type: z.enum(["exec", "exec-sudo", "push", "service"]),
  target: z.string().min(1),
  command: z.string().optional(),
  localPath: z.string().optional(),
  remotePath: z.string().optional(),
  unit: z.string().optional(),
  action: z.enum(["start", "stop", "restart", "reload"]).optional(),
  /** service steps only: run systemctl via sudo (policy sees the privileged class). */
  sudo: z.boolean().optional(),
  strategy: z.enum(["parallel", "serial", "rolling"]).optional(),
  onError: z.enum(["stop", "continue", "rollback"]).optional(),
  rollback: z
    .array(
      z.object({
        name: z.string().min(1).max(64),
        type: z.enum(["exec", "exec-sudo"]),
        target: z.string().min(1),
        command: z.string().min(1),
        timeoutMs: z.number().int().positive().optional(),
      }),
    )
    .optional(),
  timeoutMs: z.number().int().positive().optional(),
});

const workflowSchema = z.object({
  name: z.string().min(1).max(64),
  steps: z.array(stepSchema).min(1).max(50),
});

export type WorkflowStep = z.infer<typeof stepSchema>;
export type WorkflowDef = z.infer<typeof workflowSchema>;

export class WorkflowError extends Error {}

export function parseWorkflow(yamlText: string): WorkflowDef {
  let raw: unknown;
  try {
    raw = parseYaml(yamlText);
  } catch (err) {
    throw new WorkflowError(`Invalid YAML: ${err instanceof Error ? err.message : String(err)}`);
  }
  const parsed = workflowSchema.safeParse(raw);
  if (!parsed.success) {
    throw new WorkflowError(
      "Invalid workflow: " + parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "),
    );
  }
  const def = parsed.data;
  // Structural checks the schema can't express.
  const names = new Set<string>();
  for (const step of def.steps) {
    if (names.has(step.name)) throw new WorkflowError(`Duplicate step name "${step.name}"`);
    names.add(step.name);
    switch (step.type) {
      case "exec":
      case "exec-sudo":
        if (!step.command) throw new WorkflowError(`Step "${step.name}": ${step.type} requires command`);
        break;
      case "push":
        if (!step.localPath || !step.remotePath)
          throw new WorkflowError(`Step "${step.name}": push requires localPath and remotePath`);
        break;
      case "service":
        if (!step.unit || !step.action)
          throw new WorkflowError(`Step "${step.name}": service requires unit and action`);
        validateUnit(step.unit);
        break;
    }
  }
  return def;
}

// ── interpolation ──

export interface StepOutcome {
  name: string;
  ok: boolean;
  skipped?: boolean;
  error?: string;
  fanout?: FanoutResult | TransferFanoutResult;
  /** Trimmed stdout of the first successful host (exec-type steps). */
  stdout?: string;
  /** Comma-separated successful host names. */
  hosts?: string;
}

const PLACEHOLDER = /\{\{\s*steps\.([A-Za-z0-9_-]{1,64})\.(stdout|hosts)\s*\}\}/g;

export function interpolate(input: string, outcomes: StepOutcome[]): string {
  return input.replace(PLACEHOLDER, (_, name: string, field: "stdout" | "hosts") => {
    const o = outcomes.find((x) => x.name === name);
    if (!o) throw new WorkflowError(`Interpolation references unknown step "${name}"`);
    const value = field === "stdout" ? o.stdout : o.hosts;
    if (value === undefined) {
      throw new WorkflowError(`Step "${name}" has no ${field} (did it fail or run a non-exec type?)`);
    }
    return value;
  });
}

// ── planning (policy view of the whole run, before anything executes) ──

export interface PlannedStep {
  step: WorkflowStep;
  commandClass: string;
  needsApproval: boolean;
  refusals: string[];
}

export type PolicyChecker = (command: string, server: ServerConfig) => string | null;

export interface WorkflowResult {
  name: string;
  ok: boolean;
  halted: boolean;
  haltedAt?: string;
  rolledBack: boolean;
  steps: StepOutcome[];
}

export class WorkflowRunner {
  constructor(
    private readonly registry: FleetRegistry,
    private readonly executor: Executor,
    private readonly defaults: DefaultsConfig,
    private readonly checkPolicy: PolicyChecker,
  ) {}

  /**
   * Static policy pass over every step (targets resolved, commands built —
   * but NOT interpolated yet: placeholders referencing earlier outputs are
   * checked again at execution time). Callers use this to gate one approval
   * for the whole run before executing anything.
   */
  plan(def: WorkflowDef): PlannedStep[] {
    return def.steps.map((step) => {
      const refusals: string[] = [];
      let needsApproval = false;
      let commandClass = "safe";
      try {
        const servers = resolveTarget(this.registry, step.target);
        const probe = this.stepProbeCommand(step);
        commandClass = classifyCommand(probe);
        for (const s of servers) {
          const reason = this.checkPolicy(probe, s);
          if (reason) refusals.push(`${s.name}: ${reason}`);
        }
        // Scope layers that aren't command-shaped.
        for (const s of servers) {
          if (step.type === "push") {
            if (s.readOnly) refusals.push(`${s.name}: server is configured readOnly`);
            const scope = checkPathScope(s, step.remotePath!);
            if (scope) refusals.push(scope);
          }
          if (step.type === "service") {
            const scope = checkServiceScope(s, validateUnit(step.unit!));
            if (scope) refusals.push(scope);
          }
        }
        needsApproval = commandClass === "unknown" || commandClass === "destructive" || commandClass === "privileged";
      } catch (err) {
        refusals.push(err instanceof Error ? err.message : String(err));
      }
      return { step, commandClass, needsApproval, refusals };
    });
  }

  /** Execute the workflow. Callers must have approved the plan already. */
  async run(def: WorkflowDef): Promise<WorkflowResult> {
    const outcomes: StepOutcome[] = [];
    let halted = false;
    let haltedAt: string | undefined;
    let rolledBack = false;

    for (const step of def.steps) {
      const outcome = await this.runStep(step, outcomes);
      outcomes.push(outcome);
      if (outcome.ok) continue;

      const onError = step.onError ?? "stop";
      if (onError === "continue") continue;

      halted = true;
      haltedAt = step.name;
      if (onError === "rollback") {
        rolledBack = true;
        // Failed step's own rollback first…
        if (step.rollback) {
          for (const rb of step.rollback) {
            outcomes.push(await this.runRollback(rb, outcomes));
          }
        }
        // …then previously succeeded steps' rollbacks, in reverse.
        const failedIdx = def.steps.findIndex((s) => s.name === step.name);
        for (const prev of def.steps.slice(0, failedIdx).reverse()) {
          const prevOutcome = outcomes.find((o) => o.name === prev.name);
          if (!prevOutcome?.ok || !prev.rollback) continue;
          for (const rb of prev.rollback) {
            outcomes.push(await this.runRollback(rb, outcomes));
          }
        }
      }
      break;
    }

    const ok = !halted && outcomes.every((o) => o.ok || o.skipped);
    return { name: def.name, ok, halted, haltedAt, rolledBack, steps: outcomes };
  }

  // ── internals ──

  private stepProbeCommand(step: WorkflowStep): string {
    switch (step.type) {
      case "exec":
        return step.command!;
      case "exec-sudo":
        return `sudo ${step.command!}`;
      case "push":
        // Uploads overwrite: same probe the fleet-push tool uses.
        return "rm -rf <upload-overwrite>";
      case "service": {
        const cmd = buildControlCommand(validateUnit(step.unit!), step.action as ServiceAction);
        return step.sudo ? `sudo ${cmd}` : cmd;
      }
    }
  }

  private stepStrategy(step: WorkflowStep, servers: ServerConfig[]): Strategy {
    if (step.strategy) return { kind: step.strategy, stopOnError: step.strategy === "serial" };
    const probe = this.stepProbeCommand(step);
    const cls = classifyCommand(probe);
    const gated = cls === "unknown" || cls === "destructive" || cls === "privileged" || step.type === "push";
    return gated && servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" };
  }

  private interpolateStep(step: WorkflowStep, outcomes: StepOutcome[]): WorkflowStep {
    const fields = [step.command, step.remotePath, step.localPath, step.unit, step.target];
    if (!fields.some((f) => f?.includes("{{"))) return step;
    const sub = (s: string | undefined) => (s ? interpolate(s, outcomes) : s);
    return {
      ...step,
      target: sub(step.target)!,
      command: sub(step.command),
      remotePath: sub(step.remotePath),
      localPath: sub(step.localPath),
      unit: sub(step.unit),
    };
  }

  private async runStep(rawStep: WorkflowStep, outcomes: StepOutcome[]): Promise<StepOutcome> {
    let step: WorkflowStep;
    try {
      step = this.interpolateStep(rawStep, outcomes);
    } catch (err) {
      return { name: rawStep.name, ok: false, error: err instanceof Error ? err.message : String(err) };
    }

    let servers: ServerConfig[];
    try {
      servers = resolveTarget(this.registry, step.target);
    } catch (err) {
      return { name: step.name, ok: false, error: err instanceof Error ? err.message : String(err) };
    }

    // Policy again post-interpolation: a placeholder could smuggle anything.
    const probe = this.stepProbeCommand(step);
    const refusals: string[] = [];
    for (const s of servers) {
      const reason = this.checkPolicy(probe, s);
      if (reason) refusals.push(`${s.name}: ${reason}`);
      if (step.type === "push") {
        if (s.readOnly) refusals.push(`${s.name}: server is configured readOnly`);
        const scope = checkPathScope(s, step.remotePath!);
        if (scope) refusals.push(scope);
      }
      if (step.type === "service") {
        const scope = checkServiceScope(s, validateUnit(step.unit!));
        if (scope) refusals.push(scope);
      }
    }
    if (refusals.length > 0) {
      return { name: step.name, ok: false, error: `Refused by policy:\n  - ${refusals.join("\n  - ")}` };
    }

    const strategy = this.stepStrategy(step, servers);
    const timeoutMs = step.timeoutMs ?? this.defaults.commandTimeoutMs;

    try {
      switch (step.type) {
        case "exec":
        case "exec-sudo": {
          const fanout = await this.executor.run(servers, step.command!, strategy, {
            timeoutMs,
            sudo: step.type === "exec-sudo",
          });
          return this.outcomeFromFanout(step.name, fanout);
        }
        case "push": {
          const fanout = await this.executor.push(servers, step.localPath!, step.remotePath!, strategy, {
            timeoutMs,
          });
          return this.outcomeFromFanout(step.name, fanout);
        }
        case "service": {
          const unit = validateUnit(step.unit!);
          const command = buildControlCommand(unit, step.action as ServiceAction);
          const fanout = await this.executor.run(servers, command, strategy, {
            timeoutMs,
            sudo: step.sudo,
          });
          return this.outcomeFromFanout(step.name, fanout);
        }
      }
    } catch (err) {
      return { name: step.name, ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  private async runRollback(
    rb: NonNullable<WorkflowStep["rollback"]>[number],
    outcomes: StepOutcome[],
  ): Promise<StepOutcome> {
    const asStep: WorkflowStep = { ...rb, name: `rollback:${rb.name}`, onError: "continue" };
    const outcome = await this.runStep(asStep, outcomes);
    return { ...outcome, name: asStep.name };
  }

  private outcomeFromFanout(
    name: string,
    fanout: FanoutResult | TransferFanoutResult,
  ): StepOutcome {
    const ok = fanout.summary.failed === 0 && !fanout.summary.halted;
    const base: StepOutcome = { name, ok, fanout };
    if ("results" in fanout) {
      const first = fanout.results[0];
      if (first && "stdout" in first && first.ok) base.stdout = first.stdout.trim();
      base.hosts = fanout.results.filter((r) => r.ok).map((r) => r.host).join(",");
    }
    if (!ok) base.error = `${fanout.summary.failed} host(s) failed${fanout.summary.halted ? ", circuit breaker halted" : ""}`;
    return base;
  }
}
