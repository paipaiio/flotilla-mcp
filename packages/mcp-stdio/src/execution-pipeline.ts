import {
  classifyCommand,
  formatQuotaRefusal,
  type AuditEvent,
  type CommandClass,
  type PolicyDecision,
  type QuotaStatus,
  type ServerConfig,
} from "flotilla-core";

export type TargetInput = string | string[];

export interface PipelineApprovalRequest {
  tool: string;
  action: string;
  commandClass: string;
  hosts: string[];
  confirmFlag: boolean | undefined;
}

export type PipelineApprovalOutcome =
  | { kind: "approved"; via: string; remember?: boolean }
  | { kind: "refused"; reason: string };

export interface ExecutionPipelinePorts {
  resolve(target: TargetInput): ServerConfig[];
  decide(command: string, server: ServerConfig): PolicyDecision;
  approve(extra: unknown, request: PipelineApprovalRequest): Promise<PipelineApprovalOutcome>;
  quota?: {
    check(): QuotaStatus;
    record(): void;
  };
  audit(event: AuditEvent): void;
}

export interface PrepareCommandRequest {
  tool: string;
  target: TargetInput;
  /** Exact command evaluated by policy; include sudo when privilege is requested. */
  command: string;
  extra?: unknown;
  confirmFlag?: boolean;
  requiredClass?: CommandClass;
  /** policy = follow per-host needsApproval; always = gate regardless; never = skip. */
  approval?: "policy" | "always" | "never";
  approvalAction?: string;
  approvalClass?: string;
  quota?: boolean;
}

export interface PreparedCommand {
  ok: true;
  servers: ServerConfig[];
  commandClass: CommandClass;
}

export interface PreparationFailure {
  ok: false;
  message: string;
}

/**
 * One ordered pre-dispatch boundary shared by every command-bearing MCP tool:
 * resolve targets → classify/policy → approval → quota → quota consumption.
 */
export class ExecutionPipeline {
  constructor(private readonly ports: ExecutionPipelinePorts) {}

  async prepare(request: PrepareCommandRequest): Promise<PreparedCommand | PreparationFailure> {
    let servers: ServerConfig[];
    try {
      servers = this.ports.resolve(request.target);
    } catch (error) {
      return { ok: false, message: error instanceof Error ? error.message : String(error) };
    }

    const hosts = servers.map((server) => server.name);
    const commandClass = classifyCommand(request.command);
    if (request.requiredClass && commandClass !== request.requiredClass) {
      const reason = `tool requires ${request.requiredClass}, command classified as ${commandClass}`;
      this.deny(request.tool, request.command, commandClass, hosts, reason);
      return { ok: false, message: `Refused: ${reason}.` };
    }

    const refusals: string[] = [];
    let policyNeedsApproval = false;
    for (const server of servers) {
      const decision = this.ports.decide(request.command, server);
      if (!decision.allowed) refusals.push(`${server.name}: ${decision.reason ?? "policy denied"}`);
      policyNeedsApproval ||= decision.needsApproval;
    }
    if (refusals.length > 0) {
      this.deny(request.tool, request.command, commandClass, hosts, refusals.join("; "));
      return {
        ok: false,
        message: `Refused by policy (${commandClass}):\n${refusals.map((reason) => `  - ${reason}`).join("\n")}`,
      };
    }

    const approval = request.approval ?? "policy";
    if (approval === "always" || (approval === "policy" && policyNeedsApproval)) {
      const outcome = await this.ports.approve(request.extra, {
        tool: request.tool,
        action: request.approvalAction ?? request.command,
        commandClass: request.approvalClass ?? commandClass,
        hosts,
        confirmFlag: request.confirmFlag,
      });
      if (outcome.kind === "refused") return { ok: false, message: outcome.reason };
    }

    if (request.quota && this.ports.quota) {
      const status = this.ports.quota.check();
      if (!status.allowed) {
        this.deny(
          request.tool,
          request.command,
          "quota",
          hosts,
          `quota exhausted ${status.used}/${status.limit}`,
        );
        return { ok: false, message: formatQuotaRefusal(status) };
      }
      this.ports.quota.record();
    }

    return { ok: true, servers, commandClass };
  }

  auditExecution(
    tool: string,
    command: string,
    fanout: {
      results: { host: string }[];
      summary: { total: number; succeeded: number; failed: number; skipped: number; halted: boolean };
    },
  ): void {
    this.ports.audit({
      kind: "execution",
      tool,
      command,
      hosts: fanout.results.map((result) => result.host),
      outcome: fanout.summary.failed > 0 || fanout.summary.halted ? "failed" : "ok",
      results: {
        total: fanout.summary.total,
        succeeded: fanout.summary.succeeded,
        failed: fanout.summary.failed,
        skipped: fanout.summary.skipped,
      },
    });
  }

  private deny(tool: string, command: string, commandClass: string, hosts: string[], reason: string): void {
    this.ports.audit({ kind: "decision", tool, command, commandClass, hosts, outcome: "deny", reason });
  }
}
