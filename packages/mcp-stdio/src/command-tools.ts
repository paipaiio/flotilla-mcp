import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  buildSignalCommand,
  diffFanout,
  formatDiff,
  type Executor,
  type FanoutResult,
  type SignalName,
  type Strategy,
} from "flotilla-core";
import { ExecutionPipeline } from "./execution-pipeline.js";
import { parseStrategy, strategySchema } from "./tool-schemas.js";

type TextResult = {
  isError?: true;
  content: { type: "text"; text: string }[];
};

export interface CommandToolDependencies {
  getExecutor(): Executor | undefined;
  pipeline: ExecutionPipeline;
  notConfigured(): TextResult;
  errorResult(message: string): TextResult;
  formatFanout(result: FanoutResult): string;
}

/** Register command-bearing tools outside the stdio bootstrap entrypoint. */
export function registerCommandTools(server: McpServer, deps: CommandToolDependencies): void {
  server.registerTool(
    "exec-read",
    {
      description:
        "Run an allowlisted read-only command across a target. Uses the shared resolve/policy/approval/quota/audit boundary.",
      inputSchema: {
        target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
        command: z.string().describe("Read-only shell command"),
        timeoutMs: z.number().int().positive().optional(),
      },
    },
    async ({ target, command, timeoutMs }, extra) => {
      const executor = deps.getExecutor();
      if (!executor) return deps.notConfigured();
      try {
        const prepared = await deps.pipeline.prepare({
          tool: "exec-read", target, command, extra, requiredClass: "read-only", quota: true,
        });
        if (!prepared.ok) return deps.errorResult(prepared.message);
        const result = await executor.run(prepared.servers, command, { kind: "parallel" }, { timeoutMs, signal: extra.signal });
        deps.pipeline.auditExecution("exec-read", command, result);
        return { content: [{ type: "text" as const, text: deps.formatFanout(result) }] };
      } catch (error) {
        return deps.errorResult(error instanceof Error ? error.message : String(error));
      }
    },
  );

  server.registerTool(
    "fleet-diff",
    {
      description:
        "Run a read-only command across a target and group hosts by identical output. Uses the shared execution boundary.",
      inputSchema: {
        target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
        command: z.string().describe("Read-only shell command whose stdout is compared across hosts"),
        timeoutMs: z.number().int().positive().optional(),
      },
    },
    async ({ target, command, timeoutMs }, extra) => {
      const executor = deps.getExecutor();
      if (!executor) return deps.notConfigured();
      try {
        const prepared = await deps.pipeline.prepare({
          tool: "fleet-diff", target, command, extra, requiredClass: "read-only",
        });
        if (!prepared.ok) return deps.errorResult(prepared.message);
        const fanout = await executor.run(prepared.servers, command, { kind: "parallel" }, { timeoutMs, signal: extra.signal });
        deps.pipeline.auditExecution("fleet-diff", command, fanout);
        const report = diffFanout(fanout);
        const result = { content: [{ type: "text" as const, text: formatDiff(report) }] };
        return report.consistent ? result : { ...result, isError: true as const };
      } catch (error) {
        return deps.errorResult(error instanceof Error ? error.message : String(error));
      }
    },
  );

  server.registerTool(
    "exec",
    {
      description:
        "Run an arbitrary command through the shared resolve/policy/approval/quota/audit boundary. Risky multi-host commands default to rolling execution.",
      inputSchema: {
        target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
        command: z.string().describe("Shell command"),
        strategy: strategySchema.describe("parallel (default) | serial | rolling"),
        confirm: z.boolean().optional().describe("Set true to approve a destructive/privileged command"),
        timeoutMs: z.number().int().positive().optional(),
      },
    },
    async ({ target, command, strategy, confirm, timeoutMs }, extra) => {
      const executor = deps.getExecutor();
      if (!executor) return deps.notConfigured();
      try {
        const prepared = await deps.pipeline.prepare({
          tool: "exec", target, command, extra, confirmFlag: confirm, quota: true,
        });
        if (!prepared.ok) return deps.errorResult(prepared.message);
        const risky = ["unknown", "destructive", "privileged"].includes(prepared.commandClass);
        const fallback: Strategy = risky && prepared.servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" };
        const result = await executor.run(
          prepared.servers,
          command,
          parseStrategy(strategy, fallback),
          { timeoutMs, signal: extra.signal },
        );
        deps.pipeline.auditExecution("exec", command, result);
        const text = deps.formatFanout(result);
        return result.summary.failed > 0
          ? { isError: true as const, content: [{ type: "text" as const, text }] }
          : { content: [{ type: "text" as const, text }] };
      } catch (error) {
        return deps.errorResult(error instanceof Error ? error.message : String(error));
      }
    },
  );

  server.registerTool(
    "exec-sudo",
    {
      description:
        "Run a command through sudo. The shared execution boundary always requires approval and applies quota before SSH dispatch.",
      inputSchema: {
        target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
        command: z.string().describe("Shell command to run as root (sudo is prepended)"),
        strategy: strategySchema.describe("rolling (default for multi-host) | parallel | serial"),
        confirm: z.boolean().optional().describe("Set true to approve the privileged command"),
        timeoutMs: z.number().int().positive().optional(),
      },
    },
    async ({ target, command, strategy, confirm, timeoutMs }, extra) => {
      const executor = deps.getExecutor();
      if (!executor) return deps.notConfigured();
      try {
        const policyCommand = `sudo ${command}`;
        const prepared = await deps.pipeline.prepare({
          tool: "exec-sudo",
          target,
          command: policyCommand,
          extra,
          confirmFlag: confirm,
          approval: "always",
          approvalAction: policyCommand,
          approvalClass: "privileged (sudo)",
          quota: true,
        });
        if (!prepared.ok) return deps.errorResult(prepared.message);
        const fallback: Strategy = prepared.servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" };
        const result = await executor.run(
          prepared.servers,
          command,
          parseStrategy(strategy, fallback),
          { timeoutMs, sudo: true, signal: extra.signal },
        );
        deps.pipeline.auditExecution("exec-sudo", policyCommand, result);
        const text = deps.formatFanout(result);
        return result.summary.failed > 0
          ? { isError: true as const, content: [{ type: "text" as const, text }] }
          : { content: [{ type: "text" as const, text }] };
      } catch (error) {
        return deps.errorResult(error instanceof Error ? error.message : String(error));
      }
    },
  );

  server.registerTool(
    "signal-process",
    {
      description:
        "Send INT/TERM/KILL/HUP to a numeric remote PID. The shared execution boundary always requires approval.",
      inputSchema: {
        target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
        pid: z.number().int().positive().describe("Remote process ID"),
        signal: z.enum(["INT", "TERM", "KILL", "HUP"]).describe("Signal to send"),
        strategy: strategySchema.describe("serial (default for multi-host) | parallel | rolling"),
        sudo: z.boolean().optional().describe("Send the signal as root via sudo"),
        confirm: z.boolean().optional().describe("Set true to approve (when confirm flag is enabled)"),
        timeoutMs: z.number().int().positive().optional(),
      },
    },
    async ({ target, pid, signal, strategy, sudo, confirm, timeoutMs }, extra) => {
      const executor = deps.getExecutor();
      if (!executor) return deps.notConfigured();
      try {
        const command = buildSignalCommand(pid, signal as SignalName);
        const policyCommand = sudo ? `sudo ${command}` : command;
        const prepared = await deps.pipeline.prepare({
          tool: "signal-process",
          target,
          command: policyCommand,
          extra,
          confirmFlag: confirm,
          approval: "always",
          approvalAction: `kill -${signal} ${pid}${sudo ? " (via sudo)" : ""}`,
          approvalClass: sudo ? "privileged (signal-process)" : "destructive (signal-process)",
        });
        if (!prepared.ok) return deps.errorResult(prepared.message);
        const fallback: Strategy = prepared.servers.length > 1 ? { kind: "serial" } : { kind: "parallel" };
        const result = await executor.run(
          prepared.servers,
          command,
          parseStrategy(strategy, fallback),
          { timeoutMs, sudo, signal: extra.signal },
        );
        deps.pipeline.auditExecution("signal-process", policyCommand, result);
        const text = deps.formatFanout(result);
        return result.summary.failed > 0
          ? { isError: true as const, content: [{ type: "text" as const, text }] }
          : { content: [{ type: "text" as const, text }] };
      } catch (error) {
        return deps.errorResult(error instanceof Error ? error.message : String(error));
      }
    },
  );
}
