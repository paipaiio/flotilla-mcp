#!/usr/bin/env node
/**
 * Flotilla stdio MCP server (v0.1).
 *
 * Tools: fleet-list, fleet-resolve, exec-read, exec.
 * Config resolution order: --config <path> -> FLOTILLA_CONFIG -> platform default.
 * Without a config the server still starts (so MCP handshake and tools/list work)
 * but every tool call is refused with a message naming the expected path.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  Executor,
  FleetRegistry,
  SshTransport,
  classifyCommand,
  checkPathScope,
  decide,
  defaultConfigPath,
  diffFanout,
  formatDiff,
  loadFleetConfig,
  resolveTarget,
  type FanoutResult,
  type FleetConfig,
  type Strategy,
} from "@flotilla/core";

const MAX_OUTPUT_CHARS_PER_HOST = 8_000;

interface AppContext {
  config?: FleetConfig;
  configError?: string;
  registry?: FleetRegistry;
  executor?: Executor;
  transport?: SshTransport;
}

function initContext(): AppContext {
  const argv = process.argv.slice(2);
  const flagIdx = argv.indexOf("--config");
  const configPath = flagIdx >= 0 ? argv[flagIdx + 1] : undefined;

  try {
    const config = loadFleetConfig(configPath);
    const registry = new FleetRegistry(config);
    const transport = new SshTransport(
      new Map(config.servers.map((s) => [s.name, s])),
    );
    return {
      config,
      registry,
      transport,
      executor: new Executor(transport, config.defaults),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`flotilla-mcp: starting unconfigured (${message})`);
    return { configError: message };
  }
}

const ctx = initContext();

function notConfigured() {
  return {
    isError: true as const,
    content: [
      {
        type: "text" as const,
        text:
          `Flotilla is not configured: ${ctx.configError}\n` +
          `Expected config at ${defaultConfigPath()} (or pass --config <path> / set FLOTILLA_CONFIG).`,
      },
    ],
  };
}

function errorResult(message: string) {
  return { isError: true as const, content: [{ type: "text" as const, text: message }] };
}

function truncate(s: string): string {
  return s.length > MAX_OUTPUT_CHARS_PER_HOST
    ? s.slice(0, MAX_OUTPUT_CHARS_PER_HOST) + `\n... [truncated, ${s.length} chars total]`
    : s;
}

function formatFanout(result: FanoutResult): string {
  const { summary } = result;
  const lines: string[] = [
    `strategy=${summary.strategy} total=${summary.total} succeeded=${summary.succeeded} failed=${summary.failed} skipped=${summary.skipped}${summary.halted ? " HALTED(circuit-breaker)" : ""}`,
    "",
  ];
  for (const r of result.results) {
    const status = r.skipped ? "SKIP" : r.ok ? "OK  " : "FAIL";
    lines.push(`── ${status} ${r.host} (exit=${r.exitCode ?? "-"}, ${r.durationMs}ms)`);
    if (r.error) lines.push(`error: ${r.error}`);
    if (r.stdout) lines.push(truncate(r.stdout.trimEnd()));
    if (r.stderr) lines.push(`stderr: ${truncate(r.stderr.trimEnd())}`);
    lines.push("");
  }
  return lines.join("\n");
}

const server = new McpServer(
  { name: "flotilla-mcp", version: "0.1.0" },
  {
    instructions:
      "Flotilla manages a fleet of SSH servers. Address hosts with target expressions: " +
      "a server name, group:<name>, tag:<tag>, all, comma-separated unions, and !exclusions. " +
      "Use fleet-resolve to preview a target before running anything. " +
      "exec-read is for allowlisted read-only commands; exec is for everything else and " +
      "enforces the policy engine (forbidden list, role x tier matrix, approval gate).",
  },
);

server.registerTool(
  "fleet-list",
  {
    description:
      "List all servers, groups, tags, and tiers in the fleet, with each server's role and policy tier.",
    inputSchema: {},
  },
  async () => {
    if (!ctx.registry) return notConfigured();
    const servers = ctx.registry.servers().map((s) => ({
      name: s.name,
      host: `${s.user}@${s.host}:${s.port}`,
      tier: s.group,
      tags: s.tags,
      role: s.role,
      readOnly: s.readOnly,
      via: s.via,
    }));
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              servers,
              groups: ctx.registry.groups(),
              tiers: ctx.registry.allTiers(),
              tags: ctx.registry.allTags(),
              defaults: ctx.config!.defaults,
            },
            null,
            2,
          ),
        },
      ],
    };
  },
);

server.registerTool(
  "fleet-resolve",
  {
    description:
      "Dry-run a target expression and return the servers it matches. Always do this before a destructive fan-out.",
    inputSchema: {
      target: z
        .union([z.string(), z.array(z.string())])
        .describe('Target expression, e.g. "web-1", "group:web-prod", "tag:web !web-3", "all"'),
    },
  },
  async ({ target }) => {
    if (!ctx.registry) return notConfigured();
    try {
      const servers = resolveTarget(ctx.registry, target);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              servers.map((s) => ({ name: s.name, host: s.host, tier: s.group, role: s.role })),
              null,
              2,
            ),
          },
        ],
      };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

const strategySchema = z
  .union([
    z.literal("parallel"),
    z.literal("serial"),
    z.literal("rolling"),
    z.object({
      kind: z.literal("rolling"),
      batchSize: z.number().int().positive().optional(),
      maxBatchFailures: z.number().int().min(0).optional(),
    }),
    z.object({ kind: z.literal("serial"), stopOnError: z.boolean().optional() }),
    z.object({ kind: z.literal("parallel"), concurrency: z.number().int().positive().optional() }),
  ])
  .optional();

function parseStrategy(raw: z.infer<typeof strategySchema>, fallback: Strategy): Strategy {
  if (!raw) return fallback;
  if (typeof raw === "string") return { kind: raw } as Strategy;
  return raw as Strategy;
}

server.registerTool(
  "exec-read",
  {
    description:
      "Run an allowlisted read-only command (ls, cat, grep, df, systemctl status, ...) across a target. Parallel fan-out, per-host results.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      command: z.string().describe("Read-only shell command"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, command, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    const cls = classifyCommand(command);
    if (cls !== "read-only") {
      return errorResult(
        `Refused: "${command}" classified as ${cls}, not read-only. Use exec instead (policy applies).`,
      );
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      const writable = servers.filter((s) => !s.readOnly);
      void writable; // read-only commands are fine on readOnly servers
      const result = await ctx.executor.run(servers, command, { kind: "parallel" }, { timeoutMs });
      return { content: [{ type: "text" as const, text: formatFanout(result) }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "fleet-diff",
  {
    description:
      "Run a read-only command across a target and group hosts by identical output. " +
      "Reports CONSISTENT when all hosts agree, otherwise lists drift groups and failures. " +
      "Use for version checks (nginx -v), config drift (md5sum of a config file), and state audits.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      command: z.string().describe("Read-only shell command whose stdout is compared across hosts"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, command, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    const cls = classifyCommand(command);
    if (cls !== "read-only") {
      return errorResult(
        `Refused: fleet-diff only runs read-only commands; "${command}" classified as ${cls}.`,
      );
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      const fanout = await ctx.executor.run(servers, command, { kind: "parallel" }, { timeoutMs });
      const report = diffFanout(fanout);
      // Drift or failures are a finding the caller must notice: mark isError.
      return report.consistent
        ? { content: [{ type: "text" as const, text: formatDiff(report) }] }
        : { isError: true as const, content: [{ type: "text" as const, text: formatDiff(report) }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "exec",
  {
    description:
      "Run an arbitrary command across a target with policy enforcement. " +
      "Forbidden commands are always refused. Destructive/privileged commands require confirm=true " +
      "(v0.1 interim approval; an interactive approval gate lands in v0.5). " +
      "Multi-host destructive runs default to rolling execution with a circuit breaker.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      command: z.string().describe("Shell command"),
      strategy: strategySchema.describe("parallel (default) | serial | rolling"),
      confirm: z
        .boolean()
        .optional()
        .describe("Set true to approve a destructive/privileged command"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, command, strategy, confirm, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    let servers;
    try {
      servers = resolveTarget(ctx.registry, target);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    // Policy check per host: the strictest host decides. A command allowed on
    // dev servers but not on prod must not slip through a mixed target.
    const refusals: string[] = [];
    let needsApproval = false;
    let commandClass = classifyCommand(command);
    for (const s of servers) {
      const decision = decide(command, {
        role: s.role,
        tier: s.group,
        readOnly: s.readOnly,
        approvalMode: ctx.config!.defaults.approvalMode,
      });
      if (!decision.allowed) refusals.push(`${s.name}: ${decision.reason}`);
      needsApproval = needsApproval || decision.needsApproval;
    }
    if (refusals.length > 0) {
      return errorResult(
        `Refused by policy (${commandClass}):\n` + refusals.map((r) => `  - ${r}`).join("\n"),
      );
    }
    if (needsApproval && confirm !== true) {
      return errorResult(
        `Approval required: "${command}" is ${commandClass}. ` +
          `Re-run with confirm=true to approve (interactive approval arrives in v0.5). ` +
          `Matched servers: ${servers.map((s) => s.name).join(", ")}`,
      );
    }

    const defaultStrategy: Strategy =
      (commandClass === "destructive" || commandClass === "privileged") && servers.length > 1
        ? { kind: "rolling" }
        : { kind: "parallel" };
    const resolved = parseStrategy(strategy, defaultStrategy);

    try {
      const result = await ctx.executor.run(servers, command, resolved, { timeoutMs });
      const text = formatFanout(result);
      return result.summary.failed > 0
        ? { isError: true as const, content: [{ type: "text" as const, text }] }
        : { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "fleet-push",
  {
    description:
      "Upload one local file to the same remote path on every target via SFTP (batch distribution). " +
      "Uploads overwrite, so this is destructive: it requires confirm=true, refuses readOnly servers, " +
      "enforces per-server scopes.paths, and defaults to rolling execution with a circuit breaker " +
      "for multi-host targets.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      localPath: z.string().describe("Local file path to upload"),
      remotePath: z.string().describe("Absolute remote destination path (parent dirs are created)"),
      strategy: strategySchema.describe("rolling (default for multi-host) | parallel | serial"),
      confirm: z.boolean().optional().describe("Set true to approve the upload"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, localPath, remotePath, strategy, confirm, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    let servers;
    try {
      servers = resolveTarget(ctx.registry, target);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    const refusals: string[] = [];
    for (const s of servers) {
      if (s.readOnly) {
        refusals.push(`${s.name}: server is configured readOnly`);
        continue;
      }
      const scopeReason = checkPathScope(s, remotePath);
      if (scopeReason) refusals.push(scopeReason);
      // Uploads need at least the destructive class on this host's role/tier.
      const decision = decide("rm -rf <upload-overwrite>", {
        role: s.role,
        tier: s.group,
        readOnly: s.readOnly,
        approvalMode: ctx.config!.defaults.approvalMode,
      });
      if (!decision.allowed) refusals.push(`${s.name}: ${decision.reason}`);
    }
    if (refusals.length > 0) {
      return errorResult("Refused by policy (upload):\n" + refusals.map((r) => `  - ${r}`).join("\n"));
    }
    if (confirm !== true) {
      return errorResult(
        `Approval required: uploading "${localPath}" -> "${remotePath}" overwrites on ` +
          `${servers.length} host(s) (${servers.map((s) => s.name).join(", ")}). ` +
          `Re-run with confirm=true to approve.`,
      );
    }

    const resolved = parseStrategy(strategy, servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" });
    try {
      const result = await ctx.executor.push(servers, localPath, remotePath, resolved, { timeoutMs });
      const lines = [
        `upload ${localPath} -> ${remotePath}`,
        `strategy=${result.summary.strategy} total=${result.summary.total} succeeded=${result.summary.succeeded} failed=${result.summary.failed} skipped=${result.summary.skipped}${result.summary.halted ? " HALTED(circuit-breaker)" : ""}`,
        "",
        ...result.results.map((r) =>
          r.skipped
            ? `SKIP ${r.host}: ${r.error}`
            : r.ok
              ? `OK   ${r.host}: ${r.bytes} bytes in ${r.durationMs}ms`
              : `FAIL ${r.host}: ${r.error}`,
        ),
      ];
      const text = lines.join("\n");
      return result.summary.failed > 0
        ? { isError: true as const, content: [{ type: "text" as const, text }] }
        : { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`flotilla-mcp v0.1.0 running on stdio (${ctx.registry ? `${ctx.registry.servers().length} servers configured` : "unconfigured"})`);

  const shutdown = async () => {
    await ctx.transport?.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("flotilla-mcp fatal:", err);
  process.exit(1);
});
