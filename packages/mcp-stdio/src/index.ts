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
import { chmodSync, readFileSync, watch, writeFileSync } from "node:fs";
import { dirname, join, resolve as resolvePath } from "node:path";
import {
  AuditLogger,
  Executor,
  FleetRegistry,
  SshTransport,
  analyzeDoctor,
  appendServerToConfig,
  buildServerToml,
  probeServer,
  pullConfigToFile,
  buildControlCommand,
  buildChecksumCommand,
  buildDoctorScript,
  buildLogsCommand,
  buildMetricsScript,
  buildPathKindProbe,
  buildSessionCaptureCommand,
  buildSessionKillCommand,
  buildSessionListCommand,
  buildSessionSendCommand,
  buildSessionStartCommand,
  buildSignalCommand,
  buildStatusCommand,
  buildFileTailCommand,
  buildJournalTailCommand,
  checkServiceScope,
  checkRelayPolicy,
  classifyCommand,
  checkPathScope,
  decide,
  defaultAuditPath,
  defaultConfigPath,
  diffFanout,
  filterTailOutput,
  formatDiff,
  formatDoctor,
  formatMetrics,
  formatRelay,
  formatSyncPlan,
  formatSyncResult,
  formatQuotaRefusal,
  loadFleetConfig,
  parseChecksums,
  parseMetrics,
  parsePathKind,
  parseSessionList,
  parseWorkflow,
  planSync,
  QuotaCounter,
  relayFile,
  resolveTarget,
  runSyncPlan,
  validateSessionName,
  validateUnit,
  WorkflowRunner,
  type AuditEvent,
  type FanoutResult,
  type FleetConfig,
  type ServiceAction,
  type SignalName,
  type Strategy,
} from "flotilla-core";
import { gateApproval, type ApprovalAsk, type ElicitSender } from "./approval.js";

const MAX_OUTPUT_CHARS_PER_HOST = 8_000;

interface AppContext {
  config?: FleetConfig;
  configPath?: string;
  configError?: string;
  registry?: FleetRegistry;
  executor?: Executor;
  transport?: SshTransport;
  audit?: AuditLogger;
  quota?: QuotaCounter;
}

function buildContext(configPath: string | undefined): AppContext {
  const config = loadFleetConfig(configPath);
  const registry = new FleetRegistry(config);
  const transport = new SshTransport(
    new Map(config.servers.map((s) => [s.name, s])),
    { idleReapMs: config.defaults.idleReapMs },
  );
  const audit = new AuditLogger(
    config.audit?.path ?? defaultAuditPath(configPath),
    { hashChain: config.audit?.hashChain ?? true, entropyScan: config.audit?.entropyScan ?? false },
  );
  // Quota state lives next to the effective config so restarts don't reset it.
  const effectivePath = resolvePath(configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
  const quota = new QuotaCounter(
    join(dirname(effectivePath), "quota-state.json"),
    config.defaults.commandQuotaPerDay ?? 0,
  );
  return {
    config,
    configPath,
    registry,
    transport,
    audit,
    quota,
    executor: new Executor(transport, config.defaults),
  };
}

function initContext(): AppContext {
  const argv = process.argv.slice(2);
  const flagIdx = argv.indexOf("--config");
  const configPath = flagIdx >= 0 ? argv[flagIdx + 1] : undefined;

  try {
    return buildContext(configPath);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`flotilla-mcp: starting unconfigured (${message})`);
    return { configError: message, configPath };
  }
}

const ctx = initContext();

/** The path the running config was (or would be) loaded from. */
function effectiveConfigPath(): string {
  return resolvePath(ctx.configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
}

/**
 * Hot-reload: rebuild config/registry/transport/audit/executor from disk and
 * swap them into ctx. On any failure the old context stays in place — a bad
 * edit must never take the running server down.
 */
function reloadFleet(reason: string): { ok: boolean; message: string } {
  try {
    const next = buildContext(ctx.configPath);
    const oldTransport = ctx.transport;
    const names = next.registry!.servers().map((s) => s.name);
    ctx.config = next.config;
    ctx.registry = next.registry;
    ctx.transport = next.transport;
    ctx.audit = next.audit;
    ctx.executor = next.executor;
    ctx.quota = next.quota;
    ctx.configError = undefined;
    console.error(
      `flotilla-mcp: config reloaded (${reason}): ${names.length} server(s): ${names.join(", ") || "(none)"}`,
    );
    // Close the old pool after the swap so in-flight calls keep their conns.
    if (oldTransport) void oldTransport.close();
    return { ok: true, message: `${names.length} server(s): ${names.join(", ") || "(none)"}` };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`flotilla-mcp: reload FAILED (${reason}), keeping previous config: ${message}`);
    return { ok: false, message };
  }
}

/** Debounced config-file watcher: edits (and fleet-add appends) go live without a restart. */
function startConfigWatcher(): void {
  if (!ctx.config) return;
  const path = effectiveConfigPath();
  let timer: NodeJS.Timeout | undefined;
  try {
    watch(path, () => {
      clearTimeout(timer);
      timer = setTimeout(() => reloadFleet("file changed"), 300);
    });
  } catch (err) {
    console.error(`flotilla-mcp: cannot watch ${path}: ${err instanceof Error ? err.message : err}`);
  }
}

/** Optional periodic remote pull (config [remote] refreshMs). */
function startRemoteRefresh(): void {
  const remote = ctx.config?.remote;
  if (!remote?.refreshMs) return;
  setInterval(() => {
    void (async () => {
      try {
        await pullConfigToFile(remote, effectiveConfigPath());
        reloadFleet("remote refresh");
      } catch (err) {
        console.error(
          `flotilla-mcp: remote refresh failed, keeping current config: ${err instanceof Error ? err.message : err}`,
        );
      }
    })();
  }, remote.refreshMs).unref();
}

/** Record an audit event; never throws, silently no-ops when unconfigured. */
function audit(event: AuditEvent): void {
  ctx.audit?.log(event);
}

/** confirm=true is honored only when the operator explicitly enabled it. */
function confirmFlagEnabled(): boolean {
  return (
    ctx.config?.defaults.allowConfirmFlag === true ||
    process.env.FLOTILLA_ALLOW_CONFIRM_FLAG === "1" ||
    process.env.FLOTILLA_ALLOW_CONFIRM_FLAG === "true"
  );
}

/** Approval gate with the operator's confirm-flag policy applied + audited. */
async function gate(
  extra: unknown,
  ask: Omit<ApprovalAsk, "allowConfirmFlag"> & { tool: string },
) {
  const { tool, ...rest } = ask;
  const outcome = await gateApproval(server, extra as unknown as ElicitSender, {
    ...rest,
    allowConfirmFlag: confirmFlagEnabled(),
  });
  audit({
    kind: "approval",
    tool,
    command: ask.action,
    commandClass: ask.commandClass,
    hosts: ask.hosts,
    outcome: outcome.kind === "approved" ? "approved" : "refused",
    approver: outcome.kind === "approved" ? outcome.via : undefined,
    reason: outcome.kind === "refused" ? outcome.reason : undefined,
  });
  return outcome;
}

/** Audit a policy refusal. */
function auditDenial(tool: string, command: string, commandClass: string, hosts: string[], reason: string): void {
  audit({ kind: "decision", tool, command, commandClass, hosts, outcome: "deny", reason });
}

/** Audit an execution fan-out (aggregate only — stdout never hits the log). */
function auditExecution(
  tool: string,
  command: string,
  fanout: { results: { host: string }[]; summary: { total: number; succeeded: number; failed: number; skipped: number; halted: boolean } },
): void {
  audit({
    kind: "execution",
    tool,
    command,
    hosts: fanout.results.map((r) => r.host),
    outcome: fanout.summary.failed > 0 || fanout.summary.halted ? "failed" : "ok",
    results: {
      total: fanout.summary.total,
      succeeded: fanout.summary.succeeded,
      failed: fanout.summary.failed,
      skipped: fanout.summary.skipped,
    },
  });
}

/**
 * Rolling-24h quota gate for command-bearing tools (exec / exec-read /
 * exec-sudo). Returns an error result when the window is full; the caller
 * records the consumption itself right before dispatching, so policy-refused
 * and approval-refused calls never consume quota.
 */
function quotaGate(tool: string, command: string, hosts: string[]) {
  if (!ctx.quota) return null;
  const status = ctx.quota.check();
  if (status.allowed) return null;
  const message = formatQuotaRefusal(status);
  auditDenial(tool, command, "quota", hosts, `quota exhausted ${status.used}/${status.limit}`);
  return errorResult(message);
}

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
  { name: "flotilla-mcp", version: "0.4.0" },
  {
    instructions:
      "Flotilla manages a fleet of SSH servers. Address hosts with target expressions: " +
      "a server name, group:<name>, tag:<tag>, all, comma-separated unions, and !exclusions. " +
      "Use fleet-resolve to preview a target before running anything. " +
      "exec-read is for allowlisted read-only commands; exec is for everything else and " +
      "enforces the policy engine (forbidden list, role x tier matrix, approval gate). " +
      "fleet-diff compares a read-only command's output across hosts; fleet-diff-file compares " +
      "a file or directory by sha256; fleet-push distributes a local file to many hosts; " +
      "fleet-copy relays a file from one server to another through the control machine (no " +
      "server-to-server SSH keys needed); fleet-sync does rsync-style directory sync the same way. " +
      "Destructive actions ask for approval interactively when the " +
      "client supports elicitation, otherwise pass confirm=true. session-start/list/output/send/kill " +
      "manage persistent tmux sessions that survive disconnects; exec-sudo runs commands as root.",
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
      const q = quotaGate("exec-read", command, servers.map((s) => s.name));
      if (q) return q;
      ctx.quota?.record();
      const result = await ctx.executor.run(servers, command, { kind: "parallel" }, { timeoutMs });
      auditExecution("exec-read", command, result);
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
      auditExecution("fleet-diff", command, fanout);
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
      "Forbidden commands are always refused. Destructive/privileged commands require approval: " +
      "an interactive prompt on clients that support elicitation, otherwise confirm=true. " +
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
  async ({ target, command, strategy, confirm, timeoutMs }, extra) => {
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
      auditDenial("exec", command, commandClass, servers.map((s) => s.name), refusals.join("; "));
      return errorResult(
        `Refused by policy (${commandClass}):\n` + refusals.map((r) => `  - ${r}`).join("\n"),
      );
    }
    if (needsApproval) {
      const outcome = await gate(extra, {
        tool: "exec",
        action: command,
        commandClass,
        hosts: servers.map((s) => s.name),
        confirmFlag: confirm,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);
    }

    const defaultStrategy: Strategy =
      (commandClass === "destructive" || commandClass === "privileged") && servers.length > 1
        ? { kind: "rolling" }
        : { kind: "parallel" };
    const resolved = parseStrategy(strategy, defaultStrategy);

    const q = quotaGate("exec", command, servers.map((s) => s.name));
    if (q) return q;

    try {
      ctx.quota?.record();
      const result = await ctx.executor.run(servers, command, resolved, { timeoutMs });
      auditExecution("exec", command, result);
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
  async ({ target, localPath, remotePath, strategy, confirm, timeoutMs }, extra) => {
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
      auditDenial("fleet-push", `upload ${localPath} -> ${remotePath}`, "destructive (upload)", servers.map((s) => s.name), refusals.join("; "));
      return errorResult("Refused by policy (upload):\n" + refusals.map((r) => `  - ${r}`).join("\n"));
    }
    {
      const outcome = await gate(extra, {
        tool: "fleet-push",
        action: `upload "${localPath}" -> "${remotePath}" (overwrites existing files)`,
        commandClass: "destructive (upload)",
        hosts: servers.map((s) => s.name),
        confirmFlag: confirm,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);
    }

    const resolved = parseStrategy(strategy, servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" });
    try {
      const result = await ctx.executor.push(servers, localPath, remotePath, resolved, { timeoutMs });
      auditExecution("fleet-push", `upload ${localPath} -> ${remotePath}`, result);
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

server.registerTool(
  "fleet-pull",
  {
    description:
      "Download the same remote path from every target via SFTP. localPath may contain {host}; " +
      "with multiple hosts and no placeholder, -<host> is inserted before the extension so " +
      "downloads don't overwrite each other. Enforces scopes.paths on the remote path when " +
      "configured. Read-only on the remote side, no approval needed.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      remotePath: z.string().describe("Absolute remote file path"),
      localPath: z.string().describe('Local destination file; supports "{host}" placeholder'),
      strategy: strategySchema.describe("parallel (default) | serial | rolling"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, remotePath, localPath, strategy, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    let servers;
    try {
      servers = resolveTarget(ctx.registry, target);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    const refusals: string[] = [];
    for (const s of servers) {
      // Downloads read remote files: scopes.paths narrows reads too.
      const scopeReason = checkPathScope(s, remotePath);
      if (scopeReason) refusals.push(scopeReason);
    }
    if (refusals.length > 0) {
      auditDenial("fleet-pull", `download ${remotePath}`, "read (scoped)", servers.map((s) => s.name), refusals.join("; "));
      return errorResult("Refused by policy (download):\n" + refusals.map((r) => `  - ${r}`).join("\n"));
    }

    const resolved = parseStrategy(strategy, { kind: "parallel" });
    try {
      const result = await ctx.executor.pull(servers, remotePath, localPath, resolved, { timeoutMs });
      auditExecution("fleet-pull", `download ${remotePath}`, result);
      const lines = [
        `download ${remotePath} -> ${localPath}`,
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

// ── server-to-server (relay through the control machine, never disk) ──

/** Resolve a target expression that must name exactly one server. */
function resolveOne(target: string, side: "source" | "dest") {
  const servers = resolveTarget(ctx.registry!, target);
  if (servers.length !== 1) {
    throw new Error(`${side} must name exactly one server; "${target}" matched ${servers.length}`);
  }
  return servers[0]!;
}

function auditRelay(tool: string, action: string, hosts: string[], ok: boolean): void {
  audit({
    kind: "execution",
    tool,
    command: action,
    hosts,
    outcome: ok ? "ok" : "failed",
    results: { total: 1, succeeded: ok ? 1 : 0, failed: ok ? 0 : 1, skipped: 0 },
  });
}

server.registerTool(
  "fleet-copy",
  {
    description:
      "Copy one file from server A to server B, relayed through the control machine's memory " +
      "(SFTP read piped into SFTP write — nothing touches local disk, and the two servers never " +
      "need network access or SSH keys to each other). Overwrites the destination, so this is " +
      "destructive: policy is checked on BOTH ends (scopes.paths, role x tier on the dest), and " +
      "cross-tier transfers (e.g. dev -> prod) always require approval.",
    inputSchema: {
      source: z.string().describe("Source server name (exactly one)"),
      sourcePath: z.string().describe("Absolute file path on the source server"),
      dest: z.string().describe("Destination server name (exactly one)"),
      destPath: z.string().describe("Absolute destination file path (parent dirs are created)"),
      confirm: z.boolean().optional().describe("Set true to approve the copy"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ source, sourcePath, dest, destPath, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.transport || !ctx.config) return notConfigured();

    let src, dst;
    try {
      src = resolveOne(source, "source");
      dst = resolveOne(dest, "dest");
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    const action = `relay ${source}:${sourcePath} -> ${dest}:${destPath}`;
    const policy = checkRelayPolicy(src, sourcePath, dst, destPath, ctx.config.defaults.approvalMode);
    if (policy.refusals.length > 0) {
      auditDenial("fleet-copy", action, "destructive (relay)", [src.name, dst.name], policy.refusals.join("; "));
      return errorResult("Refused by policy (relay):\n" + policy.refusals.map((r) => `  - ${r}`).join("\n"));
    }
    if (policy.needsApproval) {
      const outcome = await gate(extra, {
        tool: "fleet-copy",
        action: `${action} (overwrites destination${policy.crossTier ? ", CROSS-TIER" : ""})`,
        commandClass: "destructive (relay)",
        hosts: [src.name, dst.name],
        confirmFlag: confirm,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);
    }

    const result = await relayFile(ctx.transport, src, sourcePath, dst, destPath, { timeoutMs });
    auditRelay("fleet-copy", action, [src.name, dst.name], result.ok);
    const text = formatRelay(result);
    return result.ok
      ? { content: [{ type: "text" as const, text }] }
      : { isError: true as const, content: [{ type: "text" as const, text }] };
  },
);

server.registerTool(
  "fleet-sync",
  {
    description:
      "Sync a directory from server A to server B (rsync semantics, relayed through the control " +
      "machine — servers never talk to each other directly). Computes sha256 listings on both " +
      "sides, then relays only missing/changed files. delete=true also removes dest-only files " +
      "(always requires approval). dryRun defaults to true: first call shows the plan, call again " +
      "with dryRun=false to apply.",
    inputSchema: {
      source: z.string().describe("Source server name (exactly one)"),
      sourceDir: z.string().describe("Absolute directory path on the source server"),
      dest: z.string().describe("Destination server name (exactly one)"),
      destDir: z.string().describe("Absolute directory path on the destination server"),
      delete: z.boolean().optional().describe("Also remove files that exist only on the destination"),
      dryRun: z.boolean().optional().describe("Plan only, change nothing (default true)"),
      confirm: z.boolean().optional().describe("Set true to approve applying the plan"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ source, sourceDir, dest, destDir, delete: del, dryRun, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.transport || !ctx.executor || !ctx.config) return notConfigured();

    let src, dst;
    try {
      src = resolveOne(source, "source");
      dst = resolveOne(dest, "dest");
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    const action = `sync ${source}:${sourceDir} -> ${dest}:${destDir}${del ? " --delete" : ""}`;
    const policy = checkRelayPolicy(src, sourceDir, dst, destDir, ctx.config.defaults.approvalMode);
    if (policy.refusals.length > 0) {
      auditDenial("fleet-sync", action, "destructive (sync)", [src.name, dst.name], policy.refusals.join("; "));
      return errorResult("Refused by policy (sync):\n" + policy.refusals.map((r) => `  - ${r}`).join("\n"));
    }

    try {
      // Probe both dirs; a missing dest dir means "empty" (everything copies).
      const probeSrc = await ctx.executor.run([src], buildPathKindProbe(sourceDir), { kind: "parallel" }, { timeoutMs });
      const srcKind = probeSrc.results[0]?.ok ? parsePathKind(probeSrc.results[0].stdout) : "missing";
      if (srcKind !== "dir") {
        return errorResult(`Source ${source}:${sourceDir} is ${srcKind === "missing" ? "missing or unreachable" : "not a directory"}`);
      }
      const probeDst = await ctx.executor.run([dst], buildPathKindProbe(destDir), { kind: "parallel" }, { timeoutMs });
      const dstKind = probeDst.results[0]?.ok ? parsePathKind(probeDst.results[0].stdout) : "missing";
      if (dstKind === "file") {
        return errorResult(`Destination ${dest}:${destDir} exists and is a file, not a directory`);
      }

      const srcList = await ctx.executor.run([src], buildChecksumCommand(sourceDir, "dir"), { kind: "parallel" }, { timeoutMs });
      if (!srcList.results[0]?.ok) {
        return errorResult(`Checksum listing failed on ${source}: ${srcList.results[0]?.error ?? srcList.results[0]?.stderr}`);
      }
      const srcEntries = parseChecksums(srcList.results[0].stdout);
      let dstEntries: ReturnType<typeof parseChecksums> = [];
      if (dstKind === "dir") {
        const dstList = await ctx.executor.run([dst], buildChecksumCommand(destDir, "dir"), { kind: "parallel" }, { timeoutMs });
        if (!dstList.results[0]?.ok) {
          return errorResult(`Checksum listing failed on ${dest}: ${dstList.results[0]?.error ?? dstList.results[0]?.stderr}`);
        }
        dstEntries = parseChecksums(dstList.results[0].stdout);
      }

      const plan = planSync(srcEntries, dstEntries, del === true);
      if (dryRun !== false) {
        return { content: [{ type: "text" as const, text: formatSyncPlan(`${source}:${sourceDir}`, `${dest}:${destDir}`, plan, true) + "\n\nRe-run with dryRun=false to apply." }] };
      }
      if (plan.copy.length === 0 && plan.remove.length === 0) {
        return { content: [{ type: "text" as const, text: `Already in sync (${plan.unchanged} files identical).` }] };
      }

      // Applying overwrites files; removals (delete=true) always force the gate.
      if (policy.needsApproval || plan.remove.length > 0) {
        const outcome = await gate(extra, {
          tool: "fleet-sync",
          action:
            `${action}: copy ${plan.copy.length} file(s)` +
            (plan.remove.length > 0 ? `, REMOVE ${plan.remove.length} dest-only file(s)` : "") +
            (policy.crossTier ? " — CROSS-TIER" : ""),
          commandClass: plan.remove.length > 0 ? "destructive (sync --delete)" : "destructive (sync)",
          hosts: [src.name, dst.name],
          confirmFlag: confirm,
        });
        if (outcome.kind === "refused") return errorResult(outcome.reason);
      }

      const result = await runSyncPlan(ctx.transport, src, sourceDir, dst, destDir, plan, { timeoutMs });
      auditRelay("fleet-sync", `${action} (copied=${result.copied.length} removed=${result.removed.length} bytes=${result.totalBytes})`, [src.name, dst.name], result.failures.length === 0);
      const text = formatSyncResult(plan, result);
      return result.failures.length > 0
        ? { isError: true as const, content: [{ type: "text" as const, text }] }
        : { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "fleet-diff-file",
  {
    description:
      "Compare a file or directory across hosts by sha256 and group hosts by identical content. " +
      "Reports CONSISTENT when all hosts agree, otherwise drift groups, hosts where the path is " +
      "missing, and failures. Read-only; enforces scopes.paths. Use for config drift, deploy " +
      "verification, and 'did that file actually land everywhere?'.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      path: z.string().describe("Absolute file or directory path to compare"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, path, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    let servers;
    try {
      servers = resolveTarget(ctx.registry, target);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    const refusals: string[] = [];
    for (const s of servers) {
      const scopeReason = checkPathScope(s, path);
      if (scopeReason) refusals.push(scopeReason);
    }
    if (refusals.length > 0) {
      auditDenial("fleet-diff-file", `checksum ${path}`, "read (scoped)", servers.map((s) => s.name), refusals.join("; "));
      return errorResult("Refused by policy (checksum):\n" + refusals.map((r) => `  - ${r}`).join("\n"));
    }

    try {
      // Probe each host: file, dir, or missing.
      const probe = await ctx.executor.run(servers, buildPathKindProbe(path), { kind: "parallel" }, { timeoutMs });
      const missing: string[] = [];
      const probeFailed: typeof probe.results = [];
      const kinds = new Map<string, "file" | "dir">();
      for (const r of probe.results) {
        if (!r.ok) { probeFailed.push(r); continue; }
        const kind = parsePathKind(r.stdout);
        if (kind === "missing") missing.push(r.host);
        else kinds.set(r.host, kind);
      }

      const kindSet = new Set(kinds.values());
      if (kindSet.size > 1) {
        const files = [...kinds].filter(([, k]) => k === "file").map(([h]) => h);
        const dirs = [...kinds].filter(([, k]) => k === "dir").map(([h]) => h);
        const text =
          `DRIFT — path kinds disagree for ${path}:\n` +
          (dirs.length ? `  directory: ${dirs.join(", ")}\n` : "") +
          (files.length ? `  file: ${files.join(", ")}\n` : "") +
          (missing.length ? `  missing: ${missing.join(", ")}\n` : "");
        auditExecution("fleet-diff-file", `checksum ${path}`, probe);
        return { isError: true as const, content: [{ type: "text" as const, text }] };
      }

      const comparable = servers.filter((s) => kinds.has(s.name));
      let report;
      if (comparable.length > 0) {
        const kind = kindSet.values().next().value ?? "file";
        const fanout = await ctx.executor.run(comparable, buildChecksumCommand(path, kind), { kind: "parallel" }, { timeoutMs });
        report = diffFanout(fanout);
        // Hosts where the path is missing are their own finding.
        for (const h of missing) {
          report.failures.push({ host: h, exitCode: null, stderr: "", error: "path missing" });
        }
        report.total += missing.length;
        if (missing.length > 0) report.consistent = false;
      } else {
        const text =
          `Nothing to compare for ${path}:\n` +
          (missing.length ? `  missing everywhere: ${missing.join(", ")}\n` : "") +
          (probeFailed.length ? `  probe failed: ${probeFailed.map((r) => r.host).join(", ")}\n` : "");
        auditExecution("fleet-diff-file", `checksum ${path}`, probe);
        return { isError: true as const, content: [{ type: "text" as const, text }] };
      }

      auditExecution("fleet-diff-file", `checksum ${path}`, probe);
      const text = formatDiff(report);
      return report.consistent
        ? { content: [{ type: "text" as const, text }] }
        : { isError: true as const, content: [{ type: "text" as const, text }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "signal-process",
  {
    description:
      "Send INT/TERM/KILL/HUP to a remote PID across a target. Destructive: always requires " +
      "approval (interactive prompt or confirm=true when enabled). Numeric PIDs only — no " +
      "pattern matching. Pass sudo=true to signal processes owned by root (privileged class).",
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
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    let command: string;
    try {
      command = buildSignalCommand(pid, signal as SignalName);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    let servers;
    try {
      servers = resolveTarget(ctx.registry, target);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    const policyCommand = sudo ? `sudo ${command}` : command;
    const commandClass = classifyCommand(policyCommand);
    const refusals: string[] = [];
    for (const s of servers) {
      const decision = decide(policyCommand, {
        role: s.role,
        tier: s.group,
        readOnly: s.readOnly,
        approvalMode: ctx.config!.defaults.approvalMode,
      });
      if (!decision.allowed) refusals.push(`${s.name}: ${decision.reason}`);
    }
    if (refusals.length > 0) {
      auditDenial("signal-process", policyCommand, commandClass, servers.map((s) => s.name), refusals.join("; "));
      return errorResult(
        `Refused by policy (${commandClass}, signal-process):\n` + refusals.map((r) => `  - ${r}`).join("\n"),
      );
    }
    // Signalling processes is always gated, whatever the approval mode.
    const outcome = await gate(extra, {
      tool: "signal-process",
      action: `kill -${signal} ${pid}${sudo ? " (via sudo)" : ""}`,
      commandClass: `${commandClass} (signal-process)`,
      hosts: servers.map((s) => s.name),
      confirmFlag: confirm,
    });
    if (outcome.kind === "refused") return errorResult(outcome.reason);

    const resolved = parseStrategy(strategy, servers.length > 1 ? { kind: "serial" } : { kind: "parallel" });
    try {
      const result = await ctx.executor.run(servers, command, resolved, { timeoutMs, sudo });
      auditExecution("signal-process", policyCommand, result);
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
  "metrics-snapshot",
  {
    description:
      "Collect per-host metrics (load, cores, memory, disks, top processes) across a target. " +
      "Zero-dependency: runs a fixed read-only probe script, no approval needed.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    try {
      const servers = resolveTarget(ctx.registry, target);
      const fanout = await ctx.executor.run(servers, buildMetricsScript(), { kind: "parallel" }, { timeoutMs });
      auditExecution("metrics-snapshot", "metrics probe", fanout);
      const lines: string[] = [`metrics-snapshot: ${fanout.summary.succeeded}/${fanout.summary.total} hosts OK`, ""];
      for (const r of fanout.results) {
        if (r.ok) {
          lines.push(formatMetrics(parseMetrics(r.host, r.stdout)), "");
        } else {
          lines.push(`── FAIL ${r.host}: ${r.error ?? r.stderr.trim()}`, "");
        }
      }
      return fanout.summary.failed > 0
        ? { isError: true as const, content: [{ type: "text" as const, text: lines.join("\n") }] }
        : { content: [{ type: "text" as const, text: lines.join("\n") }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "doctor",
  {
    description:
      "One-shot health check across a target: disk/memory/load thresholds, failed systemd units, " +
      "zombie processes. Returns HEALTHY / WARN / CRIT per host with details. Read-only probe, no approval needed.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    try {
      const servers = resolveTarget(ctx.registry, target);
      const fanout = await ctx.executor.run(servers, buildDoctorScript(), { kind: "parallel" }, { timeoutMs });
      auditExecution("doctor", "doctor probe", fanout);
      const lines: string[] = [];
      let crits = 0;
      let warns = 0;
      let healthy = 0;
      for (const r of fanout.results) {
        if (r.ok) {
          const m = parseMetrics(r.host, r.stdout);
          const issues = analyzeDoctor(m);
          if (issues.some((i) => i.severity === "crit")) crits++;
          else if (issues.length > 0) warns++;
          else healthy++;
          lines.push(formatDoctor(r.host, m, issues), "");
        } else {
          warns++;
          lines.push(`── WARN ${r.host}: probe failed — ${r.error ?? r.stderr.trim()}`, "");
        }
      }
      lines.unshift(
        `doctor: ${servers.length} hosts — ${healthy} healthy, ${warns} warn, ${crits} crit`,
        "",
      );
      return crits > 0
        ? { isError: true as const, content: [{ type: "text" as const, text: lines.join("\n") }] }
        : { content: [{ type: "text" as const, text: lines.join("\n") }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

const unitSchema = z.string().describe('systemd unit name, e.g. "myapp" or "myapp.service"');

server.registerTool(
  "exec-sudo",
  {
    description:
      "Run a command with root privileges via sudo across a target. If a sudo password is set in " +
      "FLOTILLA_<NAME>_SUDO_PASSWORD / FLOTILLA_SUDO_PASSWORD it is piped through stdin (never argv, " +
      "never logged); with NOPASSWD sudoers rules no password is needed at all (sudo -n). " +
      "Always classified as privileged, always " +
      "requires approval (interactive prompt or confirm=true), and multi-host runs default to " +
      "rolling execution with a circuit breaker. Prefer service-control for systemd units.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      command: z.string().describe("Shell command to run as root (sudo is prepended)"),
      strategy: strategySchema.describe("rolling (default for multi-host) | parallel | serial"),
      confirm: z
        .boolean()
        .optional()
        .describe("Set true to approve the privileged command"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, command, strategy, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    let servers;
    try {
      servers = resolveTarget(ctx.registry, target);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    // Classify as "sudo <command>" so the policy engine sees the real risk
    // class (privileged), including any forbidden patterns in the command.
    const sudoCommand = `sudo ${command}`;
    const commandClass = classifyCommand(sudoCommand);
    const refusals: string[] = [];
    for (const s of servers) {
      const decision = decide(sudoCommand, {
        role: s.role,
        tier: s.group,
        readOnly: s.readOnly,
        approvalMode: ctx.config!.defaults.approvalMode,
      });
      if (!decision.allowed) refusals.push(`${s.name}: ${decision.reason}`);
    }
    if (refusals.length > 0) {
      auditDenial("exec-sudo", sudoCommand, commandClass, servers.map((s) => s.name), refusals.join("; "));
      return errorResult(
        `Refused by policy (${commandClass}, sudo):\n` + refusals.map((r) => `  - ${r}`).join("\n"),
      );
    }
    // sudo is an escalation: approval is mandatory regardless of what the
    // per-host decision says about needsApproval.
    const outcome = await gate(extra, {
      tool: "exec-sudo",
      action: `sudo ${command}`,
      commandClass: "privileged (sudo)",
      hosts: servers.map((s) => s.name),
      confirmFlag: confirm,
    });
    if (outcome.kind === "refused") return errorResult(outcome.reason);

    const resolved = parseStrategy(
      strategy,
      servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" },
    );
    const q = quotaGate("exec-sudo", sudoCommand, servers.map((s) => s.name));
    if (q) return q;

    try {
      ctx.quota?.record();
      const result = await ctx.executor.run(servers, command, resolved, { timeoutMs, sudo: true });
      auditExecution("exec-sudo", `sudo ${command}`, result);
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
  "service-status",
  {
    description:
      "Show systemctl status for a unit across a target. Read-only. " +
      "Enforces per-server scopes.services when configured.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      unit: unitSchema,
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, unit, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    let normalized: string;
    try {
      normalized = validateUnit(unit);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      const refused = servers.map((s) => checkServiceScope(s, normalized)).filter(Boolean);
      if (refused.length > 0) return errorResult(refused.join("\n"));
      const result = await ctx.executor.run(servers, buildStatusCommand(normalized), { kind: "parallel" }, { timeoutMs });
      auditExecution("service-status", buildStatusCommand(normalized), result);
      // systemctl status exits non-zero for inactive units — that is information, not failure.
      return { content: [{ type: "text" as const, text: formatFanout(result) }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "service-logs",
  {
    description:
      "Tail a unit's journal logs across a target. Read-only; enforces scopes.services. " +
      "Pass sudo=true when the SSH user is not in the systemd-journal group (requires approval; " +
      "sudo password from FLOTILLA_*_SUDO_PASSWORD env).",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      unit: unitSchema,
      lines: z.number().int().positive().max(1000).optional().describe("Log lines per host (default 50)"),
      sudo: z
        .boolean()
        .optional()
        .describe("Run journalctl via sudo (for users outside the systemd-journal group)"),
      confirm: z.boolean().optional().describe("Set true to approve sudo log access"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, unit, lines, sudo, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    let normalized: string;
    try {
      normalized = validateUnit(unit);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      const refused = servers.map((s) => checkServiceScope(s, normalized)).filter(Boolean);
      if (refused.length > 0) return errorResult(refused.join("\n"));
      if (sudo) {
        // Reading logs as root is still an escalation: require approval.
        const outcome = await gate(extra, {
          tool: "service-logs",
          action: `sudo journalctl -u ${normalized}`,
          commandClass: "privileged (service-logs, sudo)",
          hosts: servers.map((s) => s.name),
          confirmFlag: confirm,
        });
        if (outcome.kind === "refused") return errorResult(outcome.reason);
      }
      const result = await ctx.executor.run(servers, buildLogsCommand(normalized, lines ?? 50), { kind: "parallel" }, { timeoutMs, sudo });
      auditExecution("service-logs", buildLogsCommand(normalized, lines ?? 50), result);
      return { content: [{ type: "text" as const, text: formatFanout(result) }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "service-control",
  {
    description:
      "start/stop/restart/reload a unit across a target. Destructive: requires approval " +
      "(interactive prompt or confirm=true), enforces scopes.services, and defaults to rolling " +
      "execution with a circuit breaker for multi-host targets. Pass sudo=true to run systemctl " +
      "as root (sudo password from env; treated as privileged).",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      unit: unitSchema,
      action: z.enum(["start", "stop", "restart", "reload"]),
      strategy: strategySchema.describe("rolling (default for multi-host) | parallel | serial"),
      sudo: z
        .boolean()
        .optional()
        .describe("Run systemctl via sudo as root (password from FLOTILLA_*_SUDO_PASSWORD env)"),
      confirm: z.boolean().optional().describe("Set true to approve the action"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, unit, action, strategy, sudo, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    let normalized: string;
    try {
      normalized = validateUnit(unit);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      const command = buildControlCommand(normalized, action as ServiceAction);
      // With sudo the policy engine must see the escalated form.
      const policyCommand = sudo ? `sudo ${command}` : command;

      const refusals: string[] = [];
      for (const s of servers) {
        const scopeReason = checkServiceScope(s, normalized);
        if (scopeReason) refusals.push(scopeReason);
        const decision = decide(policyCommand, {
          role: s.role,
          tier: s.group,
          readOnly: s.readOnly,
          approvalMode: ctx.config!.defaults.approvalMode,
        });
        if (!decision.allowed) refusals.push(`${s.name}: ${decision.reason}`);
      }
      if (refusals.length > 0) {
        auditDenial("service-control", policyCommand, sudo ? "privileged" : "destructive", servers.map((s) => s.name), refusals.join("; "));
        return errorResult("Refused by policy (service-control):\n" + refusals.map((r) => `  - ${r}`).join("\n"));
      }
      const outcome = await gate(extra, {
        tool: "service-control",
        action: `${sudo ? "sudo " : ""}${action} ${normalized}`,
        commandClass: sudo ? "privileged (service-control, sudo)" : "destructive (service-control)",
        hosts: servers.map((s) => s.name),
        confirmFlag: confirm,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);

      const resolved = parseStrategy(strategy, servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" });
      const result = await ctx.executor.run(servers, command, resolved, { timeoutMs, sudo });
      auditExecution("service-control", sudo ? `sudo ${command}` : command, result);
      const text = formatFanout(result);
      return result.summary.failed > 0
        ? { isError: true as const, content: [{ type: "text" as const, text }] }
        : { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

const sessionNameSchema = z
  .string()
  .describe("Session name (1-48 chars: letters, digits, '_' '-'). Stored as tmux session 'flotilla-<name>'.");

server.registerTool(
  "session-start",
  {
    description:
      "Start a persistent tmux session on the target hosts — survives SSH/MCP disconnects. " +
      "With no command you get an idle shell; with a command it runs inside the session and the " +
      "session stays alive after it exits, so output remains capturable. The command's own policy " +
      "class applies (destructive/privileged commands need approval). Requires tmux on the host.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      name: sessionNameSchema,
      command: z.string().optional().describe("Command to run inside the session (omit for an idle shell)"),
      workdir: z.string().optional().describe("Working directory for the session"),
      confirm: z.boolean().optional().describe("Set true to approve a destructive/privileged command"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, name, command, workdir, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    let fullName: string;
    try {
      fullName = validateSessionName(name);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      if (command) {
        // The session's command faces the same policy engine as exec.
        const commandClass = classifyCommand(command);
        const refusals: string[] = [];
        let needsApproval = false;
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
          auditDenial("session-start", command, commandClass, servers.map((s) => s.name), refusals.join("; "));
          return errorResult(
            `Refused by policy (${commandClass}, session-start):\n` + refusals.map((r) => `  - ${r}`).join("\n"),
          );
        }
        if (needsApproval) {
          const outcome = await gate(extra, {
            tool: "session-start",
            action: `session "${name}" running: ${command}`,
            commandClass: `${commandClass} (session-start)`,
            hosts: servers.map((s) => s.name),
            confirmFlag: confirm,
          });
          if (outcome.kind === "refused") return errorResult(outcome.reason);
        }
      }
      const result = await ctx.executor.run(
        servers,
        buildSessionStartCommand(fullName, { workdir, command }),
        { kind: "parallel" },
        { timeoutMs },
      );
      auditExecution("session-start", command ? `session ${name}: ${command}` : `session ${name} (shell)`, result);
      const text = `session "${name}" started\n` + formatFanout(result);
      return result.summary.failed > 0
        ? { isError: true as const, content: [{ type: "text" as const, text }] }
        : { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "session-list",
  {
    description: "List flotilla-* tmux sessions on the target hosts. Read-only, no approval needed.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    try {
      const servers = resolveTarget(ctx.registry, target);
      const fanout = await ctx.executor.run(servers, buildSessionListCommand(), { kind: "parallel" }, { timeoutMs });
      auditExecution("session-list", "tmux list-sessions", fanout);
      const lines: string[] = [];
      let total = 0;
      for (const r of fanout.results) {
        if (!r.ok) {
          lines.push(`── FAIL ${r.host}: ${r.error ?? r.stderr.trim()}`, "");
          continue;
        }
        const sessions = parseSessionList(r.host, r.stdout);
        total += sessions.length;
        if (sessions.length === 0) {
          lines.push(`── ${r.host}: no sessions`, "");
        }
        for (const s of sessions) {
          lines.push(
            `── ${r.host}  ${s.name}  created=${s.createdAt}  windows=${s.windows}${s.attached ? "  [attached]" : ""}`,
          );
        }
      }
      lines.unshift(`session-list: ${total} session(s) across ${fanout.results.length} host(s)`, "");
      return { content: [{ type: "text" as const, text: lines.join("\n") }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "session-output",
  {
    description:
      "Capture the recent scrollback of a session on the target hosts (default last 100 lines). " +
      "Read-only, no approval needed.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      name: sessionNameSchema,
      lines: z.number().int().positive().max(10000).optional().describe("Scrollback lines to capture (default 100)"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, name, lines, timeoutMs }) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    let fullName: string;
    try {
      fullName = validateSessionName(name);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      const result = await ctx.executor.run(
        servers,
        buildSessionCaptureCommand(fullName, lines ?? 100),
        { kind: "parallel" },
        { timeoutMs },
      );
      auditExecution("session-output", `capture session ${name}`, result);
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
  "session-send",
  {
    description:
      "Send a line of input to a live session on the target hosts (literal text + Enter). " +
      "This is input injection into a running shell: always requires approval, and the text " +
      "itself faces the forbidden list. Use for interactive programs, confirmations, Ctrl-key " +
      "sequences are NOT supported yet.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      name: sessionNameSchema,
      text: z.string().describe("Literal text to type, followed by Enter"),
      confirm: z.boolean().optional().describe("Set true to approve the input injection"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, name, text, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    let fullName: string;
    try {
      fullName = validateSessionName(name);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      // The text being typed must not smuggle a forbidden command.
      const textClass = classifyCommand(text);
      if (textClass === "forbidden") {
        auditDenial("session-send", text, "forbidden", servers.map((s) => s.name), "text matches the never-allowed list");
        return errorResult(`Refused by policy: the text itself matches the never-allowed list.`);
      }
      const outcome = await gate(extra, {
        tool: "session-send",
        action: `send to session "${name}": ${text}`,
        commandClass: "input injection (session-send)",
        hosts: servers.map((s) => s.name),
        confirmFlag: confirm,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);
      const result = await ctx.executor.run(
        servers,
        buildSessionSendCommand(fullName, text),
        { kind: "parallel" },
        { timeoutMs },
      );
      auditExecution("session-send", `session ${name} <- input`, result);
      const out = formatFanout(result);
      return result.summary.failed > 0
        ? { isError: true as const, content: [{ type: "text" as const, text: out }] }
        : { content: [{ type: "text" as const, text: out }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "session-kill",
  {
    description:
      "Kill a session on the target hosts. Destroys the tmux session and anything running in it. " +
      "Always requires approval.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      name: sessionNameSchema,
      confirm: z.boolean().optional().describe("Set true to approve killing the session"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, name, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    let fullName: string;
    try {
      fullName = validateSessionName(name);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
    try {
      const servers = resolveTarget(ctx.registry, target);
      const outcome = await gate(extra, {
        tool: "session-kill",
        action: `kill session "${name}" (and any process running in it)`,
        commandClass: "destructive (session-kill)",
        hosts: servers.map((s) => s.name),
        confirmFlag: confirm,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);
      const result = await ctx.executor.run(
        servers,
        buildSessionKillCommand(fullName),
        { kind: "parallel" },
        { timeoutMs },
      );
      auditExecution("session-kill", `kill session ${name}`, result);
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
  "workflow-run",
  {
    description:
      "Run a declarative YAML workflow: ordered steps, each with its own target expression, " +
      "fan-out, and policy. Step types: exec, exec-sudo, push, service. Steps can reference " +
      "earlier output via {{ steps.<name>.stdout }} and {{ steps.<name>.hosts }}. Per-step " +
      "onError: stop (default) | continue | rollback (runs rollback blocks in reverse). " +
      "The whole run is planned against the policy engine first; if any step needs approval, " +
      "one approval covers the entire plan.",
    inputSchema: {
      yaml: z.string().describe("Workflow definition in YAML"),
      confirm: z
        .boolean()
        .optional()
        .describe("Set true to approve the whole plan when gated steps exist"),
    },
  },
  async ({ yaml, confirm }, extra) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();

    let def;
    try {
      def = parseWorkflow(yaml);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    const checkPolicy = (command: string, s: { role: "viewer" | "operator" | "admin"; group: string; readOnly: boolean; name: string }) => {
      const decision = decide(command, {
        role: s.role,
        tier: s.group,
        readOnly: s.readOnly,
        approvalMode: ctx.config!.defaults.approvalMode,
      });
      return decision.allowed ? null : (decision.reason ?? "refused");
    };
    const runner = new WorkflowRunner(ctx.registry, ctx.executor, ctx.config.defaults, checkPolicy);

    const plan = runner.plan(def);
    const planRefusals = plan.flatMap((p) => p.refusals.map((r) => `${p.step.name}: ${r}`));
    if (planRefusals.length > 0) {
      auditDenial("workflow-run", `workflow "${def.name}"`, "workflow plan", [...new Set(def.steps.map((s) => s.target))], planRefusals.join("; "));
      return errorResult("Workflow refused by policy:\n" + planRefusals.map((r) => `  - ${r}`).join("\n"));
    }
    const gated = plan.filter((p) => p.needsApproval);
    if (gated.length > 0) {
      const outcome = await gate(extra, {
        tool: "workflow-run",
        action:
          `workflow "${def.name}" (${def.steps.length} steps), gated steps: ` +
          gated.map((p) => `${p.step.name} [${p.commandClass}]`).join(", "),
        commandClass: "workflow plan",
        hosts: [...new Set(def.steps.map((s) => s.target))],
        confirmFlag: confirm,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);
    }

    const result = await runner.run(def);
    audit({
      kind: "execution",
      tool: "workflow-run",
      command: `workflow "${def.name}" (${def.steps.length} steps)`,
      outcome: result.ok ? "ok" : "failed",
      reason: result.haltedAt ? `halted at ${result.haltedAt}${result.rolledBack ? ", rolled back" : ""}` : undefined,
      results: {
        total: result.steps.length,
        succeeded: result.steps.filter((s) => s.ok).length,
        failed: result.steps.filter((s) => !s.ok && !s.skipped).length,
        skipped: result.steps.filter((s) => s.skipped).length,
      },
    });
    const lines: string[] = [
      `workflow "${result.name}": ${result.ok ? "OK" : "FAILED"}${result.halted ? ` (halted at "${result.haltedAt}")` : ""}${result.rolledBack ? " rolled-back" : ""}`,
      "",
    ];
    for (const s of result.steps) {
      if (s.skipped) {
        lines.push(`── SKIP ${s.name}: ${s.error ?? ""}`);
        continue;
      }
      const summary = s.fanout?.summary;
      const detail = summary
        ? `total=${summary.total} ok=${summary.succeeded} fail=${summary.failed}${summary.halted ? " HALTED" : ""}`
        : (s.error ?? "");
      lines.push(`── ${s.ok ? "OK  " : "FAIL"} ${s.name}  ${detail}`);
      if (!s.ok && s.error && summary) lines.push(`     ${s.error}`);
    }
    return result.ok
      ? { content: [{ type: "text" as const, text: lines.join("\n") }] }
      : { isError: true as const, content: [{ type: "text" as const, text: lines.join("\n") }] };
  },
);

server.registerTool(
  "logs-tail",
  {
    description:
      "Follow a unit's journal or a file for a bounded window (default 30s, max 300s) across a " +
      "target, then return what was captured — optionally filtered by a local grep pattern. " +
      "This is bounded collection, not an infinite stream: call again to keep watching. " +
      "File tails enforce scopes.paths when configured; sudo journal tails require NOPASSWD " +
      "and approval (privileged).",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      unit: unitSchema.optional().describe("systemd unit to follow (journalctl -f)"),
      path: z.string().optional().describe("File to follow (tail -F); alternative to unit"),
      seconds: z.number().int().positive().max(300).optional().describe("Collection window in seconds (default 30, max 300)"),
      grep: z.string().optional().describe("Local regex filter applied to captured lines"),
      sudo: z.boolean().optional().describe("Follow the journal via sudo -n (NOPASSWD required)"),
      confirm: z.boolean().optional().describe("Set true to approve sudo journal tails"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, unit, path, seconds, grep, sudo, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.executor || !ctx.config) return notConfigured();
    if (!unit && !path) return errorResult("logs-tail requires either unit or path");
    if (unit && path) return errorResult("logs-tail takes unit OR path, not both");

    let command: string;
    try {
      if (unit) {
        const normalized = validateUnit(unit);
        command = buildJournalTailCommand(normalized, seconds ?? 30, { sudo });
      } else {
        command = buildFileTailCommand(path!, seconds ?? 30);
      }
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    try {
      const servers = resolveTarget(ctx.registry, target);
      const commandClass = classifyCommand(command);
      const refusals: string[] = [];
      for (const s of servers) {
        const decision = decide(command, {
          role: s.role,
          tier: s.group,
          readOnly: s.readOnly,
          approvalMode: ctx.config!.defaults.approvalMode,
        });
        if (!decision.allowed) refusals.push(`${s.name}: ${decision.reason}`);
        if (unit) {
          const scope = checkServiceScope(s, validateUnit(unit));
          if (scope) refusals.push(scope);
        } else {
          // File tails can read anything on the box: narrow by scopes.paths
          // when the server defines them (same narrowing semantics as push).
          const scope = checkPathScope(s, path!);
          if (scope) refusals.push(scope);
        }
      }
      if (refusals.length > 0) {
        auditDenial("logs-tail", command, commandClass, servers.map((s) => s.name), refusals.join("; "));
        return errorResult(
          `Refused by policy (${commandClass}, logs-tail):\n` + refusals.map((r) => `  - ${r}`).join("\n"),
        );
      }
      if (commandClass === "privileged") {
        const outcome = await gate(extra, {
          tool: "logs-tail",
          action: `sudo tail ${unit ? `journal of ${unit}` : path} for ${seconds ?? 30}s`,
          commandClass: "privileged (logs-tail, sudo)",
          hosts: servers.map((s) => s.name),
          confirmFlag: confirm,
        });
        if (outcome.kind === "refused") return errorResult(outcome.reason);
      }

      // The exec timeout must outlive the collection window.
      const windowMs = (seconds ?? 30) * 1000;
      const fanout = await ctx.executor.run(servers, command, { kind: "parallel" }, {
        timeoutMs: timeoutMs ?? windowMs + 15_000,
      });
      auditExecution("logs-tail", `tail ${unit ? `journal:${unit}` : path} ${seconds ?? 30}s`, fanout);

      const lines: string[] = [`logs-tail: ${seconds ?? 30}s window`, ""];
      let anyFail = false;
      for (const r of fanout.results) {
        if (!r.ok) {
          anyFail = true;
          lines.push(`── FAIL ${r.host}: ${r.error ?? r.stderr.trim()}`, "");
          continue;
        }
        const filtered = filterTailOutput(r.stdout, grep);
        if (filtered.grepError) return errorResult(filtered.grepError);
        lines.push(
          `── ${r.host}: ${filtered.matched}/${filtered.total} line(s)${grep ? ` matching /${grep}/` : ""}`,
        );
        for (const l of filtered.lines.slice(0, 200)) lines.push(`   ${l}`);
        if (filtered.lines.length > 200) lines.push(`   ... [${filtered.lines.length - 200} more]`);
        lines.push("");
      }
      return anyFail
        ? { isError: true as const, content: [{ type: "text" as const, text: lines.join("\n") }] }
        : { content: [{ type: "text" as const, text: lines.join("\n") }] };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "fleet-add",
  {
    description:
      "Onboard a new server into the fleet config: probes it over SSH (hostname, uid, tmux, " +
      "host key), then appends a [[servers]] block with the host key pinned (TOFU — first " +
      "contact doubles as key enrollment). This changes who the fleet is authorized to control, " +
      "so it always requires approval. The config is hot-reloaded afterwards, so the new server " +
      "is targetable immediately.",
    inputSchema: {
      name: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/).describe("Server name (unique in the config)"),
      host: z.string().describe("IP or DNS name to SSH into"),
      user: z.string().optional().describe('SSH user (default "root" — a warning is shown for uid 0)'),
      port: z.number().int().positive().max(65535).optional().describe("SSH port (default 22)"),
      auth: z.enum(["agent", "key", "password"]).optional().describe('Auth method (default "agent", or "key" when keyRef is given)'),
      keyRef: z.string().optional().describe("Private key path (required when auth = key); '~' is expanded"),
      group: z.string().optional().describe('Policy tier group (default "dev")'),
      role: z.enum(["viewer", "operator", "admin"]).optional().describe('Policy role (default "operator")'),
      tags: z.array(z.string()).optional().describe("Tags for targeting, e.g. [\"web\", \"arm\"]"),
      readOnly: z.boolean().optional().describe("Refuse all non-read-only commands on this server"),
      via: z.string().optional().describe("ProxyJump: name of an existing server to tunnel through"),
      confirm: z.boolean().optional().describe("Set true to approve the config change"),
    },
  },
  async ({ name, host, user, port, auth: authMethod, keyRef, group, role, tags, readOnly: ro, via, confirm }, extra) => {
    if (!ctx.registry || !ctx.config) return notConfigured();

    const outcome = await gate(extra, {
      tool: "fleet-add",
      action: `add server "${name}" (${user ?? "root"}@${host}:${port ?? 22}, group=${group ?? "dev"}, role=${role ?? "operator"}${ro ? ", readOnly" : ""}${via ? `, via ${via}` : ""})`,
      commandClass: "privileged (config change)",
      hosts: [name],
      confirmFlag: confirm,
    });
    if (outcome.kind === "refused") return errorResult(outcome.reason);

    const newServer = {
      name,
      host,
      port: port ?? 22,
      user: user ?? "root",
      auth: authMethod ?? (keyRef ? "key" : "agent"),
      keyRef,
      group: group ?? "dev",
      tags: tags ?? [],
      role: role ?? "operator",
      readOnly: ro ?? false,
      via,
    } as const;
    if (newServer.auth === "key" && !keyRef) {
      return errorResult("Refused: auth = \"key\" requires keyRef (path to the private key).");
    }

    try {
      const probe = await probeServer({ ...newServer });
      if (!probe.ok) return errorResult(`Probe failed — server NOT added: ${probe.error}`);

      const cfgPath = resolvePath(ctx.configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
      const text = readFileSync(cfgPath, "utf8");
      const pinned = { ...newServer, trustedHostKey: probe.hostKey };
      const next = appendServerToConfig(text, pinned);
      writeFileSync(cfgPath, next, "utf8");
      chmodSync(cfgPath, 0o600);

      audit({
        kind: "execution",
        tool: "fleet-add",
        command: `add server "${name}" (${newServer.user}@${host}:${newServer.port})`,
        hosts: [name],
        outcome: "ok",
      });

      const lines = [
        `Server "${name}" added to ${cfgPath}`,
        "",
        `probe: hostname=${probe.hostname}  uid=${probe.uid ?? "?"}  tmux=${probe.tmux ? "yes" : "NO (sessions unavailable)"}`,
        `host key pinned: ${probe.hostKey ?? "(not captured)"}`,
      ];
      if (probe.uid === 0) {
        lines.push("", "WARNING: uid=0 — this account is root. Prefer a low-privilege user plus a NOPASSWD sudoers allowlist.");
      }
      lines.push("", "Appended block:", buildServerToml(pinned).trim());
      const reload = reloadFleet("fleet-add");
      lines.push(
        "",
        reload.ok
          ? `Config hot-reloaded — "${name}" is targetable NOW (${reload.message}).`
          : `Hot-reload failed (${reload.message}) — restart the MCP server to pick up "${name}".`,
      );
      return { content: [{ type: "text" as const, text: lines.join("\n") }] };
    } catch (err) {
      audit({
        kind: "execution",
        tool: "fleet-add",
        command: `add server "${name}" (${newServer.user}@${host}:${newServer.port})`,
        hosts: [name],
        outcome: "failed",
        reason: err instanceof Error ? err.message : String(err),
      });
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "config-pull",
  {
    description:
      "Pull the fleet config from the configured [remote] url (HTTP(S), e.g. a GitHub/GitLab " +
      "raw-file URL), validate it, back up the current file, atomically install the new one, " +
      "and hot-reload. This rewrites the authorization source of the whole fleet, so it always " +
      "requires approval. Requires [remote] in the config; the bearer token comes from the env " +
      "var named by remote.tokenEnv.",
    inputSchema: {
      confirm: z.boolean().optional().describe("Set true to approve the config replacement"),
    },
  },
  async ({ confirm }, extra) => {
    if (!ctx.config) return notConfigured();
    const remote = ctx.config.remote;
    if (!remote) {
      return errorResult(
        'No [remote] section in the config. Add e.g.:\n[remote]\nurl = "https://raw.githubusercontent.com/<org>/<repo>/main/fleet.toml"',
      );
    }
    const outcome = await gate(extra, {
      tool: "config-pull",
      action: `replace the fleet config with ${remote.url}`,
      commandClass: "privileged (config pull)",
      hosts: ctx.registry?.servers().map((s) => s.name) ?? [],
      confirmFlag: confirm,
    });
    if (outcome.kind === "refused") return errorResult(outcome.reason);

    try {
      const before = ctx.registry?.servers().map((s) => s.name) ?? [];
      const result = await pullConfigToFile(remote, effectiveConfigPath());
      const reload = reloadFleet("config-pull");
      audit({
        kind: "execution",
        tool: "config-pull",
        command: `pull ${remote.url}`,
        outcome: reload.ok ? "ok" : "failed",
        reason: reload.ok ? undefined : reload.message,
      });
      const after = ctx.registry?.servers().map((s) => s.name) ?? [];
      const added = after.filter((n) => !before.includes(n));
      const removed = before.filter((n) => !after.includes(n));
      const lines = [
        `Config pulled from ${remote.url} (${result.bytes} bytes)`,
        `backup: ${result.backupPath ?? "(none — first install)"}`,
        `servers: ${after.length} (${after.join(", ") || "none"})`,
      ];
      if (added.length) lines.push(`added: ${added.join(", ")}`);
      if (removed.length) lines.push(`removed: ${removed.join(", ")}`);
      lines.push(
        reload.ok ? "Hot-reloaded — the new fleet is live." : `Hot-reload FAILED: ${reload.message} (restart to apply)`,
      );
      return reload.ok
        ? { content: [{ type: "text" as const, text: lines.join("\n") }] }
        : { isError: true as const, content: [{ type: "text" as const, text: lines.join("\n") }] };
    } catch (err) {
      audit({
        kind: "execution",
        tool: "config-pull",
        command: `pull ${remote.url}`,
        outcome: "failed",
        reason: err instanceof Error ? err.message : String(err),
      });
      return errorResult(`Pull failed — local config untouched: ${err instanceof Error ? err.message : String(err)}`);
    }
  },
);

server.registerTool(
  "config-reload",
  {
    description:
      "Re-read the config file from disk and hot-reload the fleet (registry, connection pool, " +
      "policy defaults). On failure the previous config stays active. Normally unnecessary — " +
      "file changes are picked up automatically; use after out-of-band edits if needed.",
    inputSchema: {},
  },
  async () => {
    if (!ctx.config && !ctx.configError) return notConfigured();
    const reload = reloadFleet("config-reload tool");
    audit({
      kind: "execution",
      tool: "config-reload",
      command: "reload config",
      outcome: reload.ok ? "ok" : "failed",
      reason: reload.ok ? undefined : reload.message,
    });
    return reload.ok
      ? { content: [{ type: "text" as const, text: `Reloaded: ${reload.message}` }] }
      : errorResult(`Reload failed, previous config still active: ${reload.message}`);
  },
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  startConfigWatcher();
  startRemoteRefresh();
  console.error(`flotilla-mcp v0.4.0 running on stdio (${ctx.registry ? `${ctx.registry.servers().length} servers configured` : "unconfigured"})`);

  const shutdown = async () => {
    await ctx.transport?.close();
    process.exit(0);
  };
  // Client disconnects (stdin EOF) must reap pooled SSH connections,
  // otherwise the open sockets keep the process alive. The SDK transport
  // never listens for stdin "end", so we do it ourselves.
  transport.onclose = () => {
    void shutdown();
  };
  process.stdin.on("end", shutdown);
  process.stdin.on("close", shutdown);
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("flotilla-mcp fatal:", err);
  process.exit(1);
});
