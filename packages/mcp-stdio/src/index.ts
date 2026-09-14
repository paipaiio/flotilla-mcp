#!/usr/bin/env node
/**
 * Flotilla stdio MCP server.
 *
 * Tool packs: diagnostics, fleet targeting, command execution, file transfer,
 * services, sessions, monitoring, workflows, onboarding, and config reload.
 * Config resolution order: --config <path> -> FLOTILLA_CONFIG -> platform default.
 * Without a config the server still starts (so MCP handshake and tools/list work)
 * but every tool call is refused with a message naming the expected path.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createHash } from "node:crypto";
import { chmodSync, createReadStream, readFileSync, renameSync, unlinkSync, watch, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import {
  AuditLogger,
  Executor,
  FleetRegistry,
  SshTransport,
  analyzeDoctor,
  applyStructuredChanges,
  appendServerToConfig,
  buildServerToml,
  probeServer,
  redactSensitiveText,
  pullConfigToFile,
  buildControlCommand,
  buildChecksumCommand,
  buildDoctorScript,
  buildLogsCommand,
  buildServiceManagerProbeCommand,
  buildMetricsScript,
  buildPathKindProbe,
  buildSessionCaptureCommand,
  buildSessionKillCommand,
  buildSessionListCommand,
  buildSessionSendCommand,
  buildSessionStartCommand,
  buildStatusCommand,
  buildFileTailCommand,
  buildJournalTailCommand,
  buildKeyInstallCommand,
  checkServiceScope,
  checkRelayPolicy,
  classifyCommand,
  checkPathScope,
  checkCommandScope,
  checkCommandPathScope,
  createChangeSet,
  decide,
  decideChangeSet,
  decideForServer,
  resolveAuditPath,
  defaultConfigPath,
  defaultKeychainBackend,
  diffFanout,
  filterTailOutput,
  formatDiff,
  formatDoctor,
  formatMetrics,
  formatRelay,
  formatSyncPlan,
  formatSyncResult,
  grantKey,
  GrantStore,
  inspectFleetCredentials,
  ensureFleetKeyPair,
  loadFleetConfig,
  migratePasswordServersInConfig,
  assessAction,
  formatAssessmentCard,
  parseChecksums,
  parseMetrics,
  parsePathKind,
  parseSessionList,
  parseServiceManager,
  parseWorkflow,
  planSync,
  QuotaCounter,
  relayFile,
  resolveTarget,
  runConfigTransaction,
  runSyncPlan,
  validateSessionName,
  validateUnit,
  WorkflowRunner,
  type AuditEvent,
  type ConfigChange,
  type ChangeSet,
  type FanoutResult,
  type FleetConfig,
  type ServiceAction,
  type ResolvedServiceManager,
  type ServerConfig,
  type Strategy,
} from "flotilla-core";
import { gateApproval, type ApprovalAsk, type ElicitSender } from "./approval.js";
import { registerCommandTools } from "./command-tools.js";
import { CredentialBroker } from "./credential-broker.js";
import { buildCredentialReport, buildRuntimeInfo } from "./diagnostics.js";
import { ExecutionPipeline } from "./execution-pipeline.js";
import { LocalSecretBroker } from "./local-secret-broker.js";
import { parseStrategy, strategySchema } from "./tool-schemas.js";

const MAX_OUTPUT_CHARS_PER_HOST = 8_000;
const MODULE_PATH = fileURLToPath(import.meta.url);
const MCP_VERSION = (() => {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      version?: unknown;
    };
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
})();

interface AppContext {
  config?: FleetConfig;
  configPath?: string;
  configError?: string;
  registry?: FleetRegistry;
  executor?: Executor;
  transport?: SshTransport;
  audit?: AuditLogger;
  quota?: QuotaCounter;
  grants?: GrantStore;
  serviceManagers?: Map<string, ResolvedServiceManager>;
}

let credentialBroker: CredentialBroker | undefined;

function buildContext(configPath: string | undefined): AppContext {
  const config = loadFleetConfig(configPath);
  const effectivePath = resolvePath(configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
  const registry = new FleetRegistry(config);
  const transport = new SshTransport(
    new Map(config.servers.map((s) => [s.name, s])),
    {
      idleReapMs: config.defaults.idleReapMs,
      strictAlgorithms: config.defaults.strictAlgorithms,
      maxSshOutputBytes: config.defaults.maxSshOutputBytes,
      onCredentialRequired: (server, kind) =>
        credentialBroker?.repair(server, kind) ?? Promise.resolve(false),
    },
  );
  const audit = new AuditLogger(
    resolveAuditPath(effectivePath, config.audit?.path),
    { hashChain: config.audit?.hashChain ?? true, entropyScan: config.audit?.entropyScan ?? false },
  );
  // Quota state lives next to the effective config so restarts don't reset it.
  const quota = new QuotaCounter(
    join(dirname(effectivePath), "quota-state.json"),
    config.defaults.commandQuotaPerDay ?? 0,
  );
  // JIT grants: in-memory, cleared on restart/reload — by design.
  const grants = new GrantStore(config.defaults.jitGrantTtlMs ?? 900_000);
  return {
    config,
    configPath,
    registry,
    transport,
    audit,
    quota,
    grants,
    serviceManagers: new Map(),
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
const retiringTransports = new Set<Promise<void>>();

/** Drain an old pool after a context swap; force-close after the grace period. */
function retireTransport(transport: SshTransport, timeoutMs: number, reason: string): void {
  let retirement!: Promise<void>;
  retirement = transport.drainAndClose(timeoutMs)
    .then((result) => {
      console.error(
        result.drained
          ? `flotilla-mcp: previous SSH pool drained (${reason})`
          : `flotilla-mcp: previous SSH pool grace period expired (${reason}); force-closed ${result.activeAtClose} active operation(s)`,
      );
    })
    .catch((error) => {
      console.error(`flotilla-mcp: previous SSH pool retirement failed (${reason}): ${error instanceof Error ? error.message : error}`);
    })
    .finally(() => retiringTransports.delete(retirement));
  retiringTransports.add(retirement);
}

/** The path the running config was (or would be) loaded from. */
function effectiveConfigPath(): string {
  return resolvePath(ctx.configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
}

/** Validated callers use this to replace the active config without partial writes. */
function writeConfigAtomically(path: string, text: string, label: string): void {
  const temporary = `${path}.${label}-${process.pid}-${Date.now()}.tmp`;
  try {
    writeFileSync(temporary, text, { encoding: "utf8", mode: 0o600, flag: "wx" });
    renameSync(temporary, path);
    chmodSync(path, 0o600);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* no temporary file to clean */ }
    throw error;
  }
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
    ctx.grants = next.grants;
    ctx.serviceManagers = next.serviceManagers;
    ctx.configError = undefined;
    console.error(
      `flotilla-mcp: config reloaded (${reason}): ${names.length} server(s): ${names.join(", ") || "(none)"}`,
    );
    // Stop new work on the old pool, but let in-flight calls finish before its
    // connections close. The new context is already serving fresh requests.
    if (oldTransport) retireTransport(oldTransport, next.config!.defaults.commandTimeoutMs, reason);
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

/** Resolve configured/auto-detected init systems and cache probes until reload. */
async function resolveServiceManagers(
  servers: ServerConfig[],
  timeoutMs?: number,
): Promise<Map<string, ResolvedServiceManager>> {
  if (!ctx.executor) throw new Error("Executor is not configured");
  const resolved = new Map<string, ResolvedServiceManager>();
  const probe: ServerConfig[] = [];
  for (const server of servers) {
    const configured = server.serviceManager ?? "auto";
    if (configured !== "auto") {
      resolved.set(server.name, configured);
      continue;
    }
    const cached = ctx.serviceManagers?.get(server.name);
    if (cached) resolved.set(server.name, cached);
    else probe.push(server);
  }
  if (probe.length > 0) {
    const result = await ctx.executor.run(
      probe,
      buildServiceManagerProbeCommand(),
      { kind: "parallel" },
      { timeoutMs },
    );
    for (const host of result.results) {
      if (!host.ok) {
        throw new Error(`Service-manager probe failed on ${host.host}: ${host.error ?? host.stderr.trim()}`);
      }
      const manager = parseServiceManager(host.stdout);
      ctx.serviceManagers?.set(host.host, manager);
      resolved.set(host.host, manager);
    }
  }
  return resolved;
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

  // Channel -1: a live JIT grant covers the identical request — no prompt.
  const key = grantKey(tool, ask.changeSet?.id ?? ask.action, ask.hosts);
  if (ctx.grants?.check(key)) {
    audit({
      kind: "approval",
      tool,
      command: ask.action,
      commandClass: ask.commandClass,
      hosts: ask.hosts,
      outcome: "approved",
      approver: "jit-grant",
    });
    return { kind: "approved", via: "jit-grant" } as const;
  }

  // AI risk card (§6.2 layer 2): advisory only, computed before the prompt.
  // Runs AFTER policy has already gated the action — no path from here to
  // "allowed". Any failure degrades to "no card", the prompt works as before.
  let assessmentCard: string | undefined;
  const assessor = ctx.config?.aiAssessor;
  if (assessor?.enabled) {
    try {
      const assessment = await assessAction(assessor, {
        action: ask.action,
        commandClass: ask.commandClass,
        hosts: ask.hosts,
        tool,
      });
      assessmentCard = formatAssessmentCard(assessment);
      audit({
        kind: "decision",
        tool,
        command: ask.action,
        commandClass: ask.commandClass,
        hosts: ask.hosts,
        outcome: "ok",
        reason: `ai-assessment: ${assessment.recommendation} — ${assessment.summary}`,
      });
    } catch (err) {
      assessmentCard = `── AI risk card unavailable: ${err instanceof Error ? err.message : String(err)} ──`;
    }
  }

  const outcome = await gateApproval(server, extra as unknown as ElicitSender, {
    ...rest,
    allowConfirmFlag: confirmFlagEnabled(),
    jitGrantTtlMs: ctx.config?.defaults.jitGrantTtlMs ?? 900_000,
    assessmentCard,
  });
  // An interactive "remember" approval mints a grant. The confirm-flag
  // channel never does (it is model-filled — granting would be self-approval).
  if (outcome.kind === "approved" && outcome.remember) {
    ctx.grants?.grant(key);
  }
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
  executionPipeline.auditExecution(tool, command, fanout);
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
  return { isError: true as const, content: [{ type: "text" as const, text: redactSensitiveText(message).text }] };
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
    if (r.error) lines.push(`error: ${redactSensitiveText(r.error).text}`);
    if (r.stdout) lines.push(truncate(redactSensitiveText(r.stdout.trimEnd()).text));
    if (r.stderr) lines.push(`stderr: ${truncate(redactSensitiveText(r.stderr.trimEnd()).text)}`);
    lines.push("");
  }
  return lines.join("\n");
}

const server = new McpServer(
  { name: "flotilla-mcp", version: MCP_VERSION },
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
      "manage persistent tmux sessions that survive disconnects; exec-sudo runs commands as root. " +
      "When a password is missing and the client supports URL elicitation, Flotilla opens a one-time " +
      "loopback form, saves the secret to the OS keychain, and resumes the original call automatically. " +
      "For sensitive config values use config-apply valueFromLocal=true: the one-time loopback page keeps " +
      "the value out of MCP, config contents move through bounded memory SFTP, and returned sensitive output " +
      "is replaced by a stable SHA-256 fingerprint.",
  },
);

credentialBroker = new CredentialBroker({
  getKeychain: defaultKeychainBackend,
  supportsUrlElicitation: () => {
    const capabilities = server.server.getClientCapabilities();
    return capabilities?.elicitation?.url !== undefined;
  },
  createCompletionNotifier: (elicitationId) =>
    server.server.createElicitationCompletionNotifier(elicitationId),
});

const localSecretBroker = new LocalSecretBroker({
  supportsUrlElicitation: () => server.server.getClientCapabilities()?.elicitation?.url !== undefined,
  createCompletionNotifier: (elicitationId) =>
    server.server.createElicitationCompletionNotifier(elicitationId),
});

// Attach the request-scoped elicitation sender to every tool, including tools
// registered by command-tools.ts. AsyncLocalStorage keeps concurrent calls
// isolated, so a missing credential is always prompted through its own client.
type ContextualExtra = ElicitSender & { signal?: AbortSignal };
type UntypedToolHandler = (args: unknown, extra: ContextualExtra) => Promise<unknown> | unknown;
type UntypedRegisterTool = (
  name: string,
  config: unknown,
  handler: UntypedToolHandler,
) => unknown;

function sanitizeMcpBoundary(value: unknown): unknown {
  if (typeof value === "string") return redactSensitiveText(value).text;
  if (Array.isArray(value)) return value.map(sanitizeMcpBoundary);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizeMcpBoundary(item)]));
  }
  return value;
}

const registerToolWithoutCredentialContext = server.registerTool.bind(server) as unknown as UntypedRegisterTool;
server.registerTool = ((name: string, config: unknown, handler: UntypedToolHandler) =>
  registerToolWithoutCredentialContext(name, config, async (args, extra) =>
    sanitizeMcpBoundary(await credentialBroker!.runWithRequest(
      { sender: extra, signal: extra.signal },
      async () => handler(args, extra),
    )),
  )) as unknown as typeof server.registerTool;

const executionPipeline = new ExecutionPipeline({
  resolve: (target) => {
    if (!ctx.registry) throw new Error(`Flotilla is not configured: ${ctx.configError ?? "missing config"}`);
    return resolveTarget(ctx.registry, target);
  },
  decide: (command, host) => {
    if (!ctx.config) throw new Error("Flotilla policy defaults are not configured");
    return decideForServer(command, host, ctx.config.defaults.approvalMode);
  },
  approve: (extra, request) => gate(extra, request),
  quota: {
    check: () => ctx.quota?.check() ?? { limit: 0, used: 0, allowed: true },
    record: () => ctx.quota?.record(),
  },
  audit,
});

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
  "runtime-info",
  {
    description:
      "Show the exact running Flotilla version, executable/module paths, effective config path, " +
      "config source, Node version, and OS keychain availability. Use this first when an upgrade " +
      "appears ineffective or the MCP process seems to be using a different installation.",
    inputSchema: {},
  },
  async () => {
    const keychain = await defaultKeychainBackend();
    const info = buildRuntimeInfo({
      version: MCP_VERSION,
      modulePath: MODULE_PATH,
      execPath: process.execPath,
      cwd: process.cwd(),
      configPath: effectiveConfigPath(),
      configSource: ctx.configPath
        ? "argument"
        : process.env.FLOTILLA_CONFIG
          ? "environment"
          : "platform-default",
      configuredServers: ctx.registry?.servers().length ?? 0,
      keychainAvailable: keychain !== null,
    });
    return {
      content: [{ type: "text" as const, text: JSON.stringify(info, null, 2) }],
      structuredContent: info,
    };
  },
);

server.registerTool(
  "credential-status",
  {
    description:
      "Diagnose credential readiness for a target without returning any password, private key, " +
      "or token. Reports the active source (agent, key file, environment, OS keychain, or missing) " +
      "and gives one recovery command. Set repair=true for a one-time loopback URL that saves missing " +
      "passwords to the OS keychain; the current request continues without an MCP restart.",
    inputSchema: {
      target: z
        .union([z.string(), z.array(z.string())])
        .optional()
        .describe('Target expression; defaults to "all"'),
      repair: z
        .boolean()
        .optional()
        .describe("Prompt securely for each missing SSH password, save it to the OS keychain, and re-check"),
    },
  },
  async ({ target, repair }) => {
    if (!ctx.registry) return notConfigured();
    try {
      const servers = resolveTarget(ctx.registry, target ?? "all");
      let credentials = await inspectFleetCredentials(servers);
      let attempted = 0;
      let saved = 0;
      if (repair) {
        for (let index = 0; index < servers.length; index++) {
          if (servers[index].auth !== "password" || credentials[index].ready) continue;
          attempted++;
          if (await credentialBroker?.repair(servers[index], "password")) saved++;
        }
        credentials = await inspectFleetCredentials(servers);
      }
      const report = {
        ...buildCredentialReport(credentials),
        repair: { requested: repair === true, attempted, saved },
      };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }],
        structuredContent: report,
      };
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  },
);

server.registerTool(
  "setup-repair",
  {
    description:
      "Preview or execute a batch migration of existing password-authenticated targets to one " +
      "dedicated Ed25519 key. Missing passwords use the secure loopback credential flow; each " +
      "public-key install is verified with a fresh key-auth connection before a single validated, " +
      "atomic config edit and hot reload. No MCP restart is required.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).optional().describe('Target expression; defaults to "all"'),
      keyRef: z.string().optional().describe("Private key path; defaults to fleet_ed25519 beside the active config"),
      apply: z.boolean().optional().describe("False/omitted previews only; true installs, verifies, and updates config"),
      removeStoredPasswords: z.boolean().optional().describe("After successful hot reload, remove migrated login passwords from OS Keychain"),
      confirm: z.boolean().optional().describe("Explicit approval fallback when enabled by operator policy"),
    },
  },
  async ({ target, keyRef, apply, removeStoredPasswords, confirm }, extra) => {
    if (!ctx.registry || !ctx.config || !ctx.transport) return notConfigured();
    const selected = resolveTarget(ctx.registry, target ?? "all");
    const candidates = selected.filter((candidate) => candidate.auth === "password");
    const cfgPath = effectiveConfigPath();
    const desiredKeyPath = keyRef ?? join(dirname(cfgPath), "fleet_ed25519");
    const preview = {
      mode: apply ? "apply" : "preview",
      target: target ?? "all",
      selected: selected.length,
      passwordServers: candidates.map((candidate) => candidate.name),
      skippedAlreadyKeyOrAgent: selected.filter((candidate) => candidate.auth !== "password").map((candidate) => candidate.name),
      keyRef: desiredKeyPath,
      next: candidates.length === 0
        ? "No password-authenticated servers need migration."
        : "Re-run with apply=true; one approval covers this batch.",
    };
    if (!apply || candidates.length === 0) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(preview, null, 2) }],
        structuredContent: preview,
      };
    }

    const outcome = await gate(extra, {
      tool: "setup-repair",
      action:
        `install one dedicated public key on ${candidates.length} password-authenticated server(s), ` +
        `verify key login, then change auth to key in ${cfgPath}: ${candidates.map((server) => server.name).join(", ")}`,
      commandClass: "privileged (credential migration)",
      hosts: candidates.map((candidate) => candidate.name),
      confirmFlag: confirm,
    });
    if (outcome.kind === "refused") return errorResult(outcome.reason);

    const results: Array<{
      server: string;
      status: "migrated" | "failed";
      hostname?: string;
      hostKey?: string;
      reason?: string;
    }> = [];
    try {
      const keyPair = ensureFleetKeyPair(desiredKeyPath);
      const allServers = ctx.registry.servers();
      for (const candidate of candidates) {
        const passwordServer: ServerConfig = {
          ...candidate,
          scopes: undefined,
          readOnly: false,
          auth: "password",
          keyRef: undefined,
        };
        const passwordFleet = new Map(allServers.map((server) => [
          server.name,
          server.name === candidate.name ? passwordServer : server,
        ]));
        const installer = new SshTransport(passwordFleet, {
          idleReapMs: ctx.config.defaults.idleReapMs,
          strictAlgorithms: ctx.config.defaults.strictAlgorithms,
          maxSshOutputBytes: ctx.config.defaults.maxSshOutputBytes,
          onCredentialRequired: (server, kind) =>
            credentialBroker?.repair(server, kind) ?? Promise.resolve(false),
        });
        try {
          const installed = await installer.exec(
            passwordServer,
            buildKeyInstallCommand(keyPair.publicKey),
            { timeoutMs: ctx.config.defaults.commandTimeoutMs },
          );
          if (!installed.ok || !installed.stdout.includes("INSTALLED")) {
            results.push({
              server: candidate.name,
              status: "failed",
              reason: installed.error ?? (installed.stderr.trim() || "public-key install did not confirm"),
            });
            continue;
          }
          const capturedHostKey = candidate.trustedHostKey ?? installer.hostKeyOf(candidate.name);
          const keyServer: ServerConfig = {
            ...candidate,
            scopes: undefined,
            readOnly: false,
            auth: "key",
            keyRef: keyPair.privateKeyPath,
            trustedHostKey: capturedHostKey,
          };
          const keyFleet = new Map(allServers.map((server) => [
            server.name,
            server.name === candidate.name ? keyServer : server,
          ]));
          const verifier = new SshTransport(keyFleet, {
            idleReapMs: ctx.config.defaults.idleReapMs,
            strictAlgorithms: ctx.config.defaults.strictAlgorithms,
            maxSshOutputBytes: ctx.config.defaults.maxSshOutputBytes,
            onCredentialRequired: (server, kind) =>
              credentialBroker?.repair(server, kind) ?? Promise.resolve(false),
          });
          try {
            const verified = await verifier.exec(keyServer, "hostname && id -u", {
              timeoutMs: ctx.config.defaults.commandTimeoutMs,
            });
            if (!verified.ok) {
              results.push({
                server: candidate.name,
                status: "failed",
                reason: `public key installed but key login verification failed: ${verified.error ?? verified.stderr.trim()}`,
              });
              continue;
            }
            results.push({
              server: candidate.name,
              status: "migrated",
              hostname: verified.stdout.trim().split("\n")[0],
              hostKey: capturedHostKey,
            });
          } finally {
            await verifier.close();
          }
        } catch (error) {
          results.push({
            server: candidate.name,
            status: "failed",
            reason: error instanceof Error ? error.message : String(error),
          });
        } finally {
          await installer.close();
        }
      }

      const migrated = results.filter((result) => result.status === "migrated");
      let hotReloaded = false;
      const passwordCleanup = {
        requested: removeStoredPasswords === true,
        keychainAvailable: false,
        removed: 0,
      };
      if (migrated.length > 0) {
        const original = readFileSync(cfgPath, "utf8");
        const next = migratePasswordServersInConfig(
          original,
          migrated.map((result) => ({
            server: result.server,
            keyRef: keyPair.privateKeyPath,
            trustedHostKey: result.hostKey,
          })),
        );
        writeConfigAtomically(cfgPath, next, "setup-repair");
        const reload = reloadFleet("setup-repair key migration");
        if (!reload.ok) {
          writeConfigAtomically(cfgPath, original, "setup-repair-rollback");
          reloadFleet("setup-repair rollback");
          return errorResult(`Key login verified, but config hot reload failed and the config was restored: ${reload.message}`);
        }
        hotReloaded = true;
        if (removeStoredPasswords) {
          const keychain = await defaultKeychainBackend();
          if (keychain) {
            passwordCleanup.keychainAvailable = true;
            const removals = await Promise.allSettled(
              migrated.map((result) => keychain.remove(result.server)),
            );
            passwordCleanup.removed = removals.filter(
              (removal) => removal.status === "fulfilled" && removal.value,
            ).length;
          }
        }
      }
      const report = {
        ...preview,
        mode: "applied",
        key: { path: keyPair.privateKeyPath, created: keyPair.created },
        summary: {
          attempted: candidates.length,
          migrated: migrated.length,
          failed: results.length - migrated.length,
        },
        hotReloaded,
        restartRequired: false,
        passwordCleanup,
        results,
      };
      audit({
        kind: "execution",
        tool: "setup-repair",
        command: `migrate password auth to key: ${candidates.map((candidate) => candidate.name).join(", ")}`,
        hosts: candidates.map((candidate) => candidate.name),
        outcome: report.summary.failed === 0 ? "ok" : "failed",
        reason: `${report.summary.migrated} migrated, ${report.summary.failed} failed`,
      });
      return report.summary.failed === 0
        ? { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }], structuredContent: report }
        : { isError: true as const, content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }], structuredContent: report };
    } catch (error) {
      audit({
        kind: "execution",
        tool: "setup-repair",
        command: `migrate password auth to key: ${candidates.map((candidate) => candidate.name).join(", ")}`,
        hosts: candidates.map((candidate) => candidate.name),
        outcome: "failed",
        reason: error instanceof Error ? error.message : String(error),
      });
      return errorResult(error instanceof Error ? error.message : String(error));
    }
  },
);

const configChangeSchema = z.discriminatedUnion("op", [
  z.object({
    op: z.literal("set"),
    path: z.string().startsWith("/"),
    value: z.unknown().optional(),
    valueFromEnv: z.string().optional(),
    valueFromLocal: z.boolean().optional(),
    label: z.string().max(80).optional(),
  }),
  z.object({ op: z.literal("delete"), path: z.string().startsWith("/") }),
]);

type ConfigApplyChange =
  | {
      op: "set";
      path: string;
      value?: unknown;
      valueFromEnv?: string;
      valueFromLocal?: boolean;
      label?: string;
    }
  | { op: "delete"; path: string };

const SENSITIVE_CONFIG_PATH =
  /(?:^|\/)(?:password|passwd|secret|token|api[-_]?key|private[-_]?key|credential)(?:\/|$)/i;

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function valueFingerprint(value: unknown): string {
  const encoded = JSON.stringify(value);
  return `sha256:${createHash("sha256").update(encoded === undefined ? "undefined" : encoded).digest("hex")}`;
}

async function fileFingerprint(path: string): Promise<string> {
  const expanded = path === "~" ? homedir() : path.startsWith("~/") ? join(homedir(), path.slice(2)) : path;
  const hash = createHash("sha256");
  await new Promise<void>((resolve, reject) => {
    const stream = createReadStream(expanded);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return `sha256:${hash.digest("hex")}`;
}

server.registerTool(
  "config-apply",
  {
    description:
      "Preview or apply structured JSON/YAML/TOML changes as a remote transaction: keep a sibling " +
      "backup, upload a staged file, validate it, atomically replace the live path, restart/reload " +
      "the service, health-check it, and automatically restore/restart/re-check on failure. Literal " +
      "values are never echoed; valueFromEnv or valueFromLocal keeps secrets out of the MCP conversation.",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      path: z.string().max(4096).startsWith("/").refine((value) => !/[\0\r\n]/.test(value), "Remote config path cannot contain NUL or newlines").describe("Absolute remote config path allowed by scopes.paths"),
      format: z.enum(["json", "yaml", "toml"]),
      changes: z.array(configChangeSchema).min(1).max(100).describe("JSON-Pointer set/delete operations"),
      unit: z.string().optional().describe("Service to restart/reload and health-check; required when apply=true"),
      action: z.enum(["restart", "reload"]).optional().describe("Service action after install; defaults to restart"),
      validateCommand: z.string().max(8192).optional().describe("Optional app validator; must contain {file}, replaced with the quoted staged path"),
      healthCommand: z.string().max(8192).optional().describe("Optional post-action health command; defaults to service status"),
      apply: z.boolean().optional().describe("False/omitted previews only; true executes the transaction"),
      confirm: z.boolean().optional().describe("Explicit approval fallback when enabled by operator policy"),
      timeoutMs: z.number().int().positive().optional(),
    },
  },
  async ({ target, path, format, changes, unit, action, validateCommand, healthCommand, apply, confirm, timeoutMs }, extra) => {
    if (!ctx.registry || !ctx.config || !ctx.transport) return notConfigured();
    try {
      if (validateCommand !== undefined && !validateCommand.includes("{file}")) {
        return errorResult("validateCommand must contain the {file} placeholder");
      }
      const servers = resolveTarget(ctx.registry, target);
      const normalizedUnit = unit === undefined ? undefined : validateUnit(unit);
      const requestedChanges = changes as ConfigApplyChange[];
      for (const change of requestedChanges) {
        if (change.op !== "set") continue;
        const sources = [
          Object.prototype.hasOwnProperty.call(change, "value"),
          typeof change.valueFromEnv === "string",
          "valueFromLocal" in change && change.valueFromLocal === true,
        ].filter(Boolean).length;
        if (sources !== 1) return errorResult(`Set change at "${change.path}" requires exactly one of value, valueFromEnv, or valueFromLocal=true`);
        if (Object.prototype.hasOwnProperty.call(change, "value") && SENSITIVE_CONFIG_PATH.test(change.path)) {
          return errorResult(`Sensitive field "${change.path}" must use valueFromLocal=true or valueFromEnv`);
        }
      }
      if (apply && !normalizedUnit) return errorResult("unit is required when apply=true");
      const summaries = requestedChanges.map((change) => ({
        op: change.op,
        path: change.path,
        ...(change.op === "set" ? {
          source: "valueFromLocal" in change && change.valueFromLocal
            ? "local-page"
            : change.valueFromEnv ? "environment" : "literal",
        } : {}),
      }));
      const userCommands = [validateCommand, healthCommand].filter((command): command is string => command !== undefined);
      const forbidden = userCommands.find((command) => classifyCommand(command.replaceAll("{file}", "CONFIG_FILE")) === "forbidden");
      if (forbidden) return errorResult("validateCommand/healthCommand matches the built-in never-allowed list");
      const changeSetFrom = (payloadFingerprints: string[]): ChangeSet => createChangeSet({
        tool: "config-apply",
        summary: `Apply ${summaries.length} structured change(s) to ${path}`,
        targets: servers.map((candidate) => candidate.name),
        paths: [path],
        services: normalizedUnit ? [normalizedUnit] : [],
        operations: [
          ...summaries.map((change) => `${change.op} ${change.path} (${"source" in change ? change.source : "no-value"})`),
          ...(validateCommand ? [`validate command: ${validateCommand}`] : ["validate staged structured document"]),
          ...(normalizedUnit ? [`${action ?? "restart"} ${normalizedUnit}`, `health-check ${normalizedUnit}`] : []),
          ...(healthCommand ? [`health command: ${healthCommand}`] : []),
        ],
        rollback: normalizedUnit ? `restore the per-host backup, ${action ?? "restart"} ${normalizedUnit}, and health-check again` : "restore the per-host backup",
        risk: userCommands.some((command) => classifyCommand(command.replaceAll("{file}", "CONFIG_FILE")) === "privileged") ? "privileged" : "destructive",
        payloadFingerprints,
      });
      const preliminaryFingerprints: string[] = [];
      for (const change of requestedChanges) {
        if (change.op !== "set") continue;
        if ("valueFromLocal" in change && change.valueFromLocal) {
          preliminaryFingerprints.push(`${change.path}=unresolved-local-page`);
        } else if (change.valueFromEnv) {
          const value = process.env[change.valueFromEnv];
          if (value === undefined && apply) return errorResult(`Environment variable "${change.valueFromEnv}" is not set`);
          preliminaryFingerprints.push(`${change.path}=${value === undefined ? `unresolved-env:${change.valueFromEnv}` : valueFingerprint(value)}`);
        } else {
          preliminaryFingerprints.push(`${change.path}=${valueFingerprint(change.value)}`);
        }
      }
      const preliminaryChangeSet = changeSetFrom(preliminaryFingerprints);
      const transactionPaths = new Map(servers.map((candidate, index) => {
        const nonce = `${process.pid}-${Date.now()}-${index}-${Math.random().toString(16).slice(2, 10)}`;
        return [candidate.name, {
          backup: `${path}.flotilla-backup-${nonce}`,
          staged: `${path}.flotilla-stage-${nonce}`,
        }] as const;
      }));
      const localChanges = requestedChanges.filter((change): change is Extract<ConfigApplyChange, { op: "set" }> & { valueFromLocal: true } =>
        change.op === "set" && change.valueFromLocal === true,
      );
      if (apply && localChanges.length > 0) {
        const preflightDenied: string[] = [];
        for (const candidate of servers) {
          const decision = decideChangeSet(preliminaryChangeSet, candidate, ctx.config.defaults.approvalMode);
          if (!decision.allowed) preflightDenied.push(`${candidate.name}: ${decision.reason}`);
          const paths = transactionPaths.get(candidate.name)!;
          const scopedUserCommands = [
            validateCommand ? validateCommand.replaceAll("{file}", shellQuote(paths.staged)) : undefined,
            healthCommand,
          ].filter((command): command is string => command !== undefined);
          if (
            scopedUserCommands.length > 0 &&
            candidate.role === "operator" &&
            candidate.group === "prod" &&
            (!candidate.scopes?.commands || candidate.scopes.commands.length === 0)
          ) {
            preflightDenied.push(`${candidate.name}: production operator custom validation/health commands require explicit scopes.commands`);
          }
          for (const command of scopedUserCommands) {
            const scopeReason = checkCommandScope(candidate, command) ?? checkCommandPathScope(candidate, command);
            if (scopeReason) preflightDenied.push(`${candidate.name}: ${scopeReason}`);
          }
        }
        if (preflightDenied.length > 0) return errorResult(`Change-set preflight failed:\n${[...new Set(preflightDenied)].join("\n")}`);
      }
      const resolvedChanges: ConfigChange[] = [];
      const payloadFingerprints: string[] = [];
      for (const change of requestedChanges) {
        if (change.op === "delete") { resolvedChanges.push(change); continue; }
        if ("valueFromLocal" in change && change.valueFromLocal) {
          if (!apply) {
            payloadFingerprints.push(`${change.path}=unresolved-local-page`);
            continue;
          }
          const captured = await localSecretBroker.capture(
            { sender: extra as unknown as ElicitSender, signal: extra.signal },
            { target: servers.map((candidate) => candidate.name).join(", "), path: change.path, label: change.label ?? "sensitive config value" },
          );
          if (captured === undefined) return errorResult(`LOCAL_SECRET_REQUIRED: use a URL-elicitation client to enter ${change.path} on the one-time local page`);
          resolvedChanges.push({ op: "set", path: change.path, value: captured });
          payloadFingerprints.push(`${change.path}=${valueFingerprint(captured)}`);
        } else {
          resolvedChanges.push(change);
          if (change.valueFromEnv) payloadFingerprints.push(`${change.path}=${valueFingerprint(process.env[change.valueFromEnv]!)}`);
          else payloadFingerprints.push(`${change.path}=${valueFingerprint(change.value)}`);
        }
      }
      const changeSet = apply ? changeSetFrom(payloadFingerprints) : preliminaryChangeSet;
      const preview = {
        mode: apply ? "apply" : "preview",
        target,
        hosts: servers.map((candidate) => candidate.name),
        path,
        format,
        changes: summaries,
        service: normalizedUnit ? { unit: normalizedUnit, action: action ?? "restart" } : undefined,
        validation: validateCommand ? "local-structure + remote-command" : "local-structure + staged-file",
        health: healthCommand ? "remote-command" : "service-status",
        changeSet: {
          id: changeSet.id,
          risk: changeSet.risk,
          paths: changeSet.paths,
          services: changeSet.services,
          operations: changeSet.operations,
          rollback: changeSet.rollback,
          payloadFingerprints: changeSet.payloadFingerprints,
        },
        transaction: ["backup", "stage", "validate", "atomic-replace", action ?? "restart", "health-check", "rollback-on-failure"],
        next: apply ? "Execute after one approval." : "Re-run with apply=true and unit to execute after one approval.",
      };
      if (!apply) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify(preview, null, 2) }],
          structuredContent: preview,
        };
      }
      const requiredUnit = normalizedUnit!;
      const denied: string[] = [];
      for (const candidate of servers) {
        const paths = transactionPaths.get(candidate.name)!;
        const changeDecision = decideChangeSet(changeSet, candidate, ctx.config.defaults.approvalMode);
        if (!changeDecision.allowed) denied.push(`${candidate.name}: ${changeDecision.reason}`);
        const scopedUserCommands = [
          validateCommand ? validateCommand.replaceAll("{file}", shellQuote(paths.staged)) : undefined,
          healthCommand ?? undefined,
        ].filter((command): command is string => command !== undefined);
        if (
          scopedUserCommands.length > 0 &&
          candidate.role === "operator" &&
          candidate.group === "prod" &&
          (!candidate.scopes?.commands || candidate.scopes.commands.length === 0)
        ) {
          denied.push(`${candidate.name}: production operator custom validation/health commands require explicit scopes.commands`);
        }
        for (const command of scopedUserCommands) {
          const commandScopeReason = checkCommandScope(candidate, command) ?? checkCommandPathScope(candidate, command);
          if (commandScopeReason) denied.push(`${candidate.name}: ${commandScopeReason}`);
        }
      }
      if (denied.length > 0) {
        const reasons = [...new Set(denied)];
        auditDenial("config-apply", `${action ?? "restart"} ${normalizedUnit} after structured update to ${path}`, "destructive", servers.map((candidate) => candidate.name), reasons.join("; "));
        return errorResult("Refused by policy (config-apply):\n" + reasons.map((reason) => `  - ${reason}`).join("\n"));
      }

      const approval = await gate(extra, {
        tool: "config-apply",
        action: `change-set ${changeSet.id}: transactionally apply ${summaries.length} structured change(s) to ${path}, ${action ?? "restart"} ${normalizedUnit}, health-check, and roll back on failure`,
        commandClass: `${changeSet.risk} (transactional config change)`,
        hosts: servers.map((candidate) => candidate.name),
        confirmFlag: confirm,
        changeSet,
      });
      if (approval.kind === "refused") return errorResult(approval.reason);

      const quota = ctx.quota?.check();
      if (quota && !quota.allowed) return errorResult(`Daily command quota reached (${quota.used}/${quota.limit})`);
      ctx.quota?.record();
      const managers = await resolveServiceManagers(servers, timeoutMs);
      const results: Array<Record<string, unknown>> = [];
      let halted = false;
      for (const candidate of servers) {
        if (halted) {
          results.push({ server: candidate.name, ok: false, skipped: true, error: "Skipped: previous target failed and stopped the rollout" });
          continue;
        }
        const plannedPaths = transactionPaths.get(candidate.name)!;
        const backupPath = plannedPaths.backup;
        const stagedPath = plannedPaths.staged;
        const unrestricted: ServerConfig = { ...candidate, scopes: undefined, readOnly: false };
        const transport = new SshTransport(new Map([[candidate.name, unrestricted]]), {
          idleReapMs: ctx.config.defaults.idleReapMs,
          strictAlgorithms: ctx.config.defaults.strictAlgorithms,
          maxSshOutputBytes: ctx.config.defaults.maxSshOutputBytes,
          onCredentialRequired: (server, kind) => credentialBroker?.repair(server, kind) ?? Promise.resolve(false),
        });
        const opts = { timeoutMs: timeoutMs ?? ctx.config.defaults.commandTimeoutMs, signal: extra.signal };
        const execChecked = async (command: string): Promise<void> => {
          const response = await transport.exec(unrestricted, command, opts);
          if (!response.ok) throw new Error(response.error ?? `remote command failed with exit ${response.exitCode ?? "unknown"}`);
        };
        try {
          const downloaded = await ctx.transport.readText(candidate, path, opts);
          const transformed = applyStructuredChanges(downloaded.text, format, resolvedChanges);
          const manager = managers.get(candidate.name)!;
          const restartCommand = buildControlCommand(requiredUnit, action ?? "restart", manager);
          const healthCheck = healthCommand ?? buildStatusCommand(requiredUnit, manager);
          const transaction = await runConfigTransaction({
            backup: () => execChecked(
              `cp -p -- ${shellQuote(path)} ${shellQuote(backupPath)} && cp -p -- ${shellQuote(path)} ${shellQuote(stagedPath)}`,
            ),
            stage: async () => {
              const uploaded = await transport.writeText(unrestricted, stagedPath, transformed.text, opts);
              if (!uploaded.ok) throw new Error(uploaded.error ?? "staged upload failed");
            },
            validate: () => execChecked(validateCommand ? validateCommand.replaceAll("{file}", shellQuote(stagedPath)) : `test -s ${shellQuote(stagedPath)}`),
            install: () => execChecked(`mv -f -- ${shellQuote(stagedPath)} ${shellQuote(path)}`),
            restart: () => execChecked(restartCommand),
            health: () => execChecked(healthCheck),
            rollback: () => execChecked(`mv -f -- ${shellQuote(backupPath)} ${shellQuote(path)}`),
            cleanup: () => execChecked(`rm -f -- ${shellQuote(stagedPath)}`),
          });
          results.push({
            server: candidate.name,
            ...transaction,
            backupPath: transaction.ok ? backupPath : transaction.rolledBack ? undefined : backupPath,
            appliedChanges: summaries,
          });
          if (!transaction.ok) halted = true;
        } catch (error) {
          results.push({ server: candidate.name, ok: false, error: error instanceof Error ? error.message : String(error) });
          halted = true;
        } finally {
          await transport.close();
        }
      }
      const succeeded = results.filter((result) => result.ok === true).length;
      const skipped = results.filter((result) => result.skipped === true).length;
      const report = {
        ...preview,
        mode: "applied",
        summary: { total: results.length, succeeded, failed: results.length - succeeded - skipped, skipped, halted },
        results,
      };
      audit({
        kind: "execution",
        tool: "config-apply",
        command: `${action ?? "restart"} ${normalizedUnit} after structured update to ${path}`,
        hosts: servers.map((candidate) => candidate.name),
        outcome: succeeded === results.length ? "ok" : "failed",
        reason: `${succeeded} succeeded, ${results.length - succeeded - skipped} failed, ${skipped} skipped`,
      });
      return succeeded === results.length
        ? { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }], structuredContent: report }
        : { isError: true as const, content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }], structuredContent: report };
    } catch (error) {
      return errorResult(error instanceof Error ? error.message : String(error));
    }
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

registerCommandTools(server, {
  getExecutor: () => ctx.executor,
  pipeline: executionPipeline,
  notConfigured,
  errorResult,
  formatFanout,
});

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

    let changeSet: ChangeSet;
    try {
      const payload = await fileFingerprint(localPath);
      changeSet = createChangeSet({
        tool: "fleet-push",
        summary: `Upload ${localPath} to ${remotePath}`,
        targets: servers.map((candidate) => candidate.name),
        paths: [remotePath],
        operations: [`overwrite ${remotePath}`, `strategy ${JSON.stringify(parseStrategy(strategy, servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" }))}`],
        rollback: "restore the destination from its operator-managed backup",
        risk: "destructive",
        payloadFingerprints: [payload],
      });
    } catch (error) {
      return errorResult(`Cannot fingerprint upload source: ${error instanceof Error ? error.message : String(error)}`);
    }
    const refusals: string[] = [];
    for (const s of servers) {
      const decision = decideChangeSet(changeSet, s, ctx.config.defaults.approvalMode);
      if (!decision.allowed) refusals.push(`${s.name}: ${decision.reason}`);
    }
    if (refusals.length > 0) {
      auditDenial("fleet-push", `upload ${localPath} -> ${remotePath}`, "destructive (upload)", servers.map((s) => s.name), refusals.join("; "));
      return errorResult("Refused by policy (upload):\n" + refusals.map((r) => `  - ${r}`).join("\n"));
    }
    {
      const outcome = await gate(extra, {
        tool: "fleet-push",
        action: `change-set ${changeSet.id}: upload ${JSON.stringify(localPath)} -> ${JSON.stringify(remotePath)} (overwrites existing files)`,
        commandClass: "destructive (upload)",
        hosts: servers.map((s) => s.name),
        confirmFlag: confirm,
        changeSet,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);
    }

    const resolved = parseStrategy(strategy, servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" });
    try {
      const result = await ctx.executor.push(servers, localPath, remotePath, resolved, { timeoutMs, signal: extra.signal });
      auditExecution("fleet-push", `upload ${localPath} -> ${remotePath}`, result);
      const lines = [
        `change-set=${changeSet.id}`,
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
  async ({ target, remotePath, localPath, strategy, timeoutMs }, extra) => {
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
      const result = await ctx.executor.pull(servers, remotePath, localPath, resolved, { timeoutMs, signal: extra.signal });
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

    const result = await relayFile(ctx.transport, src, sourcePath, dst, destPath, { timeoutMs, signal: extra.signal });
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
      const probeSrc = await ctx.executor.run([src], buildPathKindProbe(sourceDir), { kind: "parallel" }, { timeoutMs, signal: extra.signal });
      const srcKind = probeSrc.results[0]?.ok ? parsePathKind(probeSrc.results[0].stdout) : "missing";
      if (srcKind !== "dir") {
        return errorResult(`Source ${source}:${sourceDir} is ${srcKind === "missing" ? "missing or unreachable" : "not a directory"}`);
      }
      const probeDst = await ctx.executor.run([dst], buildPathKindProbe(destDir), { kind: "parallel" }, { timeoutMs, signal: extra.signal });
      const dstKind = probeDst.results[0]?.ok ? parsePathKind(probeDst.results[0].stdout) : "missing";
      if (dstKind === "file") {
        return errorResult(`Destination ${dest}:${destDir} exists and is a file, not a directory`);
      }

      const srcList = await ctx.executor.run([src], buildChecksumCommand(sourceDir, "dir"), { kind: "parallel" }, { timeoutMs, signal: extra.signal });
      if (!srcList.results[0]?.ok) {
        return errorResult(`Checksum listing failed on ${source}: ${srcList.results[0]?.error ?? srcList.results[0]?.stderr}`);
      }
      const srcEntries = parseChecksums(srcList.results[0].stdout);
      let dstEntries: ReturnType<typeof parseChecksums> = [];
      if (dstKind === "dir") {
        const dstList = await ctx.executor.run([dst], buildChecksumCommand(destDir, "dir"), { kind: "parallel" }, { timeoutMs, signal: extra.signal });
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

      const result = await runSyncPlan(ctx.transport, src, sourceDir, dst, destDir, plan, { timeoutMs, signal: extra.signal });
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
  "fleet-grants",
  {
    description:
      "Inspect or clear active JIT grants — the 'remember for N minutes' exemptions minted by " +
      "interactive approvals. Grants are in-memory only and die with the server process. " +
      "action=list shows live grants with expiry; action=clear revokes everything immediately.",
    inputSchema: {
      action: z.enum(["list", "clear"]).describe("list (default) | clear"),
    },
  },
  async ({ action }) => {
    if (!ctx.grants) return notConfigured();
    if (action === "clear") {
      const n = ctx.grants.clear();
      audit({
        kind: "decision",
        tool: "fleet-grants",
        command: "clear all JIT grants",
        hosts: [],
        outcome: "ok",
        reason: `cleared ${n} grant(s)`,
      });
      return { content: [{ type: "text" as const, text: `Cleared ${n} grant(s). New gated actions will prompt again.` }] };
    }
    const live = ctx.grants.list();
    if (live.length === 0) {
      return { content: [{ type: "text" as const, text: "No active grants. Gated actions will prompt for approval." }] };
    }
    const lines = [`${live.length} active grant(s):`];
    for (const g of live) {
      lines.push(`  - ${g.key}\n    expires ${new Date(g.expiresAtMs).toISOString()}`);
    }
    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
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

const unitSchema = z.string().describe('service name, e.g. "myapp" or "myapp.service"');

server.registerTool(
  "service-status",
  {
    description:
      "Show service status across a target; auto-detects systemd/OpenRC per host. Read-only. " +
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
      const managers = await resolveServiceManagers(servers, timeoutMs);
      const result = await ctx.executor.runMapped(
        servers,
        (s) => buildStatusCommand(normalized, managers.get(s.name)!),
        { kind: "parallel" },
        { timeoutMs },
      );
      auditExecution("service-status", `status ${normalized} (per-host service manager)`, result);
      // Service status commands may exit non-zero for inactive units — that is information.
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
      "Tail a systemd unit's journal across a target; OpenRC hosts receive a precise logs-tail path instruction. " +
      "Read-only; enforces scopes.services. " +
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
      const managers = await resolveServiceManagers(servers, timeoutMs);
      // Validate every generated command before prompting for sudo.
      for (const s of servers) buildLogsCommand(normalized, lines ?? 50, managers.get(s.name)!);
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
      const result = await ctx.executor.runMapped(
        servers,
        (s) => buildLogsCommand(normalized, lines ?? 50, managers.get(s.name)!),
        { kind: "parallel" },
        { timeoutMs, sudo },
      );
      auditExecution("service-logs", `logs ${normalized} (per-host service manager)`, result);
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
      "execution with a circuit breaker for multi-host targets. Auto-detects systemd/OpenRC. " +
      "Pass sudo=true to run as root (sudo password from env; treated as privileged).",
    inputSchema: {
      target: z.union([z.string(), z.array(z.string())]).describe("Target expression"),
      unit: unitSchema,
      action: z.enum(["start", "stop", "restart", "reload"]),
      strategy: strategySchema.describe("rolling (default for multi-host) | parallel | serial"),
      sudo: z
        .boolean()
        .optional()
        .describe("Run the detected service command via sudo as root (password from FLOTILLA_*_SUDO_PASSWORD env)"),
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
      const managers = await resolveServiceManagers(servers, timeoutMs);
      const resolvedStrategy = parseStrategy(strategy, servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" });
      const changeSet = createChangeSet({
        tool: "service-control",
        summary: `${sudo ? "sudo " : ""}${action} ${normalized}`,
        targets: servers.map((candidate) => candidate.name),
        services: [normalized],
        operations: [`${sudo ? "privileged " : ""}${action} ${normalized}`, `strategy ${JSON.stringify(resolvedStrategy)}`],
        rollback: "operator-defined; service control has no automatic state rollback",
        risk: sudo ? "privileged" : "destructive",
      });

      const refusals: string[] = [];
      for (const s of servers) {
        const decision = decideChangeSet(changeSet, s, ctx.config.defaults.approvalMode);
        if (!decision.allowed) refusals.push(`${s.name}: ${decision.reason}`);
      }
      if (refusals.length > 0) {
        auditDenial("service-control", `${action} ${normalized}`, sudo ? "privileged" : "destructive", servers.map((s) => s.name), refusals.join("; "));
        return errorResult("Refused by policy (service-control):\n" + refusals.map((r) => `  - ${r}`).join("\n"));
      }
      const outcome = await gate(extra, {
        tool: "service-control",
        action: `change-set ${changeSet.id}: ${sudo ? "sudo " : ""}${action} ${normalized}`,
        commandClass: sudo ? "privileged (service-control, sudo)" : "destructive (service-control)",
        hosts: servers.map((s) => s.name),
        confirmFlag: confirm,
        changeSet,
      });
      if (outcome.kind === "refused") return errorResult(outcome.reason);

      // The human-approved change set replaces command-regex matching for this
      // tool-generated service command; path/service resource scopes were
      // already checked above and remain the authoritative boundary.
      const authorizedServers = servers.map((candidate) => ({
        ...candidate,
        scopes: candidate.scopes ? { ...candidate.scopes, commands: undefined } : undefined,
      }));
      const result = await ctx.executor.runMapped(
        authorizedServers,
        (s) => buildControlCommand(normalized, action as ServiceAction, managers.get(s.name)!),
        resolvedStrategy,
        { timeoutMs, sudo },
      );
      auditExecution("service-control", `${sudo ? "sudo " : ""}${action} ${normalized} (per-host service manager)`, result);
      const text = `change-set=${changeSet.id}\n${formatFanout(result)}`;
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
          const decision = decideForServer(command, s, ctx.config!.defaults.approvalMode);
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

    const checkPolicy = (command: string, s: ServerConfig) => {
      const decision = decideForServer(command, s, ctx.config!.defaults.approvalMode);
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
        const decision = decideForServer(command, s, ctx.config!.defaults.approvalMode);
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
  console.error(`flotilla-mcp v${MCP_VERSION} running on stdio (${ctx.registry ? `${ctx.registry.servers().length} servers configured` : "unconfigured"})`);

  let shutdownPromise: Promise<void> | undefined;
  const shutdown = () => {
    if (shutdownPromise) return shutdownPromise;
    shutdownPromise = (async () => {
      await Promise.allSettled([...retiringTransports]);
      await ctx.transport?.drainAndClose(ctx.config?.defaults.commandTimeoutMs ?? 30_000);
      await credentialBroker?.close();
      await localSecretBroker.close();
      process.exit(0);
    })();
    return shutdownPromise;
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
