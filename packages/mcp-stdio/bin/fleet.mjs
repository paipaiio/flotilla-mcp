#!/usr/bin/env node
/**
 * Flotilla CLI —— 绕过 MCP 直接调 core 引擎（npm 包内命令 "flotilla"）。
 *
 * 用法：
 *   flotilla list
 *   flotilla info
 *   flotilla credentials [target] [--repair]  # 批量诊断；repair 安全写入 OS Keychain
 *   flotilla resolve "<target>"
 *   flotilla exec-read "<target>" "<command>"
 *   flotilla exec "<target>" "<command>" [--strategy parallel|serial|rolling] [--confirm]
 *   flotilla classify "<command>"
 *   flotilla copy <source> <srcPath> <dest> <dstPath> [--confirm]
 *   flotilla sync <source> <srcDir> <dest> <dstDir> [--delete] [--apply] [--confirm]
 *   flotilla diff-file "<target>" <path>
 *   flotilla keychain set|check|delete <server> [--sudo]
 *   flotilla add <name> --host <ip> [--user u] [--auth key --key p] [--group g] ...
 *   flotilla add <name> --host <ip> --bootstrap   # 一次性密码首连装公钥，之后全走密钥
 *   flotilla pull-config [--url <https://...>] [--token-env VAR]
 *
 * 配置：--config <path> 或 FLOTILLA_CONFIG 环境变量。
 */
import {
  AuditLogger,
  Executor,
  FleetRegistry,
  SshTransport,
  analyzeDoctor,
  appendServerToConfig,
  bootstrapKey,
  buildControlCommand,
  buildDoctorScript,
  buildLogsCommand,
  buildServiceManagerProbeCommand,
  buildMetricsScript,
  buildSessionCaptureCommand,
  buildSessionKillCommand,
  buildSessionListCommand,
  buildSessionSendCommand,
  buildSessionStartCommand,
  buildServerToml,
  buildSignalCommand,
  buildStatusCommand,
  buildFileTailCommand,
  buildJournalTailCommand,
  buildChecksumCommand,
  buildPathKindProbe,
  checkRelayPolicy,
  checkServiceScope,
  classifyCommand,
  checkPathScope,
  decide,
  decideForServer,
  defaultConfigPath,
  diffFanout,
  filterTailOutput,
  formatDiff,
  formatDoctor,
  formatMetrics,
  formatRelay,
  formatSyncPlan,
  formatSyncResult,
  inspectFleetCredentials,
  loadFleetConfig,
  parseChecksums,
  parseMetrics,
  parsePathKind,
  parseSessionList,
  parseServiceManager,
  parseWorkflow,
  planSync,
  probeServer,
  pullConfigToFile,
  resolveAuditPath,
  defaultKeychainBackend,
  keychainAccount,
  relayFile,
  resolveTarget,
  runSyncPlan,
  validateSessionName,
  validateUnit,
  WorkflowRunner,
} from "flotilla-core";
import { readFileSync as readLocalFileSync } from "node:fs";
import { resolve as resolveLocalPath } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCredentialReport, buildRuntimeInfo } from "../dist/diagnostics.js";

const modulePath = fileURLToPath(import.meta.url);
const packageVersion = (() => {
  try {
    return JSON.parse(readLocalFileSync(new URL("../package.json", import.meta.url), "utf8")).version ?? "unknown";
  } catch {
    return "unknown";
  }
})();

const argv = process.argv.slice(2);
const flagIdx = argv.indexOf("--config");
const configPath = flagIdx >= 0 ? argv[flagIdx + 1] : undefined;
// flagIdx === -1 时不能把第一个参数当 --config 的值吃掉。
const args = flagIdx >= 0 ? argv.filter((_, i) => i !== flagIdx && i !== flagIdx + 1) : argv;
const [cmd, ...rest] = args;

function die(msg, code = 2) {
  console.error(`error: ${msg}`);
  process.exit(code);
}

/** 交互读取密码，回显为 *，不进 shell 历史（stdin 非 TTY 时直接读一行）。 */
async function promptHidden(query) {
  const readline = await import("node:readline");
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: process.stdin.isTTY === true });
    if (rl.terminal) {
      rl._writeToOutput = (s) => {
        if (s.includes(query)) process.stdout.write(s);
        else if (s === "\n" || s === "\r\n") process.stdout.write(s);
        else process.stdout.write("*");
      };
    }
    rl.question(query, (answer) => {
      rl.close();
      process.stdout.write("\n");
      resolve(answer);
    });
  });
}

function formatFanout(result) {
  const { summary } = result;
  const lines = [
    `\nstrategy=${summary.strategy} total=${summary.total} succeeded=${summary.succeeded} failed=${summary.failed} skipped=${summary.skipped}${summary.halted ? " HALTED(circuit-breaker)" : ""}\n`,
  ];
  for (const r of result.results) {
    const status = r.skipped ? "SKIP" : r.ok ? "OK  " : "FAIL";
    lines.push(`── ${status} ${r.host} (exit=${r.exitCode ?? "-"}, ${r.durationMs}ms)`);
    if (r.error) lines.push(`   error: ${r.error}`);
    if (r.stdout) lines.push(r.stdout.trimEnd());
    if (r.stderr) lines.push(`   stderr: ${r.stderr.trimEnd()}`);
  }
  return lines.join("\n");
}

let config;
let configLoadError;
let activeTransport;
try {
  config = loadFleetConfig(configPath);
} catch (err) {
  configLoadError = err instanceof Error ? err.message : String(err);
}

async function main() {
  // 本地配置缺失时只有 pull-config（--url bootstrap）能继续。
  const registry = config ? new FleetRegistry(config) : undefined;
  const transport = config
    ? new SshTransport(new Map(config.servers.map((s) => [s.name, s])), {
        idleReapMs: config.defaults.idleReapMs,
        strictAlgorithms: config.defaults.strictAlgorithms,
        maxSshOutputBytes: config.defaults.maxSshOutputBytes,
      })
    : undefined;
  activeTransport = transport;
  const executor = config ? new Executor(transport, config.defaults) : undefined;
  const effectivePath = resolveLocalPath(configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
  const auditLog = config
    ? new AuditLogger(resolveAuditPath(effectivePath, config.audit?.path), {
        hashChain: config.audit?.hashChain ?? true,
        entropyScan: config.audit?.entropyScan ?? false,
      })
    : undefined;

  /** CLI 侧审计：操作者本人，approver 记为 "cli"。 */
  function audit(event) {
    try {
      auditLog?.log(event);
    } catch {
      /* 审计失败不阻断操作 */
    }
  }

  async function serviceManagersFor(servers) {
    const managers = new Map();
    const auto = [];
    for (const server of servers) {
      const configured = server.serviceManager ?? "auto";
      if (configured === "auto") auto.push(server);
      else managers.set(server.name, configured);
    }
    if (auto.length > 0) {
      const probes = await executor.run(auto, buildServiceManagerProbeCommand(), { kind: "parallel" });
      for (const result of probes.results) {
        if (!result.ok) die(`服务管理器探测失败 ${result.host}: ${result.error ?? result.stderr.trim()}`, 1);
        try {
          managers.set(result.host, parseServiceManager(result.stdout));
        } catch (err) {
          die(`${result.host}: ${err instanceof Error ? err.message : String(err)}`, 1);
        }
      }
    }
    return managers;
  }

  if (cmd === "pull-config") {
    const { resolve } = await import("node:path");
    const dest = resolve(configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
    const urlIdx = rest.indexOf("--url");
    const urlOverride = urlIdx >= 0 ? rest[urlIdx + 1] : undefined;
    const tokenIdx = rest.indexOf("--token-env");
    const tokenEnv = tokenIdx >= 0 ? rest[tokenIdx + 1] : undefined;
    const remote = urlOverride
      ? { url: urlOverride, tokenEnv }
      : config?.remote ?? die(`本地没有 [remote] 配置，也没有 --url。${configLoadError ?? ""}`, 2);

    console.log(`拉取 ${remote.url} ...`);
    try {
      const result = await pullConfigToFile(remote, dest);
      console.log(`已写入 ${dest}（${result.bytes} 字节，0600）`);
      if (result.backupPath) console.log(`旧配置备份: ${result.backupPath}`);
      console.log(`服务器 ${result.servers.length} 台: ${result.servers.join(", ") || "(无)"}`);
      audit({
        kind: "execution", tool: "config-pull", command: `pull ${remote.url}`,
        outcome: "ok", reason: `-> ${dest}`,
      });
    } catch (err) {
      die(`拉取失败，本地配置未动: ${err instanceof Error ? err.message : String(err)}`, 1);
    }
    return;
  }

  if (!config) die(configLoadError);

  switch (cmd) {
    case "info": {
      const backend = await defaultKeychainBackend();
      console.log(JSON.stringify(buildRuntimeInfo({
        version: packageVersion,
        modulePath,
        execPath: process.execPath,
        cwd: process.cwd(),
        configPath: effectivePath,
        configSource: configPath ? "argument" : process.env.FLOTILLA_CONFIG ? "environment" : "platform-default",
        configuredServers: registry.servers().length,
        keychainAvailable: backend !== null,
      }), null, 2));
      break;
    }

    case "credentials": {
      const target = rest.find((arg) => !arg.startsWith("--")) ?? "all";
      const servers = resolveTarget(registry, target);
      let statuses = await inspectFleetCredentials(servers);
      if (rest.includes("--repair")) {
        const backend = await defaultKeychainBackend();
        if (!backend) die("本机 OS Keychain 后端当前不可用", 1);
        const repairable = statuses.filter((status) => !status.ready && status.auth === "password");
        for (const status of repairable) {
          const password = await promptHidden(`输入 ${status.server} 的登录密码（直接存入 OS Keychain）: `);
          if (!password) {
            console.error(`跳过 ${status.server}: 输入为空`);
            continue;
          }
          await backend.set(keychainAccount(status.server, false), password);
          console.error(`✓ ${status.server}: 已存入 OS Keychain，可直接重试，无需重启 MCP`);
        }
        statuses = await inspectFleetCredentials(servers, { keychain: backend });
      }
      const report = buildCredentialReport(statuses);
      console.log(JSON.stringify(report, null, 2));
      if (report.summary.missing > 0) process.exitCode = 1;
      break;
    }

    case "list": {
      for (const s of registry.servers()) {
        console.log(
          `${s.name}\t${s.user}@${s.host}:${s.port}\ttier=${s.group}\trole=${s.role}${s.readOnly ? "\treadOnly" : ""}${s.via ? `\tvia=${s.via}` : ""}\ttags=[${s.tags.join(",")}]`,
        );
      }
      const groups = registry.groups();
      if (groups.length) {
        console.log("\ngroups:");
        for (const g of groups) console.log(`  ${g.name}\t${JSON.stringify(g.match)}`);
      }
      break;
    }

    case "resolve": {
      const target = rest[0] ?? die("resolve 需要 target 表达式");
      const servers = resolveTarget(registry, target);
      console.log(`target "${target}" 命中 ${servers.length} 台:`);
      for (const s of servers) console.log(`  ${s.name} (${s.host}, tier=${s.group}, role=${s.role})`);
      break;
    }

    case "classify": {
      const command = rest[0] ?? die("classify 需要命令");
      console.log(`${command}  →  ${classifyCommand(command)}`);
      break;
    }

    case "diff": {
      const target = rest[0] ?? die("diff 需要 target 和 command");
      const command = rest[1] ?? die("diff 需要 command");
      const cls = classifyCommand(command);
      if (cls !== "read-only") {
        die(`fleet-diff 只跑只读命令；"${command}" 分类为 ${cls}`);
      }
      const servers = resolveTarget(registry, target);
      console.log(`比对 ${servers.length} 台: ${servers.map((s) => s.name).join(", ")}`);
      const fanout = await executor.run(servers, command, { kind: "parallel" });
      const report = diffFanout(fanout);
      console.log(formatDiff(report));
      process.exitCode = report.consistent ? 0 : 1;
      break;
    }

    case "service": {
      // service <target> <unit> <status|logs|start|stop|restart|reload> [--lines N] [--strategy S] [--confirm]
      const target = rest[0] ?? die("service 需要 target、unit、action");
      const rawUnit = rest[1] ?? die("service 需要 unit");
      const action = rest[2] ?? die("service 需要 action: status|logs|start|stop|restart|reload");
      const linesIdx = rest.indexOf("--lines");
      const lines = linesIdx >= 0 ? Number(rest[linesIdx + 1]) : 50;
      const confirm = rest.includes("--confirm");
      const sudo = rest.includes("--sudo");
      const stratIdx = rest.indexOf("--strategy");
      const stratName = stratIdx >= 0 ? rest[stratIdx + 1] : undefined;

      let unit;
      try {
        unit = validateUnit(rawUnit);
      } catch (err) {
        die(err instanceof Error ? err.message : String(err));
      }
      const servers = resolveTarget(registry, target);
      const managers = await serviceManagersFor(servers);
      const commandFor = (server) => {
        const manager = managers.get(server.name);
        if (action === "status") return buildStatusCommand(unit, manager);
        if (action === "logs") return buildLogsCommand(unit, lines, manager);
        if (["start", "stop", "restart", "reload"].includes(action)) return buildControlCommand(unit, action, manager);
        return die(`未知 action: ${action}`);
      };
      // Build all commands up front so unsupported combinations fail before policy/approval.
      for (const s of servers) commandFor(s);
      const cls = sudo ? "privileged" : action === "status" || action === "logs" ? "read-only" : "destructive";
      const refusals = [];
      for (const s of servers) {
        const command = commandFor(s);
        const policyCommand = sudo ? `sudo ${command}` : command;
        const scopeReason = checkServiceScope(s, unit);
        if (scopeReason) refusals.push(`  - ${scopeReason}`);
        const d = decideForServer(policyCommand, s, config.defaults.approvalMode);
        if (!d.allowed) refusals.push(`  - ${s.name}: ${d.reason}`);
      }
      if (refusals.length) die(`策略拒绝:\n${refusals.join("\n")}`, 1);
      if ((cls === "destructive" || sudo) && !confirm) {
        die(`需要审批: "${action} ${unit}" 是 ${cls}${sudo ? "（sudo 提权）" : ""}。确认后加 --confirm 重跑。`, 1);
      }

      let strategy;
      if (stratName) strategy = { kind: stratName, stopOnError: true };
      else strategy = cls === "destructive" && servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" };

      console.log(`${sudo ? "sudo " : ""}${action} ${unit}  命中 ${servers.length} 台  策略=${strategy.kind}`);
      const result = await executor.runMapped(servers, commandFor, strategy, { sudo });
      audit({
        kind: "execution", tool: `service:${action}`, command: `${sudo ? "sudo " : ""}${action} ${unit} (per-host service manager)`,
        hosts: servers.map((s) => s.name),
        outcome: result.summary.failed > 0 ? "failed" : "ok",
        approver: confirm ? "cli" : undefined,
        results: result.summary,
      });
      console.log(formatFanout(result));
      process.exitCode = result.summary.failed > 0 && action !== "status" ? 1 : 0;
      break;
    }

    case "metrics":
    case "doctor": {
      const target = rest[0] ?? die(`${cmd} 需要 target`);
      const servers = resolveTarget(registry, target);
      const script = cmd === "doctor" ? buildDoctorScript() : buildMetricsScript();
      const fanout = await executor.run(servers, script, { kind: "parallel" });
      if (cmd === "metrics") {
        console.log(`metrics-snapshot: ${fanout.summary.succeeded}/${fanout.summary.total} hosts OK\n`);
        for (const r of fanout.results) {
          console.log(r.ok ? formatMetrics(parseMetrics(r.host, r.stdout)) : `── FAIL ${r.host}: ${r.error ?? r.stderr.trim()}`);
        }
      } else {
        let crits = 0, warns = 0, healthy = 0;
        const blocks = [];
        for (const r of fanout.results) {
          if (r.ok) {
            const m = parseMetrics(r.host, r.stdout);
            const issues = analyzeDoctor(m);
            if (issues.some((i) => i.severity === "crit")) crits++;
            else if (issues.length > 0) warns++;
            else healthy++;
            blocks.push(formatDoctor(r.host, m, issues));
          } else {
            warns++;
            blocks.push(`── WARN ${r.host}: probe failed — ${r.error ?? r.stderr.trim()}`);
          }
        }
        console.log(`doctor: ${servers.length} hosts — ${healthy} healthy, ${warns} warn, ${crits} crit\n`);
        console.log(blocks.join("\n\n"));
        process.exitCode = crits > 0 ? 1 : 0;
      }
      break;
    }

    case "push": {
      const target = rest[0] ?? die("push 需要 target、localPath、remotePath");
      const localPath = rest[1] ?? die("push 需要 localPath");
      const remotePath = rest[2] ?? die("push 需要 remotePath");
      const confirm = rest.includes("--confirm");
      const stratIdx = rest.indexOf("--strategy");
      const stratName = stratIdx >= 0 ? rest[stratIdx + 1] : undefined;

      const servers = resolveTarget(registry, target);
      console.log(`推送 ${servers.length} 台: ${servers.map((s) => s.name).join(", ")}`);

      const refusals = [];
      for (const s of servers) {
        if (s.readOnly) refusals.push(`  - ${s.name}: readOnly 服务器`);
        const scopeReason = checkPathScope(s, remotePath);
        if (scopeReason) refusals.push(`  - ${scopeReason}`);
        const d = decide("rm -rf <upload-overwrite>", {
          role: s.role,
          tier: s.group,
          readOnly: s.readOnly,
          approvalMode: config.defaults.approvalMode,
        });
        if (!d.allowed) refusals.push(`  - ${s.name}: ${d.reason}`);
      }
      if (refusals.length) die(`策略拒绝 (upload):\n${refusals.join("\n")}`, 1);
      if (!confirm) {
        die(`需要审批: 上传 "${localPath}" -> "${remotePath}" 会覆盖 ${servers.length} 台机器上的文件。确认后加 --confirm 重跑。`, 1);
      }

      let strategy;
      if (stratName === "serial") strategy = { kind: "serial", stopOnError: true };
      else if (stratName === "parallel") strategy = { kind: "parallel" };
      else if (stratName === "rolling") strategy = { kind: "rolling" };
      else strategy = servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" };

      console.log(`策略=${strategy.kind}  已确认(--confirm)`);
      const result = await executor.push(servers, localPath, remotePath, strategy);
      audit({
        kind: "execution", tool: "fleet-push", command: `upload ${localPath} -> ${remotePath}`,
        hosts: servers.map((s) => s.name),
        outcome: result.summary.failed > 0 ? "failed" : "ok",
        approver: "cli",
        results: result.summary,
      });
      const { summary } = result;
      console.log(`\nstrategy=${summary.strategy} total=${summary.total} succeeded=${summary.succeeded} failed=${summary.failed} skipped=${summary.skipped}${summary.halted ? " HALTED(circuit-breaker)" : ""}\n`);
      for (const r of result.results) {
        console.log(
          r.skipped
            ? `── SKIP ${r.host}: ${r.error}`
            : r.ok
              ? `── OK   ${r.host}: ${r.bytes} bytes in ${r.durationMs}ms`
              : `── FAIL ${r.host}: ${r.error}`,
        );
      }
      process.exitCode = summary.failed > 0 ? 1 : 0;
      break;
    }

    case "session": {
      // session list <target>
      // session start <target> <name> [--cmd "<command>"] [--workdir <dir>] [--confirm]
      // session output <target> <name> [--lines N]
      // session send <target> <name> "<text>" --confirm
      // session kill <target> <name> --confirm
      const sub = rest[0] ?? die("session 需要子命令: list|start|output|send|kill");

      if (sub === "list") {
        const target = rest[1] ?? die("session list 需要 target");
        const servers = resolveTarget(registry, target);
        const fanout = await executor.run(servers, buildSessionListCommand(), { kind: "parallel" });
        let total = 0;
        for (const r of fanout.results) {
          if (!r.ok) {
            console.log(`── FAIL ${r.host}: ${r.error ?? r.stderr.trim()}`);
            continue;
          }
          const sessions = parseSessionList(r.host, r.stdout);
          total += sessions.length;
          if (sessions.length === 0) console.log(`── ${r.host}: 无会话`);
          for (const s of sessions) {
            console.log(`── ${r.host}  ${s.name}  created=${s.createdAt}  windows=${s.windows}${s.attached ? "  [attached]" : ""}`);
          }
        }
        console.log(`\n共 ${total} 个会话 / ${fanout.results.length} 台主机`);
        break;
      }

      const target = rest[1] ?? die(`session ${sub} 需要 target 和 name`);
      const rawName = rest[2] ?? die(`session ${sub} 需要 name`);
      let fullName;
      try {
        fullName = validateSessionName(rawName);
      } catch (err) {
        die(err instanceof Error ? err.message : String(err));
      }
      const servers = resolveTarget(registry, target);
      const confirm = rest.includes("--confirm");

      if (sub === "start") {
        const cmdIdx = rest.indexOf("--cmd");
        const command = cmdIdx >= 0 ? rest[cmdIdx + 1] : undefined;
        const wdIdx = rest.indexOf("--workdir");
        const workdir = wdIdx >= 0 ? rest[wdIdx + 1] : undefined;
        if (command) {
          const cls = classifyCommand(command);
          const refusals = [];
          let needsApproval = false;
          for (const s of servers) {
            const d = decideForServer(command, s, config.defaults.approvalMode);
            if (!d.allowed) refusals.push(`  - ${s.name}: ${d.reason}`);
            needsApproval = needsApproval || d.needsApproval;
          }
          if (refusals.length) die(`策略拒绝 (${cls}, session-start):\n${refusals.join("\n")}`, 1);
          if (needsApproval && !confirm) {
            die(`需要审批: 会话 "${rawName}" 将运行 ${cls} 命令 "${command}"。确认后加 --confirm 重跑。`, 1);
          }
        }
        console.log(`启动会话 "${rawName}"  命中 ${servers.length} 台${command ? `  命令: ${command}` : ""}`);
        const result = await executor.run(servers, buildSessionStartCommand(fullName, { workdir, command }), { kind: "parallel" });
        audit({
          kind: "execution", tool: "session-start", command: command ?? "(idle shell)",
          hosts: servers.map((s) => s.name),
          outcome: result.summary.failed > 0 ? "failed" : "ok",
          results: result.summary,
        });
        console.log(formatFanout(result));
        process.exitCode = result.summary.failed > 0 ? 1 : 0;
      } else if (sub === "output") {
        const linesIdx = rest.indexOf("--lines");
        const lines = linesIdx >= 0 ? Number(rest[linesIdx + 1]) : 100;
        const result = await executor.run(servers, buildSessionCaptureCommand(fullName, lines), { kind: "parallel" });
        console.log(formatFanout(result));
        process.exitCode = result.summary.failed > 0 ? 1 : 0;
      } else if (sub === "send") {
        const text = rest[3];
        if (!text) die(`session send 需要文本: session send <target> <name> "<text>" --confirm`);
        if (classifyCommand(text) === "forbidden") die(`策略拒绝: 文本命中 never-allowed 列表`, 1);
        if (!confirm) die(`需要审批: 将向会话 "${rawName}" 注入输入 "${text}"。确认后加 --confirm 重跑。`, 1);
        const result = await executor.run(servers, buildSessionSendCommand(fullName, text), { kind: "parallel" });
        audit({
          kind: "execution", tool: "session-send", command: `session ${rawName} <- input`,
          hosts: servers.map((s) => s.name),
          outcome: result.summary.failed > 0 ? "failed" : "ok",
          approver: "cli",
          results: result.summary,
        });
        console.log(formatFanout(result));
        process.exitCode = result.summary.failed > 0 ? 1 : 0;
      } else if (sub === "kill") {
        if (!confirm) die(`需要审批: 将杀掉会话 "${rawName}" 及其中运行的进程。确认后加 --confirm 重跑。`, 1);
        const result = await executor.run(servers, buildSessionKillCommand(fullName), { kind: "parallel" });
        audit({
          kind: "execution", tool: "session-kill", command: `kill session ${rawName}`,
          hosts: servers.map((s) => s.name),
          outcome: result.summary.failed > 0 ? "failed" : "ok",
          approver: "cli",
          results: result.summary,
        });
        console.log(formatFanout(result));
        process.exitCode = result.summary.failed > 0 ? 1 : 0;
      } else {
        die(`未知 session 子命令: ${sub}`);
      }
      break;
    }

    case "workflow": {
      // workflow <file.yaml> [--confirm] [--plan]
      const file = rest[0] ?? die("workflow 需要 YAML 文件路径");
      const confirm = rest.includes("--confirm");
      const planOnly = rest.includes("--plan");

      const { readFileSync } = await import("node:fs");
      let def;
      try {
        def = parseWorkflow(readFileSync(file, "utf8"));
      } catch (err) {
        die(err instanceof Error ? err.message : String(err));
      }

      const checkPolicy = (command, s) => {
        const d = decideForServer(command, s, config.defaults.approvalMode);
        return d.allowed ? null : (d.reason ?? "refused");
      };
      const runner = new WorkflowRunner(registry, executor, config.defaults, checkPolicy);

      const plan = runner.plan(def);
      console.log(`workflow "${def.name}" 计划 (${def.steps.length} 步):`);
      for (const p of plan) {
        console.log(
          `  ${p.step.name}  [${p.step.type} → ${p.step.target}]  class=${p.commandClass}${p.needsApproval ? "  需审批" : ""}${p.step.onError ? `  onError=${p.step.onError}` : ""}`,
        );
        for (const r of p.refusals) console.log(`    ✗ ${r}`);
      }
      const planRefusals = plan.flatMap((p) => p.refusals);
      if (planRefusals.length) die(`工作流被策略拒绝（${planRefusals.length} 条），未执行`, 1);
      if (planOnly) break;
      const gated = plan.filter((p) => p.needsApproval);
      if (gated.length > 0 && !confirm) {
        die(`需要审批: ${gated.length} 个步骤（${gated.map((p) => p.step.name).join(", ")}）。确认计划后加 --confirm 重跑。`, 1);
      }

      const result = await runner.run(def);
      audit({
        kind: "execution", tool: "workflow-run", command: `workflow "${def.name}" (${def.steps.length} steps)`,
        outcome: result.ok ? "ok" : "failed",
        approver: gated.length > 0 ? "cli" : undefined,
        reason: result.haltedAt ? `halted at ${result.haltedAt}${result.rolledBack ? ", rolled back" : ""}` : undefined,
      });
      console.log(
        `\n结果: ${result.ok ? "OK" : "FAILED"}${result.halted ? `（在 "${result.haltedAt}" 中止）` : ""}${result.rolledBack ? " 已回滚" : ""}\n`,
      );
      for (const s of result.steps) {
        const summary = s.fanout?.summary;
        const detail = summary
          ? `total=${summary.total} ok=${summary.succeeded} fail=${summary.failed}${summary.halted ? " HALTED" : ""}`
          : (s.error ?? "");
        console.log(`── ${s.ok ? "OK  " : "FAIL"} ${s.name}  ${detail}`);
        if (!s.ok && s.fanout) {
          for (const r of s.fanout.results.filter((x) => !x.ok && !x.skipped)) {
            console.log(`     ${r.host}: ${r.error ?? r.stderr.trim()}`);
          }
        }
      }
      process.exitCode = result.ok ? 0 : 1;
      break;
    }

    case "logs-tail": {
      // logs-tail <target> (--unit <unit> | --file <path>) [--seconds N] [--grep RE] [--sudo] [--confirm]
      const target = rest[0] ?? die("logs-tail 需要 target 和 --unit/--file");
      const unitIdx = rest.indexOf("--unit");
      const fileIdx = rest.indexOf("--file");
      const unit = unitIdx >= 0 ? rest[unitIdx + 1] : undefined;
      const file = fileIdx >= 0 ? rest[fileIdx + 1] : undefined;
      if (!unit && !file) die("logs-tail 需要 --unit <unit> 或 --file <path>");
      if (unit && file) die("--unit 和 --file 二选一");
      const secIdx = rest.indexOf("--seconds");
      const seconds = secIdx >= 0 ? Number(rest[secIdx + 1]) : 30;
      const grepIdx = rest.indexOf("--grep");
      const grep = grepIdx >= 0 ? rest[grepIdx + 1] : undefined;
      const sudo = rest.includes("--sudo");
      const confirm = rest.includes("--confirm");

      let command;
      try {
        if (unit) command = buildJournalTailCommand(validateUnit(unit), seconds, { sudo });
        else command = buildFileTailCommand(file, seconds);
      } catch (err) {
        die(err instanceof Error ? err.message : String(err));
      }

      const servers = resolveTarget(registry, target);
      const cls = classifyCommand(command);
      const refusals = [];
      for (const s of servers) {
        const d = decideForServer(command, s, config.defaults.approvalMode);
        if (!d.allowed) refusals.push(`  - ${s.name}: ${d.reason}`);
        if (unit) {
          const scope = checkServiceScope(s, validateUnit(unit));
          if (scope) refusals.push(`  - ${scope}`);
        } else {
          const scope = checkPathScope(s, file);
          if (scope) refusals.push(`  - ${scope}`);
        }
      }
      if (refusals.length) die(`策略拒绝 (${cls}, logs-tail):\n${refusals.join("\n")}`, 1);
      if (cls === "privileged" && !confirm) {
        die(`需要审批: sudo tail 将持续 ${seconds}s。确认后加 --confirm 重跑。`, 1);
      }

      console.log(`跟踪 ${seconds}s  命中 ${servers.length} 台${grep ? `  过滤 /${grep}/` : ""} ...`);
      const fanout = await executor.run(servers, command, { kind: "parallel" }, { timeoutMs: seconds * 1000 + 15000 });
      for (const r of fanout.results) {
        if (!r.ok) {
          console.log(`── FAIL ${r.host}: ${r.error ?? r.stderr.trim()}`);
          continue;
        }
        const filtered = filterTailOutput(r.stdout, grep);
        if (filtered.grepError) die(filtered.grepError);
        console.log(`── ${r.host}: ${filtered.matched}/${filtered.total} 行${grep ? `（匹配 /${grep}/）` : ""}`);
        for (const l of filtered.lines.slice(0, 200)) console.log(`   ${l}`);
        if (filtered.lines.length > 200) console.log(`   ... 还有 ${filtered.lines.length - 200} 行`);
      }
      process.exitCode = fanout.summary.failed > 0 ? 1 : 0;
      break;
    }

    case "add": {
      // add <name> --host <ip> [--user u] [--port N] [--auth agent|key|password] [--key path]
      //      [--group g] [--role viewer|operator|admin] [--tags a,b] [--read-only] [--via bastion]
      //      [--bootstrap] 一次性密码首连 → 安装公钥 → 之后全走密钥（密码可用
      //      FLOTILLA_BOOTSTRAP_PASSWORD 提供，否则交互隐藏输入；仅 CLI，不经 MCP）
      const name = rest[0] ?? die("add 需要服务器名称");
      const get = (flag) => {
        const i = rest.indexOf(flag);
        return i >= 0 ? rest[i + 1] : undefined;
      };
      const host = get("--host") ?? die("add 需要 --host");
      const bootstrap = rest.includes("--bootstrap");
      const auth = bootstrap ? "key" : (get("--auth") ?? (get("--key") ? "key" : "agent"));
      const newServer = {
        name,
        host,
        port: get("--port") ? Number(get("--port")) : 22,
        user: get("--user") ?? "root",
        auth,
        keyRef: get("--key"),
        group: get("--group") ?? "dev",
        tags: get("--tags") ? get("--tags").split(",") : [],
        role: get("--role") ?? "operator",
        readOnly: rest.includes("--read-only"),
        via: get("--via"),
      };
      if (!["viewer", "operator", "admin"].includes(newServer.role)) die(`未知 role: ${newServer.role}`);
      if (!["agent", "key", "password"].includes(newServer.auth)) die(`未知 auth: ${newServer.auth}`);
      if (newServer.auth === "key" && !newServer.keyRef && !bootstrap) die(`auth=key 需要 --key <path>（或 --bootstrap 自动生成舰队密钥）`);

      const { readFileSync, writeFileSync, chmodSync, existsSync } = await import("node:fs");
      const { resolve, dirname, join } = await import("node:path");
      const cfgPath = resolve(configPath ?? process.env.FLOTILLA_CONFIG ?? "config.toml");

      if (bootstrap) {
        const { execFileSync } = await import("node:child_process");
        const { homedir } = await import("node:os");
        const expand = (p) => p.replace(/^~(?=$|\/)/, homedir());
        // 公钥来源：--key 指定的私钥，或舰队专用密钥（不存在则生成）
        let keyPath = newServer.keyRef ? expand(newServer.keyRef) : join(dirname(cfgPath), "fleet_ed25519");
        if (!newServer.keyRef && !existsSync(keyPath)) {
          console.log(`生成舰队专用密钥 ${keyPath} ...`);
          execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "flotilla-fleet", "-f", keyPath], { stdio: ["ignore", "ignore", "inherit"] });
          chmodSync(keyPath, 0o600);
        }
        if (!existsSync(keyPath)) die(`私钥不存在: ${keyPath}`, 1);
        const publicKey = execFileSync("ssh-keygen", ["-y", "-f", keyPath], { encoding: "utf8" }).trim();
        newServer.keyRef = newServer.keyRef ?? keyPath;

        const password = process.env.FLOTILLA_BOOTSTRAP_PASSWORD ??
          (await promptHidden(`输入 ${newServer.user}@${host}:${newServer.port} 的一次性登录密码: `));
        if (!password) die("空密码，未执行", 1);

        console.log(`bootstrap ${newServer.user}@${host}:${newServer.port}（密码首连 → 安装公钥）...`);
        const boot = await bootstrapKey(newServer, password, publicKey);
        if (!boot.ok) {
          audit({ kind: "execution", tool: "fleet-bootstrap", command: `bootstrap ${name} (${newServer.user}@${host}:${newServer.port})`, hosts: [name], outcome: "error", approver: "cli" });
          die(`bootstrap 失败: ${boot.error}`, 1);
        }
        console.log(`  公钥已安装  hostname=${boot.hostname}  uid=${boot.uid}`);
        console.log(`  host key: ${boot.hostKey ?? "未捕获"}`);
        audit({ kind: "execution", tool: "fleet-bootstrap", command: `bootstrap ${name} (${newServer.user}@${host}:${newServer.port})`, hosts: [name], outcome: "ok", approver: "cli" });
        // 继续走下面的 probe：装上了不代表 sshd 允许密钥登录，必须验证
      }

      console.log(`探测 ${newServer.user}@${host}:${newServer.port}${bootstrap ? "（密钥认证验证）" : ""} ...`);
      const probe = await probeServer(newServer);
      if (!probe.ok) {
        die(bootstrap
          ? `公钥已安装但密钥认证失败: ${probe.error}——检查目标机 sshd 的 PubkeyAuthentication / PermitRootLogin`
          : `连接失败: ${probe.error}`, 1);
      }
      console.log(`  hostname=${probe.hostname}  uid=${probe.uid}  tmux=${probe.tmux ? "✓" : "✗（会话功能不可用）"}`);
      console.log(`  host key: ${probe.hostKey ?? "未捕获"}`);
      if (probe.uid === 0) console.log("  ⚠ 该用户是 root——强烈建议换低权限账户 + sudoers 白名单");

      const text = readFileSync(cfgPath, "utf8");
      const pinned = { ...newServer, trustedHostKey: probe.hostKey };
      let next;
      try {
        next = appendServerToConfig(text, pinned);
      } catch (err) {
        die(err instanceof Error ? err.message : String(err), 1);
      }
      writeFileSync(cfgPath, next, "utf8");
      chmodSync(cfgPath, 0o600);
      console.log(`\n已追加到 ${cfgPath}（host key 已钉死）：`);
      console.log(buildServerToml(pinned));
      console.log("提示：运行中的 MCP server 会自动热重载这份配置（fs.watch），新机器即刻可用。");
      break;
    }

    case "pull": {
      // pull <target> <remotePath> <localPath> [--strategy S]
      const target = rest[0] ?? die("pull 需要 target、remotePath、localPath");
      const remotePath = rest[1] ?? die("pull 需要 remotePath");
      const localPath = rest[2] ?? die("pull 需要 localPath（多机自动加 -<host> 后缀，可用 {host} 占位）");
      const stratIdx = rest.indexOf("--strategy");
      const stratName = stratIdx >= 0 ? rest[stratIdx + 1] : undefined;

      const servers = resolveTarget(registry, target);
      const refusals = [];
      for (const s of servers) {
        const scopeReason = checkPathScope(s, remotePath);
        if (scopeReason) refusals.push(`  - ${scopeReason}`);
      }
      if (refusals.length) die(`策略拒绝 (download):\n${refusals.join("\n")}`, 1);

      const strategy = stratName ? { kind: stratName } : { kind: "parallel" };
      console.log(`下载 ${servers.length} 台: ${servers.map((s) => s.name).join(", ")}`);
      const result = await executor.pull(servers, remotePath, localPath, strategy);
      audit({
        kind: "execution", tool: "fleet-pull", command: `download ${remotePath}`,
        hosts: servers.map((s) => s.name),
        outcome: result.summary.failed > 0 ? "failed" : "ok",
        results: result.summary,
      });
      for (const r of result.results) {
        console.log(
          r.skipped ? `── SKIP ${r.host}: ${r.error}`
          : r.ok ? `── OK   ${r.host}: ${r.bytes} bytes in ${r.durationMs}ms`
          : `── FAIL ${r.host}: ${r.error}`,
        );
      }
      process.exitCode = result.summary.failed > 0 ? 1 : 0;
      break;
    }

    case "copy": {
      // copy <source> <sourcePath> <dest> <destPath> [--confirm]
      // A→B 文件中转：经控制机内存流式转发，服务器之间不需要互通或互加密钥。
      const source = rest[0] ?? die("copy 需要 source、sourcePath、dest、destPath");
      const sourcePath = rest[1] ?? die("copy 需要 sourcePath");
      const dest = rest[2] ?? die("copy 需要 dest");
      const destPath = rest[3] ?? die("copy 需要 destPath");
      const confirm = rest.includes("--confirm");

      const srcs = resolveTarget(registry, source);
      const dsts = resolveTarget(registry, dest);
      if (srcs.length !== 1) die(`source 必须命中恰好 1 台；"${source}" 命中 ${srcs.length} 台`);
      if (dsts.length !== 1) die(`dest 必须命中恰好 1 台；"${dest}" 命中 ${dsts.length} 台`);
      const src = srcs[0];
      const dst = dsts[0];

      const policy = checkRelayPolicy(src, sourcePath, dst, destPath, config.defaults.approvalMode);
      if (policy.refusals.length) {
        audit({ kind: "decision", tool: "fleet-copy", command: `relay ${source}:${sourcePath} -> ${dest}:${destPath}`, commandClass: "destructive (relay)", hosts: [src.name, dst.name], outcome: "deny", reason: policy.refusals.join("; ") });
        die(`策略拒绝 (relay):\n${policy.refusals.map((r) => `  - ${r}`).join("\n")}`, 1);
      }
      if (!confirm) {
        die(`需要审批: 中转 "${source}:${sourcePath}" -> "${dest}:${destPath}"（覆盖目标文件${policy.crossTier ? "，跨 tier" : ""}）。确认后加 --confirm 重跑。`, 1);
      }

      console.log(`中转 ${source}:${sourcePath} -> ${dest}:${destPath}  已确认(--confirm)`);
      const result = await relayFile(transport, src, sourcePath, dst, destPath);
      audit({
        kind: "execution", tool: "fleet-copy", command: `relay ${source}:${sourcePath} -> ${dest}:${destPath}`,
        hosts: [src.name, dst.name], outcome: result.ok ? "ok" : "failed", approver: "cli",
        results: { total: 1, succeeded: result.ok ? 1 : 0, failed: result.ok ? 0 : 1, skipped: 0 },
      });
      console.log(formatRelay(result));
      process.exitCode = result.ok ? 0 : 1;
      break;
    }

    case "sync": {
      // sync <source> <sourceDir> <dest> <destDir> [--delete] [--apply] [--confirm]
      // 目录级同步（rsync 语义，中转模式）。默认 dry-run 只出计划；--apply 才落地。
      const source = rest[0] ?? die("sync 需要 source、sourceDir、dest、destDir");
      const sourceDir = rest[1] ?? die("sync 需要 sourceDir");
      const dest = rest[2] ?? die("sync 需要 dest");
      const destDir = rest[3] ?? die("sync 需要 destDir");
      const del = rest.includes("--delete");
      const apply = rest.includes("--apply");
      const confirm = rest.includes("--confirm");

      const srcs = resolveTarget(registry, source);
      const dsts = resolveTarget(registry, dest);
      if (srcs.length !== 1) die(`source 必须命中恰好 1 台；"${source}" 命中 ${srcs.length} 台`);
      if (dsts.length !== 1) die(`dest 必须命中恰好 1 台；"${dest}" 命中 ${dsts.length} 台`);
      const src = srcs[0];
      const dst = dsts[0];

      const action = `sync ${source}:${sourceDir} -> ${dest}:${destDir}${del ? " --delete" : ""}`;
      const policy = checkRelayPolicy(src, sourceDir, dst, destDir, config.defaults.approvalMode);
      if (policy.refusals.length) {
        audit({ kind: "decision", tool: "fleet-sync", command: action, commandClass: "destructive (sync)", hosts: [src.name, dst.name], outcome: "deny", reason: policy.refusals.join("; ") });
        die(`策略拒绝 (sync):\n${policy.refusals.map((r) => `  - ${r}`).join("\n")}`, 1);
      }

      const probeSrc = await executor.run([src], buildPathKindProbe(sourceDir), { kind: "parallel" });
      const srcKind = probeSrc.results[0]?.ok ? parsePathKind(probeSrc.results[0].stdout) : "missing";
      if (srcKind !== "dir") die(`源 ${source}:${sourceDir} ${srcKind === "missing" ? "不存在或不可达" : "不是目录"}`, 1);
      const probeDst = await executor.run([dst], buildPathKindProbe(destDir), { kind: "parallel" });
      const dstKind = probeDst.results[0]?.ok ? parsePathKind(probeDst.results[0].stdout) : "missing";
      if (dstKind === "file") die(`目标 ${dest}:${destDir} 已存在且是文件，不是目录`, 1);

      const srcList = await executor.run([src], buildChecksumCommand(sourceDir, "dir"), { kind: "parallel" });
      if (!srcList.results[0]?.ok) die(`源侧 checksum 失败: ${srcList.results[0]?.error ?? srcList.results[0]?.stderr}`, 1);
      let dstEntries = [];
      if (dstKind === "dir") {
        const dstList = await executor.run([dst], buildChecksumCommand(destDir, "dir"), { kind: "parallel" });
        if (!dstList.results[0]?.ok) die(`目标侧 checksum 失败: ${dstList.results[0]?.error ?? dstList.results[0]?.stderr}`, 1);
        dstEntries = parseChecksums(dstList.results[0].stdout);
      }
      const plan = planSync(parseChecksums(srcList.results[0].stdout), dstEntries, del);

      if (!apply) {
        console.log(formatSyncPlan(`${source}:${sourceDir}`, `${dest}:${destDir}`, plan, true));
        console.log("\n加 --apply 执行；涉及删除时还需 --confirm。");
        break;
      }
      if (plan.copy.length === 0 && plan.remove.length === 0) {
        console.log(`已同步（${plan.unchanged} 个文件一致）。`);
        break;
      }
      if (!confirm) {
        die(`需要审批: ${action} 将复制 ${plan.copy.length} 个文件${plan.remove.length ? `、删除目标侧 ${plan.remove.length} 个文件` : ""}${policy.crossTier ? "（跨 tier）" : ""}。确认后加 --confirm 重跑。`, 1);
      }

      console.log(`${action}  已确认(--confirm)`);
      const result = await runSyncPlan(transport, src, sourceDir, dst, destDir, plan, { concurrency: config.defaults.maxConcurrency });
      audit({
        kind: "execution", tool: "fleet-sync",
        command: `${action} (copied=${result.copied.length} removed=${result.removed.length} bytes=${result.totalBytes})`,
        hosts: [src.name, dst.name], outcome: result.failures.length === 0 ? "ok" : "failed", approver: "cli",
        results: { total: plan.copy.length + plan.remove.length, succeeded: result.copied.length + result.removed.length, failed: result.failures.length, skipped: 0 },
      });
      console.log(formatSyncResult(plan, result));
      process.exitCode = result.failures.length > 0 ? 1 : 0;
      break;
    }

    case "diff-file": {
      // diff-file <target> <path> —— 跨机比对文件/目录的 sha256，输出一致性报告。
      const target = rest[0] ?? die("diff-file 需要 target 和 path");
      const path = rest[1] ?? die("diff-file 需要 path");

      const servers = resolveTarget(registry, target);
      const refusals = [];
      for (const s of servers) {
        const scopeReason = checkPathScope(s, path);
        if (scopeReason) refusals.push(`  - ${scopeReason}`);
      }
      if (refusals.length) die(`策略拒绝 (checksum):\n${refusals.join("\n")}`, 1);

      console.log(`比对 ${path}  ${servers.length} 台: ${servers.map((s) => s.name).join(", ")}`);
      const probe = await executor.run(servers, buildPathKindProbe(path), { kind: "parallel" });
      const missing = [];
      const kinds = new Map();
      for (const r of probe.results) {
        if (!r.ok) continue;
        const kind = parsePathKind(r.stdout);
        if (kind === "missing") missing.push(r.host);
        else kinds.set(r.host, kind);
      }
      const kindSet = new Set(kinds.values());
      if (kindSet.size > 1) {
        const files = [...kinds].filter(([, k]) => k === "file").map(([h]) => h);
        const dirs = [...kinds].filter(([, k]) => k === "dir").map(([h]) => h);
        console.log(`DRIFT — 路径类型不一致:`);
        if (dirs.length) console.log(`  目录: ${dirs.join(", ")}`);
        if (files.length) console.log(`  文件: ${files.join(", ")}`);
        if (missing.length) console.log(`  缺失: ${missing.join(", ")}`);
        process.exitCode = 1;
        break;
      }
      const comparable = servers.filter((s) => kinds.has(s.name));
      if (comparable.length === 0) {
        console.log(`无可比对主机${missing.length ? `（全部缺失: ${missing.join(", ")}）` : ""}`);
        process.exitCode = 1;
        break;
      }
      const kind = kindSet.values().next().value ?? "file";
      const fanout = await executor.run(comparable, buildChecksumCommand(path, kind), { kind: "parallel" });
      const report = diffFanout(fanout);
      for (const h of missing) {
        report.failures.push({ host: h, exitCode: null, stderr: "", error: "path missing" });
      }
      report.total += missing.length;
      if (missing.length > 0) report.consistent = false;
      audit({
        kind: "execution", tool: "fleet-diff-file", command: `checksum ${path}`,
        hosts: servers.map((s) => s.name), outcome: report.consistent ? "ok" : "failed",
        results: { total: report.total, succeeded: comparable.length, failed: report.failures.length, skipped: 0 },
      });
      console.log(formatDiff(report));
      process.exitCode = report.consistent ? 0 : 1;
      break;
    }

    case "keychain": {
      // keychain set <server> [--sudo]    — 交互输入密码（不回显），存进 OS 钥匙串
      // keychain check <server> [--sudo]  — 验证钥匙串里有没有（不显示内容）
      // keychain delete <server> [--sudo] — 删除
      const sub = rest[0] ?? die("keychain 需要子命令: set|check|delete");
      const name = rest[1] ?? die(`keychain ${sub} 需要 server 名`);
      const sudo = rest.includes("--sudo");
      const account = keychainAccount(name, sudo);
      const backend = await defaultKeychainBackend();
      if (!backend) die("本机 OS 钥匙串不可用（缺预编译二进制或无 Secret Service 守护进程）。改用环境变量: FLOTILLA_<NAME>_PASSWORD", 1);

      if (sub === "set") {
        const password = await promptHidden(`输入 ${name}${sudo ? " 的 sudo" : ""}密码: `);
        if (!password) die("空密码，未存储", 1);
        await backend.set(account, password);
        console.log(`已存入钥匙串: service=flotilla-mcp account=${account}`);
        audit({ kind: "execution", tool: "keychain-set", command: `keychain set ${account}`, hosts: [name], outcome: "ok", approver: "cli" });
      } else if (sub === "check") {
        const found = (await backend.get(account)) !== undefined;
        console.log(found ? `✓ 钥匙串中有 ${account}` : `✗ 钥匙串中没有 ${account}`);
        process.exitCode = found ? 0 : 1;
      } else if (sub === "delete") {
        const ok = await backend.remove(account);
        console.log(ok ? `已删除 ${account}` : `${account} 不存在，无需删除`);
        audit({ kind: "execution", tool: "keychain-delete", command: `keychain delete ${account}`, hosts: [name], outcome: "ok", approver: "cli" });
      } else {
        die(`未知子命令: ${sub}（set|check|delete）`);
      }
      break;
    }

    case "signal": {
      // signal <target> <pid> <INT|TERM|KILL|HUP> [--sudo] [--confirm]
      const target = rest[0] ?? die("signal 需要 target、pid、信号");
      const pid = Number(rest[1]);
      const sig = rest[2];
      const sudo = rest.includes("--sudo");
      const confirm = rest.includes("--confirm");

      let command;
      try {
        command = buildSignalCommand(pid, sig);
      } catch (err) {
        die(err instanceof Error ? err.message : String(err));
      }
      const servers = resolveTarget(registry, target);
      const policyCommand = sudo ? `sudo ${command}` : command;
      const cls = classifyCommand(policyCommand);
      const refusals = [];
      for (const s of servers) {
        const d = decideForServer(policyCommand, s, config.defaults.approvalMode);
        if (!d.allowed) refusals.push(`  - ${s.name}: ${d.reason}`);
      }
      if (refusals.length) die(`策略拒绝 (${cls}, signal):\n${refusals.join("\n")}`, 1);
      if (!confirm) die(`需要审批: 将向 ${servers.length} 台机器发送 ${policyCommand}。确认后加 --confirm 重跑。`, 1);

      const strategy = servers.length > 1 ? { kind: "serial" } : { kind: "parallel" };
      console.log(`${policyCommand}  命中 ${servers.length} 台  策略=${strategy.kind}  已确认(--confirm)`);
      const result = await executor.run(servers, command, strategy, { sudo });
      audit({
        kind: "execution", tool: "signal-process", command: policyCommand,
        hosts: servers.map((s) => s.name),
        outcome: result.summary.failed > 0 ? "failed" : "ok",
        approver: "cli",
        results: result.summary,
      });
      console.log(formatFanout(result));
      process.exitCode = result.summary.failed > 0 ? 1 : 0;
      break;
    }

    case "exec-sudo": {
      // exec-sudo <target> <command> [--strategy S] [--confirm]
      // 以 root 运行任意命令；密码从 FLOTILLA_*_SUDO_PASSWORD 环境变量读取，走 stdin。
      const target = rest[0] ?? die("exec-sudo 需要 target 和 command");
      const command = rest[1] ?? die("exec-sudo 需要 command");
      const confirm = rest.includes("--confirm");
      const stratIdx = rest.indexOf("--strategy");
      const stratName = stratIdx >= 0 ? rest[stratIdx + 1] : undefined;

      const servers = resolveTarget(registry, target);
      console.log(`命中 ${servers.length} 台: ${servers.map((s) => s.name).join(", ")}`);

      const sudoCommand = `sudo ${command}`;
      const cls = classifyCommand(sudoCommand);
      const refusals = [];
      for (const s of servers) {
        const d = decideForServer(sudoCommand, s, config.defaults.approvalMode);
        if (!d.allowed) refusals.push(`  - ${s.name}: ${d.reason}`);
      }
      if (refusals.length) die(`策略拒绝 (${cls}, sudo):\n${refusals.join("\n")}`, 1);
      if (!confirm) {
        die(`需要审批: "sudo ${command}" 将以 root 在 ${servers.length} 台机器上执行。确认后加 --confirm 重跑。`, 1);
      }

      let strategy;
      if (stratName === "serial") strategy = { kind: "serial", stopOnError: true };
      else if (stratName === "rolling") strategy = { kind: "rolling" };
      else if (stratName === "parallel") strategy = { kind: "parallel" };
      else strategy = servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" };

      console.log(`分类=${cls}  策略=${strategy.kind}  已确认(--confirm)`);
      const result = await executor.run(servers, command, strategy, { sudo: true });
      audit({
        kind: "execution", tool: "exec-sudo", command: `sudo ${command}`,
        hosts: servers.map((s) => s.name),
        outcome: result.summary.failed > 0 ? "failed" : "ok",
        approver: "cli",
        results: result.summary,
      });
      console.log(formatFanout(result));
      process.exitCode = result.summary.failed > 0 ? 1 : 0;
      break;
    }

    case "exec-read":
    case "exec": {
      const target = rest[0] ?? die(`${cmd} 需要 target 和 command`);
      const command = rest[1] ?? die(`${cmd} 需要 command`);
      const confirm = rest.includes("--confirm");
      const stratIdx = rest.indexOf("--strategy");
      const stratName = stratIdx >= 0 ? rest[stratIdx + 1] : undefined;

      const servers = resolveTarget(registry, target);
      console.log(`命中 ${servers.length} 台: ${servers.map((s) => s.name).join(", ")}`);

      const cls = classifyCommand(command);
      if (cmd === "exec-read" && cls !== "read-only") {
        die(`"${command}" 分类为 ${cls}，不是 read-only，请用 exec`);
      }

      let needsApproval = false;
      const refusals = [];
      for (const s of servers) {
        const d = decideForServer(command, s, config.defaults.approvalMode);
        if (!d.allowed) refusals.push(`  - ${s.name}: ${d.reason}`);
        needsApproval = needsApproval || d.needsApproval;
      }
      if (refusals.length) die(`策略拒绝 (${cls}):\n${refusals.join("\n")}`, 1);
      if (cmd === "exec" && needsApproval && !confirm) {
        die(`需要审批: "${command}" 是 ${cls} 命令。确认无误后加 --confirm 重跑。`, 1);
      }

      let strategy;
      if (stratName === "serial") strategy = { kind: "serial", stopOnError: true };
      else if (stratName === "rolling") strategy = { kind: "rolling" };
      else if (stratName === "parallel") strategy = { kind: "parallel" };
      else
        strategy =
          (cls === "unknown" || cls === "destructive" || cls === "privileged") && servers.length > 1
            ? { kind: "rolling" }
            : { kind: "parallel" };

      console.log(`分类=${cls}  策略=${strategy.kind}${needsApproval ? "  已确认(--confirm)" : ""}`);
      const result = await executor.run(servers, command, strategy);
      if (cmd === "exec") {
        audit({
          kind: "execution", tool: "exec", command,
          hosts: servers.map((s) => s.name),
          outcome: result.summary.failed > 0 ? "failed" : "ok",
          approver: needsApproval ? "cli" : undefined,
          results: result.summary,
        });
      }
      console.log(formatFanout(result));
      process.exitCode = result.summary.failed > 0 ? 1 : 0;
      break;
    }

    default:
      console.error(`用法: flotilla <info|credentials|list|resolve|add|classify|exec-read|exec|exec-sudo|diff|push|pull|signal|service|session|workflow|logs-tail|metrics|doctor|pull-config> ...`);
      process.exit(2);
  }
}

try {
  await main();
} finally {
  await activeTransport?.close();
}
