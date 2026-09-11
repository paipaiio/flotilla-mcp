#!/usr/bin/env node
/**
 * Flotilla dev CLI —— 实机测试用，绕过 MCP 直接调 core 引擎。
 *
 * 用法：
 *   node scripts/fleet.mjs list
 *   node scripts/fleet.mjs resolve "<target>"
 *   node scripts/fleet.mjs exec-read "<target>" "<command>"
 *   node scripts/fleet.mjs exec "<target>" "<command>" [--strategy parallel|serial|rolling] [--confirm]
 *   node scripts/fleet.mjs classify "<command>"
 *
 * 配置：--config <path> 或 FLOTILLA_CONFIG 环境变量。
 */
import {
  Executor,
  FleetRegistry,
  SshTransport,
  analyzeDoctor,
  buildControlCommand,
  buildDoctorScript,
  buildLogsCommand,
  buildMetricsScript,
  buildSessionCaptureCommand,
  buildSessionKillCommand,
  buildSessionListCommand,
  buildSessionSendCommand,
  buildSessionStartCommand,
  buildStatusCommand,
  checkServiceScope,
  classifyCommand,
  checkPathScope,
  decide,
  diffFanout,
  formatDiff,
  formatDoctor,
  formatMetrics,
  loadFleetConfig,
  parseMetrics,
  parseSessionList,
  resolveTarget,
  validateSessionName,
  validateUnit,
} from "../packages/core/dist/index.js";

const argv = process.argv.slice(2);
const flagIdx = argv.indexOf("--config");
const configPath = flagIdx >= 0 ? argv[flagIdx + 1] : undefined;
const args = argv.filter((_, i) => i !== flagIdx && i !== flagIdx + 1);
const [cmd, ...rest] = args;

function die(msg, code = 2) {
  console.error(`error: ${msg}`);
  process.exit(code);
}

let config;
try {
  config = loadFleetConfig(configPath);
} catch (err) {
  die(err instanceof Error ? err.message : String(err));
}
const registry = new FleetRegistry(config);
const transport = new SshTransport(new Map(config.servers.map((s) => [s.name, s])));
const executor = new Executor(transport, config.defaults);

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

async function main() {
  switch (cmd) {
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

      let command;
      if (action === "status") command = buildStatusCommand(unit);
      else if (action === "logs") command = buildLogsCommand(unit, lines);
      else if (["start", "stop", "restart", "reload"].includes(action)) command = buildControlCommand(unit, action);
      else die(`未知 action: ${action}`);

      const policyCommand = sudo ? `sudo ${command}` : command;
      const cls = classifyCommand(policyCommand);
      const refusals = [];
      for (const s of servers) {
        const scopeReason = checkServiceScope(s, unit);
        if (scopeReason) refusals.push(`  - ${scopeReason}`);
        const d = decide(policyCommand, {
          role: s.role,
          tier: s.group,
          readOnly: s.readOnly,
          approvalMode: config.defaults.approvalMode,
        });
        if (!d.allowed) refusals.push(`  - ${s.name}: ${d.reason}`);
      }
      if (refusals.length) die(`策略拒绝:\n${refusals.join("\n")}`, 1);
      if ((cls === "destructive" || sudo) && !confirm) {
        die(`需要审批: "${policyCommand}" 是 ${cls}${sudo ? "（sudo 提权）" : ""}。确认后加 --confirm 重跑。`, 1);
      }

      let strategy;
      if (stratName) strategy = { kind: stratName, stopOnError: true };
      else strategy = cls === "destructive" && servers.length > 1 ? { kind: "rolling" } : { kind: "parallel" };

      console.log(`${sudo ? "sudo " : ""}${action} ${unit}  命中 ${servers.length} 台  策略=${strategy.kind}`);
      const result = await executor.run(servers, command, strategy, { sudo });
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
            const d = decide(command, {
              role: s.role,
              tier: s.group,
              readOnly: s.readOnly,
              approvalMode: config.defaults.approvalMode,
            });
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
        console.log(formatFanout(result));
        process.exitCode = result.summary.failed > 0 ? 1 : 0;
      } else if (sub === "kill") {
        if (!confirm) die(`需要审批: 将杀掉会话 "${rawName}" 及其中运行的进程。确认后加 --confirm 重跑。`, 1);
        const result = await executor.run(servers, buildSessionKillCommand(fullName), { kind: "parallel" });
        console.log(formatFanout(result));
        process.exitCode = result.summary.failed > 0 ? 1 : 0;
      } else {
        die(`未知 session 子命令: ${sub}`);
      }
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
        const d = decide(sudoCommand, {
          role: s.role,
          tier: s.group,
          readOnly: s.readOnly,
          approvalMode: config.defaults.approvalMode,
        });
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
        const d = decide(command, {
          role: s.role,
          tier: s.group,
          readOnly: s.readOnly,
          approvalMode: config.defaults.approvalMode,
        });
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
          (cls === "destructive" || cls === "privileged") && servers.length > 1
            ? { kind: "rolling" }
            : { kind: "parallel" };

      console.log(`分类=${cls}  策略=${strategy.kind}${needsApproval ? "  已确认(--confirm)" : ""}`);
      const result = await executor.run(servers, command, strategy);
      console.log(formatFanout(result));
      process.exitCode = result.summary.failed > 0 ? 1 : 0;
      break;
    }

    default:
      console.error(`用法: node scripts/fleet.mjs <list|resolve|classify|exec-read|exec|exec-sudo|diff|push|service|session|metrics|doctor> ...`);
      process.exit(2);
  }
}

try {
  await main();
} finally {
  await transport.close();
}
