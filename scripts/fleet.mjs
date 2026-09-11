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
  classifyCommand,
  checkPathScope,
  decide,
  diffFanout,
  formatDiff,
  loadFleetConfig,
  resolveTarget,
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
      console.error(`用法: node scripts/fleet.mjs <list|resolve|classify|exec-read|exec|diff|push> ...`);
      process.exit(2);
  }
}

try {
  await main();
} finally {
  await transport.close();
}
