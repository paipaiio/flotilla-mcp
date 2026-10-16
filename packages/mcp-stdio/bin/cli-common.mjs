/**
 * Flotilla CLI 公共部分：参数解析、帮助、策略拒绝与常见错误的中文解释、结果格式化。
 */
import { builtinAllowedClasses } from "flotilla-core";

/** 带值的参数（值可以写成 --x v 或 --x=v）。 */
const VALUE_FLAGS = new Set([
  "--tags", "--strategy", "--tier", "--group", "--role", "--port", "--user", "--ssh-alias", "--lines", "--workdir",
  "--via", "--url", "--token-env", "--seconds", "--key", "--host", "--grep", "--file", "--cmd", "--auth", "--unit",
]);
const BOOL_FLAGS = new Set([
  "--confirm", "--sudo", "--repair", "--read-only", "--no-read-only", "--plan", "--delete", "--apply", "--local",
  "--localhost-only", "--dry-run", "--all", "--bootstrap", "--password-only", "--no-sudo", "--verbose", "--create-user",
]);
const ADD_FLAGS = [
  "--host", "--user", "--port", "--auth", "--key", "--tier", "--group", "--role", "--tags", "--via", "--ssh-alias",
  "--create-user", "--no-sudo", "--local", "--localhost-only", "--dry-run", "--bootstrap", "--password-only",
  "--read-only", "--verbose",
];

/** Flags each command actually reads: anything else is an error, never silently ignored. */
export const COMMAND_FLAGS = {
  info: [], list: [], resolve: [], classify: [], discover: [], diff: [], "diff-file": [], metrics: [], doctor: [],
  "exec-read": ["--strategy"],
  credentials: ["--repair"],
  keychain: ["--sudo"],
  add: ADD_FLAGS,
  "import-ssh": ["--all", ...ADD_FLAGS.filter((f) => !["--host", "--user", "--port", "--auth", "--key", "--via", "--ssh-alias", "--local", "--localhost-only"].includes(f))],
  remove: ["--confirm", "--dry-run"],
  set: ["--role", "--tier", "--group", "--tags", "--read-only", "--no-read-only", "--user", "--port", "--dry-run"],
  exec: ["--confirm", "--strategy"],
  "exec-sudo": ["--confirm", "--strategy"],
  service: ["--confirm", "--lines", "--strategy", "--sudo"],
  push: ["--confirm", "--strategy"],
  pull: ["--strategy"],
  copy: ["--confirm"],
  sync: ["--apply", "--confirm", "--delete"],
  signal: ["--confirm", "--sudo"],
  session: ["--cmd", "--confirm", "--lines", "--workdir"],
  workflow: ["--confirm", "--plan"],
  "logs-tail": ["--confirm", "--file", "--grep", "--seconds", "--sudo", "--unit"],
  "pull-config": ["--url", "--token-env"],
};

const ENUMS = {
  "--strategy": ["parallel", "serial", "rolling"],
  "--role": ["viewer", "operator", "admin"],
  "--auth": ["agent", "key", "password"],
};
const POSITIVE_INTS = new Set(["--port", "--lines", "--seconds"]);
const USERNAME_RE = /^[a-z_][a-z0-9_-]{0,31}$/;

function distance(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

export function closest(word, candidates) {
  let best;
  let bestScore = Infinity;
  for (const c of candidates) {
    const d = distance(word, c);
    if (d < bestScore) {
      best = c;
      bestScore = d;
    }
  }
  return bestScore <= Math.max(2, Math.floor(word.length / 3)) ? best : undefined;
}

/**
 * 把参数整理成「位置参数在前、参数对在后」，这样各命令里的 rest[0]/rest[1]
 * 永远是真正的位置参数（不会把 --confirm 当命令执行）。未知参数、缺值、
 * 非法枚举和非数字直接报错。
 */
export function normalizeArgs(list, die, cmd) {
  const allowed = cmd ? COMMAND_FLAGS[cmd] : undefined;
  const checkAllowed = (name) => {
    if (allowed && !allowed.includes(name)) {
      die(`${cmd} 不支持 ${name}${allowed.length ? `（可用：${allowed.join(" ")}）` : "（这个命令不带参数）"}`);
    }
  };
  const positionals = [];
  const flags = [];
  for (let i = 0; i < list.length; i++) {
    const arg = list[i];
    if (arg === "--") {
      positionals.push(...list.slice(i + 1));
      break;
    }
    if (!arg.startsWith("--")) {
      positionals.push(arg);
      continue;
    }
    const eq = arg.indexOf("=");
    const name = eq > 0 ? arg.slice(0, eq) : arg;
    const inline = eq > 0 ? arg.slice(eq + 1) : undefined;
    if (VALUE_FLAGS.has(name) || BOOL_FLAGS.has(name)) checkAllowed(name);
    if (name === "--create-user") {
      // 可选值只认 --create-user=name：空格分隔会和后面的位置参数（别名/地址）混淆。
      if (inline !== undefined && !USERNAME_RE.test(inline)) die(`--create-user 的用户名不合法: "${inline}"`);
      flags.push(name, ...(inline ? [inline] : []));
      continue;
    }
    if (VALUE_FLAGS.has(name)) {
      const value = inline ?? list[++i];
      if (value === undefined || (inline === undefined && value.startsWith("--"))) die(`${name} 需要一个值`);
      if (ENUMS[name] && !ENUMS[name].includes(value)) die(`${name} 只能是 ${ENUMS[name].join(" | ")}（收到 "${value}"）`);
      if (POSITIVE_INTS.has(name) && !/^[1-9]\d*$/.test(value)) die(`${name} 需要正整数（收到 "${value}"）`);
      flags.push(name, value);
      continue;
    }
    if (BOOL_FLAGS.has(name)) {
      if (inline !== undefined) die(`${name} 不带值`);
      flags.push(name);
      continue;
    }
    const hint = closest(name, [...VALUE_FLAGS, ...BOOL_FLAGS]);
    die(`未知参数 ${name}${hint ? `，是不是 ${hint}？` : ""}（flotilla --help 查看用法）`);
  }
  return [...positionals, ...flags];
}

export const COMMANDS = [
  "info", "credentials", "list", "resolve", "classify", "add", "import-ssh", "discover", "remove", "set", "exec-read",
  "exec", "exec-sudo", "diff", "diff-file", "push", "pull", "copy", "sync", "signal", "service", "session", "workflow",
  "logs-tail", "metrics", "doctor", "keychain", "pull-config",
];

export const USAGE = `flotilla —— 一条命令管理多台服务器（SSH）

加机器（ssh 能连就能加；只认密码的机器会提示输入一次）
  flotilla discover                          列出 ~/.ssh/config 里还没加入的主机
  flotilla add <ssh别名>                      用 ~/.ssh/config 的配置添加
  flotilla add root@10.0.1.11[:22]            直接给地址（名字默认用 IP）
  flotilla add web-1 root@10.0.1.11           指定名字
      [--tier prod|staging|dev] [--role viewer|operator|admin] [--tags a,b] [--via 跳板机]
      [--create-user[=名字]] 首连时自动建低权限用户   [--password-only] 只用密码登录   [--dry-run] 预演
  flotilla import-ssh <别名...> | --all       批量导入
  flotilla set <名字> --tier dev --role admin  改权限/标签/端口（加 --dry-run 先看 旧 → 新）
  flotilla remove <名字> --confirm             移出舰队（不碰服务器；--dry-run 预演）
  flotilla list                               查看舰队

执行（<目标> 可以是：名字、all、tag:web、tier:prod、group:xx，逗号并集，!排除）
  flotilla resolve <目标>                      预演目标命中哪些机器
  flotilla exec-read <目标> "<只读命令>"        只读命令，无需确认
  flotilla exec <目标> "<命令>" [--confirm] [--strategy parallel|serial|rolling]
  flotilla exec-sudo <目标> "<命令>" --confirm
  flotilla classify "<命令>" [目标]            看命令的风险等级（给目标则说明能否执行）
  flotilla diff <目标> "<命令>"                跨机比对输出      flotilla diff-file <目标> <路径>
  flotilla push <目标> <本地> <远端> --confirm   flotilla pull <目标> <远端> <本地>
  flotilla copy <源> <源路径> <目的> <目的路径> --confirm
  flotilla sync <源> <源目录> <目的> <目的目录> [--delete] [--apply --confirm]
  flotilla service <目标> <unit> status|logs|start|stop|restart|reload [--confirm]
  flotilla session list|start|output|send|kill <目标> [名字] ...
  flotilla workflow <文件.yaml> [--plan] [--confirm]
  flotilla logs-tail <目标> --file <路径> | --unit <unit> [--seconds N] [--grep 正则]
  flotilla signal <目标> <pid> INT|TERM|KILL|HUP [--confirm]
  flotilla metrics <目标>     flotilla doctor <目标>

凭据与配置
  flotilla credentials [目标] [--repair]       诊断（并修复）登录凭据
  flotilla keychain set|check|delete <名字> [--sudo]
  flotilla pull-config [--url https://...]     从远端拉取舰队配置
  flotilla info                               运行时信息

全局：--config <路径>（或 FLOTILLA_CONFIG）  ·  --help  ·  --version
`;

const CLASS_ZH = {
  "read-only": "只读",
  safe: "低风险",
  unknown: "未分类",
  destructive: "破坏性",
  privileged: "特权（root）",
  forbidden: "永禁",
};

export const classZh = (c) => CLASS_ZH[c] ?? c;

/** 策略拒绝 → 中文原因 + 最小的放开方式（不一上来就建议 admin）。 */
export function explainRefusalZh(server, decision, matrix) {
  const cls = decision.commandClass;
  if (cls === "forbidden") return `${server.name}: 命中永禁清单，任何人都不能执行`;
  if (/readOnly/.test(decision.reason ?? "")) {
    return `${server.name}: 该机器设为只读。要放开：flotilla set ${server.name} --no-read-only`;
  }
  const m = /Role "(\w+)" on tier "([^"]+)" does not permit (\S+) commands/.exec(decision.reason ?? "");
  if (!m) return `${server.name}: ${decision.reason}`;
  const [, role, tier] = m;
  const allows = (r, t) => builtinAllowedClasses(r, t).includes(cls) && (!matrix?.[r] || (matrix[r][t] ?? matrix[r]["*"] ?? [cls]).includes(cls));
  const options = [];
  for (const t of ["staging", "dev"]) if (t !== tier && allows(role, t)) options.push(`--tier ${t}`);
  for (const r of ["operator", "admin"]) if (r !== role && allows(r, tier)) options.push(`--role ${r}`);
  const fix = options.length
    ? `要放开（任选其一）：flotilla set ${server.name} ${options.slice(0, 3).join(" 或 ")}`
    : "任何角色在该层级都不允许，只能自己登录执行";
  return `${server.name}: ${role} 角色在 ${tier} 层级不允许${classZh(cls)}命令。${fix}`;
}

/** 常见执行错误 → 下一步。 */
export function errorHintZh(serverName, text) {
  const t = text ?? "";
  if (/a password is required|sudo: .*password/i.test(t)) {
    return `需要 sudo 密码：flotilla keychain set ${serverName} --sudo（或设置 FLOTILLA_${serverName.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_SUDO_PASSWORD）`;
  }
  if (/CREDENTIAL_REQUIRED|login password|authentication methods failed/i.test(t)) return `登录凭据有问题：flotilla credentials ${serverName} --repair`;
  if (/subsystem: sftp|Unable to start subsystem/i.test(t)) return "服务器没开 SFTP：在 sshd_config 里启用 Subsystem sftp（多数发行版默认开启）";
  if (/ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|Timed out while waiting for handshake/i.test(t)) return "连不上这台机器：检查网络、地址和端口（flotilla set 可改端口）";
  if (/no server running on|can't find session|session not found/i.test(t)) return "会话不存在：flotilla session list <目标> 看看现有会话";
  return undefined;
}

/** 多机结果（中文表头 + 每台机器的错误提示）。 */
export function formatFanout(result) {
  const { summary } = result;
  const strategy = { parallel: "并行", serial: "串行", rolling: "滚动" }[summary.strategy.split(/[ (]/)[0]] ?? summary.strategy;
  const lines = [
    `\n${strategy}执行 ${summary.total} 台：成功 ${summary.succeeded}，失败 ${summary.failed}${summary.skipped ? `，跳过 ${summary.skipped}` : ""}${summary.halted ? "（批次失败已熔断，后续未执行）" : ""}\n`,
  ];
  for (const r of result.results) {
    const status = r.skipped ? "跳过" : r.ok ? "成功" : "失败";
    lines.push(`── ${status} ${r.host}（退出码 ${r.exitCode ?? "-"}，${r.durationMs}ms）`);
    if (r.error) lines.push(`   错误: ${r.error}`);
    if (r.stdout) lines.push(r.stdout.trimEnd());
    if (r.stderr) lines.push(`   stderr: ${r.stderr.trimEnd()}`);
    if (!r.ok && !r.skipped) {
      const hint = errorHintZh(r.host, `${r.error ?? ""}\n${r.stderr ?? ""}`);
      if (hint) lines.push(`   → ${hint}`);
      else if (!r.error && !r.stderr && !r.stdout) lines.push("   → 命令没有任何输出就失败了（可能是命令不存在）");
    }
  }
  return lines.join("\n");
}
