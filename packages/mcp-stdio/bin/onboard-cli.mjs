/**
 * Flotilla CLI —— 舰队成员命令：add / import-ssh / discover / remove / set。
 *
 * 加机器只有一条路，自动选最省事的方式：
 *   ~/.ssh/config + 本机密钥/ssh-agent 能登 → 直接用；
 *   都登不上 → 提示输入一次密码 → 装舰队专用密钥 → 之后免密（密码不保存）；
 *   服务器只允许密码登录 → 自动改用密码方式，密码存进系统钥匙串（sudo 同用）。
 */
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { hostname as osHostname, userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  OnboardError,
  appendServerToConfig,
  buildServerToml,
  defaultConfigPath,
  defaultKeychainBackend,
  ensureFleetConfigFile,
  ensureFleetKeyPair,
  installPublicKeyLocally,
  keychainAccount,
  knownHostKeys,
  listLocalPrivateKeys,
  listSshConfigAliases,
  onboardServer,
  parseFleetConfig,
  planServer,
  removeServerFromConfig,
  resolveSshHost,
  secretEnvNames,
  setServerFields,
} from "flotilla-core";

const VALUE_FLAGS = new Set([
  "--host", "--user", "--port", "--auth", "--key", "--tier", "--group", "--role", "--tags", "--via", "--ssh-alias", "--create-user",
]);
const NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

function parseFlags(rest) {
  const get = (flag) => {
    const i = rest.indexOf(flag);
    return i >= 0 && rest[i + 1] !== undefined && !rest[i + 1].startsWith("--") ? rest[i + 1] : undefined;
  };
  const has = (flag) => rest.includes(flag);
  const positionals = rest.filter((a, i) => !a.startsWith("--") && !(i > 0 && VALUE_FLAGS.has(rest[i - 1])));
  return { get, has, positionals };
}

/** "user@host:port" / "host:port" / "host" → parts. */
function parseDestination(value) {
  const m = /^(?:([^@\s]+)@)?(\[[^\]]+\]|[^:@\s]+)(?::(\d+))?$/.exec(value ?? "");
  if (!m) return undefined;
  return { user: m[1], host: m[2].replace(/^\[|\]$/g, ""), port: m[3] ? Number(m[3]) : undefined };
}

const looksLikeHost = (s) => /^[0-9.]+$/.test(s) || s.includes(".") || s.includes(":");

function networkReasonZh(reason = "") {
  if (/ECONNREFUSED/i.test(reason)) return "端口拒绝连接：sshd 没运行，或端口不对";
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(reason)) return "域名解析失败：检查主机名拼写";
  if (/EHOSTUNREACH|ENETUNREACH/i.test(reason)) return "主机不可达：检查 IP 和网络";
  if (/timed out|ETIMEDOUT/i.test(reason)) return "连接超时：地址不通，或防火墙/安全组没放行 SSH 端口";
  return reason || "未知网络错误";
}

/** OnboardError → 中文解释 + 下一步。 */
export function explainOnboardError(err, req = {}) {
  if (!(err instanceof OnboardError)) return [err instanceof Error ? err.message : String(err)];
  const d = err.details ?? {};
  const where = d.host ? `${d.user ? `${d.user}@` : ""}${d.host}${d.port ? `:${d.port}` : ""}` : req.name;
  const tried = (d.attempts ?? []).map((a) => `    · ${a}`);
  switch (err.code) {
    case "unreachable":
      return [
        `连不上 ${where}——${networkReasonZh(d.reason)}。`,
        "  检查地址和端口（非 22 端口加 --port 或写成 user@host:port）；只能经跳板机访问的机器加 --via <跳板机>。",
      ];
    case "password-needed":
      return [
        `${where} 用密钥和 ssh-agent 都登不上，需要一次密码。`,
        ...(tried.length ? ["  已尝试:", ...tried] : []),
        "  在终端里直接运行即可（会提示输入密码）；脚本里可用环境变量 FLOTILLA_BOOTSTRAP_PASSWORD 传入。",
      ];
    case "password-not-allowed":
      return [
        `${where} 只接受密钥登录，而本机的密钥和 ssh-agent 它都不认（也不接受密码，所以没有问你密码）。`,
        ...(tried.length ? ["  已尝试:", ...tried] : []),
        "  任选一种：",
        "  ① 登录它用的私钥在本机别处：flotilla add … --key <私钥路径>",
        "  ② 私钥在密码管理器/硬件密钥/另一台电脑：先载入 ssh-agent（ssh-add <私钥>，或开启 1Password 等的 SSH agent），再重跑",
        ...(d.fleetPublicKey
          ? [
              "  ③ 手头没有能登录的私钥：通过云控制台或另一台能登录的机器，把下面这行加到服务器的 ~/.ssh/authorized_keys，然后重跑同一条 flotilla add（会自动用上它）：",
              `     ${String(d.fleetPublicKey).trim()}`,
            ]
          : []),
      ];
    case "password-rejected":
      return [`${where} 拒绝了这个密码（或该账户禁止密码登录）。`, "  用户名不对的话加 --user <用户名>，或写成 user@host。"];
    case "host-key-mismatch":
      return [
        `⚠ ${where} 出示的 host key 与 known_hosts 记录不一致——已中止，没有发送任何凭据。`,
        `  记录: ${(d.trusted ?? []).join(", ")}`,
        `  实际: ${d.presented ?? "?"}`,
        "  若服务器刚重装过：线下核实新指纹后 ssh-keygen -R <host> 清掉旧记录再加。否则可能有人在中间劫持。",
      ];
    case "jump-host-missing":
      return [`${req.name ?? ""} 要经跳板机 "${d.jump}"，但它还不在舰队里。`, `  先加跳板机：flotilla add ${d.jump}  （import-ssh 会自动排好顺序）`];
    case "unsupported-proxy":
      return [`ssh config 里用了 ${d.proxyCommand ? "ProxyCommand" : "多级 ProxyJump"}，flotilla 无法复现。`, "  改成单级 ProxyJump，或加 --via <舰队里的跳板机>。"];
    case "duplicate":
      return [`"${d.name}" 已在舰队里。`, `  改参数：flotilla set ${d.name} --tier <层级> --role <角色>；重新添加：先 flotilla remove ${d.name} --confirm`];
    case "create-user-failed":
      if (!d.reason && /only accepts passwords/.test(err.message)) {
        return ["这台机器只允许密码登录，没法给新用户配密钥登录，--create-user 用不了。", "  去掉 --create-user 直接加（会用密码方式）。"];
      }
      return [
        `建低权限用户失败：${d.reason ?? err.message}`,
        d.needsSudo
          ? "  首连账户不是 root，需要免密 sudo；或改用 root 首连（root@host），或加 --bootstrap 用密码登录（会用同一个密码 sudo）。"
          : "  去掉 --create-user 也能先直接加上。",
      ];
    default:
      return [err.message];
  }
}

function methodZh(result) {
  const s = result.server;
  switch (result.method) {
    case "agent": return "ssh-agent";
    case "key": return `密钥 ${s.keyRef}`;
    case "password→key": return `密码首连 → 已换成舰队专用密钥 ${s.keyRef}（密码没有保存）`;
    default: return "密码";
  }
}

const NOTE_ZH = {
  tofu: "host key 不在 known_hosts 里，已按首次连接钉死（TOFU）",
  "root-account": "这是 root 账户：它的破坏性命令每次都要审批（auto 和 JIT 免批对它无效）。想换专用低权限用户：flotilla remove <名字> --confirm 后加 --create-user 重加",
  "uid0-not-root": "该账户 uid 为 0（换了名字的 root），建议加 --create-user",
  "key-not-accepted": "服务器不接受密钥登录（只允许密码），已改用密码方式",
  "created-user": null, // 单独打印
};

async function storePassword(name, password, isRoot) {
  const backend = await defaultKeychainBackend();
  if (!backend) {
    const [loginEnv] = secretEnvNames(name, "password");
    const [sudoEnv] = secretEnvNames(name, "sudo");
    return [
      "系统钥匙串不可用，密码没有保存。运行 MCP server / 命令前设置：",
      `    export ${loginEnv}='<密码>'${isRoot ? "" : `  ${sudoEnv}='<密码>'`}`,
    ];
  }
  await backend.set(keychainAccount(name, false), password);
  // sudo 默认问的就是登录用户自己的密码。
  if (!isRoot) await backend.set(keychainAccount(name, true), password);
  return [`密码已存入系统钥匙串${isRoot ? "" : "（sudo 也用它）"}；删除：flotilla keychain delete ${name}`];
}

function printAdded(result, cfgPath, req, keychainMissing) {
  const s = result.server;
  console.log(`${keychainMissing ? "⚠ 已添加，但还缺登录凭据" : "✓ 已添加"} ${s.name}  ${s.user}@${s.host}:${s.port}${s.via ? `  via ${s.via}` : ""}`);
  if (!req.user && !result.createdUser) console.log(`  用户      ${s.user}（来自 ssh config / 本机用户名；要换用 --user 或 user@host）`);
  console.log(`  登录方式  ${methodZh(result)}`);
  console.log(`  主机      ${result.probe.hostname ?? "?"}  uid=${result.probe.uid ?? "?"}  tmux ${result.probe.tmux ? "✓" : "✗（持久会话不可用）"}`);
  console.log(`  host key  ${s.trustedHostKey ?? "未捕获"}${result.hostKeySource === "known_hosts" ? "（与 known_hosts 一致）" : ""}`);
  const inferred = req.group ? "" : "（按名字推断，认不出默认最严的 prod）";
  const tierNote = s.group === "prod" && s.role === "operator" ? "；operator 在 prod 上不能执行破坏性命令" : "";
  console.log(`  权限      tier=${s.group}${inferred} role=${s.role}${tierNote}`);
  if (!req.group && s.group === "prod") console.log(`            测试/自用机器可改：flotilla set ${s.name} --tier dev`);
  if (result.createdUser) console.log(`  用户      已创建低权限用户 ${result.createdUser}，之后用它登录（sudo 仅限 systemctl 启停/状态，日志免 sudo）`);
  for (const n of result.notes) {
    const zh = NOTE_ZH[n.code];
    if (zh) console.log(`  ⚠ ${zh.replace("<名字>", s.name)}`);
  }
  console.log(`  已写入    ${cfgPath}`);
}

function makePasswordSource(promptHidden) {
  return {
    maxAttempts: 3,
    async obtain({ user, host, port, attempts, retry }) {
      if (process.env.FLOTILLA_BOOTSTRAP_PASSWORD) {
        return retry ? undefined : process.env.FLOTILLA_BOOTSTRAP_PASSWORD;
      }
      // No terminal to ask on (script/CI): fail with the env-var hint instead of hanging.
      if (!process.stdin.isTTY) return undefined;
      if (retry) {
        console.log("  密码不对，再试一次（Ctrl+C 退出）");
      } else {
        if (attempts.length > 0) {
          console.log(`  试过 ${attempts.length} 把密钥/agent，这台机器都不认：`);
          for (const a of attempts) console.log(`    · ${a.replace(/: .*$/, "")}`);
          console.log("  平时用别的密钥登录它？Ctrl+C 后加 --key <私钥路径> 重跑（或先 ssh-add 载入 agent）。");
        } else {
          console.log("  本机没有可用的密钥或 ssh-agent。");
        }
        console.log("  也可以输入一次登录密码：flotilla 会装上专用密钥，之后免密、不保存密码；");
        console.log("  若服务器只允许密码登录，就改用密码方式并存进系统钥匙串。");
      }
      const answer = await promptHidden(`  ${user}@${host}:${port} 的密码: `);
      return answer ? answer : undefined;
    },
  };
}

/** 根据位置参数/--host 推出一个 add 请求；参数错误在初始化配置之前就退出。 */
function buildAddRequest(flags, local, sshCfg, die) {
  const { get, positionals } = flags;
  let name = positionals[0];
  let dest = parseDestination(positionals[1]);
  if (!dest && name?.includes("@")) {
    dest = parseDestination(name);
    // 同一 IP 不同端口是不同机器：名字带上端口，避免撞名。
    name = dest ? (dest.port && dest.port !== 22 ? `${dest.host}-${dest.port}` : dest.host) : undefined;
  }
  if (!name) {
    if (local) name = osHostname().split(".")[0] || "localhost";
    else die("add 需要服务器名称。例：flotilla add web-1（~/.ssh/config 别名）、flotilla add root@10.0.1.11、flotilla add web-1 --host 10.0.1.11");
  }
  if (!NAME_RE.test(name)) die(`服务器名称 "${name}" 只能包含字母、数字、. _ -，且以字母或数字开头`);
  let host = get("--host") ?? dest?.host ?? (local ? "127.0.0.1" : undefined);
  const alias = get("--ssh-alias") ?? name;
  if (!host && !listSshConfigAliases(sshCfg).includes(alias)) {
    if (looksLikeHost(name)) host = name;
    else {
      const aliases = listSshConfigAliases(sshCfg);
      die(
        `"${alias}" 不是 ~/.ssh/config 里的 Host 别名。给出地址：flotilla add ${name} --host <IP或域名>` +
          (aliases.length ? `\n  ssh config 里有：${aliases.slice(0, 12).join(", ")}${aliases.length > 12 ? " …" : ""}` : ""),
      );
    }
  }
  const role = get("--role");
  const auth = get("--auth");
  if (role && !["viewer", "operator", "admin"].includes(role)) die(`未知 role: ${role}（viewer | operator | admin）`);
  if (auth && !["agent", "key", "password"].includes(auth)) die(`未知 auth: ${auth}（agent | key | password）`);
  const port = get("--port") ?? dest?.port;
  if (port !== undefined && !(Number(port) >= 1 && Number(port) <= 65535)) die(`端口不对: ${port}`);
  return {
    name,
    host,
    sshAlias: get("--ssh-alias"),
    user: get("--user") ?? dest?.user,
    port: port !== undefined ? Number(port) : undefined,
    auth,
    keyRef: get("--key"),
    via: get("--via"),
    group: get("--tier") ?? get("--group"),
    role,
    tags: get("--tags") ? get("--tags").split(",").filter(Boolean) : undefined,
    readOnly: flags.has("--read-only") || undefined,
  };
}

/** import-ssh 的目标：跳板机排在依赖它的主机前面。 */
function importRequests(flags, config, sshCfg, die) {
  const inFleet = new Set(config?.servers.map((s) => s.name) ?? []);
  const aliases = flags.has("--all") ? listSshConfigAliases(sshCfg) : flags.positionals;
  if (aliases.length === 0) die("import-ssh 需要别名，或 --all 导入 ~/.ssh/config 里的全部 Host（先 flotilla discover 看看有哪些）");
  const pending = aliases.filter((a) => !inFleet.has(a));
  const jumpOf = new Map(
    pending.map((a) => {
      try {
        const pj = resolveSshHost(a, undefined, sshCfg).proxyJump;
        return [a, pj ? pj.replace(/^.*@/, "").replace(/:\d+$/, "") : undefined];
      } catch {
        return [a, undefined];
      }
    }),
  );
  const ordered = [];
  const visit = (a, depth = 0) => {
    if (ordered.includes(a) || depth > 8) return;
    const jump = jumpOf.get(a);
    if (jump && pending.includes(jump)) visit(jump, depth + 1);
    ordered.push(a);
  };
  pending.forEach((a) => visit(a));
  const { get } = flags;
  return ordered.map((name) => ({
    name,
    group: get("--tier") ?? get("--group"),
    role: get("--role"),
    tags: get("--tags") ? get("--tags").split(",").filter(Boolean) : undefined,
    readOnly: flags.has("--read-only") || undefined,
  }));
}

/** authorized_keys 的最终状态：新写入 / 收紧为仅本机 / 已存在（是否受限）。 */
function localAkLine(r, preview) {
  const will = preview ? "会" : "已";
  if (r.appended) return `公钥${will}写入${r.restricted ? '（仅限本机 from="127.0.0.1,::1"）' : ""}`;
  if (r.tightened) return `已有的公钥行${will}收紧为仅限本机（from="127.0.0.1,::1"）：`;
  return `公钥已存在（${r.restricted ? "已限制来源" : "未限制来源"}）于`;
}

async function runAdd(cmd, rest, ctx) {
  const { config, configPath, audit, die, promptHidden } = ctx;
  const flags = parseFlags(rest);
  const sshCfg = process.env.FLOTILLA_SSH_CONFIG || undefined;
  const sshG = (alias) => resolveSshHost(alias, undefined, sshCfg);
  const local = cmd === "add" && flags.has("--local");
  const dryRun = flags.has("--dry-run");
  const requests = cmd === "import-ssh" ? importRequests(flags, config, sshCfg, die) : [buildAddRequest(flags, local, sshCfg, die)];
  if (requests.length === 0) {
    console.log("没有需要导入的主机（都已在舰队里）");
    return;
  }

  const cfgPath = resolve(configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
  if (!existsSync(cfgPath) && !dryRun) {
    const init = ensureFleetConfigFile(cfgPath);
    console.log(`已自动初始化配置 ${init.path}（目录 700 / 文件 600）`);
  }
  const fleetKeyPath = join(dirname(cfgPath), "fleet_ed25519");
  let fleetKeyCache;
  const fleetKey = () => {
    if (!fleetKeyCache) {
      const created = !existsSync(fleetKeyPath);
      fleetKeyCache = ensureFleetKeyPair(fleetKeyPath);
      if (created) console.log(`  生成舰队专用密钥 ${fleetKeyPath}`);
    }
    return fleetKeyCache;
  };

  if (local) {
    // 人已经在机器上：装公钥是本地文件追加，不需要任何密码
    const req = requests[0];
    if (req.keyRef && !existsSync(req.keyRef.replace(/^~(?=$|\/)/, process.env.HOME ?? ""))) die(`私钥不存在: ${req.keyRef}`, 1);
    req.user = req.user ?? userInfo().username;
    const localhostOnly = flags.has("--localhost-only");
    if (dryRun) {
      // 预演不生成密钥、不写 authorized_keys、不建配置：只说明会发生什么。
      if (config?.servers.some((s) => s.name === req.name)) {
        console.log(`! ${req.name}: 已在舰队里（换个名字，或先 flotilla remove ${req.name} --confirm）`);
        process.exitCode = 1;
        return;
      }
      const keyPath = req.keyRef ?? fleetKeyPath;
      const pubPath = `${keyPath.replace(/^~(?=$|\/)/, process.env.HOME ?? "")}.pub`;
      console.log(`预演：自管本机 ${req.user}@127.0.0.1（未写入任何文件）`);
      if (!existsSync(pubPath)) {
        console.log(`  会生成密钥 ${keyPath}`);
        console.log(`  会把公钥${localhostOnly ? '（加 from="127.0.0.1,::1" 限制）' : ""}写入 ~/.ssh/authorized_keys`);
      } else {
        const r = installPublicKeyLocally(readFileSync(pubPath, "utf8"), undefined, { localhostOnly, dryRun: true });
        console.log(`  ${localAkLine(r, true)} ${r.authorizedKeysPath}`);
      }
      console.log(`  会把 "${req.name}" 加入 ${cfgPath}。去掉 --dry-run 正式添加。`);
      return;
    }
    const key = req.keyRef ? { publicKey: ensureFleetKeyPair(req.keyRef).publicKey, privateKeyPath: req.keyRef } : fleetKey();
    req.keyRef = key.privateKeyPath;
    const installed = installPublicKeyLocally(key.publicKey, undefined, { localhostOnly });
    console.log(`自管本机 ${req.user}@127.0.0.1（免密）`);
    console.log(`  ${localAkLine(installed, false)} ${installed.authorizedKeysPath}`);
    console.log("  撤销本机访问：删除 authorized_keys 中该行即可；sshd 配置未被改动。");
    if (!installed.restricted) {
      console.log('  加固（可选）：重跑加 --localhost-only，或在 authorized_keys 中给该行加 from="127.0.0.1,::1" 前缀，让 fleet 密钥只能本机使用。');
    }
  }

  const createUserName = flags.has("--create-user") ? (flags.get("--create-user") ?? "flotilla") : undefined;
  const options = {
    createUser: createUserName ? { name: createUserName, sudo: !flags.has("--no-sudo") } : undefined,
    fleetKey,
    password: local ? undefined : makePasswordSource(promptHidden),
    passwordFirst: flags.has("--bootstrap"),
    passwordOnly: flags.has("--password-only"),
    // A fleet key installed by an earlier add (or re-add) is worth a try before any password.
    // Keys ssh would not try for this host on its own: every usable key in
    // ~/.ssh (e.g. one only named under another Host), then the fleet key.
    deps: { sshG, extraKeys: [...listLocalPrivateKeys(), ...(existsSync(fleetKeyPath) ? [fleetKeyPath] : [])] },
  };

  let fleet = config?.servers ?? [];
  const failed = [];
  for (const req of requests) {
    if (dryRun) {
      try {
        // Same candidates the real run would try (incl. other ~/.ssh keys and the fleet key).
        const plan = planServer(req, { ...options.deps, fleetServers: fleet.map((s) => s.name) });
        const known = plan.knownKeys;
        const creds = plan.candidates.length ? plan.candidates.map((c) => c.label).join(", ") : "无（会提示输入一次密码）";
        console.log(
          `+ ${req.name}: ${plan.server.user}@${plan.server.host}:${plan.server.port} tier=${plan.server.group} role=${plan.server.role}` +
            `${plan.server.via ? ` via=${plan.server.via}` : ""} 凭据=[${creds}] host key=${known.length ? "known_hosts" : "TOFU"}`,
        );
        fleet = [...fleet, plan.server];
      } catch (err) {
        failed.push(req.name);
        console.log(`! ${req.name}: ${explainOnboardError(err, req).join("\n  ")}`);
      }
      continue;
    }

    const label = req.host ? `${req.user ? `${req.user}@` : ""}${req.host}${req.port ? `:${req.port}` : ""}` : `ssh 别名 ${req.sshAlias ?? req.name}`;
    console.log(`${requests.length > 1 ? "\n" : ""}连接 ${req.name}（${label}）...`);
    let result;
    try {
      result = await onboardServer(req, { ...options, fleet });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      audit({ kind: "execution", tool: "fleet-add", command: `add server "${req.name}"`, hosts: [req.name], outcome: "failed", reason, approver: "cli" });
      const lines = explainOnboardError(err, req);
      if (local && !(err instanceof OnboardError && err.code === "duplicate")) {
        lines.push("  本机自管需要 sshd 运行且允许密钥登录（Debian/Ubuntu: apt install openssh-server && systemctl enable --now ssh；确认 sshd_config 的 PubkeyAuthentication 未关闭）。");
      }
      if (requests.length === 1) die(lines.join("\n"), 1);
      failed.push(req.name);
      console.log(`  ✗ ${lines.join("\n    ")}`);
      continue;
    }

    const text = readFileSync(cfgPath, "utf8");
    try {
      writeFileSync(cfgPath, appendServerToConfig(text, result.server), "utf8");
    } catch (err) {
      die(err instanceof Error ? err.message : String(err), 1);
    }
    chmodSync(cfgPath, 0o600);
    fleet = [...fleet, result.server];
    audit({ kind: "execution", tool: "fleet-add", command: `add server "${req.name}" (${result.method})`, hosts: [req.name], outcome: "ok", approver: "cli" });
    const keychainMissing = Boolean(result.passwordToStore) && !(await defaultKeychainBackend());
    printAdded(result, cfgPath, req, keychainMissing);
    if (result.passwordToStore) {
      for (const line of await storePassword(req.name, result.passwordToStore, result.probe.uid === 0)) console.log(`  ${line}`);
    }
    if (flags.has("--verbose")) console.log(buildServerToml(result.server));
  }

  if (dryRun) {
    console.log(
      failed.length
        ? `\n${failed.length} 台有问题，见上。`
        : "\n离线预演完成（只读了 ssh 配置和 known_hosts，没有连接服务器）。去掉 --dry-run 正式添加。",
    );
    process.exitCode = failed.length ? 1 : 0;
    return;
  }
  const added = requests.length - failed.length;
  if (requests.length > 1) console.log(`\n完成：成功 ${added} 台${failed.length ? `，失败 ${failed.length} 台（${failed.join(", ")}）` : ""}`);
  if (added > 0) {
    const first = requests.find((r) => !failed.includes(r.name));
    console.log(`\n下一步：flotilla exec-read ${first.name} uptime   ·   运行中的 MCP server 已自动热重载，新机器即刻可用`);
  }
  process.exitCode = failed.length ? 1 : 0;
}

function runDiscover(ctx) {
  const sshCfg = process.env.FLOTILLA_SSH_CONFIG || undefined;
  const inFleet = new Set(ctx.config?.servers.map((s) => s.name) ?? []);
  const aliases = listSshConfigAliases(sshCfg);
  if (aliases.length === 0) {
    console.log("~/.ssh/config 里没有具体的 Host 条目。直接加：flotilla add <名字> --host <IP>（或 user@host）");
    return;
  }
  let addable = 0;
  for (const alias of aliases) {
    if (inFleet.has(alias)) {
      console.log(`= ${alias}  已在舰队`);
      continue;
    }
    try {
      const eff = resolveSshHost(alias, undefined, sshCfg);
      const known = knownHostKeys(eff.hostKeyAlias ?? eff.hostname, eff.port, eff.knownHostsFiles);
      addable++;
      console.log(
        `+ ${alias}  ${eff.user}@${eff.hostname}:${eff.port}${eff.proxyJump ? `  via ${eff.proxyJump}` : ""}` +
          `${eff.proxyCommand ? "  ProxyCommand(不支持)" : ""}  host key: ${known.length ? "known_hosts" : "未知(TOFU)"}`,
      );
    } catch (err) {
      console.log(`! ${alias}  ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  if (addable > 0) console.log("\n导入：flotilla import-ssh <别名...>  或  flotilla import-ssh --all（先加 --dry-run 预演）");
}

function runRemove(rest, ctx) {
  const { configPath, audit, die } = ctx;
  const name = rest[0] && !rest[0].startsWith("--") ? rest[0] : die("remove 需要服务器名称");
  const dryRun = rest.includes("--dry-run");
  if (!dryRun && !rest.includes("--confirm")) die(`将从舰队移除 "${name}"（只改本地配置，不碰服务器）——确认请加 --confirm，或 --dry-run 先预演`, 1);
  const cfgPath = resolve(configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
  let next;
  try {
    next = removeServerFromConfig(readFileSync(cfgPath, "utf8"), name);
  } catch (err) {
    die(editErrorZh(err, name), 1);
  }
  if (dryRun) {
    console.log(`预演：将从 ${cfgPath} 移除 "${name}"（未写入；去掉 --dry-run 并加 --confirm 正式移除）`);
    return;
  }
  writeFileSync(cfgPath, next, "utf8");
  chmodSync(cfgPath, 0o600);
  audit({ kind: "execution", tool: "fleet-remove", command: `remove server "${name}"`, hosts: [name], outcome: "ok", approver: "cli" });
  console.log(`✓ 已从 ${cfgPath} 移除 "${name}"。若存过密码：flotilla keychain delete ${name}`);
}

function runSet(rest, ctx) {
  const { configPath, audit, die } = ctx;
  const name = rest[0] && !rest[0].startsWith("--") ? rest[0] : die("set 需要服务器名称");
  const get = (flag) => {
    const i = rest.indexOf(flag);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const patch = {
    role: get("--role"),
    group: get("--tier") ?? get("--group"),
    tags: get("--tags") !== undefined ? get("--tags").split(",").filter(Boolean) : undefined,
    readOnly: rest.includes("--read-only") ? true : rest.includes("--no-read-only") ? false : undefined,
    user: get("--user"),
    port: get("--port") !== undefined ? Number(get("--port")) : undefined,
  };
  if (Object.values(patch).every((v) => v === undefined)) {
    die("set 至少要改一项：--role <viewer|operator|admin> --tier <prod|staging|dev|…> --tags a,b --read-only/--no-read-only --user u --port n");
  }
  const cfgPath = resolve(configPath ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath());
  let before;
  let next;
  try {
    before = readFileSync(cfgPath, "utf8");
    next = setServerFields(before, name, patch);
  } catch (err) {
    die(editErrorZh(err, name), 1);
  }
  if (rest.includes("--dry-run")) {
    console.log(`预演 "${name}"（未写入；去掉 --dry-run 正式修改）：`);
    for (const line of setDiffLines(before, next, name)) console.log(`  ${line}`);
    return;
  }
  writeFileSync(cfgPath, next, "utf8");
  chmodSync(cfgPath, 0o600);
  const summary = Object.entries(patch)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k === "group" ? "tier" : k}=${JSON.stringify(v)}`)
    .join(" ");
  audit({ kind: "execution", tool: "fleet-set", command: `set ${summary} on "${name}"`, hosts: [name], outcome: "ok", approver: "cli" });
  console.log(`✓ "${name}": ${summary}`);
}

/** set 预演：按解析后的生效值（含默认值）逐项列出 旧 → 新。 */
function setDiffLines(beforeText, afterText, name) {
  const pick = (text) => {
    const s = parseFleetConfig(text).servers.find((x) => x.name === name) ?? {};
    return { role: s.role, tier: s.group, tags: (s.tags ?? []).join(",") || "(无)", readOnly: s.readOnly ?? false, user: s.user, port: s.port };
  };
  const a = pick(beforeText);
  const b = pick(afterText);
  const lines = Object.keys(b)
    .filter((k) => String(a[k]) !== String(b[k]))
    .map((k) => `${k}: ${a[k] ?? "(未设置)"} → ${b[k]}`);
  return lines.length ? lines : ["没有变化（这些值本来就是这样）"];
}

/** 修改配置（set/remove）时的核心层错误 → 中文。 */
function editErrorZh(err, name) {
  const msg = err instanceof Error ? err.message : String(err);
  let m;
  if (/^No server named/.test(msg)) return `舰队里没有 "${name}"（flotilla list 查看现有机器）`;
  if ((m = /is the jump host \(via\) for (.+?) —/.exec(msg))) return `"${name}" 是 ${m[1]} 的跳板机：先移除它们，或用 flotilla set 让它们改走别的跳板机`;
  if ((m = /^Edit would produce an invalid config: ([\s\S]*)$/.exec(msg))) return `改完的配置不合法，已放弃修改：\n${m[1]}`;
  if ((m = /^Could not set (\w+)/.exec(msg))) return `无法安全修改 ${m[1] === "group" ? "tier" : m[1]}（配置写法特殊），请手动编辑配置文件`;
  if (/has no \[\[servers\]\] block/.test(msg)) return `"${name}" 是用内联表写的，无法自动修改，请手动编辑配置文件`;
  return msg;
}

/** fleet.mjs 的入口：处理成员管理命令，返回 false 表示不是这里的命令。 */
export async function runOnboardingCommand(cmd, rest, ctx) {
  switch (cmd) {
    case "add":
    case "import-ssh":
      await runAdd(cmd, rest, ctx);
      return true;
    case "discover":
      runDiscover(ctx);
      return true;
    case "remove":
      runRemove(rest, ctx);
      return true;
    case "set":
      runSet(rest, ctx);
      return true;
    default:
      return false;
  }
}
