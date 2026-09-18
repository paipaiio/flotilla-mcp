<div align="center">

# Flotilla

**多服务器 SSH MCP server —— 一条命令扇出到整个舰队**

target 表达式 · rolling 执行带熔断 · 跨机比对 · 策略引擎 + 审批门 · 可篡改检测的审计日志

[English](./README_en.md) · [文档](#目录) · [快速开始](#快速开始) · [路线图](#路线图)

[![CI](https://github.com/paipaiio/flotilla-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/paipaiio/flotilla-mcp/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](./LICENSE)
[![Node.js ≥ 20](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![npm](https://img.shields.io/npm/v/flotilla-mcp.svg)](https://www.npmjs.com/package/flotilla-mcp)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fpaipaiio%2Fflotilla--mcp-2496ED?logo=docker&logoColor=white)](https://github.com/paipaiio/flotilla-mcp/pkgs/container/flotilla-mcp)

</div>

---

Flotilla 把"逐台 SSH 20 台机器"变成"声明一次意图，安全地执行"。它让 AI agent 通过 MCP 协议接管你的整个服务器舰队——但每一步都有策略引擎、审批门和审计链兜底。

```
你: "重启所有 web 节点的 myapp，rolling，一次两台"
        │
        ▼
  fleet-resolve 预演命中 → 策略引擎逐台过 → 审批门弹窗
        │
        ▼
  rolling 扇出（批次失败即熔断）→ 全程进哈希链审计日志
```

## 目录

- [为什么是 Flotilla](#为什么是-flotilla)
- [功能亮点](#功能亮点)
- [28 个工具](#28-个工具)
- [快速开始](#快速开始)
- [HTTP Gateway（v2 首个切片）](#http-gatewayv2-首个切片)
- [Target 表达式](#target-表达式)
- [安全模型](#安全模型)
- [远程配置与热重载](#远程配置与热重载)
- [Docker](#docker)
- [路线图](#路线图)
- [贡献](#贡献)
- [License](#license)

## 为什么是 Flotilla

大多数 SSH MCP 工具解决的是"让 AI 操作**一台**服务器"。Flotilla 从第一天就是**舰队视角**设计的：

- **一次调用，命中整个舰队**——target 表达式（`group:prod`、`tag:web !web-3`、`all`）把一条命令扇出到 N 台机器
- **执行有战术**——并行求快、串行求稳、**rolling + 熔断**求安全：批次失败自动停，不会把好机器一起拖下水
- **比对是一等公民**——`fleet-diff` 一条命令告诉你全舰队的版本/配置是否漂移
- **安全不是开关是默认值**——策略矩阵、审批门、哈希链审计全部默认开启，关掉要写进配置里
- **配置能集中管**——放 Git 私有仓库，各端定时拉取 + 热重载，50 台机器改一处

## 功能亮点

- 🎯 **Target 表达式寻址** — `group:prod !web-3`、`tag:web,tag:arm`、`all`，先 `fleet-resolve` 预演再执行
- 🚦 **三种扇出策略** — 并行、串行、rolling（批次失败自动熔断，prod 破坏性操作默认 rolling）
- 🛡️ **六层安全模型** — 永禁清单、角色×层级矩阵、资源白名单、审批门（MCP elicitation 弹窗 + JIT 免批）、哈希链审计、命令配额
- 🤖 **AI 辅助审批** — 破坏性命令触发审批时，本地 LLM 先生成风险评估卡（只做建议，永不做判决；提示注入防护内置）
- 🔍 **跨机比对** — `fleet-diff` 比命令输出，`fleet-diff-file` 按 sha256 比文件/目录
- 📦 **SFTP 批量分发/收集** — `fleet-push` / `fleet-pull`，按机路径白名单
- 🔁 **服务器间直传** — `fleet-copy` / `fleet-sync`：A→B 经控制机内存中转，**服务器之间不用互通、不用互配 SSH 密钥**
- 🖥️ **tmux 持久会话** — 断连不死，MCP server 重启也不死
- 🩺 **零依赖体检** — `doctor` 一键全舰队 HEALTHY/WARN/CRIT
- ⚙️ **systemd 全家桶** — 服务状态、日志、启停重载，带服务白名单
- 🔄 **YAML 工作流** — 多步骤编排、变量插值、失败回滚
- ➕ **一行加机器** — `fleet add --bootstrap` 一次性密码首连自动装公钥，新机器零准备入网；`fleet-add` 探测主机、钉死 host key、热重载生效
- ☁️ **配置集中管理** — 配置放 Git 私有仓库，各端定时拉取 + 热重载
- 🐳 **Docker 双架构** — amd64 + arm64（树莓派友好），非 root 运行

## 28 个工具

<details open><summary><b>舰队管理</b></summary>

| 工具 | 说明 |
|---|---|
| `fleet-list` | 一览服务器/分组/标签/层级/角色 |
| `fleet-resolve` | 预演 target 表达式，跑之前先看清命中哪些机器 |
| `fleet-add` | 加机器：探测（hostname/uid/tmux/host key）→ 钉 key → 追加配置 → 热重载 |
| `config-pull` / `config-reload` | 远程配置拉取（强制审批）/ 本地热重载 |
| `fleet-grants` | 查看 / 一键清空活跃的 JIT 免批授权 |

</details>

<details open><summary><b>命令执行</b></summary>

| 工具 | 说明 |
|---|---|
| `exec-read` | 白名单只读命令，并行扇出 |
| `exec` | 任意命令，完整策略引擎 + 审批门 |
| `exec-sudo` | sudo 提权；强制审批；密码走 env → stdin，不进 argv |
| `signal-process` | 给数字 PID 发 INT/TERM/KILL/HUP，强制审批 |

</details>

<details open><summary><b>比对与观测</b></summary>

| 工具 | 说明 |
|---|---|
| `fleet-diff` | 一条只读命令跑全场，按相同输出分组 |
| `fleet-diff-file` | 按 sha256 比对文件/目录，漂移、缺失、失败分组报告 |
| `metrics-snapshot` | 负载、内存、磁盘、进程——零依赖探针 |
| `doctor` | 一键体检：每台 HEALTHY / WARN / CRIT |
| `logs-tail` | 限时跟踪 journal 或文件，本地 grep 过滤 |

</details>

<details open><summary><b>文件与服务</b></summary>

| 工具 | 说明 |
|---|---|
| `fleet-push` / `fleet-pull` | SFTP 批量分发 / 收集文件，多机默认 rolling |
| `fleet-copy` | A→B 单文件直传：控制机内存中转，不落盘；两端过策略，跨 tier 强制审批 |
| `fleet-sync` | A→B 目录同步（rsync 语义）：sha256 增量，默认 dry-run，`--delete` 强制审批 |
| `service-status` / `service-logs` / `service-control` | 全舰队的 systemd 管理 |

</details>

<details open><summary><b>会话与编排</b></summary>

| 工具 | 说明 |
|---|---|
| `session-start` / `session-list` / `session-output` / `session-send` / `session-kill` | 断连不死的 tmux 持久会话 |
| `workflow-run` | YAML 工作流：有序步骤、插值、回滚 |

</details>

## 快速开始

### 安装

```bash
# npm（推荐）
npm install -g flotilla-mcp

# 或 Docker
docker pull ghcr.io/paipaiio/flotilla-mcp:latest

# 或源码
git clone https://github.com/paipaiio/flotilla-mcp.git && cd flotilla-mcp
pnpm install && pnpm build
```

### 配置

零手动初始化：配置目录/文件不存在时 `flotilla add` 会自动创建（目录 700 / 文件 600），权限松了也会自动修好并提示。下面直接加机器即可：

逐台加机器（探测 + 钉 host key 一步到位，`flotilla` 是 npm 包自带的 CLI）：

```bash
# 新机器还没装过公钥？一条命令入网（一次性密码首连 → 自动装公钥 → 之后全走密钥）：
flotilla add web-1 --host 10.0.1.11 --user root --bootstrap --group prod --tags web
# 密码交互隐藏输入，或用 FLOTILLA_BOOTSTRAP_PASSWORD 环境变量传入（不进 shell 历史）。
# 默认生成舰队专用密钥 <配置目录>/fleet_ed25519；想复用已有私钥加 --key <path>。

# 机器上已有公钥时直接登记：
flotilla add web-1 --host 10.0.1.11 --user deploy --auth key --key ~/.ssh/id_ed25519 --group prod --tags web
```

（默认读平台配置目录；自定义路径加 `--config <path>`。`--bootstrap` 只在 CLI 提供——密码不作为 MCP 工具参数传递。）

或手编（完整字段见 [config.example.toml](./config.example.toml)）：

```toml
[defaults]
approvalMode = "ask-destructive"   # auto | ask-destructive | ask-all | deny
commandQuotaPerDay = 500           # 滚动 24h 内命令类调用上限，0 = 不限；防 agent 失控死循环

[[servers]]
name = "web-1"
host = "10.0.1.11"
port = 22                          # 非标配端口写这里
user = "deploy"
auth = "agent"                     # agent | key | password | certificate（密码从环境变量读，不落文件）
group = "prod"                     # 策略层级，缺省按名字推断，推断不出按最严的 prod
tags = ["web"]

[[servers]]
name = "db-1"
host = "10.0.2.11"
user = "deploy"
auth = "key"
keyRef = "~/.ssh/id_ed25519"
group = "prod"
via = "bastion"                    # 经跳板机（ProxyJump）
```

### 接入 MCP 客户端

```bash
# Claude Code（npm 全局安装后直接用 flotilla-mcp 命令）
claude mcp add --transport stdio flotilla -- flotilla-mcp
```

任何兼容 stdio 的 MCP 客户端同理：命令指向 `flotilla-mcp`（或源码安装的 `packages/mcp-stdio/dist/index.js`），传 `--config <path>` 或设 `FLOTILLA_CONFIG`。Codex 配置示例：

```toml
# ~/.codex/config.toml
[mcp_servers.flotilla]
command = "flotilla-mcp"
```

### HTTP Gateway（v2 首个切片）

同一套引擎常驻成 HTTP 服务：全部工具、策略引擎、配额、审计原样可用，传输层换成无状态 Streamable HTTP MCP。

```bash
# 无 token 直接拒绝启动——没认证的舰队网关 = 远程 root shell
export FLOTILLA_GATEWAY_TOKEN=$(openssl rand -hex 32)
flotilla-gateway --config ~/.config/flotilla/config.toml --host 127.0.0.1 --port 8080

# /mcp 每个请求都要 Bearer token；/healthz 开放给负载均衡探活
curl -s http://127.0.0.1:8080/healthz
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $FLOTILLA_GATEWAY_TOKEN" \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

默认只监听 127.0.0.1；要对局域网开放请放在反向代理 / TLS 之后。HTTP 客户端暂不支持交互式 elicitation：审批类操作会明确拒绝并提示用 `confirm=true`（若策略允许），缺失密码请走环境变量或 OS keychain。

**一行入网（Tailscale 式）**：运营方签发一次性入网令牌，新机器自助完成入网——节点自装舰队公钥（密码不过线），网关回探 SSH 通过后原子写入配置并热重载：

```bash
# 运营方：签发令牌（仅显示一次，落盘的是 sha256 哈希）
curl -X POST http://127.0.0.1:8080/api/enroll/tokens \
  -H "Authorization: Bearer $FLOTILLA_GATEWAY_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"rack-5"}'
# → {"token":"flt_…", …}

# 新机器（root 执行；首次在不信任网络可加 --fingerprint 钉住网关证书）：
curl -fsSL http://127.0.0.1:8080/join.sh | sudo sh -s -- --token flt_…
```

令牌支持 TTL / 次数上限 / 吊销（`DELETE /api/enroll/tokens/<id>`）；回连地址取入网请求的 TCP 对端（要求网关能直连新机的 SSH，与全舰队一致）。

**集中审计与合规导出**：引擎的哈希链审计日志在网关侧汇聚，可同步到外部 sink，并按需导出报表：

```bash
# 审计 sink（可选，env 配置）：转发到 webhook 或归档文件，失败只记日志不影响网关
FLOTILLA_AUDIT_WEBHOOK_URL=https://siem.internal/hook FLOTILLA_AUDIT_WEBHOOK_TOKEN=…
FLOTILLA_AUDIT_SINK_FILE=/mnt/audit/flotilla.jsonl

# 合规导出（运营方 Bearer，过滤器 AND 组合，CSV/JSON，默认最新在前、上限 1 万行）
curl -H "Authorization: Bearer $FLOTILLA_GATEWAY_TOKEN" \
  "http://127.0.0.1:8080/api/audit/export?from=2026-09-01&host=web-1&outcome=failed&format=csv"
```

**Web 控制台**：网关直接伺服一个零依赖的静态控制台（`packages/gateway/console/`，无构建步骤），浏览器打开 `http://<gateway>/console/`（`/` 会 302 过去），输入 Bearer token 登录后即可用：总览（引擎健康 + 服务器清单）、命令执行（只读/带确认，走同一套策略引擎）、入网管理（签发/吊销令牌，显示一行入网命令）、审计（过滤 + CSV 导出）。静态文件不含任何秘密，所有 API 调用仍由服务端逐一鉴权——控制台没有新增攻击面。

**MCP 聚合入口**：一个 `/mcp` 端点不止挂舰队工具——用 JSON 配置把外部 MCP server（本地 stdio 命令或远程 HTTP 端点）挂载进来，工具以 `<上游名>__<工具名>` 前缀出现在同一个 tools/list 里，调用原样代理转发：

```bash
# upstreams.json：stdio 起本地命令，http 带鉴权头连远端
cat > upstreams.json <<'EOF'
[
  { "name": "fs", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"] },
  { "name": "peer", "transport": "http", "url": "http://10.0.0.9:8080/mcp",
    "headers": { "Authorization": "Bearer <对方网关 token>" } }
]
EOF
flotilla-gateway --config fleet.toml --upstreams upstreams.json   # 或 FLOTILLA_GATEWAY_UPSTREAMS
# 之后客户端就能看到 fs__read_file、peer__fleet-list …
```

连接失败的上游不阻塞启动，在 `/healthz` 里显示 `error` 状态和原因。上游工具是运营方显式信任的"外来代码"，不舰队策略引擎管辖（网关 Bearer 仍然兜底整面）；参数以自由对象透传，上游自带的 schema 负责校验。

常驻部署（Docker 镜像 / systemd unit / Caddy + nginx TLS 模板）见 [deploy/README.md](./deploy/README.md)；发布版网关镜像为 `ghcr.io/paipaiio/flotilla-gateway`。

### 开始使唤

> "看下所有 prod 机器的磁盘" → `exec-read` 打 `group:prod`
> "所有 web 节点的 nginx 版本一致吗？" → `fleet-diff nginx -v` 打 `tag:web`
> "prod 上重启 myapp，rolling，一次两台" → `service-control` 自动带熔断

## Target 表达式

```
web-1                     单台
group:web-prod            配置的分组（或层级名：group:prod）
tag:web                   按标签
all                       全部
group:prod !web-3         排除
tag:web,tag:arm           并集
["web-1", "web-2"]        显式列表
```

破坏性扇出之前，先 `fleet-resolve` 预演。

## 安全模型

六层纵深防御：

1. **永禁清单** — `rm -rf /`、`curl | sh`、写 `authorized_keys`、fork 炸弹……对所有人拒绝，不可配置关闭
2. **角色 × 层级矩阵** — `viewer` / `operator` / `admin` × `prod` / `staging` / `dev`。`group` 缺省按名字推断，推断不出一律按最严的 **prod**
3. **资源白名单** — 按服务器的 `scopes.paths` / `scopes.services` / `scopes.commands` 进一步收窄（只收窄，不放宽）
4. **审批门** — 破坏性/特权操作走 MCP elicitation 交互弹窗；`confirm` 标志默认 **fail-closed**（`defaults.allowConfirmFlag = true` 或 `FLOTILLA_ALLOW_CONFIRM_FLAG=1` 才开启）。模型无法自我审批。弹窗可勾选「N 分钟内不再询问」生成 **JIT grant**（纯内存、重启即失效），`fleet-grants` 随时查看/一键清空
5. **审计** — 每个决策和执行都落 JSONL，三层脱敏 + SHA-256 哈希链，篡改可检测
6. **命令配额** — `defaults.commandQuotaPerDay` 限制滚动 24h 内命令类调用次数，状态落盘（重启不清零），防 agent 失控死循环

另外：

- 凭据永不进 argv、永不进日志：SSH agent → 密钥文件 → 环境变量（`FLOTILLA_<NAME>_PASSWORD` / `FLOTILLA_SUDO_PASSWORD`……）→ **OS 钥匙串**（`flotilla keychain set <name> [--sudo]` 存入，配置文件零敏感信息）
- 主机密钥：进程内 TOFU，`trustedHostKey` 钉死跨重启；`fleet-add` 首次接触即钉
- **算法白名单默认开启**（RFC 9142）：禁 SHA-1（ssh-rsa/group1/hmac-sha1）和 CBC；老机器可用 `allowLegacyAlgorithms = true` 单台豁免（建议升级 sshd）
- 配置文件权限强制 `0600`；`readOnly` 服务器拒绝一切写操作
- ⚠️ **不要指向 root 账户。** 用低权限账户 + NOPASSWD sudoers 白名单；不要在 prod 上开 `approvalMode = "auto"`

## 远程配置与热重载

服务器多了以后，把 `config.toml` 放进 Git 私有仓库，各端定时拉取：

```toml
[remote]
url = "https://raw.githubusercontent.com/<org>/<repo>/main/fleet.toml"
tokenEnv = "FLOTILLA_CONFIG_TOKEN"   # GitHub PAT，走 Authorization: Bearer
refreshMs = 300000                    # 每 5 分钟自动拉取+热重载；缺省只手动
```

拉取 = 完整校验 → 旧文件时间戳备份 → 原子写入 → 热重载。坏负载永远不碰本地文件。日常改配置直接编辑本地文件也行——watcher 300ms 内自动生效。

## Docker

```bash
docker run -i --rm \
  -v ~/.config/flotilla/config.toml:/home/node/.config/flotilla/config.toml:ro \
  -v ~/.ssh:/home/node/.ssh:ro \
  ghcr.io/paipaiio/flotilla-mcp:latest
```

非 root 运行，amd64 + arm64 双架构。

## 路线图

- **v1.0** ✅ — fleet-add、审计、远程配置拉取 + 热重载、双语 README、npm 发布、Docker、CI/CD
- **v1.x** ✅ — 服务器间操作（fleet-copy / fleet-sync / 文件比对）、命令配额、JIT 审批授权、算法白名单（RFC 9142）、系统 keychain、`fleet add --bootstrap` 一键加机
- **v2 ✅ 全部收官** — Gateway 常驻服务（无状态 HTTP MCP + Bearer 认证）；常驻部署（Docker / systemd / TLS 模板）；Tailscale 式一行入网；集中审计（sink 转发 + 合规导出）；Web 控制台（/console/ 静态 SPA）；MCP 聚合入口（单端点挂外部 MCP server）；CA 证书认证（短寿用户证书 + fleet CA，见下文）
- **v3 设想** — 目标机轻量 agent、DAG 编排、团队协作

### CA 证书认证（v2 收官切片）

第四种认证方式 `auth = "certificate"`：不再把每台机器的公钥钉进 `authorized_keys`，而是由一把 fleet CA（ed25519，自动创建于 config 同目录的 `fleet_ca` / `fleet_ca.pub`）签**短寿用户证书**（默认 8 小时，`certValiditySeconds` 可调 300–604800 秒），目标机 sshd 只信任 CA 一行。

```toml
[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
auth = "certificate"
keyRef = "~/.ssh/id_ed25519"     # 被认证的私钥；principals 自动 = user
certValiditySeconds = 3600       # 可选，默认 28800（8h）；剩 1/4 寿命自动重签
```

目标机一次性装机（把 CA 公钥装进 sshd 的 TrustedUserCAKeys，drop-in 到 `sshd_config.d`，幂等）：

```bash
# 从 MCP 工具拿到命令后 root 执行；fleet onboard 的服务器可以直接用该工具
install -d -m 755 /etc/ssh/sshd_config.d && \
  printf '%s\n' '<fleet_ca.pub 内容>' > /etc/ssh/flotilla-ca.pub && \
  printf '%s\n' 'TrustedUserCAKeys /etc/ssh/flotilla-ca.pub' > /etc/ssh/sshd_config.d/60-flotilla-ca.conf && \
  systemctl reload ssh
```

工作原理一句话：ssh2 客户端协议无法直接出示 OpenSSH 证书，所以 flotilla 为每个 server 起了一个**迷你 ssh-agent**（进程内 UNIX socket，实现 OpenSSH agent 协议的 IDENTITIES/SIGN 两种请求），证书由它代持、签名用它背后的私钥——和 OpenSSH 本人用 agent 持证上场的机制完全一致。换来两个运维收益：证书泄露 8 小时后自动作废；吊销整支舰队的访问 = 在目标机上删一行 CA，而不是逐台翻 authorized_keys。

注意：enroll（一行入网）流程不变——先用 password/agent 认证把机器加进来，再执行上面的 CA 装机命令并切换 `auth = "certificate"`。CI 没有对真实 sshd 的端到端证书登录测试（环境没有 sshd 目标），证书正确性由 `ssh-keygen -L` 与验签测试保证。

## 贡献

私有打磨期暂不开放外部贡献。开源后：issue 提 bug / 需求，PR 请先开 issue 讨论方向。所有 PR 需要通过 CI（build + 460+ 测试 + Docker 构建）。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=paipaiio/flotilla-mcp&type=Date)](https://star-history.com/#paipaiio/flotilla-mcp&Date)

## License

**GNU Affero General Public License v3.0**（见 [LICENSE](./LICENSE)）：

- ✅ 自由使用、修改、分发——包括企业内部生产使用
- ⚠️ Copyleft：分发或**通过网络提供**基于 Flotilla 的服务时，必须向用户公开完整源代码（AGPL 的网络条款）
- 💼 不想受 AGPL 约束（例如闭源商用）？提供商业授权——通过 [GitHub](https://github.com/paipaiio/flotilla-mcp) 联系
