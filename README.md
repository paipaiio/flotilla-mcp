<div align="center">

<img src="./assets/logo.png" alt="Flotilla" width="160" />

# Flotilla

**多服务器 SSH MCP：让 AI 一次管理所有服务器**

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
- [安装与运行模式](#安装与运行模式)
- [工具一览](#工具一览)
- [快速开始](#快速开始)
- [HTTP Gateway（v2 首个切片）](#http-gatewayv2-首个切片)
- [Target 表达式](#target-表达式)
- [安全模型](#安全模型)
- [远程配置与热重载](#远程配置与热重载)
- [Docker](#docker)
- [v1.1.0 更新](#v110-更新)
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
- ➕ **一行加机器** — `flotilla add <ssh别名>` 或 `flotilla add root@IP`：本机密钥/ssh-agent 能登就免密；登不上就提示输入一次密码，自动装上专用密钥后改走密钥；只允许密码的机器自动改用密码并存进系统钥匙串。host key 与 known_hosts 核对后钉死，热重载生效
- ☁️ **配置集中管理** — 配置放 Git 私有仓库，各端定时拉取 + 热重载
- 🐳 **Docker 双架构** — amd64 + arm64（树莓派友好），非 root 运行

## 安装与运行模式

做 Flotilla 的初衷就是「不想在多台服务器之间跳来跳去」——所以安装被压缩到三句命令。两种用法，按需选：

### 模式一：本地运行（自用首选）

装在自己的 MacBook / 工作机上，MCP 以 stdio 方式跑在本机，接进 Claude Code、Codex、Kimi、Cursor 等：

```bash
npm install -g flotilla-mcp                          # 1. 安装（Node ≥ 20）
flotilla add root@10.0.1.11                          # 2. 加机器：有密钥就免密，没有就提示输一次密码
claude mcp add flotilla -- flotilla-mcp              # 3. 接入 Claude Code（其它客户端见「接入 MCP 客户端」）
```

`~/.ssh/config` 里已有的机器直接 `flotilla add <别名>`，或 `flotilla discover` 一次全看。
私钥和配置只存在你自己的机器上，信任边界最清晰；审批弹窗、交互式确认全可用。

### 模式二：网站模式（团队 / 云端 agent）

部署到一台服务器，把整个舰队暴露为一个带 token 鉴权的 HTTPS MCP 端点。两个典型接法：

- **网站连接器**：Grok 等平台的自定义 MCP 连接器，直接填 URL + token
- **聚合服务**：Cloudflare 这类 MCP 聚合/代理服务背后挂它

一键部署脚本（Linux；有 Docker 用 Docker，有 Node ≥ 20 用 Node，都没有会询问后安装 Docker；可重复执行，重跑即升级）：

```bash
curl -fsSL https://raw.githubusercontent.com/paipaiio/flotilla-mcp/main/deploy/bootstrap.sh -o bootstrap.sh
bash bootstrap.sh   # 装完把 127.0.0.1:PORT 反代到 Caddy/nginx 并配 HTTPS（模板见 deploy/）
```

⚠ 网站模式（HTTP）没有审批弹窗：默认只能执行只读/安全命令。要允许变更，把对应机器设到 staging/dev
（`flotilla set <名字> --tier staging`），或在配置 `[defaults]` 里开 `allowConfirmFlag = true`。

fleet 随即成为 `https://mcp.example.com/mcp`。团队新机器入网只需一行
`curl -fsSL https://mcp.example.com/join.sh | sudo sh -s -- --token <令牌>`，
人和 agent 走同一个入口，同一套策略与审计。

## 工具一览

<details open><summary><b>舰队管理</b></summary>

| 工具 | 说明 |
|---|---|
| `fleet-list` | 一览服务器/分组/标签/层级/角色 |
| `fleet-resolve` | 预演 target 表达式，跑之前先看清命中哪些机器 |
| `fleet-discover` | 列出 `~/.ssh/config` 里还没纳入舰队的主机（只读） |
| `fleet-add` | 加机器：复用 ssh config / 本机密钥 / agent 免密连接 → host key 与 known_hosts 核对后钉死 → 追加配置 → 热重载；可选 `createUser` 自动建低权限用户 |
| `fleet-remove` / `fleet-set` | 移除机器 / 改 role、tier、tags、readOnly 等（保留配置里的注释，强制审批） |
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

<details open><summary><b>诊断与配置</b></summary>

| 工具 | 说明 |
|---|---|
| `runtime-info` | 运行时信息：版本、配置路径、钥匙串是否可用 |
| `credential-status` | 诊断每台机器的登录凭据；客户端支持时可在安全页面补录密码 |
| `setup-repair` | 把密码登录的机器迁移到舰队密钥（免密） |
| `config-apply` | 结构化修改远端 JSON/YAML/TOML 配置文件，变更集审批 + 备份回滚 |

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

加机器只有一条命令，flotilla 自动选最省事的方式（`flotilla` 是 npm 包自带的 CLI）：

```bash
flotilla add root@10.0.1.11              # 名字默认用 IP；非 22 端口写 root@IP:2222
flotilla add web-1 root@10.0.1.11        # 指定名字
flotilla add web-1                       # ~/.ssh/config 里的 Host 别名（HostName/User/Port/IdentityFile/ProxyJump 全从 ssh -G 取）
```

- **本机密钥 / ssh-agent 能登** → 直接用，不问任何问题
- **都登不上** → 提示输入一次登录密码（隐藏输入）→ 装上舰队专用密钥 `<配置目录>/fleet_ed25519` → 之后免密，**密码不保存**
- **服务器只允许密码登录**（路由器、NAS、部分托管主机）→ 自动改用密码方式，密码存进系统钥匙串（sudo 同用）
- host key 先和 `~/.ssh/known_hosts` 核对：不一致直接中止，**密码一个字节都不会发出去**；没记录则首次连接钉死
- 除了 ssh config 指定的密钥，`~/.ssh` 里其它可用私钥（比如只写在别的 Host 下的 `~/.ssh/muskzhou`）也会自动试一遍
- **服务器只接受密钥**（`PasswordAuthentication no`）→ 不再白问密码，直接列出三种办法：`--key <私钥>`、`ssh-add`，或把打印出来的舰队公钥加到服务器上

```bash
flotilla discover                        # ssh config 里还有哪些没纳入
flotilla import-ssh --all --dry-run      # 批量预演（离线：只读 ssh 配置，不连服务器）
flotilla import-ssh --all                # 批量导入（跳板机自动排前面）
flotilla add web-1 --create-user         # 不想用 root：首连时建低权限用户 flotilla 并改用它
                                         # sudo 只放行 systemctl status/start/stop/restart/reload，日志靠 systemd-journal 组免 sudo 读
flotilla add web-1 --password-only       # 明确只用密码登录
flotilla add --local                     # 纳管本机（Gateway 宿主机自己），免密
flotilla add --local --localhost-only    # 同上，并把该公钥限制为只能从本机使用（已存在的行会被收紧）
flotilla set web-1 --tier dev --role admin --dry-run   # 先看「旧 → 新」，不写文件
flotilla set web-1 --tier dev --role admin             # 改权限
flotilla remove web-1 --dry-run          # 预演；正式移出用 flotilla remove web-1 --confirm
```

每个子命令只接受自己用得上的参数：写错或写了不相干的参数会直接报错并列出可用参数，不会被悄悄忽略。
`add` / `import-ssh` / `set` / `remove` 都支持 `--dry-run`，预演不会写任何文件、不会生成密钥。

不写 `--tier` 时按名字推断（按完整单词认 `prod` / `staging` / `stg` / `dev` / `test` / `local` / `sandbox`，`latest` 这类词不会被当成 test；认不出一律 prod，最严：operator 在 prod 上不能执行破坏性命令）；
不写用户时跟 `ssh` 一样取 ssh config / 本机用户名。脚本里用 `FLOTILLA_BOOTSTRAP_PASSWORD` 传密码（不进 shell 历史）。
密码永远不作为 MCP 工具参数：AI 调 `fleet-add` 需要密码时，会弹出本机一次性安全页面让你输入。

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

本地模式（stdio，命令指向 `flotilla-mcp`）：

```bash
claude mcp add flotilla -- flotilla-mcp           # Claude Code
codex mcp add flotilla -- flotilla-mcp            # Codex
```

Kimi / Cursor / Claude Desktop 等用 `mcpServers` JSON 的客户端：

```json
{ "mcpServers": { "flotilla": { "command": "flotilla-mcp" } } }
```

网站模式（HTTP Gateway，带 token）：

```bash
claude mcp add --transport http flotilla https://mcp.example.com/mcp --header "Authorization: Bearer <token>"
codex mcp add flotilla --url https://mcp.example.com/mcp --bearer-token-env-var FLOTILLA_GATEWAY_TOKEN
```

接好后在客户端里说一句「列出我的服务器」验证（会调用 `fleet-list`）。非默认配置路径加 `--config <path>` 或设 `FLOTILLA_CONFIG`。

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
# 在新机器上执行；地址必须是新机器能访问到的网关地址（反代后的域名），不是 127.0.0.1
curl -fsSL https://mcp.example.com/join.sh | sudo sh -s -- --token flt_…
```

令牌支持 TTL / 次数上限 / 吊销（`DELETE /api/enroll/tokens/<id>`）；入网失败后在同一台机器重跑 join.sh 会续上原来的记录，不会耗掉单次令牌。回连地址取入网请求的 TCP 对端（要求网关能直连新机的 SSH）；`X-Forwarded-For` 只信本机/Docker 网桥上的反代，反代在别的机器上时用 `FLOTILLA_TRUSTED_PROXIES=<IP>` 声明。

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

常驻部署（Docker 镜像 / systemd unit / Caddy + nginx TLS 模板）见 [deploy/README.md](./deploy/README.md)；发布版网关镜像为 `ghcr.io/paipaiio/flotilla-mcp-gateway`。空白服务器冷启动、入网报错对照、反代必配头与重装清理清单见 [deploy/TROUBLESHOOTING.md](./deploy/TROUBLESHOOTING.md)（按真实部署踩坑沉淀）。

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
2. **角色 × 层级矩阵** — `viewer` / `operator` / `admin` × `prod` / `staging` / `dev`。层级写 `tier`（旧名 `group` 仍可用），大小写不敏感（`Prod` 也按 prod 管），缺省按名字推断，推断不出一律按最严的 **prod**。可用 `[policy.matrix]` 收紧内置矩阵（只能收紧，写了放宽的项会启动报错）：
   ```toml
   [policy.matrix.operator]
   staging = ["read-only", "safe"]   # staging 上 operator 也不许破坏性命令
   ```
3. **资源白名单** — 按服务器的 `scopes.paths` / `scopes.services` / `scopes.commands` 进一步收窄（只收窄，不放宽）
4. **审批门** — 破坏性/特权操作走 MCP elicitation 交互弹窗；`confirm` 标志默认 **fail-closed**（`defaults.allowConfirmFlag = true` 或 `FLOTILLA_ALLOW_CONFIRM_FLAG=1` 才开启）。模型无法自我审批。弹窗可勾选「N 分钟内不再询问」生成 **JIT grant**（纯内存、重启即失效），`fleet-grants` 随时查看/一键清空
5. **审计** — 每个决策和执行都落 JSONL，三层脱敏 + SHA-256 哈希链，篡改可检测
6. **命令配额** — `defaults.commandQuotaPerDay` 限制滚动 24h 内命令类调用次数（exec 系列、config-apply、session-start/send、logs-tail、workflow-run 共用一个额度，审批前就检查），状态落盘（重启不清零），防 agent 失控死循环

只读白名单看的是完整参数，不只是命令名：`sort -o`、`git branch -D`、`dmesg -c`、`sysctl -w` 这类会写东西的用法不算只读；`--out=` 这种缩写的长参数、`-Tc` 这种合并的短参数也一样能识别。

另外：

- 凭据永不进 argv、永不进日志：SSH agent → 密钥文件 → 环境变量（`FLOTILLA_<NAME>_PASSWORD` / `FLOTILLA_SUDO_PASSWORD`……）→ **OS 钥匙串**（`flotilla keychain set <name> [--sudo]` 存入，配置文件零敏感信息）
- 主机密钥：进程内 TOFU，`trustedHostKey` 钉死跨重启；`fleet-add` 首次接触即钉
- **算法白名单默认开启**（RFC 9142）：禁 SHA-1（ssh-rsa/group1/hmac-sha1）和 CBC；老机器可用 `allowLegacyAlgorithms = true` 单台豁免（建议升级 sshd）
- 配置文件权限强制 `0600`；`readOnly` 服务器拒绝一切写操作
- **root 账户自动收紧**：`user = "root"` 的机器上，破坏性命令永远走审批（`approvalMode = "auto"` 对它无效，JIT 免批也不生效）。更推荐 `flotilla add <name> --create-user`：首连时自动建低权限用户 + 受限 sudoers（visudo 校验），不用手动配置
- **Gateway 受限 token**：除管理员 token 外，可发多个只访问 `/mcp` 的受限 token，各带角色上限和可见目标，看不到的机器对它不存在；改舰队成员、上游 MCP 工具只允许管理员 token。文件只存哈希，增删即时生效：
  ```bash
  flotilla-gateway token create ci-readonly --role viewer --targets "tag:web"
  flotilla-gateway token create ops-all --role operator --all   # 全舰队必须显式写 --all
  flotilla-gateway token list
  flotilla-gateway token revoke ci-readonly
  ```

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

## v1.1.0 更新

**加机器**
- `~/.ssh` 里其它可用私钥会自动尝试；只接受密钥的服务器不再要密码，直接给出解决办法
- `--create-user` 建低权限用户时按 sudo 版本生成 sudoers 规则（≥1.9.10 用正则规则）
- `set` / `remove` / `add --local` 支持真正的 `--dry-run`；`--localhost-only` 会收紧已存在的公钥行
- 层级按完整单词推断，`Prod` / `PROD` 按 prod 处理

**命令行**
- 每个子命令只接受自己的参数，传错直接报错（以前会被忽略）
- `signal` 只允许单台机器

**策略与执行**
- 只读白名单检查参数（含缩写长参数、合并短参数），`$(...)` 里的命令也按最危险的那条判定
- 每日配额覆盖 workflow / session / logs-tail
- 工作流：审批时一并展示回滚步骤；`{{ steps.x.hosts }}` 可作目标；只有回滚全部成功才标记「已回滚」
- `fleet-sync`：有文件复制失败时不删除旧文件；校验清单被截断时拒绝同步
- `fleet-diff` 在 stdout 为空时比较 stderr；`fleet-diff-file` 把连不上的机器算作不一致
- CA 安装：`sshd -t` 失败会恢复原配置；重载失败或未生效都不再报成功

**Gateway 与控制台**
- 慢请求期间其它请求排队，等太久返回 503 + Retry-After，不再报 500；通知类消息不占队列
- 入网令牌吊销/过期后不能再完成 confirm；吊销会作废未完成的入网；令牌文件损坏时报错而不是清空
- 审计导出：错误日期返回 400，CSV 中和表格公式；审计 sink 不能指向审计日志本身
- 控制台：受限 token 不会被踢回登录页（管理页面自动隐藏）；点单台会替换「全部」；执行前强制重新解析目标；批准勾选用完即清；防连点
- 控制台静态目录不提供隐藏文件，不跟随指向目录外的软链接
- `token create` 必须写 `--targets` 或 `--all`

**升级注意**：脚本里如果给子命令传了它不用的参数，或者用 `token create` 时没写范围，现在会报错；部分以前被当成只读的写操作（见上）现在需要审批。

## 路线图

- **v1.0** ✅ — fleet-add、审计、远程配置拉取 + 热重载、双语 README、npm 发布、Docker、CI/CD
- **v1.x** ✅ — 服务器间操作（fleet-copy / fleet-sync / 文件比对）、命令配额、JIT 审批授权、算法白名单（RFC 9142）、系统 keychain、`flotilla add` 一键加机
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
