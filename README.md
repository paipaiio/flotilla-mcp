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

- [为什么是 Flotilla](#为什么是-flotilla对比-ssh-mcp)
- [功能亮点](#功能亮点)
- [24 个工具](#24-个工具)
- [快速开始](#快速开始)
- [Target 表达式](#target-表达式)
- [安全模型](#安全模型)
- [远程配置与热重载](#远程配置与热重载)
- [Docker](#docker)
- [路线图](#路线图)
- [贡献](#贡献)
- [License](#license)

## 为什么是 Flotilla（对比 ssh-mcp）

[ssh-mcp](https://github.com/tufantunc/ssh-mcp) 是优秀的安全优先单机 SSH MCP 桥——它把"单次调用一台主机"做得很深。Flotilla 回答的是另一个问题：**同时操作很多台主机。**

| 能力 | ssh-mcp v2 | Flotilla |
|---|---|---|
| 单次调用的主机数 | 1（选一个 profile） | **target 表达式**命中 N 台：`group:prod`、`tag:web !web-3`、`all` |
| 扇出执行 | — | 并行 / 串行 / **rolling + 熔断** |
| 跨机比对 | — | `fleet-diff` 按相同输出分组，查版本/配置漂移 |
| 全舰队 systemd | — | status / logs / start / stop / restart / reload + 按机服务白名单 |
| 舰队体检与指标 | — | `doctor`（每台 HEALTHY/WARN/CRIT）+ `metrics-snapshot` |
| 日志跟踪 | 后台会话轮询 | `logs-tail` 限时窗口 + 本地 grep，扇出到多台 |
| 文件传输 | 单机 SFTP 上传/下载 | `fleet-push` / `fleet-pull` 跨 target，多机默认 rolling |
| 长任务 | 进程内后台会话 | **tmux 会话，连 MCP server 自己重启都不死** |
| 多步操作 | — | YAML **workflow**：逐步 target、插值、回滚 |
| 加机器 | 手编一个 profile | `fleet-add`：探测 → 钉 host key → 追加配置，一步完成 |
| 配置管理 | 本地文件 | **远程拉取（Git raw/HTTP）+ 热重载**，改一处全端生效 |
| 审计 | JSONL、脱敏、可选哈希链 | JSONL、三层脱敏、哈希链**默认开启** |
| 聚合层 | HTTP transport | v2 路线图：Gateway + Web 控制台，单端点聚合 MCP |

ssh-mcp 目前领先的地方（如实承认）：Windows OpenSSH 主机、OPA 外部策略、命令配额、JIT 审批授权、系统 keychain 与 SSH CA 证书。其中大部分已在我们的 v1.x 路线图上。

> 只管一两台机器，ssh-mcp 是对的工具；管一支舰队，这就是 Flotilla 存在的意义。

## 功能亮点

- 🎯 **Target 表达式寻址** — `group:prod !web-3`、`tag:web,tag:arm`、`all`，先 `fleet-resolve` 预演再执行
- 🚦 **三种扇出策略** — 并行、串行、rolling（批次失败自动熔断，prod 破坏性操作默认 rolling）
- 🛡️ **五层安全模型** — 永禁清单、角色×层级矩阵、资源白名单、审批门（MCP elicitation 弹窗）、哈希链审计
- 🔍 **跨机比对** — `fleet-diff` 一条命令查出全舰队的版本/配置漂移
- 📦 **SFTP 批量分发/收集** — `fleet-push` / `fleet-pull`，按机路径白名单
- 🖥️ **tmux 持久会话** — 断连不死，MCP server 重启也不死
- 🩺 **零依赖体检** — `doctor` 一键全舰队 HEALTHY/WARN/CRIT
- ⚙️ **systemd 全家桶** — 服务状态、日志、启停重载，带服务白名单
- 🔄 **YAML 工作流** — 多步骤编排、变量插值、失败回滚
- ➕ **一行加机器** — `fleet-add` 探测主机、钉死 host key、热重载生效
- ☁️ **配置集中管理** — 配置放 Git 私有仓库，各端定时拉取 + 热重载
- 🐳 **Docker 双架构** — amd64 + arm64（树莓派友好），非 root 运行

## 24 个工具

<details open><summary><b>舰队管理</b></summary>

| 工具 | 说明 |
|---|---|
| `fleet-list` | 一览服务器/分组/标签/层级/角色 |
| `fleet-resolve` | 预演 target 表达式，跑之前先看清命中哪些机器 |
| `fleet-add` | 加机器：探测（hostname/uid/tmux/host key）→ 钉 key → 追加配置 → 热重载 |
| `config-pull` / `config-reload` | 远程配置拉取（强制审批）/ 本地热重载 |

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
| `metrics-snapshot` | 负载、内存、磁盘、进程——零依赖探针 |
| `doctor` | 一键体检：每台 HEALTHY / WARN / CRIT |
| `logs-tail` | 限时跟踪 journal 或文件，本地 grep 过滤 |

</details>

<details open><summary><b>文件与服务</b></summary>

| 工具 | 说明 |
|---|---|
| `fleet-push` / `fleet-pull` | SFTP 批量分发 / 收集文件，多机默认 rolling |
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
# 源码
git clone https://github.com/paipaiio/flotilla-mcp.git && cd flotilla-mcp
pnpm install && pnpm build

# 或发布后：  npm install -g flotilla-mcp
# 或 Docker： docker build -t flotilla-mcp .
```

### 配置

```bash
# 建配置目录（默认路径，权限必须 700/600）
mkdir -p "$HOME/Library/Application Support/flotilla" && chmod 700 "$_"
touch "$_/config.toml" && chmod 600 "$_/config.toml"
```

逐台加机器（探测 + 钉 host key 一步到位）：

```bash
node scripts/fleet.mjs --config "$HOME/Library/Application Support/flotilla/config.toml" \
  add web-1 --host 10.0.1.11 --user deploy --auth key --key ~/.ssh/id_ed25519 --group prod --tags web
```

或手编（完整字段见 [config.example.toml](./config.example.toml)）：

```toml
[defaults]
approvalMode = "ask-destructive"   # auto | ask-destructive | ask-all | deny

[[servers]]
name = "web-1"
host = "10.0.1.11"
port = 22                          # 非标配端口写这里
user = "deploy"
auth = "agent"                     # agent | key | password（密码从环境变量读，不落文件）
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
# Claude Code
claude mcp add --transport stdio flotilla -- \
  node /path/to/flotilla-mcp/packages/mcp-stdio/dist/index.js
```

任何兼容 stdio 的 MCP 客户端同理：指向 `packages/mcp-stdio/dist/index.js`，传 `--config <path>` 或设 `FLOTILLA_CONFIG`。Codex 配置示例：

```toml
# ~/.codex/config.toml
[mcp_servers.flotilla]
command = "node"
args = ["/path/to/flotilla-mcp/packages/mcp-stdio/dist/index.js"]
```

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

五层纵深防御：

1. **永禁清单** — `rm -rf /`、`curl | sh`、写 `authorized_keys`、fork 炸弹……对所有人拒绝，不可配置关闭
2. **角色 × 层级矩阵** — `viewer` / `operator` / `admin` × `prod` / `staging` / `dev`。`group` 缺省按名字推断，推断不出一律按最严的 **prod**
3. **资源白名单** — 按服务器的 `scopes.paths` / `scopes.services` / `scopes.commands` 进一步收窄（只收窄，不放宽）
4. **审批门** — 破坏性/特权操作走 MCP elicitation 交互弹窗；`confirm` 标志默认 **fail-closed**（`defaults.allowConfirmFlag = true` 或 `FLOTILLA_ALLOW_CONFIRM_FLAG=1` 才开启）。模型无法自我审批
5. **审计** — 每个决策和执行都落 JSONL，三层脱敏 + SHA-256 哈希链，篡改可检测

另外：

- 凭据永不进 argv、永不进日志：SSH agent → 密钥文件 → 环境变量（`FLOTILLA_<NAME>_PASSWORD` / `FLOTILLA_SUDO_PASSWORD`……）
- 主机密钥：进程内 TOFU，`trustedHostKey` 钉死跨重启；`fleet-add` 首次接触即钉
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
docker build -t flotilla-mcp .
docker run -i --rm \
  -v ~/.config/flotilla/config.toml:/home/node/.config/flotilla/config.toml:ro \
  -v ~/.ssh:/home/node/.ssh:ro \
  flotilla-mcp
```

非 root 运行，amd64 + arm64 双架构。

## 路线图

- **v1.0** ✅ — fleet-add、审计、远程配置拉取 + 热重载、双语 README、npm 就绪、Docker、CI/CD
- **v1.x** — 服务器间操作（fleet-copy / fleet-sync / 文件比对）、命令配额、JIT 审批授权、算法白名单（RFC 9142）、CA 证书、系统 keychain
- **v2** — 中心化 Gateway + Web 控制台、聚合单端点 MCP、Tailscale 式一行命令入网
- **v3 设想** — 目标机轻量 agent、DAG 编排、团队协作

## 贡献

私有打磨期暂不开放外部贡献。开源后：issue 提 bug / 需求，PR 请先开 issue 讨论方向。所有 PR 需要通过 CI（build + 160+ 测试 + Docker 构建）。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=paipaiio/flotilla-mcp&type=Date)](https://star-history.com/#paipaiio/flotilla-mcp&Date)

## License

**GNU Affero General Public License v3.0**（见 [LICENSE](./LICENSE)）：

- ✅ 自由使用、修改、分发——包括企业内部生产使用
- ⚠️ Copyleft：分发或**通过网络提供**基于 Flotilla 的服务时，必须向用户公开完整源代码（AGPL 的网络条款）
- 💼 不想受 AGPL 约束（例如闭源商用）？提供商业授权——通过 [GitHub](https://github.com/paipaiio/flotilla-mcp) 联系
