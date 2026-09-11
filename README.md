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
- [24 个工具](#24-个工具)
- [快速开始](#快速开始)
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
- 🛡️ **五层安全模型** — 永禁清单、角色×层级矩阵、资源白名单、审批门（MCP elicitation 弹窗）、哈希链审计
- 🔍 **跨机比对** — `fleet-diff` 比命令输出，`fleet-diff-file` 按 sha256 比文件/目录
- 📦 **SFTP 批量分发/收集** — `fleet-push` / `fleet-pull`，按机路径白名单
- 🔁 **服务器间直传** — `fleet-copy` / `fleet-sync`：A→B 经控制机内存中转，**服务器之间不用互通、不用互配 SSH 密钥**
- 🖥️ **tmux 持久会话** — 断连不死，MCP server 重启也不死
- 🩺 **零依赖体检** — `doctor` 一键全舰队 HEALTHY/WARN/CRIT
- ⚙️ **systemd 全家桶** — 服务状态、日志、启停重载，带服务白名单
- 🔄 **YAML 工作流** — 多步骤编排、变量插值、失败回滚
- ➕ **一行加机器** — `fleet-add` 探测主机、钉死 host key、热重载生效
- ☁️ **配置集中管理** — 配置放 Git 私有仓库，各端定时拉取 + 热重载
- 🐳 **Docker 双架构** — amd64 + arm64（树莓派友好），非 root 运行

## 27 个工具

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

```bash
# 建配置目录（默认路径，权限必须 700/600）
mkdir -p "$HOME/Library/Application Support/flotilla" && chmod 700 "$_"
touch "$_/config.toml" && chmod 600 "$_/config.toml"
```

逐台加机器（探测 + 钉 host key 一步到位，`flotilla` 是 npm 包自带的 CLI）：

```bash
flotilla add web-1 --host 10.0.1.11 --user deploy --auth key --key ~/.ssh/id_ed25519 --group prod --tags web
```

（默认读平台配置目录；自定义路径加 `--config <path>`。）

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
# Claude Code（npm 全局安装后直接用 flotilla-mcp 命令）
claude mcp add --transport stdio flotilla -- flotilla-mcp
```

任何兼容 stdio 的 MCP 客户端同理：命令指向 `flotilla-mcp`（或源码安装的 `packages/mcp-stdio/dist/index.js`），传 `--config <path>` 或设 `FLOTILLA_CONFIG`。Codex 配置示例：

```toml
# ~/.codex/config.toml
[mcp_servers.flotilla]
command = "flotilla-mcp"
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
docker run -i --rm \
  -v ~/.config/flotilla/config.toml:/home/node/.config/flotilla/config.toml:ro \
  -v ~/.ssh:/home/node/.ssh:ro \
  ghcr.io/paipaiio/flotilla-mcp:latest
```

非 root 运行，amd64 + arm64 双架构。

## 路线图

- **v1.0** ✅ — fleet-add、审计、远程配置拉取 + 热重载、双语 README、npm 发布、Docker、CI/CD
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
