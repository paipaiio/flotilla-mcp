# Flotilla

**多服务器 SSH MCP server。** 一条命令扇出到整个舰队——target 表达式、rolling 执行带熔断、跨机比对、策略引擎、可篡改检测的审计日志。

Flotilla 把"逐台 SSH 20 台机器"变成"声明一次意图，安全地执行"。

[English README](./README.md)

## 为什么是 Flotilla（对比 ssh-mcp）

[ssh-mcp](https://github.com/tufantunc/ssh-mcp) 是一个优秀的、安全优先的 SSH MCP 桥——它的 v2 在**单次调用一台主机**这件事上做得很深（策略矩阵、elicitation 审批、审计、OPA、Windows 主机）。Flotilla 回答的是 ssh-mcp 不回答的问题：**同时操作很多台主机。**

| 能力 | ssh-mcp v2 | Flotilla |
|---|---|---|
| 单次调用的主机数 | 1（选一个 profile） | **target 表达式**命中 N 台：`group:prod`、`tag:web !web-3`、`all`、并集 |
| 扇出执行 | — | 并行 / 串行 / **rolling + 熔断** |
| 跨机比对 | — | `fleet-diff` 按相同输出分组，查版本/配置漂移 |
| 全舰队 systemd | — | status / logs / start / stop / restart / reload + 按机服务白名单 |
| 舰队体检与指标 | — | `doctor`（每台 HEALTHY/WARN/CRIT）+ `metrics-snapshot` |
| 日志跟踪 | 后台会话轮询 | `logs-tail` 限时窗口 + 本地 grep，扇出到多台 |
| 文件传输 | 单机 SFTP 上传/下载 | `fleet-push` / `fleet-pull` 跨 target，多机默认 rolling |
| 长任务 | 进程内后台会话 | **tmux 会话，连 MCP server 自己重启都不死** |
| 多步操作 | — | YAML **workflow**：逐步 target、插值、回滚 |
| 加机器 | 手编一个 profile | `fleet-add`：探测 → 钉 host key → 追加配置，一步完成 |
| 审计 | JSONL、脱敏、可选哈希链 | JSONL、三层脱敏、哈希链**默认开启** |
| 聚合层 | HTTP transport | v2 路线图：Gateway + Web 控制台，单端点聚合 MCP |

ssh-mcp 目前领先的地方（我们如实承认）：Windows OpenSSH 主机、OPA 外部策略、命令配额、JIT 审批授权、系统 keychain 与 SSH CA 证书、已发布的 npm 包和 Docker 镜像。其中几项已在我们的 v1.x 路线图上。

只管一两台机器，ssh-mcp 是对的工具；管一支舰队，这就是 Flotilla 存在的意义。

## 22 个工具

| 工具 | 说明 |
|---|---|
| `fleet-list` | 一览服务器/分组/标签/层级/角色 |
| `fleet-resolve` | 预演 target 表达式，跑之前先看清命中哪些机器 |
| `fleet-add` | 加机器：探测（hostname/uid/tmux/host key）→ 钉 key → 追加配置 |
| `exec-read` | 白名单只读命令，并行扇出 |
| `exec` | 任意命令，完整策略引擎 + 审批门 |
| `exec-sudo` | sudo 提权；强制审批；密码走 env → stdin，不进 argv |
| `fleet-diff` | 一条只读命令跑全场，按相同输出分组 |
| `fleet-push` / `fleet-pull` | SFTP 批量分发 / 收集文件，多机默认 rolling |
| `service-status` / `service-logs` / `service-control` | 全舰队的 systemd 管理 |
| `logs-tail` | 限时跟踪 journal 或文件，本地 grep 过滤 |
| `session-start` / `session-list` / `session-output` / `session-send` / `session-kill` | 断连不死的 tmux 持久会话 |
| `metrics-snapshot` | 负载、内存、磁盘、进程——零依赖探针 |
| `doctor` | 一键体检：每台 HEALTHY / WARN / CRIT |
| `signal-process` | 给数字 PID 发 INT/TERM/KILL/HUP，强制审批 |
| `workflow-run` | YAML 工作流：有序步骤、插值、回滚 |

## 快速开始

```bash
git clone <repo> && cd flotilla-mcp
pnpm install && pnpm build
```

写配置（完整字段见 `config.example.toml`）：

```toml
[defaults]
approvalMode = "ask-destructive"

[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
auth = "agent"        # agent | key | password（密码从环境变量读，不落文件）
group = "prod"
tags = ["web"]

[[servers]]
name = "db-1"
host = "10.0.2.11"
user = "deploy"
auth = "key"
keyRef = "~/.ssh/id_ed25519"
group = "prod"
via = "bastion"       # 经跳板机
```

更省事的方式（探测 + 钉 host key 一步到位）：

```bash
node scripts/fleet.mjs --config config.toml add web-2 \
  --host 10.0.1.12 --user deploy --auth key --key ~/.ssh/id_ed25519 --group prod --tags web
```

接入 MCP 客户端：

```bash
# Claude Code
claude mcp add --transport stdio flotilla -- \
  node /path/to/flotilla-mcp/packages/mcp-stdio/dist/index.js --config /path/to/config.toml
```

任何兼容 stdio 的 MCP 客户端同理：指向 `packages/mcp-stdio/dist/index.js`，传 `--config <path>`（或设 `FLOTILLA_CONFIG`）。

然后直接使唤你的舰队：

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

1. **永禁清单**——`rm -rf /`、`curl | sh`、写 `authorized_keys`、fork 炸弹……对所有人拒绝，不可配置关闭。
2. **角色 × 层级矩阵**——`viewer` / `operator` / `admin` × `prod` / `staging` / `dev`。`group` 缺省按名字推断，推断不出一律按最严的 **prod**。
3. **资源白名单**——按服务器的 `scopes.paths` / `scopes.services` / `scopes.commands` 进一步收窄（只收窄，不放宽）。
4. **审批门**——破坏性/特权操作在客户端支持时走 MCP elicitation 交互弹窗；否则用 `confirm` 标志，但默认 **fail-closed**，需运维显式开启（`defaults.allowConfirmFlag = true` 或 `FLOTILLA_ALLOW_CONFIRM_FLAG=1`）。模型无法自我审批。
5. **审计**——每个决策和执行都落 JSONL 日志，三层脱敏 + SHA-256 哈希链，篡改可检测。

另外：

- 凭据永不进 argv、永不进日志：SSH agent → 密钥文件 → 环境变量（`FLOTILLA_<NAME>_PASSWORD` / `FLOTILLA_SUDO_PASSWORD`……）。
- 主机密钥：进程内 TOFU，`trustedHostKey` 钉死跨重启；`fleet-add` 首次接触即钉。
- 配置文件权限强制 `0600`；`readOnly` 服务器拒绝一切写操作。
- **不要指向 root 账户。** 用低权限账户 + NOPASSWD sudoers 白名单。不要在 prod 上开 `approvalMode = "auto"`。

## 开发

```bash
pnpm build      # 编译所有包
pnpm -r test    # 152 个单测
node scripts/fleet.mjs --config config.test.toml list   # 开发 CLI
```

```
packages/
  core/        引擎：config / registry / target / executor / policy / ssh / diff /
               monitor / service / session / workflow / logstream / audit / signal / onboard
  mcp-stdio/   stdio MCP server（将发布为 npm 包 flotilla-mcp）
scripts/       fleet.mjs——跑在同一引擎上的开发 CLI
```

## 路线图

- **v1.0**（当前）：fleet-add ✅、审计 ✅、远程配置拉取（Git/HTTP）、README ✅、npm 发布 + Docker
- **v1.x**：JIT 授权、命令配额、算法白名单、CA 证书、系统 keychain
- **v2**：中心化 Gateway + Web 控制台、聚合单端点 MCP、一行命令入网

## License

MIT
