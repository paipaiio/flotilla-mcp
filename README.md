# Flotilla

多服务器 SSH MCP server —— ssh-mcp 的增强版：一条命令扇出到整个舰队，rolling 执行带熔断，跨机比对，策略引擎兜底。

## 状态

v0.1 骨架：核心引擎（registry / target 表达式 / 执行器 / 策略）+ 最小 stdio MCP server。详见设计方案 `../flotilla-mcp-方案.md`。

## 快速开始

```bash
pnpm install
pnpm build
pnpm test
```

配置（见 `config.example.toml`）：

```toml
[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
auth = "agent"
group = "prod"
tags = ["web"]

[[groups]]
name = "web-prod"
match = { group = "prod", tags = ["web"] }
```

接入 MCP 客户端（以 Claude Code 为例）：

```bash
claude mcp add --transport stdio flotilla -- \
  node /path/to/flotilla-mcp/packages/mcp-stdio/dist/index.js --config /path/to/config.toml
```

## 工具（v0.1）

| 工具 | 说明 |
|------|------|
| `fleet-list` | 列出服务器/分组/标签/层级 |
| `fleet-resolve` | 预演 target 表达式，返回命中的服务器 |
| `exec-read` | 白名单只读命令，并行扇出 |
| `exec` | 任意命令，策略引擎 + 审批门；多机破坏性操作默认 rolling + 熔断 |

## Target 表达式

```
web-1                     单台
group:web-prod            配置的分组（或层级名，如 group:prod）
tag:web                   按标签
all                       全部
group:prod !web-3         排除
["web-1", "web-2"]        显式列表
```

## 安全要点

- 凭据永不走命令行：SSH agent → 密钥文件 → 环境变量（`FLOTILLA_<NAME>_PASSWORD` / `FLOTILLA_PASSWORD`）
- 永禁清单（`rm -rf /`、`curl|sh`、写 `authorized_keys` 等）对所有人拒绝，不可配置关闭
- 角色 × 层级矩阵：viewer/operator/admin × prod/staging/dev；`group` 缺省按名字推断，推断不出一律按 prod
- 主机密钥 TOFU（进程内），`trustedHostKey`  pinning 可跨重启
- **不要指向 root 账户；不要在 prod 上开 `approvalMode = "auto"`**

## Monorepo 结构

```
packages/
  core/        引擎：config / registry / target / executor / policy / ssh
  mcp-stdio/   stdio MCP server（npm 主包 flotilla-mcp）
# v2 规划：packages/gateway（HTTP + 聚合）、packages/web（控制台）
```
