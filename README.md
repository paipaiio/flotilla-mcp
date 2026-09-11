# Flotilla

**A multi-server SSH MCP server.** One command fans out to your whole fleet — with target expressions, rolling execution and circuit breakers, cross-host diffing, a policy engine, and tamper-evident audit logs.

Flotilla turns "SSH into 20 boxes one by one" into "state intent once, safely."

[中文文档](./README.zh-CN.md)

## Why Flotilla (vs. ssh-mcp)

[ssh-mcp](https://github.com/tufantunc/ssh-mcp) is an excellent, security-first SSH bridge for MCP — and its v2 covers a single host *per tool call* deeply (policy matrix, elicitation approval, audit, OPA, Windows hosts). Flotilla is built for the question ssh-mcp doesn't answer: **operating on many hosts at once.**

| Capability | ssh-mcp v2 | Flotilla |
|---|---|---|
| Hosts per tool call | 1 (pick a profile) | A **target expression** matching N hosts: `group:prod`, `tag:web !web-3`, `all`, unions |
| Fan-out execution | — | parallel / serial / **rolling with circuit breaker** |
| Cross-host comparison | — | `fleet-diff` groups hosts by identical output (version/config drift) |
| systemd fleet-wide | — | status / logs / start / stop / restart / reload with per-host service scopes |
| Fleet health & metrics | — | `doctor` (HEALTHY/WARN/CRIT per host) and `metrics-snapshot` |
| Log following | background session + poll | `logs-tail` bounded window + local grep, fan-out |
| File transfer | single-host SFTP up/download | `fleet-push` / `fleet-pull` across a target, rolling by default |
| Long-running tasks | in-process background sessions | **tmux sessions that survive even the MCP server restarting** |
| Multi-step ops | — | Declarative YAML **workflows**: per-step targets, interpolation, rollback |
| Fleet onboarding | hand-edit one profile | `fleet-add`: probe host → pin host key → append config, one step |
| Audit trail | JSONL, redaction, optional hash chain | JSONL, 3-layer redaction, hash chain **on by default** |
| Aggregation plane | HTTP transport | v2 roadmap: Gateway + Web console, one aggregated MCP endpoint |

Where ssh-mcp is ahead today (we're honest about it): Windows OpenSSH hosts, OPA sidecar policy, command quotas, JIT approval grants, OS keychain and SSH CA cert auth, published npm package and Docker image. Several are on our v1.x roadmap.

If you manage one or two boxes, ssh-mcp is the right tool. If you manage a fleet, that's what Flotilla is for.

## The 22 tools

| Tool | What it does |
|---|---|
| `fleet-list` | Servers, groups, tags, tiers, roles at a glance |
| `fleet-resolve` | Dry-run a target expression before you run anything |
| `fleet-add` | Onboard a server: probe (hostname/uid/tmux/host key) → pin key → append to config |
| `exec-read` | Allowlisted read-only commands, parallel fan-out |
| `exec` | Any command, full policy engine + approval gate |
| `exec-sudo` | Root via sudo; always gated; password via env → stdin, never argv |
| `fleet-diff` | Run one read-only command everywhere, group hosts by identical output |
| `fleet-push` / `fleet-pull` | SFTP distribute / collect files, rolling by default on multi-host |
| `service-status` / `service-logs` / `service-control` | systemd across the fleet |
| `logs-tail` | Follow a journal or file for a bounded window, local grep filter |
| `session-start` / `session-list` / `session-output` / `session-send` / `session-kill` | Persistent tmux sessions that survive disconnects |
| `metrics-snapshot` | Load, memory, disks, top processes — zero-dependency probe |
| `doctor` | One-shot health check: HEALTHY / WARN / CRIT per host |
| `signal-process` | INT/TERM/KILL/HUP a numeric PID, gated |
| `workflow-run` | YAML workflows: ordered steps, per-step targets, interpolation, rollback |

## Quick start

```bash
git clone <repo> && cd flotilla-mcp
pnpm install && pnpm build
```

Write a config (see `config.example.toml` for the full reference):

```toml
[defaults]
approvalMode = "ask-destructive"

[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
auth = "agent"        # agent | key | password (password comes from env, never the file)
group = "prod"
tags = ["web"]

[[servers]]
name = "db-1"
host = "10.0.2.11"
user = "deploy"
auth = "key"
keyRef = "~/.ssh/id_ed25519"
group = "prod"
via = "bastion"       # ProxyJump through another server
```

Add a host the easy way instead (probe + host-key pinning in one step):

```bash
node scripts/fleet.mjs --config config.toml add web-2 \
  --host 10.0.1.12 --user deploy --auth key --key ~/.ssh/id_ed25519 --group prod --tags web
```

Wire it into your MCP client:

```bash
# Claude Code
claude mcp add --transport stdio flotilla -- \
  node /path/to/flotilla-mcp/packages/mcp-stdio/dist/index.js --config /path/to/config.toml
```

Any stdio-compatible MCP client works the same way: point it at `packages/mcp-stdio/dist/index.js` with `--config <path>` (or set `FLOTILLA_CONFIG`).

Then talk to your fleet:

> "Check disk usage on all prod servers" → `exec-read` on `group:prod`
> "Are all web nodes running the same nginx version?" → `fleet-diff nginx -v` on `tag:web`
> "Restart myapp on prod, rolling, two at a time" → `service-control` with the circuit breaker on

## Target expressions

```
web-1                     a single server
group:web-prod            a configured group (or a tier name: group:prod)
tag:web                   every server with a tag
all                       everything
group:prod !web-3         exclusion
tag:web,tag:arm           union
["web-1", "web-2"]        explicit list
```

Always `fleet-resolve` a target before a destructive fan-out.

## Security model

Defense in depth, five layers:

1. **Never-allowed list** — `rm -rf /`, `curl | sh`, writing `authorized_keys`, fork bombs, … refused for everyone, not configurable off.
2. **Role × tier matrix** — `viewer` / `operator` / `admin` × `prod` / `staging` / `dev`. `group` is inferred from the server name when omitted; unrecognized names default to **prod**, the strictest tier.
3. **Resource scopes** — per-server `scopes.paths` / `scopes.services` / `scopes.commands` narrow what a role may touch (only narrows, never widens).
4. **Approval gate** — destructive/privileged actions prompt interactively via MCP elicitation when the client supports it; otherwise a `confirm` flag that is **fail-closed** unless the operator opts in (`defaults.allowConfirmFlag = true` or `FLOTILLA_ALLOW_CONFIRM_FLAG=1`). A rogue model cannot self-approve.
5. **Audit trail** — every decision and execution lands in a JSONL log with three-layer secret redaction and a SHA-256 hash chain, so tampering is detectable.

Plus:

- Credentials never touch argv or logs: SSH agent → key file → env vars (`FLOTILLA_<NAME>_PASSWORD` / `FLOTILLA_SUDO_PASSWORD` …).
- Host keys: TOFU in-process, `trustedHostKey` pinning across restarts; `fleet-add` pins on first contact.
- Config file permissions are enforced (`0600`); `readOnly` servers refuse all writes.
- **Don't point Flotilla at root accounts.** Use a low-privilege user plus a NOPASSWD sudoers allowlist. Don't set `approvalMode = "auto"` on prod.

## Development

```bash
pnpm build      # compile all packages
pnpm -r test    # 152 unit tests
node scripts/fleet.mjs --config config.test.toml list   # dev CLI
```

```
packages/
  core/        engine: config, registry, target exprs, executor, policy, ssh, diff, monitor,
               service, session, workflow, logstream, audit, signal, onboard
  mcp-stdio/   the stdio MCP server (to be published as flotilla-mcp)
scripts/       fleet.mjs — dev CLI over the same engine
```

## Roadmap

- **v1.0** (current focus): fleet-add ✅, audit ✅, remote config pull (Git/HTTP), README ✅, npm publish + Docker
- **v1.x**: JIT grants, command quotas, algorithm allowlists, CA certificates, OS keychain integration
- **v2**: central Gateway + Web console, aggregated single-endpoint MCP, one-line host enrollment

## License

MIT
