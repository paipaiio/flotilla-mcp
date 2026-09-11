<div align="center">

# Flotilla

**A multi-server SSH MCP server — one command fans out to your whole fleet**

Target expressions · rolling execution with circuit breakers · cross-host diffing · policy engine with approval gates · tamper-evident audit logs

[中文](./README.md) · [Docs](#contents) · [Quick start](#quick-start) · [Roadmap](#roadmap)

[![CI](https://github.com/paipaiio/flotilla-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/paipaiio/flotilla-mcp/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](./LICENSE)
[![Node.js ≥ 20](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![npm](https://img.shields.io/npm/v/flotilla-mcp.svg)](https://www.npmjs.com/package/flotilla-mcp)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fpaipaiio%2Fflotilla--mcp-2496ED?logo=docker&logoColor=white)](https://github.com/paipaiio/flotilla-mcp/pkgs/container/flotilla-mcp)

</div>

---

Flotilla turns "SSH into 20 boxes one by one" into "state intent once, safely." It lets AI agents operate your entire server fleet over MCP — with a policy engine, approval gates, and a hash-chained audit log behind every step.

```
You: "Restart myapp on all web nodes, rolling, two at a time"
        │
        ▼
  fleet-resolve previews the target → per-host policy checks → approval prompt
        │
        ▼
  rolling fan-out (batch failure trips the breaker) → everything lands in the audit chain
```

## Contents

- [Why Flotilla](#why-flotilla)
- [Highlights](#highlights)
- [The 24 tools](#the-24-tools)
- [Quick start](#quick-start)
- [Target expressions](#target-expressions)
- [Security model](#security-model)
- [Remote config & hot reload](#remote-config--hot-reload)
- [Docker](#docker)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Why Flotilla

Most SSH MCP tools answer "let an AI operate **one** server." Flotilla was designed fleet-first from day one:

- **One call, the whole fleet** — target expressions (`group:prod`, `tag:web !web-3`, `all`) fan a command out to N hosts
- **Execution with tactics** — parallel for speed, serial for caution, **rolling + circuit breaker** for safety: a failing batch stops the run instead of dragging healthy hosts down with it
- **Comparison is a first-class citizen** — `fleet-diff` tells you with one command whether versions/configs have drifted across the fleet
- **Security is the default, not a switch** — policy matrix, approval gates, hash-chained audit are all on out of the box; turning them off requires a deliberate config edit
- **Config can be centralized** — keep it in a private Git repo; every node pulls and hot-reloads. Fifty machines, one edit

## Highlights

- 🎯 **Target expressions** — `group:prod !web-3`, `tag:web,tag:arm`, `all`; `fleet-resolve` previews before anything runs
- 🚦 **Three fan-out strategies** — parallel, serial, rolling (batch failure trips the circuit breaker; rolling is the default for destructive multi-host runs)
- 🛡️ **Five-layer security model** — never-allowed list, role × tier matrix, resource scopes, approval gate (MCP elicitation), hash-chained audit
- 🔍 **Cross-host diffing** — `fleet-diff` finds version/config drift across the whole fleet with one command
- 📦 **SFTP batch distribute/collect** — `fleet-push` / `fleet-pull` with per-host path scopes
- 🖥️ **Persistent tmux sessions** — survive disconnects, even survive the MCP server restarting
- 🩺 **Zero-dependency health checks** — `doctor` reports HEALTHY/WARN/CRIT per host
- ⚙️ **systemd suite** — status, logs, start/stop/restart/reload, with service scopes
- 🔄 **YAML workflows** — multi-step orchestration, interpolation, rollback
- ➕ **One-line onboarding** — `fleet-add` probes the host, pins its key, hot-reloads the config
- ☁️ **Centralized config** — keep the config in a private Git repo; every node pulls and hot-reloads
- 🐳 **Docker, two architectures** — amd64 + arm64 (Raspberry Pi friendly), runs non-root

## The 24 tools

<details open><summary><b>Fleet management</b></summary>

| Tool | What it does |
|---|---|
| `fleet-list` | Servers, groups, tags, tiers, roles at a glance |
| `fleet-resolve` | Dry-run a target expression before you run anything |
| `fleet-add` | Onboard a server: probe (hostname/uid/tmux/host key) → pin key → append config → hot reload |
| `config-pull` / `config-reload` | Remote config pull (approval-gated) / local hot reload |

</details>

<details open><summary><b>Command execution</b></summary>

| Tool | What it does |
|---|---|
| `exec-read` | Allowlisted read-only commands, parallel fan-out |
| `exec` | Any command, full policy engine + approval gate |
| `exec-sudo` | Root via sudo; always gated; password via env → stdin, never argv |
| `signal-process` | INT/TERM/KILL/HUP a numeric PID, always gated |

</details>

<details open><summary><b>Diffing & observability</b></summary>

| Tool | What it does |
|---|---|
| `fleet-diff` | Run one read-only command everywhere, group hosts by identical output |
| `metrics-snapshot` | Load, memory, disks, top processes — zero-dependency probe |
| `doctor` | One-shot health check: HEALTHY / WARN / CRIT per host |
| `logs-tail` | Follow a journal or file for a bounded window, local grep filter |

</details>

<details open><summary><b>Files & services</b></summary>

| Tool | What it does |
|---|---|
| `fleet-push` / `fleet-pull` | SFTP distribute / collect files, rolling by default on multi-host |
| `service-status` / `service-logs` / `service-control` | systemd across the fleet |

</details>

<details open><summary><b>Sessions & orchestration</b></summary>

| Tool | What it does |
|---|---|
| `session-start` / `session-list` / `session-output` / `session-send` / `session-kill` | Persistent tmux sessions that survive disconnects |
| `workflow-run` | YAML workflows: ordered steps, interpolation, rollback |

</details>

## Quick start

### Install

```bash
# npm (recommended)
npm install -g flotilla-mcp

# or Docker
docker pull ghcr.io/paipaiio/flotilla-mcp:latest

# or from source
git clone https://github.com/paipaiio/flotilla-mcp.git && cd flotilla-mcp
pnpm install && pnpm build
```

### Configure

```bash
# config dir at the platform default path (must be 700 / 600)
mkdir -p "$HOME/Library/Application Support/flotilla" && chmod 700 "$_"
touch "$_/config.toml" && chmod 600 "$_/config.toml"
```

Add servers one by one (probe + host-key pinning in one step):

```bash
node scripts/fleet.mjs --config "$HOME/Library/Application Support/flotilla/config.toml" \
  add web-1 --host 10.0.1.11 --user deploy --auth key --key ~/.ssh/id_ed25519 --group prod --tags web
```

Or hand-edit (full reference in [config.example.toml](./config.example.toml)):

```toml
[defaults]
approvalMode = "ask-destructive"   # auto | ask-destructive | ask-all | deny

[[servers]]
name = "web-1"
host = "10.0.1.11"
port = 22                          # non-standard SSH ports go here
user = "deploy"
auth = "agent"                     # agent | key | password (password comes from env, never the file)
group = "prod"                     # policy tier; inferred from the name when omitted,
                                   # unrecognized names default to the strictest tier: prod
tags = ["web"]

[[servers]]
name = "db-1"
host = "10.0.2.11"
user = "deploy"
auth = "key"
keyRef = "~/.ssh/id_ed25519"
group = "prod"
via = "bastion"                    # ProxyJump through another server
```

### Wire it into your MCP client

```bash
# Claude Code (with the npm global install, just use the flotilla-mcp binary)
claude mcp add --transport stdio flotilla -- flotilla-mcp
```

Any stdio-compatible MCP client works the same way: point it at `flotilla-mcp` (or `packages/mcp-stdio/dist/index.js` for a source install), passing `--config <path>` or setting `FLOTILLA_CONFIG`. Codex example:

```toml
# ~/.codex/config.toml
[mcp_servers.flotilla]
command = "flotilla-mcp"
```

### Talk to your fleet

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

1. **Never-allowed list** — `rm -rf /`, `curl | sh`, writing `authorized_keys`, fork bombs… refused for everyone, not configurable off
2. **Role × tier matrix** — `viewer` / `operator` / `admin` × `prod` / `staging` / `dev`. `group` is inferred from the server name when omitted; unrecognized names default to **prod**, the strictest tier
3. **Resource scopes** — per-server `scopes.paths` / `scopes.services` / `scopes.commands` narrow what a role may touch (only narrows, never widens)
4. **Approval gate** — destructive/privileged actions prompt interactively via MCP elicitation; the `confirm` flag is **fail-closed** unless the operator opts in (`defaults.allowConfirmFlag = true` or `FLOTILLA_ALLOW_CONFIRM_FLAG=1`). A rogue model cannot self-approve
5. **Audit trail** — every decision and execution lands in a JSONL log with three-layer redaction and a SHA-256 hash chain, so tampering is detectable

Plus:

- Credentials never touch argv or logs: SSH agent → key file → env vars (`FLOTILLA_<NAME>_PASSWORD` / `FLOTILLA_SUDO_PASSWORD` …)
- Host keys: TOFU in-process, `trustedHostKey` pinning across restarts; `fleet-add` pins on first contact
- Config file permissions are enforced (`0600`); `readOnly` servers refuse all writes
- ⚠️ **Don't point Flotilla at root accounts.** Use a low-privilege user plus a NOPASSWD sudoers allowlist. Don't set `approvalMode = "auto"` on prod

## Remote config & hot reload

At scale, keep `config.toml` in a private Git repo and let every node pull it:

```toml
[remote]
url = "https://raw.githubusercontent.com/<org>/<repo>/main/fleet.toml"
tokenEnv = "FLOTILLA_CONFIG_TOKEN"   # GitHub PAT, sent as Authorization: Bearer
refreshMs = 300000                    # auto-pull + hot reload every 5 min; manual by default
```

A pull validates the payload fully, backs up the previous file, writes atomically, and hot-reloads. A bad payload never touches disk. Plain local edits work too — the watcher applies them within 300 ms.

## Docker

```bash
docker run -i --rm \
  -v ~/.config/flotilla/config.toml:/home/node/.config/flotilla/config.toml:ro \
  -v ~/.ssh:/home/node/.ssh:ro \
  ghcr.io/paipaiio/flotilla-mcp:latest
```

Non-root, amd64 + arm64.

## Roadmap

- **v1.0** ✅ — fleet-add, audit, remote config pull + hot reload, bilingual README, published on npm, Docker, CI/CD
- **v1.x** — server-to-server ops (fleet-copy / fleet-sync / file diff), command quotas, JIT approval grants, algorithm allowlists (RFC 9142), CA certificates, OS keychain
- **v2** — central Gateway + Web console, aggregated single-endpoint MCP, Tailscale-style one-line host enrollment
- **v3 ideas** — lightweight on-host agent, DAG orchestration, team collaboration

## Contributing

Not open to external contributions during the private phase. After open-sourcing: file issues for bugs and requests; open an issue to discuss direction before large PRs. All PRs must pass CI (build + 160+ tests + Docker build).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=paipaiio/flotilla-mcp&type=Date)](https://star-history.com/#paipaiio/flotilla-mcp&Date)

## License

**GNU Affero General Public License v3.0** (see [LICENSE](./LICENSE)):

- ✅ Free to use, modify, and distribute — including internal production use
- ⚠️ Copyleft: distributing Flotilla or **offering it as a network service** requires disclosing the full source code to users (the AGPL network clause)
- 💼 Need to use it without AGPL obligations (e.g. closed-source commercial use)? Commercial licenses are available — reach out via [GitHub](https://github.com/paipaiio/flotilla-mcp)
