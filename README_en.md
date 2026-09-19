<div align="center">

<img src="./assets/logo.png" alt="Flotilla" width="160" />

# Flotilla

**A multi-server SSH MCP server — let AI manage all your servers at once**

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
- [The 28 tools](#the-28-tools)
- [Quick start](#quick-start)
- [HTTP Gateway (first v2 slice)](#http-gateway-first-v2-slice)
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
- 🛡️ **Six-layer security model** — never-allowed list, role × tier matrix, resource scopes, approval gate (MCP elicitation + JIT grants), hash-chained audit, daily command quota
- 🤖 **AI-assisted approval** — when a destructive action prompts, a local LLM renders a risk card first (advisory only, never a verdict; prompt-injection hardened)
- 🔍 **Cross-host diffing** — `fleet-diff` compares command output; `fleet-diff-file` compares files/dirs by sha256
- 📦 **SFTP batch distribute/collect** — `fleet-push` / `fleet-pull` with per-host path scopes
- 🔁 **Server-to-server transfer** — `fleet-copy` / `fleet-sync`: A→B relayed through the control machine's memory, so **servers never need network access or SSH keys to each other**
- 🖥️ **Persistent tmux sessions** — survive disconnects, even survive the MCP server restarting
- 🩺 **Zero-dependency health checks** — `doctor` reports HEALTHY/WARN/CRIT per host
- ⚙️ **systemd suite** — status, logs, start/stop/restart/reload, with service scopes
- 🔄 **YAML workflows** — multi-step orchestration, interpolation, rollback
- ➕ **One-line onboarding** — `fleet add --bootstrap` installs your public key over a one-time password connection, so a fresh machine joins with zero prep; `fleet-add` probes the host, pins its key, hot-reloads the config
- ☁️ **Centralized config** — keep the config in a private Git repo; every node pulls and hot-reloads
- 🐳 **Docker, two architectures** — amd64 + arm64 (Raspberry Pi friendly), runs non-root

## The 28 tools

<details open><summary><b>Fleet management</b></summary>

| Tool | What it does |
|---|---|
| `fleet-list` | Servers, groups, tags, tiers, roles at a glance |
| `fleet-resolve` | Dry-run a target expression before you run anything |
| `fleet-add` | Onboard a server: probe (hostname/uid/tmux/host key) → pin key → append config → hot reload |
| `config-pull` / `config-reload` | Remote config pull (approval-gated) / local hot reload |
| `fleet-grants` | List / clear active JIT approval grants |

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
| `fleet-diff-file` | Compare a file/directory by sha256; drift, missing, and failures grouped |
| `metrics-snapshot` | Load, memory, disks, top processes — zero-dependency probe |
| `doctor` | One-shot health check: HEALTHY / WARN / CRIT per host |
| `logs-tail` | Follow a journal or file for a bounded window, local grep filter |

</details>

<details open><summary><b>Files & services</b></summary>

| Tool | What it does |
|---|---|
| `fleet-push` / `fleet-pull` | SFTP distribute / collect files, rolling by default on multi-host |
| `fleet-copy` | A→B single-file relay via control-machine memory, never disk; policy on both ends, cross-tier always gated |
| `fleet-sync` | A→B directory sync (rsync semantics): sha256-incremental, dry-run by default, `--delete` always gated |
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

Zero manual setup: when the config dir/file is missing, `flotilla add` creates it automatically (dir 700 / file 600), and loose permissions are auto-repaired with a warning. Just add servers:

Add servers one by one (probe + host-key pinning in one step; `flotilla` is the CLI shipped in the npm package):

```bash
# Fresh machine without your public key yet? One command to onboard (one-time password
# first contact → installs the public key → key auth from then on):
flotilla add web-1 --host 10.0.1.11 --user root --bootstrap --group prod --tags web
# The password is prompted with hidden input, or passed via FLOTILLA_BOOTSTRAP_PASSWORD
# (kept out of shell history). By default a fleet-dedicated key <config dir>/fleet_ed25519
# is generated; pass --key <path> to reuse an existing private key.

# When the machine already trusts your key, register it directly:
flotilla add web-1 --host 10.0.1.11 --user deploy --auth key --key ~/.ssh/id_ed25519 --group prod --tags web

# Self-manage the gateway host itself: passwordless — the fleet pubkey goes
# straight into the local authorized_keys; nothing to type:
flotilla add --local
```

(Reads the platform config dir by default; pass `--config <path>` for a custom location. `--bootstrap` is CLI-only — a password is never accepted as an MCP tool argument.)

Or hand-edit (full reference in [config.example.toml](./config.example.toml)):

```toml
[defaults]
approvalMode = "ask-destructive"   # auto | ask-destructive | ask-all | deny
commandQuotaPerDay = 500           # cap on command-bearing calls per rolling 24h; 0 = unlimited — the tripwire against runaway agent loops

[[servers]]
name = "web-1"
host = "10.0.1.11"
port = 22                          # non-standard SSH ports go here
user = "deploy"
auth = "agent"                     # agent | key | password | certificate (password comes from env, never the file)
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

### HTTP Gateway (first v2 slice)

The same engine as a resident HTTP service: every tool, the policy engine, quotas, and the audit trail — with the transport swapped for stateless Streamable HTTP MCP.

```bash
# Refuses to start without a token — an unauthenticated fleet gateway is a remote root shell
export FLOTILLA_GATEWAY_TOKEN=$(openssl rand -hex 32)
flotilla-gateway --config ~/.config/flotilla/config.toml --host 127.0.0.1 --port 8080

# every /mcp request needs the Bearer token; /healthz is open for load balancers
curl -s http://127.0.0.1:8080/healthz
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $FLOTILLA_GATEWAY_TOKEN" \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

Binds 127.0.0.1 by default; put it behind a reverse proxy / TLS to expose it on a network. HTTP clients do not support interactive elicitation yet: approval-gated actions are refused with a hint to pass `confirm=true` (when policy allows it), and missing passwords go through env vars or the OS keychain.

For production deployments (Docker image / systemd unit / Caddy + nginx TLS templates) see [deploy/README.md](./deploy/README.md); the released gateway image is `ghcr.io/paipaiio/flotilla-mcp-gateway`.

**One-line enrollment (Tailscale-style)**: the operator mints a short-lived enrollment token; a new host enrolls itself — it installs the fleet public key into its own authorized_keys (no password ever crosses the wire), the gateway verifies with a real SSH probe, then appends the server to the fleet config atomically and the watcher hot-reloads it:

```bash
# Operator: mint a token (shown once; only its sha256 is persisted)
curl -X POST http://127.0.0.1:8080/api/enroll/tokens \
  -H "Authorization: Bearer $FLOTILLA_GATEWAY_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"rack-5"}'
# → {"token":"flt_…", …}

# New host (as root; add --fingerprint to pin the gateway cert on first enroll):
curl -fsSL http://127.0.0.1:8080/join.sh | sudo sh -s -- --token flt_…
```

Tokens support TTL / max uses / revocation (`DELETE /api/enroll/tokens/<id>`). The connect-back address is the join request's TCP peer, so the gateway must reach the host's SSH directly — the same constraint as every other fleet operation.

**Centralized audit & compliance export**: the engine's hash-chained audit trail converges at the gateway, forwards to external sinks, and exports on demand:

```bash
# optional audit sinks (env-configured): webhook or archive file; failures
# are logged and dropped — a compliance sink never takes the gateway down
FLOTILLA_AUDIT_WEBHOOK_URL=https://siem.internal/hook FLOTILLA_AUDIT_WEBHOOK_TOKEN=…
FLOTILLA_AUDIT_SINK_FILE=/mnt/audit/flotilla.jsonl

# compliance export (operator bearer; ANDed filters; CSV/JSON; newest first,
# default limit 10k rows)
curl -H "Authorization: Bearer $FLOTILLA_GATEWAY_TOKEN" \
  "http://127.0.0.1:8080/api/audit/export?from=2026-09-01&host=web-1&outcome=failed&format=csv"
```

**Web console**: the gateway serves a zero-dependency static console (`packages/gateway/console/`, no build step) at `http://<gateway>/console/` (`/` 302-redirects there). Log in with the bearer token and you get: overview (engine health + server list), command execution (read-only / with-confirm, through the same policy engine), enrollment management (issue/revoke tokens, shows the one-line join command), and audit (filters + CSV export). The static files hold no secrets — every API call is still authorized server-side, so the console adds no new attack surface.

**Aggregated MCP endpoint**: one `/mcp` endpoint no longer serves only the fleet tools — mount external MCP servers (local stdio commands or remote HTTP endpoints) via a JSON file and their tools appear in the same tools/list under a `<upstream>__<tool>` prefix, with calls proxied verbatim:

```bash
cat > upstreams.json <<'EOF'
[
  { "name": "fs", "transport": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"] },
  { "name": "peer", "transport": "http", "url": "http://10.0.0.9:8080/mcp",
    "headers": { "Authorization": "Bearer <other gateway token>" } }
]
EOF
flotilla-gateway --config fleet.toml --upstreams upstreams.json   # or FLOTILLA_GATEWAY_UPSTREAMS
# clients now see fs__read_file, peer__fleet-list, …
```

An upstream that fails to connect never blocks boot — it shows as `error` in `/healthz` with its reason. Upstream tools are foreign code the operator explicitly trusted by mounting them: they sit outside the fleet policy engine (the gateway bearer still gates the whole surface), and arguments pass through as a free-form object validated by the upstream's own schema.

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

Defense in depth, six layers:

1. **Never-allowed list** — `rm -rf /`, `curl | sh`, writing `authorized_keys`, fork bombs… refused for everyone, not configurable off
2. **Role × tier matrix** — `viewer` / `operator` / `admin` × `prod` / `staging` / `dev`. `group` is inferred from the server name when omitted; unrecognized names default to **prod**, the strictest tier
3. **Resource scopes** — per-server `scopes.paths` / `scopes.services` / `scopes.commands` narrow what a role may touch (only narrows, never widens)
4. **Approval gate** — destructive/privileged actions prompt interactively via MCP elicitation; the `confirm` flag is **fail-closed** unless the operator opts in (`defaults.allowConfirmFlag = true` or `FLOTILLA_ALLOW_CONFIRM_FLAG=1`). A rogue model cannot self-approve. The prompt offers a "don't ask again for N minutes" checkbox minting a **JIT grant** (in-memory only, dies on restart); `fleet-grants` lists or clears active grants anytime
5. **Audit trail** — every decision and execution lands in a JSONL log with three-layer redaction and a SHA-256 hash chain, so tampering is detectable
6. **Command quota** — `defaults.commandQuotaPerDay` caps command-bearing calls in a rolling 24h window, persisted on disk (restarts don't reset it), stopping runaway agent loops cold

Plus:

- Credentials never touch argv or logs: SSH agent → key file → env vars (`FLOTILLA_<NAME>_PASSWORD` / `FLOTILLA_SUDO_PASSWORD` …) → **OS keychain** (`flotilla keychain set <name> [--sudo]` — the config file stays secret-free)
- Host keys: TOFU in-process, `trustedHostKey` pinning across restarts; `fleet-add` pins on first contact
- **Algorithm allowlist on by default** (RFC 9142): no SHA-1 (ssh-rsa/group1/hmac-sha1), no CBC; a legacy box can opt out individually with `allowLegacyAlgorithms = true` (better: upgrade its sshd)
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
- **v1.x** ✅ — server-to-server ops (fleet-copy / fleet-sync / file diff), command quotas, JIT approval grants, algorithm allowlists (RFC 9142), OS keychain, `fleet add --bootstrap` one-command onboarding
- **v2 complete** — resident Gateway (stateless HTTP MCP + bearer auth) ✅; production deployment kit (Docker / systemd / TLS templates) ✅; Tailscale-style one-line enrollment ✅; centralized audit (sink forwarding + compliance export) ✅; web console (/console/ static SPA) ✅; aggregated MCP endpoint (mount external MCP servers behind the one /mcp) ✅; CA certificate auth (short-lived user certificates + fleet CA, see below)
- **v3 ideas** — lightweight on-host agent, DAG orchestration, team collaboration

### CA certificate auth (final v2 slice)

A fourth auth method, `auth = "certificate"`: instead of pinning each machine's public key into `authorized_keys`, a fleet CA (ed25519, auto-created next to the config as `fleet_ca` / `fleet_ca.pub`) signs **short-lived user certificates** (default 8h; `certValiditySeconds` tunes 300–604800), and each target's sshd trusts just one CA line.

```toml
[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
auth = "certificate"
keyRef = "~/.ssh/id_ed25519"     # the certified private key; principals default to user
certValiditySeconds = 3600       # optional, default 28800 (8h); auto re-signed at 1/4 TTL left
```

One-time target setup (installs the CA public key as an sshd TrustedUserCAKeys drop-in under `sshd_config.d`, idempotent):

```bash
install -d -m 755 /etc/ssh/sshd_config.d && \
  printf '%s\n' '<fleet_ca.pub contents>' > /etc/ssh/flotilla-ca.pub && \
  printf '%s\n' 'TrustedUserCAKeys /etc/ssh/flotilla-ca.pub' > /etc/ssh/sshd_config.d/60-flotilla-ca.conf && \
  systemctl reload ssh
```

How it works, in one sentence: the ssh2 client protocol cannot present OpenSSH certificates directly, so flotilla runs a **minimal ssh-agent per server** (in-process UNIX socket speaking the OpenSSH agent protocol's IDENTITIES/SIGN requests) that holds the current certificate and signs with the private key behind it — exactly the mechanism OpenSSH itself uses when an agent holds a cert. The operational wins: a leaked certificate dies at expiry, and revoking fleet access is deleting one CA line per target instead of hunting individual `authorized_keys` entries.

Note: enrollment (one-line onboarding) is unchanged — add the machine with password/agent auth first, run the CA install command above, then switch to `auth = "certificate"`. CI has no end-to-end sshd certificate-login test (no sshd targets in the environment); certificate correctness is guaranteed by `ssh-keygen -L` inspection and signature-verification tests instead.

## Contributing

Not open to external contributions during the private phase. After open-sourcing: file issues for bugs and requests; open an issue to discuss direction before large PRs. All PRs must pass CI (build + 460+ tests + Docker build).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=paipaiio/flotilla-mcp&type=Date)](https://star-history.com/#paipaiio/flotilla-mcp&Date)

## License

**GNU Affero General Public License v3.0** (see [LICENSE](./LICENSE)):

- ✅ Free to use, modify, and distribute — including internal production use
- ⚠️ Copyleft: distributing Flotilla or **offering it as a network service** requires disclosing the full source code to users (the AGPL network clause)
- 💼 Need to use it without AGPL obligations (e.g. closed-source commercial use)? Commercial licenses are available — reach out via [GitHub](https://github.com/paipaiio/flotilla-mcp)
