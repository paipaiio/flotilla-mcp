/**
 * Flotilla enrollment — Tailscale-style one-line host onboarding (§9.1).
 *
 * The fleet stays agentless: a new host proves possession of a short-lived
 * enrollment token, installs the fleet public key into its own
 * authorized_keys (so no password ever crosses the wire), and the gateway
 * verifies the result with a real SSH probe before atomically appending the
 * server to the fleet config. The existing config watcher hot-reloads it.
 *
 * Token model: `flt_<64 hex>`, shown once at creation, stored only as a
 * sha256 hash next to the fleet config (mode 600) alongside TTL / max-use /
 * revoke metadata. A token is consumed by /join — after that the pending
 * enrollment lives on and /confirm can be retried with the same token.
 *
 * Threat notes:
 * - The enrollment token is a bearer secret: TLS in front of the gateway is
 *   mandatory on any untrusted network (see deploy/).
 * - join.sh pins nothing about the gateway by itself; operators should pass
 *   --fingerprint <sha256> on first enrollment so the node can detect a
 *   counterfeit gateway.
 * - The gateway must be able to open the SSH connection back to the joining
 *   host (same constraint as every other fleet operation). The connect IP
 *   defaults to the TCP peer of the join request.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  appendServerToConfig,
  ensureFleetKeyPair,
  parseFleetConfig,
  probeServer,
  type AuditEvent,
  type ProbeResult,
  type Role,
  type ServerConfig,
} from "flotilla-core";

export const ENROLL_TOKEN_PREFIX = "flt_";
const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1h
const MAX_PENDING_PER_TOKEN = 8;

export interface EnrollmentTokenMeta {
  id: string;
  name: string;
  createdAt: number;
  expiresAt: number;
  maxUses: number;
  usedCount: number;
  revoked: boolean;
}

interface TokenRecord extends EnrollmentTokenMeta {
  /** sha256 of the bearer token — the secret itself is never persisted. */
  hash: string;
}

interface PendingEnrollment {
  tokenId: string;
  serverName: string;
  user: string;
  port: number;
  /** Where the gateway will SSH back to. */
  connectHost: string;
  hostname: string;
  requestedAt: number;
  lastError?: string;
}

interface TokenStoreFile {
  tokens: TokenRecord[];
  pending: PendingEnrollment[];
}

export interface EnrollmentOptions {
  /** Effective fleet config path — servers are appended here. */
  configPath: string;
  /** Fleet keypair path; created on first use (ssh-keygen ed25519). */
  fleetKeyPath: string;
  defaults?: {
    user?: string;
    port?: number;
    group?: string;
    role?: Role;
    tags?: string[];
  };
  /** SSH probe — inject a fake in tests. Defaults to core probeServer. */
  probe?: (server: ServerConfig) => Promise<ProbeResult>;
  audit?: (event: AuditEvent) => void;
}

export interface Enrollment {
  /** Handle an HTTP request; returns true when consumed. */
  handle(req: IncomingMessage, res: ServerResponse): Promise<boolean>;
  /** Direct API for tests/CLI: create a token, returns the secret once. */
  createToken(input: { name: string; ttlMs?: number; maxUses?: number }): EnrollmentTokenMeta & { token: string };
  listTokens(): EnrollmentTokenMeta[];
  revokeToken(id: string): boolean;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

function readBody(req: IncomingMessage, limit = 64 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** Atomically rewrite the store; a torn write must never lose tokens. */
function writeStoreAtomic(path: string, store: TokenStoreFile): void {
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmp, JSON.stringify(store, null, 2), { encoding: "utf8", mode: 0o600, flag: "wx" });
  renameSync(tmp, path);
  chmodSync(path, 0o600);
}

/** Parse the container's default gateway from /proc/net-route (Linux).
 *  Behind docker bridge networking every proxied connection arrives with the
 *  HOST's bridge IP (e.g. 172.17.0.1) as peer — treating that as the node's
 *  address makes the gateway SSH into itself instead of the enrolling host. */
function dockerDefaultGateway(): string {
  try {
    const routes = readFileSync("/proc/net/route", "utf8").split("\n");
    for (const line of routes.slice(1)) {
      const fields = line.trim().split(/\s+/);
      if (fields[1] === "00000000" && fields[2]) {
        const hex = fields[2];
        return [6, 4, 2, 0].map((i) => parseInt(hex.slice(i, i + 2), 16)).join(".");
      }
    }
  } catch { /* non-Linux or unreadable — no gateway to exclude */ }
  return "";
}

export function connectIpOf(req: IncomingMessage, selfReported?: string, gatewayIp = dockerDefaultGateway()): string {
  // Behind a reverse proxy the peer is the proxy, not the node — the original
  // client IP rides in X-Forwarded-For (leftmost hop).
  const xff = req.headers["x-forwarded-for"];
  if (xff) {
    const first = String(xff).split(",")[0]?.trim();
    if (first) return first;
  }
  const peer = req.socket.remoteAddress ?? "";
  const v4 = peer.startsWith("::ffff:") ? peer.slice(7) : peer;
  if (v4 && v4 !== "::1" && v4 !== "127.0.0.1" && v4 !== gatewayIp) return v4;
  return selfReported ?? v4 ?? "127.0.0.1";
}

export function createEnrollment(options: EnrollmentOptions): Enrollment {
  const storePath = `${dirname(options.configPath)}/enroll-tokens.json`;
  const probe = options.probe ?? probeServer;
  const defaults = options.defaults ?? {};
  const fleetKey = () => ensureFleetKeyPair(options.fleetKeyPath);

  function loadStore(): TokenStoreFile {
    try {
      if (!existsSync(storePath)) return { tokens: [], pending: [] };
      const parsed = JSON.parse(readFileSync(storePath, "utf8")) as TokenStoreFile;
      return { tokens: parsed.tokens ?? [], pending: parsed.pending ?? [] };
    } catch {
      return { tokens: [], pending: [] };
    }
  }

  function saveStore(store: TokenStoreFile): void {
    writeStoreAtomic(storePath, store);
  }

  function publicMeta(t: TokenRecord): EnrollmentTokenMeta {
    const { hash: _hash, ...meta } = t;
    return meta;
  }

  function findUsableToken(store: TokenStoreFile, presented: string): TokenRecord | undefined {
    const hash = hashToken(presented);
    const now = Date.now();
    return store.tokens.find(
      (t) => !t.revoked && t.expiresAt > now && t.usedCount < t.maxUses && safeEqualHex(t.hash, hash),
    );
  }

  /** Unique server name: hostname, hostname-2, hostname-3, ... */
  function allocateName(taken: Set<string>, hostname: string): string {
    const base =
      hostname.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "host";
    if (!taken.has(base)) return base;
    for (let i = 2; ; i++) {
      const candidate = `${base}-${i}`;
      if (!taken.has(candidate)) return candidate;
    }
  }

  function takenNames(): Set<string> {
    const taken = new Set<string>();
    try {
      for (const s of parseFleetConfig(readFileSync(options.configPath, "utf8")).servers) taken.add(s.name);
    } catch { /* config unreadable — pending names still guard duplicates */ }
    for (const p of loadStore().pending) taken.add(p.serverName);
    return taken;
  }

  function appendServerToFleetConfig(server: ServerConfig): void {
    const text = readFileSync(options.configPath, "utf8");
    const next = appendServerToConfig(text, server);
    const tmp = `${options.configPath}.enroll-${process.pid}-${Date.now()}.tmp`;
    try {
      writeFileSync(tmp, next, { encoding: "utf8", mode: 0o600, flag: "wx" });
      renameSync(tmp, options.configPath);
      chmodSync(options.configPath, 0o600);
    } catch (err) {
      try { unlinkSync(tmp); } catch { /* nothing to clean */ }
      throw err;
    }
  }

  function createToken(input: { name: string; ttlMs?: number; maxUses?: number }) {
    const token = ENROLL_TOKEN_PREFIX + randomBytes(32).toString("hex");
    const record: TokenRecord = {
      id: randomBytes(8).toString("hex"),
      name: input.name,
      createdAt: Date.now(),
      expiresAt: Date.now() + (input.ttlMs ?? DEFAULT_TTL_MS),
      maxUses: Math.max(1, input.maxUses ?? 1),
      usedCount: 0,
      revoked: false,
      hash: hashToken(token),
    };
    const store = loadStore();
    store.tokens.push(record);
    saveStore(store);
    options.audit?.({
      kind: "execution",
      tool: "enroll-token-create",
      command: `enrollment token "${input.name}" created (ttl=${input.ttlMs ?? DEFAULT_TTL_MS}ms, maxUses=${record.maxUses})`,
      outcome: "ok",
    });
    return { ...publicMeta(record), token };
  }

  function listTokens(): EnrollmentTokenMeta[] {
    return loadStore().tokens.map(publicMeta);
  }

  function revokeToken(id: string): boolean {
    const store = loadStore();
    const record = store.tokens.find((t) => t.id === id);
    if (!record) return false;
    record.revoked = true;
    saveStore(store);
    options.audit?.({
      kind: "execution",
      tool: "enroll-token-revoke",
      command: `enrollment token "${record.name}" revoked`,
      outcome: "ok",
    });
    return true;
  }

  async function handleJoin(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const presented = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
    const body = JSON.parse(await readBody(req)) as {
      hostname?: string;
      user?: string;
      port?: number;
      primaryIp?: string;
    };
    const store = loadStore();
    const record = presented ? findUsableToken(store, presented) : undefined;
    if (!record) {
      sendJson(res, 401, { error: "invalid, expired, or exhausted enrollment token" });
      return;
    }
    const hostname = (body.hostname ?? "").trim();
    if (!hostname) {
      sendJson(res, 400, { error: "hostname is required" });
      return;
    }
    const user = (body.user ?? defaults.user ?? "root").trim() || "root";
    const port =
      Number.isInteger(body.port) && (body.port as number) > 0 && (body.port as number) <= 65535
        ? (body.port as number)
        : (defaults.port ?? 22);
    const tokenPending = store.pending.filter((p) => p.tokenId === record.id);
    if (tokenPending.length >= MAX_PENDING_PER_TOKEN) {
      sendJson(res, 429, { error: "too many pending enrollments on this token" });
      return;
    }
    record.usedCount += 1;
    const serverName = allocateName(takenNames(), hostname);
    store.pending.push({
      tokenId: record.id,
      serverName,
      user,
      port,
      connectHost: connectIpOf(req, body.primaryIp),
      hostname,
      requestedAt: Date.now(),
    });
    saveStore(store);
    options.audit?.({
      kind: "execution",
      tool: "enroll-join",
      command: `host "${hostname}" requested enrollment as "${serverName}" (${user}@${connectIpOf(req, body.primaryIp)}:${port})`,
      hosts: [serverName],
      outcome: "ok",
    });
    sendJson(res, 200, {
      serverName,
      fleetPublicKey: fleetKey().publicKey.trim(),
      enrollUser: user,
    });
  }

  async function handleConfirm(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const presented = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
    const body = JSON.parse(await readBody(req)) as { serverName?: string };
    const store = loadStore();
    // Confirm requires the same enrollment token: pending names are not a
    // capability — guessing one must not be enough to trigger SSH probes.
    const record = presented ? store.tokens.find((t) => safeEqualHex(t.hash, hashToken(presented))) : undefined;
    const pending = store.pending.find((p) => p.serverName === body.serverName && p.tokenId === record?.id);
    if (!record || !pending) {
      sendJson(res, 404, { error: `no pending enrollment named "${body.serverName ?? ""}"` });
      return;
    }
    const keyRef = fleetKey().privateKeyPath;
    const server: ServerConfig = {
      name: pending.serverName,
      host: pending.connectHost,
      port: pending.port,
      user: pending.user,
      auth: "key",
      keyRef,
      group: defaults.group ?? "dev",
      tags: [...(defaults.tags ?? []), "enrolled"],
      role: defaults.role ?? "operator",
      readOnly: false,
    };
    const result = await probe(server);
    if (!result.ok) {
      pending.lastError = result.error ?? "probe failed";
      saveStore(store);
      options.audit?.({
        kind: "execution",
        tool: "enroll-confirm",
        command: `SSH probe of "${pending.serverName}" failed: ${pending.lastError}`,
        hosts: [pending.serverName],
        outcome: "failed",
      });
      sendJson(res, 502, {
        error: `SSH probe failed (key auth not working yet?): ${pending.lastError}`,
        retryable: true,
      });
      return;
    }
    try {
      appendServerToFleetConfig({ ...server, trustedHostKey: result.hostKey });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      pending.lastError = message;
      saveStore(store);
      sendJson(res, 500, { error: `config append failed: ${message}` });
      return;
    }
    store.pending = store.pending.filter((p) => p !== pending);
    saveStore(store);
    options.audit?.({
      kind: "execution",
      tool: "enroll-confirm",
      command: `server "${pending.serverName}" enrolled (${pending.user}@${pending.connectHost}:${pending.port})`,
      hosts: [pending.serverName],
      outcome: "ok",
    });
    sendJson(res, 200, {
      ok: true,
      serverName: pending.serverName,
      probedHostname: result.hostname,
      hostKey: result.hostKey ?? null,
      note: "fleet config updated; the watcher hot-reloads within ~300ms",
    });
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    try {
      // Node-facing surface: the script is public (it embeds no secret),
      // join/confirm authenticate with the enrollment token itself.
      if (path === "/join.sh" && method === "GET") {
        // Behind a TLS-terminating reverse proxy the local request is plain
        // http — trust X-Forwarded-Proto so the script points at https and
        // doesn't eat an nginx 301 on its own join/confirm POSTs.
        const proto = String(req.headers["x-forwarded-proto"] ?? "http").split(",")[0].trim();
        const host = req.headers.host ?? url.host;
        const origin = `${proto}://${host}`;
        res.writeHead(200, { "content-type": "text/x-shellscript; charset=utf-8" });
        res.end(renderJoinScript(origin));
        return true;
      }
      if (path === "/api/enroll/join" && method === "POST") {
        await handleJoin(req, res);
        return true;
      }
      if (path === "/api/enroll/confirm" && method === "POST") {
        await handleConfirm(req, res);
        return true;
      }

      // Operator-facing management: http-server runs these only after the
      // gateway bearer check, so the token never needs its own middleware.
      if (path === "/api/enroll/tokens") {
        if (method === "POST") {
          const body = JSON.parse(await readBody(req)) as { name?: string; ttlMs?: number; maxUses?: number };
          if (!body.name || !body.name.trim()) {
            sendJson(res, 400, { error: "name is required" });
            return true;
          }
          sendJson(res, 200, createToken({ name: body.name.trim(), ttlMs: body.ttlMs, maxUses: body.maxUses }));
          return true;
        }
        if (method === "GET") {
          sendJson(res, 200, { tokens: listTokens() });
          return true;
        }
      }
      const revokeMatch = path.match(/^\/api\/enroll\/tokens\/([a-f0-9]+)$/);
      if (revokeMatch && method === "DELETE") {
        const revoked = revokeToken(revokeMatch[1]);
        sendJson(res, revoked ? 200 : 404, revoked ? { ok: true } : { error: "no such token" });
        return true;
      }
    } catch (err) {
      if (!res.headersSent) {
        sendJson(res, 400, { error: `bad request: ${err instanceof Error ? err.message : String(err)}` });
      }
      return true;
    }
    return false;
  }

  return { handle, createToken, listTokens, revokeToken };
}

/**
 * Self-enrollment script served at /join.sh. POSIX sh, set -eu, needs only
 * curl + standard coreutils. The fleet public key is appended idempotently
 * to the enrolling user's authorized_keys; no password ever crosses the wire.
 */
export function renderJoinScript(origin: string): string {
  const gateway = origin.replace(/"/g, "");
  return `#!/bin/sh
# Flotilla self-enrollment — run: curl -fsSL ${gateway}/join.sh | sudo sh -s -- --token flt_...
set -eu

TOKEN=""
USER_NAME=""
PORT="22"
FINGERPRINT=""
API="${gateway}"

while [ \$# -gt 0 ]; do
  case "\$1" in
    --token) TOKEN="\$2"; shift 2 ;;
    --user) USER_NAME="\$2"; shift 2 ;;
    --port) PORT="\$2"; shift 2 ;;
    --fingerprint) FINGERPRINT="\$2"; shift 2 ;;
    *) echo "unknown argument: \$1" >&2; exit 2 ;;
  esac
done

[ -n "\$TOKEN" ] || { echo "--token is required (create one: POST /api/enroll/tokens)" >&2; exit 2; }

if [ "\$(id -u)" != "0" ] && [ -z "\$USER_NAME" ]; then
  echo "run as root, or pass --user <name> to enroll a non-root account" >&2
  exit 1
fi
USER_NAME="\${USER_NAME:-\$(id -un)}"

# Optional on first enrollment over an untrusted network: pin the gateway's
# TLS certificate SHA-256 so a counterfeit gateway is rejected.
if [ -n "\$FINGERPRINT" ]; then
  HOSTPORT="\$(printf '%s' "\$API" | sed -e 's|^https://||' -e 's|/.*||')"
  FP="\$(openssl s_client -connect "\$HOSTPORT:443" -servername "\$HOSTPORT" </dev/null 2>/dev/null \\
        | openssl x509 -noout -fingerprint -sha256 | sed 's/^.*= *//; s/://g' | tr 'A-F' 'a-f')"
  [ "\$FP" = "\$(echo "\$FINGERPRINT" | tr 'A-F' 'a-f' | sed 's/://g')" ] \\
    || { echo "gateway certificate fingerprint mismatch — possible counterfeit" >&2; exit 1; }
fi

HOSTNAME_S="\$(hostname -s 2>/dev/null || hostname)"
PRIMARY_IP="\$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print \$2}' | cut -d/ -f1 | head -n1 || true)"
[ -n "\$PRIMARY_IP" ] || PRIMARY_IP="\$(ifconfig 2>/dev/null | awk '/inet /{print \$2}' | grep -v '^127\\.' | head -n1 || true)"

RESP_BODY="\$(mktemp)"; trap 'rm -f "\$RESP_BODY"' EXIT

echo ">> enrolling '\$HOSTNAME_S' into \$API as \$USER_NAME (port \$PORT)"
# 不用 curl -f：-f 会把 4xx 的响应体吞掉，报错只剩空白。手动判状态码，
# 把 gateway 返回的具体错误（如 bad request: ...）原样亮出来，否则现场无法诊断。
JOIN_HTTP="\$(curl -sS -L -o "\$RESP_BODY" -w '%{http_code}' -X POST "\$API/api/enroll/join" \\
  -H "Authorization: Bearer \$TOKEN" -H 'Content-Type: application/json' \\
  -d "{\\"hostname\\":\\"\$HOSTNAME_S\\",\\"user\\":\\"\$USER_NAME\\",\\"port\\":\$PORT,\\"primaryIp\\":\\"\$PRIMARY_IP\\"}")" \\
  || { echo "enrollment request failed: 网络/传输错误（HTTP 都没拿到）" >&2; exit 1; }
JOIN_RESP="\$(cat "\$RESP_BODY")"
[ "\$JOIN_HTTP" = "200" ] || { echo "enrollment refused (HTTP \$JOIN_HTTP): \$JOIN_RESP" >&2; exit 1; }

SERVER_NAME="\$(printf '%s' "\$JOIN_RESP" | sed -n 's/.*"serverName":"\\([^"]*\\)".*/\\1/p')"
FLEET_KEY="\$(printf '%s' "\$JOIN_RESP" | sed -n 's/.*"fleetPublicKey":"\\([^"]*\\)".*/\\1/p')"
[ -n "\$SERVER_NAME" ] && [ -n "\$FLEET_KEY" ] || { echo "enrollment refused: \$JOIN_RESP" >&2; exit 1; }

HOME_DIR="\$(getent passwd "\$USER_NAME" | cut -d: -f6)"
AUTH_DIR="\$HOME_DIR/.ssh"
AUTH_FILE="\$AUTH_DIR/authorized_keys"
mkdir -p "\$AUTH_DIR"
touch "\$AUTH_FILE"
chmod 700 "\$AUTH_DIR" 2>/dev/null || true
chmod 600 "\$AUTH_FILE" 2>/dev/null || true

grep -qxF "\$FLEET_KEY" "\$AUTH_FILE" 2>/dev/null || printf '%s\\n' "\$FLEET_KEY" >> "\$AUTH_FILE"
chown -R "\$USER_NAME" "\$AUTH_DIR" 2>/dev/null || true

echo ">> fleet key installed for \$USER_NAME; confirming with gateway..."
CONFIRM_HTTP="\$(curl -sS -L -o "\$RESP_BODY" -w '%{http_code}' -X POST "\$API/api/enroll/confirm" \\
  -H "Authorization: Bearer \$TOKEN" -H 'Content-Type: application/json' \\
  -d "{\\"serverName\\":\\"\$SERVER_NAME\\"}")" || CONFIRM_HTTP="000"
CONFIRM_RESP="\$(cat "\$RESP_BODY")"
if [ "\$CONFIRM_HTTP" != "200" ]; then
  echo ">> gateway could not SSH back yet (sshd reloaded? firewall?): HTTP \$CONFIRM_HTTP \${CONFIRM_RESP:-curl failed}" >&2
  echo ">> the enrollment stays pending; re-run this script to retry" >&2
  exit 1
fi

echo ">> enrolled as '\$SERVER_NAME': \$CONFIRM_RESP"
echo ">> host key pinned by the gateway; fleet config updated (hot reload ~300ms)"
`;
}
