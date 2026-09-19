import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ProbeResult, ServerConfig } from "flotilla-core";
import { createEnrollment } from "../src/enroll.js";
import { createGateway } from "../src/http-server.js";

const BEARER = "operator-bearer-token-0123456";

let dir: string;
let configPath: string;
let auditEvents: unknown[];

/** Probe fake: hosts starting with "unreachable-" fail; others succeed. */
const fakeProbe = async (server: ServerConfig): Promise<ProbeResult> =>
  server.host.startsWith("unreachable-")
    ? { ok: false, error: "connect ECONNREFUSED" }
    : { ok: true, hostname: server.name, uid: 1000, tmux: true, hostKey: "SHA256:fakehostkey" };

const FLEET_CONFIG = `[defaults]
approvalMode = "ask-destructive"

[[servers]]
name = "web-1"
host = "192.168.1.10"
user = "root"
auth = "agent"
group = "dev"
tags = ["web"]
role = "operator"
readOnly = false
`;

async function startHttp(): Promise<{ server: Server; base: string }> {
  const stub = new McpServer({ name: "stub", version: "0" });
  const enrollment = createEnrollment({
    configPath,
    fleetKeyPath: join(dir, "fleet_ed25519"),
    probe: fakeProbe,
    audit: (event) => auditEvents.push(event),
  });
  const gateway = createGateway({ mcpServer: stub, token: BEARER, enrollment });
  await new Promise<void>((r) => gateway.server.listen(0, "127.0.0.1", r));
  const port = (gateway.server.address() as AddressInfo).port;
  return { server: gateway.server, base: `http://127.0.0.1:${port}` };
}

async function post(base: string, path: string, body: unknown, token?: string): Promise<{ status: number; json: () => Promise<unknown> }> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${base}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: res.status, json: async () => res.json() };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flotilla-enroll-"));
  configPath = join(dir, "config.toml");
  writeFileSync(configPath, FLEET_CONFIG, { mode: 0o600 });
  auditEvents = [];
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("enrollment token lifecycle", () => {
  it("creates a flt_ token, persists only its hash", () => {
    const enrollment = createEnrollment({ configPath, fleetKeyPath: join(dir, "fleet_ed25519") });
    const created = enrollment.createToken({ name: "rack-4" });
    expect(created.token).toMatch(/^flt_[0-9a-f]{64}$/);
    const stored = readFileSync(join(dir, "enroll-tokens.json"), "utf8");
    expect(stored).not.toContain(created.token);
    expect(stored).not.toContain(created.token.slice(4)); // no raw secret substring
    expect(enrollment.listTokens()).toHaveLength(1);
    expect(enrollment.listTokens()[0]).not.toHaveProperty("token");
  });

  it("enforces TTL", () => {
    const enrollment = createEnrollment({ configPath, fleetKeyPath: join(dir, "fleet_ed25519") });
    const expired = enrollment.createToken({ name: "old", ttlMs: -1000 });
    expect(expired.expiresAt).toBeLessThan(Date.now());
  });

  it("revokes", () => {
    const enrollment = createEnrollment({ configPath, fleetKeyPath: join(dir, "fleet_ed25519") });
    const created = enrollment.createToken({ name: "bye" });
    expect(enrollment.revokeToken(created.id)).toBe(true);
    expect(enrollment.revokeToken("nonexistent")).toBe(false);
    expect(enrollment.listTokens()[0].revoked).toBe(true);
  });
});

describe("enrollment join/confirm flow", () => {
  it("full lifecycle: join → install key → confirm → config appended", async () => {
    const { server, base } = await startHttp();
    try {
      // Operator creates a token with the gateway bearer.
      const denied = await post(base, "/api/enroll/tokens", { name: "nope" });
      expect(denied.status).toBe(401);
      const created = await post(base, "/api/enroll/tokens", { name: "rack-4-batch" }, BEARER);
      expect(created.status).toBe(200);
      const { token } = (await created.json()) as { token: string };

      // Node fetches the public script (no auth needed).
      const script = await fetch(`${base}/join.sh`);
      expect(script.status).toBe(200);
      const scriptText = await script.text();
      expect(scriptText).toContain(base);
      expect(() => execFileSync("sh", ["-n"], { input: scriptText })).not.toThrow();

      // Behind a TLS-terminating proxy the request is plain http; the script
      // must trust X-Forwarded-Proto so join/confirm don't eat a 301.
      // (fetch 会自行覆盖 Host 头，所以这里只断言协议部分。)
      const proxied = await fetch(`${base}/join.sh`, { headers: { "x-forwarded-proto": "https" } });
      const proxiedText = await proxied.text();
      expect(proxiedText).toContain('API="https://');
      expect(proxiedText).not.toContain('API="http://');

      // Node joins with the enrollment token.
      const joinRes = await post(base, "/api/enroll/join", { hostname: "pi-worker", user: "deploy", port: 2222 }, token);
      expect(joinRes.status).toBe(200);
      const joinBody = (await joinRes.json()) as { serverName: string; fleetPublicKey: string };
      expect(joinBody.serverName).toBe("pi-worker");
      expect(joinBody.fleetPublicKey).toContain("ssh-ed25519");
      expect(existsSync(join(dir, "fleet_ed25519"))).toBe(true);

      // A second host on a fresh token dedupes the name.
      const created2 = await post(base, "/api/enroll/tokens", { name: "second" }, BEARER);
      const { token: token2 } = (await created2.json()) as { token: string };
      const joinRes2 = await post(base, "/api/enroll/join", { hostname: "pi-worker" }, token2);
      expect(((await joinRes2.json()) as { serverName: string }).serverName).toBe("pi-worker-2");

      // The first token is single-use: a replay is refused.
      const replay = await post(base, "/api/enroll/join", { hostname: "evil" }, token);
      expect(replay.status).toBe(401);

      // Confirm binds pending + token: wrong token cannot trigger the probe.
      const wrongConfirm = await post(base, "/api/enroll/confirm", { serverName: "pi-worker" }, token2);
      expect(wrongConfirm.status).toBe(404);

      // Confirm succeeds; the config gains the server with a pinned host key.
      const confirm = await post(base, "/api/enroll/confirm", { serverName: "pi-worker" }, token);
      expect(confirm.status).toBe(200);
      const confirmBody = (await confirm.json()) as { ok: boolean; probedHostname: string };
      expect(confirmBody.ok).toBe(true);
      const configText = readFileSync(configPath, "utf8");
      expect(configText).toContain('name = "pi-worker"');
      expect(configText).toContain('host = "127.0.0.1"');
      expect(configText).toContain('port = 2222');
      expect(configText).toContain('user = "deploy"');
      expect(configText).toContain("SHA256:fakehostkey");
      expect(configText).toContain('"enrolled"');

      // Confirm is no longer retryable once consumed.
      const again = await post(base, "/api/enroll/confirm", { serverName: "pi-worker" }, token);
      expect(again.status).toBe(404);

      // Audit trail recorded the lifecycle.
      const tools = auditEvents.map((e) => (e as { tool: string }).tool);
      expect(tools).toContain("enroll-token-create");
      expect(tools).toContain("enroll-join");
      expect(tools).toContain("enroll-confirm");
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("pending enrollments and tokens survive a gateway restart", async () => {
    const first = createEnrollment({ configPath, fleetKeyPath: join(dir, "fleet_ed25519"), probe: fakeProbe });
    const { token } = first.createToken({ name: "across-restart" });
    const stub = new McpServer({ name: "stub", version: "0" });
    const gw1 = createGateway({ mcpServer: stub, token: BEARER, enrollment: first });
    await new Promise<void>((r) => gw1.server.listen(0, "127.0.0.1", r));
    const base1 = `http://127.0.0.1:${(gw1.server.address() as AddressInfo).port}`;
    const joinRes = await post(base1, "/api/enroll/join", { hostname: "survivor" }, token);
    const { serverName } = (await joinRes.json()) as { serverName: string };
    await new Promise<void>((r) => gw1.server.close(() => r()));

    // New process, same paths: the pending enrollment must still confirm.
    const second = createEnrollment({ configPath, fleetKeyPath: join(dir, "fleet_ed25519"), probe: fakeProbe });
    const gw2 = createGateway({ mcpServer: stub, token: BEARER, enrollment: second });
    await new Promise<void>((r) => gw2.server.listen(0, "127.0.0.1", r));
    const base2 = `http://127.0.0.1:${(gw2.server.address() as AddressInfo).port}`;
    try {
      const confirm = await post(base2, "/api/enroll/confirm", { serverName }, token);
      expect(confirm.status).toBe(200);
      expect(readFileSync(configPath, "utf8")).toContain('name = "survivor"');
    } finally {
      await new Promise<void>((r) => gw2.server.close(() => r()));
    }
  });

  it("allocates names that do not collide with existing fleet servers", async () => {
    const enrollment = createEnrollment({ configPath, fleetKeyPath: join(dir, "fleet_ed25519"), probe: fakeProbe });
    const { token } = enrollment.createToken({ name: "dup" });
    const stub = new McpServer({ name: "stub", version: "0" });
    const gateway = createGateway({ mcpServer: stub, token: BEARER, enrollment });
    await new Promise<void>((r) => gateway.server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(gateway.server.address() as AddressInfo).port}`;
    try {
      // "web-1" already exists in the fleet config.
      const joinRes = await post(base, "/api/enroll/join", { hostname: "web-1" }, token);
      expect(joinRes.status).toBe(200);
      expect(((await joinRes.json()) as { serverName: string }).serverName).toBe("web-1-2");
    } finally {
      await new Promise<void>((r) => gateway.server.close(() => r()));
    }
  });

  it("probe failure: 502, retryable, config untouched, then success on retry", async () => {
    // Direct-API test with a probe that fails once then succeeds.
    let attempts = 0;
    const flakyProbe = async (server: ServerConfig): Promise<ProbeResult> => {
      attempts += 1;
      if (attempts === 1) return { ok: false, error: "sshd not reloaded yet" };
      return { ok: true, hostname: server.name, uid: 0, tmux: false, hostKey: "SHA256:retry-key" };
    };
    const enrollment = createEnrollment({
      configPath,
      fleetKeyPath: join(dir, "fleet_ed25519"),
      probe: flakyProbe,
      audit: (event) => auditEvents.push(event),
    });
    const { token } = enrollment.createToken({ name: "flaky" });

    // Drive join/confirm through a throwaway HTTP server.
    const stub = new McpServer({ name: "stub", version: "0" });
    const gateway = createGateway({ mcpServer: stub, token: BEARER, enrollment });
    await new Promise<void>((r) => gateway.server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(gateway.server.address() as AddressInfo).port}`;
    try {
      const joinRes = await post(base, "/api/enroll/join", { hostname: "slowbox" }, token);
      const { serverName } = (await joinRes.json()) as { serverName: string };
      const before = readFileSync(configPath, "utf8");

      const fail = await post(base, "/api/enroll/confirm", { serverName }, token);
      expect(fail.status).toBe(502);
      expect(((await fail.json()) as { retryable: boolean }).retryable).toBe(true);
      expect(readFileSync(configPath, "utf8")).toBe(before);

      const ok = await post(base, "/api/enroll/confirm", { serverName }, token);
      expect(ok.status).toBe(200);
      const text = readFileSync(configPath, "utf8");
      expect(text).toContain('name = "slowbox"');
      expect(text).toContain("SHA256:retry-key");
    } finally {
      await new Promise<void>((r) => gateway.server.close(() => r()));
    }
  });

  it("join requires a usable token and a hostname", async () => {
    const enrollment = createEnrollment({ configPath, fleetKeyPath: join(dir, "fleet_ed25519") });
    const stub = new McpServer({ name: "stub", version: "0" });
    const gateway = createGateway({ mcpServer: stub, token: BEARER, enrollment });
    await new Promise<void>((r) => gateway.server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(gateway.server.address() as AddressInfo).port}`;
    try {
      expect((await post(base, "/api/enroll/join", { hostname: "x" })).status).toBe(401);
      const { token } = enrollment.createToken({ name: "t" });
      expect((await post(base, "/api/enroll/join", {}, token)).status).toBe(400);

      // Expired tokens refuse.
      const expired = enrollment.createToken({ name: "e", ttlMs: -1 });
      expect((await post(base, "/api/enroll/join", { hostname: "x" }, expired.token)).status).toBe(401);

      // Revoked tokens refuse.
      const revoked = enrollment.createToken({ name: "r" });
      expect(enrollment.revokeToken(revoked.id)).toBe(true);
      expect((await post(base, "/api/enroll/join", { hostname: "x" }, revoked.token)).status).toBe(401);

      // maxUses is enforced across joins.
      const multi = enrollment.createToken({ name: "m", maxUses: 2 });
      expect((await post(base, "/api/enroll/join", { hostname: "a1" }, multi.token)).status).toBe(200);
      expect((await post(base, "/api/enroll/join", { hostname: "a2" }, multi.token)).status).toBe(200);
      expect((await post(base, "/api/enroll/join", { hostname: "a3" }, multi.token)).status).toBe(401);
    } finally {
      await new Promise<void>((r) => gateway.server.close(() => r()));
    }
  });

  it("sanitizes hostnames, defaults user/port, and honors the self-reported IP", async () => {
    const probed: ServerConfig[] = [];
    const enrollment = createEnrollment({
      configPath,
      fleetKeyPath: join(dir, "fleet_ed25519"),
      probe: async (server) => {
        probed.push(server);
        return { ok: true, hostname: server.name, uid: 1000, tmux: true, hostKey: "SHA256:pk" };
      },
    });
    const stub = new McpServer({ name: "stub", version: "0" });
    const gateway = createGateway({ mcpServer: stub, token: BEARER, enrollment });
    await new Promise<void>((r) => gateway.server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(gateway.server.address() as AddressInfo).port}`;
    try {
      const { token } = enrollment.createToken({ name: "defaults" });
      // Weird hostname sanitized; empty user → root; out-of-range port → 22;
      // TCP peer is loopback, so the self-reported primary IP wins.
      const joinRes = await post(
        base,
        "/api/enroll/join",
        { hostname: "My_Host.local!", user: "  ", port: 70000, primaryIp: "10.9.8.7" },
        token,
      );
      expect(joinRes.status).toBe(200);
      const { serverName } = (await joinRes.json()) as { serverName: string };
      expect(serverName).toBe("my-host-local");
      const confirm = await post(base, "/api/enroll/confirm", { serverName }, token);
      expect(confirm.status).toBe(200);
      expect(probed).toHaveLength(1);
      expect(probed[0].user).toBe("root");
      expect(probed[0].port).toBe(22);
      expect(probed[0].host).toBe("10.9.8.7");
    } finally {
      await new Promise<void>((r) => gateway.server.close(() => r()));
    }
  });

  it("caps pending enrollments per token and surfaces store errors as 4xx", async () => {
    const enrollment = createEnrollment({ configPath, fleetKeyPath: join(dir, "fleet_ed25519"), probe: fakeProbe });
    const stub = new McpServer({ name: "stub", version: "0" });
    const gateway = createGateway({ mcpServer: stub, token: BEARER, enrollment });
    await new Promise<void>((r) => gateway.server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(gateway.server.address() as AddressInfo).port}`;
    try {
      const { token } = enrollment.createToken({ name: "burst", maxUses: 20 });
      for (let i = 0; i < 8; i++) {
        expect((await post(base, "/api/enroll/join", { hostname: `burst-${i}` }, token)).status).toBe(200);
      }
      expect((await post(base, "/api/enroll/join", { hostname: "burst-9" }, token)).status).toBe(429);

      // Malformed JSON on a node route is a 400, not a crash.
      const bad = await fetch(`${base}/api/enroll/join`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: "{oops",
      });
      expect(bad.status).toBe(400);

      // Operator management over HTTP: list and revoke.
      const list = await fetch(`${base}/api/enroll/tokens`, { headers: { authorization: `Bearer ${BEARER}` } });
      expect(list.status).toBe(200);
      const listed = ((await list.json()) as { tokens: Array<{ id: string; name: string }> }).tokens;
      const burst = listed.find((t) => t.name === "burst");
      expect(burst).toBeDefined();
      const del = await fetch(`${base}/api/enroll/tokens/${burst!.id}`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${BEARER}` },
      });
      expect(del.status).toBe(200);
      // Unknown id → 404 (already-revoked stays idempotent 200).
      const delAgain = await fetch(`${base}/api/enroll/tokens/ffffffffffffffff`, {
        method: "DELETE",
        headers: { authorization: `Bearer ${BEARER}` },
      });
      expect(delAgain.status).toBe(404);
      // Token creation without a name is a 400.
      const noName = await post(base, "/api/enroll/tokens", {}, BEARER);
      expect(noName.status).toBe(400);
    } finally {
      await new Promise<void>((r) => gateway.server.close(() => r()));
    }
  });
});
