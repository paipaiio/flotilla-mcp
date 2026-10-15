import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createGateway } from "../src/http-server.js";
import { addToken, createTokenStore, listTokens, revokeToken } from "../src/tokens.js";

const ADMIN = "admin-gateway-token-0123456789";

function tokensPath(): string {
  return join(mkdtempSync(join(tmpdir(), "flotilla-tokens-")), "gateway-tokens.json");
}

describe("scoped gateway tokens file", () => {
  it("stores only a hash, 0600, and round-trips create/list/revoke", () => {
    const path = tokensPath();
    const { token, entry } = addToken(path, { name: "ci", maxRole: "viewer", targets: ["tag:web"] });
    expect(token).toMatch(/^flt_gw_[A-Za-z0-9_-]{40,}$/);
    const raw = readFileSync(path, "utf8");
    expect(raw).not.toContain(token);
    expect(raw).toContain(entry.sha256);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(listTokens(path).map((t) => [t.name, t.maxRole, t.targets])).toEqual([["ci", "viewer", ["tag:web"]]]);
    expect(() => addToken(path, { name: "ci", maxRole: "admin" })).toThrow(/exists/);
    // An empty target list must never silently mean "whole fleet".
    expect(() => addToken(path, { name: "empty", maxRole: "viewer", targets: [] })).toThrow(/empty/);
    expect(revokeToken(path, "ci")).toBe(true);
    expect(listTokens(path)).toEqual([]);
    expect(revokeToken(path, "ci")).toBe(false);
  });

  it("matches presented tokens and picks up edits without a restart", () => {
    const path = tokensPath();
    const store = createTokenStore(path);
    const first = addToken(path, { name: "a", maxRole: "operator" });
    expect(store.match(first.token)?.name).toBe("a");
    expect(store.match("flt_gw_wrong")).toBeUndefined();
    revokeToken(path, "a");
    expect(store.match(first.token)).toBeUndefined();
  });

  it("rejects malformed files instead of guessing", () => {
    const path = tokensPath();
    writeFileSync(path, JSON.stringify({ tokens: [{ name: "x", sha256: "nothex", maxRole: "root" }] }), { mode: 0o600 });
    expect(() => listTokens(path)).toThrow(/tokens file/);
  });

  it("treats a missing file as no scoped tokens", () => {
    expect(createTokenStore(join(tmpdir(), "flotilla-definitely-missing.json")).match("anything")).toBeUndefined();
  });
});

describe("gateway with scoped tokens", () => {
  let http: Server | undefined;
  afterEach(() => http?.close());

  async function call(base: string, token: string) {
    const headers = { accept: "application/json, text/event-stream", "content-type": "application/json", authorization: `Bearer ${token}` };
    const post = (body: unknown) => fetch(`${base}/mcp`, { method: "POST", headers, body: JSON.stringify(body) });
    await post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    const res = await post({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "whoami", arguments: {} } });
    const text = await res.text();
    const line = text.split(/\r?\n/).find((l) => l.startsWith("data: "));
    return { status: res.status, body: line ? JSON.parse(line.slice(6)) : text };
  }

  it("attaches the token's principal to MCP calls; the admin token has none", async () => {
    const path = tokensPath();
    const { token } = addToken(path, { name: "ci", maxRole: "viewer", targets: ["tag:web"] });
    const server = new McpServer({ name: "stub", version: "0" });
    server.registerTool("whoami", { description: "echo principal", inputSchema: {} }, async (_args, extra) => ({
      content: [{ type: "text" as const, text: JSON.stringify(extra.authInfo?.extra?.["flotillaPrincipal"] ?? null) }],
    }));
    const gateway = createGateway({ mcpServer: server, token: ADMIN, scopedTokens: createTokenStore(path), requestLog: () => {} });
    http = gateway.server;
    await new Promise<void>((r) => http!.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;

    const scoped = await call(base, token);
    expect(scoped.status).toBe(200);
    expect(JSON.parse(scoped.body.result.content[0].text)).toEqual({ name: "ci", maxRole: "viewer", targets: ["tag:web"] });

    const admin = await call(base, ADMIN);
    expect(admin.body.result.content[0].text).toBe("null");

    expect((await call(base, "flt_gw_not_a_token")).status).toBe(401);
  });
});
