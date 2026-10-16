import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createGateway } from "../src/http-server.js";

const TOKEN = "test-gateway-token-0123456789abcdef";

let stubServer: McpServer;
let http: Server;
let base: string;

function makeStubServer(): McpServer {
  const server = new McpServer({ name: "gateway-stub", version: "0.0.0" });
  server.registerTool("ping", { description: "reply pong", inputSchema: {} }, async () => ({
    content: [{ type: "text" as const, text: "pong" }],
  }));
  return server;
}

async function start(gatewayOpts?: Partial<Parameters<typeof createGateway>[0]>): Promise<void> {
  const gateway = createGateway({ mcpServer: stubServer, token: TOKEN, ...gatewayOpts });
  http = gateway.server;
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  const port = (http.address() as AddressInfo).port;
  base = `http://127.0.0.1:${port}`;
}

async function mcpPost(
  body: unknown,
  token?: string,
): Promise<{ status: number; contentType: string | null; payload: unknown }> {
  const headers: Record<string, string> = {
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
  };
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  const res = await fetch(`${base}/mcp`, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await res.text();
  // Streamable HTTP answers JSON-RPC either as plain JSON or as one SSE
  // `data:` line — normalize both to the parsed JSON-RPC object.
  let payload: unknown = null;
  if (text) {
    const dataLine = text.split(/\r?\n/).find((l) => l.startsWith("data: "));
    const jsonText = dataLine ? dataLine.slice("data: ".length) : text;
    try {
      payload = JSON.parse(jsonText);
    } catch {
      payload = text;
    }
  }
  return { status: res.status, contentType: res.headers.get("content-type"), payload };
}

const initialize = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "gateway-test", version: "1.0.0" } } };
const initialized = { jsonrpc: "2.0", method: "notifications/initialized" };

beforeEach(async () => {
  stubServer = makeStubServer();
  await start();
});

afterEach(async () => {
  await new Promise<void>((r) => http.close(() => r()));
});

describe("gateway auth", () => {
  it("rejects /mcp without a bearer token", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
  });

  it("rejects /mcp with a wrong bearer token", async () => {
    const { status } = await mcpPost(initialize, "wrong-token-value");
    expect(status).toBe(401);
  });

  it("rejects bearer tokens of the same length as a timing probe", async () => {
    const { status } = await mcpPost(initialize, "x".repeat(TOKEN.length));
    expect(status).toBe(401);
  });

  it("accepts the correct bearer token", async () => {
    const { status, payload } = await mcpPost(initialize, TOKEN);
    expect(status).toBe(200);
    const msg = payload as { result?: { serverInfo?: { name?: string } } };
    expect(msg.result?.serverInfo?.name).toBe("gateway-stub");
  });

  it("refuses to start without a token or with a trivial one", () => {
    expect(() => createGateway({ mcpServer: stubServer, token: "" })).toThrow(/token/);
    expect(() => createGateway({ mcpServer: stubServer, token: "short" })).toThrow(/token/);
  });
});

describe("gateway MCP stateless transport", () => {
  it("serves tools/list after initialize", async () => {
    await mcpPost(initialize, TOKEN);
    await mcpPost(initialized, TOKEN);
    const { status, payload } = await mcpPost({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, TOKEN);
    expect(status).toBe(200);
    const msg = payload as { result?: { tools?: Array<{ name: string }> } };
    expect(msg.result?.tools?.map((t) => t.name)).toContain("ping");
  });

  it("serves a tool call without any session header (stateless)", async () => {
    const { status, payload } = await mcpPost(
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "ping", arguments: {} } },
      TOKEN,
    );
    expect(status).toBe(200);
    const msg = payload as { result?: { content?: Array<{ type: string; text?: string }> } };
    expect(msg.result?.content?.[0]?.text).toBe("pong");
  });

  it("rejects malformed JSON with 400", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: "{not json",
    });
    expect(res.status).toBe(400);
  });

  it("rejects DELETE (stateless: no sessions) with 405", async () => {
    const res = await fetch(`${base}/mcp`, { method: "DELETE", headers: { authorization: `Bearer ${TOKEN}` } });
    expect(res.status).toBe(405);
  });

  it("rejects GET (stateless: no standing server-initiated stream) with 405", async () => {
    const res = await fetch(`${base}/mcp`, { method: "GET", headers: { authorization: `Bearer ${TOKEN}` } });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST, OPTIONS");
  });

  it("answers CORS preflight with 204", async () => {
    const res = await fetch(`${base}/mcp`, { method: "OPTIONS" });
    expect(res.status).toBe(204);
  });
});

describe("gateway non-MCP surface", () => {
  it("/healthz is open and reports ok", async () => {
    const res = await fetch(`${base}/healthz`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; service: string };
    expect(body.ok).toBe(true);
    expect(body.service).toBe("flotilla-gateway");
  });

  it("merges the health provider payload", async () => {
    await new Promise<void>((r) => http.close(() => r()));
    await start({ health: () => ({ servers: 4, version: "9.9.9" }) });
    const body = (await (await fetch(`${base}/healthz`)).json()) as { servers: number; version: string };
    expect(body.servers).toBe(4);
    expect(body.version).toBe("9.9.9");
  });

  it("unknown paths are 404", async () => {
    const res = await fetch(`${base}/nope`);
    expect(res.status).toBe(404);
  });
});

describe("gateway with the real Flotilla engine", () => {
  it("serves the fleet tools over HTTP", async () => {
    // Point the engine at a definitely-missing config BEFORE it loads:
    // the dev machine running this test may have a real fleet at the
    // platform default path, and this test asserts the fail-closed path.
    process.env.FLOTILLA_CONFIG = resolve(import.meta.dirname, ".gateway-missing.toml");
    const real = await import("flotilla-mcp");
    await new Promise<void>((r) => http.close(() => r()));
    await start({ mcpServer: real.flotillaMcpServer });

    const init = await mcpPost(initialize, TOKEN);
    expect(init.status).toBe(200);
    const info = (init.payload as { result?: { serverInfo?: { name?: string } } }).result?.serverInfo;
    expect(info?.name).toBe("flotilla-mcp");

    const tools = await mcpPost({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, TOKEN);
    const toolsMsg = tools.payload as { result?: { tools?: Array<{ name: string }> } };
    const names = (toolsMsg.result?.tools ?? []).map((t) => t.name);
    expect(names).toContain("fleet-list");
    expect(names.length).toBeGreaterThanOrEqual(28);

    // No fleet config in the test environment: the tool must fail closed
    // with a helpful message rather than crash the gateway.
    const call = await mcpPost(
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "fleet-list", arguments: {} } },
      TOKEN,
    );
    const msg = call.payload as { result?: { isError?: boolean; content?: Array<{ text?: string }> } };
    expect(msg.result?.isError).toBe(true);
    expect(msg.result?.content?.[0]?.text).toMatch(/not configured|未配置/i);
  }, 30_000);
});

describe("shared engine under concurrent requests", () => {
  const call = (id: number, name: string) =>
    mcpPost({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: {} } }, TOKEN);

  async function startWithSlowTool(opts?: Partial<Parameters<typeof createGateway>[0]>): Promise<void> {
    await new Promise<void>((r) => http.close(() => r()));
    stubServer = makeStubServer();
    stubServer.registerTool("slow", { description: "slow", inputSchema: {} }, async () => {
      await new Promise((r) => setTimeout(r, 900));
      return { content: [{ type: "text" as const, text: "done" }] };
    });
    await start(opts);
  }

  it("queues a quick query behind a long one instead of answering 500", async () => {
    await startWithSlowTool();
    const slow = call(10, "slow");
    await new Promise((r) => setTimeout(r, 50));
    const [s, p] = await Promise.all([slow, call(11, "ping")]);
    expect(s.status).toBe(200);
    expect(p.status).toBe(200);
    expect(JSON.stringify(p.payload)).toContain("pong");
  });

  it("answers 503 with Retry-After when the wait would exceed the busy limit", async () => {
    await startWithSlowTool({ busyWaitMs: 100 });
    const slow = call(20, "slow");
    await new Promise((r) => setTimeout(r, 50));
    const headers = { accept: "application/json, text/event-stream", "content-type": "application/json", authorization: `Bearer ${TOKEN}` };
    const busy = await fetch(`${base}/mcp`, {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 21, method: "tools/call", params: { name: "ping", arguments: {} } }),
    });
    expect(busy.status).toBe(503);
    expect(Number(busy.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(((await busy.json()) as { error: string }).error).toMatch(/busy/);
    expect((await slow).status).toBe(200);
    // The slot is free again afterwards.
    expect((await call(22, "ping")).status).toBe(200);
  });
});

describe("engine slot is only for requests", () => {
  it("answers notifications / client responses at once instead of queueing them behind a long call", async () => {
    await new Promise<void>((r) => http.close(() => r()));
    stubServer = makeStubServer();
    stubServer.registerTool("slow", { description: "slow", inputSchema: {} }, async () => {
      await new Promise((r) => setTimeout(r, 900));
      return { content: [{ type: "text" as const, text: "done" }] };
    });
    await start({ busyWaitMs: 100 });
    const slow = mcpPost({ jsonrpc: "2.0", id: 30, method: "tools/call", params: { name: "slow", arguments: {} } }, TOKEN);
    await new Promise((r) => setTimeout(r, 50));
    const started = Date.now();
    const note = await mcpPost({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } }, TOKEN);
    expect(note.status).toBe(202);
    const reply = await mcpPost({ jsonrpc: "2.0", id: 99, result: {} }, TOKEN);
    expect(reply.status).toBe(202);
    expect(Date.now() - started).toBeLessThan(300);
    // A body that is not JSON-RPC still goes to the transport (which rejects it), not the fast path.
    expect((await mcpPost({ hello: 1 }, TOKEN)).status).not.toBe(202);
    expect((await slow).status).toBe(200);
  });
});

describe("console static files", () => {
  it("serves only regular, non-hidden files that really live inside the console dir", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const root = mkdtempSync(join(tmpdir(), "flotilla-console-"));
    const consoleDir = join(root, "console");
    mkdirSync(consoleDir);
    writeFileSync(join(consoleDir, "index.html"), "<h1>ok</h1>");
    writeFileSync(join(consoleDir, ".env"), "SECRET=1");
    writeFileSync(join(root, "outside.txt"), "private");
    symlinkSync(join(root, "outside.txt"), join(consoleDir, "leak.txt"));
    await new Promise<void>((r) => http.close(() => r()));
    await start({ consoleDir });
    expect((await fetch(`${base}/console/`)).status).toBe(200);
    expect((await fetch(`${base}/console/.env`)).status).toBe(404);
    expect((await fetch(`${base}/console/leak.txt`)).status).toBe(404);
  });
});
