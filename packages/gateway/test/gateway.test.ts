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
