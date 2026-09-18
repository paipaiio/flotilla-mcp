import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import {
  createUpstreamManager,
  loadUpstreamsConfig,
  sanitizePrefix,
  type UpstreamConfig,
} from "../src/upstreams.js";

const FIXTURE = resolve(__dirname, "fixtures/echo-upstream.mjs");

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flotilla-upstreams-test-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function writeConfig(content: unknown): string {
  const path = join(dir, "upstreams.json");
  writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content));
  return path;
}

function makeServer(): McpServer {
  return new McpServer({ name: "fleet-stub", version: "0.0.0" });
}

interface Probe {
  tools: string[];
  call: (name: string, args: unknown) => Promise<{ isError?: boolean; content?: unknown[] }>;
  close: () => Promise<void>;
}

/** Attach one in-memory MCP client to a server (one per server, SDK rule). */
async function connectProbe(server: McpServer): Promise<Probe> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "probe", version: "1.0.0" });
  await client.connect(clientTransport);
  return {
    tools: (await client.listTools()).tools.map((t) => t.name),
    call: (name, args) =>
      client.callTool({ name, arguments: args as Record<string, unknown> }) as Promise<{
        isError?: boolean;
        content?: unknown[];
      }>,
    close: () => client.close(),
  };
}

async function attachAndList(configs: UpstreamConfig[]): Promise<{
  server: McpServer;
  manager: ReturnType<typeof createUpstreamManager>;
  probe: Probe;
}> {
  const server = makeServer();
  const manager = createUpstreamManager(configs);
  await manager.attach(server);
  // The probe stays open for the whole test — an MCP server can only be
  // connected to one transport at a time.
  const probe = await connectProbe(server);
  return { server, manager, probe };
}

/** Minimal stateless Streamable HTTP MCP upstream on an ephemeral port.
 * A fresh McpServer per request: a shared server cannot reconnect its one
 * transport slot within a keep-alive burst. */
async function makeHttpUpstream(
  register: (mcp: McpServer) => void,
): Promise<{ url: string; close: () => Promise<void> }> {
  const http = createServer((req, res) => {
    void (async () => {
      if (req.method !== "POST" || req.url !== "/mcp") {
        res.writeHead(404).end(JSON.stringify({ error: "not found" }));
        return;
      }
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const mcp = new McpServer({ name: "http-upstream", version: "1.0.0" });
      register(mcp);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    })().catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${(http.address() as AddressInfo).port}/mcp`,
    close: () => new Promise<void>((r) => http.close(() => r())),
  };
}

describe("loadUpstreamsConfig", () => {
  it("parses a valid stdio and http entry", () => {
    const path = writeConfig([
      { name: "fs", transport: "stdio", command: "npx", args: ["-y", "some-mcp"], env: { A: "1" } },
      { name: "internal", transport: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: "Bearer x" } },
    ]);
    const configs = loadUpstreamsConfig(path);
    expect(configs).toHaveLength(2);
    expect(configs[0]).toMatchObject({ name: "fs", transport: "stdio", command: "npx", args: ["-y", "some-mcp"] });
    expect(configs[1].headers?.Authorization).toBe("Bearer x");
  });

  it("rejects invalid JSON and non-array top level", () => {
    expect(() => loadUpstreamsConfig(writeConfig("{nope"))).toThrow(/invalid JSON/);
    expect(() => loadUpstreamsConfig(writeConfig({ not: "array" }))).toThrow(/array/);
  });

  it("rejects bad names, transports and colliding sanitized names", () => {
    expect(() => loadUpstreamsConfig(writeConfig([{ name: "", transport: "stdio", command: "x" }]))).toThrow(/name/);
    expect(() => loadUpstreamsConfig(writeConfig([{ name: "a", transport: "sse", command: "x" }]))).toThrow(/transport/);
    expect(() =>
      loadUpstreamsConfig(writeConfig([
        { name: "My Up!", transport: "stdio", command: "x" },
        { name: "my up?", transport: "stdio", command: "y" },
      ])),
    ).toThrow(/collides/);
  });

  it("rejects stdio without command and http without a valid http(s) url", () => {
    expect(() => loadUpstreamsConfig(writeConfig([{ name: "a", transport: "stdio" }]))).toThrow(/command/);
    expect(() => loadUpstreamsConfig(writeConfig([{ name: "a", transport: "http", url: "ftp://x" }]))).toThrow(/http/);
    expect(() => loadUpstreamsConfig(writeConfig([{ name: "a", transport: "http", url: "notaurl" }]))).toThrow(/URL/);
    expect(() =>
      loadUpstreamsConfig(writeConfig([{ name: "a", transport: "stdio", command: "x", args: "nope" }])),
    ).toThrow(/args/);
    expect(() =>
      loadUpstreamsConfig(writeConfig([{ name: "a", transport: "stdio", command: "x", env: { A: 1 } }])),
    ).toThrow(/env/);
  });

  it("rejects too many upstreams", () => {
    const configs = Array.from({ length: 17 }, (_, i) => ({ name: `u${i}`, transport: "stdio", command: "x" }));
    expect(() => loadUpstreamsConfig(writeConfig(configs))).toThrow(/16/);
  });
});

describe("sanitizePrefix", () => {
  it("keeps safe names and sanitizes the rest", () => {
    expect(sanitizePrefix("fs")).toBe("fs");
    expect(sanitizePrefix("My Up!")).toBe("my_up");
    expect(sanitizePrefix("___")).toBe("up");
  });
});

describe("stdio upstream aggregation", () => {
  it("mounts fixture tools under the upstream prefix and proxies calls", async () => {
    const { manager, probe } = await attachAndList([
      { name: "Echo Svc", transport: "stdio", command: process.execPath, args: [FIXTURE] },
    ]);
    expect(probe.tools).toEqual(expect.arrayContaining(["echo_svc__echo", "echo_svc__boom"]));

    const result = await probe.call("echo_svc__echo", { text: "hi" });
    expect(result.isError).toBeUndefined();
    // The fixture's own zod schema strips unknown keys — proxied defined
    // arguments arrive intact, which is what the passthrough must guarantee.
    const echoed = (result.content as Array<{ text?: string }> | undefined)?.[0]?.text;
    expect(echoed).toBe('echo:{"text":"hi"}');
    expect(manager.summary()).toEqual({ total: 1, connected: 1, tools: 2 });
    await probe.close();
    await manager.close();
  });

  it("surfaces upstream isError results", async () => {
    const { manager, probe } = await attachAndList([
      { name: "e", transport: "stdio", command: process.execPath, args: [FIXTURE] },
    ]);
    const result = await probe.call("e__boom", {});
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain("deliberate failure");
    await probe.close();
    await manager.close();
  });
});

describe("http upstream aggregation", () => {
  it("mounts and proxies through the HTTP transport", async () => {
    const upstream = await makeHttpUpstream((mcp) => {
      mcp.registerTool(
        "add",
        { description: "add two numbers", inputSchema: { a: z.number(), b: z.number() } },
        async (args) => ({ content: [{ type: "text", text: String(args.a + args.b) }] }),
      );
    });
    try {
      const { manager, probe } = await attachAndList([{ name: "calc", transport: "http", url: upstream.url }]);
      expect(probe.tools).toContain("calc__add");
      const result = await probe.call("calc__add", { a: 2, b: 40 });
      expect(JSON.stringify(result.content)).toContain("42");
      await probe.close();
      await manager.close();
    } finally {
      await upstream.close();
    }
  });
});

describe("failure and recovery", () => {
  it("marks a dead upstream as error without blocking others", async () => {
    const { manager, probe } = await attachAndList([
      { name: "dead", transport: "stdio", command: process.execPath, args: ["-e", "process.exit(1)"] },
      { name: "Echo Svc", transport: "stdio", command: process.execPath, args: [FIXTURE] },
    ]);
    expect(probe.tools).toContain("echo_svc__echo");
    expect(probe.tools).not.toContain("dead__echo");
    const statuses = manager.statuses();
    expect(statuses.find((s) => s.name === "dead")?.state).toBe("error");
    expect(statuses.find((s) => s.name === "Echo Svc")?.state).toBe("connected");
    expect(manager.summary().connected).toBe(1);
    await probe.close();
    await manager.close();
  });

  it("refresh() mounts an upstream that appears after boot", async () => {
    // Reserve a port, capture it, release it: the config below fails at boot,
    // then we start a real server on that port and refresh().
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    const latePort = (probe.address() as AddressInfo).port;
    await new Promise<void>((r) => probe.close(() => r()));

    const manager = createUpstreamManager([
      { name: "late", transport: "http", url: `http://127.0.0.1:${latePort}/mcp` },
    ]);
    const server = makeServer();
    await manager.attach(server);
    expect(manager.statuses()[0].state).toBe("error");

    const upstream = await makeHttpUpstream((mcp) => {
      mcp.registerTool("ping", { description: "pong", inputSchema: {} }, async () => ({
        content: [{ type: "text", text: "pong" }],
      }));
    });
    // makeHttpUpstream picked an ephemeral port; rebind on latePort instead.
    await upstream.close();
    const late = createServer((req, res) => {
      void (async () => {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        const mcp = new McpServer({ name: "late", version: "1.0.0" });
        mcp.registerTool("ping", { description: "pong", inputSchema: {} }, async () => ({
          content: [{ type: "text", text: "pong" }],
        }));
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        await mcp.connect(transport);
        await transport.handleRequest(req, res, body);
      })().catch(() => {
        if (!res.headersSent) res.writeHead(500).end();
      });
    });
    await new Promise<void>((r) => late.listen(latePort, "127.0.0.1", r));
    try {
      await manager.refresh();
      expect(manager.statuses()[0].state).toBe("connected");
      expect(manager.statuses()[0].tools).toEqual(["late__ping"]);
      const clientProbe = await connectProbe(server);
      const result = await clientProbe.call("late__ping", {});
      expect(JSON.stringify(result.content)).toContain("pong");
      await clientProbe.close();
    } finally {
      await manager.close();
      await new Promise<void>((r) => late.close(() => r()));
    }
  });

  it("returns isError when the upstream call itself throws", async () => {
    const upstream = await makeHttpUpstream((mcp) => {
      mcp.registerTool("hello", { description: "h", inputSchema: {} }, async () => ({
        content: [{ type: "text", text: "hi" }],
      }));
    });
    const manager = createUpstreamManager([{ name: "fragile", transport: "http", url: upstream.url }]);
    const server = makeServer();
    await manager.attach(server);
    await upstream.close(); // kill the upstream: mounted tool must fail soft
    const probe = await connectProbe(server);
    const result = await probe.call("fragile__hello", {});
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toMatch(/failed/);
    await probe.close();
    await manager.close();
  });
});

describe("collision safety", () => {
  it("refuses to mount a tool that collides with a fleet tool", async () => {
    const server = makeServer();
    server.registerTool("fleet__echo", { description: "existing fleet tool", inputSchema: {} }, async () => ({
      content: [{ type: "text", text: "fleet" }],
    }));
    const manager = createUpstreamManager([
      { name: "fleet", transport: "stdio", command: process.execPath, args: [FIXTURE] },
    ]);
    await manager.attach(server);
    const status = manager.statuses()[0];
    expect(status.state).toBe("error");
    expect(status.error).toMatch(/already (registered|in use)/);
    await manager.close();
  });
});
