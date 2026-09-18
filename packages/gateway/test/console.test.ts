import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createGateway } from "../src/http-server.js";

const TOKEN = "test-console-token-0123456789abcdef";

let http: Server;
let base: string;
let consoleDir: string;

function makeStubServer(): McpServer {
  const server = new McpServer({ name: "console-stub", version: "0.0.0" });
  server.registerTool("ping", { description: "reply pong", inputSchema: {} }, async () => ({
    content: [{ type: "text" as const, text: "pong" }],
  }));
  return server;
}

async function start(gatewayOpts?: Partial<Parameters<typeof createGateway>[0]>): Promise<void> {
  const gateway = createGateway({ mcpServer: makeStubServer(), token: TOKEN, ...gatewayOpts });
  http = gateway.server;
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  const port = (http.address() as AddressInfo).port;
  base = `http://127.0.0.1:${port}`;
}

beforeEach(() => {
  // Isolated console dir: one file per known MIME type plus an unknown one,
  // so every branch of the content-type map is exercised.
  consoleDir = mkdtempSync(join(tmpdir(), "flotilla-console-test-"));
  writeFileSync(join(consoleDir, "index.html"), "<!DOCTYPE html><title>console</title>");
  writeFileSync(join(consoleDir, "app.js"), "console.log(1);");
  writeFileSync(join(consoleDir, "style.css"), "body{}");
  writeFileSync(join(consoleDir, "data.bin"), "\x00\x01");
  mkdirSync(join(consoleDir, "sub"));
});

afterEach(async () => {
  await new Promise<void>((r) => http.close(() => r()));
  rmSync(consoleDir, { recursive: true, force: true });
});

describe("web console static serving", () => {
  it("redirects / to /console/", async () => {
    await start({ consoleDir });
    const res = await fetch(`${base}/`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/console/");
  });

  it("serves /console/ (and bare /console) as index.html without auth", async () => {
    await start({ consoleDir });
    for (const path of ["/console/", "/console"]) {
      const res = await fetch(`${base}${path}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(res.headers.get("cache-control")).toBe("no-cache");
      expect(await res.text()).toContain("<!DOCTYPE html>");
    }
  });

  it("serves console assets with the right MIME types and caching", async () => {
    await start({ consoleDir });
    const cases: Array<[string, string]> = [
      ["/console/app.js", "text/javascript; charset=utf-8"],
      ["/console/style.css", "text/css; charset=utf-8"],
      ["/console/data.bin", "application/octet-stream"],
    ];
    for (const [path, type] of cases) {
      const res = await fetch(`${base}${path}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toBe(type);
      expect(res.headers.get("cache-control")).toBe("max-age=300");
    }
  });

  it("serves the real shipped console directory", async () => {
    await start({ consoleDir: resolve(__dirname, "../console") });
    const res = await fetch(`${base}/console/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Flotilla");
    const js = await fetch(`${base}/console/app.js`);
    expect(js.status).toBe(200);
  });

  it("404s on missing console files", async () => {
    await start({ consoleDir });
    const res = await fetch(`${base}/console/nope.js`);
    expect(res.status).toBe(404);
  });

  it("404s on directory paths that are not files", async () => {
    await start({ consoleDir });
    const res = await fetch(`${base}/console/sub/`);
    expect(res.status).toBe(404);
  });

  it("refuses path traversal out of consoleDir", async () => {
    await start({ consoleDir });
    // Encoded dot segments never reach the filesystem (file does not exist
    // under the encoded name), raw ones are normalized away by URL parsing.
    const encoded = await fetch(`${base}/console/%2e%2e/src/enroll.ts`);
    expect(encoded.status).toBe(404);
    const raw = await fetch(`${base}/console/../src/enroll.ts`);
    expect(raw.status).toBe(404);
  });

  it("refuses dot-dot inside a filename component", async () => {
    await start({ consoleDir });
    const res = await fetch(`${base}/console/..a/x.js`);
    expect(res.status).toBe(404);
  });

  it("does not serve the console for non-GET methods", async () => {
    await start({ consoleDir });
    const res = await fetch(`${base}/console/app.js`, { method: "POST" });
    expect(res.status).toBe(404);
  });

  it("keeps /console/ disabled when no consoleDir is configured", async () => {
    await start();
    const res = await fetch(`${base}/console/`);
    expect(res.status).toBe(404);
    const root = await fetch(`${base}/`, { redirect: "manual" });
    expect(root.status).toBe(404);
  });
});
