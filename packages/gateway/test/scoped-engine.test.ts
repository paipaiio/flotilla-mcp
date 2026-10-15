import { mkdtempSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createGateway } from "../src/http-server.js";
import { addToken, createTokenStore } from "../src/tokens.js";

const ADMIN = "admin-gateway-token-0123456789";

describe("scoped tokens against the real Flotilla engine", () => {
  let http: Server;
  let base: string;
  let viewerToken: string;
  let webAdminToken: string;
  let shutdown: () => Promise<void>;

  beforeAll(async () => {
    const dir = mkdtempSync(join(tmpdir(), "flotilla-scoped-engine-"));
    const cfg = join(dir, "fleet.toml");
    writeFileSync(
      cfg,
      `[[servers]]\nname = "web-1"\nhost = "10.255.0.1"\nuser = "deploy"\ntier = "staging"\ntags = ["web"]\nrole = "admin"\n\n` +
        `[[servers]]\nname = "db-1"\nhost = "10.255.0.2"\nuser = "deploy"\ntier = "prod"\n`,
      { mode: 0o600 },
    );
    process.env.FLOTILLA_CONFIG = cfg;
    const engine = await import("flotilla-mcp");
    shutdown = engine.shutdownFleet;
    const tokensFile = join(dir, "gateway-tokens.json");
    viewerToken = addToken(tokensFile, { name: "ci", maxRole: "viewer", targets: ["tag:web"] }).token;
    webAdminToken = addToken(tokensFile, { name: "web-admin", maxRole: "admin", targets: ["tag:web"] }).token;
    http = createGateway({ mcpServer: engine.flotillaMcpServer, token: ADMIN, scopedTokens: createTokenStore(tokensFile), requestLog: () => {} }).server;
    await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    http?.close();
    await shutdown?.();
  });

  async function tool(token: string, name: string, args: Record<string, unknown>) {
    const headers = { accept: "application/json, text/event-stream", "content-type": "application/json", authorization: `Bearer ${token}` };
    const post = (body: unknown) => fetch(`${base}/mcp`, { method: "POST", headers, body: JSON.stringify(body) });
    await post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    const text = await (await post({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: args } })).text();
    const line = text.split(/\r?\n/).find((l) => l.startsWith("data: "));
    const result = JSON.parse(line ? line.slice(6) : text).result as { isError?: boolean; content: { text: string }[] };
    return { isError: result.isError === true, text: result.content.map((c) => c.text).join("\n") };
  }

  it("shows a scoped token only its targets, with roles capped", async () => {
    const scoped = await tool(viewerToken, "fleet-list", {});
    expect(scoped.text).toContain('"web-1"');
    expect(scoped.text).not.toContain('"db-1"');
    expect(scoped.text).toMatch(/"role": "viewer"/);
    const admin = await tool(ADMIN, "fleet-list", {});
    expect(admin.text).toContain('"db-1"');
  });

  it("makes servers outside the token's targets unaddressable and indistinguishable from missing ones", async () => {
    const hidden = await tool(viewerToken, "fleet-resolve", { target: "db-1" });
    const missing = await tool(viewerToken, "fleet-resolve", { target: "db-2" });
    expect(hidden.isError).toBe(true);
    expect(missing.isError).toBe(true);
    // Same wording for both (a "did you mean" hint may follow, drawn from visible servers only).
    expect(hidden.text).toMatch(/^Unknown server "db-1"/);
    expect(missing.text).toMatch(/^Unknown server "db-2"/);
    expect(hidden.text).not.toMatch(/token|access|hidden|10\.255/);
  });

  it("scopes workflow steps too", async () => {
    const yaml = "name: sneak\nsteps:\n  - name: s1\n    type: exec\n    target: db-1\n    command: uptime\n";
    const r = await tool(viewerToken, "workflow-run", { yaml });
    expect(r.isError).toBe(true);
    expect(r.text).not.toContain("10.255.0.2");
    const all = await tool(viewerToken, "workflow-run", { yaml: yaml.replace("target: db-1", "target: all").replace("uptime", "rm -rf /tmp/x") });
    expect(all.isError).toBe(true);
    expect(all.text).toMatch(/web-1: .*viewer/);
    expect(all.text).not.toMatch(/db-1/);
  });

  it("does not treat a target-limited admin as a fleet admin", async () => {
    const r = await tool(webAdminToken, "fleet-set", { name: "db-1", tags: ["web"] });
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/admin token/);
    const grants = await tool(viewerToken, "fleet-grants", { action: "clear" });
    expect(grants.isError).toBe(true);
  });

  it("enforces the capped role in the policy engine before any connection", async () => {
    const r = await tool(viewerToken, "exec", { target: "web-1", command: "rm -rf /tmp/flotilla-x" });
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/viewer/);
  });

  it("keeps fleet membership changes admin-only", async () => {
    const r = await tool(viewerToken, "fleet-remove", { name: "web-1" });
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/admin token/);
  });
});
