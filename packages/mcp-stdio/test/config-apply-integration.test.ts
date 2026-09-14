import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

describe("config-apply MCP preview", () => {
  const packageRoot = resolve(import.meta.dirname, "..");
  const entrypoint = resolve(packageRoot, "dist/index.js");
  const client = new Client({ name: "config-apply-integration", version: "1.0.0" });
  let directory: string;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "flotilla-config-apply-"));
    const configPath = join(directory, "fleet.toml");
    await writeFile(configPath, `
[[servers]]
name = "app-1"
host = "127.0.0.1"
user = "deploy"
auth = "agent"
group = "prod"
role = "operator"
serviceManager = "systemd"
[servers.scopes]
paths = ["/etc/app/**"]
services = ["app.service"]
`, { mode: 0o600 });
    const env = Object.fromEntries(
      Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
    );
    transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "--config", configPath],
      cwd: packageRoot,
      env,
      stderr: "pipe",
    });
    await client.connect(transport);
  }, 10_000);

  afterAll(async () => {
    await client.close();
    await rm(directory, { recursive: true, force: true });
  });

  it("returns a secret-free seven-stage plan without connecting", async () => {
    const response = await client.callTool({
      name: "config-apply",
      arguments: {
        target: "all",
        path: "/etc/app/config.json",
        format: "json",
        unit: "app",
        changes: [
          { op: "set", path: "/server/port", value: 443 },
          { op: "set", path: "/server/token", valueFromEnv: "APP_TOKEN" },
        ],
      },
    });
    expect(response.isError).not.toBe(true);
    expect(response.structuredContent).toMatchObject({
      mode: "preview",
      hosts: ["app-1"],
      path: "/etc/app/config.json",
      service: { unit: "app.service", action: "restart" },
      changeSet: {
        id: expect.stringMatching(/^cs_[a-f0-9]{16}$/),
        risk: "destructive",
        paths: ["/etc/app/config.json"],
        services: ["app.service"],
      },
      changes: [
        { op: "set", path: "/server/port", source: "literal" },
        { op: "set", path: "/server/token", source: "environment" },
      ],
    });
    expect(JSON.stringify(response)).not.toContain("443");
    expect((response.structuredContent as { transaction: string[] }).transaction).toHaveLength(7);
  });

  it("previews one-time local capture using only an unresolved fingerprint", async () => {
    const response = await client.callTool({
      name: "config-apply",
      arguments: {
        target: "all",
        path: "/etc/app/config.json",
        format: "json",
        unit: "app",
        changes: [{ op: "set", path: "/server/token", valueFromLocal: true, label: "API token" }],
      },
    });
    expect(response.isError).not.toBe(true);
    expect(response.structuredContent).toMatchObject({
      mode: "preview",
      changes: [{ op: "set", path: "/server/token", source: "local-page" }],
      changeSet: { payloadFingerprints: ["/server/token=unresolved-local-page"] },
    });
    expect(JSON.stringify(response)).not.toContain("API token value");
  });

  it("asks for a URL-capable local page before any connection", async () => {
    const response = await client.callTool({
      name: "config-apply",
      arguments: {
        target: "all",
        path: "/etc/app/config.json",
        format: "json",
        unit: "app",
        changes: [{ op: "set", path: "/server/token", valueFromLocal: true }],
        apply: true,
      },
    });
    expect(response.isError).toBe(true);
    const text = response.content[0]?.type === "text" ? response.content[0].text : "";
    expect(text).toContain("LOCAL_SECRET_REQUIRED");
    expect(text).not.toContain("Approval required");
    expect(text).not.toContain("ECONNREFUSED");
  });

  it("rejects a literal value for a sensitive path without echoing it", async () => {
    const response = await client.callTool({
      name: "config-apply",
      arguments: {
        target: "all",
        path: "/etc/app/config.json",
        format: "json",
        changes: [{ op: "set", path: "/server/token", value: "never-return-this-token" }],
      },
    });
    expect(response.isError).toBe(true);
    const text = response.content[0]?.type === "text" ? response.content[0].text : "";
    expect(text).toContain("must use valueFromLocal=true or valueFromEnv");
    expect(JSON.stringify(response)).not.toContain("never-return-this-token");
  });

  it("lets an operator submit a scoped production change set to the approval boundary", async () => {
    const response = await client.callTool({
      name: "config-apply",
      arguments: {
        target: "all",
        path: "/etc/app/config.json",
        format: "json",
        unit: "app",
        changes: [{ op: "set", path: "/server/port", value: 443 }],
        apply: true,
      },
    });
    expect(response.isError).toBe(true);
    const text = response.content[0]?.type === "text" ? response.content[0].text : "";
    expect(text).toContain("Approval required");
    expect(text).toMatch(/change-set cs_[a-f0-9]{16}/);
    expect(text).not.toContain('Role "operator" on tier "prod"');
  });

  it("requires an explicit command scope before a production operator adds a custom validator", async () => {
    const response = await client.callTool({
      name: "config-apply",
      arguments: {
        target: "all",
        path: "/etc/app/config.json",
        format: "json",
        unit: "app",
        validateCommand: "appctl validate {file}",
        changes: [{ op: "set", path: "/server/port", value: 443 }],
        apply: true,
      },
    });
    expect(response.isError).toBe(true);
    const text = response.content[0]?.type === "text" ? response.content[0].text : "";
    expect(text).toContain("require explicit scopes.commands");
    expect(text).not.toContain("Approval required");
  });

  it("finishes custom-command preflight before opening a local secret page", async () => {
    const response = await client.callTool({
      name: "config-apply",
      arguments: {
        target: "all",
        path: "/etc/app/config.json",
        format: "json",
        unit: "app",
        validateCommand: "appctl validate {file}",
        changes: [{ op: "set", path: "/server/token", valueFromLocal: true }],
        apply: true,
      },
    });
    expect(response.isError).toBe(true);
    const text = response.content[0]?.type === "text" ? response.content[0].text : "";
    expect(text).toContain("require explicit scopes.commands");
    expect(text).not.toContain("LOCAL_SECRET_REQUIRED");
  });
});
