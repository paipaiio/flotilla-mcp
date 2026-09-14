import { access } from "node:fs/promises";
import { resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TOOL_CASES: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
  ["fleet-list", {}],
  ["runtime-info", {}],
  ["credential-status", {}],
  ["setup-repair", {}],
  ["config-apply", { target: "all", path: "/tmp/app.json", format: "json", changes: [{ op: "set", path: "/enabled", value: true }] }],
  ["fleet-resolve", { target: "all" }],
  ["fleet-push", { target: "all", localPath: "/tmp/source", remotePath: "/tmp/dest" }],
  ["fleet-pull", { target: "all", remotePath: "/tmp/source", localPath: "/tmp/dest" }],
  ["fleet-copy", { source: "source", sourcePath: "/tmp/source", dest: "dest", destPath: "/tmp/dest" }],
  ["fleet-sync", { source: "source", sourceDir: "/tmp/source", dest: "dest", destDir: "/tmp/dest" }],
  ["fleet-diff-file", { target: "all", path: "/tmp/file" }],
  ["fleet-grants", { action: "list" }],
  ["metrics-snapshot", { target: "all" }],
  ["doctor", { target: "all" }],
  ["service-status", { target: "all", unit: "app.service" }],
  ["service-logs", { target: "all", unit: "app.service" }],
  ["service-control", { target: "all", unit: "app.service", action: "restart" }],
  ["session-start", { target: "all", name: "test" }],
  ["session-list", { target: "all" }],
  ["session-output", { target: "all", name: "test" }],
  ["session-send", { target: "all", name: "test", text: "status" }],
  ["session-kill", { target: "all", name: "test" }],
  ["workflow-run", { yaml: "name: integration\nsteps: []\n" }],
  ["logs-tail", { target: "all", path: "/tmp/app.log", seconds: 1 }],
  ["fleet-add", { name: "test-host", host: "127.0.0.1" }],
  ["config-pull", {}],
  ["config-reload", {}],
  ["exec-read", { target: "all", command: "uptime" }],
  ["fleet-diff", { target: "all", command: "uname -a" }],
  ["exec", { target: "all", command: "echo integration" }],
  ["exec-sudo", { target: "all", command: "id" }],
  ["signal-process", { target: "all", pid: 1234, signal: "TERM" }],
];

describe("MCP stdio tool integration", () => {
  const packageRoot = resolve(import.meta.dirname, "..");
  const entrypoint = resolve(packageRoot, "dist/index.js");
  const missingConfig = resolve(packageRoot, ".integration-missing.toml");
  const client = new Client({ name: "flotilla-integration-test", version: "1.0.0" });
  let transport: StdioClientTransport;

  beforeAll(async () => {
    await access(entrypoint);
    const env = Object.fromEntries(
      Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
    );
    transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "--config", missingConfig],
      cwd: packageRoot,
      env,
      stderr: "pipe",
    });
    await client.connect(transport);
  }, 10_000);

  afterAll(async () => {
    await client.close();
  });

  it("publishes the complete 32-tool contract with descriptions and object schemas", async () => {
    const listed = await client.listTools();
    const actualNames = listed.tools.map((tool) => tool.name).sort();
    const expectedNames = TOOL_CASES.map(([name]) => name).sort();

    expect(actualNames).toEqual(expectedNames);
    expect(new Set(actualNames).size).toBe(32);
    for (const tool of listed.tools) {
      expect(tool.description?.trim().length).toBeGreaterThan(10);
      expect(tool.inputSchema.type).toBe("object");
    }
    const credentialStatus = listed.tools.find((tool) => tool.name === "credential-status");
    expect(credentialStatus?.inputSchema.properties).toHaveProperty("repair");
    const setupRepair = listed.tools.find((tool) => tool.name === "setup-repair");
    expect(setupRepair?.inputSchema.properties).toHaveProperty("apply");
    const configApply = listed.tools.find((tool) => tool.name === "config-apply");
    expect(configApply?.inputSchema.properties).toHaveProperty("changes");
  });

  it.each(TOOL_CASES)("dispatches %s through MCP with schema-valid input", async (name, args) => {
    const result = await client.callTool({ name, arguments: args });
    expect("content" in result).toBe(true);
    if ("content" in result) {
      expect(result.content.length).toBeGreaterThan(0);
      expect(result.content[0]?.type).toBe("text");
    }
  });
});
