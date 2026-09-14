import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

describe("setup-repair MCP preview", () => {
  const packageRoot = resolve(import.meta.dirname, "..");
  const entrypoint = resolve(packageRoot, "dist/index.js");
  const client = new Client({ name: "setup-repair-integration", version: "1.0.0" });
  let directory: string;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "flotilla-setup-repair-"));
    const configPath = join(directory, "fleet.toml");
    await writeFile(configPath, `
[[servers]]
name = "password-1"
host = "127.0.0.1"
user = "deploy"
auth = "password"
group = "dev"
role = "operator"

[[servers]]
name = "key-1"
host = "127.0.0.2"
user = "deploy"
auth = "key"
keyRef = "/tmp/existing-key"
group = "dev"
role = "operator"
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

  it("detects password nodes without generating a key or connecting", async () => {
    const response = await client.callTool({
      name: "setup-repair",
      arguments: { target: "all" },
    });
    expect(response.isError).not.toBe(true);
    expect(response.structuredContent).toMatchObject({
      mode: "preview",
      selected: 2,
      passwordServers: ["password-1"],
      skippedAlreadyKeyOrAgent: ["key-1"],
      next: "Re-run with apply=true; one approval covers this batch.",
    });
  });
});
