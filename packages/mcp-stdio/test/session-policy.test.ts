import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const FLEET = `[[servers]]\nname = "web-1"\nhost = "10.255.0.1"\nuser = "deploy"\ntier = "prod"\nrole = "operator"\n`;

describe("typed session input cannot bypass the role x tier policy", () => {
  const packageRoot = resolve(import.meta.dirname, "..");
  const client = new Client({ name: "session-policy", version: "1.0.0" });
  let directory: string;
  let configPath: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "flotilla-session-policy-"));
    configPath = join(directory, "fleet.toml");
    await writeFile(configPath, FLEET, { mode: 0o600 });
    const env = Object.fromEntries(Object.entries(process.env).filter((e): e is [string, string] => e[1] !== undefined));
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [resolve(packageRoot, "dist/index.js"), "--config", configPath],
        cwd: packageRoot,
        env: { ...env, FLOTILLA_KEYCHAIN: "off" },
        stderr: "pipe",
      }),
    );
  }, 10_000);

  afterAll(async () => {
    await client.close();
    await rm(directory, { recursive: true, force: true });
  });

  it("MCP session-send refuses what exec would refuse, before touching the host", async () => {
    const result = await client.callTool({ name: "session-send", arguments: { target: "web-1", name: "s", text: "rm -rf /tmp/x" } });
    expect(result.isError).toBe(true);
    const text = (result.content as Array<{ text: string }>)[0]!.text;
    expect(text).toMatch(/does not permit destructive/);
    expect(text).toMatch(/NEXT:/);
  });

  it("CLI session send refuses it too", () => {
    const r = spawnSync(process.execPath, [resolve(packageRoot, "bin/fleet.mjs"), "--config", configPath, "session", "send", "web-1", "s", "rm -rf /tmp/x", "--confirm"], {
      encoding: "utf8",
      env: { ...process.env, FLOTILLA_KEYCHAIN: "off" },
      timeout: 20_000,
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("策略拒绝");
  });
});
