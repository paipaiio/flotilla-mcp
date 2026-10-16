import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** Quota is one shared budget: every command-bearing tool must respect it, not only exec. */
describe("daily command quota covers workflow / session / logs-tail", () => {
  const packageRoot = resolve(import.meta.dirname, "..");
  const client = new Client({ name: "flotilla-quota-test", version: "1.0.0" });
  let dir: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "flotilla-quota-"));
    const configPath = join(dir, "config.toml");
    writeFileSync(
      configPath,
      `[defaults]\ncommandQuotaPerDay = 1\n\n[audit]\npath = "audit.jsonl"\n\n[[servers]]\nname = "web"\nhost = "127.0.0.1"\nport = 1\nuser = "u"\ntier = "dev"\n`,
      { mode: 0o600 },
    );
    // The single unit for today is already used.
    writeFileSync(join(dir, "quota-state.json"), JSON.stringify({ t: [Date.now()] }));
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
  }, 15_000);

  afterAll(async () => {
    await client.close();
    rmSync(dir, { recursive: true, force: true });
  });

  const cases: Array<[string, Record<string, unknown>]> = [
    ["session-start", { target: "web", name: "q", command: "uptime" }],
    ["session-send", { target: "web", name: "q", text: "typed-s3cret-123" }],
    ["logs-tail", { target: "web", path: "/var/log/syslog", seconds: 1 }],
    ["workflow-run", { yaml: "name: q\nsteps:\n  - {name: s, type: exec, target: web, command: uptime}\n" }],
  ];

  it.each(cases)("%s is refused once the quota is used up, before any SSH", async (name, args) => {
    const result = await client.callTool({ name, arguments: args });
    const text = (result.content as Array<{ text?: string }>).map((c) => c.text ?? "").join("\n");
    expect(result.isError, text).toBe(true);
    expect(text).toMatch(/quota/i);
    expect(text).not.toMatch(/ECONNREFUSED/);
  });

  it("never writes text typed into a session to the audit log, even when refused", () => {
    expect(readFileSync(join(dir, "audit.jsonl"), "utf8")).not.toContain("typed-s3cret-123");
  });
});
