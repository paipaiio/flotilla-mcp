import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdirSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const FLEET = `# my fleet
[[servers]]
name = "bastion"
host = "10.0.0.1"
user = "ops"
group = "prod"

# keep this comment
[[servers]]
name = "web-1"
host = "10.0.0.2"
user = "deploy"
group = "staging"
tags = ["web"]
`;

const SSH_CONFIG = `Host web-1
  HostName 10.0.0.2
Host lab-pi
  HostName 192.168.1.50
  User pi
  Port 2222
Host *
  ServerAliveInterval 30
`;

function text(result: unknown): string {
  const content = (result as { content?: Array<{ text?: string }> }).content ?? [];
  return content.map((c) => c.text ?? "").join("\n");
}

describe("fleet membership tools over MCP", () => {
  const packageRoot = resolve(import.meta.dirname, "..");
  const entrypoint = resolve(packageRoot, "dist/index.js");
  const client = new Client({ name: "onboarding-integration", version: "1.0.0" }, { capabilities: { elicitation: {} } });
  const prompts: string[] = [];
  let directory: string;
  let configPath: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "flotilla-onboarding-"));
    configPath = join(directory, "fleet.toml");
    await writeFile(configPath, FLEET, { mode: 0o600 });
    await writeFile(join(directory, "ssh_config"), SSH_CONFIG, { mode: 0o600 });
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      prompts.push(String(request.params.message));
      return { action: "accept", content: {} };
    });
    const env = Object.fromEntries(
      Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "--config", configPath],
      cwd: packageRoot,
      env: { ...env, FLOTILLA_SSH_CONFIG: join(directory, "ssh_config"), SSH_AUTH_SOCK: "", FLOTILLA_KEYCHAIN: "off" },
      stderr: "pipe",
    });
    await client.connect(transport);
  }, 10_000);

  afterAll(async () => {
    await client.close();
    sshd?.kill();
    await rm(directory, { recursive: true, force: true });
  });

  let sshd: ChildProcess | undefined;
  async function startSshd(args: string[]): Promise<{ port: number; home: string }> {
    const home = join(directory, `sshd-home-${args.join("")}`);
    mkdirSync(home, { recursive: true });
    sshd = spawn(process.execPath, [resolve(packageRoot, "test/fixtures/fake-sshd.mjs"), "--home", home, ...args], { stdio: ["ignore", "pipe", "inherit"] });
    const line = await new Promise<string>((ok) => createInterface({ input: sshd!.stdout! }).once("line", ok));
    return { port: (JSON.parse(line) as { port: number }).port, home };
  }

  it("fleet-discover lists ssh config hosts that are not in the fleet yet", async () => {
    const out = text(await client.callTool({ name: "fleet-discover", arguments: {} }));
    expect(out).toContain("= web-1: already in the fleet");
    expect(out).toContain("+ lab-pi: pi@192.168.1.50:2222");
    expect(out).not.toContain("*");
  });

  it("fleet-set changes fields after approval and keeps comments", async () => {
    const result = await client.callTool({ name: "fleet-set", arguments: { name: "web-1", role: "viewer", tags: ["web", "edge"] } });
    expect(result.isError).not.toBe(true);
    expect(prompts.at(-1)).toContain('role: "operator" → "viewer"');
    expect(prompts.at(-1)).toMatch(/no longer allows: .*destructive/);
    const saved = await readFile(configPath, "utf8");
    expect(saved).toContain("# keep this comment");
    expect(saved).toContain('role = "viewer"');
    const listed = text(await client.callTool({ name: "fleet-list", arguments: {} }));
    expect(listed).toContain('"edge"');
  });

  it("fleet-remove refuses a jump host in use, then removes a leaf", async () => {
    await writeFile(configPath, (await readFile(configPath, "utf8")) + `\n[[servers]]\nname = "db-1"\nhost = "10.0.0.3"\nuser = "deploy"\nvia = "bastion"\n`, { mode: 0o600 });
    await client.callTool({ name: "config-reload", arguments: {} });
    const blocked = await client.callTool({ name: "fleet-remove", arguments: { name: "bastion" } });
    expect(blocked.isError).toBe(true);
    expect(text(blocked)).toMatch(/jump host .* db-1/);
    const removed = await client.callTool({ name: "fleet-remove", arguments: { name: "db-1" } });
    expect(removed.isError).not.toBe(true);
    expect(await readFile(configPath, "utf8")).not.toContain('name = "db-1"');
  });

  it("fleet-add explains why nothing could authenticate instead of asking for a password", async () => {
    const result = await client.callTool({
      name: "fleet-add",
      arguments: { name: "lab-pi", keyRef: join(directory, "missing_key") },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/Server NOT added/);
    expect(await readFile(configPath, "utf8")).not.toContain("lab-pi");
  }, 30_000);

  it("fleet-add logs in with a key and pins the host key", async () => {
    const { port, home } = await startSshd(["--password", "s3cret"]);
    const key = join(directory, "user_key");
    spawnSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key]);
    mkdirSync(join(home, ".ssh"), { recursive: true });
    await writeFile(join(home, ".ssh", "authorized_keys"), await readFile(`${key}.pub`, "utf8"));
    const result = await client.callTool({ name: "fleet-add", arguments: { name: "keyed-1", host: "127.0.0.1", port, user: "x", keyRef: key, tier: "dev" } });
    expect(result.isError).not.toBe(true);
    expect(text(result)).toContain(`login: key ${key}`);
    expect(await readFile(configPath, "utf8")).toMatch(/name = "keyed-1"[\s\S]*trustedHostKey = "SHA256:/);
    sshd?.kill();
  }, 30_000);

  it("fleet-add never asks for a password in chat when the client cannot open the secure page", async () => {
    const { port } = await startSshd(["--password", "s3cret", "--no-pubkey"]);
    const result = await client.callTool({ name: "fleet-add", arguments: { name: "router-1", host: "127.0.0.1", port, user: "x" } });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/needs a password/);
    expect(text(result)).toContain("flotilla add router-1");
    expect(text(result)).toContain("Never ask for the password in chat");
  }, 30_000);
});
