import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function config(scopes = ""): string {
  const dir = mkdtempSync(join(tmpdir(), "flotilla-cli-diagnostics-"));
  dirs.push(dir);
  const path = join(dir, "config.toml");
  writeFileSync(
    path,
    `[[servers]]\nname = "diag-agent"\nhost = "127.0.0.1"\nuser = "test"\nauth = "agent"\ngroup = "dev"\n${scopes}`,
  );
  chmodSync(path, 0o600);
  return path;
}

function run(args: string[]) {
  return spawnSync(
    process.execPath,
    [resolve("bin/fleet.mjs"), ...args],
    {
      cwd: resolve("."),
      encoding: "utf8",
      env: { ...process.env, SSH_AUTH_SOCK: "/tmp/flotilla-test-agent.sock" },
    },
  );
}

describe("diagnostic CLI journeys", () => {
  it("shows the exact running module and effective config", () => {
    const path = config();
    const result = run(["--config", path, "info"]);
    expect(result.status).toBe(0);
    const output = JSON.parse(result.stdout);
    expect(output).toMatchObject({
      name: "flotilla-mcp",
      configPath: path,
      configSource: "argument",
      configuredServers: 1,
    });
    expect(output.modulePath).toMatch(/bin\/fleet\.mjs$/);
  });

  it("reports credential readiness without opening an SSH connection", () => {
    const path = config();
    const result = run(["--config", path, "credentials", "all"]);
    expect(result.status).toBe(0);
    const output = JSON.parse(result.stdout);
    expect(output.summary).toEqual({ total: 1, ready: 1, missing: 0 });
    expect(output.credentials[0]).toMatchObject({
      server: "diag-agent",
      source: "ssh-agent",
      ready: true,
    });
  });

  it("classifies unknown commands and requires approval before connecting", () => {
    const path = config();
    expect(run(["--config", path, "classify", "custom-deploy --region west"]).stdout).toContain("unknown");
    const result = run(["--config", path, "exec", "all", "custom-deploy --region west"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("需要审批");
  });

  it("enforces command and path scopes at the executor boundary", () => {
    const path = config('[servers.scopes]\ncommands = ["^uptime$"]\npaths = ["/opt/myapp/**"]\n');
    const command = run(["--config", path, "exec-read", "all", "cat /etc/hosts"]);
    expect(command.status).toBe(1);
    expect(command.stderr).toContain("scopes.commands");
    const pathOnly = config('[servers.scopes]\ncommands = ["^cat "]\npaths = ["/opt/myapp/**"]\n');
    const escaped = run(["--config", pathOnly, "exec-read", "all", "cat ../../etc/hosts"]);
    expect(escaped.status).toBe(1);
    expect(escaped.stderr).toContain("must be absolute");
  });
});
