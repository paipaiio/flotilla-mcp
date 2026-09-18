import { chmodSync, existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function run(args: string[]) {
  return spawnSync(process.execPath, [resolve("bin/fleet.mjs"), ...args], {
    cwd: resolve("."),
    encoding: "utf8",
    env: { ...process.env, SSH_AUTH_SOCK: "/tmp/flotilla-test-agent.sock" },
  });
}

describe("CLI add auto-initializes the config (foolproof first run)", () => {
  it("creates the config file 600 before probing, even when the probe fails", () => {
    const dir = mkdtempSync(join(tmpdir(), "flotilla-cli-init-"));
    dirs.push(dir);
    const cfg = join(dir, "config.toml");
    expect(existsSync(cfg)).toBe(false);

    // Unreachable target: add must fail at the probe, but only AFTER init.
    const result = run([
      "--config", cfg,
      "add", "ghost-1", "--host", "127.0.0.1", "--port", "1", "--user", "nobody",
    ]);

    expect(existsSync(cfg)).toBe(true);
    if (process.platform !== "win32") {
      expect(statSync(cfg).mode & 0o777).toBe(0o600);
    }
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("已自动初始化配置");
    expect(result.stdout + result.stderr).toMatch(/探测|连接失败/);
    chmodSync(cfg, 0o600);
  });

  it("still requires --host and a server name", () => {
    const dir = mkdtempSync(join(tmpdir(), "flotilla-cli-init-"));
    dirs.push(dir);
    const cfg = join(dir, "config.toml");
    const noHost = run(["--config", cfg, "add", "x-1"]);
    expect(noHost.status).toBe(2);
    // Validation dies before any config initialization.
    expect(existsSync(cfg)).toBe(false);
  });
});
