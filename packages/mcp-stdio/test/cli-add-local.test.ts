import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function run(args: string[], env: Record<string, string> = {}) {
  return spawnSync(process.execPath, [resolve("bin/fleet.mjs"), ...args], {
    cwd: resolve("."),
    encoding: "utf8",
    env: { ...process.env, SSH_AUTH_SOCK: "/tmp/flotilla-test-agent.sock", ...env },
  });
}

describe("CLI add --local (self-onboarding, passwordless)", () => {
  it("installs the fleet pubkey into the (fake) HOME authorized_keys before probing", () => {
    const dir = mkdtempSync(join(tmpdir(), "flotilla-cli-local-"));
    dirs.push(dir);
    const home = join(dir, "home");
    const cfg = join(dir, "config.toml");

    // No local sshd usable for this fake user → probe fails, but ALL local
    // side effects must already be in place.
    const result = run(["--config", cfg, "add", "--local"], { HOME: home });

    // Fleet key generated next to the config.
    const fleetKey = join(dir, "fleet_ed25519");
    expect(existsSync(fleetKey)).toBe(true);

    // authorized_keys created in the fake HOME with the fleet public key.
    const ak = join(home, ".ssh", "authorized_keys");
    expect(existsSync(ak)).toBe(true);
    if (process.platform !== "win32") {
      expect(statSync(ak).mode & 0o777).toBe(0o600);
    }
    const pub = spawnSync("ssh-keygen", ["-y", "-f", fleetKey], { encoding: "utf8" }).stdout.trim();
    expect(readFileSync(ak, "utf8")).toContain(pub);

    // Probe fails (no sshd for the fake user) with the actionable sshd hint.
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("自管本机");
    expect(result.stdout + result.stderr).toMatch(/sshd/);
    // The server must NOT have been added to the config.
    expect(readFileSync(cfg, "utf8")).not.toContain("[[servers]]");
  });

  it("is idempotent: second run reports the key already present", () => {
    const dir = mkdtempSync(join(tmpdir(), "flotilla-cli-local-"));
    dirs.push(dir);
    const home = join(dir, "home");
    const cfg = join(dir, "config.toml");
    run(["--config", cfg, "add", "--local"], { HOME: home });
    const second = run(["--config", cfg, "add", "--local"], { HOME: home });
    expect(second.stdout).toContain("公钥已存在");
    const ak = join(home, ".ssh", "authorized_keys");
    const lines = readFileSync(ak, "utf8").trim().split("\n").filter(Boolean);
    expect(lines).toHaveLength(1);
  });
});
