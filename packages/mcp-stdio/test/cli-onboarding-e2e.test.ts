import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** Start test/fixtures/fake-sshd.mjs and wait for its {"port":...} line. */
async function fakeSshd(home: string, args: string[]): Promise<{ port: number; proc: ChildProcess }> {
  mkdirSync(home, { recursive: true });
  const proc = spawn(process.execPath, [resolve("test/fixtures/fake-sshd.mjs"), "--home", home, ...args], { stdio: ["ignore", "pipe", "inherit"] });
  const line = await new Promise<string>((ok) => createInterface({ input: proc.stdout! }).once("line", ok));
  return { port: (JSON.parse(line) as { port: number }).port, proc };
}

describe("CLI add against real SSH handshakes", () => {
  let dir: string;
  let both: { port: number; proc: ChildProcess };
  let pwOnly: { port: number; proc: ChildProcess };
  const cfg = () => join(dir, "config.toml");
  const run = (args: string[], env: Record<string, string> = {}) =>
    spawnSync(process.execPath, [resolve("bin/fleet.mjs"), "--config", cfg(), ...args], {
      cwd: resolve("."),
      encoding: "utf8",
      timeout: 30_000,
      env: {
        ...process.env,
        // Hermetic: no real keychain, no ssh config/agent from the developer machine.
        FLOTILLA_KEYCHAIN: "off",
        FLOTILLA_SSH_CONFIG: join(dir, "no-ssh-config"),
        SSH_AUTH_SOCK: "",
        ...env,
      },
    });

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "flotilla-cli-e2e-"));
    both = await fakeSshd(join(dir, "both-home"), ["--password", "s3cret"]);
    pwOnly = await fakeSshd(join(dir, "pw-home"), ["--password", "s3cret", "--no-pubkey"]);
  });

  afterAll(() => {
    both?.proc.kill();
    pwOnly?.proc.kill();
    rmSync(dir, { recursive: true, force: true });
  });

  it("asks for the password once, installs the fleet key and switches to it", () => {
    const r = run(["add", "vps-1", `x@127.0.0.1:${both.port}`], { FLOTILLA_BOOTSTRAP_PASSWORD: "s3cret" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("密码首连 → 已换成舰队专用密钥");
    const saved = readFileSync(cfg(), "utf8");
    expect(saved).toMatch(/name = "vps-1"[\s\S]*auth = "key"/);
    expect(saved).not.toContain("s3cret");
    expect(readFileSync(join(dir, "both-home", ".ssh", "authorized_keys"), "utf8")).toContain("flotilla-fleet");
  });

  it("reuses the fleet key for the next server without asking again", () => {
    const r = run(["add", "vps-2", `x@127.0.0.1:${both.port}`]);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain("的密码");
    expect(r.stdout).toMatch(/登录方式\s+密钥 .*fleet_ed25519/);
  });

  it("keeps password login for password-only servers and says where the password must live", () => {
    const r = run(["add", "router-1", `x@127.0.0.1:${pwOnly.port}`], { FLOTILLA_BOOTSTRAP_PASSWORD: "s3cret" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("服务器不接受密钥登录");
    expect(r.stdout).toContain("FLOTILLA_ROUTER_1_PASSWORD");
    expect(readFileSync(cfg(), "utf8")).toMatch(/name = "router-1"[\s\S]*auth = "password"/);
  });

  it("explains a wrong password", () => {
    const r = run(["add", "bad-1", `x@127.0.0.1:${pwOnly.port}`], { FLOTILLA_BOOTSTRAP_PASSWORD: "nope" });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("拒绝了这个密码");
  });

  it("does not hang without a terminal and tells how to pass the password", () => {
    const r = run(["add", "np-1", `x@127.0.0.1:${pwOnly.port}`]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("FLOTILLA_BOOTSTRAP_PASSWORD");
  });

  it("fails fast with a reason when nothing listens", () => {
    const started = Date.now();
    const r = run(["add", "dead-1", "x@127.0.0.1:1"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("端口拒绝连接");
    expect(Date.now() - started).toBeLessThan(8_000);
  });

  it("finds a key that only another ssh config Host names (like ~/.ssh/muskzhou) and never asks for a password", async () => {
    const home = join(dir, "user-home");
    mkdirSync(join(home, ".ssh"), { recursive: true });
    spawnSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", join(home, ".ssh", "muskzhou")]);
    const keyOnly = await fakeSshd(join(dir, "keyonly-home"), []);
    try {
      mkdirSync(join(dir, "keyonly-home", ".ssh"), { recursive: true });
      writeFileSync(join(dir, "keyonly-home", ".ssh", "authorized_keys"), readFileSync(join(home, ".ssh", "muskzhou.pub"), "utf8"));
      const r = run(["add", "keyonly-1", `root@127.0.0.1:${keyOnly.port}`], { HOME: home });
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toMatch(/登录方式\s+密钥 .*muskzhou/);
      expect(r.stdout).not.toContain("的密码");
    } finally {
      keyOnly.proc.kill();
    }
  });

  it("does not ask for a password a key-only server would refuse, and shows the fleet key to install", async () => {
    const keyOnly = await fakeSshd(join(dir, "keyonly2-home"), []);
    try {
      const r = run(["add", "keyonly-2", `root@127.0.0.1:${keyOnly.port}`], { HOME: join(dir, "empty-home"), FLOTILLA_BOOTSTRAP_PASSWORD: "unused" });
      expect(r.status).toBe(1);
      expect(r.stdout).not.toContain("的密码");
      expect(r.stderr).toContain("只接受密钥登录");
      expect(r.stderr).toMatch(/ssh-ed25519 \S+ flotilla-fleet/);
    } finally {
      keyOnly.proc.kill();
    }
  });

  it("accepts a bare address as the name", () => {
    const r = run(["add", "127.0.0.1", "--port", String(both.port), "--user", "x"]);
    expect(r.status).toBe(0);
    expect(readFileSync(cfg(), "utf8")).toContain('name = "127.0.0.1"');
  });
});
