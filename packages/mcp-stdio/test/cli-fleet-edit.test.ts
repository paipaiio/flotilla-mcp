import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const FLEET = `# fleet
[[servers]]
name = "bastion"
host = "10.0.0.1"
user = "ops"

[[servers]]
name = "web-1"
host = "10.0.0.2"
user = "deploy"
tier = "staging"
`;

const SSH_CONFIG = `Host bastion
  HostName 10.0.0.1
Host lab-pi
  HostName 192.168.1.50
  User pi
  Port 2222
  IdentityFile ~/.ssh/flotilla-test-nonexistent
Host db-1
  HostName 10.0.0.3
  ProxyJump ops@bastion
  IdentityFile ~/.ssh/flotilla-test-nonexistent
`;

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "flotilla-cli-edit-"));
  dirs.push(dir);
  const cfg = join(dir, "config.toml");
  writeFileSync(cfg, FLEET, { mode: 0o600 });
  writeFileSync(join(dir, "ssh_config"), SSH_CONFIG, { mode: 0o600 });
  const run = (args: string[]) =>
    spawnSync(process.execPath, [resolve("bin/fleet.mjs"), "--config", cfg, ...args], {
      cwd: resolve("."),
      encoding: "utf8",
      env: { ...process.env, FLOTILLA_SSH_CONFIG: join(dir, "ssh_config"), SSH_AUTH_SOCK: "/tmp/flotilla-test-agent.sock" },
    });
  return { cfg, run };
}

describe("CLI fleet membership commands", () => {
  it("set edits one server and keeps the file's comments", () => {
    const { cfg, run } = setup();
    const r = run(["set", "web-1", "--role", "viewer", "--tier", "prod", "--tags", "web,edge"]);
    expect(r.status).toBe(0);
    const saved = readFileSync(cfg, "utf8");
    expect(saved).toContain("# fleet");
    expect(saved).toContain('tier = "prod"');
    expect(saved).toContain('tags = ["web", "edge"]');
    expect(saved).toContain('role = "viewer"');
  });

  it("remove needs --confirm and refuses jump hosts in use", () => {
    const { cfg, run } = setup();
    expect(run(["remove", "web-1"]).status).toBe(1);
    expect(readFileSync(cfg, "utf8")).toContain('name = "web-1"');
    writeFileSync(cfg, readFileSync(cfg, "utf8") + '\n[[servers]]\nname = "db-1"\nhost = "10.0.0.3"\nuser = "u"\nvia = "bastion"\n', { mode: 0o600 });
    const blocked = run(["remove", "bastion", "--confirm"]);
    expect(blocked.status).toBe(1);
    expect(blocked.stderr).toMatch(/db-1/);
    expect(run(["remove", "web-1", "--confirm"]).status).toBe(0);
    expect(readFileSync(cfg, "utf8")).not.toContain('name = "web-1"');
  });

  it("discover lists ssh config hosts against the fleet", () => {
    const { run } = setup();
    const r = run(["discover"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("= bastion");
    expect(r.stdout).toContain("+ lab-pi  pi@192.168.1.50:2222");
    expect(r.stdout).toContain("via ops@bastion");
  });

  it("import-ssh --dry-run plans every alias without connecting", () => {
    const { cfg, run } = setup();
    const r = run(["import-ssh", "lab-pi", "db-1", "--dry-run"]);
    expect(r.stdout).toMatch(/\+ lab-pi: pi@192\.168\.1\.50:2222 tier=prod role=operator/);
    expect(r.stdout).toMatch(/\+ db-1: .* via=bastion/);
    expect(readFileSync(cfg, "utf8")).not.toContain("lab-pi");
  });

  it("set --dry-run shows before → after and leaves the file untouched", () => {
    const { cfg, run } = setup();
    const before = readFileSync(cfg, "utf8");
    const r = run(["set", "web-1", "--role", "viewer", "--tier", "prod", "--dry-run"]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain("预演");
    expect(r.stdout).toMatch(/role: operator → viewer/);
    expect(r.stdout).toMatch(/tier: staging → prod/);
    expect(readFileSync(cfg, "utf8")).toBe(before);
  });

  it("set --dry-run still validates (unknown server fails)", () => {
    const { run } = setup();
    const r = run(["set", "nope", "--role", "viewer", "--dry-run"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("舰队里没有");
  });

  it("remove --dry-run previews without --confirm and without writing", () => {
    const { cfg, run } = setup();
    const before = readFileSync(cfg, "utf8");
    const r = run(["remove", "web-1", "--dry-run"]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain("预演");
    expect(r.stdout).toContain("web-1");
    expect(readFileSync(cfg, "utf8")).toBe(before);
    expect(run(["remove", "bastion", "--dry-run"]).status).toBe(0);
    const blocked = run(["remove", "nope", "--dry-run"]);
    expect(blocked.status).toBe(1);
  });
});

describe("CLI per-command flags", () => {
  it("rejects a flag the command does not read instead of silently ignoring it", () => {
    const { run } = setup();
    const r = run(["list", "--confirm"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("list 不支持 --confirm");
    const s = run(["exec-read", "web-1", "uptime", "--sudo"]);
    expect(s.status).toBe(2);
    expect(s.stderr).toContain("exec-read 不支持 --sudo");
    const p = run(["pull", "web-1", "/a", "/b", "--confirm"]);
    expect(p.stderr).toMatch(/pull 不支持 --confirm（可用：--strategy）/);
  });

  it("still accepts the flags a command reads", () => {
    const { run } = setup();
    expect(run(["set", "web-1", "--tags", "a", "--dry-run"]).status).toBe(0);
    // exec-read shares exec's handler and honours --strategy.
    expect(run(["exec-read", "web-1", "rm -rf /tmp/x", "--strategy", "serial"]).stderr).not.toContain("不支持");
  });
});
