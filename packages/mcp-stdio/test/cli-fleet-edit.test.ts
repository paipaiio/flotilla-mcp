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
});
