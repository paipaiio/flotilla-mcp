import { describe, expect, it } from "vitest";
import {
  OnboardError,
  appendServerToConfig,
  buildKeyInstallCommand,
  buildServerToml,
  parseFleetConfig,
  type ServerConfig,
} from "../src/index.js";

const BASE: ServerConfig = {
  name: "pi-4",
  host: "192.168.100.4",
  port: 22,
  user: "deploy",
  auth: "agent",
  group: "dev",
  tags: [],
  role: "operator",
  readOnly: false,
};

const EXISTING = `
[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
group = "prod"
tags = ["web"]
role = "admin"
`;

describe("buildServerToml", () => {
  it("renders only the fields that are set", () => {
    const toml = buildServerToml(BASE);
    expect(toml).toContain('name = "pi-4"');
    expect(toml).toContain('host = "192.168.100.4"');
    expect(toml).toContain('user = "deploy"');
    expect(toml).toContain('group = "dev"');
    // defaults and unset fields are omitted
    expect(toml).not.toContain("port =");
    expect(toml).not.toContain("keyRef");
    expect(toml).not.toContain("readOnly");
    expect(toml).not.toContain("tags =");
    expect(toml).not.toContain("via");
    expect(toml).not.toContain("trustedHostKey");
  });

  it("renders non-default and optional fields", () => {
    const toml = buildServerToml({
      ...BASE,
      port: 2222,
      keyRef: "~/.ssh/pi",
      auth: "key",
      tags: ["arm", "edge"],
      role: "admin",
      readOnly: true,
      via: "bastion-1",
      trustedHostKey: "SHA256:abc123",
    });
    expect(toml).toContain("port = 2222");
    expect(toml).toContain('auth = "key"');
    expect(toml).toContain('keyRef = "~/.ssh/pi"');
    expect(toml).toContain('tags = ["arm", "edge"]');
    expect(toml).toContain('role = "admin"');
    expect(toml).toContain("readOnly = true");
    expect(toml).toContain('via = "bastion-1"');
    expect(toml).toContain('trustedHostKey = "SHA256:abc123"');
  });

  it("escapes quotes and backslashes in string fields", () => {
    const toml = buildServerToml({ ...BASE, keyRef: 'C:\\keys\\"weird".pem', auth: "key" });
    expect(toml).toContain('keyRef = "C:\\\\keys\\\\\\"weird\\".pem"');
    // and the escaped form still parses back to the original value
    const cfg = parseFleetConfig(toml);
    expect(cfg.servers[0]!.keyRef).toBe('C:\\keys\\"weird".pem');
  });
});

describe("appendServerToConfig", () => {
  it("appends a parseable [[servers]] block", () => {
    const next = appendServerToConfig(EXISTING, BASE);
    const cfg = parseFleetConfig(next);
    expect(cfg.servers.map((s) => s.name)).toEqual(["web-1", "pi-4"]);
    expect(cfg.servers[1]!.host).toBe("192.168.100.4");
  });

  it("works on a file with no trailing newline", () => {
    const next = appendServerToConfig(EXISTING.trimEnd(), BASE);
    const cfg = parseFleetConfig(next);
    expect(cfg.servers).toHaveLength(2);
  });

  it("works on a config with no servers at all", () => {
    const next = appendServerToConfig("[defaults]\napprovalMode = \"ask-all\"\n", BASE);
    const cfg = parseFleetConfig(next);
    expect(cfg.servers.map((s) => s.name)).toEqual(["pi-4"]);
    expect(cfg.defaults.approvalMode).toBe("ask-all");
  });

  it("refuses a duplicate name", () => {
    expect(() => appendServerToConfig(EXISTING, { ...BASE, name: "web-1" })).toThrow(OnboardError);
    expect(() => appendServerToConfig(EXISTING, { ...BASE, name: "web-1" })).toThrow(/already exists/);
  });

  it("refuses a via jump host that does not exist", () => {
    expect(() => appendServerToConfig(EXISTING, { ...BASE, via: "nowhere" })).toThrow(/Jump host/);
  });

  it("accepts a via jump host that exists", () => {
    const next = appendServerToConfig(EXISTING, { ...BASE, via: "web-1" });
    const cfg = parseFleetConfig(next);
    expect(cfg.servers[1]!.via).toBe("web-1");
  });

  it("keeps the pinned host key through the round trip", () => {
    const next = appendServerToConfig(EXISTING, { ...BASE, trustedHostKey: "SHA256:pinned" });
    const cfg = parseFleetConfig(next);
    expect(cfg.servers[1]!.trustedHostKey).toBe("SHA256:pinned");
  });
});

describe("buildKeyInstallCommand", () => {
  const ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKeyMaterialForTestsOnly0123456789abcdef fleet";

  it("builds an idempotent install command for a valid key", () => {
    const cmd = buildKeyInstallCommand(ED25519);
    expect(cmd).toContain("mkdir -p ~/.ssh");
    expect(cmd).toContain("chmod 700 ~/.ssh");
    expect(cmd).toContain("chmod 600 ~/.ssh/authorized_keys");
    expect(cmd).toContain("grep -qxF");
    expect(cmd).toContain("INSTALLED");
    // key is single-quoted
    expect(cmd).toContain(`'${ED25519}'`);
  });

  it("accepts a key with surrounding whitespace", () => {
    expect(() => buildKeyInstallCommand(`  ${ED25519}\n`)).not.toThrow();
  });

  it("accepts all supported key types", () => {
    const body = "A".repeat(64);
    for (const t of ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]) {
      expect(() => buildKeyInstallCommand(`${t} ${body}`)).not.toThrow();
    }
  });

  it("rejects a key with an embedded newline (command injection)", () => {
    expect(() =>
      buildKeyInstallCommand(`ssh-ed25519 ${"A".repeat(64)}\nrm -rf /`),
    ).toThrow(OnboardError);
  });

  it("rejects a key with shell metacharacters in the body", () => {
    expect(() =>
      buildKeyInstallCommand(`ssh-ed25519 ${"A".repeat(40)}; rm -rf /`),
    ).toThrow(OnboardError);
    expect(() =>
      buildKeyInstallCommand(`ssh-ed25519 ${"A".repeat(40)}$(whoami)`),
    ).toThrow(OnboardError);
    expect(() =>
      buildKeyInstallCommand(`ssh-ed25519 ${"A".repeat(40)}\`id\``),
    ).toThrow(OnboardError);
  });

  it("rejects a single quote that would break out of quoting", () => {
    expect(() =>
      buildKeyInstallCommand(`ssh-ed25519 ${"A".repeat(40)}'$(id)'`),
    ).toThrow(OnboardError);
  });

  it("rejects unknown key types and garbage", () => {
    expect(() => buildKeyInstallCommand("sk-ssh-ed25519@openssh.com AAAA")).toThrow(OnboardError);
    expect(() => buildKeyInstallCommand("not-a-key")).toThrow(OnboardError);
    expect(() => buildKeyInstallCommand("")).toThrow(OnboardError);
  });
});

describe("installPublicKeyLocally", () => {
  it("creates ~/.ssh 700 + authorized_keys 600 and is idempotent", async () => {
    const { mkdtempSync, statSync, readFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { installPublicKeyLocally } = await import("../src/index.js");
    const home = mkdtempSync(join(tmpdir(), "flotilla-ak-"));
    const pub = `ssh-ed25519 ${"A".repeat(56)} flotilla-fleet`;

    const first = installPublicKeyLocally(pub, home);
    expect(first.appended).toBe(true);
    expect(statSync(join(home, ".ssh")).mode & 0o777).toBe(0o700);
    expect(statSync(first.authorizedKeysPath).mode & 0o777).toBe(0o600);
    expect(readFileSync(first.authorizedKeysPath, "utf8").trim()).toBe(pub);

    // Idempotent: second install does not duplicate the line.
    const second = installPublicKeyLocally(pub, home);
    expect(second.appended).toBe(false);
    expect(readFileSync(first.authorizedKeysPath, "utf8").trim().split("\n")).toHaveLength(1);

    // Appends alongside an existing key without clobbering.
    const other = `ssh-ed25519 ${"B".repeat(56)} other`;
    installPublicKeyLocally(other, home);
    const lines = readFileSync(first.authorizedKeysPath, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe(pub);
    rmSync(home, { recursive: true, force: true });
  });

  it("preserves existing content that lacks a trailing newline", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { installPublicKeyLocally } = await import("../src/index.js");
    const home = mkdtempSync(join(tmpdir(), "flotilla-ak-"));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "authorized_keys"), `ssh-ed25519 ${"C".repeat(56)} old`);
    const pub = `ssh-ed25519 ${"D".repeat(56)} flotilla-fleet`;
    installPublicKeyLocally(pub, home);
    const text = readFileSync(join(home, ".ssh", "authorized_keys"), "utf8");
    expect(text).toBe(`ssh-ed25519 ${"C".repeat(56)} old\n${pub}\n`);
    rmSync(home, { recursive: true, force: true });
  });

  it("rejects malformed public keys", async () => {
    const { mkdtempSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { installPublicKeyLocally } = await import("../src/index.js");
    const home = mkdtempSync(join(tmpdir(), "flotilla-ak-"));
    expect(() => installPublicKeyLocally("ssh-ed25519 not-base64!!", home)).toThrow();
    rmSync(home, { recursive: true, force: true });
  });
});

describe("installPublicKeyLocally localhostOnly", () => {
  it("writes a from= restriction and still detects the key as present", async () => {
    const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { installPublicKeyLocally } = await import("../src/index.js");
    const home = mkdtempSync(join(tmpdir(), "flotilla-ak-"));
    const pub = `ssh-ed25519 ${"E".repeat(56)} flotilla-fleet`;

    const first = installPublicKeyLocally(pub, home, { localhostOnly: true });
    expect(first.appended).toBe(true);
    const text = readFileSync(first.authorizedKeysPath, "utf8");
    expect(text).toContain(`from="127.0.0.1,::1" ${pub}`);

    // Same key without the flag (or with) must be detected as already present.
    expect(installPublicKeyLocally(pub, home).appended).toBe(false);
    expect(installPublicKeyLocally(pub, home, { localhostOnly: true }).appended).toBe(false);
    expect(readFileSync(first.authorizedKeysPath, "utf8").trim().split("\n")).toHaveLength(1);
    rmSync(home, { recursive: true, force: true });
  });
});
