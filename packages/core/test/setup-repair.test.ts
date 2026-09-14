import { describe, expect, it } from "vitest";
import {
  SetupRepairError,
  ensureFleetKeyPair,
  migratePasswordServersInConfig,
  parseFleetConfig,
  type KeyPairIO,
} from "../src/index.js";

const CONFIG = `
[defaults]
approvalMode = "ask-destructive"

[[servers]] # keep this comment
name = "web-1"
host = "10.0.0.1"
user = "deploy"
auth = "password"
group = "prod"
tags = ["web"]
role = "operator"

[[servers]]
name = "web-2"
host = "10.0.0.2"
user = "deploy"
auth = "password"
keyRef = "/old/key"
group = "prod"
role = "operator"
`;

describe("migratePasswordServersInConfig", () => {
  it("updates selected server blocks structurally and preserves unrelated content", () => {
    const next = migratePasswordServersInConfig(CONFIG, [
      { server: "web-1", keyRef: "/keys/fleet_ed25519", trustedHostKey: "SHA256:new-pin" },
    ]);
    const parsed = parseFleetConfig(next);
    expect(parsed.servers[0]).toMatchObject({
      name: "web-1", auth: "key", keyRef: "/keys/fleet_ed25519", trustedHostKey: "SHA256:new-pin",
    });
    expect(parsed.servers[1]).toMatchObject({ name: "web-2", auth: "password", keyRef: "/old/key" });
    expect(next).toContain("[[servers]] # keep this comment");
    expect(next).toContain('tags = ["web"]');
  });

  it("migrates several password blocks in one validated edit", () => {
    const next = migratePasswordServersInConfig(CONFIG, [
      { server: "web-1", keyRef: "/keys/fleet" },
      { server: "web-2", keyRef: "/keys/fleet", trustedHostKey: "SHA256:web-2" },
    ]);
    const parsed = parseFleetConfig(next);
    expect(parsed.servers.every((server) => server.auth === "key")).toBe(true);
    expect(parsed.servers.every((server) => server.keyRef === "/keys/fleet")).toBe(true);
    expect(parsed.servers[1].trustedHostKey).toBe("SHA256:web-2");
  });

  it("inserts key fields before a nested scopes table", () => {
    const scoped = CONFIG.replace(
      'role = "operator"\n\n[[servers]]',
      'role = "operator"\n[servers.scopes]\npaths = ["/srv/app/**"]\n\n[[servers]]',
    );
    const next = migratePasswordServersInConfig(scoped, [
      { server: "web-1", keyRef: "/keys/fleet" },
    ]);
    const parsed = parseFleetConfig(next);
    expect(parsed.servers[0]).toMatchObject({
      auth: "key", keyRef: "/keys/fleet", scopes: { paths: ["/srv/app/**"] },
    });
    expect(next.indexOf('keyRef = "/keys/fleet"')).toBeLessThan(next.indexOf("[servers.scopes]"));
  });

  it("returns the original text for an empty migration", () => {
    expect(migratePasswordServersInConfig(CONFIG, [])).toBe(CONFIG);
  });

  it("rejects unknown and already-key-authenticated targets", () => {
    expect(() => migratePasswordServersInConfig(CONFIG, [
      { server: "missing", keyRef: "/keys/fleet" },
    ])).toThrow(/not found/);
    const keyConfig = CONFIG.replace('auth = "password"', 'auth = "key"\nkeyRef = "/existing/key"');
    expect(() => migratePasswordServersInConfig(keyConfig, [
      { server: "web-1", keyRef: "/keys/fleet" },
    ])).toThrow(/is not configured for password authentication/);
  });
});

describe("ensureFleetKeyPair", () => {
  const publicKey = `ssh-ed25519 ${"A".repeat(64)} flotilla-fleet`;

  it("creates a dedicated Ed25519 key without putting secrets in argv", () => {
    const files = new Set<string>();
    const calls: Array<{ command: string; args: string[] }> = [];
    const io: KeyPairIO = {
      exists: (path) => files.has(path),
      mkdir: () => undefined,
      chmod: () => undefined,
      run(command, args) {
        calls.push({ command, args });
        const output = args.includes("-y") ? publicKey : "";
        const outputIndex = args.indexOf("-f");
        if (args.includes("-t") && outputIndex >= 0) files.add(args[outputIndex + 1]);
        return output;
      },
    };
    const result = ensureFleetKeyPair("/config/fleet_ed25519", io);
    expect(result).toEqual({
      privateKeyPath: "/config/fleet_ed25519", publicKey, created: true,
    });
    expect(calls[0]).toMatchObject({
      command: "ssh-keygen",
      args: ["-t", "ed25519", "-N", "", "-C", "flotilla-fleet", "-f", "/config/fleet_ed25519"],
    });
    expect(calls.flatMap((call) => call.args)).not.toContain(expect.stringContaining("password"));
  });

  it("reuses an existing private key and only derives its public key", () => {
    const calls: string[][] = [];
    const result = ensureFleetKeyPair("/config/existing", {
      exists: () => true,
      mkdir: () => { throw new Error("must not create a directory"); },
      chmod: () => { throw new Error("must not change an existing key"); },
      run(_command, args) { calls.push(args); return publicKey; },
    });
    expect(result.created).toBe(false);
    expect(calls).toEqual([["-y", "-f", "/config/existing"]]);
  });

  it("fails when key generation or public-key derivation produces no usable key", () => {
    const io: KeyPairIO = {
      exists: () => false,
      mkdir: () => undefined,
      chmod: () => undefined,
      run: () => "",
    };
    expect(() => ensureFleetKeyPair("/config/broken", io)).toThrow(SetupRepairError);
  });
});
