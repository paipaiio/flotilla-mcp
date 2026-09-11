import { describe, expect, it } from "vitest";
import { effectiveAlgorithms, STRICT_ALGORITHMS } from "../src/ssh.js";
import { parseFleetConfig } from "../src/config.js";

describe("effectiveAlgorithms", () => {
  it("strict mode returns the RFC 9142 allowlist", () => {
    const algs = effectiveAlgorithms(true, false);
    expect(algs).toBeDefined();
    expect(algs!.serverHostKey).toContain("ssh-ed25519");
    expect(algs!.serverHostKey).toContain("rsa-sha2-256");
  });

  it("strict disabled or legacy server means ssh2 defaults (undefined)", () => {
    expect(effectiveAlgorithms(false, false)).toBeUndefined();
    expect(effectiveAlgorithms(true, true)).toBeUndefined();
  });
});

describe("STRICT_ALGORITHMS content (RFC 9142)", () => {
  const flat = Object.values(STRICT_ALGORITHMS).flat() as unknown as string[];

  it("bans SHA-1 constructions and CBC/legacy ciphers", () => {
    for (const banned of [
      "ssh-rsa", "ssh-dss",
      "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
      "hmac-sha1",
      "3des-cbc", "aes128-cbc", "aes256-cbc",
      "arcfour", "arcfour128",
    ]) {
      expect(flat).not.toContain(banned);
    }
  });

  it("excludes algorithms ssh2 cannot negotiate (sk-* hardware keys)", () => {
    // Regression: listing sk-ssh-ed25519@openssh.com makes ssh2 throw
    // "Unsupported algorithm" at connect time (caught by real-fleet testing).
    expect(flat.some((a) => a.startsWith("sk-"))).toBe(false);
  });

  it("keeps the recommended modern set", () => {
    expect(STRICT_ALGORITHMS.kex).toContain("curve25519-sha256");
    expect(STRICT_ALGORITHMS.cipher).toContain("chacha20-poly1305@openssh.com");
    expect(STRICT_ALGORITHMS.hmac).toContain("hmac-sha2-256");
  });
});

describe("config: algorithm knobs", () => {
  it("strictAlgorithms defaults to true, allowLegacyAlgorithms to false", () => {
    const cfg = parseFleetConfig("[[servers]]\nname='a'\nhost='h'\nuser='u'\n");
    expect(cfg.defaults.strictAlgorithms).toBe(true);
    expect(cfg.servers[0]!.allowLegacyAlgorithms).toBe(false);
  });

  it("both knobs parse when set", () => {
    const cfg = parseFleetConfig(
      "[defaults]\nstrictAlgorithms=false\n" +
        "[[servers]]\nname='old-1'\nhost='h'\nuser='u'\nallowLegacyAlgorithms=true\n",
    );
    expect(cfg.defaults.strictAlgorithms).toBe(false);
    expect(cfg.servers[0]!.allowLegacyAlgorithms).toBe(true);
  });
});
