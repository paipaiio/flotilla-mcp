import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import { Server, utils } from "ssh2";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  checkHostKeyAgainstKnown,
  createChangeSet,
  decideChangeSet,
  parseFleetConfig,
  removeServerFromConfig,
  scanHostKey,
} from "../src/index.js";
import { hostKeyBlobType } from "../src/ssh.js";

describe("type-aware known_hosts verdicts", () => {
  it("only compares keys of the same algorithm", () => {
    const known = [{ type: "ecdsa-sha2-nistp256", fingerprint: "SHA256:ec" }];
    expect(checkHostKeyAgainstKnown({ fingerprint: "SHA256:ed", type: "ssh-ed25519" }, known)).toBe("unknown");
    expect(checkHostKeyAgainstKnown({ fingerprint: "SHA256:ec", type: "ecdsa-sha2-nistp256" }, known)).toBe("verified");
    expect(checkHostKeyAgainstKnown({ fingerprint: "SHA256:evil", type: "ecdsa-sha2-nistp256" }, known)).toBe("mismatch");
    expect(checkHostKeyAgainstKnown({ fingerprint: "SHA256:x" }, [])).toBe("unknown");
    // untyped entries (legacy callers) compare against everything
    expect(checkHostKeyAgainstKnown({ fingerprint: "SHA256:x", type: "ssh-ed25519" }, ["SHA256:y"])).toBe("mismatch");
  });

  it("reads the algorithm name from a key blob", () => {
    const blob = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from("ssh-ed25519"), Buffer.alloc(36)]);
    expect(hostKeyBlobType(blob)).toBe("ssh-ed25519");
    expect(hostKeyBlobType(Buffer.from([0, 0, 1]))).toBeUndefined();
  });
});

describe("scanHostKey", () => {
  const keys = utils.generateKeyPairSync("ed25519");
  const parsed = utils.parseKey(keys.public);
  const expected = `SHA256:${createHash("sha256").update((parsed as { getPublicSSH(): Buffer }).getPublicSSH()).digest("hex")}`;
  const methodsSeen: string[] = [];
  let server: Server;
  let port: number;

  beforeAll(async () => {
    server = new Server({ hostKeys: [keys.private] }, (client) => {
      client.on("authentication", (ctx) => {
        methodsSeen.push(ctx.method);
        ctx.reject(["publickey", "password"]);
      });
      client.on("error", () => {});
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(() => server.close());

  it("reads the host key, type and accepted auth methods without sending a credential", async () => {
    const scanned = await scanHostKey({ host: "127.0.0.1", port, user: "nobody" });
    // Learns which methods the server accepts, having sent no credential at all.
    expect(scanned).toEqual({ fingerprint: expected, type: "ssh-ed25519", authMethods: ["publickey", "password"] });
    expect(methodsSeen).toEqual(["none"]);
  });

  it("refuses to negotiate a host key type other than the pinned one", async () => {
    // The server only has ed25519; restricted to ecdsa the handshake cannot complete.
    await expect(
      scanHostKey({ host: "127.0.0.1", port, user: "nobody", hostKeyAlgorithm: "ecdsa-sha2-nistp256" }, 3_000),
    ).rejects.toMatchObject({ code: "unreachable" });
    await expect(scanHostKey({ host: "127.0.0.1", port, user: "nobody", hostKeyAlgorithm: "ssh-ed25519" })).resolves.toMatchObject({
      fingerprint: expected,
    });
  });

  it("fails cleanly when nothing listens", async () => {
    await expect(scanHostKey({ host: "127.0.0.1", port: 1, user: "x" }, 2_000)).rejects.toThrow(/host key/);
  });
});

describe("change sets honor [policy.matrix]", () => {
  const changeSet = createChangeSet({
    tool: "service-control",
    summary: "restart app",
    targets: ["web-1"],
    paths: [],
    services: ["app.service"],
    operations: ["restart app.service"],
    rollback: "none",
    risk: "destructive",
  });
  const server = { name: "web-1", role: "operator" as const, group: "staging", readOnly: false };

  it("denies a change set whose risk class the override omits", () => {
    expect(decideChangeSet(changeSet, server, "ask-destructive").allowed).toBe(true);
    const narrowed = decideChangeSet(changeSet, server, "ask-destructive", {
      matrix: { operator: { staging: ["read-only", "safe"] } },
    });
    expect(narrowed.allowed).toBe(false);
    expect(narrowed.reason).toMatch(/policy\.matrix/);
  });
});

describe("removeServerFromConfig leaves unrelated bytes alone", () => {
  it("does not touch blank lines inside multi-line strings elsewhere", () => {
    const text = `[defaults]\napprovalMode = "ask-destructive"\n\n[[servers]]\nname = "a"\nhost = "h"\nuser = "u"\nworkdir = """\n/x\n\n\n\n/y"""\n\n\n[[servers]]\nname = "b"\nhost = "h2"\nuser = "u"\n`;
    const next = removeServerFromConfig(text, "b");
    expect(parseFleetConfig(next).servers[0]!.workdir).toBe("/x\n\n\n\n/y");
  });
});
