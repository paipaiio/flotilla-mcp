import { execFileSync } from "node:child_process";
import { createPublicKey, randomInt, verify as cryptoVerify } from "node:crypto";
import { connect, type Socket } from "node:net";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { utils } from "ssh2";
import {
  buildTrustedCAInstallCommand,
  createCertAgentManager,
  ensureFleetCA,
  parseFleetConfig,
  signUserCertificate,
  type ServerConfig,
} from "../src/index.js";

let workDir: string | undefined;
afterEach(() => {
  vi.restoreAllMocks();
  if (workDir) {
    rmSync(workDir, { recursive: true, force: true });
    workDir = undefined;
  }
});

function freshDir(): string {
  workDir = mkdtempSync(join(tmpdir(), "flotilla-cert-test-"));
  return workDir;
}

function sshKeygen(args: string[]): string {
  return execFileSync("ssh-keygen", args, { encoding: "utf8" });
}

function makeUserKey(dir: string): string {
  const keyPath = join(dir, "user_ed25519");
  sshKeygen(["-t", "ed25519", "-N", "", "-C", "test-user", "-f", keyPath]);
  return keyPath;
}

function certServer(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    name: "web-1",
    host: "10.0.0.1",
    port: 22,
    user: "deploy",
    auth: "certificate",
    tags: [],
    role: "operator",
    readOnly: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Raw agent-protocol client (PROTOCOL.agent framing)
// ---------------------------------------------------------------------------

function sendFrame(socket: Socket, type: number, payload: Buffer = Buffer.alloc(0)): void {
  const body = Buffer.concat([Buffer.from([type]), payload]);
  const head = Buffer.allocUnsafe(4);
  head.writeUInt32BE(body.length, 0);
  socket.write(Buffer.concat([head, body]));
}

function readFrame(socket: Socket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
      if (buf.length < 5) return;
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) return;
      socket.off("data", onData);
      resolve(buf.subarray(4, 4 + len));
    };
    socket.on("data", onData);
    socket.once("error", reject);
  });
}

function str(b: Buffer): Buffer {
  const head = Buffer.allocUnsafe(4);
  head.writeUInt32BE(b.length, 0);
  return Buffer.concat([head, b]);
}

function readStr(msg: Buffer, offset: number): { value: Buffer; next: number } {
  const len = msg.readUInt32BE(offset);
  return { value: msg.subarray(offset + 4, offset + 4 + len), next: offset + 4 + len };
}

async function withAgentSocket(
  socketPath: string,
  fn: (socket: Socket) => Promise<void>,
): Promise<void> {
  const socket = connect(socketPath);
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", () => resolve());
    socket.once("error", reject);
  });
  try {
    await fn(socket);
  } finally {
    socket.destroy();
  }
}

/** Extract the raw 32-byte ed25519 public key from an OpenSSH public key line. */
function rawEd25519Pub(publicKeyLine: string): Buffer {
  const blob = Buffer.from(publicKeyLine.trim().split(/\s+/)[1], "base64");
  return blob.subarray(blob.length - 32);
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// ---------------------------------------------------------------------------
// ensureFleetCA
// ---------------------------------------------------------------------------

describe("ensureFleetCA", () => {
  it("creates a CA keypair once and is idempotent", () => {
    const dir = freshDir();
    const first = ensureFleetCA(dir);
    expect(first.created).toBe(true);
    expect(existsSync(first.caPrivateKeyPath)).toBe(true);
    expect(first.publicKey).toMatch(/^ssh-ed25519 AAAA/);
    const stat = readFileSync(first.caPrivateKeyPath, { encoding: undefined });
    expect(stat).toBeDefined();
    // Second call reuses the same key.
    const second = ensureFleetCA(dir);
    expect(second.created).toBe(false);
    expect(second.publicKey).toBe(first.publicKey);
  });

  it("wraps failures in SetupRepairError", () => {
    const dir = freshDir();
    expect(() => ensureFleetCA(dir, () => {
      throw new Error("ssh-keygen exploded");
    })).toThrow(/fleet CA setup failed.*ssh-keygen exploded/);
  });
});

// ---------------------------------------------------------------------------
// signUserCertificate
// ---------------------------------------------------------------------------

describe("signUserCertificate", () => {
  it("signs a certificate that ssh-keygen -L validates end to end", () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const signed = signUserCertificate({
      caPath: ca.caPrivateKeyPath,
      userKeyPath: userKey,
      keyId: "flotilla-web-1",
      principals: ["deploy"],
      validSeconds: 3600,
      serial: 42,
    });
    expect(signed.certificate).toContain("-cert-v01@openssh.com");
    expect(signed.validUntil).toBeGreaterThan(Date.now() + 3500_000);

    // Inspect the certificate with OpenSSH itself.
    const certPath = join(dir, "inspect-cert.pub");
    writeFileSync(certPath, `${signed.certificate}\n`);
    const info = sshKeygen(["-L", "-f", certPath]);
    expect(info).toContain("Type: ssh-ed25519-cert-v01@openssh.com");
    expect(info).toContain('Key ID: "flotilla-web-1"');
    expect(info).toContain("Serial: 42");
    expect(info).toContain("Principals:");
    expect(info).toContain("deploy");
    const caBlob = ca.publicKey.split(/\s+/)[1];
    const caFp = execFileSync("ssh-keygen", ["-l", "-f", ca.caPublicKeyPath], { encoding: "utf8" });
    const sha = caFp.split(/\s+/)[1]; // SHA256:<base64> fingerprint of the CA
    expect(info).toContain("Signing CA:");
    expect(info).toContain(sha);
  });

  it("cleans up its temporary files", () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    signUserCertificate({
      caPath: ca.caPrivateKeyPath,
      userKeyPath: userKey,
      keyId: "k",
      principals: ["deploy"],
      validSeconds: 3600,
    });
    const leftovers = readdirSync(dir).filter((f) => f.startsWith(".flotilla-sign-"));
    expect(leftovers).toEqual([]);
  });

  it("rejects bad principals and TTLs", () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const base = {
      caPath: ca.caPrivateKeyPath,
      userKeyPath: userKey,
      keyId: "k",
      principals: ["deploy"],
      validSeconds: 3600,
    };
    expect(() => signUserCertificate({ ...base, principals: [] })).toThrow(/at least one principal/);
    expect(() => signUserCertificate({ ...base, principals: ["bad principal!"] })).toThrow(/invalid certificate principal/);
    expect(() => signUserCertificate({ ...base, validSeconds: 59 })).toThrow(/validSeconds/);
    expect(() => signUserCertificate({ ...base, validSeconds: 604801 })).toThrow(/validSeconds/);
    expect(() => signUserCertificate({ ...base, validSeconds: 1.5 })).toThrow(/validSeconds/);
  });

  it("produces certificates ssh2 can parse as certificate types", () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const signed = signUserCertificate({
      caPath: ca.caPrivateKeyPath,
      userKeyPath: userKey,
      keyId: "k",
      principals: ["deploy"],
      validSeconds: 3600,
    });
    const parsed = utils.parseKey(signed.certificate);
    expect(parsed instanceof Error || Array.isArray(parsed)).toBe(false);
    if (!(parsed instanceof Error) && !Array.isArray(parsed)) {
      expect(parsed.type).toContain("-cert-v01@openssh.com");
    }
  });
});

// ---------------------------------------------------------------------------
// Certificate agent (OpenSSH agent protocol over a UNIX socket)
// ---------------------------------------------------------------------------

describe("certificate agent protocol", () => {
  it("answers REQUEST_IDENTITIES with the served certificate", async () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const server = certServer({ keyRef: userKey });
    const manager = createCertAgentManager({ socketDir: join(dir, "agent") });
    try {
      const socketPath = await manager.socketFor(server, ca.caPrivateKeyPath);
      await withAgentSocket(socketPath, async (socket) => {
        const replyPromise = readFrame(socket);
        sendFrame(socket, 11);
        const reply = await replyPromise;
        expect(reply[0]).toBe(12); // SSH_AGENT_IDENTITIES_ANSWER
        expect(reply.readUInt32BE(1)).toBe(1); // one identity
        const blob = readStr(reply, 5);
        const comment = readStr(reply, blob.next);
        expect(blob.value.toString("base64")).toContain("AAAA"); // non-trivial blob
        // Wire blob = string certType + string key material (skip length header).
        const certHead = Buffer.from("ssh-ed25519-cert-v01@openssh.com");
        expect(blob.value.readUInt32BE(0)).toBe(certHead.length);
        expect(blob.value.subarray(4, 4 + certHead.length).equals(certHead)).toBe(true);
        expect(comment.value.toString("utf8")).toBe("flotilla-web-1");
      });
    } finally {
      await manager.close();
    }
  });

  it("answers SIGN_REQUEST with a verifiable ed25519 signature", async () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const server = certServer({ keyRef: userKey });
    const manager = createCertAgentManager({ socketDir: join(dir, "agent") });
    try {
      const socketPath = await manager.socketFor(server, ca.caPrivateKeyPath);
      // Learn the served blob via REQUEST_IDENTITIES.
      let servedBlob = Buffer.alloc(0);
      await withAgentSocket(socketPath, async (socket) => {
        const p = readFrame(socket);
        sendFrame(socket, 11);
        const answer = await p;
        servedBlob = readStr(answer, 5).value;
      });
      const data = Buffer.from(`sign-me-${randomInt(1_000_000)}`, "utf8");
      await withAgentSocket(socketPath, async (socket) => {
        const replyPromise = readFrame(socket);
        sendFrame(socket, 13, Buffer.concat([str(servedBlob), str(data), (() => {
          const f = Buffer.allocUnsafe(4);
          f.writeUInt32BE(0, 0);
          return f;
        })()]));
        const reply = await replyPromise;
        expect(reply[0]).toBe(14); // SSH_AGENT_SIGN_RESPONSE
        const inner = readStr(reply, 1).value;
        const sigFormat = readStr(inner, 0);
        const rawSig = readStr(inner, sigFormat.next);
        expect(sigFormat.value.toString("utf8")).toBe("ssh-ed25519-cert-v01@openssh.com");
        // Verify against the user's real public key: agent signs with keyRef's key.
        const pubLine = sshKeygen(["-y", "-f", userKey]).trim();
        const keyObj = createPublicKey({
          key: Buffer.concat([ED25519_SPKI_PREFIX, rawEd25519Pub(pubLine)]),
          format: "der",
          type: "spki",
        });
        expect(cryptoVerify(null, data, keyObj, rawSig.value)).toBe(true);
      });
    } finally {
      await manager.close();
    }
  });

  it("returns FAILURE for unknown message types and wrong key blobs", async () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const server = certServer({ keyRef: userKey });
    const manager = createCertAgentManager({ socketDir: join(dir, "agent") });
    try {
      const socketPath = await manager.socketFor(server, ca.caPrivateKeyPath);
      await withAgentSocket(socketPath, async (socket) => {
        // Unknown type.
        let p = readFrame(socket);
        sendFrame(socket, 99, str(Buffer.from("junk")));
        expect((await p)[0]).toBe(5); // SSH_AGENT_FAILURE
        // Sign request for a blob the agent does not serve.
        p = readFrame(socket);
        const foreign = Buffer.from("not-the-served-blob");
        sendFrame(socket, 13, Buffer.concat([str(foreign), str(Buffer.from("data")), Buffer.alloc(4)]));
        expect((await p)[0]).toBe(5);
        // Partial frame followed by the rest must still parse (buffering).
        p = readFrame(socket);
        const full = Buffer.concat([Buffer.from([11])]);
        const head = Buffer.allocUnsafe(4);
        head.writeUInt32BE(full.length, 0);
        socket.write(head.subarray(0, 2));
        socket.write(Buffer.concat([head.subarray(2), full]));
        expect((await p)[0]).toBe(12);
      });
    } finally {
      await manager.close();
    }
  });
});

// ---------------------------------------------------------------------------
// CertAgentManager lifecycle
// ---------------------------------------------------------------------------

describe("createCertAgentManager", () => {
  it("returns the same socket while the certificate is fresh", async () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const server = certServer({ keyRef: userKey, certValiditySeconds: 3600 });
    const manager = createCertAgentManager({ socketDir: join(dir, "agent") });
    try {
      const first = await manager.socketFor(server, ca.caPrivateKeyPath);
      const second = await manager.socketFor(server, ca.caPrivateKeyPath);
      expect(second).toBe(first);
      expect(existsSync(first)).toBe(true);
    } finally {
      await manager.close();
    }
  });

  it("re-signs in place once less than a quarter of the TTL remains", async () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const server = certServer({ keyRef: userKey, certValiditySeconds: 300 });
    const manager = createCertAgentManager({ socketDir: join(dir, "agent") });
    try {
      const first = await manager.socketFor(server, ca.caPrivateKeyPath);
      // Still fresh: same socket, no re-sign.
      expect(await manager.socketFor(server, ca.caPrivateKeyPath)).toBe(first);
      // Jump past 3/4 of the TTL: re-signs but keeps the same socket path.
      vi.spyOn(Date, "now").mockReturnValue(Date.now() + 240_000 + 1);
      const renewed = await manager.socketFor(server, ca.caPrivateKeyPath);
      expect(renewed).toBe(first);
      expect(existsSync(renewed)).toBe(true);
    } finally {
      await manager.close();
    }
  });

  it("rejects servers that are not certificate-auth and closes cleanly", async () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const userKey = makeUserKey(dir);
    const manager = createCertAgentManager({ socketDir: join(dir, "agent") });
    await expect(manager.socketFor(certServer({ auth: "key", keyRef: userKey }), ca.caPrivateKeyPath))
      .rejects.toThrow(/does not use auth="certificate"/);
    await expect(manager.socketFor(certServer({ keyRef: undefined }), ca.caPrivateKeyPath))
      .rejects.toThrow(/has no keyRef/);

    const socketPath = await manager.socketFor(certServer({ keyRef: userKey }), ca.caPrivateKeyPath);
    await manager.close();
    expect(existsSync(socketPath)).toBe(false);
    // Idempotent close.
    await manager.close();
  });
});

// ---------------------------------------------------------------------------
// buildTrustedCAInstallCommand
// ---------------------------------------------------------------------------

describe("buildTrustedCAInstallCommand", () => {
  it("installs a drop-in TrustedUserCAKeys config and reloads sshd", () => {
    const dir = freshDir();
    const ca = ensureFleetCA(dir);
    const cmd = buildTrustedCAInstallCommand(ca.publicKey);
    expect(cmd).toContain("TrustedUserCAKeys /etc/ssh/flotilla-ca.pub");
    expect(cmd).toContain("sshd_config.d/60-flotilla-ca.conf");
    expect(cmd).toContain(ca.publicKey);
    expect(cmd).toContain("CA-INSTALLED");
    expect(cmd).toContain("sshd -t");
  });

  it("rejects malformed CA public keys", () => {
    expect(() => buildTrustedCAInstallCommand("ssh-ed25519 not-base64!!")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// config: auth="certificate" wiring
// ---------------------------------------------------------------------------

describe("config certificate auth", () => {
  it("accepts auth=certificate with certValiditySeconds", () => {
    const config = parseFleetConfig(`
[[servers]]
name = "web-1"
host = "10.0.0.1"
user = "deploy"
auth = "certificate"
keyRef = "~/.ssh/id_ed25519"
certValiditySeconds = 3600
`);
    const server = config.servers[0];
    expect(server.auth).toBe("certificate");
    expect(server.certValiditySeconds).toBe(3600);
  });

  it("rejects certificate servers without keyRef and out-of-range TTLs", () => {
    expect(() => parseFleetConfig(`
[[servers]]
name = "web-1"
host = "10.0.0.1"
user = "deploy"
auth = "certificate"
`)).toThrow(/has no keyRef/);
    expect(() => parseFleetConfig(`
[[servers]]
name = "web-1"
host = "10.0.0.1"
user = "deploy"
auth = "certificate"
keyRef = "~/.ssh/id_ed25519"
certValiditySeconds = 299
`)).toThrow();
    expect(() => parseFleetConfig(`
[[servers]]
name = "web-1"
host = "10.0.0.1"
user = "deploy"
auth = "certificate"
keyRef = "~/.ssh/id_ed25519"
certValiditySeconds = 604801
`)).toThrow();
  });
});
