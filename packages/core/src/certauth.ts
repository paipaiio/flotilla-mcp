/**
 * CA certificate authentication (§v2): short-lived OpenSSH user certificates
 * as an alternative to permanent authorized_keys entries.
 *
 * Why an agent shim: ssh2 (our SSH transport) cannot present OpenSSH
 * certificates — its publickey auth always sends the plain public key
 * derived from `privateKey`. So for auth="certificate" we run a minimal
 * ssh-agent on a per-process UNIX socket: it serves exactly one identity
 * (the current certificate for the target server) and signs with the
 * server's private key. ssh2's existing `agent:` path then presents the
 * certificate on the wire — the same mechanism OpenSSH itself uses (an
 * ssh-agent holds cert + key; ssh presents the cert).
 *
 * Trust model: the operator creates a fleet CA (ensureFleetCA), installs
 * its public key on each target as a TrustedUserCAKeys entry
 * (buildTrustedCAInstallCommand), and sets auth = "certificate" on the
 * server. Flotilla signs one certificate per server+user pair, valid for a
 * short TTL (default 8h, server.certValiditySeconds overrides), and
 * re-signs automatically once less than a quarter of the TTL remains. A
 * leaked certificate dies at expiry, and revoking fleet access is deleting
 * one CA line on the targets instead of hunting individual key lines.
 *
 * The agent speaks the OpenSSH agent protocol (PROTOCOL.agent) — the same
 * framing ssh2's own agent client parses in lib/agent.js.
 */
import { randomInt } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createServer, type Server as NetServer, type Socket } from "node:net";
import { existsSync, mkdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import type { ServerConfig } from "./types.js";
import { buildKeyInstallCommand } from "./onboard.js";
import { SetupRepairError } from "./setup-repair.js";

// ssh2 is CommonJS; Node's ESM named-export detection misses `utils`, so we
// take the default (module.exports) and destructure. ssh2's own agent client
// uses this same `utils.parseKey` for identity blobs.
const { utils } = ssh2;

/** Default certificate lifetime: short enough to limit leakage, long enough
 * to amortize re-signing across a work day. */
export const DEFAULT_CERT_TTL_SECONDS = 8 * 60 * 60;

const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;
const SSH_AGENT_RSA_SHA2_256 = 2;
const SSH_AGENT_RSA_SHA2_512 = 4;

// ---------------------------------------------------------------------------
// Fleet CA
// ---------------------------------------------------------------------------

export interface FleetCA {
  caPrivateKeyPath: string;
  caPublicKeyPath: string;
  /** Full public key line, e.g. "ssh-ed25519 AAAA... flotilla-ca". */
  publicKey: string;
  created: boolean;
}

function defaultRun(command: string, args: string[]): string {
  return execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 });
}

function expandHome(path: string): string {
  if (path === "~") return process.env.HOME ?? path;
  if (path.startsWith("~/")) return join(process.env.HOME ?? "~", path.slice(2));
  return path;
}

/** Create the fleet CA keypair at `<dir>/fleet_ca` when absent. */
export function ensureFleetCA(dir: string, run = defaultRun): FleetCA {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const caPrivateKeyPath = join(dir, "fleet_ca");
    const caPublicKeyPath = `${caPrivateKeyPath}.pub`;
    let created = false;
    if (!existsSync(caPrivateKeyPath)) {
      run("ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "flotilla-ca", "-f", caPrivateKeyPath]);
      if (!existsSync(caPrivateKeyPath)) throw new Error("ssh-keygen did not create the CA key");
      chmodCaKey(caPrivateKeyPath);
      created = true;
    }
    const publicKey = readFileSync(caPublicKeyPath, "utf8").trim();
    // Reuse the strict public-key validator (throws on malformed lines).
    buildKeyInstallCommand(publicKey);
    return { caPrivateKeyPath, caPublicKeyPath, publicKey, created };
  } catch (error) {
    throw new SetupRepairError(
      `fleet CA setup failed in ${dir}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function chmodCaKey(path: string): void {
  try {
    // CA private key must never be group/world readable.
    execFileSync("chmod", ["600", path], { stdio: "ignore" });
  } catch {
    /* best effort; ssh-keygen already applies a restrictive umask */
  }
}

// ---------------------------------------------------------------------------
// Certificate signing
// ---------------------------------------------------------------------------

export interface SignedCertificate {
  /** Full certificate line: "<type>-cert-v01@openssh.com <base64> <comment>". */
  certificate: string;
  /** Epoch ms after which the certificate stops being accepted. */
  validUntil: number;
}

const PRINCIPAL_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;

export function signUserCertificate(opts: {
  caPath: string;
  /** Private key whose public half gets certified. */
  userKeyPath: string;
  keyId: string;
  principals: string[];
  validSeconds: number;
  serial?: number;
  run?: (command: string, args: string[]) => string;
}): SignedCertificate {
  const { caPath, userKeyPath, keyId, principals, validSeconds, serial, run = defaultRun } = opts;
  if (principals.length === 0) throw new Error("certificate needs at least one principal");
  for (const p of principals) {
    if (!PRINCIPAL_RE.test(p)) throw new Error(`invalid certificate principal "${p}"`);
  }
  if (!Number.isInteger(validSeconds) || validSeconds < 60 || validSeconds > 7 * 24 * 3600) {
    throw new Error("validSeconds must be an integer between 60 and 604800");
  }

  const keyPath = expandHome(userKeyPath);
  // Derive the public key to certify; strict-format validated (throws on junk).
  const publicKey = run("ssh-keygen", ["-y", "-f", keyPath]).trim();
  buildKeyInstallCommand(publicKey);

  const tmpBase = join(dirname(keyPath), `.flotilla-sign-${process.pid}-${randomInt(1_000_000_000)}`);
  const tmpPub = `${tmpBase}.pub`;
  const tmpCert = `${tmpBase}-cert.pub`;
  try {
    writeFileSync(tmpPub, `${publicKey}\n`, { mode: 0o600 });
    run("ssh-keygen", [
      "-s", caPath,
      "-I", keyId,
      "-n", principals.join(","),
      "-V", `+${validSeconds}s`,
      "-z", String(serial ?? randomInt(0, 0x7fffffff)),
      tmpPub,
    ]);
    if (!existsSync(tmpCert)) throw new Error("ssh-keygen did not produce a certificate");
    const certificate = readFileSync(tmpCert, "utf8").trim();
    const [certType] = certificate.split(/\s+/);
    if (!certType.endsWith("-cert-v01@openssh.com")) {
      throw new Error(`unexpected certificate type "${certType}"`);
    }
    return { certificate, validUntil: Date.now() + validSeconds * 1000 };
  } finally {
    for (const f of [tmpPub, tmpCert]) {
      try {
        unlinkSync(f);
      } catch {
        /* already gone */
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Per-server certificate agent (OpenSSH agent protocol, minimal)
// ---------------------------------------------------------------------------

interface AgentIdentity {
  /** Raw wire blob: base64-decoded certificate. */
  blob: Buffer;
  /** Certificate algorithm, e.g. "ssh-ed25519-cert-v01@openssh.com". */
  certType: string;
  comment: string;
  /** Server private key, used to answer SIGN requests. */
  signKey: ParsedKey;
}

interface AgentState {
  socketPath: string;
  server: NetServer;
  /** Mutable holder so re-signing swaps the served identity in place. */
  current: { identity: AgentIdentity };
  expiresAt: number;
  ttlMs: number;
}

function stringField(b: Buffer): Buffer {
  const head = Buffer.allocUnsafe(4);
  head.writeUInt32BE(b.length, 0);
  return Buffer.concat([head, b]);
}

function frame(payload: Buffer): Buffer {
  const head = Buffer.allocUnsafe(4);
  head.writeUInt32BE(payload.length, 0);
  return Buffer.concat([head, payload]);
}

function buildIdentity(certificate: string, server: ServerConfig): AgentIdentity {
  const [certType, b64] = certificate.trim().split(/\s+/);
  if (!certType || !b64) throw new Error("malformed certificate line");
  const blob = Buffer.from(b64, "base64");
  if (blob.length === 0) throw new Error("malformed certificate blob");
  const parsed = utils.parseKey(certificate);
  if (parsed instanceof Error || Array.isArray(parsed)) {
    throw new Error(`ssh2 cannot parse the signed certificate: ${parsed instanceof Error ? parsed.message : "array"}`);
  }
  const signKeyRaw = utils.parseKey(readFileSync(expandHome(server.keyRef!), "utf8"));
  if (signKeyRaw instanceof Error || Array.isArray(signKeyRaw)) {
    throw new Error(`cannot parse private key ${server.keyRef}`);
  }
  if (!signKeyRaw.isPrivateKey()) throw new Error(`${server.keyRef} is not a private key`);
  return {
    blob,
    certType,
    comment: `flotilla-${server.name}`,
    signKey: signKeyRaw,
  };
}

function identitiesAnswer(identity: AgentIdentity): Buffer {
  return Buffer.concat([
    Buffer.from([SSH_AGENT_IDENTITIES_ANSWER]),
    (() => {
      const n = Buffer.allocUnsafe(4);
      n.writeUInt32BE(1, 0);
      return n;
    })(),
    stringField(identity.blob),
    stringField(Buffer.from(identity.comment, "utf8")),
  ]);
}

function signResponse(identity: AgentIdentity, msg: Buffer): Buffer {
  // payload after type byte: string key_blob, string data, uint32 flags
  let p = 1;
  const keyLen = msg.readUInt32BE(p);
  p += 4;
  const keyBlob = msg.subarray(p, p + keyLen);
  p += keyLen;
  const dataLen = msg.readUInt32BE(p);
  p += 4;
  const data = msg.subarray(p, p + dataLen);
  p += dataLen;
  if (keyBlob.equals(identity.blob) === false) throw new Error("unknown key blob");
  if (p + 4 > msg.length) throw new Error("malformed sign request");
  const flags = msg.readUInt32BE(p);

  let hash: string | undefined;
  if (identity.certType.startsWith("ssh-rsa-cert")) {
    if (flags & SSH_AGENT_RSA_SHA2_256) hash = "sha256";
    else if (flags & SSH_AGENT_RSA_SHA2_512) hash = "sha512";
  }
  const signature = identity.signKey.sign(data, hash);
  if (!(signature instanceof Buffer) || signature.length === 0) {
    throw new Error("private key refused to sign");
  }
  const inner = Buffer.concat([stringField(Buffer.from(identity.certType, "utf8")), stringField(signature)]);
  return Buffer.concat([Buffer.from([SSH_AGENT_SIGN_RESPONSE]), stringField(inner)]);
}

function handleAgentSocket(socket: Socket, current: { identity: AgentIdentity }): void {
  let buf: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  socket.on("data", (chunk: Buffer) => {
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 5) return;
      const msgLen = buf.readUInt32BE(0);
      if (buf.length < 4 + msgLen) return;
      const msg = buf.subarray(4, 4 + msgLen);
      buf = buf.subarray(4 + msgLen);
      let reply: Buffer;
      try {
        const type = msg[0];
        if (type === SSH_AGENTC_REQUEST_IDENTITIES) {
          reply = identitiesAnswer(current.identity);
        } else if (type === SSH_AGENTC_SIGN_REQUEST) {
          reply = signResponse(current.identity, msg);
        } else {
          reply = Buffer.from([SSH_AGENT_FAILURE]);
        }
      } catch {
        reply = Buffer.from([SSH_AGENT_FAILURE]);
      }
      socket.write(frame(reply));
    }
  });
}

export interface CertAgentManager {
  /** UNIX socket path of the agent serving `server`'s current certificate. */
  socketFor(server: ServerConfig, caPath: string): Promise<string>;
  close(): Promise<void>;
}

export function createCertAgentManager(opts: { socketDir?: string } = {}): CertAgentManager {
  const dir = opts.socketDir ?? join(tmpdir(), `flotilla-ca-${process.pid}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const agents = new Map<string, AgentState>();
  // Best-effort socket cleanup on exit; the OS also reaps tmp.
  process.once("exit", () => {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  function socketPathFor(server: ServerConfig): string {
    // macOS sun_path is ~104 bytes: keep the per-server name short and hash
    // long ones.
    const raw = `${server.name}-${createNameHash(server.name)}`;
    return join(dir, `s-${raw.slice(0, 40)}.sock`);
  }

  async function socketFor(server: ServerConfig, caPath: string): Promise<string> {
    if (server.auth !== "certificate") {
      throw new Error(`Server "${server.name}" does not use auth="certificate"`);
    }
    if (!server.keyRef) {
      throw new Error(`Server "${server.name}" uses auth="certificate" but has no keyRef`);
    }
    const ttlSeconds = server.certValiditySeconds ?? DEFAULT_CERT_TTL_SECONDS;
    const ttlMs = ttlSeconds * 1000;
    let state = agents.get(server.name);
    if (state && Date.now() + ttlMs / 4 < state.expiresAt) {
      return state.socketPath;
    }

    // (Re)sign. Signing and listener creation are synchronous up to the
    // listen() — a concurrent caller either sees the fresh state above or
    // re-signs once extra; both converge on the same socket.
    ensureFleetCA(dirname(caPath));
    const signed = signUserCertificate({
      caPath,
      userKeyPath: server.keyRef,
      keyId: `flotilla-${server.name}`,
      principals: [server.user],
      validSeconds: ttlSeconds,
    });
    const identity = buildIdentity(signed.certificate, server);
    if (state) {
      state.current.identity = identity;
      state.expiresAt = signed.validUntil;
      return state.socketPath;
    }

    const socketPath = socketPathFor(server);
    try {
      unlinkSync(socketPath);
    } catch {
      /* no stale socket */
    }
    const holder: { identity: AgentIdentity } = { identity };
    const netServer = createServer((s) => handleAgentSocket(s, holder));
    state = { socketPath, server: netServer, current: holder, expiresAt: signed.validUntil, ttlMs };
    agents.set(server.name, state);
    await new Promise<void>((resolve, reject) => {
      netServer.once("error", (err) => {
        agents.delete(server.name);
        reject(err);
      });
      netServer.listen(socketPath, () => resolve());
    });
    return socketPath;
  }

  async function close(): Promise<void> {
    for (const state of agents.values()) {
      await new Promise<void>((resolve) => state.server.close(() => resolve()));
      try {
        unlinkSync(state.socketPath);
      } catch {
        /* already gone */
      }
    }
    agents.clear();
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }

  return { socketFor, close };
}

function createNameHash(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}

// ---------------------------------------------------------------------------
// Target-side CA trust install
// ---------------------------------------------------------------------------

/**
 * Idempotent install of the fleet CA as a TrustedUserCAKeys source on a
 * target (root shell). Uses an sshd_config.d drop-in — mainstream OpenSSH
 * (≥7.4, and every maintained distro) includes that directory; the reload
 * is best-effort and never fails the install.
 */
export function buildTrustedCAInstallCommand(caPublicKey: string): string {
  const pub = caPublicKey.trim();
  try {
    buildKeyInstallCommand(pub); // strict OpenSSH public-key validation
  } catch (err) {
    throw new SetupRepairError(
      `not a valid CA public key: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  return (
    `install -d -m 755 /etc/ssh/sshd_config.d && ` +
    `printf '%s\\n' ${q(pub)} > /etc/ssh/flotilla-ca.pub && ` +
    `printf '%s\\n' 'TrustedUserCAKeys /etc/ssh/flotilla-ca.pub' > /etc/ssh/sshd_config.d/60-flotilla-ca.conf && ` +
    `{ sshd -t 2>/dev/null && (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || true) || true; } && ` +
    `echo CA-INSTALLED`
  );
}
