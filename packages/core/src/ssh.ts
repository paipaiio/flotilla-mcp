/**
 * SSH transport built on ssh2, with:
 * - connection pooling keyed by server name
 * - auth cascade: SSH agent -> key file -> env password (never CLI args)
 * - TOFU host-key verification within the process lifetime; trustedHostKey pins
 *   are the only control that survives restarts
 * - ProxyJump via forwardOut through a bastion server (no agent forwarding)
 */
import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { dirname as posixDirname } from "node:path/posix";
import { Client, type ClientChannel, type ConnectConfig, type SFTPWrapper } from "ssh2";
import {
  defaultKeychainBackend,
  resolveServerSecret,
  resolveServerSecretWithRepair,
  type CredentialRepair,
} from "./keychain.js";
import { credentialRecoveryMessage } from "./credentials.js";
import { createCertAgentManager, type CertAgentManager } from "./certauth.js";
import { BoundedText, OperationDrainer, withCancellation, type DrainResult } from "./io.js";
import {
  checkCommandPathScope,
  checkCommandScope,
  checkPathScope,
  resolveRemotePathForScope,
} from "./policy.js";
import type { ExecOptions, ExecResult, RelayResult, ServerConfig, TransferResult, Transport } from "./types.js";

/**
 * RFC 9142 algorithm allowlist — SHA-1 constructions (ssh-rsa, group1/14-sha1,
 * hmac-sha1), CBC ciphers, and arcfour/3des are out. On by default; a server
 * can opt back into ssh2's full negotiation set with allowLegacyAlgorithms.
 */
export const STRICT_ALGORITHMS = {
  kex: [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
  ],
  serverHostKey: [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
  ],
  cipher: [
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
  ],
  hmac: [
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
  ],
  compress: ["none", "zlib@openssh.com"],
} as const;

/**
 * The algorithm set for a connection: the strict allowlist unless globally
 * disabled or the server is flagged legacy. Undefined = ssh2 defaults.
 */
export function effectiveAlgorithms(
  strict: boolean,
  allowLegacy: boolean | undefined,
): ConnectConfig["algorithms"] | undefined {
  if (!strict || allowLegacy) return undefined;
  // ssh2 mutates nothing but types want a plain record; cast off const.
  return STRICT_ALGORITHMS as unknown as ConnectConfig["algorithms"];
}

function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

/**
 * Credential cascade: env var first (explicit operator choice), then the OS
 * keychain. The keychain backend is resolved lazily and its absence (no
 * prebuilt binary, no Secret Service daemon) degrades to env-only.
 */
async function serverSecret(server: ServerConfig, kind: "password" | "sudo"): Promise<string | undefined> {
  return resolveServerSecret(server, kind, process.env, await defaultKeychainBackend());
}

export class SshTransport implements Transport {
  private readonly pool = new Map<string, Client>();
  private readonly connecting = new Map<string, Promise<Client>>();
  /** TOFU store: process-lifetime only, nothing written to disk. */
  private readonly knownHostKeys = new Map<string, string>();
  /** Last use per pooled connection; drives idle reaping. */
  private readonly lastUsed = new Map<string, number>();
  private readonly idleReapMs: number;
  private readonly strictAlgorithms: boolean;
  private readonly maxSshOutputBytes: number;
  private readonly onCredentialRequired?: CredentialRepair;
  private readonly reapTimer: NodeJS.Timeout;
  private readonly operations = new OperationDrainer("SSH transport");
  /** auth="certificate" support: fleet CA path + lazily created agent manager. */
  private readonly certAuth?: { caPath: string };
  private certAgent?: CertAgentManager;

  constructor(
    private readonly serversByName: Map<string, ServerConfig>,
    opts: {
      idleReapMs?: number;
      strictAlgorithms?: boolean;
      maxSshOutputBytes?: number;
      onCredentialRequired?: CredentialRepair;
      certAuth?: { caPath: string };
    } = {},
  ) {
    this.idleReapMs = opts.idleReapMs ?? 15 * 60_000;
    this.strictAlgorithms = opts.strictAlgorithms ?? true;
    this.maxSshOutputBytes = opts.maxSshOutputBytes ?? 1_048_576;
    this.onCredentialRequired = opts.onCredentialRequired;
    this.certAuth = opts.certAuth;
    // unref'd so the timer never keeps the process alive on its own.
    this.reapTimer = setInterval(() => this.reapIdle(), 60_000);
    this.reapTimer.unref();
  }

  /** Close pooled connections idle longer than idleReapMs. */
  reapIdle(now = Date.now()): number {
    let reaped = 0;
    for (const [name, conn] of this.pool) {
      const used = this.lastUsed.get(name) ?? now;
      if (now - used > this.idleReapMs) {
        try {
          conn.end();
        } catch {
          /* ignore */
        }
        this.pool.delete(name);
        this.lastUsed.delete(name);
        reaped++;
      }
    }
    return reaped;
  }

  /** Lexical + remote realpath boundary check for scoped SFTP operations. */
  private async assertScopedPath(
    server: ServerConfig,
    remotePath: string,
    sftp: SFTPWrapper,
    opts: ExecOptions,
  ): Promise<void> {
    const lexicalReason = checkPathScope(server, remotePath);
    if (lexicalReason) throw new Error(lexicalReason);
    if (!server.scopes?.paths?.length) return;
    const resolved = await resolveRemotePathForScope(
      remotePath,
      (candidate) => withCancellation(
        new Promise<string>((resolve, reject) => {
          sftp.realpath(candidate, (err, absolutePath) =>
            err ? reject(err) : resolve(absolutePath),
          );
        }),
        opts.timeoutMs ?? 60_000,
        `SFTP realpath ${candidate} on ${server.name}`,
        () => sftp.end(),
        opts.signal,
      ),
      (error) => typeof error === "object" && error !== null && (error as { code?: unknown }).code === 2,
    );
    const resolvedReason = checkPathScope(server, remotePath, resolved);
    if (resolvedReason) throw new Error(resolvedReason);
  }

  private touch(name: string): void {
    this.lastUsed.set(name, Date.now());
  }

  /** Open an SFTP subsystem with the same timeout/cancellation contract as transfers. */
  private openSftp(server: ServerConfig, conn: Client, opts: ExecOptions): Promise<SFTPWrapper> {
    let opened: SFTPWrapper | undefined;
    const operation = new Promise<SFTPWrapper>((resolve, reject) => {
      conn.sftp((err, sftp) => {
        if (err) reject(err);
        else {
          opened = sftp;
          resolve(sftp);
        }
      });
    });
    return withCancellation(
      operation,
      opts.timeoutMs ?? 60_000,
      `SFTP initialization on ${server.name}`,
      () => {
        try { opened?.end(); } catch { /* subsystem not open or already closed */ }
        this.drop(server.name);
      },
      opts.signal,
    );
  }

  /** The TOFU-accepted host key for a connected server, "SHA256:..." form. */
  hostKeyOf(name: string): string | undefined {
    const k = this.knownHostKeys.get(name);
    return k ? `SHA256:${k}` : undefined;
  }

  exec(server: ServerConfig, command: string, opts: ExecOptions): Promise<ExecResult> {
    return this.operations.run(() => this.execUntracked(server, command, opts));
  }

  private async execUntracked(
    server: ServerConfig,
    command: string,
    opts: ExecOptions,
  ): Promise<ExecResult> {
    const started = Date.now();
    if (opts.signal?.aborted) throw new Error(`Command aborted on ${server.name}`);
    const effectiveScopeCommand = opts.sudo ? `sudo ${command}` : command;
    const scopeReason =
      checkCommandScope(server, effectiveScopeCommand) ??
      checkCommandPathScope(server, effectiveScopeCommand) ??
      (opts.workdir ? checkPathScope(server, opts.workdir) : null);
    if (scopeReason) {
      return {
        host: server.name,
        ok: false,
        exitCode: null,
        stdout: "",
        stderr: "",
        durationMs: Date.now() - started,
        error: scopeReason,
      };
    }
    let password: string | undefined;
    if (opts.sudo) {
      // Password is optional: with NOPASSWD sudoers rules none is needed.
      password = await serverSecret(server, "sudo");
    }
    const conn = await this.connection(server);
    this.touch(server.name);
    const baseCommand = opts.workdir
      ? `cd ${shellQuote(opts.workdir)} && ${command}`
      : command;
    let fullCommand = baseCommand;
    if (opts.sudo) {
      // Two modes:
      // - password configured: `sudo -S -p ''` reads it from stdin (never
      //   argv, prompt suppressed so it can't leak into stderr)
      // - no password: `sudo -n` runs non-interactively — NOPASSWD rules
      //   succeed, anything else fails immediately instead of hanging
      // The command is NOT wrapped in sh -c: ssh2's exec channel already runs
      // it through the remote shell, and a wrapper would break sudoers
      // command whitelists (sudo would see sh, not the real command).
      // With workdir, cd happens as the user before sudo.
      const sudoPrefix = password ? "sudo -S -p ''" : "sudo -n";
      fullCommand = opts.workdir
        ? `cd ${shellQuote(opts.workdir)} && ${sudoPrefix} ${command}`
        : `${sudoPrefix} ${command}`;
    }
    const timeoutMs = opts.timeoutMs ?? 60_000;
    return new Promise<ExecResult>((resolve, reject) => {
      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      let channel: ClientChannel | undefined;

      const finish = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        opts.signal?.removeEventListener("abort", onAbort);
        fn();
      };
      const onAbort = (): void => {
        try { channel?.close(); } catch { /* channel already gone */ }
        finish(() => reject(new Error(`Command aborted on ${server.name}`)));
      };
      opts.signal?.addEventListener("abort", onAbort, { once: true });
      // Abort may have raced with connection acquisition before the listener
      // was registered. Re-check so no remote channel is opened afterwards.
      if (opts.signal?.aborted) {
        onAbort();
        return;
      }

      conn.exec(fullCommand, (err, ch) => {
        if (err) {
          // Drop a possibly-dead connection so the next call reconnects.
          this.drop(server.name);
          finish(() => reject(err));
          return;
        }
        channel = ch;
        if (password !== undefined) {
          ch.write(password + "\n");
        }
        const stdout = new BoundedText(this.maxSshOutputBytes, "stdout");
        const stderr = new BoundedText(this.maxSshOutputBytes, "stderr");
        let exitCode: number | null = null;

        ch.on("data", (d: Buffer) => {
          stdout.append(d);
        });
        ch.stderr.on("data", (d: Buffer) => {
          stderr.append(d);
        });
        ch.on("exit", (code: number | null) => {
          exitCode = code;
        });
        ch.on("close", () => {
          finish(() =>
            resolve({
              host: server.name,
              ok: exitCode === 0,
              exitCode,
              stdout: stdout.value(),
              stderr: stderr.value(),
              durationMs: Date.now() - started,
            }),
          );
        });
        ch.on("error", (e: Error) => {
          finish(() => reject(e));
        });

        timer = setTimeout(() => {
          try {
            channel?.close();
          } catch {
            /* channel already gone */
          }
          finish(() =>
            reject(new Error(`Command timed out after ${timeoutMs}ms on ${server.name}`)),
          );
        }, timeoutMs);
      });
    });
  }

  /**
   * SFTP upload: mkdir -p the remote parent, then fastPut. Overwrites existing
   * files. The bytes reported come from the local file's stat — what was sent.
   */
  upload(server: ServerConfig, localPath: string, remotePath: string, opts: ExecOptions): Promise<TransferResult> {
    return this.operations.run(() => this.uploadUntracked(server, localPath, remotePath, opts));
  }

  private async uploadUntracked(
    server: ServerConfig,
    localPath: string,
    remotePath: string,
    opts: ExecOptions,
  ): Promise<TransferResult> {
    const started = Date.now();
    const bytes = statSync(expandHome(localPath)).size;
    const lexicalReason = checkPathScope(server, remotePath);
    if (lexicalReason) throw new Error(lexicalReason);
    const conn = await this.connection(server);
    this.touch(server.name);

    const sftp = await this.openSftp(server, conn, opts);
    try {
      await this.assertScopedPath(server, remotePath, sftp, opts);
      const dir = posixDirname(remotePath);
      if (dir && dir !== "/" && dir !== ".") {
        const mkdir = await this.execUntracked(server, `mkdir -p ${shellQuote(dir)}`, opts);
        if (!mkdir.ok) throw new Error(`mkdir ${dir} failed on ${server.name}: ${mkdir.stderr.trim() || mkdir.error}`);
      }
      await withCancellation(
        new Promise<void>((resolve, reject) => {
          sftp.fastPut(expandHome(localPath), remotePath, (err) => err ? reject(err) : resolve());
        }),
        opts.timeoutMs ?? 60_000,
        `SFTP upload to ${server.name}:${remotePath}`,
        () => sftp.end(),
        opts.signal,
      );
    } finally {
      sftp.end();
    }
    return { host: server.name, ok: true, bytes, durationMs: Date.now() - started };
  }

  /** SFTP download: fastGet remotePath to localPath (parent dir must exist locally). */
  download(server: ServerConfig, remotePath: string, localPath: string, opts: ExecOptions): Promise<TransferResult> {
    return this.operations.run(() => this.downloadUntracked(server, remotePath, localPath, opts));
  }

  private async downloadUntracked(
    server: ServerConfig,
    remotePath: string,
    localPath: string,
    opts: ExecOptions,
  ): Promise<TransferResult> {
    const started = Date.now();
    const lexicalReason = checkPathScope(server, remotePath);
    if (lexicalReason) throw new Error(lexicalReason);
    const conn = await this.connection(server);
    this.touch(server.name);

    const sftp = await this.openSftp(server, conn, opts);
    try {
      await this.assertScopedPath(server, remotePath, sftp, opts);
      await withCancellation(
        new Promise<void>((resolve, reject) => {
          sftp.fastGet(remotePath, expandHome(localPath), (err) => err ? reject(err) : resolve());
        }),
        opts.timeoutMs ?? 60_000,
        `SFTP download from ${server.name}:${remotePath}`,
        () => sftp.end(),
        opts.signal,
      );
    } finally {
      sftp.end();
    }
    const bytes = statSync(expandHome(localPath)).size;
    return { host: server.name, ok: true, bytes, durationMs: Date.now() - started };
  }

  /** Read a bounded UTF-8 remote file directly into process memory. */
  readText(
    server: ServerConfig,
    remotePath: string,
    opts: ExecOptions,
  ): Promise<{ host: string; text: string; bytes: number; durationMs: number }> {
    return this.operations.run(() => this.readTextUntracked(server, remotePath, opts));
  }

  private async readTextUntracked(
    server: ServerConfig,
    remotePath: string,
    opts: ExecOptions,
  ): Promise<{ host: string; text: string; bytes: number; durationMs: number }> {
    const started = Date.now();
    const lexicalReason = checkPathScope(server, remotePath);
    if (lexicalReason) throw new Error(lexicalReason);
    const conn = await this.connection(server);
    this.touch(server.name);
    const sftp = await this.openSftp(server, conn, opts);
    try {
      await this.assertScopedPath(server, remotePath, sftp, opts);
      const size = await withCancellation(
        new Promise<number>((resolve, reject) => {
          sftp.stat(remotePath, (error, attrs) => error ? reject(error) : resolve(attrs.size));
        }),
        opts.timeoutMs ?? 60_000,
        `SFTP stat ${server.name}:${remotePath}`,
        () => sftp.end(),
        opts.signal,
      );
      if (size > this.maxSshOutputBytes) {
        throw new Error(`Remote file exceeds memory transfer limit (${size} > ${this.maxSshOutputBytes} bytes)`);
      }
      const data = await withCancellation(
        new Promise<Buffer>((resolve, reject) => {
          sftp.readFile(remotePath, (error, value) => error ? reject(error) : resolve(value));
        }),
        opts.timeoutMs ?? 60_000,
        `SFTP in-memory read from ${server.name}:${remotePath}`,
        () => sftp.end(),
        opts.signal,
      );
      if (data.byteLength > this.maxSshOutputBytes) {
        throw new Error(`Remote file exceeds memory transfer limit (${data.byteLength} > ${this.maxSshOutputBytes} bytes)`);
      }
      return { host: server.name, text: data.toString("utf8"), bytes: data.byteLength, durationMs: Date.now() - started };
    } finally {
      sftp.end();
    }
  }

  /** Write a bounded UTF-8 value directly from process memory via SFTP. */
  writeText(server: ServerConfig, remotePath: string, text: string, opts: ExecOptions): Promise<TransferResult> {
    return this.operations.run(() => this.writeTextUntracked(server, remotePath, text, opts));
  }

  private async writeTextUntracked(
    server: ServerConfig,
    remotePath: string,
    text: string,
    opts: ExecOptions,
  ): Promise<TransferResult> {
    const started = Date.now();
    const data = Buffer.from(text, "utf8");
    if (data.byteLength > this.maxSshOutputBytes) {
      throw new Error(`Text exceeds memory transfer limit (${data.byteLength} > ${this.maxSshOutputBytes} bytes)`);
    }
    const lexicalReason = checkPathScope(server, remotePath);
    if (lexicalReason) throw new Error(lexicalReason);
    const conn = await this.connection(server);
    this.touch(server.name);
    const sftp = await this.openSftp(server, conn, opts);
    try {
      await this.assertScopedPath(server, remotePath, sftp, opts);
      const dir = posixDirname(remotePath);
      if (dir && dir !== "/" && dir !== ".") {
        const mkdir = await this.execUntracked(server, `mkdir -p ${shellQuote(dir)}`, opts);
        if (!mkdir.ok) throw new Error(`mkdir ${dir} failed on ${server.name}: ${mkdir.stderr.trim() || mkdir.error}`);
      }
      await withCancellation(
        new Promise<void>((resolve, reject) => {
          sftp.writeFile(remotePath, data, (error) => error ? reject(error) : resolve());
        }),
        opts.timeoutMs ?? 60_000,
        `SFTP in-memory write to ${server.name}:${remotePath}`,
        () => sftp.end(),
        opts.signal,
      );
      return { host: server.name, ok: true, bytes: data.byteLength, durationMs: Date.now() - started };
    } finally {
      sftp.end();
    }
  }

  /**
   * Server-to-server relay: open an SFTP read stream on src and pipe it into an
   * SFTP write stream on dst. Bytes flow through this process's memory only —
   * the control machine never writes a copy to disk. The destination parent
   * directory is created first; an existing destination file is overwritten.
   */
  relayCopy(
    src: ServerConfig,
    srcPath: string,
    dst: ServerConfig,
    dstPath: string,
    opts: ExecOptions,
  ): Promise<RelayResult> {
    return this.operations.run(() => this.relayCopyUntracked(src, srcPath, dst, dstPath, opts));
  }

  private async relayCopyUntracked(
    src: ServerConfig,
    srcPath: string,
    dst: ServerConfig,
    dstPath: string,
    opts: ExecOptions,
  ): Promise<RelayResult> {
    const started = Date.now();
    const base = { source: src.name, dest: dst.name };
    const srcLexicalReason = checkPathScope(src, srcPath);
    if (srcLexicalReason) return { ...base, ok: false, bytes: 0, durationMs: Date.now() - started, error: srcLexicalReason };
    const dstLexicalReason = checkPathScope(dst, dstPath);
    if (dstLexicalReason) return { ...base, ok: false, bytes: 0, durationMs: Date.now() - started, error: dstLexicalReason };

    const srcConn = await this.connection(src);
    const dstConn = await this.connection(dst);
    this.touch(src.name);
    this.touch(dst.name);

    const srcSftp = await this.openSftp(src, srcConn, opts);
    let dstSftp: SFTPWrapper;
    try {
      dstSftp = await this.openSftp(dst, dstConn, opts);
    } catch (error) {
      srcSftp.end();
      throw error;
    }

    try {
      await this.assertScopedPath(src, srcPath, srcSftp, opts);
      await this.assertScopedPath(dst, dstPath, dstSftp, opts);
      const dir = posixDirname(dstPath);
      if (dir && dir !== "/" && dir !== ".") {
        const mkdir = await this.execUntracked(dst, `mkdir -p ${shellQuote(dir)}`, opts);
        if (!mkdir.ok) {
          return {
            ...base, ok: false, bytes: 0, durationMs: Date.now() - started,
            error: `mkdir ${dir} failed on ${dst.name}: ${mkdir.stderr.trim() || mkdir.error}`,
          };
        }
      }
      let read: ReturnType<SFTPWrapper["createReadStream"]> | undefined;
      let write: ReturnType<SFTPWrapper["createWriteStream"]> | undefined;
      const transfer = new Promise<number>((resolve, reject) => {
        let n = 0;
        let settled = false;
        const fail = (err: Error) => {
          if (settled) return;
          settled = true;
          read?.destroy();
          write?.destroy();
          reject(err);
        };
        const readStream = srcSftp.createReadStream(srcPath);
        const writeStream = dstSftp.createWriteStream(dstPath);
        read = readStream;
        write = writeStream;
        readStream.on("data", (chunk: Buffer) => { n += chunk.length; });
        readStream.on("error", fail);
        writeStream.on("error", fail);
        writeStream.on("close", () => {
          if (settled) return;
          settled = true;
          resolve(n);
        });
        readStream.pipe(writeStream);
      });
      const bytes = await withCancellation(
        transfer,
        opts.timeoutMs ?? 60_000,
        `SFTP relay ${src.name}:${srcPath} -> ${dst.name}:${dstPath}`,
        () => { read?.destroy(); write?.destroy(); },
        opts.signal,
      );
      return { ...base, ok: true, bytes, durationMs: Date.now() - started };
    } finally {
      srcSftp.end();
      dstSftp.end();
    }
  }

  async close(): Promise<void> {
    this.operations.stopAccepting();
    clearInterval(this.reapTimer);
    for (const [name, conn] of this.pool) {
      try {
        conn.end();
      } catch {
        /* ignore */
      }
      this.pool.delete(name);
      this.lastUsed.delete(name);
    }
  }

  /** Stop accepting work, let active channels finish, then close the old pool. */
  async drainAndClose(timeoutMs = 30_000): Promise<DrainResult> {
    const result = await this.operations.drain(timeoutMs);
    await this.close();
    return result;
  }

  private drop(name: string): void {
    const conn = this.pool.get(name);
    if (conn) {
      try {
        conn.end();
      } catch {
        /* ignore */
      }
      this.pool.delete(name);
      this.lastUsed.delete(name);
    }
  }

  private connection(server: ServerConfig): Promise<Client> {
    const pooled = this.pool.get(server.name);
    if (pooled) return Promise.resolve(pooled);

    // Deduplicate concurrent connect attempts for the same server.
    const pending = this.connecting.get(server.name);
    if (pending) return pending;

    const attempt = this.connect(server)
      .then((conn) => {
        this.pool.set(server.name, conn);
        conn.on("close", () => {
          this.pool.delete(server.name);
          this.lastUsed.delete(server.name);
        });
        conn.on("error", () => {
          this.pool.delete(server.name);
          this.lastUsed.delete(server.name);
        });
        return conn;
      })
      .finally(() => this.connecting.delete(server.name));
    this.connecting.set(server.name, attempt);
    return attempt;
  }

  private async connect(server: ServerConfig): Promise<Client> {
    const config = await this.connectConfig(server);

    if (!server.via) return openConnection(config);

    const bastionConfig = this.serversByName.get(server.via);
    if (!bastionConfig) {
      throw new Error(`Jump host "${server.via}" not found for server "${server.name}"`);
    }
    const bastion = await this.connection(bastionConfig);
    const stream = await new Promise<ClientChannel>((resolve, reject) => {
      bastion.forwardOut(
        "127.0.0.1",
        0,
        server.host,
        server.port,
        (err, ch) => (err ? reject(err) : resolve(ch)),
      );
    });
    return openConnection({ ...config, sock: stream });
  }

  private async connectConfig(server: ServerConfig): Promise<ConnectConfig> {
    const base: ConnectConfig = {
      host: server.host,
      port: server.port,
      username: server.user,
      readyTimeout: 20_000,
      hostHash: "sha256",
      hostVerifier: (hashedKey: string) => this.verifyHostKey(server, hashedKey),
    };

    const algorithms = effectiveAlgorithms(this.strictAlgorithms, server.allowLegacyAlgorithms);
    if (algorithms) base.algorithms = algorithms;

    switch (server.auth) {
      case "agent":
        if (process.env.SSH_AUTH_SOCK) {
          base.agent = process.env.SSH_AUTH_SOCK;
          break;
        }
        throw new Error(
          `Server "${server.name}" uses auth="agent" but SSH_AUTH_SOCK is not set`,
        );
      case "key":
        base.privateKey = readFileSync(expandHome(server.keyRef!), "utf8");
        break;
      case "certificate": {
        if (!this.certAuth) {
          throw new Error(
            `Server "${server.name}" uses auth="certificate" but no fleet CA is configured for this transport`,
          );
        }
        this.certAgent ??= createCertAgentManager();
        base.agent = await this.certAgent.socketFor(server, this.certAuth.caPath);
        break;
      }
      case "password": {
        const password = await resolveServerSecretWithRepair(
          server,
          "password",
          () => serverSecret(server, "password"),
          this.onCredentialRequired,
        );
        if (!password) {
          throw new Error(credentialRecoveryMessage(server.name));
        }
        base.password = password;
        break;
      }
    }
    return base;
  }

  /**
   * TOFU within the process: first sighting of a host key is accepted and
   * remembered; a later mismatch in the same process fails the connection.
   * A configured trustedHostKey pin always wins and is never overridden.
   */
  private verifyHostKey(server: ServerConfig, hashedKey: string): boolean {
    const pinned = server.trustedHostKey;
    if (pinned) {
      const expected = pinned.startsWith("SHA256:") ? pinned.slice("SHA256:".length) : pinned;
      return hashedKey === expected;
    }
    const known = this.knownHostKeys.get(server.name);
    if (known === undefined) {
      this.knownHostKeys.set(server.name, hashedKey);
      return true;
    }
    return known === hashedKey;
  }
}

function openConnection(config: ConnectConfig): Promise<Client> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn.once("ready", () => resolve(conn));
    conn.once("error", reject);
    conn.connect(config);
  });
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
