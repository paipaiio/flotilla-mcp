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
import type { ExecOptions, ExecResult, ServerConfig, TransferResult, Transport } from "./types.js";

function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

function envPassword(server: ServerConfig): string | undefined {
  const perHost = `FLOTILLA_${server.name.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_PASSWORD`;
  return process.env[perHost] ?? process.env.FLOTILLA_PASSWORD;
}

function sudoPassword(server: ServerConfig): string | undefined {
  const perHost = `FLOTILLA_${server.name.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_SUDO_PASSWORD`;
  return process.env[perHost] ?? process.env.FLOTILLA_SUDO_PASSWORD;
}

export class SshTransport implements Transport {
  private readonly pool = new Map<string, Client>();
  private readonly connecting = new Map<string, Promise<Client>>();
  /** TOFU store: process-lifetime only, nothing written to disk. */
  private readonly knownHostKeys = new Map<string, string>();
  /** Last use per pooled connection; drives idle reaping. */
  private readonly lastUsed = new Map<string, number>();
  private readonly idleReapMs: number;
  private readonly reapTimer: NodeJS.Timeout;

  constructor(
    private readonly serversByName: Map<string, ServerConfig>,
    opts: { idleReapMs?: number } = {},
  ) {
    this.idleReapMs = opts.idleReapMs ?? 15 * 60_000;
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

  private touch(name: string): void {
    this.lastUsed.set(name, Date.now());
  }

  /** The TOFU-accepted host key for a connected server, "SHA256:..." form. */
  hostKeyOf(name: string): string | undefined {
    const k = this.knownHostKeys.get(name);
    return k ? `SHA256:${k}` : undefined;
  }

  async exec(
    server: ServerConfig,
    command: string,
    opts: ExecOptions,
  ): Promise<ExecResult> {
    let password: string | undefined;
    if (opts.sudo) {
      // Password is optional: with NOPASSWD sudoers rules none is needed.
      password = sudoPassword(server);
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
    const started = Date.now();

    return new Promise<ExecResult>((resolve, reject) => {
      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      let channel: ClientChannel | undefined;

      const finish = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        fn();
      };

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
        let stdout = "";
        let stderr = "";
        let exitCode: number | null = null;

        ch.on("data", (d: Buffer) => {
          stdout += d.toString("utf8");
        });
        ch.stderr.on("data", (d: Buffer) => {
          stderr += d.toString("utf8");
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
              stdout,
              stderr,
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
  async upload(
    server: ServerConfig,
    localPath: string,
    remotePath: string,
    opts: ExecOptions,
  ): Promise<TransferResult> {
    const started = Date.now();
    const bytes = statSync(expandHome(localPath)).size;
    const conn = await this.connection(server);
    this.touch(server.name);

    const dir = posixDirname(remotePath);
    if (dir && dir !== "/" && dir !== ".") {
      await this.exec(server, `mkdir -p ${shellQuote(dir)}`, opts);
    }

    const sftp = await new Promise<SFTPWrapper>((resolve, reject) => {
      conn.sftp((err, s) => (err ? reject(err) : resolve(s)));
    });
    try {
      await new Promise<void>((resolve, reject) => {
        sftp.fastPut(expandHome(localPath), remotePath, (err) =>
          err ? reject(err) : resolve(),
        );
      });
    } finally {
      sftp.end();
    }
    return { host: server.name, ok: true, bytes, durationMs: Date.now() - started };
  }

  /** SFTP download: fastGet remotePath to localPath (parent dir must exist locally). */
  async download(
    server: ServerConfig,
    remotePath: string,
    localPath: string,
    _opts: ExecOptions,
  ): Promise<TransferResult> {
    const started = Date.now();
    const conn = await this.connection(server);
    this.touch(server.name);

    const sftp = await new Promise<SFTPWrapper>((resolve, reject) => {
      conn.sftp((err, s) => (err ? reject(err) : resolve(s)));
    });
    try {
      await new Promise<void>((resolve, reject) => {
        sftp.fastGet(remotePath, expandHome(localPath), (err) =>
          err ? reject(err) : resolve(),
        );
      });
    } finally {
      sftp.end();
    }
    const bytes = statSync(expandHome(localPath)).size;
    return { host: server.name, ok: true, bytes, durationMs: Date.now() - started };
  }

  async close(): Promise<void> {
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
    const config = this.connectConfig(server);

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

  private connectConfig(server: ServerConfig): ConnectConfig {
    const base: ConnectConfig = {
      host: server.host,
      port: server.port,
      username: server.user,
      readyTimeout: 20_000,
      hostHash: "sha256",
      hostVerifier: (hashedKey: string) => this.verifyHostKey(server, hashedKey),
    };

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
      case "password": {
        const password = envPassword(server);
        if (!password) {
          throw new Error(
            `No password for "${server.name}": set FLOTILLA_${server.name
              .toUpperCase()
              .replace(/[^A-Z0-9]/g, "_")}_PASSWORD or FLOTILLA_PASSWORD`,
          );
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
