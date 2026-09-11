/**
 * SSH transport built on ssh2, with:
 * - connection pooling keyed by server name
 * - auth cascade: SSH agent -> key file -> env password (never CLI args)
 * - TOFU host-key verification within the process lifetime; trustedHostKey pins
 *   are the only control that survives restarts
 * - ProxyJump via forwardOut through a bastion server (no agent forwarding)
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Client } from "ssh2";
function expandHome(p) {
    if (p === "~")
        return homedir();
    if (p.startsWith("~/"))
        return join(homedir(), p.slice(2));
    return p;
}
function envPassword(server) {
    const perHost = `FLOTILLA_${server.name.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_PASSWORD`;
    return process.env[perHost] ?? process.env.FLOTILLA_PASSWORD;
}
export class SshTransport {
    serversByName;
    pool = new Map();
    connecting = new Map();
    /** TOFU store: process-lifetime only, nothing written to disk. */
    knownHostKeys = new Map();
    constructor(serversByName) {
        this.serversByName = serversByName;
    }
    async exec(server, command, opts) {
        const conn = await this.connection(server);
        const fullCommand = opts.workdir
            ? `cd ${shellQuote(opts.workdir)} && ${command}`
            : command;
        const timeoutMs = opts.timeoutMs ?? 60_000;
        const started = Date.now();
        return new Promise((resolve, reject) => {
            let settled = false;
            let timer;
            let channel;
            const finish = (fn) => {
                if (settled)
                    return;
                settled = true;
                if (timer)
                    clearTimeout(timer);
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
                let stdout = "";
                let stderr = "";
                let exitCode = null;
                ch.on("data", (d) => {
                    stdout += d.toString("utf8");
                });
                ch.stderr.on("data", (d) => {
                    stderr += d.toString("utf8");
                });
                ch.on("exit", (code) => {
                    exitCode = code;
                });
                ch.on("close", () => {
                    finish(() => resolve({
                        host: server.name,
                        ok: exitCode === 0,
                        exitCode,
                        stdout,
                        stderr,
                        durationMs: Date.now() - started,
                    }));
                });
                ch.on("error", (e) => {
                    finish(() => reject(e));
                });
                timer = setTimeout(() => {
                    try {
                        channel?.close();
                    }
                    catch {
                        /* channel already gone */
                    }
                    finish(() => reject(new Error(`Command timed out after ${timeoutMs}ms on ${server.name}`)));
                }, timeoutMs);
            });
        });
    }
    async close() {
        for (const [name, conn] of this.pool) {
            try {
                conn.end();
            }
            catch {
                /* ignore */
            }
            this.pool.delete(name);
        }
    }
    drop(name) {
        const conn = this.pool.get(name);
        if (conn) {
            try {
                conn.end();
            }
            catch {
                /* ignore */
            }
            this.pool.delete(name);
        }
    }
    connection(server) {
        const pooled = this.pool.get(server.name);
        if (pooled)
            return Promise.resolve(pooled);
        // Deduplicate concurrent connect attempts for the same server.
        const pending = this.connecting.get(server.name);
        if (pending)
            return pending;
        const attempt = this.connect(server)
            .then((conn) => {
            this.pool.set(server.name, conn);
            conn.on("close", () => this.pool.delete(server.name));
            conn.on("error", () => this.pool.delete(server.name));
            return conn;
        })
            .finally(() => this.connecting.delete(server.name));
        this.connecting.set(server.name, attempt);
        return attempt;
    }
    async connect(server) {
        const config = this.connectConfig(server);
        if (!server.via)
            return openConnection(config);
        const bastionConfig = this.serversByName.get(server.via);
        if (!bastionConfig) {
            throw new Error(`Jump host "${server.via}" not found for server "${server.name}"`);
        }
        const bastion = await this.connection(bastionConfig);
        const stream = await new Promise((resolve, reject) => {
            bastion.forwardOut("127.0.0.1", 0, server.host, server.port, (err, ch) => (err ? reject(err) : resolve(ch)));
        });
        return openConnection({ ...config, sock: stream });
    }
    connectConfig(server) {
        const base = {
            host: server.host,
            port: server.port,
            username: server.user,
            readyTimeout: 20_000,
            hostHash: "sha256",
            hostVerifier: (hashedKey) => this.verifyHostKey(server, hashedKey),
        };
        switch (server.auth) {
            case "agent":
                if (process.env.SSH_AUTH_SOCK) {
                    base.agent = process.env.SSH_AUTH_SOCK;
                    break;
                }
                throw new Error(`Server "${server.name}" uses auth="agent" but SSH_AUTH_SOCK is not set`);
            case "key":
                base.privateKey = readFileSync(expandHome(server.keyRef), "utf8");
                break;
            case "password": {
                const password = envPassword(server);
                if (!password) {
                    throw new Error(`No password for "${server.name}": set FLOTILLA_${server.name
                        .toUpperCase()
                        .replace(/[^A-Z0-9]/g, "_")}_PASSWORD or FLOTILLA_PASSWORD`);
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
    verifyHostKey(server, hashedKey) {
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
function openConnection(config) {
    return new Promise((resolve, reject) => {
        const conn = new Client();
        conn.once("ready", () => resolve(conn));
        conn.once("error", reject);
        conn.connect(config);
    });
}
function shellQuote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
