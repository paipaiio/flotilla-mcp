/** Batch setup/repair primitives: dedicated key creation and precise config edits. */
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { parseFleetConfig } from "./config.js";
import { buildKeyInstallCommand } from "./onboard.js";

export class SetupRepairError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SetupRepairError";
  }
}

export interface PasswordServerMigration {
  server: string;
  keyRef: string;
  trustedHostKey?: string;
}

function tomlString(value: string): string {
  return JSON.stringify(value);
}

function upsertBlockField(block: string, field: string, value: string): string {
  const pattern = new RegExp(`^([ \\t]*)${field}[ \\t]*=.*$`, "m");
  if (pattern.test(block)) return block.replace(pattern, `$1${field} = ${value}`);
  const firstLineEnd = block.indexOf("\n") + 1;
  const nestedTable = /^[ \t]*\[(?!\[)/gm;
  nestedTable.lastIndex = firstLineEnd;
  const nested = nestedTable.exec(block);
  if (nested) {
    const before = block.slice(0, nested.index);
    return before + (before.endsWith("\n") ? "" : "\n") + `${field} = ${value}\n` + block.slice(nested.index);
  }
  return block.replace(/\s*$/, "") + `\n${field} = ${value}\n`;
}

/**
 * Change only selected [[servers]] blocks from password to key auth, then
 * parse the entire result before returning it. Comments, ordering, groups,
 * policy fields, and unrelated server blocks remain byte-for-byte intact.
 */
export function migratePasswordServersInConfig(
  tomlText: string,
  migrations: PasswordServerMigration[],
): string {
  if (migrations.length === 0) return tomlText;
  const config = parseFleetConfig(tomlText);
  const requested = new Map<string, PasswordServerMigration>();
  for (const migration of migrations) {
    if (requested.has(migration.server)) {
      throw new SetupRepairError(`Duplicate migration for server "${migration.server}"`);
    }
    requested.set(migration.server, migration);
  }
  for (const migration of migrations) {
    const server = config.servers.find((candidate) => candidate.name === migration.server);
    if (!server) throw new SetupRepairError(`Server "${migration.server}" not found in config`);
    if (server.auth !== "password") {
      throw new SetupRepairError(
        `Server "${migration.server}" is not configured for password authentication`,
      );
    }
  }

  const headers = [...tomlText.matchAll(/^[ \t]*\[\[servers\]\][ \t]*(?:#.*)?$/gm)];
  if (headers.length !== config.servers.length) {
    throw new SetupRepairError("Could not map parsed servers back to their TOML blocks");
  }
  let next = tomlText;
  for (let index = headers.length - 1; index >= 0; index--) {
    const server = config.servers[index];
    const migration = requested.get(server.name);
    if (!migration) continue;
    const start = headers[index].index!;
    const end = index + 1 < headers.length ? headers[index + 1].index! : tomlText.length;
    let block = tomlText.slice(start, end);
    block = upsertBlockField(block, "auth", tomlString("key"));
    block = upsertBlockField(block, "keyRef", tomlString(migration.keyRef));
    if (migration.trustedHostKey) {
      block = upsertBlockField(block, "trustedHostKey", tomlString(migration.trustedHostKey));
    }
    next = next.slice(0, start) + block + next.slice(end);
  }
  parseFleetConfig(next);
  return next;
}

export interface KeyPairIO {
  exists(path: string): boolean;
  mkdir(path: string): void;
  chmod(path: string, mode: number): void;
  run(command: string, args: string[]): string;
}

const defaultKeyPairIO: KeyPairIO = {
  exists: existsSync,
  mkdir: (path) => mkdirSync(path, { recursive: true, mode: 0o700 }),
  chmod: chmodSync,
  run: (command, args) => execFileSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 15_000,
  }),
};

export interface FleetKeyPair {
  privateKeyPath: string;
  publicKey: string;
  created: boolean;
}

function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return path;
}

/** Create a dedicated Ed25519 key when absent, or reuse the requested key. */
export function ensureFleetKeyPair(path: string, io: KeyPairIO = defaultKeyPairIO): FleetKeyPair {
  const privateKeyPath = expandHome(path);
  let created = false;
  try {
    if (!io.exists(privateKeyPath)) {
      io.mkdir(dirname(privateKeyPath));
      io.run("ssh-keygen", [
        "-t", "ed25519", "-N", "", "-C", "flotilla-fleet", "-f", privateKeyPath,
      ]);
      if (!io.exists(privateKeyPath)) throw new Error("ssh-keygen did not create the private key");
      io.chmod(privateKeyPath, 0o600);
      created = true;
    }
    const publicKey = io.run("ssh-keygen", ["-y", "-f", privateKeyPath]).trim();
    buildKeyInstallCommand(publicKey); // strict OpenSSH public-key validation
    return { privateKeyPath, publicKey, created };
  } catch (error) {
    throw new SetupRepairError(
      `SSH key setup failed for ${privateKeyPath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
