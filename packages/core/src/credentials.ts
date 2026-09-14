/**
 * Secret-free credential diagnostics.
 *
 * These helpers report whether a server has usable credential material and
 * where it will come from, but never return the credential itself. They are
 * shared by the CLI, MCP diagnostics, and SSH error messages so operators get
 * one recovery path that works without restarting the MCP process.
 */
import { accessSync, constants } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  defaultKeychainBackend,
  keychainAccount,
  secretEnvNames,
  type KeychainBackend,
} from "./keychain.js";
import type { ServerConfig } from "./types.js";

export type CredentialSource =
  | "ssh-agent"
  | "key-file"
  | "env-host"
  | "env-shared"
  | "os-keychain"
  | "missing";

export interface CredentialStatus {
  server: string;
  auth: ServerConfig["auth"];
  ready: boolean;
  source: CredentialSource;
  detail: string;
  /** A local command that repairs the missing credential without exposing it. */
  recoveryCommand?: string;
  /** Keychain changes are read on every connection attempt. */
  restartRequired: boolean;
}

export interface CredentialInspectOptions {
  env?: NodeJS.ProcessEnv;
  /** Pass null to explicitly disable keychain lookup (useful for diagnostics/tests). */
  keychain?: KeychainBackend | null;
  keyReadable?: (path: string) => boolean;
}

function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return path;
}

function readable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

function shellArg(value: string): string {
  return /^[A-Za-z0-9._-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Primary recovery text for a missing login password. */
export function credentialRecoveryMessage(serverName: string): string {
  const [perHost, generic] = secretEnvNames(serverName, "password");
  return (
    `CREDENTIAL_REQUIRED: no login password is available for "${serverName}". ` +
    `Run \`flotilla keychain set ${shellArg(serverName)}\` once, then retry without restarting the MCP server. ` +
    `Environment fallback: ${perHost} or ${generic}.`
  );
}

/** Inspect one server without returning or logging any secret value. */
export async function inspectServerCredential(
  server: ServerConfig,
  options: CredentialInspectOptions = {},
): Promise<CredentialStatus> {
  const env = options.env ?? process.env;

  if (server.auth === "agent") {
    return env.SSH_AUTH_SOCK
      ? {
          server: server.name,
          auth: server.auth,
          ready: true,
          source: "ssh-agent",
          detail: "SSH_AUTH_SOCK is available to the running process",
          restartRequired: false,
        }
      : {
          server: server.name,
          auth: server.auth,
          ready: false,
          source: "missing",
          detail: "SSH_AUTH_SOCK is absent from the running process",
          recoveryCommand: `flotilla credentials ${shellArg(server.name)}`,
          restartRequired: true,
        };
  }

  if (server.auth === "key") {
    const path = server.keyRef ? expandHome(server.keyRef) : "";
    const keyReadable = options.keyReadable ?? readable;
    return path && keyReadable(path)
      ? {
          server: server.name,
          auth: server.auth,
          ready: true,
          source: "key-file",
          detail: "configured private key is readable",
          restartRequired: false,
        }
      : {
          server: server.name,
          auth: server.auth,
          ready: false,
          source: "missing",
          detail: path ? "configured private key is missing or unreadable" : "keyRef is missing",
          recoveryCommand: `flotilla credentials ${shellArg(server.name)}`,
          restartRequired: false,
        };
  }

  const [perHost, generic] = secretEnvNames(server.name, "password");
  if (env[perHost]) {
    return {
      server: server.name,
      auth: server.auth,
      ready: true,
      source: "env-host",
      detail: `${perHost} is set`,
      restartRequired: false,
    };
  }
  if (env[generic]) {
    return {
      server: server.name,
      auth: server.auth,
      ready: true,
      source: "env-shared",
      detail: `${generic} is set`,
      restartRequired: false,
    };
  }

  const backend = Object.prototype.hasOwnProperty.call(options, "keychain")
    ? (options.keychain ?? null)
    : await defaultKeychainBackend();
  if (backend) {
    try {
      if ((await backend.get(keychainAccount(server.name, false))) !== undefined) {
        return {
          server: server.name,
          auth: server.auth,
          ready: true,
          source: "os-keychain",
          detail: `OS keychain entry exists for ${keychainAccount(server.name, false)}`,
          restartRequired: false,
        };
      }
    } catch {
      // Report the same repair path as an unavailable backend; never expose its error or secret.
    }
  }

  return {
    server: server.name,
    auth: server.auth,
    ready: false,
    source: "missing",
    detail: credentialRecoveryMessage(server.name),
    recoveryCommand: `flotilla keychain set ${shellArg(server.name)}`,
    restartRequired: false,
  };
}

/** Inspect a resolved fleet while reusing one keychain backend instance. */
export async function inspectFleetCredentials(
  servers: ServerConfig[],
  options: CredentialInspectOptions = {},
): Promise<CredentialStatus[]> {
  const keychain = Object.prototype.hasOwnProperty.call(options, "keychain")
    ? (options.keychain ?? null)
    : await defaultKeychainBackend();
  return Promise.all(
    servers.map((server) => inspectServerCredential(server, { ...options, keychain })),
  );
}
