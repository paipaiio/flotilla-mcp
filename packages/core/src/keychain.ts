/**
 * OS keychain credentials — the last rung of the auth cascade, so the config
 * file and shell env can stay completely secret-free.
 *
 * Cascade order (env first on purpose): an explicitly-set
 * FLOTILLA_<NAME>_PASSWORD env var is the operator's deliberate choice and
 * must keep winning; the keychain is the fallback for people who don't want
 * secrets in shell rc files at all.
 *
 * The native module (@napi-rs/keyring) is lazy-loaded and every failure
 * degrades to "no keychain" — a missing prebuilt binary or a headless Linux
 * box without a Secret Service daemon must never break SSH auth.
 */
import type { ServerConfig } from "./types.js";

const SERVICE = "flotilla-mcp";

export interface KeychainBackend {
  get(account: string): Promise<string | undefined>;
  set(account: string, password: string): Promise<void>;
  remove(account: string): Promise<boolean>;
}

/** Keychain account names: "<server>" for the login password, "<server>:sudo". */
export function keychainAccount(serverName: string, sudo: boolean): string {
  return sudo ? `${serverName}:sudo` : serverName;
}

/** Per-server and generic env var names for a secret kind. */
export function secretEnvNames(serverName: string, kind: "password" | "sudo"): [string, string] {
  const slug = serverName.toUpperCase().replace(/[^A-Z0-9]/g, "_");
  return kind === "sudo"
    ? [`FLOTILLA_${slug}_SUDO_PASSWORD`, "FLOTILLA_SUDO_PASSWORD"]
    : [`FLOTILLA_${slug}_PASSWORD`, "FLOTILLA_PASSWORD"];
}

/**
 * Resolve a secret: env var first (explicit operator choice), then the OS
 * keychain. Returns undefined when neither has it.
 */
export async function resolveServerSecret(
  server: Pick<ServerConfig, "name">,
  kind: "password" | "sudo",
  env: NodeJS.ProcessEnv,
  backend: KeychainBackend | null,
): Promise<string | undefined> {
  const [perHost, generic] = secretEnvNames(server.name, kind);
  const fromEnv = env[perHost] ?? env[generic];
  if (fromEnv) return fromEnv;
  if (!backend) return undefined;
  try {
    return await backend.get(keychainAccount(server.name, kind === "sudo"));
  } catch {
    return undefined;
  }
}

export type CredentialKind = "password" | "sudo";
export type CredentialRepair = (
  server: Pick<ServerConfig, "name">,
  kind: CredentialKind,
) => Promise<boolean>;

/**
 * Resolve once, optionally repair out-of-band, then resolve again. Keeping the
 * repair callback separate means the secret itself never crosses the MCP tool
 * result or error channel, while the original SSH operation remains pending.
 */
export async function resolveServerSecretWithRepair(
  server: Pick<ServerConfig, "name">,
  kind: CredentialKind,
  resolveSecret: () => Promise<string | undefined>,
  repair?: CredentialRepair,
): Promise<string | undefined> {
  const current = await resolveSecret();
  if (current || !repair) return current;
  if (!(await repair(server, kind))) return undefined;
  return resolveSecret();
}

// ── default backend: @napi-rs/keyring, lazily ──

let cachedBackend: KeychainBackend | null | undefined;

/** The OS keychain, or null when unavailable. Resolved once per process. */
export async function defaultKeychainBackend(): Promise<KeychainBackend | null> {
  if (cachedBackend !== undefined) return cachedBackend;
  try {
    const { Entry } = await import("@napi-rs/keyring");
    cachedBackend = {
      async get(account) {
        try {
          return new Entry(SERVICE, account).getPassword() ?? undefined;
        } catch {
          return undefined; // not found
        }
      },
      async set(account, password) {
        new Entry(SERVICE, account).setPassword(password);
      },
      async remove(account) {
        try {
          return new Entry(SERVICE, account).deletePassword();
        } catch {
          return false;
        }
      },
    };
  } catch {
    cachedBackend = null;
  }
  return cachedBackend;
}

/** Test hook: reset the cached backend. */
export function _resetKeychainCache(): void {
  cachedBackend = undefined;
}
