import type { FleetConfig } from "./types.js";
/** Infer the policy tier from a server name; unrecognized names land on "prod". */
export declare function inferTier(name: string): string;
export declare class ConfigError extends Error {
    constructor(message: string);
}
/**
 * Parse and validate fleet config from a TOML string.
 * Throws ConfigError with a readable message on any violation.
 */
export declare function parseFleetConfig(tomlText: string): FleetConfig;
/** Default platform config path (XDG on Linux, Application Support on macOS). */
export declare function defaultConfigPath(): string;
/** Load fleet config from disk. Throws ConfigError when the file is missing or invalid. */
export declare function loadFleetConfig(path?: string): FleetConfig;
