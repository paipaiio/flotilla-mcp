/**
 * Fleet configuration: TOML loading, schema validation, cross-reference checks.
 *
 * Unknown keys are a startup error, not a warning (borrowed from ssh-mcp):
 * a typo must not silently leave you running defaults you thought you overrode.
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { z } from "zod";
import type { FleetConfig, ServerConfig } from "./types.js";

const scopesSchema = z
  .object({
    paths: z.array(z.string()).optional(),
    services: z.array(z.string()).optional(),
    commands: z.array(z.string()).optional(),
  })
  .strict();

const serverSchema = z
  .object({
    name: z.string().min(1),
    host: z.string().min(1),
    port: z.number().int().min(1).max(65535).default(22),
    user: z.string().min(1),
    auth: z.enum(["agent", "key", "password"]).default("agent"),
    keyRef: z.string().optional(),
    group: z.string().optional(),
    tags: z.array(z.string()).default([]),
    role: z.enum(["viewer", "operator", "admin"]).default("operator"),
    readOnly: z.boolean().default(false),
    workdir: z.string().optional(),
    via: z.string().optional(),
    trustedHostKey: z.string().optional(),
    scopes: scopesSchema.optional(),
  })
  .strict();

const groupSchema = z
  .object({
    name: z.string().min(1),
    match: z
      .object({
        group: z.string().optional(),
        tags: z.array(z.string()).optional(),
        names: z.array(z.string()).optional(),
      })
      .strict(),
  })
  .strict();

const defaultsSchema = z
  .object({
    approvalMode: z
      .enum(["auto", "ask-destructive", "ask-all", "deny"])
      .default("ask-destructive"),
    commandTimeoutMs: z.number().int().positive().default(60_000),
    maxConcurrency: z.number().int().positive().default(16),
    rollingBatchSize: z.number().int().positive().default(2),
    rollingMaxBatchFailures: z.number().int().min(0).default(0),
    /**
     * Honor the confirm=true tool parameter as an approval channel.
     * Default false (fail closed): the flag is filled in by the AI model
     * itself, so honoring it by default would be self-approval.
     */
    allowConfirmFlag: z.boolean().default(false),
  })
  .strict();

const fleetSchema = z
  .object({
    defaults: defaultsSchema.default({}),
    servers: z.array(serverSchema).min(1),
    groups: z.array(groupSchema).default([]),
    audit: z
      .object({
        path: z.string().optional(),
        hashChain: z.boolean().default(true),
        entropyScan: z.boolean().default(false),
      })
      .strict()
      .optional(),
  })
  .strict();

const TIER_HINTS = ["prod", "staging", "dev", "local", "test", "sandbox"];

/** Infer the policy tier from a server name; unrecognized names land on "prod". */
export function inferTier(name: string): string {
  const lower = name.toLowerCase();
  for (const hint of TIER_HINTS) {
    if (lower.includes(hint)) return hint;
  }
  return "prod";
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

function formatIssues(err: z.ZodError): string {
  return err.issues
    .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
    .join("\n");
}

/**
 * Parse and validate fleet config from a TOML string.
 * Throws ConfigError with a readable message on any violation.
 */
export function parseFleetConfig(tomlText: string): FleetConfig {
  let raw: unknown;
  try {
    raw = parseToml(tomlText);
  } catch (err) {
    throw new ConfigError(
      `Invalid TOML: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const parsed = fleetSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigError(`Invalid fleet config:\n${formatIssues(parsed.error)}`);
  }
  const data = parsed.data;

  // Cross-reference checks.
  const names = new Set<string>();
  for (const s of data.servers) {
    if (names.has(s.name)) {
      throw new ConfigError(`Duplicate server name: "${s.name}"`);
    }
    names.add(s.name);
  }

  for (const s of data.servers) {
    if (s.via !== undefined && !names.has(s.via)) {
      throw new ConfigError(
        `Server "${s.name}" has via="${s.via}" but no server named "${s.via}" exists`,
      );
    }
    if (s.via === s.name) {
      throw new ConfigError(`Server "${s.name}" cannot use itself as a jump host`);
    }
    if (s.auth === "key" && !s.keyRef) {
      throw new ConfigError(
        `Server "${s.name}" uses auth="key" but has no keyRef`,
      );
    }
  }

  // Bastion chains must not cycle.
  const byName = new Map(data.servers.map((s) => [s.name, s]));
  for (const s of data.servers) {
    const seen = new Set<string>([s.name]);
    let cur = s.via;
    while (cur !== undefined) {
      if (seen.has(cur)) {
        throw new ConfigError(
          `Jump-host chain starting at "${s.name}" cycles through "${cur}"`,
        );
      }
      seen.add(cur);
      cur = byName.get(cur)?.via;
    }
  }

  const groupNames = new Set<string>();
  for (const g of data.groups) {
    if (groupNames.has(g.name)) {
      throw new ConfigError(`Duplicate group name: "${g.name}"`);
    }
    groupNames.add(g.name);
    if (!g.match.group && !g.match.tags?.length && !g.match.names?.length) {
      throw new ConfigError(
        `Group "${g.name}" has an empty match: set group, tags, or names`,
      );
    }
    for (const n of g.match.names ?? []) {
      if (!names.has(n)) {
        throw new ConfigError(
          `Group "${g.name}" references unknown server "${n}"`,
        );
      }
    }
  }

  // Validate scope command regexes up front: an invalid pattern fails at
  // startup rather than degrading silently at decision time.
  for (const s of data.servers) {
    for (const pattern of s.scopes?.commands ?? []) {
      try {
        new RegExp(pattern);
      } catch {
        throw new ConfigError(
          `Server "${s.name}" has an invalid scopes.commands pattern: ${pattern}`,
        );
      }
    }
  }

  const servers: ServerConfig[] = data.servers.map((s) => ({
    ...s,
    group: s.group ?? inferTier(s.name),
  }));

  return { defaults: data.defaults, servers, groups: data.groups, audit: data.audit };
}

/** Default platform config path (XDG on Linux, Application Support on macOS). */
export function defaultConfigPath(): string {
  if (process.platform === "darwin") {
    return join(homedir(), "Library", "Application Support", "flotilla", "config.toml");
  }
  if (process.platform === "win32") {
    return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "flotilla", "config.toml");
  }
  return join(
    process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"),
    "flotilla",
    "config.toml",
  );
}

/** Load fleet config from disk. Throws ConfigError when the file is missing or invalid. */
export function loadFleetConfig(path?: string): FleetConfig {
  const resolved = path ?? process.env.FLOTILLA_CONFIG ?? defaultConfigPath();
  let text: string;
  try {
    text = readFileSync(resolved, "utf8");
  } catch {
    throw new ConfigError(
      `No fleet config at ${resolved}. Create it, or pass --config <path>, or set FLOTILLA_CONFIG.`,
    );
  }
  return parseFleetConfig(text);
}
