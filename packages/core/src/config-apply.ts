import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

export type StructuredConfigFormat = "json" | "yaml" | "toml";

export type ConfigChange =
  | { op: "set"; path: string; value?: unknown; valueFromEnv?: string }
  | { op: "delete"; path: string };

export interface AppliedConfigChange {
  op: "set" | "delete";
  path: string;
  source?: "literal" | "environment";
}

export interface StructuredChangeResult {
  text: string;
  changes: AppliedConfigChange[];
}

export class ConfigApplyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigApplyError";
  }
}

const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function parseDocument(text: string, format: StructuredConfigFormat): unknown {
  try {
    if (format === "json") return JSON.parse(text);
    if (format === "yaml") return parseYaml(text);
    return parseToml(text);
  } catch {
    throw new ConfigApplyError(`Existing ${format.toUpperCase()} config is invalid`);
  }
}

function serializeDocument(value: unknown, format: StructuredConfigFormat): string {
  try {
    if (format === "json") return JSON.stringify(value, null, 2) + "\n";
    if (format === "yaml") return stringifyYaml(value);
    return stringifyToml(value as Record<string, unknown>);
  } catch {
    throw new ConfigApplyError(`Changed config cannot be serialized as ${format.toUpperCase()}`);
  }
}

function pointerSegments(pointer: string): string[] {
  if (!pointer.startsWith("/") || pointer === "/") {
    throw new ConfigApplyError(`Change path "${pointer}" must be a non-root JSON Pointer such as /server/port`);
  }
  const segments = pointer.slice(1).split("/").map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
  for (const segment of segments) {
    if (!segment || FORBIDDEN_KEYS.has(segment)) {
      throw new ConfigApplyError(`Change path "${pointer}" contains a forbidden or empty segment`);
    }
  }
  return segments;
}

function isContainer(value: unknown): value is Record<string, unknown> | unknown[] {
  return typeof value === "object" && value !== null;
}

function arrayIndex(segment: string, length: number, allowAppend: boolean): number {
  if (allowAppend && segment === "-") return length;
  if (!/^(0|[1-9]\d*)$/.test(segment)) throw new ConfigApplyError(`Array segment "${segment}" is not an index`);
  const index = Number(segment);
  if (!Number.isSafeInteger(index) || index < 0 || index > (allowAppend ? length : length - 1)) {
    throw new ConfigApplyError(`Array index "${segment}" is out of range`);
  }
  return index;
}

function parentFor(root: unknown, segments: string[], create: boolean): { parent: Record<string, unknown> | unknown[]; key: string } {
  if (!isContainer(root)) throw new ConfigApplyError("Structured config root must be an object or array");
  let cursor: Record<string, unknown> | unknown[] = root;
  for (let index = 0; index < segments.length - 1; index++) {
    const segment = segments[index]!;
    const nextSegment = segments[index + 1]!;
    let child: unknown;
    if (Array.isArray(cursor)) {
      const position = arrayIndex(segment, cursor.length, false);
      child = cursor[position];
      if (!isContainer(child) && create && child === undefined) {
        child = /^(0|[1-9]\d*|-)$/.test(nextSegment) ? [] : Object.create(null);
        cursor[position] = child;
      }
    } else {
      child = cursor[segment];
      if (!isContainer(child) && create && child === undefined) {
        child = /^(0|[1-9]\d*|-)$/.test(nextSegment) ? [] : Object.create(null);
        cursor[segment] = child;
      }
    }
    if (!isContainer(child)) {
      throw new ConfigApplyError(`Change path parent "/${segments.slice(0, index + 1).join("/")}" is not a container`);
    }
    cursor = child;
  }
  return { parent: cursor, key: segments.at(-1)! };
}

function resolveSetValue(
  change: Extract<ConfigChange, { op: "set" }>,
  env: Readonly<Record<string, string | undefined>>,
): { value: unknown; source: "literal" | "environment" } {
  const hasLiteral = Object.prototype.hasOwnProperty.call(change, "value");
  const hasEnvironment = typeof change.valueFromEnv === "string";
  if (hasLiteral === hasEnvironment) {
    throw new ConfigApplyError(`Set change at "${change.path}" requires exactly one of value or valueFromEnv`);
  }
  if (hasEnvironment) {
    const name = change.valueFromEnv!;
    if (!/^[A-Z_][A-Z0-9_]*$/i.test(name)) throw new ConfigApplyError(`Invalid environment variable name "${name}"`);
    const value = env[name];
    if (value === undefined) throw new ConfigApplyError(`Environment variable "${name}" is not set`);
    return { value, source: "environment" };
  }
  return { value: change.value, source: "literal" };
}

/** Apply JSON-Pointer changes without evaluating shell text or exposing environment values in the report. */
export function applyStructuredChanges(
  source: string,
  format: StructuredConfigFormat,
  changes: ConfigChange[],
  env: Readonly<Record<string, string | undefined>> = process.env,
): StructuredChangeResult {
  if (changes.length === 0) throw new ConfigApplyError("At least one structured change is required");
  const root = parseDocument(source, format);
  const report: AppliedConfigChange[] = [];
  for (const change of changes) {
    const segments = pointerSegments(change.path);
    const { parent, key } = parentFor(root, segments, change.op === "set");
    if (change.op === "set") {
      const resolved = resolveSetValue(change, env);
      if (Array.isArray(parent)) {
        const index = arrayIndex(key, parent.length, true);
        if (index === parent.length) parent.push(resolved.value);
        else parent[index] = resolved.value;
      } else {
        parent[key] = resolved.value;
      }
      report.push({ op: "set", path: change.path, source: resolved.source });
    } else {
      if (Array.isArray(parent)) {
        parent.splice(arrayIndex(key, parent.length, false), 1);
      } else {
        if (!Object.prototype.hasOwnProperty.call(parent, key)) {
          throw new ConfigApplyError(`Change path "${change.path}" does not exist`);
        }
        delete parent[key];
      }
      report.push({ op: "delete", path: change.path });
    }
  }
  const text = serializeDocument(root, format);
  parseDocument(text, format);
  return { text, changes: report };
}

export type ConfigTransactionStage = "backup" | "stage" | "validate" | "install" | "restart" | "health";

export interface ConfigTransactionAdapter {
  backup(): Promise<void>;
  stage(): Promise<void>;
  validate(): Promise<void>;
  install(): Promise<void>;
  restart(): Promise<void>;
  health(): Promise<void>;
  rollback(): Promise<void>;
  cleanup(): Promise<void>;
}

export interface ConfigTransactionResult {
  ok: boolean;
  installed: boolean;
  rolledBack: boolean;
  rollbackVerified: boolean;
  completedStages: ConfigTransactionStage[];
  failedStage?: ConfigTransactionStage;
  error?: string;
  rollbackError?: string;
  cleanupError?: string;
}

/** Strict transaction order with compensating restore after any post-install failure. */
export async function runConfigTransaction(adapter: ConfigTransactionAdapter): Promise<ConfigTransactionResult> {
  const completedStages: ConfigTransactionStage[] = [];
  let installed = false;
  let failedStage: ConfigTransactionStage | undefined;
  let error: string | undefined;
  let rolledBack = false;
  let rollbackVerified = false;
  let rollbackError: string | undefined;
  let cleanupError: string | undefined;

  const stages: Array<[ConfigTransactionStage, () => Promise<void>]> = [
    ["backup", adapter.backup],
    ["stage", adapter.stage],
    ["validate", adapter.validate],
    ["install", adapter.install],
    ["restart", adapter.restart],
    ["health", adapter.health],
  ];
  try {
    for (const [name, action] of stages) {
      try {
        await action();
        completedStages.push(name);
        if (name === "install") installed = true;
      } catch (caught) {
        failedStage = name;
        error = caught instanceof Error ? caught.message : String(caught);
        break;
      }
    }

    if (failedStage && installed) {
      try {
        await adapter.rollback();
        rolledBack = true;
        await adapter.restart();
        await adapter.health();
        rollbackVerified = true;
      } catch (caught) {
        rollbackError = caught instanceof Error ? caught.message : String(caught);
      }
    }
  } finally {
    try {
      await adapter.cleanup();
    } catch (caught) {
      cleanupError = caught instanceof Error ? caught.message : String(caught);
    }
  }
  return {
    ok: failedStage === undefined && cleanupError === undefined,
    installed,
    rolledBack,
    rollbackVerified,
    completedStages,
    failedStage,
    error,
    rollbackError,
    cleanupError,
  };
}
