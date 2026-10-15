/**
 * In-place edits of one [[servers]] block in the fleet TOML.
 *
 * Edits are line-based on purpose: re-serializing the whole document would
 * drop every comment the operator wrote. Each edit is validated by parsing
 * the result, and set-edits are additionally checked to have produced the
 * requested values, so a surprising layout fails loudly instead of writing
 * something else.
 */
import { parse as parseToml } from "smol-toml";
import { ConfigError, parseFleetConfig } from "./config.js";
import { OnboardError } from "./onboard.js";
import type { ServerConfig } from "./types.js";

export type ServerPatch = Partial<Pick<ServerConfig, "role" | "group" | "tags" | "readOnly" | "user" | "port" | "workdir">>;

const SERVERS_HEADER = /^\s*\[\[\s*servers\s*\]\]\s*(#.*)?$/;
const ANY_HEADER = /^\s*\[/;
const SERVERS_SUBTABLE = /^\s*\[{1,2}\s*servers\./;

interface Block {
  /** Index of the [[servers]] header line. */
  start: number;
  /** End of the block's own keys (first sub-table header or block end). */
  keysEnd: number;
  /** Exclusive end including [servers.*] sub-tables. */
  end: number;
}

function keyValue(line: string): { key: string; value: unknown } | undefined {
  const m = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line);
  if (!m) return undefined;
  try {
    return { key: m[1]!, value: (parseToml(line) as Record<string, unknown>)[m[1]!] };
  } catch {
    return { key: m[1]!, value: undefined }; // multi-line value: key is still known
  }
}

function findBlock(lines: string[], name: string): Block {
  for (let i = 0; i < lines.length; i++) {
    if (!SERVERS_HEADER.test(lines[i]!)) continue;
    let keysEnd = lines.length;
    let end = lines.length;
    for (let j = i + 1; j < lines.length; j++) {
      if (!ANY_HEADER.test(lines[j]!)) continue;
      if (SERVERS_SUBTABLE.test(lines[j]!)) {
        keysEnd = Math.min(keysEnd, j);
        continue;
      }
      end = j;
      keysEnd = Math.min(keysEnd, j);
      break;
    }
    for (let j = i + 1; j < keysEnd; j++) {
      const kv = keyValue(lines[j]!);
      if (kv?.key === "name" && kv.value === name) return { start: i, keysEnd, end };
    }
  }
  throw new OnboardError(
    `Server "${name}" has no [[servers]] block in the config (inline-table configs must be edited by hand)`,
  );
}

function assertKnown(text: string, name: string): ServerConfig[] {
  const servers = parseFleetConfig(text).servers;
  if (!servers.some((s) => s.name === name)) throw new OnboardError(`No server named "${name}" in the config`);
  return servers;
}

function revalidate(next: string): void {
  try {
    parseFleetConfig(next);
  } catch (err) {
    throw new OnboardError(`Edit would produce an invalid config: ${err instanceof ConfigError ? err.message : String(err)}`);
  }
}

/** Remove a server (and its [servers.*] sub-tables). Refuses if others depend on it. */
export function removeServerFromConfig(text: string, name: string): string {
  const servers = assertKnown(text, name);
  const dependents = servers.filter((s) => s.via === name).map((s) => s.name);
  if (dependents.length > 0) {
    throw new OnboardError(`"${name}" is the jump host (via) for ${dependents.join(", ")} — remove or re-route those first`);
  }
  const lines = text.split("\n");
  const block = findBlock(lines, name);
  // Drop the block plus the blank lines right before it; leave every other
  // byte of the file alone (multi-line strings elsewhere must not change).
  let start = block.start;
  while (start > 0 && lines[start - 1]!.trim() === "") start--;
  const keepBlankBefore = start > 0 && block.end < lines.length ? [""] : [];
  const next = [...lines.slice(0, start), ...keepBlankBefore, ...lines.slice(block.end)].join("\n");
  revalidate(next);
  return next;
}

function tomlValue(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((v) => JSON.stringify(v)).join(", ")}]`;
  if (typeof value === "string") return JSON.stringify(value);
  return String(value);
}

/** Extent of a key's value lines: multi-line arrays run until brackets balance. */
function valueExtent(lines: string[], at: number, limit: number): number {
  let depth = 0;
  for (let j = at; j < limit; j++) {
    const code = lines[j]!.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, "").replace(/#.*/, "");
    for (const ch of code) {
      if (ch === "[") depth++;
      else if (ch === "]") depth--;
    }
    if (depth <= 0) return j + 1;
  }
  return at + 1;
}

/** Set fields on one server, preserving everything else in the file. */
export function setServerFields(text: string, name: string, patch: ServerPatch): string {
  assertKnown(text, name);
  let lines = text.split("\n");
  for (const [field, value] of Object.entries(patch)) {
    if (value === undefined) continue;
    const block = findBlock(lines, name);
    // `group` and `tier` are one setting; edit whichever spelling is present
    // (new entries use `tier`, the documented name).
    let key = field;
    if (field === "group") {
      key = "tier";
      for (let j = block.start + 1; j < block.keysEnd; j++) {
        if (keyValue(lines[j]!)?.key === "group") key = "group";
      }
    }
    const rendered = `${key} = ${tomlValue(value)}`;
    let replaced = false;
    for (let j = block.start + 1; j < block.keysEnd; j++) {
      if (keyValue(lines[j]!)?.key !== key) continue;
      const extent = valueExtent(lines, j, block.keysEnd);
      lines = [...lines.slice(0, j), rendered, ...lines.slice(extent)];
      replaced = true;
      break;
    }
    if (!replaced) {
      let insertAt = block.keysEnd;
      while (insertAt > block.start + 1 && lines[insertAt - 1]!.trim() === "") insertAt--;
      lines = [...lines.slice(0, insertAt), rendered, ...lines.slice(insertAt)];
    }
  }
  const next = lines.join("\n");
  revalidate(next);
  const updated = parseFleetConfig(next).servers.find((s) => s.name === name)!;
  for (const [field, value] of Object.entries(patch)) {
    if (value === undefined) continue;
    if (JSON.stringify(updated[field as keyof ServerConfig]) !== JSON.stringify(value)) {
      throw new OnboardError(`Could not set ${field} on "${name}" safely — edit the config by hand`);
    }
  }
  return next;
}
