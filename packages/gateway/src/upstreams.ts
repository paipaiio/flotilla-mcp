/**
 * Upstream MCP aggregation (§v2): mount external MCP servers behind the
 * gateway's single /mcp endpoint.
 *
 * An operator lists upstream servers in a JSON file (--upstreams /
 * FLOTILLA_GATEWAY_UPSTREAMS); each may be a local stdio command or a
 * remote Streamable HTTP endpoint. At boot the gateway connects to every
 * upstream, lists its tools, and re-registers each one on the shared fleet
 * McpServer under a `<upstream>__<tool>` name. Calls are proxied verbatim —
 * the fleet policy engine deliberately does not apply to upstream tools:
 * they are foreign code the operator explicitly trusted by mounting them.
 * The gateway bearer token still gates the whole surface.
 *
 * Failure model: an upstream that fails to connect never blocks boot — it
 * is marked "error" with its reason, its tools are absent from tools/list,
 * and refresh() retries it (e.g. after the process or host comes back).
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { z } from "zod";

/** Hard cap on a proxied tool call — fleet payloads are small. */
const UPSTREAM_CALL_TIMEOUT_MS = 120_000;
const MAX_UPSTREAMS = 16;
const MAX_ARGS = 64;

/** MCP tool names: letters, digits, underscore, dash, ≤ 64 chars. */
const TOOL_NAME_RE = /^[a-zA-Z0-9_-]{1,64}$/;

export interface UpstreamConfig {
  /** Display name; sanitized into the tool-name prefix. */
  name: string;
  transport: "stdio" | "http";
  /** stdio: command + args + optional env (merged over a safe baseline). */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** http: MCP endpoint URL + optional static headers (e.g. bearer). */
  url?: string;
  headers?: Record<string, string>;
}

export interface UpstreamStatus {
  name: string;
  transport: "stdio" | "http";
  state: "connected" | "error";
  /** Prefixed tool names currently mounted from this upstream. */
  tools: string[];
  error?: string;
}

interface UpstreamState {
  config: UpstreamConfig;
  prefix: string;
  client?: Client;
  transport?: StdioClientTransport | StreamableHTTPClientTransport;
  registered: string[];
  error?: string;
}

export interface UpstreamManager {
  /** Connect all upstreams and mount their tools on the shared server. */
  attach: (server: McpServer) => Promise<void>;
  /** Retry upstreams that are not connected (idempotent). */
  refresh: () => Promise<void>;
  statuses: () => UpstreamStatus[];
  summary: () => { total: number; connected: number; tools: number };
  close: () => Promise<void>;
}

/** `My Files!` → `my_files` — safe to embed in MCP tool names. */
export function sanitizePrefix(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9_-]/g, "_").replace(/^_+|_+$/g, "") || "up";
}

function checkStringRecord(value: unknown, what: string): Record<string, string> {
  if (value === undefined) return {};
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${what} must be an object of string values`);
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v !== "string") throw new Error(`${what}.${k} must be a string`);
  }
  return value as Record<string, string>;
}

/** Parse and validate the upstreams JSON file. Throws on any bad entry. */
export function loadUpstreamsConfig(path: string): UpstreamConfig[] {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`upstreams file ${path}: invalid JSON (${err instanceof Error ? err.message : String(err)})`);
  }
  if (!Array.isArray(raw)) throw new Error(`upstreams file ${path}: top level must be an array`);
  if (raw.length > MAX_UPSTREAMS) throw new Error(`upstreams file ${path}: at most ${MAX_UPSTREAMS} upstreams`);

  const seen = new Set<string>();
  const configs: UpstreamConfig[] = [];
  for (const [index, entry] of raw.entries()) {
    const where = `upstreams file ${path}: entry #${index}`;
    if (typeof entry !== "object" || entry === null) throw new Error(`${where} must be an object`);
    const e = entry as Record<string, unknown>;
    if (typeof e.name !== "string" || e.name.trim().length === 0 || e.name.length > 32) {
      throw new Error(`${where}: name must be a non-empty string (≤ 32 chars)`);
    }
    const prefix = sanitizePrefix(e.name);
    if (seen.has(prefix)) throw new Error(`${where}: name "${e.name}" collides with another upstream after sanitizing`);
    seen.add(prefix);

    if (e.transport !== "stdio" && e.transport !== "http") {
      throw new Error(`${where}: transport must be "stdio" or "http"`);
    }
    const config: UpstreamConfig = { name: e.name.trim(), transport: e.transport };
    if (e.transport === "stdio") {
      if (typeof e.command !== "string" || e.command.length === 0) throw new Error(`${where}: stdio upstream needs a command`);
      config.command = e.command;
      if (e.args !== undefined) {
        if (!Array.isArray(e.args) || e.args.length > MAX_ARGS || !e.args.every((a) => typeof a === "string")) {
          throw new Error(`${where}: args must be an array of ≤ ${MAX_ARGS} strings`);
        }
        config.args = e.args;
      }
      config.env = checkStringRecord(e.env, `${where}: env`);
    } else {
      if (typeof e.url !== "string") throw new Error(`${where}: http upstream needs a url`);
      let parsed: URL;
      try {
        parsed = new URL(e.url);
      } catch {
        throw new Error(`${where}: url is not a valid URL`);
      }
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error(`${where}: url must be http(s)`);
      }
      config.url = e.url;
      config.headers = checkStringRecord(e.headers, `${where}: headers`);
    }
    configs.push(config);
  }
  return configs;
}

/** Best-effort peek at the McpServer registry so a mounted tool can never
 * shadow a fleet tool. Private in the SDK — degrade to "allow" if it moves. */
function fleetHasTool(server: McpServer, name: string): boolean {
  const registry = (server as unknown as { _registeredTools?: Map<string, unknown> })._registeredTools;
  return registry instanceof Map && registry.has(name);
}

export function createUpstreamManager(configs: UpstreamConfig[]): UpstreamManager {
  const states: UpstreamState[] = configs.map((config) => ({
    config,
    prefix: sanitizePrefix(config.name),
    registered: [],
  }));
  // All names we mounted, across upstreams — refresh() must not double-mount.
  const mounted = new Set<string>();
  let server: McpServer | undefined;

  async function connectAndRegister(state: UpstreamState): Promise<void> {
    if (!server || state.client) return;
    const { config, prefix } = state;
    state.transport =
      config.transport === "stdio"
        ? new StdioClientTransport({
            command: config.command!,
            args: config.args ?? [],
            env: Object.keys(config.env ?? {}).length > 0 ? (config.env as Record<string, string>) : undefined,
          })
        : new StreamableHTTPClientTransport(new URL(config.url!), {
            requestInit: { headers: config.headers ?? {} },
          });
    const client = new Client({ name: `flotilla-upstream-${prefix}`, version: "0.9.0" });
    await client.connect(state.transport);
    const { tools } = await client.listTools();

    for (const tool of tools) {
      // Fit the 64-char tool-name cap without truncating the prefix; a
      // truncated tail colliding with an existing name is a config error.
      const local = tool.name.slice(0, 64 - prefix.length - 2);
      const prefixed = `${prefix}__${local}`;
      if (!TOOL_NAME_RE.test(prefixed) || mounted.has(prefixed) || fleetHasTool(server, prefixed)) {
        await client.close().catch(() => undefined);
        throw new Error(`tool name "${prefixed}" is invalid or already in use`);
      }
      mounted.add(prefixed);
      const upstreamName = tool.name;
      const upstreamClient = client;
      server.registerTool(
        prefixed,
        {
          description: `[${config.name}] ${tool.description ?? "(no description)"}`,
          // The SDK only advertises zod-shaped schemas; a passthrough object
          // keeps proxied arguments verbatim instead of validating them away.
          inputSchema: z.object({}).passthrough(),
        },
        async (args: Record<string, unknown>) => {
          try {
            const result = await upstreamClient.callTool(
              { name: upstreamName, arguments: args },
              undefined,
              { timeout: UPSTREAM_CALL_TIMEOUT_MS },
            );
            const proxied: CallToolResult = {
              content: (result.content ?? []) as CallToolResult["content"],
            };
            if (result.structuredContent !== undefined && result.structuredContent !== null) {
              proxied.structuredContent = result.structuredContent as Record<string, unknown>;
            }
            if (result.isError) proxied.isError = true;
            return proxied;
          } catch (err) {
            return {
              isError: true as const,
              content: [
                {
                  type: "text" as const,
                  text: `upstream "${config.name}" failed: ${err instanceof Error ? err.message : String(err)}`,
                },
              ],
            };
          }
        },
      );
      state.registered.push(prefixed);
    }
    state.client = client;
    state.error = undefined;
  }

  async function attach(target: McpServer): Promise<void> {
    server = target;
    for (const state of states) {
      try {
        await connectAndRegister(state);
      } catch (err) {
        state.error = err instanceof Error ? err.message : String(err);
        state.transport = undefined;
      }
    }
  }

  async function refresh(): Promise<void> {
    for (const state of states) {
      if (state.client) continue;
      try {
        await connectAndRegister(state);
      } catch (err) {
        state.error = err instanceof Error ? err.message : String(err);
        state.transport = undefined;
      }
    }
  }

  const statuses = (): UpstreamStatus[] =>
    states.map((s) => ({
      name: s.config.name,
      transport: s.config.transport,
      state: s.client ? ("connected" as const) : ("error" as const),
      tools: [...s.registered],
      ...(s.error !== undefined ? { error: s.error } : {}),
    }));

  const summary = () => ({
    total: states.length,
    connected: states.filter((s) => s.client).length,
    tools: states.reduce((n, s) => n + s.registered.length, 0),
  });

  async function close(): Promise<void> {
    for (const state of states) {
      if (state.client) {
        await state.client.close().catch(() => undefined);
        state.client = undefined;
      }
    }
  }

  return { attach, refresh, statuses, summary, close };
}
