/**
 * Flotilla HTTP Gateway — stateless Streamable HTTP MCP front end.
 *
 * The gateway adds a transport, not a second engine: the exact same
 * McpServer (every tool pack, the policy engine, the credential brokers,
 * the audit trail) is shared across requests, each of which gets a fresh
 * stateless StreamableHTTPServerTransport. Nothing session-scoped survives
 * a request — that keeps the shared-server model race-free.
 *
 * Auth is deliberately minimal and fail-closed: every /mcp request must
 * carry `Authorization: Bearer <token>`; the token is compared with
 * timingSafeEqual and is never logged. /healthz stays open for load
 * balancers and reports only non-sensitive liveness data.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { readFileSync, existsSync, statSync } from "node:fs";
import { join, normalize } from "node:path";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Enrollment } from "./enroll.js";
import type { AuditApi } from "./audit-api.js";

const CONSOLE_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

/** Resolve a /console/* request to a file inside consoleDir, or undefined. */
function resolveConsoleFile(consoleDir: string, pathname: string): string | undefined {
  const rel = pathname === "/console" || pathname === "/console/" ? "index.html" : pathname.slice("/console/".length);
  if (!rel || rel.includes("..") || rel.startsWith("/") || rel.includes("\\")) return undefined;
  const candidate = normalize(join(consoleDir, rel));
  if (!candidate.startsWith(normalize(consoleDir))) return undefined;
  if (!existsSync(candidate) || !statSync(candidate).isFile()) return undefined;
  return candidate;
}

/** Hard cap on a single MCP request body — fleet payloads are small. */
const MAX_BODY_BYTES = 4 * 1024 * 1024;

export interface GatewayOptions {
  /** The shared Flotilla McpServer (from flotilla-mcp). */
  mcpServer: McpServer;
  /** Bearer token required on every /mcp request. Never logged. */
  token: string;
  /** Extra fields merged into the /healthz payload. */
  health?: () => Record<string, unknown>;
  /** Enrollment endpoints (§9.1 one-line join). Operator management routes
   * (/api/enroll/tokens*) sit behind the gateway bearer token; node routes
   * (/join.sh, /api/enroll/join|confirm) authenticate with enrollment tokens. */
  enrollment?: Enrollment;
  /** Compliance export over the audit log (operator bearer routes). */
  auditApi?: AuditApi;
  /** Directory of the static web console served at /console (no secrets in
   * these files — the APIs they call still demand the bearer token). */
  consoleDir?: string;
  /** Diagnostic sink for request lines; defaults to console.error. */
  requestLog?: (line: string) => void;
}

export interface Gateway {
  server: Server;
  /** The effective token hash for sanity checks (never the token itself). */
  authSummary: string;
}

function bearerMatches(header: string | undefined, token: string): boolean {
  if (!header || !header.startsWith("Bearer ")) return false;
  const presented = header.slice("Bearer ".length).trim();
  const a = Buffer.from(presented);
  const b = Buffer.from(token);
  // timingSafeEqual throws on length mismatch — that comparison result is
  // not secret, so map it to plain inequality.
  return a.length === b.length && timingSafeEqual(a, b);
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders?: Record<string, string>): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

function readBody(req: IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** Create the gateway HTTP server. Call server.listen() on the result. */
export function createGateway(options: GatewayOptions): Gateway {
  const { mcpServer, token, health, requestLog } = options;
  if (!token || token.length < 8) {
    throw new Error("gateway token must be at least 8 characters (env FLOTILLA_GATEWAY_TOKEN or --token)");
  }
  const log = requestLog ?? ((line: string) => console.error(line));
  const authSummary = `sha256:${Buffer.from(token).length}bytes`;

  const server = createServer((req, res) => {
    void (async () => {
      const started = Date.now();
      const method = req.method ?? "?";
      const url = new URL(req.url ?? "/", "http://localhost");
      const path = url.pathname;
      let status = 200;

      try {
        if (path === "/healthz") {
          if (method !== "GET") {
            status = 405;
            sendJson(res, status, { error: "method not allowed" });
            return;
          }
          sendJson(res, 200, { ok: true, service: "flotilla-gateway", ...(health?.() ?? {}) });
          return;
        }

        // Static web console: served without auth (it holds no secrets); the
        // APIs it calls enforce the bearer token themselves.
        if (options.consoleDir && method === "GET") {
          if (path === "/") {
            status = 302;
            res.writeHead(302, { location: "/console/" });
            res.end();
            return;
          }
          if (path === "/console" || path === "/console/" || path.startsWith("/console/")) {
            const file = resolveConsoleFile(options.consoleDir, path);
            if (!file) {
              status = 404;
              sendJson(res, 404, { error: "not found" });
              return;
            }
            const ext = file.slice(file.lastIndexOf("."));
            const body = readFileSync(file);
            status = 200;
            res.writeHead(200, {
              "content-type": CONSOLE_TYPES[ext] ?? "application/octet-stream",
              "content-length": body.length,
              "cache-control": ext === ".html" ? "no-cache" : "max-age=300",
            });
            res.end(body);
            return;
          }
        }

        // Enrollment routes sit in front of the MCP surface. Node-facing
        // routes carry their own enrollment-token auth; the operator
        // management routes reuse the gateway bearer token, checked here.
        if (options.enrollment) {
          const operatorRoute = path === "/api/enroll/tokens" || path.startsWith("/api/enroll/tokens/");
          if (operatorRoute && !bearerMatches(req.headers.authorization, token)) {
            status = 401;
            sendJson(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
            return;
          }
          if (await options.enrollment.handle(req, res)) {
            status = res.statusCode;
            return;
          }
        }

        // Compliance export: operator-only, rides the gateway bearer token.
        if (options.auditApi && path === "/api/audit/export") {
          if (!bearerMatches(req.headers.authorization, token)) {
            status = 401;
            sendJson(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
            return;
          }
          if (await options.auditApi.handle(req, res)) {
            status = res.statusCode;
            return;
          }
        }

        if (path === "/mcp") {
          // CORS preflight never carries credentials — it must be answered
          // before the auth gate, and says nothing about the resource.
          if (method === "OPTIONS") {
            status = 204;
            res.writeHead(204, {
              "access-control-allow-headers": "authorization, content-type, mcp-protocol-version",
              "access-control-allow-methods": "POST, OPTIONS",
            });
            res.end();
            return;
          }

          // Fail closed: without a valid bearer token the endpoint does not
          // exist as far as the caller is concerned.
          if (!bearerMatches(req.headers.authorization, token)) {
            status = 401;
            sendJson(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
            return;
          }

          if (method === "DELETE") {
            // Stateless mode: there are no server-side sessions to delete.
            status = 405;
            sendJson(res, 405, { error: "stateless gateway: no sessions" });
            return;
          }

          if (method === "GET") {
            // The Streamable HTTP client opens a standing GET stream for
            // server-initiated messages. A stateless gateway has no session
            // state to push from, and the shared engine can only be bound to
            // one transport at a time — holding the slot for a GET stream
            // would starve every subsequent POST. Responses (including
            // elicitation) ride the POST stream; nothing is lost.
            status = 405;
            sendJson(res, 405, { error: "stateless gateway: no server-initiated stream" }, { allow: "POST, OPTIONS" });
            return;
          }

          if (method !== "POST") {
            status = 405;
            sendJson(res, 405, { error: "method not allowed" });
            return;
          }

          let parsedBody: unknown;
          if (method === "POST") {
            const raw = await readBody(req, MAX_BODY_BYTES);
            if (raw) {
              try {
                parsedBody = JSON.parse(raw);
              } catch {
                status = 400;
                sendJson(res, 400, { error: "invalid JSON body" });
                return;
              }
            }
          }

          // One transport per request, discarded with the response — the
          // documented stateless pattern. The shared engine stays connected.
          const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
          res.on("close", () => {
            void transport.close();
          });
          // Reconnect race: a fast client (e.g. the SDK client used by
          // upstream aggregation) can send its next request before this
          // response's "close" has freed the shared server's transport slot.
          // Wait out the previous close instead of failing the request.
          for (let attempt = 0; ; attempt++) {
            try {
              await mcpServer.connect(transport);
              break;
            } catch (err) {
              if (!/already connected/i.test(String(err)) || attempt >= 49) throw err;
              await new Promise((r) => setTimeout(r, 10));
            }
          }
          await transport.handleRequest(req, res, parsedBody);
          status = res.statusCode;
          return;
        }

        status = 404;
        sendJson(res, 404, { error: "not found" });
      } catch (err) {
        status = 500;
        if (!res.headersSent) {
          sendJson(res, 500, { error: "gateway internal error" });
        }
        log(`flotilla-gateway: error handling ${method} ${path}: ${err instanceof Error ? err.message : String(err)}`);
      } finally {
        log(`flotilla-gateway: ${method} ${path} ${status} ${Date.now() - started}ms`);
      }
    })();
  });

  return { server, authSummary };
}
