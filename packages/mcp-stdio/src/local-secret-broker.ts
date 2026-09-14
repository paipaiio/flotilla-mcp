/** Ephemeral sensitive-value capture through a one-time loopback page. */
import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { ElicitResultSchema } from "@modelcontextprotocol/sdk/types.js";
import type { ElicitSender } from "./approval.js";

const LOOPBACK_HOST = "127.0.0.1";
const DEFAULT_TIMEOUT_MS = 10 * 60_000;
const MAX_FORM_BYTES = 64 * 1024;

export interface LocalSecretContext {
  sender: ElicitSender;
  signal?: AbortSignal;
}

export interface LocalSecretRequest {
  target: string;
  path: string;
  label: string;
}

export interface LocalSecretBrokerOptions {
  supportsUrlElicitation: () => boolean;
  createCompletionNotifier: (elicitationId: string) => () => Promise<void>;
  timeoutMs?: number;
  makeToken?: () => string;
  makeElicitationId?: () => string;
}

interface PendingSecret extends LocalSecretRequest {
  resolve: (value: string | undefined) => void;
  completion: Promise<string | undefined>;
  timer: NodeJS.Timeout;
  abort?: () => void;
  signal?: AbortSignal;
  notify: () => Promise<void>;
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function headers(contentType = "text/html; charset=utf-8"): Record<string, string> {
  return {
    "Cache-Control": "no-store",
    "Content-Type": contentType,
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
}

function form(item: PendingSecret): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Flotilla local secret</title><style>body{font:16px system-ui;background:#0b1020;color:#eef2ff;margin:0}.card{max-width:34rem;margin:10vh auto;padding:2rem;border:1px solid #334155;border-radius:16px;background:#111827}label,input,button{display:block;width:100%;box-sizing:border-box}input{margin:.6rem 0 1rem;padding:.8rem;border-radius:8px;border:1px solid #64748b;background:#020617;color:white}button{padding:.8rem;border:0;border-radius:8px;background:#22c55e;color:#052e16;font-weight:700}.note{color:#94a3b8;font-size:.9rem}code{color:#a7f3d0}</style></head><body><main class="card"><h1>Enter ${escapeHtml(item.label)}</h1><p>Target: <strong>${escapeHtml(item.target)}</strong><br>Field: <code>${escapeHtml(item.path)}</code></p><form method="post"><label for="value">Sensitive value</label><input id="value" name="value" type="password" autocomplete="off" required autofocus><button type="submit">Use once and continue</button></form><p class="note">The value stays in this process memory only until the pending config transaction consumes it. It is not stored and is not returned through MCP.</p></main></body></html>`;
}

function resultPage(ok: boolean): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Flotilla local secret</title></head><body><h1>${ok ? "Value received" : "Value not received"}</h1><p>${ok ? "Return to the MCP client. The exact change-set approval is next." : "Return to the MCP client and retry."}</p></body></html>`;
}

async function readValue(req: IncomingMessage): Promise<string> {
  const declared = Number(req.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > MAX_FORM_BYTES) throw new Error("form too large");
  let body = "";
  for await (const chunk of req) {
    body += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
    if (Buffer.byteLength(body) > MAX_FORM_BYTES) throw new Error("form too large");
  }
  return new URLSearchParams(body).get("value") ?? "";
}

export class LocalSecretBroker {
  private readonly pending = new Map<string, PendingSecret>();
  private listener?: HttpServer;
  private listenerPromise?: Promise<number>;
  private port?: number;

  constructor(private readonly options: LocalSecretBrokerOptions) {}

  async capture(context: LocalSecretContext, request: LocalSecretRequest): Promise<string | undefined> {
    if (!this.options.supportsUrlElicitation()) return undefined;
    const port = await this.ensureListener();
    const token = this.uniqueToken();
    const elicitationId = this.options.makeElicitationId?.() ?? randomUUID();
    let resolveCompletion!: (value: string | undefined) => void;
    const completion = new Promise<string | undefined>((resolve) => { resolveCompletion = resolve; });
    const item = {} as PendingSecret;
    Object.assign(item, {
      ...request,
      resolve: resolveCompletion,
      completion,
      notify: this.options.createCompletionNotifier(elicitationId),
      timer: setTimeout(() => this.finish(token, undefined), this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    item.timer.unref();
    if (context.signal) {
      item.abort = () => this.finish(token, undefined);
      item.signal = context.signal;
      context.signal.addEventListener("abort", item.abort, { once: true });
    }
    this.pending.set(token, item);
    const url = `http://${LOOPBACK_HOST}:${port}/secret/${token}`;
    try {
      const answer = await context.sender.sendRequest({
        method: "elicitation/create",
        params: {
          mode: "url",
          message: `Flotilla needs one sensitive value for ${request.target} field ${request.path}. Open the one-time local page; the value stays out of MCP and is consumed by this config transaction only.`,
          elicitationId,
          url,
        },
      }, ElicitResultSchema);
      if (answer.action !== "accept") {
        this.finish(token, undefined);
        return undefined;
      }
      return await completion;
    } catch {
      this.finish(token, undefined);
      return undefined;
    }
  }

  private uniqueToken(): string {
    let token: string;
    do token = this.options.makeToken?.() ?? randomBytes(24).toString("base64url");
    while (this.pending.has(token));
    return token;
  }

  private async ensureListener(): Promise<number> {
    if (this.listener && this.port) return this.port;
    if (this.listenerPromise) return this.listenerPromise;
    this.listenerPromise = this.startListener();
    try { return await this.listenerPromise; } finally { this.listenerPromise = undefined; }
  }

  private async startListener(): Promise<number> {
    const listener = createServer((req, res) => { void this.handle(req, res); });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      listener.once("error", onError);
      listener.listen(0, LOOPBACK_HOST, () => { listener.off("error", onError); resolve(); });
    });
    const address = listener.address();
    if (!address || typeof address === "string") { listener.close(); throw new Error("Local secret listener did not bind to loopback"); }
    this.listener = listener;
    this.port = address.port;
    return address.port;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const token = /^\/secret\/([A-Za-z0-9_-]+)$/.exec(req.url ?? "")?.[1];
    const item = token ? this.pending.get(token) : undefined;
    if (!token || !item) { res.writeHead(404, headers("text/plain; charset=utf-8")); res.end("Not found"); return; }
    if (req.method === "GET") { res.writeHead(200, headers()); res.end(form(item)); return; }
    if (req.method !== "POST") { res.writeHead(405, { ...headers("text/plain; charset=utf-8"), Allow: "GET, POST" }); res.end("Method not allowed"); return; }
    if (!(req.headers["content-type"] ?? "").toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      res.writeHead(415, headers("text/plain; charset=utf-8")); res.end("Unsupported media type"); return;
    }
    try {
      const value = await readValue(req);
      if (!value) { res.writeHead(400, headers()); res.end(resultPage(false)); return; }
      this.finish(token, value);
      res.writeHead(200, headers());
      res.end(resultPage(true));
      void item.notify().catch(() => undefined);
    } catch {
      res.writeHead(503, headers()); res.end(resultPage(false));
    }
  }

  private finish(token: string, value: string | undefined): string | undefined {
    const item = this.pending.get(token);
    if (!item) return value;
    this.pending.delete(token);
    clearTimeout(item.timer);
    if (item.signal && item.abort) item.signal.removeEventListener("abort", item.abort);
    item.resolve(value);
    return value;
  }

  async close(): Promise<void> {
    for (const token of [...this.pending.keys()]) this.finish(token, undefined);
    const listener = this.listener;
    this.listener = undefined;
    this.port = undefined;
    if (!listener) return;
    listener.closeAllConnections?.();
    await new Promise<void>((resolve) => listener.close(() => resolve()));
  }
}
