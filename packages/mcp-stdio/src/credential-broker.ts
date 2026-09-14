/**
 * Sensitive credential repair for MCP clients supporting URL elicitation.
 *
 * Passwords are posted directly to a one-time loopback form and saved in the
 * OS keychain. They never enter MCP request/result payloads, tool arguments,
 * config files, logs, or process arguments.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { ElicitResultSchema } from "@modelcontextprotocol/sdk/types.js";
import {
  keychainAccount,
  type CredentialKind,
  type KeychainBackend,
} from "flotilla-core";
import type { ElicitSender } from "./approval.js";

const LOOPBACK_HOST = "127.0.0.1";
const DEFAULT_TIMEOUT_MS = 10 * 60_000;
const MAX_FORM_BYTES = 16 * 1024;

export interface CredentialRequestContext {
  sender: ElicitSender;
  signal?: AbortSignal;
}

export interface CredentialBrokerOptions {
  getKeychain: () => Promise<KeychainBackend | null>;
  supportsUrlElicitation: () => boolean;
  createCompletionNotifier: (elicitationId: string) => () => Promise<void>;
  timeoutMs?: number;
  makeToken?: () => string;
  makeElicitationId?: () => string;
}

interface PendingCredential {
  account: string;
  displayName: string;
  kind: CredentialKind;
  backend: KeychainBackend;
  resolve: (value: boolean) => void;
  completion: Promise<boolean>;
  timer: NodeJS.Timeout;
  abort?: () => void;
  signal?: AbortSignal;
  notify: () => Promise<void>;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function securityHeaders(contentType = "text/html; charset=utf-8"): Record<string, string> {
  return {
    "Cache-Control": "no-store",
    "Content-Type": contentType,
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
}

function credentialForm(item: PendingCredential): string {
  const label = item.kind === "sudo" ? "sudo password" : "SSH password";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Flotilla credential</title><style>body{font:16px system-ui;background:#0b1020;color:#eef2ff;margin:0}.card{max-width:32rem;margin:10vh auto;padding:2rem;border:1px solid #334155;border-radius:16px;background:#111827}label,input,button{display:block;width:100%;box-sizing:border-box}input{margin:.6rem 0 1rem;padding:.8rem;border-radius:8px;border:1px solid #64748b;background:#020617;color:white}button{padding:.8rem;border:0;border-radius:8px;background:#22c55e;color:#052e16;font-weight:700}.note{color:#94a3b8;font-size:.9rem}</style></head><body><main class="card"><h1>Save ${label}</h1><p>Target: <strong>${escapeHtml(item.displayName)}</strong></p><form method="post"><label for="password">${label}</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">Save to OS keychain and continue</button></form><p class="note">This one-time page is available only on this computer. The value is not sent through the MCP conversation.</p></main></body></html>`;
}

function resultPage(ok: boolean): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Flotilla credential</title><style>body{font:16px system-ui;max-width:34rem;margin:12vh auto;padding:2rem;background:#0b1020;color:#eef2ff}</style></head><body><h1>${ok ? "Credential saved" : "Credential not saved"}</h1><p>${ok ? "Return to the MCP client. The original operation is continuing automatically." : "Keep this page open and try again."}</p></body></html>`;
}

async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const declared = Number(req.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > MAX_FORM_BYTES) throw new Error("form too large");
  let body = "";
  for await (const chunk of req) {
    body += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
    if (Buffer.byteLength(body) > MAX_FORM_BYTES) throw new Error("form too large");
  }
  return new URLSearchParams(body);
}

export class CredentialBroker {
  private readonly requestContext = new AsyncLocalStorage<CredentialRequestContext>();
  private readonly pending = new Map<string, PendingCredential>();
  private readonly pendingByAccount = new Map<string, Promise<boolean>>();
  private listener?: HttpServer;
  private listenerPromise?: Promise<number>;
  private port?: number;

  constructor(private readonly options: CredentialBrokerOptions) {}

  runWithRequest<T>(context: CredentialRequestContext, action: () => Promise<T>): Promise<T> {
    return this.requestContext.run(context, action);
  }

  /** Attempt one secure repair. False preserves the existing recovery error. */
  async repair(server: { name: string }, kind: CredentialKind): Promise<boolean> {
    const context = this.requestContext.getStore();
    if (!context || !this.options.supportsUrlElicitation()) return false;
    const backend = await this.options.getKeychain();
    if (!backend) return false;

    const account = keychainAccount(server.name, kind === "sudo");
    const existing = this.pendingByAccount.get(account);
    if (existing) return existing;
    const port = await this.ensureListener();
    const raced = this.pendingByAccount.get(account);
    if (raced) return raced;
    const token = this.uniqueToken();
    const elicitationId = this.options.makeElicitationId?.() ?? randomUUID();
    let resolveCompletion!: (value: boolean) => void;
    const completion = new Promise<boolean>((resolve) => { resolveCompletion = resolve; });
    const item = {} as PendingCredential;
    Object.assign(item, {
      account,
      displayName: server.name,
      kind,
      backend,
      resolve: resolveCompletion,
      completion,
      notify: this.options.createCompletionNotifier(elicitationId),
      timer: setTimeout(() => this.finish(token, false), this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    item.timer.unref();
    if (context.signal) {
      item.abort = () => this.finish(token, false);
      item.signal = context.signal;
      context.signal.addEventListener("abort", item.abort, { once: true });
    }
    this.pending.set(token, item);
    this.pendingByAccount.set(account, completion);

    const url = `http://${LOOPBACK_HOST}:${port}/credential/${token}`;
    try {
      const answer = await context.sender.sendRequest(
        {
          method: "elicitation/create",
          params: {
            mode: "url",
            message: `Flotilla needs a ${kind === "sudo" ? "sudo" : "SSH login"} password for ${server.name}. Open the local one-time page; the secret is saved in the OS keychain and the current operation resumes automatically.`,
            elicitationId,
            url,
          },
        },
        ElicitResultSchema,
      );
      if (answer.action !== "accept") {
        return this.pending.has(token) ? this.finish(token, false) : await completion;
      }
      return await completion;
    } catch {
      // The browser may have completed the one-time form just before the MCP
      // request channel closed. Preserve that successful save so the original
      // SSH operation still resumes instead of asking a second time.
      return this.pending.has(token) ? this.finish(token, false) : await completion;
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
    try {
      return await this.listenerPromise;
    } finally {
      this.listenerPromise = undefined;
    }
  }

  private async startListener(): Promise<number> {
    const listener = createServer((req, res) => { void this.handleRequest(req, res); });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      listener.once("error", onError);
      listener.listen(0, LOOPBACK_HOST, () => {
        listener.off("error", onError);
        resolve();
      });
    });
    const address = listener.address();
    if (!address || typeof address === "string") {
      listener.close();
      throw new Error("Credential listener did not bind to loopback");
    }
    this.listener = listener;
    this.port = address.port;
    return address.port;
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const match = /^\/credential\/([A-Za-z0-9_-]+)$/.exec(req.url ?? "");
    const token = match?.[1];
    const item = token ? this.pending.get(token) : undefined;
    if (!token || !item) {
      res.writeHead(404, securityHeaders("text/plain; charset=utf-8"));
      res.end("Not found");
      return;
    }
    if (req.method === "GET") {
      res.writeHead(200, securityHeaders());
      res.end(credentialForm(item));
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { ...securityHeaders("text/plain; charset=utf-8"), Allow: "GET, POST" });
      res.end("Method not allowed");
      return;
    }
    if (!(req.headers["content-type"] ?? "").toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      res.writeHead(415, securityHeaders("text/plain; charset=utf-8"));
      res.end("Unsupported media type");
      return;
    }
    try {
      const password = (await readForm(req)).get("password") ?? "";
      if (!password) {
        res.writeHead(400, securityHeaders());
        res.end(resultPage(false));
        return;
      }
      await item.backend.set(item.account, password);
      this.finish(token, true);
      res.writeHead(200, securityHeaders());
      res.end(resultPage(true));
      void item.notify().catch(() => undefined);
    } catch {
      res.writeHead(503, securityHeaders());
      res.end(resultPage(false));
    }
  }

  private finish(token: string, value: boolean): boolean {
    const item = this.pending.get(token);
    if (!item) return value;
    this.pending.delete(token);
    if (this.pendingByAccount.get(item.account) === item.completion) {
      this.pendingByAccount.delete(item.account);
    }
    clearTimeout(item.timer);
    if (item.signal && item.abort) item.signal.removeEventListener("abort", item.abort);
    item.resolve(value);
    return value;
  }

  async close(): Promise<void> {
    for (const token of [...this.pending.keys()]) this.finish(token, false);
    const listener = this.listener;
    this.listener = undefined;
    this.port = undefined;
    if (!listener) return;
    listener.closeAllConnections?.();
    await new Promise<void>((resolve) => listener.close(() => resolve()));
  }
}
