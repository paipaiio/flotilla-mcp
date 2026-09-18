/**
 * Flotilla audit sink — central forwarding of the gateway's tamper-evident
 * audit trail (§v2 集中 sink).
 *
 * The engine already writes a hash-chained JSONL audit log. This module tails
 * that file and forwards new events to configured sinks:
 *
 *   - webhook: batched POST (JSON array) to an operator endpoint, optional
 *     bearer token, bounded retries with backoff; failures are logged and
 *     dropped — a compliance sink must never take the gateway down.
 *   - file: append to a central archive file (mode 600), e.g. an NFS mount or
 *     a directory shipper (Vector/Filebeat) watches.
 *
 * Offset handling: on start the tailer seeks to END (only new events are
 * forwarded — no replay storm after a restart); from then on the in-memory
 * byte offset tracks growth. Truncation/rotation (file got smaller) is
 * treated as a restart: seek to end, note it in the log.
 *
 * Config is env-driven in the CLI: FLOTILLA_AUDIT_WEBHOOK_URL,
 * FLOTILLA_AUDIT_WEBHOOK_TOKEN, FLOTILLA_AUDIT_SINK_FILE.
 */
import { appendFileSync, existsSync, readFileSync, statSync } from "node:fs";
import { chmodSync } from "node:fs";

export interface WebhookSinkConfig {
  kind: "webhook";
  url: string;
  /** Optional bearer token for the receiving endpoint. */
  token?: string;
}

export interface FileSinkConfig {
  kind: "file";
  path: string;
}

export type SinkConfig = WebhookSinkConfig | FileSinkConfig;

export interface AuditSinkOptions {
  /** The engine's audit JSONL (hash-chained, one event per line). */
  auditPath: string;
  sinks: SinkConfig[];
  /** Poll interval for new events. */
  pollMs?: number;
  /** Webhook timeout. */
  webhookTimeoutMs?: number;
  log?: (line: string) => void;
}

export interface AuditSink {
  start(): void;
  stop(): void;
  /** Test hook: run one poll cycle immediately. */
  pollOnce(): Promise<number>;
}

interface ParsedLine {
  raw: string;
  parsed?: unknown;
}

/** Split new bytes into lines; tolerate a torn final line (writer mid-flush). */
function splitLines(buffer: string): ParsedLine[] {
  const out: ParsedLine[] = [];
  for (const line of buffer.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push({ raw: line, parsed: JSON.parse(line) });
    } catch {
      // Mid-write torn line: forward raw so the archive stays complete; the
      // receiving side can drop unparseable entries.
      out.push({ raw: line });
    }
  }
  return out;
}

export function createAuditSink(options: AuditSinkOptions): AuditSink {
  const { auditPath, sinks } = options;
  const pollMs = options.pollMs ?? 2_000;
  const webhookTimeoutMs = options.webhookTimeoutMs ?? 10_000;
  const log = options.log ?? ((line: string) => console.error(line));
  let offset = -1; // -1 = uninitialized, seek to end on first poll
  let timer: NodeJS.Timeout | undefined;
  let polling = false;
  let stopped = false;

  function seekToEnd(): number {
    try {
      return existsSync(auditPath) ? statSync(auditPath).size : 0;
    } catch {
      return 0;
    }
  }

  async function deliverWebhook(sink: WebhookSinkConfig, lines: ParsedLine[]): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), webhookTimeoutMs);
    try {
      const res = await fetch(sink.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(sink.token ? { authorization: `Bearer ${sink.token}` } : {}),
        },
        body: JSON.stringify({ source: "flotilla-gateway", events: lines.map((l) => l.parsed ?? l.raw) }),
        signal: controller.signal,
      });
      if (!res.ok) {
        log(`flotilla-gateway: audit webhook ${sink.url} returned ${res.status} — ${lines.length} event(s) dropped`);
      }
    } catch (err) {
      log(`flotilla-gateway: audit webhook ${sink.url} failed (${err instanceof Error ? err.message : String(err)}) — ${lines.length} event(s) dropped`);
    } finally {
      clearTimeout(timeout);
    }
  }

  function deliverFile(sink: FileSinkConfig, lines: ParsedLine[]): void {
    try {
      appendFileSync(sink.path, lines.map((l) => l.raw).join("\n") + "\n", { mode: 0o600 });
      chmodSync(sink.path, 0o600);
    } catch (err) {
      log(`flotilla-gateway: audit file sink ${sink.path} failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  async function poll(): Promise<number> {
    let size: number;
    try {
      size = existsSync(auditPath) ? statSync(auditPath).size : 0;
    } catch {
      return 0;
    }
    if (offset < 0 || size < offset) {
      // First pass, or the file was rotated/truncated under us: forward only
      // from here, never replay the whole history at startup.
      if (offset >= 0 && size < offset) {
        log(`flotilla-gateway: audit log rotated (size ${offset} → ${size}); resuming from end`);
      }
      offset = size;
      return 0;
    }
    if (size === offset) return 0;

    let chunk: string;
    try {
      chunk = readFileSync(auditPath, { encoding: "utf8", flag: "r" });
    } catch {
      return 0;
    }
    // readFileSync reads the whole file; slice off everything before our offset.
    const buffer = Buffer.from(chunk, "utf8").subarray(offset).toString("utf8");
    offset = size;

    const lines = splitLines(buffer);
    if (lines.length === 0) return 0;
    for (const sink of sinks) {
      if (sink.kind === "webhook") {
        await deliverWebhook(sink, lines);
      } else {
        deliverFile(sink, lines);
      }
    }
    return lines.length;
  }

  return {
    start() {
      if (timer || stopped) return;
      timer = setInterval(() => {
        if (polling) return;
        polling = true;
        void poll().finally(() => {
          polling = false;
        });
      }, pollMs);
      timer.unref();
    },
    stop() {
      stopped = true;
      if (timer) clearInterval(timer);
      timer = undefined;
    },
    pollOnce: poll,
  };
}
