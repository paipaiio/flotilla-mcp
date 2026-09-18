/**
 * Flotilla compliance export — operator API over the hash-chained audit log
 * (§v2 合规导出).
 *
 *   GET /api/audit/export?from=<iso|epoch>&to=<iso|epoch>&host=<name>
 *       &tool=<name>&outcome=<ok|failed|...>&kind=<decision|approval|execution>
 *       &approver=<who>&format=csv|json&limit=<n>
 *
 * Filters are ANDed. `host` matches against the event's config server names
 * (never raw IPs — that invariant comes from the engine's AuditEvent shape).
 * JSON returns the full records (including hash-chain fields); CSV projects
 * the compliance columns and is streamed as an attachment.
 *
 * Rows are bounded (default 10k, hard cap 100k) — this endpoint is for
 * operator review and compliance reports, not bulk data pipelines; the raw
 * JSONL stays the system of record.
 */
import { existsSync, readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AuditEvent } from "flotilla-core";

export interface AuditRecord extends AuditEvent {
  ts: string;
  seq: number;
  prevHash: string;
  hash: string;
}

export interface AuditApiOptions {
  /** The engine's audit JSONL. */
  auditPath: string;
}

export interface AuditApi {
  handle(req: IncomingMessage, res: ServerResponse): Promise<boolean>;
}

const DEFAULT_LIMIT = 10_000;
const MAX_LIMIT = 100_000;

const CSV_COLUMNS = [
  "ts",
  "seq",
  "kind",
  "tool",
  "hosts",
  "command",
  "commandClass",
  "outcome",
  "approver",
  "reason",
  "durationMs",
] as const;

function csvCell(value: unknown): string {
  if (value === undefined || value === null) return "";
  const text = Array.isArray(value) ? value.join(";") : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function parseTime(value: string | null): string | undefined {
  if (!value) return undefined;
  const asNumber = Number(value);
  if (Number.isFinite(asNumber) && value.trim() !== "") {
    return new Date(asNumber).toISOString();
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function readRecords(auditPath: string): AuditRecord[] {
  if (!existsSync(auditPath)) return [];
  const out: AuditRecord[] = [];
  for (const line of readFileSync(auditPath, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as AuditRecord);
    } catch {
      // Skip torn/mid-write lines — the raw file remains the system of record.
    }
  }
  return out;
}

function sendCsv(res: ServerResponse, records: AuditRecord[], filename: string): void {
  const lines = [CSV_COLUMNS.join(",")];
  for (const record of records) {
    const row = CSV_COLUMNS.map((column) =>
      csvCell(record[column as keyof AuditRecord]),
    ).join(",");
    lines.push(row);
  }
  const body = lines.join("\n") + "\n";
  res.writeHead(200, {
    "content-type": "text/csv; charset=utf-8",
    "content-disposition": `attachment; filename="${filename}"`,
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

function sendJson(res: ServerResponse, records: AuditRecord[], filename: string): void {
  const body = JSON.stringify(records, null, 2);
  res.writeHead(200, {
    "content-type": "application/json; charset=utf-8",
    "content-disposition": `attachment; filename="${filename}"`,
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

export function createAuditApi(options: AuditApiOptions): AuditApi {
  async function handle(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== "/api/audit/export" || req.method !== "GET") return false;

    const q = url.searchParams;
    const from = parseTime(q.get("from"));
    const to = parseTime(q.get("to"));
    const host = q.get("host") ?? undefined;
    const tool = q.get("tool") ?? undefined;
    const outcome = q.get("outcome") ?? undefined;
    const kind = q.get("kind") ?? undefined;
    const approver = q.get("approver") ?? undefined;
    const format = q.get("format") === "csv" ? "csv" : "json";
    const limitParam = Number(q.get("limit") ?? DEFAULT_LIMIT);
    const limit = Number.isInteger(limitParam) && limitParam > 0 ? Math.min(limitParam, MAX_LIMIT) : DEFAULT_LIMIT;

    const matched = readRecords(options.auditPath).filter((record) => {
      if (from && record.ts < from) return false;
      if (to && record.ts > to) return false;
      if (host && !(record.hosts ?? []).includes(host)) return false;
      if (tool && record.tool !== tool) return false;
      if (outcome && record.outcome !== outcome) return false;
      if (kind && record.kind !== kind) return false;
      if (approver && record.approver !== approver) return false;
      return true;
    });

    // Newest first is what compliance reviewers expect; preserve chain fields.
    matched.sort((a, b) => b.seq - a.seq);
    const bounded = matched.slice(0, limit);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `flotilla-audit-${stamp}.${format}`;
    if (format === "csv") sendCsv(res, bounded, filename);
    else sendJson(res, bounded, filename);
    return true;
  }

  return { handle };
}
