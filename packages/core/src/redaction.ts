/** Fingerprint-based redaction for sensitive material crossing the MCP boundary. */
import { createHash } from "node:crypto";

export interface SensitiveRedaction {
  kind: "private-key" | "bearer-token" | "secret-value";
  fingerprint: string;
  length: number;
}

export interface RedactedText {
  text: string;
  redactions: SensitiveRedaction[];
}

interface Match {
  start: number;
  end: number;
  kind: SensitiveRedaction["kind"];
  value: string;
}

function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function collectMatches(text: string): Match[] {
  const matches: Match[] = [];
  const privateKeys = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;
  for (const match of text.matchAll(privateKeys)) {
    const value = match[0];
    matches.push({ start: match.index, end: match.index + value.length, kind: "private-key", value });
  }

  const bearerTokens = /\bBearer\s+([A-Za-z0-9._~+/=-]{12,})/g;
  for (const match of text.matchAll(bearerTokens)) {
    const value = match[1]!;
    const start = match.index + match[0].lastIndexOf(value);
    matches.push({ start, end: start + value.length, kind: "bearer-token", value });
  }

  const assignments = /^(\s*(?:export\s+)?[A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]*\s*(?:=|:)\s*)(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s#;\r\n]+))/gim;
  for (const match of text.matchAll(assignments)) {
    const value = match[2] ?? match[3] ?? match[4] ?? "";
    if (!value) continue;
    const quoteOffset = match[2] !== undefined || match[3] !== undefined ? 1 : 0;
    const start = match.index + match[1]!.length + quoteOffset;
    matches.push({ start, end: start + value.length, kind: "secret-value", value });
  }
  return matches.sort((left, right) => left.start - right.start || right.end - left.end);
}

/**
 * Keep public context readable while replacing known sensitive forms with a
 * deterministic, non-reversible SHA-256 prefix and the original byte length.
 */
export function redactSensitiveText(text: string): RedactedText {
  const accepted: Match[] = [];
  for (const match of collectMatches(text)) {
    if (accepted.some((item) => match.start < item.end && match.end > item.start)) continue;
    accepted.push(match);
  }
  if (accepted.length === 0) return { text, redactions: [] };

  let cursor = 0;
  let output = "";
  const redactions: SensitiveRedaction[] = [];
  for (const match of accepted) {
    const digest = fingerprint(match.value);
    const length = Buffer.byteLength(match.value);
    output += text.slice(cursor, match.start);
    output += `[REDACTED ${match.kind} sha256:${digest} length=${length}]`;
    redactions.push({ kind: match.kind, fingerprint: digest, length });
    cursor = match.end;
  }
  output += text.slice(cursor);
  return { text: output, redactions };
}
