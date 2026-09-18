import { appendFileSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createAuditApi } from "../src/audit-api.js";
import { createAuditSink } from "../src/audit-sink.js";
import { createGateway } from "../src/http-server.js";

const BEARER = "audit-bearer-token-0123456789";

let dir: string;
let auditPath: string;

/** Append one hash-chain-shaped record (content irrelevant for filters). */
function auditLine(fields: Record<string, unknown>): string {
  return JSON.stringify({ ts: "2026-09-18T10:00:00.000Z", seq: 1, prevHash: "a", hash: "b", ...fields });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flotilla-audit-"));
  auditPath = join(dir, "audit.jsonl");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("audit sink forwarding", () => {
  it("forwards new events to a file sink, seeking to end on start", async () => {
    writeFileSync(auditPath, auditLine({ tool: "exec", outcome: "ok" }) + "\n");
    const sinkPath = join(dir, "archive.jsonl");
    const sink = createAuditSink({ auditPath, sinks: [{ kind: "file", path: sinkPath }] });

    // Pre-existing events are NOT replayed: first poll initializes the offset.
    expect(await sink.pollOnce()).toBe(0);
    expect(existsSync(sinkPath)).toBe(false);

    appendFileSync(auditPath, auditLine({ tool: "exec-read", outcome: "ok" }) + "\n");
    appendFileSync(auditPath, auditLine({ tool: "exec", outcome: "failed" }) + "\n");
    expect(await sink.pollOnce()).toBe(2);

    const archived = readFileSync(sinkPath, "utf8").trim().split("\n");
    expect(archived).toHaveLength(2);
    expect(JSON.parse(archived[0]).tool).toBe("exec-read");
    expect(statSync(sinkPath).mode & 0o777).toBe(0o600);

    // No growth → nothing forwarded; idempotent polls.
    expect(await sink.pollOnce()).toBe(0);
    sink.stop();
  });

  it("treats truncation/rotation as a resume-from-end, not a replay", async () => {
    const sinkPath = join(dir, "archive.jsonl");
    const sink = createAuditSink({ auditPath, sinks: [{ kind: "file", path: sinkPath }] });
    appendFileSync(auditPath, auditLine({ tool: "exec" }) + "\n");
    expect(await sink.pollOnce()).toBe(0); // init
    appendFileSync(auditPath, auditLine({ tool: "exec" }) + "\n");
    expect(await sink.pollOnce()).toBe(1);

    // Rotate: the file shrinks (new inode, fresh content).
    writeFileSync(auditPath, auditLine({ tool: "post-rotation" }) + "\n");
    expect(await sink.pollOnce()).toBe(0); // resumption point, no replay
    appendFileSync(auditPath, auditLine({ tool: "post-rotation-2" }) + "\n");
    expect(await sink.pollOnce()).toBe(1);
    const archived = readFileSync(sinkPath, "utf8");
    expect(archived).not.toContain("post-rotation\"");
    expect(archived).toContain("post-rotation-2");
    sink.stop();
  });

  it("batches to webhooks and tolerates endpoint failures", async () => {
    const received: unknown[] = [];
    let failNext = false;
    const stub = createStubServer(async (req, body) => {
      if (req.url === "/hook") {
        if (failNext) return { status: 500 };
        received.push(JSON.parse(body));
        return { status: 200 };
      }
      return undefined;
    });

    const logs: string[] = [];
    await listen(stub);
    const hookUrl = `http://127.0.0.1:${stubPort(stub)}/hook`;
    const sink = createAuditSink({
      auditPath,
      sinks: [{ kind: "webhook", url: hookUrl, token: "hook-secret" }],
      pollMs: 100,
      log: (line) => logs.push(line),
    });
    // Deterministic init: first poll only establishes the offset.
    await sink.pollOnce();
    sink.start();
    try {
      appendFileSync(auditPath, auditLine({ tool: "exec", outcome: "ok" }) + "\n");
      appendFileSync(auditPath, auditLine({ tool: "fleet-diff", outcome: "ok" }) + "\n");
      await waitFor(() => received.length === 1);
      const batch = received[0] as { source: string; events: Array<{ tool: string }> };
      expect(batch.source).toBe("flotilla-gateway");
      expect(batch.events.map((e) => e.tool)).toEqual(["exec", "fleet-diff"]);

      failNext = true;
      appendFileSync(auditPath, auditLine({ tool: "exec", outcome: "ok" }) + "\n");
      await waitFor(() => logs.some((l) => l.includes("500")));
      // The gateway stays alive and keeps forwarding after a failed batch.
      failNext = false;
      appendFileSync(auditPath, auditLine({ tool: "exec-read", outcome: "ok" }) + "\n");
      await waitFor(() => received.length === 2);

      // Unreachable endpoint: error logged, gateway unaffected. The first
      // poll only initializes the offset; the failure lands on the second.
      const sink2 = createAuditSink({
        auditPath,
        sinks: [{ kind: "webhook", url: "http://127.0.0.1:1/nope" }],
        log: (line) => logs.push(line),
      });
      await sink2.pollOnce();
      appendFileSync(auditPath, auditLine({ tool: "last" }) + "\n");
      await sink2.pollOnce();
      expect(logs.some((l) => l.includes("failed"))).toBe(true);
    } finally {
      sink.stop();
      await closeStub(stub);
    }
  });
});

describe("compliance export API", () => {
  it("filters AND-style and exports CSV with proper escaping", async () => {
    writeFileSync(
      auditPath,
      [
        auditLine({ kind: "execution", tool: "exec", hosts: ["web-1", "web-2"], outcome: "ok", command: 'say "hi", ok', durationMs: 12 }),
        auditLine({ kind: "execution", tool: "exec", hosts: ["web-1"], outcome: "failed", reason: "denied by policy" }),
        auditLine({ kind: "approval", tool: "exec", hosts: ["db-1"], outcome: "approved", approver: "human-elicitation" }),
        auditLine({ kind: "decision", tool: "fleet-push", hosts: ["web-1"], outcome: "denied" }),
      ].join("\n") + "\n",
    );
    const { server, base } = await startGatewayWithAudit();
    try {
      const csv = await fetch(
        `${base}/api/audit/export?host=web-1&tool=exec&outcome=ok&format=csv`,
        { headers: { authorization: `Bearer ${BEARER}` } },
      );
      expect(csv.status).toBe(200);
      expect(csv.headers.get("content-type")).toContain("text/csv");
      expect(csv.headers.get("content-disposition")).toContain(".csv");
      const text = await csv.text();
      const rows = text.trim().split("\n");
      expect(rows[0]).toBe("ts,seq,kind,tool,hosts,command,commandClass,outcome,approver,reason,durationMs");
      expect(rows).toHaveLength(2); // header + exactly one matched record
      expect(rows[1]).toContain('"say ""hi"", ok"');
      expect(rows[1]).toContain("web-1;web-2");

      // Approver filter hits the approval record.
      const jsonRes = await fetch(`${base}/api/audit/export?approver=human-elicitation`, {
        headers: { authorization: `Bearer ${BEARER}` },
      });
      const json = (await jsonRes.json()) as Array<{ kind: string; approver: string }>;
      expect(json).toHaveLength(1);
      expect(json[0].kind).toBe("approval");

      // Kind + host filters.
      const denied = await fetch(`${base}/api/audit/export?kind=decision&host=web-1&format=json`, {
        headers: { authorization: `Bearer ${BEARER}` },
      });
      expect(((await denied.json()) as unknown[]).length).toBe(1);

      // Time window filter (ISO strings compare lexicographically).
      const empty = await fetch(
        `${base}/api/audit/export?from=2027-01-01&to=2027-12-31`,
        { headers: { authorization: `Bearer ${BEARER}` } },
      );
      expect(((await empty.json()) as unknown[]).length).toBe(0);

      // Limit bounds the result.
      const limited = await fetch(`${base}/api/audit/export?limit=2&format=json`, {
        headers: { authorization: `Bearer ${BEARER}` },
      });
      expect(((await limited.json()) as unknown[]).length).toBe(2);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("requires the bearer token and tolerates a missing audit file", async () => {
    const { server, base } = await startGatewayWithAudit();
    try {
      const anon = await fetch(`${base}/api/audit/export`);
      expect(anon.status).toBe(401);
      const empty = await fetch(`${base}/api/audit/export?format=json`, {
        headers: { authorization: `Bearer ${BEARER}` },
      });
      expect(empty.status).toBe(200);
      expect(await empty.json()).toEqual([]);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});

// ── helpers ────────────────────────────────────────────────────────────────

interface Stub {
  server: Server;
  port: number;
}

/** Tiny HTTP stub: handler returns {status, body?} or undefined for 404. */
function createStubServer(
  handler: (req: { url?: string; headers: Record<string, string | undefined> }, body: string) => Promise<{ status: number; body?: string } | undefined>,
): Stub {
  const server = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      await new Promise<void>((r) => {
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => r());
      });
      const result = await handler(
        { url: req.url, headers: req.headers as Record<string, string | undefined> },
        Buffer.concat(chunks).toString("utf8"),
      );
      if (result) {
        res.writeHead(result.status, { "content-type": "application/json" });
        res.end(result.body ?? "{}");
      } else {
        res.writeHead(404);
        res.end("{}");
      }
    })();
  });
  return { server, port: 0 };
}

function listen(stub: Stub): Promise<void> {
  return new Promise((r) => stub.server.listen(0, "127.0.0.1", r));
}

function closeStub(stub: Stub): Promise<void> {
  return new Promise((r) => stub.server.close(() => r()));
}

function stubPort(stub: Stub): number {
  return (stub.server.address() as AddressInfo).port;
}

async function startGatewayWithAudit(): Promise<{ server: Server; base: string }> {
  const stubMcp = new McpServer({ name: "stub", version: "0" });
  const gateway = createGateway({
    mcpServer: stubMcp,
    token: BEARER,
    auditApi: createAuditApi({ auditPath }),
  });
  await new Promise<void>((r) => gateway.server.listen(0, "127.0.0.1", r));
  const port = (gateway.server.address() as AddressInfo).port;
  return { server: gateway.server, base: `http://127.0.0.1:${port}` };
}

async function waitFor(condition: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}
