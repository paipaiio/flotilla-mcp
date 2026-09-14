import { describe, expect, it, vi } from "vitest";
import type { AuditEvent, PolicyDecision, QuotaStatus, ServerConfig } from "flotilla-core";
import { ExecutionPipeline } from "../src/execution-pipeline.js";

const host = (name: string): ServerConfig => ({
  name, host: name, port: 22, user: "u", auth: "agent", group: "dev", tags: [], role: "admin", readOnly: false,
});

function harness(decision: PolicyDecision, quota: QuotaStatus = { limit: 10, used: 1, allowed: true }) {
  const order: string[] = [];
  const audits: AuditEvent[] = [];
  const approve = vi.fn(async () => { order.push("approve"); return { kind: "approved", via: "test" } as const; });
  const record = vi.fn(() => order.push("record"));
  const pipeline = new ExecutionPipeline({
    resolve: () => { order.push("resolve"); return [host("a"), host("b")]; },
    decide: () => { order.push("policy"); return decision; },
    approve,
    quota: { check: () => { order.push("quota"); return quota; }, record },
    audit: (event) => audits.push(event),
  });
  return { pipeline, order, audits, approve, record };
}

describe("ExecutionPipeline", () => {
  it("runs resolve → policy → approval → quota → record in one ordered boundary", async () => {
    const h = harness({ allowed: true, commandClass: "unknown", needsApproval: true });
    const result = await h.pipeline.prepare({ tool: "exec", target: "all", command: "custom deploy", quota: true });
    expect(result.ok).toBe(true);
    expect(h.order).toEqual(["resolve", "policy", "policy", "approve", "quota", "record"]);
  });

  it("audits policy denial and stops before approval or quota", async () => {
    const h = harness({ allowed: false, commandClass: "destructive", needsApproval: false, reason: "role denied" });
    const result = await h.pipeline.prepare({ tool: "exec", target: "all", command: "rm app", quota: true });
    expect(result).toMatchObject({ ok: false });
    expect(h.approve).not.toHaveBeenCalled();
    expect(h.record).not.toHaveBeenCalled();
    expect(h.audits[0]).toMatchObject({ kind: "decision", outcome: "deny", hosts: ["a", "b"] });
  });

  it("enforces required command class inside the same audited boundary", async () => {
    const h = harness({ allowed: true, commandClass: "destructive", needsApproval: true });
    const result = await h.pipeline.prepare({
      tool: "exec-read", target: "all", command: "systemctl restart app", requiredClass: "read-only", quota: true,
    });
    expect(result).toMatchObject({ ok: false });
    expect(h.order).toEqual(["resolve"]);
    expect(h.audits[0]?.reason).toMatch(/requires read-only/);
  });

  it("audits quota refusal and does not consume a unit", async () => {
    const h = harness(
      { allowed: true, commandClass: "read-only", needsApproval: false },
      { limit: 1, used: 1, allowed: false, resetAtMs: 1_800_000_000_000 },
    );
    const result = await h.pipeline.prepare({ tool: "exec-read", target: "all", command: "uptime", quota: true });
    expect(result).toMatchObject({ ok: false });
    expect(h.record).not.toHaveBeenCalled();
    expect(h.audits.at(-1)).toMatchObject({ commandClass: "quota", outcome: "deny" });
  });

  it("supports mandatory approval even when host policy does not request it", async () => {
    const h = harness({ allowed: true, commandClass: "read-only", needsApproval: false });
    await h.pipeline.prepare({ tool: "signal-process", target: "all", command: "kill -TERM 10", approval: "always" });
    expect(h.approve).toHaveBeenCalledOnce();
  });
});
