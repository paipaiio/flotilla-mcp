import { describe, expect, it } from "vitest";
import { diffFanout, formatDiff, normalizeOutput } from "../src/diff.js";
import type { ExecResult, FanoutResult } from "../src/types.js";

function ok(host: string, stdout: string, exitCode = 0): ExecResult {
  return { host, ok: exitCode === 0, exitCode, stdout, stderr: "", durationMs: 1 };
}

function fail(host: string, error: string): ExecResult {
  return { host, ok: false, exitCode: null, stdout: "", stderr: "", durationMs: 1, error };
}

function fanout(results: ExecResult[]): FanoutResult {
  return {
    command: "nginx -v",
    results,
    summary: {
      total: results.length,
      succeeded: results.filter((r) => r.ok).length,
      failed: results.filter((r) => !r.ok && !r.skipped).length,
      skipped: results.filter((r) => r.skipped).length,
      halted: false,
      strategy: "parallel",
    },
  };
}

describe("diffFanout", () => {
  it("reports consistency when all hosts agree", () => {
    const r = diffFanout(fanout([ok("a", "1.24.0"), ok("b", "1.24.0"), ok("c", "1.24.0")]));
    expect(r.consistent).toBe(true);
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0]!.hosts).toEqual(["a", "b", "c"]);
  });

  it("groups drifted hosts, largest group first", () => {
    const r = diffFanout(
      fanout([ok("a", "1.24.0"), ok("b", "1.24.0"), ok("c", "1.26.1"), ok("d", "1.22.0")]),
    );
    expect(r.consistent).toBe(false);
    expect(r.groups).toHaveLength(3);
    expect(r.groups[0]!.hosts).toEqual(["a", "b"]);
    expect(r.groups.map((g) => g.output)).toEqual(["1.24.0", "1.26.1", "1.22.0"]);
  });

  it("normalizes trailing whitespace and CRLF before grouping", () => {
    const r = diffFanout(fanout([ok("a", "v1\n"), ok("b", "v1\r\n"), ok("c", "v1   ")]));
    expect(r.consistent).toBe(true);
  });

  it("keeps failures out of output groups and marks the report inconsistent", () => {
    const r = diffFanout(fanout([ok("a", "v1"), ok("b", "v1"), fail("c", "connection refused")]));
    expect(r.consistent).toBe(false);
    expect(r.groups).toHaveLength(1);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0]).toMatchObject({ host: "c", error: "connection refused" });
  });

  it("treats same stdout but different exit codes as different groups", () => {
    const weird: ExecResult = { host: "b", ok: false, exitCode: 2, stdout: "v1", stderr: "", durationMs: 1 };
    const r = diffFanout(fanout([ok("a", "v1"), weird]));
    expect(r.groups).toHaveLength(1); // b is a failure (ok=false), not an output group
    expect(r.failures).toHaveLength(1);
  });

  it("skipped hosts are excluded entirely", () => {
    const skipped: ExecResult = {
      host: "c", ok: false, exitCode: null, stdout: "", stderr: "",
      durationMs: 0, skipped: true, error: "halted",
    };
    const r = diffFanout(fanout([ok("a", "v1"), ok("b", "v1"), skipped]));
    expect(r.consistent).toBe(true);
    expect(r.failures).toHaveLength(0);
  });
});

describe("formatDiff", () => {
  it("renders a consistent report compactly", () => {
    const r = diffFanout(fanout([ok("a", "1.24.0"), ok("b", "1.24.0")]));
    expect(formatDiff(r)).toMatch(/CONSISTENT — all 2 hosts agree/);
  });

  it("renders PARTIAL when successful hosts agree but some failed", () => {
    const r = diffFanout(fanout([ok("a", "v1"), ok("b", "v1"), fail("c", "timeout")]));
    const text = formatDiff(r);
    expect(text).toMatch(/PARTIAL — all 2 successful host\(s\) agree, 1 failed/);
    expect(text).not.toMatch(/DRIFT/);
  });

  it("renders drift groups and failures", () => {
    const r = diffFanout(fanout([ok("a", "v1"), ok("b", "v2"), fail("c", "timeout")]));
    const text = formatDiff(r);
    expect(text).toMatch(/DRIFT — 2 distinct outputs/);
    expect(text).toMatch(/failures \(1\)/);
    expect(text).toMatch(/c: timeout/);
  });
});

describe("normalizeOutput", () => {
  it("strips trailing whitespace, keeps interior", () => {
    expect(normalizeOutput("a  b\n\n")).toBe("a  b");
  });
});
