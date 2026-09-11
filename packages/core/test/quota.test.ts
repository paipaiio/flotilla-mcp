import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { formatQuotaRefusal, QuotaCounter } from "../src/quota.js";

const DAY = 24 * 60 * 60 * 1000;

let dir: string;
let statePath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flotilla-quota-"));
  statePath = join(dir, "quota-state.json");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("QuotaCounter", () => {
  it("limit 0 means disabled: always allowed, nothing persisted", () => {
    const q = new QuotaCounter(statePath, 0);
    expect(q.enabled).toBe(false);
    expect(q.check().allowed).toBe(true);
    q.record();
    expect(q.check().used).toBe(0);
  });

  it("allows up to the limit, then refuses", () => {
    const q = new QuotaCounter(statePath, 2);
    q.record();
    q.record();
    const status = q.check();
    expect(status.allowed).toBe(false);
    expect(status.used).toBe(2);
    expect(status.resetAtMs).toBeGreaterThan(Date.now());
  });

  it("refusal message names the numbers and the reset time", () => {
    const q = new QuotaCounter(statePath, 1);
    q.record();
    const msg = formatQuotaRefusal(q.check());
    expect(msg).toContain("1/1");
    expect(msg).toContain("commandQuotaPerDay");
  });

  it("the window rolls: calls older than 24h stop counting", () => {
    let now = 1_000_000_000_000;
    const q = new QuotaCounter(statePath, 1, () => now);
    q.record();
    expect(q.check().allowed).toBe(false);
    now += DAY + 1; // a day later the old call ages out
    const status = q.check();
    expect(status.allowed).toBe(true);
    expect(status.used).toBe(0);
  });

  it("persists across instances (restart does not reset the quota)", () => {
    const a = new QuotaCounter(statePath, 3);
    a.record();
    a.record();
    const b = new QuotaCounter(statePath, 3);
    expect(b.check().used).toBe(2);
  });

  it("corrupt state starts fresh instead of crashing", () => {
    writeFileSync(statePath, "not json at all", "utf8");
    const q = new QuotaCounter(statePath, 1);
    expect(q.check().allowed).toBe(true);
    expect(q.check().used).toBe(0);
  });

  it("garbage entries in state are filtered out", () => {
    writeFileSync(statePath, JSON.stringify({ t: [Date.now(), "junk", -1, {}] }), "utf8");
    const q = new QuotaCounter(statePath, 5);
    expect(q.check().used).toBe(1); // Date.now() counts; -1 is outside the window
  });
});
