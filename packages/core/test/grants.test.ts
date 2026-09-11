import { describe, expect, it } from "vitest";
import { grantKey, GrantStore } from "../src/grants.js";

describe("grantKey", () => {
  it("is order-insensitive for hosts", () => {
    expect(grantKey("exec", "uptime", ["b", "a"])).toBe(grantKey("exec", "uptime", ["a", "b"]));
  });
  it("distinguishes tool, action, and host set", () => {
    const base = grantKey("exec", "uptime", ["a"]);
    expect(grantKey("exec-sudo", "uptime", ["a"])).not.toBe(base);
    expect(grantKey("exec", "whoami", ["a"])).not.toBe(base);
    expect(grantKey("exec", "uptime", ["a", "b"])).not.toBe(base);
  });
});

describe("GrantStore", () => {
  it("ttl 0 disables grants entirely", () => {
    const s = new GrantStore(0);
    expect(s.enabled).toBe(false);
    s.grant("k");
    expect(s.check("k")).toBe(false);
    expect(s.list()).toEqual([]);
  });

  it("a grant passes checks until it expires", () => {
    let now = 1_000_000;
    const s = new GrantStore(60_000, () => now);
    s.grant("k");
    expect(s.check("k")).toBe(true);
    now += 59_999;
    expect(s.check("k")).toBe(true);
    now += 2;
    expect(s.check("k")).toBe(false);
  });

  it("expiry reaps the entry so list stays clean", () => {
    let now = 0;
    const s = new GrantStore(100, () => now);
    s.grant("old");
    now += 200;
    expect(s.check("old")).toBe(false);
    expect(s.list()).toEqual([]);
  });

  it("revoke and clear work", () => {
    const s = new GrantStore(60_000);
    s.grant("a");
    s.grant("b");
    expect(s.revoke("a")).toBe(true);
    expect(s.check("a")).toBe(false);
    expect(s.check("b")).toBe(true);
    expect(s.clear()).toBe(1);
    expect(s.check("b")).toBe(false);
  });

  it("list sorts by expiry and includes timestamps", () => {
    let now = 1_000;
    const s = new GrantStore(500, () => now);
    s.grant("first");
    now += 100;
    s.grant("second");
    const live = s.list();
    expect(live.map((g) => g.key)).toEqual(["first", "second"]);
    expect(live[0]!.expiresAtMs).toBe(1_500);
    expect(live[1]!.expiresAtMs).toBe(1_600);
  });
});
