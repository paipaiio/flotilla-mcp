import { describe, expect, it } from "vitest";
import { checkPathScope, resolveRemotePathForScope } from "../src/policy.js";

const scoped = {
  name: "app-1",
  scopes: { paths: ["/opt/myapp/**", "/var/log/myapp/*", "/etc/myapp.conf"] },
};
const unscoped = { name: "free-1" };

describe("checkPathScope", () => {
  it("allows everything when no scope is configured", () => {
    expect(checkPathScope(unscoped, "/etc/passwd")).toBeNull();
  });

  it("** matches recursively under the prefix", () => {
    expect(checkPathScope(scoped, "/opt/myapp/dist/app.tar.gz")).toBeNull();
    expect(checkPathScope(scoped, "/opt/myapp")).toBeNull();
  });

  it("** does not bleed into sibling prefixes", () => {
    expect(checkPathScope(scoped, "/opt/myapp2/x")).toMatch(/outside/);
    expect(checkPathScope(scoped, "/opt/other")).toMatch(/outside/);
  });

  it("* matches direct children only", () => {
    expect(checkPathScope(scoped, "/var/log/myapp/app.log")).toBeNull();
    expect(checkPathScope(scoped, "/var/log/myapp/sub/deep.log")).toMatch(/outside/);
  });

  it("exact patterns match only themselves", () => {
    expect(checkPathScope(scoped, "/etc/myapp.conf")).toBeNull();
    expect(checkPathScope(scoped, "/etc/myapp.conf.bak")).toMatch(/outside/);
  });

  it("normalizes dot segments and blocks lexical traversal", () => {
    expect(checkPathScope(scoped, "/opt/myapp/sub/../app.js")).toBeNull();
    expect(checkPathScope(scoped, "/opt/myapp/../secret.txt")).toMatch(/outside/);
    expect(checkPathScope(scoped, "/opt/myapp/../../etc/passwd")).toMatch(/outside/);
  });

  it("requires absolute remote paths when a scope is configured", () => {
    expect(checkPathScope(scoped, "opt/myapp/app.js")).toMatch(/absolute/);
    expect(checkPathScope(scoped, "../opt/myapp/app.js")).toMatch(/absolute/);
  });

  it("checks a resolved real path so symlink escapes are refused", () => {
    expect(checkPathScope(scoped, "/opt/myapp/current/app.js", "/opt/releases/v2/app.js")).toMatch(/resolved path/);
    expect(checkPathScope(scoped, "/opt/myapp/current/app.js", "/opt/myapp/releases/v2/app.js")).toBeNull();
  });

  it("rejects NUL bytes and normalizes repeated separators", () => {
    expect(checkPathScope(scoped, "/opt/myapp/ok\0/etc/passwd")).toMatch(/NUL/);
    expect(checkPathScope(scoped, "//opt///myapp//app.js")).toBeNull();
  });
});

describe("resolveRemotePathForScope", () => {
  it("uses the target realpath when it exists", async () => {
    const result = await resolveRemotePathForScope("/opt/myapp/current/app.js", async (path) => {
      if (path === "/opt/myapp/current/app.js") return "/etc/app.js";
      throw new Error("missing");
    });
    expect(result).toBe("/etc/app.js");
  });

  it("resolves the nearest existing ancestor for a new upload destination", async () => {
    const calls: string[] = [];
    const result = await resolveRemotePathForScope("/opt/myapp/new/deep/app.js", async (path) => {
      calls.push(path);
      if (path === "/opt/myapp") return "/srv/releases/current";
      throw new Error("missing");
    });
    expect(result).toBe("/srv/releases/current/new/deep/app.js");
    expect(calls).toEqual([
      "/opt/myapp/new/deep/app.js",
      "/opt/myapp/new/deep",
      "/opt/myapp/new",
      "/opt/myapp",
    ]);
  });

  it("does not disguise permission, timeout, or cancellation failures as missing paths", async () => {
    const denied = Object.assign(new Error("permission denied"), { code: 3 });
    const calls: string[] = [];
    await expect(resolveRemotePathForScope(
      "/opt/myapp/private/app.js",
      async (path) => { calls.push(path); throw denied; },
      (error) => (error as { code?: unknown }).code === 2,
    )).rejects.toBe(denied);
    expect(calls).toEqual(["/opt/myapp/private/app.js"]);
  });
});
