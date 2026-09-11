import { describe, expect, it } from "vitest";
import { checkPathScope } from "../src/policy.js";

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
});
