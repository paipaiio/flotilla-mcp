import { describe, expect, it } from "vitest";
import {
  buildControlCommand,
  buildLogsCommand,
  buildStatusCommand,
  checkServiceScope,
  ServiceError,
  validateUnit,
} from "../src/service.js";
import { classifyCommand } from "../src/policy.js";

describe("validateUnit", () => {
  it("accepts plain and suffixed unit names", () => {
    expect(validateUnit("nginx")).toBe("nginx.service");
    expect(validateUnit("nginx.service")).toBe("nginx.service");
    expect(validateUnit("docker.socket")).toBe("docker.socket");
    expect(validateUnit("my-app_v2.timer")).toBe("my-app_v2.timer");
    expect(validateUnit("user@1000.service")).toBe("user@1000.service");
  });

  it("rejects shell metacharacters outright", () => {
    for (const bad of [
      "nginx; rm -rf /",
      "nginx && reboot",
      "$(evil).service",
      "nginx`id`",
      "nginx|cat",
      "nginx > /etc/x",
      "nginx service", // space
      "../etc",
    ]) {
      expect(() => validateUnit(bad)).toThrow(ServiceError);
    }
  });
});

describe("checkServiceScope", () => {
  const scoped = { name: "app-1", scopes: { services: ["myapp.service", "nginx.service"] } };

  it("allows listed units, refuses others", () => {
    expect(checkServiceScope(scoped, "myapp.service")).toBeNull();
    expect(checkServiceScope(scoped, "sshd.service")).toMatch(/outside/);
  });

  it("is exact match — no prefix bleed", () => {
    expect(checkServiceScope(scoped, "myapp.service.d")).toMatch(/outside/);
  });

  it("no scope configured means unrestricted at this layer", () => {
    expect(checkServiceScope({ name: "free-1" }, "anything.service")).toBeNull();
  });
});

describe("built commands classify correctly", () => {
  it("status and logs are read-only", () => {
    expect(classifyCommand(buildStatusCommand("nginx.service"))).toBe("read-only");
    expect(classifyCommand(buildLogsCommand("nginx.service", 50))).toBe("read-only");
  });

  it("every control action is destructive", () => {
    for (const action of ["start", "stop", "restart", "reload"] as const) {
      expect(classifyCommand(buildControlCommand("nginx.service", action))).toBe("destructive");
    }
  });

  it("log lines are clamped to a sane range", () => {
    expect(buildLogsCommand("u", 0)).toContain("-n 1 ");
    expect(buildLogsCommand("u", 99999)).toContain("-n 1000 ");
  });
});
