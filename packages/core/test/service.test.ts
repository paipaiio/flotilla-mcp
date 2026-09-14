import { describe, expect, it } from "vitest";
import {
  buildControlCommand,
  buildLogsCommand,
  buildServiceManagerProbeCommand,
  buildStatusCommand,
  checkServiceScope,
  parseServiceManager,
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

  it("builds OpenRC status/control commands and keeps their risk classes", () => {
    expect(buildStatusCommand("nginx.service", "openrc")).toBe("rc-service nginx status");
    expect(buildControlCommand("nginx.service", "restart", "openrc")).toBe("rc-service nginx restart");
    expect(classifyCommand(buildStatusCommand("nginx.service", "openrc"))).toBe("read-only");
    expect(classifyCommand(buildControlCommand("nginx.service", "restart", "openrc"))).toBe("destructive");
  });

  it("explains that OpenRC has no generic per-service journal", () => {
    expect(() => buildLogsCommand("nginx.service", 50, "openrc")).toThrow(/logs-tail --path/);
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

describe("service manager detection", () => {
  it("uses a fixed probe and parses supported managers", () => {
    expect(buildServiceManagerProbeCommand()).toContain("rc-service");
    expect(parseServiceManager("systemd\n")).toBe("systemd");
    expect(parseServiceManager("openrc\n")).toBe("openrc");
  });

  it("rejects hosts without a supported service manager", () => {
    expect(() => parseServiceManager("unknown\n")).toThrow(ServiceError);
  });
});
