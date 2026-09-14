import { describe, expect, it } from "vitest";
import { buildCredentialReport, buildRuntimeInfo } from "../src/diagnostics.js";
import type { CredentialStatus } from "flotilla-core";

const statuses: CredentialStatus[] = [
  {
    server: "web-1",
    auth: "password",
    ready: false,
    source: "missing",
    detail: "credential missing",
    recoveryCommand: "flotilla keychain set web-1",
    restartRequired: false,
  },
  {
    server: "web-2",
    auth: "agent",
    ready: true,
    source: "ssh-agent",
    detail: "agent ready",
    restartRequired: false,
  },
];

describe("buildCredentialReport", () => {
  it("summarizes readiness and preserves the no-restart recovery action", () => {
    expect(buildCredentialReport(statuses)).toEqual({
      summary: { total: 2, ready: 1, missing: 1 },
      credentials: statuses,
    });
  });
});

describe("buildRuntimeInfo", () => {
  it("reports the binary/module/config split that diagnoses stale MCP processes", () => {
    const info = buildRuntimeInfo({
      version: "0.8.0",
      modulePath: "/app/dist/index.js",
      execPath: "/usr/bin/node",
      cwd: "/workspace",
      configPath: "/home/me/.config/flotilla/config.toml",
      configSource: "environment",
      configuredServers: 3,
      keychainAvailable: true,
    });
    expect(info).toMatchObject({
      name: "flotilla-mcp",
      version: "0.8.0",
      modulePath: "/app/dist/index.js",
      configSource: "environment",
      configuredServers: 3,
      keychainAvailable: true,
    });
  });
});
