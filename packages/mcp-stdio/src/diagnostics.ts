import type { CredentialStatus } from "flotilla-core";

export interface RuntimeInfoInput {
  version: string;
  modulePath: string;
  execPath: string;
  cwd: string;
  configPath: string;
  configSource: "argument" | "environment" | "platform-default";
  configuredServers: number;
  keychainAvailable: boolean;
}

/** Stable, secret-free payload for diagnosing stale binaries and config confusion. */
export function buildRuntimeInfo(input: RuntimeInfoInput) {
  return {
    name: "flotilla-mcp",
    ...input,
    nodeVersion: process.version,
  };
}

/** Stable summary shared by the MCP tool and CLI output. */
export function buildCredentialReport(credentials: CredentialStatus[]) {
  const ready = credentials.filter((credential) => credential.ready).length;
  return {
    summary: {
      total: credentials.length,
      ready,
      missing: credentials.length - ready,
    },
    credentials,
  };
}
