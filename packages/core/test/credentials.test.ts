import { describe, expect, it } from "vitest";
import {
  credentialRecoveryMessage,
  inspectFleetCredentials,
  inspectServerCredential,
  type CredentialInspectOptions,
} from "../src/credentials.js";
import type { KeychainBackend } from "../src/keychain.js";
import type { ServerConfig } from "../src/types.js";

class FakeBackend implements KeychainBackend {
  constructor(private readonly values = new Map<string, string>()) {}
  async get(account: string) { return this.values.get(account); }
  async set(account: string, password: string) { this.values.set(account, password); }
  async remove(account: string) { return this.values.delete(account); }
}

function server(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    name: "web-1",
    host: "127.0.0.1",
    port: 22,
    user: "deploy",
    auth: "password",
    group: "dev",
    tags: [],
    role: "operator",
    readOnly: false,
    ...overrides,
  };
}

describe("inspectServerCredential", () => {
  it("reports the per-host environment source without revealing the value", async () => {
    const status = await inspectServerCredential(server(), {
      env: { FLOTILLA_WEB_1_PASSWORD: "top-secret" } as NodeJS.ProcessEnv,
      keychain: new FakeBackend(),
    });
    expect(status).toMatchObject({ ready: true, source: "env-host", restartRequired: false });
    expect(JSON.stringify(status)).not.toContain("top-secret");
  });

  it("reports the shared environment source", async () => {
    const status = await inspectServerCredential(server(), {
      env: { FLOTILLA_PASSWORD: "shared-secret" } as NodeJS.ProcessEnv,
      keychain: new FakeBackend(),
    });
    expect(status).toMatchObject({ ready: true, source: "env-shared" });
  });

  it("falls back to OS keychain and does not require an MCP restart", async () => {
    const status = await inspectServerCredential(server(), {
      env: {} as NodeJS.ProcessEnv,
      keychain: new FakeBackend(new Map([["web-1", "stored-secret"]])),
    });
    expect(status).toMatchObject({ ready: true, source: "os-keychain", restartRequired: false });
    expect(JSON.stringify(status)).not.toContain("stored-secret");
  });

  it("returns one executable recovery command when a password is missing", async () => {
    const status = await inspectServerCredential(server(), {
      env: {} as NodeJS.ProcessEnv,
      keychain: new FakeBackend(),
    });
    expect(status).toMatchObject({
      ready: false,
      source: "missing",
      recoveryCommand: "flotilla keychain set web-1",
      restartRequired: false,
    });
  });

  it("checks SSH agent availability", async () => {
    const ready = await inspectServerCredential(server({ auth: "agent" }), {
      env: { SSH_AUTH_SOCK: "/tmp/agent.sock" } as NodeJS.ProcessEnv,
      keychain: null,
    });
    const missing = await inspectServerCredential(server({ auth: "agent" }), {
      env: {} as NodeJS.ProcessEnv,
      keychain: null,
    });
    expect(ready).toMatchObject({ ready: true, source: "ssh-agent" });
    expect(missing).toMatchObject({ ready: false, source: "missing" });
  });

  it("checks key-file readability using the injected probe", async () => {
    const options: CredentialInspectOptions = {
      env: {} as NodeJS.ProcessEnv,
      keychain: null,
      keyReadable: (path) => path === "/keys/fleet",
    };
    const ready = await inspectServerCredential(server({ auth: "key", keyRef: "/keys/fleet" }), options);
    const missing = await inspectServerCredential(server({ auth: "key", keyRef: "/keys/missing" }), options);
    expect(ready).toMatchObject({ ready: true, source: "key-file" });
    expect(missing).toMatchObject({ ready: false, source: "missing" });
    expect(JSON.stringify([ready, missing])).not.toContain("/keys/");
  });
});

describe("inspectFleetCredentials", () => {
  it("reuses one backend and returns a fleet summary", async () => {
    const statuses = await inspectFleetCredentials(
      [server(), server({ name: "web-2", auth: "agent" })],
      { env: { SSH_AUTH_SOCK: "/tmp/agent.sock" } as NodeJS.ProcessEnv, keychain: new FakeBackend() },
    );
    expect(statuses.map((s) => [s.server, s.ready])).toEqual([
      ["web-1", false],
      ["web-2", true],
    ]);
  });
});

describe("credentialRecoveryMessage", () => {
  it("makes keychain the primary password recovery and explicitly says retry needs no restart", () => {
    const message = credentialRecoveryMessage("web-1");
    expect(message).toContain("CREDENTIAL_REQUIRED");
    expect(message).toContain("flotilla keychain set web-1");
    expect(message).toContain("retry without restarting");
    expect(message).toContain("FLOTILLA_WEB_1_PASSWORD");
  });
});
