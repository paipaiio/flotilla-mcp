import { describe, expect, it } from "vitest";
import {
  keychainAccount,
  resolveServerSecret,
  resolveServerSecretWithRepair,
  secretEnvNames,
  type KeychainBackend,
} from "../src/keychain.js";

class FakeBackend implements KeychainBackend {
  store = new Map<string, string>();
  async get(account: string) {
    return this.store.get(account);
  }
  async set(account: string, password: string) {
    this.store.set(account, password);
  }
  async remove(account: string) {
    return this.store.delete(account);
  }
}

const server = { name: "web-1" };

describe("keychainAccount", () => {
  it("login and sudo accounts are distinct", () => {
    expect(keychainAccount("web-1", false)).toBe("web-1");
    expect(keychainAccount("web-1", true)).toBe("web-1:sudo");
  });
});

describe("secretEnvNames", () => {
  it("slugs the server name and picks the right suffix", () => {
    expect(secretEnvNames("web-1", "password")).toEqual(["FLOTILLA_WEB_1_PASSWORD", "FLOTILLA_PASSWORD"]);
    expect(secretEnvNames("my.box", "sudo")).toEqual(["FLOTILLA_MY_BOX_SUDO_PASSWORD", "FLOTILLA_SUDO_PASSWORD"]);
  });
});

describe("resolveServerSecret cascade", () => {
  it("env var wins over the keychain (explicit operator choice)", async () => {
    const backend = new FakeBackend();
    await backend.set("web-1", "from-keychain");
    const env = { FLOTILLA_WEB_1_PASSWORD: "from-env" } as NodeJS.ProcessEnv;
    expect(await resolveServerSecret(server, "password", env, backend)).toBe("from-env");
  });

  it("generic env var applies when no per-host one exists", async () => {
    const env = { FLOTILLA_SUDO_PASSWORD: "generic-sudo" } as NodeJS.ProcessEnv;
    expect(await resolveServerSecret(server, "sudo", env, null)).toBe("generic-sudo");
  });

  it("falls back to the keychain when env is empty", async () => {
    const backend = new FakeBackend();
    await backend.set("web-1:sudo", "kc-sudo");
    expect(await resolveServerSecret(server, "sudo", {} as NodeJS.ProcessEnv, backend)).toBe("kc-sudo");
  });

  it("returns undefined when neither env nor keychain has it", async () => {
    expect(await resolveServerSecret(server, "password", {} as NodeJS.ProcessEnv, new FakeBackend())).toBeUndefined();
    expect(await resolveServerSecret(server, "password", {} as NodeJS.ProcessEnv, null)).toBeUndefined();
  });

  it("a throwing backend degrades to undefined, never breaks auth", async () => {
    const broken: KeychainBackend = {
      async get() { throw new Error("no secret service"); },
      async set() { throw new Error("nope"); },
      async remove() { throw new Error("nope"); },
    };
    expect(await resolveServerSecret(server, "password", {} as NodeJS.ProcessEnv, broken)).toBeUndefined();
  });
});

describe("resolveServerSecretWithRepair", () => {
  it("repairs a missing credential and resolves it again for the same operation", async () => {
    const backend = new FakeBackend();
    let resolutions = 0;
    let repairs = 0;
    const resolved = await resolveServerSecretWithRepair(
      server,
      "password",
      async () => {
        resolutions++;
        return backend.get("web-1");
      },
      async () => {
        repairs++;
        await backend.set("web-1", "saved-once");
        return true;
      },
    );

    expect(resolved).toBe("saved-once");
    expect(resolutions).toBe(2);
    expect(repairs).toBe(1);
  });

  it("does not retry resolution when repair is declined", async () => {
    let resolutions = 0;
    const resolved = await resolveServerSecretWithRepair(
      server,
      "password",
      async () => {
        resolutions++;
        return undefined;
      },
      async () => false,
    );

    expect(resolved).toBeUndefined();
    expect(resolutions).toBe(1);
  });

  it("does not prompt when the credential already exists", async () => {
    let repairs = 0;
    const resolved = await resolveServerSecretWithRepair(
      server,
      "password",
      async () => "already-present",
      async () => {
        repairs++;
        return true;
      },
    );

    expect(resolved).toBe("already-present");
    expect(repairs).toBe(0);
  });
});
