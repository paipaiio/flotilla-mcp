import { describe, expect, it } from "vitest";
import type { KeychainBackend } from "flotilla-core";
import {
  CredentialBroker,
  type CredentialRequestContext,
} from "../src/credential-broker.js";

class FakeKeychain implements KeychainBackend {
  readonly store = new Map<string, string>();
  async get(account: string) { return this.store.get(account); }
  async set(account: string, password: string) { this.store.set(account, password); }
  async remove(account: string) { return this.store.delete(account); }
}

async function waitFor<T>(read: () => T | undefined): Promise<T> {
  for (let i = 0; i < 100; i++) {
    const value = read();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timed out waiting for test state");
}

describe("CredentialBroker", () => {
  it("collects a password through a one-time loopback URL and stores it in the keychain", async () => {
    const keychain = new FakeKeychain();
    let request: { params?: Record<string, unknown> } | undefined;
    let requestCount = 0;
    const completed: string[] = [];
    const broker = new CredentialBroker({
      getKeychain: async () => keychain,
      supportsUrlElicitation: () => true,
      createCompletionNotifier: (id) => async () => { completed.push(id); },
      makeToken: () => "test-token",
      makeElicitationId: () => "elicit-1",
      timeoutMs: 2_000,
    });
    const context: CredentialRequestContext = {
      sender: {
        async sendRequest(next) {
          requestCount++;
          request = next as typeof request;
          return { action: "accept" as const };
        },
      },
    };

    try {
      const repairing = broker.runWithRequest(context, () =>
        broker.repair({ name: "web<&1" }, "password"),
      );
      const concurrentRepair = broker.runWithRequest(context, () =>
        broker.repair({ name: "web<&1" }, "password"),
      );
      const captured = await waitFor(() => request);
      const url = String(captured.params?.url);
      expect(captured.params).toMatchObject({
        mode: "url",
        elicitationId: "elicit-1",
      });
      expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/credential\/test-token$/);
      expect(requestCount).toBe(1);

      const form = await fetch(url);
      const html = await form.text();
      expect(form.status).toBe(200);
      expect(form.headers.get("cache-control")).toBe("no-store");
      expect(form.headers.get("referrer-policy")).toBe("no-referrer");
      expect(form.headers.get("x-frame-options")).toBe("DENY");
      expect(form.headers.get("content-security-policy")).toContain("form-action 'self'");
      expect(html).toContain('type="password"');
      expect(html).toContain("web&lt;&amp;1");
      expect(html).not.toContain("super-secret");

      const wrongMethod = await fetch(url, { method: "PUT" });
      expect(wrongMethod.status).toBe(405);
      expect(wrongMethod.headers.get("allow")).toBe("GET, POST");
      const wrongType = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(wrongType.status).toBe(415);
      const empty = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "password=",
      });
      expect(empty.status).toBe(400);

      const submit = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ password: "super-secret" }),
      });
      const success = await submit.text();
      expect(submit.status).toBe(200);
      expect(success).not.toContain("super-secret");
      expect(await repairing).toBe(true);
      expect(keychain.store.get("web<&1")).toBe("super-secret");
      expect(completed).toEqual(["elicit-1"]);
      expect(await concurrentRepair).toBe(true);

      const replay = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ password: "replacement" }),
      });
      expect(replay.status).toBe(404);
      expect(keychain.store.get("web<&1")).toBe("super-secret");
    } finally {
      await broker.close();
    }
  });

  it("stays inactive without URL elicitation or an active tool request", async () => {
    const keychain = new FakeKeychain();
    const broker = new CredentialBroker({
      getKeychain: async () => keychain,
      supportsUrlElicitation: () => false,
      createCompletionNotifier: () => async () => undefined,
    });
    try {
      await expect(broker.repair({ name: "web-1" }, "password")).resolves.toBe(false);
      await expect(
        broker.runWithRequest(
          { sender: { sendRequest: async () => ({ action: "accept" as const }) } },
          () => broker.repair({ name: "web-1" }, "password"),
        ),
      ).resolves.toBe(false);
      expect(keychain.store.size).toBe(0);
    } finally {
      await broker.close();
    }
  });

  it("cleans up a declined elicitation without saving anything", async () => {
    const keychain = new FakeKeychain();
    const broker = new CredentialBroker({
      getKeychain: async () => keychain,
      supportsUrlElicitation: () => true,
      createCompletionNotifier: () => async () => undefined,
      makeToken: () => "declined-token",
    });
    try {
      const repaired = await broker.runWithRequest(
        { sender: { sendRequest: async () => ({ action: "decline" as const }) } },
        () => broker.repair({ name: "web-1" }, "password"),
      );
      expect(repaired).toBe(false);
      expect(keychain.store.size).toBe(0);
    } finally {
      await broker.close();
    }
  });

  it("cancels a pending sudo-password page when the tool call is aborted", async () => {
    const keychain = new FakeKeychain();
    const controller = new AbortController();
    let url: string | undefined;
    const broker = new CredentialBroker({
      getKeychain: async () => keychain,
      supportsUrlElicitation: () => true,
      createCompletionNotifier: () => async () => undefined,
      timeoutMs: 2_000,
    });
    try {
      const repairing = broker.runWithRequest(
        {
          signal: controller.signal,
          sender: {
            async sendRequest(request) {
              url = String((request.params as Record<string, unknown>).url);
              return { action: "accept" as const };
            },
          },
        },
        () => broker.repair({ name: "web-1" }, "sudo"),
      );
      const pageUrl = await waitFor(() => url);
      expect(await (await fetch(pageUrl)).text()).toContain("sudo password");
      controller.abort();
      await expect(repairing).resolves.toBe(false);
      expect((await fetch(pageUrl)).status).toBe(404);
      expect(keychain.store.size).toBe(0);
    } finally {
      await broker.close();
    }
  });

  it("does not open a listener when the OS keychain is unavailable", async () => {
    let sent = false;
    const broker = new CredentialBroker({
      getKeychain: async () => null,
      supportsUrlElicitation: () => true,
      createCompletionNotifier: () => async () => undefined,
    });
    try {
      const repaired = await broker.runWithRequest(
        { sender: { sendRequest: async () => { sent = true; return { action: "accept" as const }; } } },
        () => broker.repair({ name: "web-1" }, "password"),
      );
      expect(repaired).toBe(false);
      expect(sent).toBe(false);
    } finally {
      await broker.close();
    }
  });

  it("preserves a successful browser save when the MCP reply channel closes afterward", async () => {
    const keychain = new FakeKeychain();
    let url: string | undefined;
    let rejectReply!: (error: Error) => void;
    const broker = new CredentialBroker({
      getKeychain: async () => keychain,
      supportsUrlElicitation: () => true,
      createCompletionNotifier: () => async () => undefined,
      timeoutMs: 2_000,
    });
    try {
      const repairing = broker.runWithRequest(
        {
          sender: {
            sendRequest(request) {
              url = String((request.params as Record<string, unknown>).url);
              return new Promise((_, reject) => { rejectReply = reject; });
            },
          },
        },
        () => broker.repair({ name: "web-1" }, "password"),
      );
      const pageUrl = await waitFor(() => url);
      expect((await fetch(pageUrl, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ password: "saved-before-disconnect" }),
      })).status).toBe(200);
      rejectReply(new Error("MCP connection closed"));
      await expect(repairing).resolves.toBe(true);
      expect(keychain.store.get("web-1")).toBe("saved-before-disconnect");
    } finally {
      await broker.close();
    }
  });
});
