import { describe, expect, it, vi } from "vitest";
import { LocalSecretBroker } from "../src/local-secret-broker.js";

async function waitFor<T>(read: () => T | undefined): Promise<T> {
  for (let index = 0; index < 100; index++) {
    const value = read();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("timed out waiting for local secret page");
}

describe("LocalSecretBroker", () => {
  it("captures a value once through loopback without returning it in HTML or MCP messages", async () => {
    let request: { params?: Record<string, unknown> } | undefined;
    const completed: string[] = [];
    const broker = new LocalSecretBroker({
      supportsUrlElicitation: () => true,
      createCompletionNotifier: (id) => async () => { completed.push(id); },
      makeToken: () => "local-secret-token",
      makeElicitationId: () => "local-secret-elicitation",
      timeoutMs: 2_000,
    });
    try {
      const capturing = broker.capture(
        {
          sender: {
            sendRequest: vi.fn(async (next) => {
              request = next as typeof request;
              return { action: "accept" as const };
            }),
          },
        },
        { target: "prod<&1", path: "/server/token", label: "API token" },
      );
      const captured = await waitFor(() => request);
      const message = String(captured.params?.message);
      const url = String(captured.params?.url);
      expect(message).toContain("/server/token");
      expect(message).not.toContain("top-secret-value");
      expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/secret\/local-secret-token$/);

      const form = await fetch(url);
      const html = await form.text();
      expect(form.headers.get("cache-control")).toBe("no-store");
      expect(form.headers.get("content-security-policy")).toContain("form-action 'self'");
      expect(html).toContain('type="password"');
      expect(html).toContain("prod&lt;&amp;1");
      expect(html).not.toContain("top-secret-value");

      const submit = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ value: "top-secret-value" }),
      });
      expect(submit.status).toBe(200);
      expect(await submit.text()).not.toContain("top-secret-value");
      await expect(capturing).resolves.toBe("top-secret-value");
      expect(completed).toEqual(["local-secret-elicitation"]);

      const replay = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ value: "replacement" }),
      });
      expect(replay.status).toBe(404);
    } finally {
      await broker.close();
    }
  });

  it("stays inactive when URL elicitation is absent and clears pending values on abort", async () => {
    const inactive = new LocalSecretBroker({
      supportsUrlElicitation: () => false,
      createCompletionNotifier: () => async () => undefined,
    });
    await expect(inactive.capture({ sender: { sendRequest: vi.fn() } }, {
      target: "prod-1", path: "/token", label: "token",
    })).resolves.toBeUndefined();

    let request: { params?: Record<string, unknown> } | undefined;
    const controller = new AbortController();
    const active = new LocalSecretBroker({
      supportsUrlElicitation: () => true,
      createCompletionNotifier: () => async () => undefined,
      makeToken: () => "abort-token",
      timeoutMs: 2_000,
    });
    try {
      const capturing = active.capture({
        signal: controller.signal,
        sender: { sendRequest: vi.fn(async (next) => {
          request = next as typeof request;
          return { action: "accept" as const };
        }) },
      }, { target: "prod-1", path: "/token", label: "token" });
      const url = String((await waitFor(() => request)).params?.url);
      controller.abort();
      await expect(capturing).resolves.toBeUndefined();
      expect((await fetch(url)).status).toBe(404);
    } finally {
      await inactive.close();
      await active.close();
    }
  });

  it("discards a submitted value when the client declines the elicitation", async () => {
    const broker = new LocalSecretBroker({
      supportsUrlElicitation: () => true,
      createCompletionNotifier: () => async () => undefined,
      makeToken: () => "declined-token",
      timeoutMs: 2_000,
    });
    try {
      const result = await broker.capture({
        sender: { sendRequest: vi.fn(async (request) => {
          const url = String((request as { params?: { url?: unknown } }).params?.url);
          await fetch(url, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ value: "declined-secret-value" }),
          });
          return { action: "decline" as const };
        }) },
      }, { target: "prod-1", path: "/token", label: "token" });
      expect(result).toBeUndefined();
    } finally {
      await broker.close();
    }
  });

  it("rejects invalid routes, methods, media types, empty values, and oversized forms", async () => {
    let request: { params?: Record<string, unknown> } | undefined;
    const broker = new LocalSecretBroker({
      supportsUrlElicitation: () => true,
      createCompletionNotifier: () => async () => undefined,
      makeToken: () => "guard-token",
      timeoutMs: 2_000,
    });
    try {
      const capturing = broker.capture({ sender: { sendRequest: vi.fn(async (next) => {
        request = next as typeof request;
        return { action: "accept" as const };
      }) } }, { target: "prod-1", path: "/token", label: "token" });
      const url = String((await waitFor(() => request)).params?.url);
      expect((await fetch(url.replace("guard-token", "missing-token"))).status).toBe(404);
      expect((await fetch(url, { method: "PUT" })).status).toBe(405);
      expect((await fetch(url, { method: "POST", headers: { "content-type": "text/plain" }, body: "value=x" })).status).toBe(415);
      expect((await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "value=" })).status).toBe(400);
      expect((await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ value: "x".repeat(65 * 1024) }),
      })).status).toBe(503);
      await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ value: "valid-value" }),
      });
      await expect(capturing).resolves.toBe("valid-value");
    } finally {
      await broker.close();
    }
  });

  it("clears the one-time route when the elicitation transport throws", async () => {
    let url = "";
    const broker = new LocalSecretBroker({
      supportsUrlElicitation: () => true,
      createCompletionNotifier: () => async () => undefined,
      makeToken: () => "transport-error-token",
    });
    try {
      await expect(broker.capture({ sender: { sendRequest: vi.fn(async (request) => {
        url = String((request as { params?: { url?: unknown } }).params?.url);
        throw new Error("client disconnected");
      }) } }, { target: "prod-1", path: "/token", label: "token" })).resolves.toBeUndefined();
      expect((await fetch(url)).status).toBe(404);
    } finally {
      await broker.close();
    }
  });
});
