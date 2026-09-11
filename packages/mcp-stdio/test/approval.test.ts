import { describe, expect, it, vi } from "vitest";
import { gateApproval, elicitationSupported, type ElicitSender } from "../src/approval.js";

/** Minimal McpServer stand-in: gateApproval only calls server.server.getClientCapabilities(). */
function fakeServer(caps?: Record<string, unknown>) {
  return {
    server: { getClientCapabilities: () => caps },
  } as never;
}

function fakeSender(result: { action: "accept" | "decline" | "cancel" } | Error): ElicitSender & {
  calls: number;
} {
  const state = { calls: 0 };
  return {
    calls: 0,
    get calls() {
      return state.calls;
    },
    sendRequest: vi.fn(async () => {
      state.calls++;
      if (result instanceof Error) throw result;
      return result;
    }),
  } as ElicitSender & { calls: number };
}

const ask = {
  action: "rm -rf /tmp/build",
  commandClass: "destructive",
  hosts: ["web-1", "web-2"],
  confirmFlag: undefined,
};

describe("gateApproval", () => {
  it("confirm=true approves only when the operator enabled the flag", async () => {
    const sender = fakeSender({ action: "accept" });
    const outcome = await gateApproval(fakeServer(undefined), sender, {
      ...ask,
      confirmFlag: true,
      allowConfirmFlag: true,
    });
    expect(outcome).toEqual({ kind: "approved", via: "confirm-flag" });
    expect(sender.sendRequest).not.toHaveBeenCalled();
  });

  it("confirm=true is refused by default — the model must not self-approve", async () => {
    const sender = fakeSender({ action: "accept" });
    const outcome = await gateApproval(fakeServer(undefined), sender, {
      ...ask,
      confirmFlag: true,
    });
    expect(outcome.kind).toBe("refused");
    if (outcome.kind === "refused") {
      expect(outcome.reason).toMatch(/confirm=true is disabled/);
      expect(outcome.reason).toMatch(/self-approval/);
    }
    expect(sender.sendRequest).not.toHaveBeenCalled();
  });

  it("elicitation accept approves", async () => {
    const sender = fakeSender({ action: "accept" });
    const outcome = await gateApproval(fakeServer({ elicitation: {} }), sender, ask);
    expect(outcome).toEqual({ kind: "approved", via: "elicitation" });
  });

  it("decline refuses", async () => {
    const sender = fakeSender({ action: "decline" });
    const outcome = await gateApproval(fakeServer({ elicitation: {} }), sender, ask);
    expect(outcome).toMatchObject({ kind: "refused", reason: "Approval declined by the user." });
  });

  it("cancel refuses", async () => {
    const sender = fakeSender({ action: "cancel" });
    const outcome = await gateApproval(fakeServer({ elicitation: {} }), sender, ask);
    expect(outcome.kind).toBe("refused");
  });

  it("clients without elicitation get a refusal; hint matches the flag setting", async () => {
    const sender = fakeSender({ action: "accept" });
    const off = await gateApproval(fakeServer({ tools: {} }), sender, ask);
    expect(off.kind).toBe("refused");
    if (off.kind === "refused") expect(off.reason).toMatch(/confirm=true is disabled/);

    const on = await gateApproval(fakeServer({ tools: {} }), sender, {
      ...ask,
      allowConfirmFlag: true,
    });
    expect(on.kind).toBe("refused");
    if (on.kind === "refused") expect(on.reason).toMatch(/confirm=true to approve/);
    expect(sender.sendRequest).not.toHaveBeenCalled();
  });

  it("elicitation errors fail closed with APPROVAL_UNAVAILABLE", async () => {
    const sender = fakeSender(new Error("Method not supported"));
    const outcome = await gateApproval(fakeServer({ elicitation: {} }), sender, ask);
    expect(outcome.kind).toBe("refused");
    if (outcome.kind === "refused") expect(outcome.reason).toMatch(/APPROVAL_UNAVAILABLE/);
  });

  it("unanswered prompts expire and refuse", async () => {
    const sender: ElicitSender = {
      sendRequest: vi.fn(() => new Promise(() => {})), // never resolves
    };
    const outcome = await gateApproval(fakeServer({ elicitation: {} }), sender, {
      ...ask,
      timeoutMs: 50,
    });
    expect(outcome.kind).toBe("refused");
    if (outcome.kind === "refused") expect(outcome.reason).toMatch(/expired/);
  });
});

describe("elicitationSupported", () => {
  it("detects the capability", () => {
    expect(elicitationSupported(fakeServer({ elicitation: {} }))).toBe(true);
    expect(elicitationSupported(fakeServer({ elicitation: { form: {} } }))).toBe(true);
    expect(elicitationSupported(fakeServer({}))).toBe(false);
    expect(elicitationSupported(fakeServer(undefined))).toBe(false);
  });
});
