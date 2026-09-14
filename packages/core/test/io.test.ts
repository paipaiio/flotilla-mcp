import { describe, expect, it, vi } from "vitest";
import { BoundedText, OperationDrainer, withCancellation } from "../src/io.js";

describe("BoundedText", () => {
  it("caps retained bytes and appends a visible truncation marker", () => {
    const output = new BoundedText(5, "stdout");
    output.append(Buffer.from("hello"));
    output.append(Buffer.from(" world"));
    expect(output.truncated).toBe(true);
    expect(output.bytesSeen).toBe(11);
    expect(output.value()).toBe("hello\n[flotilla: stdout truncated at 5 bytes; 6 bytes discarded]");
  });

  it("does not add a marker below the limit", () => {
    const output = new BoundedText(10, "stderr");
    output.append(Buffer.from("ok"));
    expect(output.value()).toBe("ok");
  });
});

describe("withCancellation", () => {
  it("times out and invokes the transport cancellation hook", async () => {
    const cancel = vi.fn();
    await expect(withCancellation(new Promise(() => {}), 15, "SFTP upload", cancel)).rejects.toThrow(
      /SFTP upload timed out after 15ms/,
    );
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("honors AbortSignal and invokes cancellation", async () => {
    const controller = new AbortController();
    const cancel = vi.fn();
    const pending = withCancellation(new Promise(() => {}), 1000, "relay", cancel, controller.signal);
    controller.abort();
    await expect(pending).rejects.toThrow(/relay aborted/);
    expect(cancel).toHaveBeenCalledOnce();
  });
});

describe("OperationDrainer", () => {
  it("waits for active work and refuses work arriving after drain starts", async () => {
    const drainer = new OperationDrainer("SSH transport");
    let release!: () => void;
    const active = drainer.run(() => new Promise<void>((resolve) => { release = resolve; }));
    const draining = drainer.drain(1000);
    await expect(drainer.run(async () => "late")).rejects.toThrow(/draining/);
    release();
    await active;
    await expect(draining).resolves.toEqual({ drained: true, activeAtClose: 0 });
  });

  it("reports remaining operations when the grace period expires", async () => {
    const drainer = new OperationDrainer("SSH transport");
    void drainer.run(() => new Promise(() => {}));
    await expect(drainer.drain(10)).resolves.toEqual({ drained: false, activeAtClose: 1 });
  });
});
