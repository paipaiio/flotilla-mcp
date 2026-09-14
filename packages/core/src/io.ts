/** Bounded output and cancellation primitives shared by SSH/SFTP transports. */

export class BoundedText {
  private readonly chunks: Buffer[] = [];
  private retained = 0;
  bytesSeen = 0;
  truncated = false;

  constructor(
    private readonly maxBytes: number,
    private readonly streamName: string,
  ) {
    if (!Number.isInteger(maxBytes) || maxBytes < 1) throw new Error("maxBytes must be a positive integer");
  }

  append(value: Uint8Array | string): void {
    const chunk = Buffer.from(value);
    this.bytesSeen += chunk.length;
    const available = this.maxBytes - this.retained;
    if (available > 0) {
      const kept = chunk.subarray(0, available);
      this.chunks.push(kept);
      this.retained += kept.length;
    }
    if (chunk.length > available) this.truncated = true;
  }

  value(): string {
    const text = Buffer.concat(this.chunks, this.retained).toString("utf8");
    if (!this.truncated) return text;
    return `${text}\n[flotilla: ${this.streamName} truncated at ${this.maxBytes} bytes; ${this.bytesSeen - this.retained} bytes discarded]`;
  }
}

/** Race an operation against timeout/AbortSignal and invoke its concrete cancellation hook. */
export function withCancellation<T>(
  operation: Promise<T>,
  timeoutMs: number,
  label: string,
  cancel: () => void,
  signal?: AbortSignal,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    let cancelled = false;
    let timer: NodeJS.Timeout | undefined;
    const cancelOnce = () => {
      if (cancelled) return;
      cancelled = true;
      try { cancel(); } catch { /* cancellation is best-effort */ }
    };
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn();
    };
    const onAbort = () => finish(() => {
      cancelOnce();
      reject(new Error(`${label} aborted`));
    });

    if (signal?.aborted) { onAbort(); return; }
    signal?.addEventListener("abort", onAbort, { once: true });
    timer = setTimeout(() => finish(() => {
      cancelOnce();
      reject(new Error(`${label} timed out after ${timeoutMs}ms`));
    }), timeoutMs);
    operation.then(
      (value) => finish(() => resolve(value)),
      (error) => finish(() => reject(error)),
    );
  });
}

export interface DrainResult {
  drained: boolean;
  activeAtClose: number;
}

/** Track active operations, stop new work, and wait a bounded grace period for idle. */
export class OperationDrainer {
  private accepting = true;
  private active = 0;
  private readonly idleWaiters = new Set<() => void>();

  constructor(private readonly label: string) {}

  async run<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.accepting) throw new Error(`${this.label} is draining; new operations are not accepted`);
    this.active++;
    try {
      return await operation();
    } finally {
      this.active--;
      if (this.active === 0) {
        for (const wake of this.idleWaiters) wake();
        this.idleWaiters.clear();
      }
    }
  }

  stopAccepting(): void {
    this.accepting = false;
  }

  async drain(timeoutMs: number): Promise<DrainResult> {
    this.stopAccepting();
    if (this.active === 0) return { drained: true, activeAtClose: 0 };

    let wake!: () => void;
    let timer: NodeJS.Timeout | undefined;
    const idle = new Promise<void>((resolve) => {
      wake = resolve;
      this.idleWaiters.add(wake);
    });
    const timeout = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, Math.max(0, timeoutMs));
    });
    try {
      await Promise.race([idle, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
      this.idleWaiters.delete(wake);
    }
    return { drained: this.active === 0, activeAtClose: this.active };
  }
}
