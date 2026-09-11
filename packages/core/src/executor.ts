/**
 * Fan-out executor: run one command (or one file upload) across a resolved
 * server set with a parallel / serial / rolling strategy, per-host results,
 * and a rolling circuit breaker.
 */
import type {
  DefaultsConfig,
  ExecOptions,
  ExecResult,
  FanoutResult,
  FanoutSummary,
  ServerConfig,
  TransferFanoutResult,
  TransferResult,
  Transport,
} from "./types.js";

export type Strategy =
  | { kind: "parallel"; concurrency?: number }
  | { kind: "serial"; stopOnError?: boolean }
  | { kind: "rolling"; batchSize?: number; maxBatchFailures?: number };

export function describeStrategy(s: Strategy): string {
  return s.kind;
}

/** Anything the fan-out machinery can aggregate: per-host ok/skipped flags. */
interface HostOutcome {
  ok: boolean;
  skipped?: boolean;
}

export class Executor {
  constructor(
    private readonly transport: Transport,
    private readonly defaults: DefaultsConfig,
  ) {}

  async run(
    servers: ServerConfig[],
    command: string,
    strategy: Strategy,
    opts: ExecOptions = {},
  ): Promise<FanoutResult> {
    const { results, halted } = await this.fan<ExecResult>(
      servers,
      strategy,
      (s) => this.execOne(s, command, opts),
      (s) => skippedExec(s),
    );
    return {
      command,
      results,
      summary: summarize(results, halted, describeStrategy(strategy)),
    };
  }

  /**
   * Upload one local file to the same remotePath on every target.
   * Uploads overwrite — treat them like destructive fan-outs (rolling by
   * default for multi-host at the caller level).
   */
  async push(
    servers: ServerConfig[],
    localPath: string,
    remotePath: string,
    strategy: Strategy,
    opts: ExecOptions = {},
  ): Promise<TransferFanoutResult> {
    const { results, halted } = await this.fan<TransferResult>(
      servers,
      strategy,
      (s) => this.uploadOne(s, localPath, remotePath, opts),
      (s) => skippedTransfer(s),
    );
    return {
      localPath,
      remotePath,
      results,
      summary: summarize(results, halted, describeStrategy(strategy)),
    };
  }

  // ── per-host operations, converting transport errors into outcomes ──

  private async execOne(
    server: ServerConfig,
    command: string,
    opts: ExecOptions,
  ): Promise<ExecResult> {
    const started = Date.now();
    try {
      return await this.transport.exec(server, command, {
        timeoutMs: opts.timeoutMs ?? this.defaults.commandTimeoutMs,
        workdir: opts.workdir ?? server.workdir,
        sudo: opts.sudo,
      });
    } catch (err) {
      return {
        host: server.name,
        ok: false,
        exitCode: null,
        stdout: "",
        stderr: "",
        durationMs: Date.now() - started,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private async uploadOne(
    server: ServerConfig,
    localPath: string,
    remotePath: string,
    opts: ExecOptions,
  ): Promise<TransferResult> {
    const started = Date.now();
    try {
      return await this.transport.upload(server, localPath, remotePath, {
        timeoutMs: opts.timeoutMs ?? this.defaults.commandTimeoutMs,
      });
    } catch (err) {
      return {
        host: server.name,
        ok: false,
        bytes: 0,
        durationMs: Date.now() - started,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  // ── generic strategy machinery ──

  private async fan<T extends HostOutcome>(
    servers: ServerConfig[],
    strategy: Strategy,
    fn: (s: ServerConfig) => Promise<T>,
    skip: (s: ServerConfig) => T,
  ): Promise<{ results: T[]; halted: boolean }> {
    switch (strategy.kind) {
      case "parallel":
        return {
          results: await this.fanParallel(
            servers,
            fn,
            strategy.concurrency ?? this.defaults.maxConcurrency,
          ),
          halted: false,
        };
      case "serial":
        return this.fanSerial(servers, fn, skip, strategy.stopOnError ?? false);
      case "rolling":
        return this.fanRolling(
          servers,
          fn,
          skip,
          strategy.batchSize ?? this.defaults.rollingBatchSize,
          strategy.maxBatchFailures ?? this.defaults.rollingMaxBatchFailures,
        );
    }
  }

  private async fanParallel<T extends HostOutcome>(
    servers: ServerConfig[],
    fn: (s: ServerConfig) => Promise<T>,
    concurrency: number,
  ): Promise<T[]> {
    const results: T[] = new Array(servers.length);
    let cursor = 0;
    const lanes = Math.max(1, Math.min(concurrency, servers.length));
    const worker = async (): Promise<void> => {
      for (;;) {
        const i = cursor++;
        if (i >= servers.length) return;
        results[i] = await fn(servers[i]!);
      }
    };
    await Promise.all(Array.from({ length: lanes }, () => worker()));
    return results;
  }

  private async fanSerial<T extends HostOutcome>(
    servers: ServerConfig[],
    fn: (s: ServerConfig) => Promise<T>,
    skip: (s: ServerConfig) => T,
    stopOnError: boolean,
  ): Promise<{ results: T[]; halted: boolean }> {
    const results: T[] = [];
    let halted = false;
    for (const server of servers) {
      if (halted) {
        results.push(skip(server));
        continue;
      }
      const result = await fn(server);
      results.push(result);
      if (stopOnError && !result.ok) halted = true;
    }
    return { results, halted };
  }

  /**
   * Rolling: run in batches; when failures inside one batch exceed
   * maxBatchFailures, halt and mark every remaining host skipped. This is the
   * circuit breaker that keeps a bad deploy from reaching the whole fleet.
   */
  private async fanRolling<T extends HostOutcome>(
    servers: ServerConfig[],
    fn: (s: ServerConfig) => Promise<T>,
    skip: (s: ServerConfig) => T,
    batchSize: number,
    maxBatchFailures: number,
  ): Promise<{ results: T[]; halted: boolean }> {
    const results: T[] = [];
    let halted = false;

    for (let offset = 0; offset < servers.length; offset += batchSize) {
      const batch = servers.slice(offset, offset + batchSize);
      if (halted) {
        for (const s of batch) results.push(skip(s));
        continue;
      }
      const batchResults = await this.fanParallel(batch, fn, batch.length);
      results.push(...batchResults);
      const failures = batchResults.filter((r) => !r.ok).length;
      if (failures > maxBatchFailures) halted = true;
    }
    return { results, halted };
  }
}

function skippedExec(server: ServerConfig): ExecResult {
  return {
    host: server.name,
    ok: false,
    exitCode: null,
    stdout: "",
    stderr: "",
    durationMs: 0,
    skipped: true,
    error: "Skipped: rollout halted by circuit breaker",
  };
}

function skippedTransfer(server: ServerConfig): TransferResult {
  return {
    host: server.name,
    ok: false,
    bytes: 0,
    durationMs: 0,
    skipped: true,
    error: "Skipped: rollout halted by circuit breaker",
  };
}

function summarize(results: HostOutcome[], halted: boolean, strategy: string): FanoutSummary {
  return {
    total: results.length,
    succeeded: results.filter((r) => r.ok).length,
    failed: results.filter((r) => !r.ok && !r.skipped).length,
    skipped: results.filter((r) => r.skipped).length,
    halted,
    strategy,
  };
}
