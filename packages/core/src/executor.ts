/**
 * Fan-out executor: run one command across a resolved server set with a
 * parallel / serial / rolling strategy, per-host results, and a rolling
 * circuit breaker.
 */
import type {
  DefaultsConfig,
  ExecOptions,
  ExecResult,
  FanoutResult,
  ServerConfig,
  Transport,
} from "./types.js";

export type Strategy =
  | { kind: "parallel"; concurrency?: number }
  | { kind: "serial"; stopOnError?: boolean }
  | { kind: "rolling"; batchSize?: number; maxBatchFailures?: number };

export function describeStrategy(s: Strategy): string {
  switch (s.kind) {
    case "parallel":
      return "parallel";
    case "serial":
      return "serial";
    case "rolling":
      return "rolling";
  }
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
    let results: ExecResult[];
    let halted = false;

    switch (strategy.kind) {
      case "parallel":
        results = await this.runParallel(
          servers,
          command,
          strategy.concurrency ?? this.defaults.maxConcurrency,
          opts,
        );
        break;
      case "serial":
        ({ results, halted } = await this.runSerial(
          servers,
          command,
          strategy.stopOnError ?? false,
          opts,
        ));
        break;
      case "rolling":
        ({ results, halted } = await this.runRolling(
          servers,
          command,
          strategy.batchSize ?? this.defaults.rollingBatchSize,
          strategy.maxBatchFailures ?? this.defaults.rollingMaxBatchFailures,
          opts,
        ));
        break;
    }

    return {
      command,
      results,
      summary: summarize(results, halted, describeStrategy(strategy)),
    };
  }

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

  private async runParallel(
    servers: ServerConfig[],
    command: string,
    concurrency: number,
    opts: ExecOptions,
  ): Promise<ExecResult[]> {
    const results: ExecResult[] = new Array(servers.length);
    let cursor = 0;
    const lanes = Math.max(1, Math.min(concurrency, servers.length));
    const worker = async (): Promise<void> => {
      for (;;) {
        const i = cursor++;
        if (i >= servers.length) return;
        results[i] = await this.execOne(servers[i]!, command, opts);
      }
    };
    await Promise.all(Array.from({ length: lanes }, () => worker()));
    return results;
  }

  private async runSerial(
    servers: ServerConfig[],
    command: string,
    stopOnError: boolean,
    opts: ExecOptions,
  ): Promise<{ results: ExecResult[]; halted: boolean }> {
    const results: ExecResult[] = [];
    let halted = false;
    for (const server of servers) {
      if (halted) {
        results.push(skippedResult(server));
        continue;
      }
      const result = await this.execOne(server, command, opts);
      results.push(result);
      if (stopOnError && !result.ok) halted = true;
    }
    return { results, halted };
  }

  /**
   * Rolling execution: run in batches; when failures inside one batch exceed
   * maxBatchFailures, halt and mark every remaining host skipped. This is the
   * circuit breaker that keeps a bad deploy from reaching the whole fleet.
   */
  private async runRolling(
    servers: ServerConfig[],
    command: string,
    batchSize: number,
    maxBatchFailures: number,
    opts: ExecOptions,
  ): Promise<{ results: ExecResult[]; halted: boolean }> {
    const results: ExecResult[] = [];
    let halted = false;

    for (let offset = 0; offset < servers.length; offset += batchSize) {
      const batch = servers.slice(offset, offset + batchSize);
      if (halted) {
        for (const s of batch) results.push(skippedResult(s));
        continue;
      }
      const batchResults = await this.runParallel(batch, command, batch.length, opts);
      results.push(...batchResults);
      const failures = batchResults.filter((r) => !r.ok).length;
      if (failures > maxBatchFailures) halted = true;
    }
    return { results, halted };
  }
}

function skippedResult(server: ServerConfig): ExecResult {
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

function summarize(results: ExecResult[], halted: boolean, strategy: string) {
  return {
    total: results.length,
    succeeded: results.filter((r) => r.ok).length,
    failed: results.filter((r) => !r.ok && !r.skipped).length,
    skipped: results.filter((r) => r.skipped).length,
    halted,
    strategy,
  };
}
