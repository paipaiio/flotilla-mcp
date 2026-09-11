/**
 * Fan-out executor: run one command across a resolved server set with a
 * parallel / serial / rolling strategy, per-host results, and a rolling
 * circuit breaker.
 */
import type { DefaultsConfig, ExecOptions, FanoutResult, ServerConfig, Transport } from "./types.js";
export type Strategy = {
    kind: "parallel";
    concurrency?: number;
} | {
    kind: "serial";
    stopOnError?: boolean;
} | {
    kind: "rolling";
    batchSize?: number;
    maxBatchFailures?: number;
};
export declare function describeStrategy(s: Strategy): string;
export declare class Executor {
    private readonly transport;
    private readonly defaults;
    constructor(transport: Transport, defaults: DefaultsConfig);
    run(servers: ServerConfig[], command: string, strategy: Strategy, opts?: ExecOptions): Promise<FanoutResult>;
    private execOne;
    private runParallel;
    private runSerial;
    /**
     * Rolling execution: run in batches; when failures inside one batch exceed
     * maxBatchFailures, halt and mark every remaining host skipped. This is the
     * circuit breaker that keeps a bad deploy from reaching the whole fleet.
     */
    private runRolling;
}
