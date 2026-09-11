export function describeStrategy(s) {
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
    transport;
    defaults;
    constructor(transport, defaults) {
        this.transport = transport;
        this.defaults = defaults;
    }
    async run(servers, command, strategy, opts = {}) {
        let results;
        let halted = false;
        switch (strategy.kind) {
            case "parallel":
                results = await this.runParallel(servers, command, strategy.concurrency ?? this.defaults.maxConcurrency, opts);
                break;
            case "serial":
                ({ results, halted } = await this.runSerial(servers, command, strategy.stopOnError ?? false, opts));
                break;
            case "rolling":
                ({ results, halted } = await this.runRolling(servers, command, strategy.batchSize ?? this.defaults.rollingBatchSize, strategy.maxBatchFailures ?? this.defaults.rollingMaxBatchFailures, opts));
                break;
        }
        return {
            command,
            results,
            summary: summarize(results, halted, describeStrategy(strategy)),
        };
    }
    async execOne(server, command, opts) {
        const started = Date.now();
        try {
            return await this.transport.exec(server, command, {
                timeoutMs: opts.timeoutMs ?? this.defaults.commandTimeoutMs,
                workdir: opts.workdir ?? server.workdir,
            });
        }
        catch (err) {
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
    async runParallel(servers, command, concurrency, opts) {
        const results = new Array(servers.length);
        let cursor = 0;
        const lanes = Math.max(1, Math.min(concurrency, servers.length));
        const worker = async () => {
            for (;;) {
                const i = cursor++;
                if (i >= servers.length)
                    return;
                results[i] = await this.execOne(servers[i], command, opts);
            }
        };
        await Promise.all(Array.from({ length: lanes }, () => worker()));
        return results;
    }
    async runSerial(servers, command, stopOnError, opts) {
        const results = [];
        let halted = false;
        for (const server of servers) {
            if (halted) {
                results.push(skippedResult(server));
                continue;
            }
            const result = await this.execOne(server, command, opts);
            results.push(result);
            if (stopOnError && !result.ok)
                halted = true;
        }
        return { results, halted };
    }
    /**
     * Rolling execution: run in batches; when failures inside one batch exceed
     * maxBatchFailures, halt and mark every remaining host skipped. This is the
     * circuit breaker that keeps a bad deploy from reaching the whole fleet.
     */
    async runRolling(servers, command, batchSize, maxBatchFailures, opts) {
        const results = [];
        let halted = false;
        for (let offset = 0; offset < servers.length; offset += batchSize) {
            const batch = servers.slice(offset, offset + batchSize);
            if (halted) {
                for (const s of batch)
                    results.push(skippedResult(s));
                continue;
            }
            const batchResults = await this.runParallel(batch, command, batch.length, opts);
            results.push(...batchResults);
            const failures = batchResults.filter((r) => !r.ok).length;
            if (failures > maxBatchFailures)
                halted = true;
        }
        return { results, halted };
    }
}
function skippedResult(server) {
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
function summarize(results, halted, strategy) {
    return {
        total: results.length,
        succeeded: results.filter((r) => r.ok).length,
        failed: results.filter((r) => !r.ok && !r.skipped).length,
        skipped: results.filter((r) => r.skipped).length,
        halted,
        strategy,
    };
}
