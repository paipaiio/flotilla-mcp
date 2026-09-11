import type { ExecOptions, ExecResult, ServerConfig, Transport } from "./types.js";
export declare class SshTransport implements Transport {
    private readonly serversByName;
    private readonly pool;
    private readonly connecting;
    /** TOFU store: process-lifetime only, nothing written to disk. */
    private readonly knownHostKeys;
    constructor(serversByName: Map<string, ServerConfig>);
    exec(server: ServerConfig, command: string, opts: ExecOptions): Promise<ExecResult>;
    close(): Promise<void>;
    private drop;
    private connection;
    private connect;
    private connectConfig;
    /**
     * TOFU within the process: first sighting of a host key is accepted and
     * remembered; a later mismatch in the same process fails the connection.
     * A configured trustedHostKey pin always wins and is never overridden.
     */
    private verifyHostKey;
}
