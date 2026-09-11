/**
 * Shared types for the Flotilla core engine.
 */

export type Role = "viewer" | "operator" | "admin";

export type ApprovalMode = "auto" | "ask-destructive" | "ask-all" | "deny";

export type AuthMethod = "agent" | "key" | "password";

/** Command risk classification, ordered from least to most dangerous. */
export type CommandClass =
  | "read-only"
  | "safe"
  | "destructive"
  | "privileged"
  | "forbidden";

/** Resource-level authorization scopes, second layer after the role x tier matrix. */
export interface ResourceScopes {
  /** Glob-ish path prefixes this server allows for file ops and path-touching commands. */
  paths?: string[];
  /** systemd units that service-* tools may touch. */
  services?: string[];
  /** Extra command regex patterns allowed on top of the role matrix. */
  commands?: string[];
}

export interface ServerConfig {
  name: string;
  host: string;
  port: number;
  user: string;
  auth: AuthMethod;
  /** Path to private key when auth = "key". "~" is expanded. */
  keyRef?: string;
  /**
   * Policy tier. Inferred from the server name when omitted
   * (prod/staging/dev/local/test/sandbox); an unrecognized name resolves to "prod",
   * the strictest tier.
   */
  group: string;
  tags: string[];
  role: Role;
  readOnly: boolean;
  workdir?: string;
  /** ProxyJump: name of another server to tunnel through. */
  via?: string;
  /** Pinned host key, e.g. "SHA256:...". The only host-key control that survives restarts. */
  trustedHostKey?: string;
  scopes?: ResourceScopes;
}

export interface GroupMatch {
  /** Tier value, matched against server.group. */
  group?: string;
  /** Server must carry ALL of these tags. */
  tags?: string[];
  /** Explicit server names. */
  names?: string[];
}

export interface GroupConfig {
  name: string;
  match: GroupMatch;
}

export interface DefaultsConfig {
  approvalMode: ApprovalMode;
  commandTimeoutMs: number;
  /** Max concurrent SSH executions for parallel fan-out. */
  maxConcurrency: number;
  /** Default batch size for rolling execution. */
  rollingBatchSize: number;
  /**
   * Failures tolerated inside one rolling batch before the run halts.
   * 0 = any failure in a batch halts the rollout (safest, the default).
   */
  rollingMaxBatchFailures: number;
}

export interface FleetConfig {
  defaults: DefaultsConfig;
  servers: ServerConfig[];
  groups: GroupConfig[];
}

export interface ExecResult {
  /** Server name (not raw host) so reports stay config-addressable. */
  host: string;
  ok: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  /** True when a rolling halt skipped this host before execution. */
  skipped?: boolean;
  /** Transport-level error message (connection refused, timeout, ...). */
  error?: string;
}

export interface FanoutSummary {
  total: number;
  succeeded: number;
  failed: number;
  skipped: number;
  /** True when a rolling run halted early due to batch failures. */
  halted: boolean;
  strategy: string;
}

export interface FanoutResult {
  command: string;
  results: ExecResult[];
  summary: FanoutSummary;
}

export interface ExecOptions {
  timeoutMs?: number;
  workdir?: string;
}

export interface TransferResult {
  host: string;
  ok: boolean;
  bytes: number;
  durationMs: number;
  skipped?: boolean;
  error?: string;
}

export interface TransferFanoutResult {
  localPath: string;
  remotePath: string;
  results: TransferResult[];
  summary: FanoutSummary;
}

/**
 * Transport abstraction. The executor and tool packs never touch ssh2 directly,
 * which keeps them testable with a mock transport.
 */
export interface Transport {
  exec(server: ServerConfig, command: string, opts: ExecOptions): Promise<ExecResult>;
  /** Upload a local file to remotePath via SFTP, creating the parent directory. */
  upload(
    server: ServerConfig,
    localPath: string,
    remotePath: string,
    opts: ExecOptions,
  ): Promise<TransferResult>;
  close(): Promise<void>;
}
