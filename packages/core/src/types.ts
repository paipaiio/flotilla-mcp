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
  /**
   * Honor confirm=true as an approval channel. Default false — see config.ts.
   */
  allowConfirmFlag?: boolean;
  /** Idle pooled SSH connections are reaped after this long. Default 15min. */
  idleReapMs?: number;
  /**
   * Max command-bearing calls in a rolling 24h window (0/omitted = unlimited).
   * Enforced by the MCP server; persisted next to the config.
   */
  commandQuotaPerDay?: number;
}

export interface AuditConfig {
  /** JSONL file path. Default: <config dir>/audit.jsonl */
  path?: string;
  /** Hash-chain tamper evidence (sha256 of prevHash + record). Default true. */
  hashChain?: boolean;
  /** Entropy-based secret scan on string fields (slower). Default false. */
  entropyScan?: boolean;
}

export interface FleetConfig {
  defaults: DefaultsConfig;
  servers: ServerConfig[];
  groups: GroupConfig[];
  audit?: AuditConfig;
  remote?: RemoteConfig;
}

/** Remote config source: pull the fleet TOML from an HTTP(S) URL. */
export interface RemoteConfig {
  /** HTTP(S) URL serving the raw TOML (e.g. a GitHub/GitLab raw file URL). */
  url: string;
  /** Name of an env var holding a bearer token for the fetch. Never logged. */
  tokenEnv?: string;
  /** MCP server: auto-pull and hot-reload this often (0/omitted = manual only). */
  refreshMs?: number;
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
  /** Run via sudo; password is piped through stdin (never argv). */
  sudo?: boolean;
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

/** Result of one server-to-server relay copy (A -> control machine -> B). */
export interface RelayResult {
  source: string;
  dest: string;
  ok: boolean;
  bytes: number;
  durationMs: number;
  error?: string;
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
  /** Download remotePath to localPath via SFTP. */
  download(
    server: ServerConfig,
    remotePath: string,
    localPath: string,
    opts: ExecOptions,
  ): Promise<TransferResult>;
  /**
   * Server-to-server relay copy: stream src:srcPath to dst:dstPath through the
   * control machine's memory (SFTP read piped into SFTP write). Nothing is
   * written to local disk. Creates the destination parent directory.
   */
  relayCopy(
    src: ServerConfig,
    srcPath: string,
    dst: ServerConfig,
    dstPath: string,
    opts: ExecOptions,
  ): Promise<RelayResult>;
  close(): Promise<void>;
}
