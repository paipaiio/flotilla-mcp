export type {
  ApprovalMode,
  AuthMethod,
  CommandClass,
  DefaultsConfig,
  ExecOptions,
  ExecResult,
  FanoutResult,
  FanoutSummary,
  FleetConfig,
  GroupConfig,
  GroupMatch,
  ResourceScopes,
  Role,
  ServerConfig,
  TransferFanoutResult,
  TransferResult,
  Transport,
} from "./types.js";

export {
  ConfigError,
  defaultConfigPath,
  inferTier,
  loadFleetConfig,
  parseFleetConfig,
} from "./config.js";

export { FleetRegistry } from "./registry.js";

export {
  TargetError,
  parseTarget,
  resolveTarget,
  type TargetExpr,
  type TargetTerm,
} from "./target.js";

export {
  Executor,
  describeStrategy,
  resolveLocalPath,
  type Strategy,
} from "./executor.js";

export {
  checkPathScope,
  classifyCommand,
  decide,
  isReadOnly,
  type PolicyContext,
  type PolicyDecision,
} from "./policy.js";

export { SshTransport } from "./ssh.js";

export {
  diffFanout,
  formatDiff,
  normalizeOutput,
  type DiffGroup,
  type DiffReport,
} from "./diff.js";

export {
  analyzeDoctor,
  buildDoctorScript,
  buildMetricsScript,
  DEFAULT_THRESHOLDS,
  formatDoctor,
  formatMetrics,
  parseMetrics,
  type DiskUsage,
  type DoctorIssue,
  type DoctorThresholds,
  type MemInfo,
  type MetricsSnapshot,
  type ProcInfo,
  type Severity,
} from "./monitor.js";

export {
  buildControlCommand,
  buildLogsCommand,
  buildStatusCommand,
  checkServiceScope,
  ServiceError,
  SERVICE_ACTIONS,
  validateUnit,
  type ServiceAction,
} from "./service.js";

export {
  buildSessionCaptureCommand,
  buildSessionKillCommand,
  buildSessionListCommand,
  buildSessionSendCommand,
  buildSessionStartCommand,
  parseSessionList,
  SESSION_PREFIX,
  validateSessionName,
  type SessionInfo,
} from "./session.js";

export {
  interpolate,
  parseWorkflow,
  WorkflowError,
  WorkflowRunner,
  type PlannedStep,
  type PolicyChecker,
  type StepOutcome,
  type WorkflowDef,
  type WorkflowResult,
  type WorkflowStep,
} from "./workflow.js";

export {
  buildFileTailCommand,
  buildJournalTailCommand,
  filterTailOutput,
  type TailFilterResult,
} from "./logstream.js";

export {
  AuditLogger,
  auditFileSize,
  defaultAuditPath,
  type AuditEvent,
  type AuditKind,
} from "./audit.js";

export {
  buildSignalCommand,
  SignalError,
  SIGNALS,
  type SignalName,
} from "./signal.js";

export {
  appendServerToConfig,
  buildServerToml,
  OnboardError,
  probeServer,
  type ProbeResult,
} from "./onboard.js";

export {
  fetchRemoteConfig,
  pullConfigToFile,
  RemoteConfigError,
  type PullResult,
} from "./remote.js";
