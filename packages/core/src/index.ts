export type {
  AiAssessorConfig,
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
  RelayResult,
  ResourceScopes,
  Role,
  ServiceManager,
  ServerConfig,
  TransferFanoutResult,
  TransferResult,
  Transport,
} from "./types.js";

export {
  ConfigError,
  defaultConfigPath,
  ensureFleetConfigFile,
  inferTier,
  loadFleetConfig,
  parseFleetConfig,
  repairConfigPermissions,
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
  checkCommandScope,
  checkCommandPathScope,
  checkPathScope,
  classifyCommand,
  decide,
  decideForServer,
  isReadOnly,
  resolveRemotePathForScope,
  type PolicyContext,
  type PolicyDecision,
} from "./policy.js";

export { SshTransport, STRICT_ALGORITHMS, effectiveAlgorithms } from "./ssh.js";

export { BoundedText, OperationDrainer, withCancellation, type DrainResult } from "./io.js";

export {
  diffFanout,
  formatDiff,
  normalizeOutput,
  type DiffGroup,
  type DiffReport,
} from "./diff.js";

export {
  redactSensitiveText,
  type RedactedText,
  type SensitiveRedaction,
} from "./redaction.js";

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
  buildServiceManagerProbeCommand,
  buildStatusCommand,
  checkServiceScope,
  ServiceError,
  SERVICE_ACTIONS,
  parseServiceManager,
  validateUnit,
  type ResolvedServiceManager,
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
  resolveAuditPath,
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
  bootstrapKey,
  buildKeyInstallCommand,
  buildServerToml,
  OnboardError,
  probeServer,
  type BootstrapResult,
  type ProbeResult,
} from "./onboard.js";

export {
  fetchRemoteConfig,
  pullConfigToFile,
  RemoteConfigError,
  type PullResult,
} from "./remote.js";

export {
  ensureFleetKeyPair,
  migratePasswordServersInConfig,
  SetupRepairError,
  type FleetKeyPair,
  type KeyPairIO,
  type PasswordServerMigration,
} from "./setup-repair.js";

export {
  ConfigApplyError,
  applyStructuredChanges,
  runConfigTransaction,
  type AppliedConfigChange,
  type ConfigChange,
  type ConfigTransactionAdapter,
  type ConfigTransactionResult,
  type ConfigTransactionStage,
  type StructuredChangeResult,
  type StructuredConfigFormat,
} from "./config-apply.js";

export {
  createChangeSet,
  decideChangeSet,
  type ChangeSet,
  type ChangeSetDecision,
  type ChangeSetInput,
  type ChangeSetRisk,
} from "./change-set.js";

export {
  formatQuotaRefusal,
  QuotaCounter,
  type QuotaStatus,
} from "./quota.js";

export {
  defaultKeychainBackend,
  keychainAccount,
  resolveServerSecret,
  resolveServerSecretWithRepair,
  secretEnvNames,
  _resetKeychainCache,
  type KeychainBackend,
  type CredentialKind,
  type CredentialRepair,
} from "./keychain.js";

export {
  credentialRecoveryMessage,
  inspectFleetCredentials,
  inspectServerCredential,
  type CredentialInspectOptions,
  type CredentialSource,
  type CredentialStatus,
} from "./credentials.js";

export {
  grantKey,
  GrantStore,
  type GrantEntry,
} from "./grants.js";

export {
  AiAssessorError,
  assessAction,
  buildAssessmentPrompt,
  formatAssessmentCard,
  parseAssessmentResponse,
  type Assessment,
} from "./aiassess.js";

export {
  buildChecksumCommand,
  buildPathKindProbe,
  checkRelayPolicy,
  formatRelay,
  formatSyncPlan,
  formatSyncResult,
  parseChecksums,
  parsePathKind,
  planSync,
  relayFile,
  relPath,
  runSyncPlan,
  type ChecksumEntry,
  type PathKind,
  type RelayPolicyDecision,
  type SyncPlan,
  type SyncRunResult,
} from "./s2s.js";

export {
  buildTrustedCAInstallCommand,
  createCertAgentManager,
  DEFAULT_CERT_TTL_SECONDS,
  ensureFleetCA,
  signUserCertificate,
  type CertAgentManager,
  type FleetCA,
  type SignedCertificate,
} from "./certauth.js";
