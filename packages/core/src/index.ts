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
