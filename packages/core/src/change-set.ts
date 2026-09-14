import { createHash } from "node:crypto";
import { checkPathScope } from "./policy.js";
import { checkServiceScope } from "./service.js";
import type { ApprovalMode, ServerConfig } from "./types.js";

export type ChangeSetRisk = "destructive" | "privileged";

export interface ChangeSetInput {
  tool: string;
  summary: string;
  targets: string[];
  paths?: string[];
  services?: string[];
  operations: string[];
  rollback: string;
  risk: ChangeSetRisk;
  /** Digests only: binds approval/JIT identity to content without displaying content. */
  payloadFingerprints?: string[];
}

export interface ChangeSet extends ChangeSetInput {
  id: string;
  paths: string[];
  services: string[];
  payloadFingerprints: string[];
}

export interface ChangeSetDecision {
  allowed: boolean;
  needsApproval: boolean;
  risk: ChangeSetRisk;
  reason?: string;
}

function uniqueSorted(values: string[] | undefined): string[] {
  return [...new Set(values ?? [])].sort();
}

/** Build a secret-free, stable identity for exactly one structured mutation request. */
export function createChangeSet(input: ChangeSetInput): ChangeSet {
  const canonical = {
    tool: input.tool,
    summary: input.summary,
    targets: uniqueSorted(input.targets),
    paths: uniqueSorted(input.paths),
    services: uniqueSorted(input.services),
    operations: [...input.operations],
    rollback: input.rollback,
    risk: input.risk,
    payloadFingerprints: uniqueSorted(input.payloadFingerprints),
  };
  if (!canonical.tool || !canonical.summary || canonical.targets.length === 0 || canonical.operations.length === 0) {
    throw new Error("Change set requires a tool, summary, target, and operation");
  }
  if (canonical.paths.length === 0 && canonical.services.length === 0) {
    throw new Error("Change set requires at least one path or service boundary");
  }
  for (const path of canonical.paths) {
    if (!path.startsWith("/") || /[\0\r\n]/.test(path)) {
      throw new Error(`Change set path must be an absolute single-line path`);
    }
  }
  if (canonical.operations.length > 200 || canonical.targets.length > 1_000) {
    throw new Error("Change set exceeds the supported operation or target limit");
  }
  const digest = createHash("sha256").update(JSON.stringify(canonical)).digest("hex").slice(0, 16);
  return { id: `cs_${digest}`, ...canonical };
}

/**
 * Authorize a structured mutation by declared resources rather than rejecting
 * its generated shell commands one-by-one. It only widens destructive
 * operator actions on prod; privileged production access remains unchanged.
 */
export function decideChangeSet(
  changeSet: ChangeSet,
  server: Pick<ServerConfig, "name" | "role" | "group" | "readOnly" | "scopes">,
  approvalMode: ApprovalMode,
): ChangeSetDecision {
  const base = { needsApproval: true, risk: changeSet.risk } as const;
  if (!changeSet.targets.includes(server.name)) {
    return { ...base, allowed: false, reason: `Server "${server.name}" is outside change set ${changeSet.id} targets` };
  }
  if (server.readOnly) return { ...base, allowed: false, reason: `Server "${server.name}" is configured readOnly` };
  if (server.role === "viewer") return { ...base, allowed: false, reason: `Role "viewer" cannot submit change sets` };
  if (approvalMode === "deny") return { ...base, allowed: false, reason: `approvalMode "deny" refuses change sets` };
  if (changeSet.risk === "privileged" && (server.role !== "admin" || server.group === "prod")) {
    return {
      ...base,
      allowed: false,
      reason: `Role "${server.role}" on tier "${server.group}" does not permit privileged change sets`,
    };
  }
  for (const path of changeSet.paths) {
    const reason = checkPathScope(server, path);
    if (reason) return { ...base, allowed: false, reason };
  }
  for (const service of changeSet.services) {
    const reason = checkServiceScope(server, service);
    if (reason) return { ...base, allowed: false, reason };
  }
  return { ...base, allowed: true };
}
