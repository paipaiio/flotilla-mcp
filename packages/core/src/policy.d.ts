/**
 * Command classification (v0.1 heuristic layer).
 *
 * Order of evaluation: forbidden -> privileged -> read-only -> destructive -> safe.
 * The forbidden list is compiled in and NOT configurable off; v0.5 adds the
 * pluggable rule engine and shell-AST analysis on top of this.
 */
import type { CommandClass } from "./types.js";
/** True only when the whole command is covered by the read-only allowlist. */
export declare function isReadOnly(command: string): boolean;
export declare function classifyCommand(command: string): CommandClass;
export interface PolicyDecision {
    allowed: boolean;
    /** Why it was refused, when allowed is false. */
    reason?: string;
    commandClass: CommandClass;
    /** True when the command may run only after explicit confirmation. */
    needsApproval: boolean;
}
export interface PolicyContext {
    role: "viewer" | "operator" | "admin";
    tier: string;
    readOnly: boolean;
    approvalMode: "auto" | "ask-destructive" | "ask-all" | "deny";
}
export declare function decide(command: string, ctx: PolicyContext): PolicyDecision;
