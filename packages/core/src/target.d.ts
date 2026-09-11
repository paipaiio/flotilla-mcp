/**
 * Target expressions: one addressing scheme shared by every multi-host tool.
 *
 * Grammar (comma or whitespace separated terms):
 *   all                 every server
 *   group:<name>        a configured [[groups]] entry, or a tier name (server.group)
 *   tag:<tag>           servers carrying the tag
 *   <name>              a single server by name
 *   !<term> / -<term>   exclusion, applied after the include union
 *
 * Examples:
 *   "web-1"
 *   "group:web-prod"
 *   "tag:web, tag:cn-east"      (union of two tag sets)
 *   "group:prod !web-3"         (all prod except web-3)
 *   ["web-1", "web-2"]          (explicit list)
 */
import type { FleetRegistry } from "./registry.js";
import type { ServerConfig } from "./types.js";
export type TargetTerm = {
    kind: "all";
} | {
    kind: "group";
    name: string;
} | {
    kind: "tag";
    tag: string;
} | {
    kind: "server";
    name: string;
};
export interface TargetExpr {
    include: TargetTerm[];
    exclude: TargetTerm[];
}
export declare class TargetError extends Error {
    constructor(message: string);
}
export declare function parseTarget(input: string | string[]): TargetExpr;
/**
 * Resolve a target expression to a deduplicated, deterministically ordered
 * server list. Throws TargetError on unknown names/groups/tags and on an
 * empty result.
 */
export declare function resolveTarget(registry: FleetRegistry, input: string | string[]): ServerConfig[];
