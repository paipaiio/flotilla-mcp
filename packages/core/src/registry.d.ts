/**
 * Fleet registry: holds validated servers and groups, answers lookups.
 */
import type { FleetConfig, GroupConfig, ServerConfig } from "./types.js";
export declare class FleetRegistry {
    readonly config: FleetConfig;
    private readonly serverMap;
    private readonly groupMap;
    constructor(config: FleetConfig);
    servers(): ServerConfig[];
    groups(): GroupConfig[];
    getServer(name: string): ServerConfig | undefined;
    hasGroup(name: string): boolean;
    /** All known tag values across the fleet, sorted. */
    allTags(): string[];
    /** All known tier values (server.group), sorted. */
    allTiers(): string[];
    /**
     * Resolve a configured group's match block against the fleet.
     * group/tags/names are ANDed together.
     */
    matchGroup(name: string): ServerConfig[];
}
