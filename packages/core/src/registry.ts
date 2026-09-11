/**
 * Fleet registry: holds validated servers and groups, answers lookups.
 */
import type { FleetConfig, GroupConfig, ServerConfig } from "./types.js";

export class FleetRegistry {
  readonly config: FleetConfig;
  private readonly serverMap: Map<string, ServerConfig>;
  private readonly groupMap: Map<string, GroupConfig>;

  constructor(config: FleetConfig) {
    this.config = config;
    this.serverMap = new Map(config.servers.map((s) => [s.name, s]));
    this.groupMap = new Map(config.groups.map((g) => [g.name, g]));
  }

  servers(): ServerConfig[] {
    return [...this.serverMap.values()];
  }

  groups(): GroupConfig[] {
    return [...this.groupMap.values()];
  }

  getServer(name: string): ServerConfig | undefined {
    return this.serverMap.get(name);
  }

  hasGroup(name: string): boolean {
    return this.groupMap.has(name);
  }

  /** All known tag values across the fleet, sorted. */
  allTags(): string[] {
    const tags = new Set<string>();
    for (const s of this.serverMap.values()) {
      for (const t of s.tags) tags.add(t);
    }
    return [...tags].sort();
  }

  /** All known tier values (server.group), sorted. */
  allTiers(): string[] {
    const tiers = new Set<string>();
    for (const s of this.serverMap.values()) tiers.add(s.group);
    return [...tiers].sort();
  }

  /**
   * Resolve a configured group's match block against the fleet.
   * group/tags/names are ANDed together.
   */
  matchGroup(name: string): ServerConfig[] {
    const group = this.groupMap.get(name);
    if (!group) return [];
    const { group: tier, tags, names } = group.match;
    return this.servers().filter((s) => {
      if (tier !== undefined && s.group !== tier) return false;
      if (tags !== undefined && !tags.every((t) => s.tags.includes(t))) return false;
      if (names !== undefined && !names.includes(s.name)) return false;
      return true;
    });
  }
}
