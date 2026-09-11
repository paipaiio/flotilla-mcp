export class FleetRegistry {
    config;
    serverMap;
    groupMap;
    constructor(config) {
        this.config = config;
        this.serverMap = new Map(config.servers.map((s) => [s.name, s]));
        this.groupMap = new Map(config.groups.map((g) => [g.name, g]));
    }
    servers() {
        return [...this.serverMap.values()];
    }
    groups() {
        return [...this.groupMap.values()];
    }
    getServer(name) {
        return this.serverMap.get(name);
    }
    hasGroup(name) {
        return this.groupMap.has(name);
    }
    /** All known tag values across the fleet, sorted. */
    allTags() {
        const tags = new Set();
        for (const s of this.serverMap.values()) {
            for (const t of s.tags)
                tags.add(t);
        }
        return [...tags].sort();
    }
    /** All known tier values (server.group), sorted. */
    allTiers() {
        const tiers = new Set();
        for (const s of this.serverMap.values())
            tiers.add(s.group);
        return [...tiers].sort();
    }
    /**
     * Resolve a configured group's match block against the fleet.
     * group/tags/names are ANDed together.
     */
    matchGroup(name) {
        const group = this.groupMap.get(name);
        if (!group)
            return [];
        const { group: tier, tags, names } = group.match;
        return this.servers().filter((s) => {
            if (tier !== undefined && s.group !== tier)
                return false;
            if (tags !== undefined && !tags.every((t) => s.tags.includes(t)))
                return false;
            if (names !== undefined && !names.includes(s.name))
                return false;
            return true;
        });
    }
}
