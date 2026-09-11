export class TargetError extends Error {
    constructor(message) {
        super(message);
        this.name = "TargetError";
    }
}
function parseTerm(raw) {
    let text = raw.trim();
    let negated = false;
    if (text.startsWith("!") || text.startsWith("-")) {
        negated = true;
        text = text.slice(1).trim();
    }
    if (!text)
        throw new TargetError(`Empty term in target expression "${raw}"`);
    if (text === "all")
        return { term: { kind: "all" }, negated };
    const colon = text.indexOf(":");
    if (colon > 0) {
        const prefix = text.slice(0, colon);
        const value = text.slice(colon + 1).trim();
        if (!value)
            throw new TargetError(`Term "${text}" is missing a value after "${prefix}:"`);
        if (prefix === "group")
            return { term: { kind: "group", name: value }, negated };
        if (prefix === "tag")
            return { term: { kind: "tag", tag: value }, negated };
        throw new TargetError(`Unknown target prefix "${prefix}:" — supported: group:, tag:`);
    }
    return { term: { kind: "server", name: text }, negated };
}
export function parseTarget(input) {
    const rawTerms = Array.isArray(input)
        ? input
        : input.split(/[\s,]+/).filter((t) => t.length > 0);
    if (rawTerms.length === 0) {
        throw new TargetError("Empty target: expected a server name, group:X, tag:X, or all");
    }
    const include = [];
    const exclude = [];
    for (const raw of rawTerms) {
        const { term, negated } = parseTerm(raw);
        (negated ? exclude : include).push(term);
    }
    if (include.length === 0) {
        throw new TargetError("Target has only exclusions; add an include term (e.g. all, group:X, or a server name)");
    }
    return { include, exclude };
}
function editDistance(a, b) {
    const m = a.length;
    const n = b.length;
    let prev = Array.from({ length: n + 1 }, (_, j) => j);
    for (let i = 1; i <= m; i++) {
        const cur = [i];
        for (let j = 1; j <= n; j++) {
            cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        }
        prev = cur;
    }
    return prev[n];
}
function closest(name, candidates) {
    const lower = name.toLowerCase();
    const exact = candidates.find((c) => c.toLowerCase() === lower);
    if (exact)
        return exact;
    const containing = candidates.find((c) => c.toLowerCase().includes(lower));
    if (containing)
        return containing;
    // Fall back to edit distance: suggest when the typo is small relative to length.
    let best;
    let bestDist = Infinity;
    for (const c of candidates) {
        const d = editDistance(lower, c.toLowerCase());
        if (d < bestDist) {
            bestDist = d;
            best = c;
        }
    }
    return best !== undefined && bestDist <= Math.max(2, Math.floor(lower.length / 3))
        ? best
        : undefined;
}
function resolveTerm(registry, term) {
    switch (term.kind) {
        case "all":
            return registry.servers();
        case "server": {
            const server = registry.getServer(term.name);
            if (!server) {
                const hint = closest(term.name, registry.servers().map((s) => s.name));
                throw new TargetError(`Unknown server "${term.name}"${hint ? ` — did you mean "${hint}"?` : ""}`);
            }
            return [server];
        }
        case "group": {
            if (registry.hasGroup(term.name))
                return registry.matchGroup(term.name);
            // Fall back to tier matching: group:prod means "servers whose group is prod".
            if (registry.allTiers().includes(term.name)) {
                return registry.servers().filter((s) => s.group === term.name);
            }
            const hint = closest(term.name, [...registry.groups().map((g) => g.name), ...registry.allTiers()]);
            throw new TargetError(`Unknown group "${term.name}"${hint ? ` — did you mean "${hint}"?` : ""}`);
        }
        case "tag": {
            const matched = registry.servers().filter((s) => s.tags.includes(term.tag));
            if (matched.length === 0 && !registry.allTags().includes(term.tag)) {
                const hint = closest(term.tag, registry.allTags());
                throw new TargetError(`Unknown tag "${term.tag}"${hint ? ` — did you mean "${hint}"?` : ""}`);
            }
            return matched;
        }
    }
}
/**
 * Resolve a target expression to a deduplicated, deterministically ordered
 * server list. Throws TargetError on unknown names/groups/tags and on an
 * empty result.
 */
export function resolveTarget(registry, input) {
    const expr = parseTarget(input);
    const included = new Map();
    for (const term of expr.include) {
        for (const s of resolveTerm(registry, term))
            included.set(s.name, s);
    }
    for (const term of expr.exclude) {
        for (const s of resolveTerm(registry, term))
            included.delete(s.name);
    }
    const result = [...included.values()].sort((a, b) => a.name.localeCompare(b.name));
    if (result.length === 0) {
        throw new TargetError(`Target "${Array.isArray(input) ? input.join(" ") : input}" matched no servers`);
    }
    return result;
}
