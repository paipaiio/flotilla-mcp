/** Never allowed, whatever the role or approval policy. */
const FORBIDDEN = [
    /\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+\/(\*|\/\*|\s*$)/, // rm -rf / (and /*)
    /\bmkfs\b/,
    /\bdd\b[^;&|]*\bof=\/dev\//,
    /\b(shutdown|poweroff|reboot)\b/,
    /\b(curl|wget)\b[^;&|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/, // curl|sh
    /:\(\)\s*\{/, // fork bomb
    /(^|[^>])(>>?)\s*[^;&|]*authorized_keys/,
    /(^|[^>])(>>?)\s*\/etc\/(cron|systemd)/,
    /\biptables\s+(-[a-zA-Z]+\s+)*-F\b/,
    /\bchmod\s+(-R\s+)?777\s+\/(\s|$)/,
];
const PRIVILEGED = /\b(sudo|su|doas|pkexec)\b/;
const DESTRUCTIVE = [
    /\brm\s+-[a-zA-Z]*[rf]/,
    /\bkill(all)?\b/,
    /\bpkill\b/,
    /\bsystemctl\s+(stop|restart|disable|mask|kill)\b/,
    /\bfind\b[^;&|]*(-delete|-exec\b|-execdir\b)/,
    /\bgit\s+push\b[^;&|]*--force/,
    /\bnpm\s+(publish|unpublish)\b/,
    /\b(apt|apt-get|yum|dnf|apk)\s+(remove|purge|autoremove)\b/,
    /\bdocker\s+(rm|rmi|system\s+prune|volume\s+rm)\b/,
    /\b(truncate|shred|wipefs)\b/,
];
/** First tokens that are read-only, possibly with per-binary argument rules below. */
const READ_ONLY_BINARIES = new Set([
    "ls", "cat", "grep", "egrep", "fgrep", "rg", "head", "tail", "wc", "stat",
    "df", "du", "free", "uptime", "uname", "hostname", "date", "whoami", "id",
    "ps", "env", "printenv", "pwd", "lsblk", "lscpu", "lsmem", "mount",
    "ip", "ss", "netstat", "ping", "traceroute", "dig", "nslookup", "host",
    "md5sum", "sha1sum", "sha256sum", "file", "which", "whereis", "type",
    "journalctl", "dmesg", "vmstat", "iostat", "nproc", "getent", "lsmod",
    "echo", "printf", "test", "true",
]);
const READ_ONLY_PREFIXES = [
    ["systemctl", /^\s*systemctl\s+(status|is-active|is-enabled|is-failed|list-units|list-unit-files|show|cat|help)\b/],
    ["git", /^\s*git\s+(status|log|diff|show|branch|remote|rev-parse|ls-files|tag)\b/],
    ["docker", /^\s*docker\s+(ps|images|inspect|logs|stats|version|info)\b/],
    ["nginx", /^\s*nginx\s+-(v|V|t)\b/],
    ["find", null], // handled specially: read-only unless write flags present
];
/** True only when the whole command is covered by the read-only allowlist. */
export function isReadOnly(command) {
    const cmd = command.trim();
    const first = cmd.split(/\s+/)[0] ?? "";
    if (first === "find") {
        return !/(-delete|-exec\b|-execdir\b|-ok\b|-fprint)/.test(cmd);
    }
    for (const [binary, pattern] of READ_ONLY_PREFIXES) {
        if (binary === "find")
            continue;
        if (first === binary)
            return pattern.test(cmd);
    }
    if (!READ_ONLY_BINARIES.has(first))
        return false;
    // Block write-ish redirections and chaining into unknown commands.
    if (/(^|[^0-9>])>>?/.test(cmd.replace(/2>&1/g, "")))
        return false;
    if (/[;|&]`|\$\(/.test(cmd)) {
        // Allow simple pipes between allowlisted read-only binaries only.
        const segments = cmd.split("|").map((s) => s.trim().split(/\s+/)[0] ?? "");
        return segments.every((seg) => READ_ONLY_BINARIES.has(seg));
    }
    return true;
}
export function classifyCommand(command) {
    const cmd = command.trim();
    if (!cmd)
        return "read-only";
    if (FORBIDDEN.some((re) => re.test(cmd)))
        return "forbidden";
    if (PRIVILEGED.test(cmd))
        return "privileged";
    if (isReadOnly(cmd))
        return "read-only";
    if (DESTRUCTIVE.some((re) => re.test(cmd)))
        return "destructive";
    return "safe";
}
/**
 * Role x tier matrix (same shape as ssh-mcp's defaults, overridable later):
 * viewer: read-only everywhere.
 * operator: + safe and destructive on dev/staging; + safe on prod.
 * admin: everything on dev/staging; no privileged on prod.
 */
const MATRIX = {
    viewer: { "*": ["read-only"] },
    operator: {
        prod: ["read-only", "safe"],
        "*": ["read-only", "safe", "destructive"],
    },
    admin: {
        prod: ["read-only", "safe", "destructive"],
        "*": ["read-only", "safe", "destructive", "privileged"],
    },
};
function allowedClasses(role, tier) {
    const row = MATRIX[role] ?? MATRIX["viewer"];
    return row[tier] ?? row["*"] ?? ["read-only"];
}
export function decide(command, ctx) {
    const commandClass = classifyCommand(command);
    if (commandClass === "forbidden") {
        return { allowed: false, reason: "Command matches the built-in never-allowed list", commandClass, needsApproval: false };
    }
    if (ctx.readOnly && commandClass !== "read-only") {
        return { allowed: false, reason: "Server is configured readOnly", commandClass, needsApproval: false };
    }
    if (!allowedClasses(ctx.role, ctx.tier).includes(commandClass)) {
        return {
            allowed: false,
            reason: `Role "${ctx.role}" on tier "${ctx.tier}" does not permit ${commandClass} commands`,
            commandClass,
            needsApproval: false,
        };
    }
    const gated = commandClass === "destructive" || commandClass === "privileged";
    switch (ctx.approvalMode) {
        case "auto":
            return { allowed: true, commandClass, needsApproval: false };
        case "ask-all":
            return { allowed: true, commandClass, needsApproval: true };
        case "deny":
            if (gated) {
                return { allowed: false, reason: `approvalMode "deny" refuses ${commandClass} commands`, commandClass, needsApproval: false };
            }
            return { allowed: true, commandClass, needsApproval: false };
        case "ask-destructive":
        default:
            return { allowed: true, commandClass, needsApproval: gated };
    }
}
