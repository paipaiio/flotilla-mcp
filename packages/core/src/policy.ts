/**
 * Structured shell-command classification.
 *
 * Quote-aware nodes prevent shell operators inside data from being mistaken
 * for executable commands. Unknown commands are distinct and approval-gated.
 */
import { posix } from "node:path";
import type { ApprovalMode, CommandClass, ServerConfig } from "./types.js";

/** Never allowed, whatever the role or approval policy. */
const PRIVILEGED = /\b(sudo|su|doas|pkexec)\b/;

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

const READ_ONLY_PREFIXES: [string, RegExp][] = [
  ["systemctl", /^\s*systemctl\s+(status|is-active|is-enabled|is-failed|list-units|list-unit-files|show|cat|help)\b/],
  ["rc-service", /^\s*rc-service\s+\S+\s+status\b/],
  ["git", /^\s*git\s+(status|log|diff|show|branch|remote|rev-parse|ls-files|tag)\b/],
  ["docker", /^\s*docker\s+(ps|images|inspect|logs|stats|version|info)\b/],
  ["nginx", /^\s*nginx\s+-(v|V|t)\b/],
  ["find", null as unknown as RegExp], // handled specially: read-only unless write flags present
];

const SAFE_PREFIXES: [string, RegExp][] = [
  ["git", /^git\s+(pull|fetch)\b/],
  ["npm", /^npm\s+(ci|install|update)\b/],
  ["pnpm", /^pnpm\s+(install|update)\b/],
  ["yarn", /^yarn\s+(install|up|upgrade)\b/],
];

interface ShellNode {
  tokens: string[];
  separatorAfter?: ";" | "&&" | "||" | "|" | "&" | "newline";
  writeRedirect: boolean;
}

interface ShellAnalysis {
  nodes: ShellNode[];
  dynamic: boolean;
  malformed: boolean;
}

/** Quote-aware shell lexer. The result is an AST-like list of simple commands and operators. */
function analyzeShell(command: string): ShellAnalysis {
  const nodes: ShellNode[] = [];
  let tokens: string[] = [];
  // Same token boundaries as `tokens`, but containing only unquoted,
  // unescaped syntax. This keeps `>` inside data from becoming a redirect.
  let syntaxTokens: string[] = [];
  let token = "";
  let syntaxToken = "";
  let started = false;
  let quote: "'" | '"' | null = null;
  let escaped = false;
  let dynamic = false;

  const flushToken = () => {
    if (started) {
      tokens.push(token);
      syntaxTokens.push(syntaxToken);
    }
    token = "";
    syntaxToken = "";
    started = false;
  };
  const hasWriteRedirect = (parts: string[]): boolean => {
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]!;
      if (!part.includes(">")) continue;
      if (/^[012]?>&[012-]$/.test(part)) continue;
      if (/^2?>\/dev\/null$/.test(part)) continue;
      if (/^2?>$/.test(part) && parts[i + 1] === "/dev/null") { i++; continue; }
      return true;
    }
    return false;
  };
  const flushNode = (separatorAfter?: ShellNode["separatorAfter"]) => {
    flushToken();
    if (tokens.length > 0) nodes.push({ tokens, separatorAfter, writeRedirect: hasWriteRedirect(syntaxTokens) });
    tokens = [];
    syntaxTokens = [];
  };

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    if (escaped) { token += ch; started = true; escaped = false; continue; }
    if (quote === "'") {
      if (ch === "'") quote = null;
      else token += ch;
      started = true;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === "\\") escaped = true;
      else {
        if (ch === "`" || (ch === "$" && command[i + 1] === "(")) dynamic = true;
        token += ch;
      }
      started = true;
      continue;
    }
    if (ch === "\\") { escaped = true; started = true; continue; }
    if (ch === "'" || ch === '"') { quote = ch; started = true; continue; }
    if (ch === "`" || (ch === "$" && command[i + 1] === "(")) dynamic = true;
    if (ch === "\n") { flushNode("newline"); continue; }
    if (/\s/.test(ch)) { flushToken(); continue; }
    if (ch === ";") { flushNode(";"); continue; }
    if (ch === "&" && token.endsWith(">")) { token += ch; syntaxToken += ch; started = true; continue; }
    if (ch === "&" || ch === "|") {
      const doubled = command[i + 1] === ch;
      flushNode(doubled ? (ch === "&" ? "&&" : "||") : ch);
      if (doubled) i++;
      continue;
    }
    token += ch;
    syntaxToken += ch;
    started = true;
  }
  flushNode();
  return { nodes, dynamic, malformed: quote !== null || escaped };
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

function commandTokens(node: ShellNode): string[] {
  const tokens = [...node.tokens];
  while (tokens[0] && ASSIGNMENT.test(tokens[0])) tokens.shift();
  while (["command", "builtin", "nohup"].includes(tokens[0] ?? "")) tokens.shift();
  if (tokens[0] === "env") {
    tokens.shift();
    while (tokens[0] && (ASSIGNMENT.test(tokens[0]) || tokens[0]!.startsWith("-"))) tokens.shift();
    // `env ... command <binary>` is a common composition of benign wrappers;
    // unwrap the inner shell builtin before classifying the actual executable.
    while (["command", "builtin", "nohup"].includes(tokens[0] ?? "")) tokens.shift();
  }
  return tokens;
}

function normalizedNode(node: ShellNode): string {
  return commandTokens(node).join(" ");
}

function unwrapPrivilege(tokens: string[]): string[] {
  if (!["sudo", "doas", "pkexec"].includes(tokens[0] ?? "")) return tokens;
  const rest = tokens.slice(1);
  while (rest[0]?.startsWith("-")) {
    const option = rest.shift()!;
    if (["-u", "-g", "-h", "-p", "-C", "-T"].includes(option) && rest.length > 0) rest.shift();
  }
  return rest;
}

function isForbiddenNode(node: ShellNode, next?: ShellNode): boolean {
  const tokens = unwrapPrivilege(commandTokens(node));
  const exe = tokens[0] ?? "";
  const args = tokens.slice(1);
  if (["sh", "bash", "zsh"].includes(exe)) {
    const commandFlag = args.findIndex((arg) => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(arg));
    if (commandFlag >= 0 && args[commandFlag + 1]) {
      if (classifyCommand(args[commandFlag + 1]!) === "forbidden") return true;
    }
  }
  if (/^mkfs(?:\.|$)/.test(exe) || ["shutdown", "poweroff", "reboot"].includes(exe)) return true;
  if (exe === "rm") {
    const flags = args.filter((a) => /^-[^-]/.test(a)).join("");
    if (flags.includes("r") && flags.includes("f") && args.some((a) => /^\/{1,2}\*?$/.test(a))) return true;
  }
  if (exe === "dd" && args.some((a) => /^of=\/dev\//.test(a))) return true;
  if (exe === "iptables" && args.includes("-F")) return true;
  if (exe === "chmod" && args.includes("777") && args.includes("/")) return true;
  if (node.writeRedirect && tokens.some((t) => /authorized_keys|^\/etc\/(cron|systemd)/.test(t))) return true;
  if (["curl", "wget"].includes(exe) && node.separatorAfter === "|") {
    const nextExe = unwrapPrivilege(commandTokens(next ?? { tokens: [], writeRedirect: false }))[0];
    if (["sh", "bash", "zsh"].includes(nextExe ?? "")) return true;
  }
  return false;
}

function isDestructiveNode(node: ShellNode): boolean {
  if (node.writeRedirect) return true;
  const tokens = commandTokens(node);
  const exe = tokens[0] ?? "";
  const args = tokens.slice(1);
  if (exe === "rm" && args.some((a) => /^-[a-zA-Z]*[rf]/.test(a))) return true;
  if (["kill", "killall", "pkill", "truncate", "shred", "wipefs"].includes(exe)) return true;
  if (exe === "systemctl" && /^(start|stop|restart|reload|enable|disable|mask|kill)$/.test(args[0] ?? "")) return true;
  if (exe === "rc-service" && /^(start|stop|restart|reload)$/.test(args[1] ?? "")) return true;
  if (exe === "find" && args.some((a) => ["-delete", "-exec", "-execdir"].includes(a))) return true;
  if (exe === "git" && args[0] === "push" && args.some((a) => a.startsWith("--force"))) return true;
  if (exe === "npm" && ["publish", "unpublish"].includes(args[0] ?? "")) return true;
  if (["apt", "apt-get", "yum", "dnf", "apk"].includes(exe) && ["remove", "purge", "autoremove"].includes(args[0] ?? "")) return true;
  if (exe === "docker" && ["rm", "rmi"].includes(args[0] ?? "")) return true;
  if (exe === "docker" && args[0] === "system" && args[1] === "prune") return true;
  if (exe === "docker" && args[0] === "volume" && args[1] === "rm") return true;
  return false;
}

/** True when ONE simple command (no chaining) is covered by the allowlist. */
function isReadOnlyNode(node: ShellNode): boolean {
  if (node.writeRedirect) return false;
  const tokens = commandTokens(node);
  const first = tokens[0] ?? "";
  const cmd = tokens.join(" ");

  if (first === "find") {
    return !tokens.some((t) => ["-delete", "-exec", "-execdir", "-ok", "-fprint"].includes(t));
  }
  for (const [binary, pattern] of READ_ONLY_PREFIXES) {
    if (binary === "find") continue;
    if (first === binary) return pattern.test(cmd);
  }
  if (!READ_ONLY_BINARIES.has(first)) return false;
  if (first === "mount" && tokens.slice(1).some((t) => !t.startsWith("-") || /^(--all|-a)$/.test(t))) return false;
  if (first === "ip" && tokens.some((t) => /^(add|delete|del|replace|change|set|flush)$/.test(t))) return false;
  return true;
}

/** True only when the whole command is covered by the read-only allowlist. */
export function isReadOnly(command: string): boolean {
  const cmd = command.trim();
  if (!cmd) return true;
  const analysis = analyzeShell(cmd);
  return !analysis.dynamic && !analysis.malformed && analysis.nodes.length > 0 && analysis.nodes.every(isReadOnlyNode);
}

export function classifyCommand(command: string): CommandClass {
  const cmd = command.trim();
  if (!cmd) return "read-only";
  const analysis = analyzeShell(cmd);
  if (analysis.malformed || analysis.dynamic) return "unknown";
  if (/:\(\)\s*\{/.test(cmd) || analysis.nodes.some((n, i) => isForbiddenNode(n, analysis.nodes[i + 1]))) return "forbidden";
  if (analysis.nodes.some((n) => PRIVILEGED.test(commandTokens(n)[0] ?? ""))) return "privileged";
  if (analysis.nodes.some(isDestructiveNode)) return "destructive";
  if (analysis.nodes.every(isReadOnlyNode)) return "read-only";
  const knownSafe = analysis.nodes.every((node) => {
    if (isReadOnlyNode(node)) return true;
    const text = normalizedNode(node);
    const first = commandTokens(node)[0] ?? "";
    return SAFE_PREFIXES.some(([binary, pattern]) => binary === first && pattern.test(text));
  });
  return knownSafe ? "safe" : "unknown";
}

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

/**
 * Role x tier matrix (same shape as ssh-mcp's defaults, overridable later):
 * viewer: read-only everywhere.
 * operator: + safe and destructive on dev/staging; + safe on prod.
 * admin: everything on dev/staging; no privileged on prod.
 */
const MATRIX: Record<string, Record<string, CommandClass[]>> = {
  viewer: { "*": ["read-only"] },
  operator: {
    prod: ["read-only", "safe", "unknown"],
    "*": ["read-only", "safe", "unknown", "destructive"],
  },
  admin: {
    prod: ["read-only", "safe", "unknown", "destructive"],
    "*": ["read-only", "safe", "unknown", "destructive", "privileged"],
  },
};

function allowedClasses(role: string, tier: string): CommandClass[] {
  const row = MATRIX[role] ?? MATRIX["viewer"]!;
  return row[tier] ?? row["*"] ?? ["read-only"];
}

export function decide(command: string, ctx: PolicyContext): PolicyDecision {
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

  const gated = commandClass === "unknown" || commandClass === "destructive" || commandClass === "privileged";
  if (commandClass === "unknown") {
    if (ctx.approvalMode === "deny") {
      return { allowed: false, reason: 'approvalMode "deny" refuses unknown commands', commandClass, needsApproval: false };
    }
    return { allowed: true, commandClass, needsApproval: true };
  }
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

export function checkCommandScope(
  server: { name: string; scopes?: { commands?: string[] } },
  command: string,
): string | null {
  const patterns = server.scopes?.commands;
  if (!patterns || patterns.length === 0) return null;
  if (patterns.some((pattern) => new RegExp(pattern).test(command))) return null;
  return `Command is outside server "${server.name}" scopes.commands allowlist`;
}

function commandPathArguments(command: string): string[] {
  const analysis = analyzeShell(command);
  const paths: string[] = [];
  for (const node of analysis.nodes) {
    const tokens = commandTokens(node);
    for (const token of tokens.slice(1)) {
      const value = token.includes("=") ? token.slice(token.indexOf("=") + 1) : token.replace(/^[012]*[<>]+/, "");
      if (value.startsWith("/") || value.startsWith("./") || value.startsWith("../") || (!value.includes("://") && value.includes("/"))) {
        paths.push(value);
      }
    }
  }
  return paths;
}

export function checkCommandPathScope(
  server: { name: string; scopes?: { paths?: string[] } },
  command: string,
): string | null {
  for (const path of commandPathArguments(command)) {
    const reason = checkPathScope(server, path);
    if (reason) return reason;
  }
  return null;
}

/** Role/tier decision plus the per-server command allowlist. */
export function decideForServer(
  command: string,
  server: Pick<ServerConfig, "name" | "role" | "group" | "readOnly" | "scopes">,
  approvalMode: ApprovalMode,
): PolicyDecision {
  const decision = decide(command, {
    role: server.role,
    tier: server.group,
    readOnly: server.readOnly,
    approvalMode,
  });
  if (!decision.allowed) return decision;
  const scopeReason = checkCommandScope(server, command);
  if (scopeReason) {
    return { allowed: false, reason: scopeReason, commandClass: decision.commandClass, needsApproval: false };
  }
  const pathReason = checkCommandPathScope(server, command);
  if (pathReason) {
    return { allowed: false, reason: pathReason, commandClass: decision.commandClass, needsApproval: false };
  }
  return decision;
}

/**
 * Resource scope check for file operations (second authorization layer).
 * Returns null when the path is in scope, or a refusal reason.
 *
 * Pattern syntax:
 *   "/opt/myapp/**"  — anything under /opt/myapp/ (recursive)
 *   "/var/log/*"     — direct children of /var/log/
 *   "/opt/myapp"     — exactly this path
 *
 * A server without scopes.paths is unrestricted at this layer — scope is an
 * additional narrowing, never a widening.
 */
export function checkPathScope(
  server: { name: string; scopes?: { paths?: string[] } },
  remotePath: string,
  resolvedPath?: string,
): string | null {
  const patterns = server.scopes?.paths;
  if (!patterns || patterns.length === 0) return null;

  const normalize = (path: string): string | null => {
    if (path.includes("\0")) return null;
    if (!path.startsWith("/")) return null;
    return posix.normalize(path.replace(/^\/{2,}/, "/"));
  };
  const lexical = normalize(remotePath);
  if (!lexical) {
    return remotePath.includes("\0")
      ? `Remote path for server "${server.name}" contains a NUL byte`
      : `Remote path "${remotePath}" must be absolute for server "${server.name}" scopes.paths`;
  }

  const matches = (candidate: string): boolean => {
    for (const rawPattern of patterns) {
      const recursive = rawPattern.endsWith("/**");
      const direct = !recursive && rawPattern.endsWith("/*");
      const baseRaw = recursive ? rawPattern.slice(0, -3) : direct ? rawPattern.slice(0, -2) : rawPattern;
      const base = normalize(baseRaw);
      if (!base) continue;
      if (recursive && (candidate === base || candidate.startsWith(base + "/"))) return true;
      if (direct) {
        const rest = candidate.startsWith(base + "/") ? candidate.slice(base.length + 1) : undefined;
        if (rest !== undefined && rest.length > 0 && !rest.includes("/")) return true;
      }
      if (!recursive && !direct && candidate === base) return true;
    }
    return false;
  };

  if (!matches(lexical)) {
    return `Remote path "${remotePath}" is outside server "${server.name}" scopes.paths: [${patterns.join(", ")}]`;
  }
  if (resolvedPath !== undefined) {
    const resolved = normalize(resolvedPath);
    if (!resolved || !matches(resolved)) {
      return `Remote path "${remotePath}" resolved path "${resolvedPath}" is outside server "${server.name}" scopes.paths`;
    }
  }
  return null;
}

/**
 * Resolve a path through remote realpath. For a not-yet-created upload path,
 * walk upward to the nearest existing ancestor and append the missing suffix.
 */
export async function resolveRemotePathForScope(
  remotePath: string,
  realpath: (candidate: string) => Promise<string>,
  isMissing: (error: unknown) => boolean = () => true,
): Promise<string> {
  if (remotePath.includes("\0") || !remotePath.startsWith("/")) {
    throw new Error("Remote path must be absolute and contain no NUL byte");
  }
  let candidate = posix.normalize(remotePath.replace(/^\/{2,}/, "/"));
  const suffix: string[] = [];
  let lastError: unknown;
  for (;;) {
    try {
      const resolved = await realpath(candidate);
      return posix.join(resolved, ...suffix);
    } catch (err) {
      lastError = err;
      // Only a missing component justifies walking to a parent. Permission,
      // timeout and cancellation failures must remain visible to the caller.
      if (!isMissing(err)) throw err;
      if (candidate === "/") break;
      suffix.unshift(posix.basename(candidate));
      candidate = posix.dirname(candidate);
    }
  }
  throw new Error(`Remote realpath failed: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
}
