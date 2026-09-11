/**
 * fleet-add: semi-automatic server onboarding.
 *
 * probeServer opens a short-lived SSH connection (its own transport, closed
 * afterwards) and collects facts: hostname, uid, tmux availability, and the
 * host key (TOFU-captured, returned in pinable "SHA256:..." form).
 *
 * buildServerToml / appendServerToConfig handle the config-file side: the
 * new server is appended as a [[servers]] block with its host key pinned —
 * first contact doubles as key enrollment, so later connections are verified
 * against it (the only host-key control that survives restarts).
 */
import { SshTransport } from "./ssh.js";
import { parseFleetConfig } from "./config.js";
import type { ServerConfig } from "./types.js";

export class OnboardError extends Error {}

export interface ProbeResult {
  ok: boolean;
  hostname?: string;
  uid?: number;
  tmux?: boolean;
  /** Pinned host key in "SHA256:..." form, ready for trustedHostKey. */
  hostKey?: string;
  error?: string;
}

export async function probeServer(server: ServerConfig): Promise<ProbeResult> {
  const transport = new SshTransport(new Map([[server.name, server]]));
  try {
    const host = await transport.exec(server, "hostname", { timeoutMs: 15_000 });
    if (!host.ok) {
      return { ok: false, error: host.error ?? host.stderr.trim() ?? "hostname probe failed" };
    }
    const uid = await transport.exec(server, "id -u", { timeoutMs: 10_000 });
    const tmux = await transport.exec(server, "command -v tmux >/dev/null 2>&1 && echo yes || echo no", {
      timeoutMs: 10_000,
    });
    return {
      ok: true,
      hostname: host.stdout.trim(),
      uid: uid.ok ? Number(uid.stdout.trim()) : undefined,
      tmux: tmux.stdout.trim() === "yes",
      hostKey: transport.hostKeyOf(server.name),
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    await transport.close();
  }
}

function tomlStr(s: string): string {
  return JSON.stringify(s); // TOML basic strings are JSON-compatible
}

/** Render one [[servers]] block. Only set fields are written. */
export function buildServerToml(s: ServerConfig): string {
  const lines: string[] = ["", "[[servers]]"];
  lines.push(`name = ${tomlStr(s.name)}`);
  lines.push(`host = ${tomlStr(s.host)}`);
  if (s.port !== 22) lines.push(`port = ${s.port}`);
  lines.push(`user = ${tomlStr(s.user)}`);
  lines.push(`auth = ${tomlStr(s.auth)}`);
  if (s.keyRef) lines.push(`keyRef = ${tomlStr(s.keyRef)}`);
  lines.push(`group = ${tomlStr(s.group)}`);
  if (s.tags.length > 0) lines.push(`tags = [${s.tags.map(tomlStr).join(", ")}]`);
  lines.push(`role = ${tomlStr(s.role)}`);
  if (s.readOnly) lines.push(`readOnly = true`);
  if (s.workdir) lines.push(`workdir = ${tomlStr(s.workdir)}`);
  if (s.via) lines.push(`via = ${tomlStr(s.via)}`);
  if (s.trustedHostKey) lines.push(`trustedHostKey = ${tomlStr(s.trustedHostKey)}`);
  return lines.join("\n") + "\n";
}

/**
 * Append a server to config text. Validates: no duplicate name, and the
 * result must still parse. Returns the new config text.
 */
export function appendServerToConfig(tomlText: string, server: ServerConfig): string {
  const existing = parseFleetConfig(tomlText);
  if (existing.servers.some((s) => s.name === server.name)) {
    throw new OnboardError(`Server "${server.name}" already exists in the config`);
  }
  if (server.via && !existing.servers.some((s) => s.name === server.via)) {
    throw new OnboardError(`Jump host "${server.via}" not found in the config`);
  }
  const next = tomlText.replace(/\s*$/, "\n") + buildServerToml(server);
  parseFleetConfig(next); // must stay valid
  return next;
}
