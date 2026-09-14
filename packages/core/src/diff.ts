/**
 * Cross-host diffing: group fan-out results by identical output and report
 * consensus or drift. The fleet's answer to "are all my web servers the same?"
 *
 * Grouping key: exitCode + normalized stdout (trailing whitespace stripped).
 * Hosts whose command failed are reported separately, never mixed into output
 * groups — an error is not a version.
 */
import type { ExecResult, FanoutResult } from "./types.js";
import { redactSensitiveText } from "./redaction.js";

export interface DiffGroup {
  /** Normalized stdout shared by every host in this group. */
  output: string;
  exitCode: number;
  hosts: string[];
}

export interface DiffReport {
  command: string;
  total: number;
  /** True when every host succeeded with byte-identical normalized output. */
  consistent: boolean;
  /** Output groups among successful hosts, largest first. */
  groups: DiffGroup[];
  /** Hosts where the command itself failed (non-zero exit or transport error). */
  failures: { host: string; exitCode: number | null; error?: string; stderr: string }[];
}

export function normalizeOutput(stdout: string): string {
  return stdout.replace(/\s+$/g, "").replace(/\r\n/g, "\n");
}

export function diffFanout(result: FanoutResult): DiffReport {
  const byKey = new Map<string, DiffGroup>();
  const failures: DiffReport["failures"] = [];

  for (const r of result.results) {
    if (r.skipped) continue;
    if (!r.ok) {
      failures.push({
        host: r.host,
        exitCode: r.exitCode,
        error: r.error,
        stderr: normalizeOutput(r.stderr),
      });
      continue;
    }
    const output = normalizeOutput(r.stdout);
    const key = `${r.exitCode ?? -1}${output}`;
    const group = byKey.get(key);
    if (group) {
      group.hosts.push(r.host);
    } else {
      byKey.set(key, { output, exitCode: r.exitCode ?? 0, hosts: [r.host] });
    }
  }

  const groups = [...byKey.values()].sort((a, b) => b.hosts.length - a.hosts.length);
  return {
    command: result.command,
    total: result.summary.total,
    consistent: failures.length === 0 && groups.length === 1,
    groups,
    failures,
  };
}

/** Human-readable rendering, also used as the MCP tool's text payload. */
export function formatDiff(report: DiffReport, maxOutputChars = 2_000): string {
  const lines: string[] = [`command: ${redactSensitiveText(report.command).text}`, `hosts: ${report.total}`, ""];

  if (report.consistent) {
    lines.push(`CONSISTENT — all ${report.groups[0]?.hosts.length ?? 0} hosts agree:`);
    lines.push(indent(clip(report.groups[0]?.output ?? "", maxOutputChars)));
    return lines.join("\n");
  }

  if (report.groups.length > 0) {
    if (report.groups.length === 1) {
      // One output group but some failures: agree where reachable, not drift.
      lines.push(
        `PARTIAL — all ${report.groups[0]!.hosts.length} successful host(s) agree, ${report.failures.length} failed:`,
      );
      lines.push(indent(clip(report.groups[0]!.output, maxOutputChars)));
    } else {
      lines.push(`DRIFT — ${report.groups.length} distinct outputs:`);
      report.groups.forEach((g, i) => {
        lines.push(`\n[group ${i + 1}] ${g.hosts.length} host(s): ${g.hosts.join(", ")}`);
        lines.push(indent(clip(g.output, maxOutputChars)));
      });
    }
  } else {
    lines.push("No successful hosts to compare.");
  }

  if (report.failures.length > 0) {
    lines.push(`\nfailures (${report.failures.length}):`);
    for (const f of report.failures) {
      lines.push(
        `  - ${f.host}: ${redactSensitiveText(f.error ?? `exit=${f.exitCode}`).text}${f.stderr ? ` — ${clip(f.stderr, 200)}` : ""}`,
      );
    }
  }
  return lines.join("\n");
}

function clip(s: string, max: number): string {
  const publicText = redactSensitiveText(s).text;
  return publicText.length > max ? publicText.slice(0, max) + `\n... [truncated, ${publicText.length} chars total]` : publicText;
}

function indent(s: string): string {
  return s
    .split("\n")
    .map((l) => `  ${l}`)
    .join("\n");
}
