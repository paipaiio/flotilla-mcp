/**
 * Monitoring and health checks (v0.5).
 *
 * Zero-dependency collection: one composite read-only shell script per host
 * (uptime/nproc/free/df/ps/systemctl), parsed locally. Every segment of the
 * script is allowlisted read-only, so the whole thing classifies "read-only"
 * and needs no approval. Debian/builtin tools assumed; sections that fail to
 * parse are reported as warnings, never fatal.
 */

export interface DiskUsage {
  mount: string;
  sizeMb: number;
  usedPct: number;
}

export interface ProcInfo {
  cpuPct: number;
  memPct: number;
  command: string;
}

export interface MemInfo {
  totalMb: number;
  usedMb: number;
  availableMb: number;
  usedPct: number;
}

export interface MetricsSnapshot {
  host: string;
  loadAvg: [number, number, number] | null;
  cores: number | null;
  mem: MemInfo | null;
  disks: DiskUsage[];
  topCpu: ProcInfo[];
  topMem: ProcInfo[];
  failedUnits: string[];
  zombies: number | null;
  /** Sections whose output could not be parsed (e.g. busybox quirks). */
  unparsed: string[];
}

const SECTIONS = ["uptime", "cores", "mem", "disk", "topcpu", "topmem", "failed", "zombies"] as const;
type Section = (typeof SECTIONS)[number];

function marker(name: Section): string {
  return `printf '##FLOTILLA ${name}\\n'; `;
}

/** The monitoring script: metrics only. */
export function buildMetricsScript(): string {
  return [
    marker("uptime") + "uptime",
    marker("cores") + "nproc",
    marker("mem") + "free -m",
    marker("disk") + "df -P -x tmpfs -x devtmpfs",
    marker("topcpu") + "ps -eo pcpu,pmem,comm --sort=-pcpu | head -6",
    marker("topmem") + "ps -eo pcpu,pmem,comm --sort=-pmem | head -6",
  ].join("; ");
}

/** The doctor script: metrics + failed systemd units + zombie count. */
export function buildDoctorScript(): string {
  return [
    buildMetricsScript(),
    marker("failed") + "systemctl list-units --failed --no-legend --plain 2>/dev/null",
    marker("zombies") + "ps axo stat= | grep -c '^Z' || true",
  ].join("; ");
}

function parseSections(output: string): Map<Section, string> {
  const sections = new Map<Section, string>();
  const re = /^##FLOTILLA (\w+)\n/gm;
  const marks: { name: string; start: number; end: number }[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(output)) !== null) {
    marks.push({ name: m[1]!, start: m.index, end: m.index + m[0].length });
  }
  marks.forEach((mark, i) => {
    const stop = i + 1 < marks.length ? marks[i + 1]!.start : output.length;
    sections.set(mark.name as Section, output.slice(mark.end, stop).trim());
  });
  return sections;
}

function parseLoad(raw: string): [number, number, number] | null {
  const m = /load averages?:\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/.exec(raw);
  return m ? [parseFloat(m[1]!), parseFloat(m[2]!), parseFloat(m[3]!)] : null;
}

function parseMem(raw: string): MemInfo | null {
  const line = raw.split("\n").find((l) => l.startsWith("Mem:"));
  if (!line) return null;
  const cols = line.split(/\s+/).slice(1).map(Number);
  // free -m: total used free shared buff/cache available
  if (cols.length < 6 || cols.some(Number.isNaN)) return null;
  const [total, used, , , , available] = cols as [number, number, number, number, number, number];
  return {
    totalMb: total,
    usedMb: used,
    availableMb: available,
    usedPct: total > 0 ? Math.round((used / total) * 100) : 0,
  };
}

function parseDisks(raw: string): DiskUsage[] {
  const disks: DiskUsage[] = [];
  for (const line of raw.split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 6) continue;
    const blocks = Number(cols[1]);
    const pct = Number((cols[4] ?? "").replace("%", ""));
    if (Number.isNaN(blocks) || Number.isNaN(pct)) continue;
    disks.push({ mount: cols[5]!, sizeMb: Math.round(blocks / 1024), usedPct: pct });
  }
  return disks;
}

function parseProcs(raw: string): ProcInfo[] {
  const procs: ProcInfo[] = [];
  for (const line of raw.split("\n").slice(1)) {
    const m = /^\s*([\d.]+)\s+([\d.]+)\s+(.+)$/.exec(line);
    if (!m) continue;
    procs.push({ cpuPct: parseFloat(m[1]!), memPct: parseFloat(m[2]!), command: m[3]!.trim() });
  }
  return procs;
}

function parseFailedUnits(raw: string): string[] {
  return raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l) => l.replace(/^●\s*/, "").split(/\s+/)[0]!)
    .filter(Boolean);
}

export function parseMetrics(host: string, output: string): MetricsSnapshot {
  const sections = parseSections(output);
  const unparsed: string[] = [];

  const uptimeRaw = sections.get("uptime");
  const loadAvg = uptimeRaw !== undefined ? parseLoad(uptimeRaw) : null;
  if (uptimeRaw !== undefined && loadAvg === null) unparsed.push("uptime");

  const coresRaw = sections.get("cores");
  const cores = coresRaw !== undefined && /^\d+$/.test(coresRaw) ? Number(coresRaw) : null;
  if (coresRaw !== undefined && cores === null) unparsed.push("cores");

  const memRaw = sections.get("mem");
  const mem = memRaw !== undefined ? parseMem(memRaw) : null;
  if (memRaw !== undefined && mem === null) unparsed.push("mem");

  const zombiesRaw = sections.get("zombies");
  const zombies = zombiesRaw !== undefined && /^\d+$/.test(zombiesRaw) ? Number(zombiesRaw) : null;
  if (zombiesRaw !== undefined && zombies === null) unparsed.push("zombies");

  return {
    host,
    loadAvg,
    cores,
    mem,
    disks: sections.has("disk") ? parseDisks(sections.get("disk")!) : [],
    topCpu: sections.has("topcpu") ? parseProcs(sections.get("topcpu")!) : [],
    topMem: sections.has("topmem") ? parseProcs(sections.get("topmem")!) : [],
    failedUnits: sections.has("failed") ? parseFailedUnits(sections.get("failed")!) : [],
    zombies,
    unparsed,
  };
}

// ── doctor: threshold analysis over a snapshot ──

export type Severity = "warn" | "crit";

export interface DoctorIssue {
  severity: Severity;
  check: string;
  detail: string;
}

export interface DoctorThresholds {
  diskWarnPct: number;
  diskCritPct: number;
  memWarnPct: number;
  memCritPct: number;
  loadWarnPerCore: number;
  loadCritPerCore: number;
  zombieWarn: number;
  zombieCrit: number;
}

export const DEFAULT_THRESHOLDS: DoctorThresholds = {
  diskWarnPct: 85,
  diskCritPct: 95,
  memWarnPct: 85,
  memCritPct: 95,
  loadWarnPerCore: 1,
  loadCritPerCore: 2,
  zombieWarn: 1,
  zombieCrit: 10,
};

export function analyzeDoctor(
  m: MetricsSnapshot,
  t: DoctorThresholds = DEFAULT_THRESHOLDS,
): DoctorIssue[] {
  const issues: DoctorIssue[] = [];

  for (const d of m.disks) {
    if (d.usedPct >= t.diskCritPct) {
      issues.push({ severity: "crit", check: `disk:${d.mount}`, detail: `${d.usedPct}% used (${d.sizeMb}MB total)` });
    } else if (d.usedPct >= t.diskWarnPct) {
      issues.push({ severity: "warn", check: `disk:${d.mount}`, detail: `${d.usedPct}% used (${d.sizeMb}MB total)` });
    }
  }

  if (m.mem) {
    if (m.mem.usedPct >= t.memCritPct) {
      issues.push({ severity: "crit", check: "memory", detail: `${m.mem.usedPct}% used (${m.mem.usedMb}/${m.mem.totalMb}MB)` });
    } else if (m.mem.usedPct >= t.memWarnPct) {
      issues.push({ severity: "warn", check: "memory", detail: `${m.mem.usedPct}% used (${m.mem.usedMb}/${m.mem.totalMb}MB)` });
    }
  }

  if (m.loadAvg && m.cores && m.cores > 0) {
    const perCore = m.loadAvg[0] / m.cores;
    if (perCore >= t.loadCritPerCore) {
      issues.push({ severity: "crit", check: "load", detail: `load1=${m.loadAvg[0]} on ${m.cores} cores (${perCore.toFixed(2)}/core)` });
    } else if (perCore >= t.loadWarnPerCore) {
      issues.push({ severity: "warn", check: "load", detail: `load1=${m.loadAvg[0]} on ${m.cores} cores (${perCore.toFixed(2)}/core)` });
    }
  }

  if (m.failedUnits.length > 0) {
    issues.push({ severity: "warn", check: "systemd", detail: `failed units: ${m.failedUnits.join(", ")}` });
  }

  if (m.zombies !== null && m.zombies >= t.zombieCrit) {
    issues.push({ severity: "crit", check: "zombies", detail: `${m.zombies} zombie processes` });
  } else if (m.zombies !== null && m.zombies >= t.zombieWarn) {
    issues.push({ severity: "warn", check: "zombies", detail: `${m.zombies} zombie process(es)` });
  }

  for (const section of m.unparsed) {
    issues.push({ severity: "warn", check: "parse", detail: `section "${section}" could not be parsed` });
  }

  return issues;
}

// ── rendering ──

export function formatMetrics(m: MetricsSnapshot): string {
  const lines = [`── ${m.host}`];
  if (m.loadAvg) {
    lines.push(`  load: ${m.loadAvg.join(" / ")}${m.cores ? ` (${m.cores} cores)` : ""}`);
  }
  if (m.mem) {
    lines.push(`  mem: ${m.mem.usedPct}% used (${m.mem.usedMb}/${m.mem.totalMb}MB, avail ${m.mem.availableMb}MB)`);
  }
  for (const d of m.disks) {
    lines.push(`  disk ${d.mount}: ${d.usedPct}% of ${d.sizeMb}MB`);
  }
  if (m.topCpu.length > 0) {
    lines.push(`  top cpu: ${m.topCpu.slice(0, 3).map((p) => `${p.command} ${p.cpuPct}%`).join(", ")}`);
  }
  if (m.topMem.length > 0) {
    lines.push(`  top mem: ${m.topMem.slice(0, 3).map((p) => `${p.command} ${p.memPct}%`).join(", ")}`);
  }
  return lines.join("\n");
}

export function formatDoctor(host: string, m: MetricsSnapshot, issues: DoctorIssue[]): string {
  const lines: string[] = [];
  if (issues.length === 0) {
    lines.push(`── HEALTHY ${host}`);
  } else {
    const worst = issues.some((i) => i.severity === "crit") ? "CRIT" : "WARN";
    lines.push(`── ${worst} ${host} (${issues.length} issue${issues.length > 1 ? "s" : ""})`);
    for (const i of issues) {
      lines.push(`  [${i.severity}] ${i.check}: ${i.detail}`);
    }
  }
  lines.push(formatMetrics(m).replace(/^── .*\n/, "")); // reuse metrics body, drop its header
  return lines.join("\n");
}
