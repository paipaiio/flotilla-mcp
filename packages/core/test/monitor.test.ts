import { describe, expect, it } from "vitest";
import {
  analyzeDoctor,
  buildDoctorScript,
  buildMetricsScript,
  formatDoctor,
  parseMetrics,
} from "../src/monitor.js";
import { classifyCommand } from "../src/policy.js";

// Realistic Debian output (matches the live shumeipai test host's format).
const SAMPLE = `##FLOTILLA uptime
 12:14:58 up 23 min,  4 users,  load average: 0.09, 0.03, 0.05
##FLOTILLA cores
4
##FLOTILLA mem
               total        used        free      shared  buff/cache   available
Mem:            3808        1234        1098          42        1476        2312
Swap:              0           0           0
##FLOTILLA disk
Filesystem     1024-blocks     Used Available Capacity Mounted on
/dev/mmcblk0p2   119557564 23068672  91318236      20% /
overlay           12345678  9999999   1234567      96% /var/lib/docker
##FLOTILLA topcpu
%CPU %MEM COMMAND
 5.2  3.1 node
 1.0  0.5 sshd
##FLOTILLA topmem
%CPU %MEM COMMAND
 0.4 12.2 java
 5.2  3.1 node
##FLOTILLA failed
● snapd.service loaded failed failed snapd.service
##FLOTILLA zombies
2
`;

describe("parseMetrics", () => {
  it("parses a full Debian sample", () => {
    const m = parseMetrics("web-1", SAMPLE);
    expect(m.loadAvg).toEqual([0.09, 0.03, 0.05]);
    expect(m.cores).toBe(4);
    expect(m.mem).toMatchObject({ totalMb: 3808, usedMb: 1234, availableMb: 2312, usedPct: 32 });
    expect(m.disks).toContainEqual({ mount: "/", sizeMb: 116755, usedPct: 20 });
    expect(m.disks).toContainEqual({ mount: "/var/lib/docker", sizeMb: 12056, usedPct: 96 });
    expect(m.topCpu[0]).toMatchObject({ command: "node", cpuPct: 5.2 });
    expect(m.topMem[0]).toMatchObject({ command: "java", memPct: 12.2 });
    expect(m.failedUnits).toEqual(["snapd.service"]);
    expect(m.zombies).toBe(2);
    expect(m.unparsed).toEqual([]);
  });

  it("marks sections that fail to parse instead of crashing", () => {
    const broken = SAMPLE.replace("load average: 0.09, 0.03, 0.05", "weird busybox output");
    const m = parseMetrics("alpine-1", broken);
    expect(m.loadAvg).toBeNull();
    expect(m.unparsed).toContain("uptime");
  });

  it("tolerates missing sections (metrics script has no doctor sections)", () => {
    const m = parseMetrics("web-1", "##FLOTILLA cores\n8\n");
    expect(m.cores).toBe(8);
    expect(m.mem).toBeNull();
    expect(m.failedUnits).toEqual([]);
    expect(m.zombies).toBeNull();
  });
});

describe("analyzeDoctor", () => {
  it("flags the sample's critical disk, failed unit, and zombies", () => {
    const issues = analyzeDoctor(parseMetrics("web-1", SAMPLE));
    expect(issues).toContainEqual(
      expect.objectContaining({ severity: "crit", check: "disk:/var/lib/docker" }),
    );
    expect(issues).toContainEqual(expect.objectContaining({ severity: "warn", check: "systemd" }));
    expect(issues).toContainEqual(expect.objectContaining({ severity: "warn", check: "zombies" }));
    // 20% root disk, 32% mem, load 0.09/4 cores: no flags.
    expect(issues.find((i) => i.check === "disk:/")).toBeUndefined();
    expect(issues.find((i) => i.check === "memory")).toBeUndefined();
    expect(issues.find((i) => i.check === "load")).toBeUndefined();
  });

  it("flags high load per core", () => {
    const m = parseMetrics("web-1", "##FLOTILLA uptime\nup 1 min, load average: 9.2, 8.0, 7.0\n##FLOTILLA cores\n4\n");
    const issues = analyzeDoctor(m);
    expect(issues).toContainEqual(expect.objectContaining({ severity: "crit", check: "load" }));
  });

  it("healthy host produces no issues", () => {
    const healthy = SAMPLE.replace("96% /var/lib/docker", "40% /var/lib/docker")
      .replace("● snapd.service loaded failed failed snapd.service", "")
      .replace("##FLOTILLA zombies\n2", "##FLOTILLA zombies\n0");
    expect(analyzeDoctor(parseMetrics("web-1", healthy))).toEqual([]);
  });
});

describe("collection scripts", () => {
  it("both scripts classify as read-only (every segment allowlisted)", () => {
    expect(classifyCommand(buildMetricsScript())).toBe("read-only");
    expect(classifyCommand(buildDoctorScript())).toBe("read-only");
  });
});

describe("formatDoctor", () => {
  it("renders HEALTHY when there are no issues", () => {
    const healthy = SAMPLE.replace("96% /var/lib/docker", "40% /var/lib/docker")
      .replace("● snapd.service loaded failed failed snapd.service", "")
      .replace("##FLOTILLA zombies\n2", "##FLOTILLA zombies\n0");
    const m = parseMetrics("web-1", healthy);
    expect(formatDoctor("web-1", m, [])).toMatch(/HEALTHY web-1/);
  });
});
