import { describe, expect, it } from "vitest";
import {
  buildChecksumCommand,
  buildPathKindProbe,
  checkRelayPolicy,
  parseChecksums,
  parsePathKind,
  planSync,
  relayFile,
  relPath,
  runSyncPlan,
} from "../src/s2s.js";
import type {
  DefaultsConfig,
  ExecOptions,
  ExecResult,
  RelayResult,
  ServerConfig,
  TransferResult,
  Transport,
} from "../src/types.js";

const DEFAULTS: DefaultsConfig = {
  approvalMode: "ask-destructive",
  commandTimeoutMs: 1000,
  maxConcurrency: 4,
  rollingBatchSize: 2,
  rollingMaxBatchFailures: 0,
};
void DEFAULTS;

function server(name: string, over: Partial<ServerConfig> = {}): ServerConfig {
  return {
    name,
    host: name,
    port: 22,
    user: "u",
    auth: "agent",
    group: "prod",
    tags: [],
    role: "operator",
    readOnly: false,
    ...over,
  };
}

/** In-memory relay transport: files live in a map keyed "host:path". */
class MemTransport implements Transport {
  files = new Map<string, string>();
  removed: string[] = [];
  failRelayFor = new Set<string>();
  async exec(s: ServerConfig, cmd: string): Promise<ExecResult> {
    const base = { host: s.name, stdout: "", stderr: "", durationMs: 1 };
    const m = cmd.match(/rm -f -- (.+)$/);
    if (m) {
      for (const p of m[1]!.split("' '").map((x) => x.replace(/^'|'$/g, ""))) {
        this.removed.push(p);
        this.files.delete(`${s.name}:${p}`);
      }
    }
    return { ...base, ok: true, exitCode: 0 };
  }
  async upload(s: ServerConfig): Promise<TransferResult> {
    return { host: s.name, ok: true, bytes: 1, durationMs: 1 };
  }
  async download(s: ServerConfig): Promise<TransferResult> {
    return { host: s.name, ok: true, bytes: 1, durationMs: 1 };
  }
  async relayCopy(src: ServerConfig, srcPath: string, dst: ServerConfig, dstPath: string): Promise<RelayResult> {
    const base = { source: src.name, dest: dst.name, durationMs: 1 };
    const data = this.files.get(`${src.name}:${srcPath}`);
    if (this.failRelayFor.has(srcPath) || data === undefined) {
      return { ...base, ok: false, bytes: 0, error: "no such file" };
    }
    this.files.set(`${dst.name}:${dstPath}`, data);
    return { ...base, ok: true, bytes: data.length };
  }
  async close(): Promise<void> {}
}

describe("path probe & checksum commands", () => {
  it("probe prints dir/file/missing and parses", () => {
    const cmd = buildPathKindProbe("/etc/nginx");
    expect(cmd).toContain("'/etc/nginx'");
    expect(parsePathKind("dir\n")).toBe("dir");
    expect(parsePathKind("file")).toBe("file");
    expect(parsePathKind("missing")).toBe("missing");
    expect(parsePathKind("bash: error")).toBe("missing");
  });

  it("file checksum command quotes the path", () => {
    expect(buildChecksumCommand("/a/b.conf", "file")).toBe("sha256sum -- '/a/b.conf'");
  });

  it("dir checksum command is relative + sorted", () => {
    const cmd = buildChecksumCommand("/var/www", "dir");
    expect(cmd).toContain("cd '/var/www'");
    expect(cmd).toContain("find . -type f");
    expect(cmd).toContain("sort -k2");
  });

  it("shell injection in the path stays quoted", () => {
    const evil = "/tmp/x'; rm -rf /; '";
    const cmd = buildChecksumCommand(evil, "file");
    // The single quotes in the path are escaped; no bare `; rm` outside quotes.
    expect(cmd).toBe(`sha256sum -- '/tmp/x'\\''; rm -rf /; '\\'''`);
  });
});

describe("parseChecksums", () => {
  const h = "a".repeat(64);
  it("parses file-mode and dir-mode lines", () => {
    const out = `${h}  /etc/nginx/nginx.conf\n${"b".repeat(64)}  ./sites/default\n`;
    const entries = parseChecksums(out);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({ sha256: h, path: "/etc/nginx/nginx.conf" });
    expect(entries[1]).toEqual({ sha256: "b".repeat(64), path: "./sites/default" });
  });
  it("ignores garbage lines", () => {
    expect(parseChecksums(`sha256sum: nope: No such file\n${"c".repeat(64)}  ok\n`)).toHaveLength(1);
  });
});

describe("relPath", () => {
  it("strips ./ prefix only", () => {
    expect(relPath("./a/b")).toBe("a/b");
    expect(relPath("a/b")).toBe("a/b");
  });
});

describe("planSync", () => {
  const A = { path: "./a", sha256: "1".repeat(64) };
  const B = { path: "./b", sha256: "2".repeat(64) };
  const C = { path: "./c", sha256: "3".repeat(64) };

  it("copies missing and changed, counts unchanged", () => {
    const src = [A, B, C];
    const dst = [A, { path: "./b", sha256: "9".repeat(64) }];
    const plan = planSync(src, dst, false);
    expect(plan.copy).toEqual(["./b", "./c"]);
    expect(plan.remove).toEqual([]);
    expect(plan.unchanged).toBe(1);
  });

  it("remove is empty without allowDelete even when dst has extras", () => {
    const plan = planSync([A], [A, B], false);
    expect(plan.remove).toEqual([]);
    expect(plan.copy).toEqual([]);
  });

  it("allowDelete lists dst-only paths", () => {
    const plan = planSync([A], [A, B, C], true);
    expect(plan.remove).toEqual(["./b", "./c"]);
  });

  it("identical trees produce an empty plan", () => {
    const plan = planSync([A, B], [B, A], true);
    expect(plan.copy).toEqual([]);
    expect(plan.remove).toEqual([]);
    expect(plan.unchanged).toBe(2);
  });
});

describe("checkRelayPolicy", () => {
  it("passes for admin same-tier with approval needed (destructive overwrite)", () => {
    const d = checkRelayPolicy(server("a", { role: "admin" }), "/x", server("b", { role: "admin" }), "/y", "ask-destructive");
    expect(d.refusals).toEqual([]);
    expect(d.needsApproval).toBe(true);
    expect(d.crossTier).toBe(false);
  });

  it("refuses operator overwriting on prod (destructive not granted)", () => {
    const d = checkRelayPolicy(server("a"), "/x", server("b"), "/y", "auto");
    expect(d.refusals.some((r) => r.includes("destructive"))).toBe(true);
  });

  it("same-tier with approvalMode auto needs no approval", () => {
    const d = checkRelayPolicy(server("a", { role: "admin" }), "/x", server("b", { role: "admin" }), "/y", "auto");
    expect(d.needsApproval).toBe(false);
  });

  it("cross-tier always needs approval even under auto", () => {
    const d = checkRelayPolicy(
      server("dev-1", { group: "dev", role: "admin" }),
      "/x",
      server("prod-1", { role: "admin" }),
      "/y",
      "auto",
    );
    expect(d.crossTier).toBe(true);
    expect(d.needsApproval).toBe(true);
    expect(d.refusals).toEqual([]);
  });

  it("refuses a readOnly destination", () => {
    const d = checkRelayPolicy(server("a"), "/x", server("b", { readOnly: true }), "/y", "auto");
    expect(d.refusals.some((r) => r.includes("readOnly"))).toBe(true);
  });

  it("refuses when dest role cannot overwrite on that tier", () => {
    const d = checkRelayPolicy(server("a"), "/x", server("b", { role: "viewer" }), "/y", "auto");
    expect(d.refusals.some((r) => r.includes("viewer"))).toBe(true);
  });

  it("enforces scopes.paths on both ends", () => {
    const scoped = { scopes: { paths: ["/opt/app/**"] }, role: "admin" as const };
    const d = checkRelayPolicy(
      server("a", scoped),
      "/etc/passwd",
      server("b", scoped),
      "/var/log/x",
      "auto",
    );
    expect(d.refusals).toHaveLength(2);
    expect(d.refusals[0]).toContain("/etc/passwd");
    expect(d.refusals[1]).toContain("/var/log/x");
  });
});

describe("relayFile", () => {
  it("returns ok on success", async () => {
    const t = new MemTransport();
    t.files.set("a:/etc/app.conf", "key=value");
    const r = await relayFile(t, server("a"), "/etc/app.conf", server("b"), "/etc/app.conf");
    expect(r.ok).toBe(true);
    expect(r.bytes).toBe(9);
    expect(t.files.get("b:/etc/app.conf")).toBe("key=value");
  });

  it("folds transport errors into the result", async () => {
    const t = new MemTransport();
    const r = await relayFile(t, server("a"), "/nope", server("b"), "/nope");
    expect(r.ok).toBe(false);
    expect(r.error).toContain("no such file");
  });
});

describe("runSyncPlan", () => {
  it("relays copies and applies removals", async () => {
    const t = new MemTransport();
    t.files.set("a:/src/a.txt", "aaa");
    t.files.set("a:/src/sub/b.txt", "bbbb");
    const src = server("a");
    const dst = server("b");
    const plan = planSync(
      [
        { path: "./a.txt", sha256: "1".repeat(64) },
        { path: "./sub/b.txt", sha256: "2".repeat(64) },
      ],
      [{ path: "./old.txt", sha256: "3".repeat(64) }],
      true,
    );
    const r = await runSyncPlan(t, src, "/src", dst, "/dst", plan, { concurrency: 2 });
    expect(r.failures).toEqual([]);
    expect(r.copied.map((c) => c.path).sort()).toEqual(["a.txt", "sub/b.txt"]);
    expect(r.totalBytes).toBe(7);
    expect(r.removed).toEqual(["old.txt"]);
    expect(t.files.get("b:/dst/a.txt")).toBe("aaa");
    expect(t.files.get("b:/dst/sub/b.txt")).toBe("bbbb");
  });

  it("collects per-file failures without aborting the rest", async () => {
    const t = new MemTransport();
    t.files.set("a:/src/ok.txt", "x");
    const plan = planSync(
      [
        { path: "./ok.txt", sha256: "1".repeat(64) },
        { path: "./missing.txt", sha256: "2".repeat(64) },
      ],
      [],
      false,
    );
    const r = await runSyncPlan(t, server("a"), "/src", server("b"), "/dst", plan);
    expect(r.copied).toHaveLength(1);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0]!.path).toBe("missing.txt");
  });
});
