import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditLogger, defaultAuditPath, resolveAuditPath } from "../src/audit.js";
import { defaultConfigPath } from "../src/config.js";

let dir: string;
let path: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flotilla-audit-"));
  path = join(dir, "audit.jsonl");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

function records(): any[] {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
}

describe("AuditLogger", () => {
  it("writes JSONL records with ts/seq", () => {
    const log = new AuditLogger(path);
    log.log({ kind: "decision", tool: "exec", command: "uptime", outcome: "allow" });
    log.log({ kind: "execution", tool: "exec", outcome: "ok", results: { total: 2, succeeded: 2, failed: 0, skipped: 0 } });
    const recs = records();
    expect(recs).toHaveLength(2);
    expect(recs[0]).toMatchObject({ kind: "decision", seq: 1, prevHash: "GENESIS" });
    expect(recs[1].seq).toBe(2);
    expect(recs[1].prevHash).toBe(recs[0].hash);
  });

  it("redacts KEY=value secrets and bearer tokens in commands", () => {
    const log = new AuditLogger(path);
    log.log({
      kind: "decision",
      tool: "exec",
      command: "AWS_SECRET_ACCESS_KEY=AKIA1234567890 curl -H 'Authorization: Bearer abc.def.ghi' x",
      outcome: "allow",
    });
    const cmd = records()[0].command as string;
    expect(cmd).not.toContain("AKIA1234567890");
    expect(cmd).not.toContain("abc.def.ghi");
    expect(cmd).toContain("<redacted>");
  });

  it("redacts PEM blocks", () => {
    const log = new AuditLogger(path);
    log.log({
      kind: "decision",
      tool: "exec",
      command: "echo '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----' > k",
      outcome: "allow",
    });
    expect(records()[0].command).not.toContain("b3BlbnNzaA==");
  });

  it("entropy scan catches long random tokens only when enabled", () => {
    const token = "xK9$mQ2vL8pR4nT6wY1zB3cF5hJ7kN0sA9dG".replace("$", "x");
    const off = new AuditLogger(path);
    off.log({ kind: "decision", tool: "exec", command: `echo ${token}`, outcome: "allow" });
    expect(records()[0].command).toContain(token);

    const path2 = join(dir, "a2.jsonl");
    const on = new AuditLogger(path2, { entropyScan: true });
    on.log({ kind: "decision", tool: "exec", command: `echo ${token}`, outcome: "allow" });
    const rec = JSON.parse(readFileSync(path2, "utf8").trim());
    expect(rec.command).toContain("<redacted>");
  });

  it("verifies a clean chain", () => {
    const log = new AuditLogger(path);
    for (let i = 0; i < 5; i++) {
      log.log({ kind: "execution", tool: "exec", outcome: "ok" });
    }
    expect(AuditLogger.verifyChain(path)).toEqual({ ok: true, total: 5 });
  });

  it("detects tampering", () => {
    const log = new AuditLogger(path);
    for (let i = 0; i < 3; i++) log.log({ kind: "execution", tool: "exec", outcome: "ok" });
    // Rewrite line 2 with different content but keep line count.
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const tampered = JSON.parse(lines[1]!);
    tampered.outcome = "failed";
    lines[1] = JSON.stringify(tampered);
    writeFileSync(path, lines.join("\n") + "\n");
    const v = AuditLogger.verifyChain(path);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBe(2);
  });

  it("resumes the chain across restarts", () => {
    new AuditLogger(path).log({ kind: "decision", tool: "exec", outcome: "allow" });
    const again = new AuditLogger(path);
    again.log({ kind: "decision", tool: "exec", outcome: "deny" });
    expect(AuditLogger.verifyChain(path)).toEqual({ ok: true, total: 2 });
    expect(records()[1].seq).toBe(2);
  });

  it("can run without a hash chain", () => {
    const log = new AuditLogger(path, { hashChain: false });
    log.log({ kind: "decision", tool: "exec", outcome: "allow" });
    expect(records()[0].hash).toBe("");
  });
});

describe("audit path resolution", () => {
  it("defaults next to the platform config instead of the process cwd", () => {
    expect(defaultAuditPath()).toBe(join(dirname(defaultConfigPath()), "audit.jsonl"));
  });

  it("resolves configured relative paths against the config directory", () => {
    const config = join(dir, "nested", "fleet.toml");
    expect(resolveAuditPath(config, "logs/security.jsonl")).toBe(
      resolve(dirname(config), "logs/security.jsonl"),
    );
    expect(resolveAuditPath(config, "/var/log/flotilla.jsonl")).toBe("/var/log/flotilla.jsonl");
  });
});
