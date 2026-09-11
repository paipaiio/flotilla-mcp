import { describe, expect, it } from "vitest";
import {
  buildFileTailCommand,
  buildJournalTailCommand,
  filterTailOutput,
} from "../src/logstream.js";

describe("tail command builders", () => {
  it("journal tail: bounded follow, exit 124 normalized", () => {
    const cmd = buildJournalTailCommand("cron.service", 30);
    expect(cmd).toContain("timeout 30 journalctl -u 'cron.service' -f -n 0 --no-pager");
    expect(cmd).toContain("[ $c -eq 124 ]");
  });

  it("clamps the window to 300s", () => {
    expect(buildJournalTailCommand("x", 9999)).toContain("timeout 300 ");
    expect(buildFileTailCommand("/var/log/x", 9999)).toContain("timeout 300 ");
  });

  it("sudo journal tail bakes sudo -n so the whitelist matches journalctl", () => {
    const cmd = buildJournalTailCommand("cron", 10, { sudo: true });
    expect(cmd).toContain("timeout 10 sudo -n -p '' journalctl -u 'cron'");
  });

  it("file tail: tail -F quoted", () => {
    expect(buildFileTailCommand("/tmp/a'b.log", 5)).toContain(
      "tail -F -n 0 '/tmp/a'\\''b.log'",
    );
  });
});

describe("filterTailOutput", () => {
  const raw = "heartbeat-1\nother\nheartbeat-2\n";

  it("no pattern returns all non-empty lines", () => {
    const r = filterTailOutput(raw);
    expect(r).toMatchObject({ matched: 3, total: 3 });
  });

  it("pattern filters locally", () => {
    const r = filterTailOutput(raw, "^heartbeat");
    expect(r.lines).toEqual(["heartbeat-1", "heartbeat-2"]);
    expect(r.total).toBe(3);
  });

  it("invalid pattern reports a grepError", () => {
    const r = filterTailOutput(raw, "([");
    expect(r.grepError).toMatch(/Invalid grep pattern/);
  });
});
