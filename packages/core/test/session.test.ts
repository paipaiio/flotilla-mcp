import { describe, expect, it } from "vitest";
import {
  buildSessionCaptureCommand,
  buildSessionKillCommand,
  buildSessionListCommand,
  buildSessionSendCommand,
  buildSessionStartCommand,
  parseSessionList,
  validateSessionName,
} from "../src/session.js";

describe("validateSessionName", () => {
  it("accepts simple names and prefixes them", () => {
    expect(validateSessionName("build")).toBe("flotilla-build");
    expect(validateSessionName("train_01-x")).toBe("flotilla-train_01-x");
  });

  it("rejects empty, dotted, colon and shell-breaking names", () => {
    for (const bad of ["", "a.b", "a:b", "a b", "a'b", "-x", "x".repeat(49)]) {
      expect(() => validateSessionName(bad)).toThrow(/Invalid session name/);
    }
  });
});

describe("session command builders", () => {
  it("start: detached session with scrollback bump", () => {
    const cmd = buildSessionStartCommand("flotilla-x");
    expect(cmd).toContain("tmux new-session -d -s 'flotilla-x'");
    expect(cmd).toContain("history-limit 50000");
    expect(cmd).not.toContain("send-keys");
  });

  it("start: workdir and command are quoted and typed into the shell", () => {
    const cmd = buildSessionStartCommand("flotilla-x", {
      workdir: "/opt/app",
      command: "make build",
    });
    expect(cmd).toContain("-c '/opt/app'");
    expect(cmd).toContain("tmux send-keys -t 'flotilla-x' -l 'make build'");
    expect(cmd).toContain("tmux send-keys -t 'flotilla-x' Enter");
  });

  it("start: single quotes in the command are escaped", () => {
    const cmd = buildSessionStartCommand("flotilla-x", { command: "echo 'hi'" });
    expect(cmd).toContain("'echo '\\''hi'\\'''");
  });

  it("capture: clamps line count", () => {
    expect(buildSessionCaptureCommand("flotilla-x", 50)).toContain("-S -50");
    expect(buildSessionCaptureCommand("flotilla-x", 999999)).toContain("-S -10000");
  });

  it("send: literal flag prevents key-name interpretation", () => {
    const cmd = buildSessionSendCommand("flotilla-x", "Enter");
    expect(cmd).toContain("-l 'Enter'");
  });

  it("kill: kills by full name", () => {
    expect(buildSessionKillCommand("flotilla-x")).toBe("tmux kill-session -t 'flotilla-x'");
  });

  it("list: tolerates a missing tmux server", () => {
    expect(buildSessionListCommand()).toContain("|| true");
  });
});

describe("parseSessionList", () => {
  const sample = [
    "flotilla-build\t1757587200\t1\t0",
    "other-session\t1757587201\t2\t1",
    "flotilla-train\t1757587300\t1\t1",
  ].join("\n");

  it("keeps only flotilla- sessions and strips the prefix", () => {
    const sessions = parseSessionList("h1", sample);
    expect(sessions).toHaveLength(2);
    expect(sessions[0]).toMatchObject({
      host: "h1",
      name: "build",
      windows: 1,
      attached: false,
    });
    expect(sessions[1]).toMatchObject({ name: "train", attached: true });
  });

  it("returns [] on empty output", () => {
    expect(parseSessionList("h1", "")).toEqual([]);
  });
});
