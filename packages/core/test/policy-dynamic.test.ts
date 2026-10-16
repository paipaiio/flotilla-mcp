import { describe, expect, it } from "vitest";
import { classifyCommand, decideForServer } from "../src/index.js";

describe("command substitution never downgrades a dangerous command", () => {
  it.each([
    ["grep -H . /proc/x > /root/b-$(date +%s).txt && printf x > /etc/sysctl.d/a.conf", "destructive"],
    ["echo $(id) > /etc/passwd2", "destructive"],
    ["echo $(rm -rf /data)", "destructive"],
    ["echo `rm -rf /data`", "destructive"],
    ["ls $(echo $(rm -rf /x))", "destructive"],
    ["echo $(sudo id)", "privileged"],
    ["rm -rf $(echo /tmp/x)", "destructive"],
  ])("%s → %s", (command, expected) => {
    expect(classifyCommand(command)).toBe(expected);
  });

  it("keeps harmless dynamic commands at unknown (approval, no hard refusal)", () => {
    expect(classifyCommand("cat /var/log/app-$(date +%F).log")).toBe("unknown");
    expect(classifyCommand("echo '$(not a substitution)'")).toBe("read-only");
  });

  it("closes the prod/operator bypass: a write hidden behind $(...) is refused like any write", () => {
    const server = { name: "dmit", role: "operator" as const, group: "prod", readOnly: false };
    const d = decideForServer("echo $(date) > /etc/sysctl.d/x.conf", server, "ask-destructive");
    expect(d.allowed).toBe(false);
    expect(d.commandClass).toBe("destructive");
  });
});
