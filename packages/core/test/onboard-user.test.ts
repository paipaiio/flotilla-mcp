import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildCreateUserScript } from "../src/index.js";

const KEY = `ssh-ed25519 ${"C".repeat(68)} flotilla-fleet`;

/** Run just the sudoers-rule part of the script with a fake `sudo -V`. */
function sudoersLine(sudoVersion: string): string {
  const script = buildCreateUserScript("flotilla", KEY, true);
  const body = script.split("\n");
  const from = body.findIndex((l) => l.includes("SV=$("));
  const to = body.findIndex((l) => l.includes('printf "%s ALL=(root)'));
  const part = [
    "U=flotilla",
    "P=/usr/bin/systemctl",
    `sudo() { echo "Sudo version ${sudoVersion}"; }`,
    ...body.slice(from, to).map((l) => l.trim()),
    'printf "%s ALL=(root) NOPASSWD: %s\\n" "$U" "$R"',
  ].join("\n");
  const r = spawnSync("sh", ["-c", part], { encoding: "utf8" });
  expect(r.stderr).toBe("");
  return r.stdout.trim();
}

describe("create-user script", () => {
  it("is valid POSIX sh", () => {
    for (const sudo of [true, false]) {
      const r = spawnSync("sh", ["-n", "-c", buildCreateUserScript("flotilla", KEY, sudo)], { encoding: "utf8" });
      expect(r.status, r.stderr).toBe(0);
    }
  });

  it("pins systemctl arguments with regex rules on sudo >= 1.9.10", () => {
    const line = sudoersLine("1.9.15p5");
    expect(line).toBe(
      "flotilla ALL=(root) NOPASSWD: /usr/bin/systemctl ^(start|stop|restart|reload) [A-Za-z0-9@._\\:][A-Za-z0-9@._\\:-]*$, " +
        "/usr/bin/systemctl ^status [A-Za-z0-9@._\\:][A-Za-z0-9@._\\:-]* --no-pager -l$",
    );
    const visudo = spawnSync("sh", ["-c", "command -v visudo"], { encoding: "utf8" }).stdout.trim();
    if (visudo) {
      const f = join(mkdtempSync(join(tmpdir(), "flotilla-sudoers-")), "rule");
      writeFileSync(f, line + "\n");
      expect(spawnSync(visudo, ["-cf", f], { encoding: "utf8" }).status).toBe(0);
    }
  });

  it("falls back to glob rules on older sudo", () => {
    expect(sudoersLine("1.8.31")).toContain("/usr/bin/systemctl restart *");
    expect(sudoersLine("1.9.9")).toContain("/usr/bin/systemctl restart *");
    expect(sudoersLine("1.9.10")).toContain("^(start|stop|restart|reload)");
  });
});
