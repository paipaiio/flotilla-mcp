import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tokenCommand } from "../src/token-cli.js";

let dir: string;
let file: string;
let errors: string[];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flotilla-token-cli-"));
  file = join(dir, "gateway-tokens.json");
  errors = [];
  vi.spyOn(console, "error").mockImplementation((m: string) => void errors.push(String(m)));
  vi.spyOn(console, "log").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

describe("flotilla-gateway token create", () => {
  it("refuses to guess the scope when neither --targets nor --all is given", () => {
    expect(tokenCommand(["create", "ci", "--role", "operator", "--tokens-file", file])).toBe(2);
    expect(errors.join("\n")).toMatch(/--targets[\s\S]*--all/);
  });

  it("refuses --targets together with --all", () => {
    expect(tokenCommand(["create", "ci", "--role", "viewer", "--all", "--targets", "tag:web", "--tokens-file", file])).toBe(2);
  });

  it("creates a scoped token with --targets and a whole-fleet token only with --all", () => {
    expect(tokenCommand(["create", "web", "--role", "viewer", "--targets", "tag:web", "--tokens-file", file])).toBe(0);
    expect(tokenCommand(["create", "all", "--role", "viewer", "--all", "--tokens-file", file])).toBe(0);
    const saved = JSON.parse(readFileSync(file, "utf8")) as { tokens: Array<{ name: string; targets?: string[] }> };
    expect(saved.tokens.find((t) => t.name === "web")?.targets).toEqual(["tag:web"]);
    expect(saved.tokens.find((t) => t.name === "all")?.targets).toBeUndefined();
  });
});
