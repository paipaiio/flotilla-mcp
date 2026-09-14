import { posix } from "node:path";
import { describe, expect, it } from "vitest";
import { checkPathScope, classifyCommand, parseTarget, TargetError } from "../src/index.js";

function seeded(seed = 0x5eedc0de): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

function randomText(next: () => number, maxLength: number, alphabet: string): string {
  const length = Math.floor(next() * (maxLength + 1));
  let value = "";
  for (let i = 0; i < length; i++) value += alphabet[Math.floor(next() * alphabet.length)];
  return value;
}

describe("deterministic fuzz regression", () => {
  it("classifies 10,000 arbitrary shell-like strings without escaping the result domain", () => {
    const next = seeded();
    const alphabet = "abcXYZ019 _-./'\"\\;$()|&<>\n\t\0";
    const classes = new Set(["read-only", "safe", "unknown", "destructive", "privileged", "forbidden"]);
    for (let i = 0; i < 10_000; i++) {
      expect(classes.has(classifyCommand(randomText(next, 96, alphabet)))).toBe(true);
    }
  });

  it("keeps shell operators and destructive words inert inside single-quoted data", () => {
    const next = seeded(0x51a11);
    const alphabet = "abcXYZ019 _-./;$()|&<>\n\t";
    for (let i = 0; i < 2_000; i++) {
      const payload = `${randomText(next, 72, alphabet)}; rm -rf / | sh`;
      expect(classifyCommand(`echo '${payload}'`)).toBe("read-only");
    }
  });

  it("detects forbidden commands through randomized benign wrappers and whitespace", () => {
    const next = seeded(0xf0b1dde);
    const wrappers = ["", "command ", "env TEST=value ", "env -i TEST=value command "];
    for (let i = 0; i < 2_000; i++) {
      const spaces = " ".repeat(1 + Math.floor(next() * 6));
      const wrapper = wrappers[Math.floor(next() * wrappers.length)];
      expect(classifyCommand(`${spaces}${wrapper}rm${spaces}-rf${spaces}/${spaces}`)).toBe("forbidden");
    }
  });

  it("never admits lexical traversal outside a recursive path scope", () => {
    const next = seeded(0x5c0fe);
    const server = { name: "fixture", scopes: { paths: ["/opt/app/**"] } };
    const segments = [".", "..", "data", "logs", "x", "", "tmp"];
    for (let i = 0; i < 5_000; i++) {
      const count = 1 + Math.floor(next() * 12);
      const suffix = Array.from({ length: count }, () => segments[Math.floor(next() * segments.length)]).join("/");
      const candidate = `/opt/app/${suffix}`;
      const normalized = posix.normalize(candidate);
      const isInside = normalized === "/opt/app" || normalized.startsWith("/opt/app/");
      expect(checkPathScope(server, candidate) === null).toBe(isInside);
    }
  });

  it("parses or returns only the domain-specific error for 5,000 target expressions", () => {
    const next = seeded(0x7a267e7);
    const alphabet = "abcXYZ019 _-,:!/.\t\n\0";
    for (let i = 0; i < 5_000; i++) {
      try {
        const parsed = parseTarget(randomText(next, 80, alphabet));
        expect(parsed.include.length).toBeGreaterThan(0);
      } catch (error) {
        expect(error).toBeInstanceOf(TargetError);
      }
    }
  });
});
