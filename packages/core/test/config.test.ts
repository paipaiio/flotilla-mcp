import { describe, expect, it } from "vitest";
import { ConfigError, inferTier, parseFleetConfig } from "../src/index.js";

const MINIMAL = `
[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
`;

describe("parseFleetConfig", () => {
  it("applies defaults and infers tier from the name", () => {
    const cfg = parseFleetConfig(MINIMAL);
    expect(cfg.servers[0]!.port).toBe(22);
    expect(cfg.servers[0]!.auth).toBe("agent");
    expect(cfg.servers[0]!.role).toBe("operator");
    expect(cfg.defaults.approvalMode).toBe("ask-destructive");
    // "web-1" matches no tier hint, so it lands on the strictest tier.
    expect(cfg.servers[0]!.group).toBe("prod");
  });

  it("respects an explicit group over inference", () => {
    const cfg = parseFleetConfig(`
[[servers]]
name = "web-1"
host = "h"
user = "u"
group = "staging"
`);
    expect(cfg.servers[0]!.group).toBe("staging");
  });

  it("rejects duplicate server names", () => {
    expect(() =>
      parseFleetConfig(`
[[servers]]
name = "a"
host = "h"
user = "u"
[[servers]]
name = "a"
host = "h2"
user = "u"
`),
    ).toThrow(/Duplicate server name/);
  });

  it("rejects unknown keys instead of silently ignoring them", () => {
    expect(() =>
      parseFleetConfig(`
[[servers]]
name = "a"
host = "h"
user = "u"
protl = 2222
`),
    ).toThrow(ConfigError);
  });

  it("rejects a via pointing nowhere", () => {
    expect(() =>
      parseFleetConfig(`
[[servers]]
name = "a"
host = "h"
user = "u"
via = "ghost"
`),
    ).toThrow(/via="ghost"/);
  });

  it("rejects jump-host cycles", () => {
    expect(() =>
      parseFleetConfig(`
[[servers]]
name = "a"
host = "h"
user = "u"
via = "b"
[[servers]]
name = "b"
host = "h2"
user = "u"
via = "a"
`),
    ).toThrow(/cycles/);
  });

  it("rejects auth=key without keyRef", () => {
    expect(() =>
      parseFleetConfig(`
[[servers]]
name = "a"
host = "h"
user = "u"
auth = "key"
`),
    ).toThrow(/keyRef/);
  });

  it("rejects groups referencing unknown servers", () => {
    expect(() =>
      parseFleetConfig(`
[[servers]]
name = "a"
host = "h"
user = "u"
[[groups]]
name = "g"
match = { names = ["ghost"] }
`),
    ).toThrow(/unknown server "ghost"/);
  });

  it("rejects invalid scope regexes at startup", () => {
    expect(() =>
      parseFleetConfig(`
[[servers]]
name = "a"
host = "h"
user = "u"
[servers.scopes]
commands = ["[unclosed"]
`),
    ).toThrow(/invalid scopes\.commands pattern/);
  });

  it("rejects invalid TOML", () => {
    expect(() => parseFleetConfig("[[[not toml")).toThrow(ConfigError);
  });
});

describe("inferTier", () => {
  it("matches known hints in names", () => {
    expect(inferTier("prod-web-1")).toBe("prod");
    expect(inferTier("my-staging-db")).toBe("staging");
    expect(inferTier("devbox")).toBe("dev");
    expect(inferTier("ci-sandbox")).toBe("sandbox");
  });

  it("defaults unrecognized names to prod", () => {
    expect(inferTier("web-01")).toBe("prod");
  });
});

describe("loadFleetConfig permissions", () => {
  it("refuses a group/world-readable config on POSIX", async () => {
    if (process.platform === "win32") return;
    const { mkdtempSync, writeFileSync, chmodSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { loadFleetConfig } = await import("../src/index.js");
    const dir = mkdtempSync(join(tmpdir(), "flotilla-cfg-"));
    const p = join(dir, "config.toml");
    writeFileSync(p, '[[servers]]\nname="a"\nhost="h"\nuser="u"\n');
    chmodSync(p, 0o644);
    expect(() => loadFleetConfig(p)).toThrow(/chmod 600/);
    chmodSync(p, 0o600);
    expect(() => loadFleetConfig(p)).not.toThrow();
    rmSync(dir, { recursive: true, force: true });
  });
});
