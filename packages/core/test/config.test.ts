import { describe, expect, it, vi } from "vitest";
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
    expect(cfg.servers[0]!.serviceManager).toBe("auto");
    expect(cfg.defaults.approvalMode).toBe("ask-destructive");
    expect(cfg.defaults.maxSshOutputBytes).toBe(1_048_576);
    // "web-1" matches no tier hint, so it lands on the strictest tier.
    expect(cfg.servers[0]!.group).toBe("prod");
  });

  it("accepts an explicit service manager override", () => {
    const cfg = parseFleetConfig(`
[[servers]]
name = "edge-1"
host = "h"
user = "u"
serviceManager = "openrc"
`);
    expect(cfg.servers[0]!.serviceManager).toBe("openrc");
  });

  it("accepts a bounded SSH output limit and rejects unsafe sizes", () => {
    expect(parseFleetConfig(`[defaults]\nmaxSshOutputBytes = 2048\n${MINIMAL}`).defaults.maxSshOutputBytes).toBe(2048);
    for (const size of [512, 16 * 1024 * 1024 + 1]) {
      expect(() => parseFleetConfig(`[defaults]\nmaxSshOutputBytes = ${size}\n${MINIMAL}`)).toThrow(ConfigError);
    }
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

  it("rejects relative or traversing scopes.paths patterns", () => {
    for (const path of ["opt/myapp/**", "/opt/myapp/../secret/**"] ) {
      expect(() =>
        parseFleetConfig(`
[[servers]]
name = "a"
host = "h"
user = "u"
[servers.scopes]
paths = ["${path}"]
`),
      ).toThrow(/invalid scopes\.paths pattern/);
    }
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
  it("auto-repairs a group/world-readable config owned by the user", async () => {
    if (process.platform === "win32") return;
    const { mkdtempSync, writeFileSync, chmodSync, statSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { loadFleetConfig } = await import("../src/index.js");
    const dir = mkdtempSync(join(tmpdir(), "flotilla-cfg-"));
    const p = join(dir, "config.toml");
    writeFileSync(p, '[[servers]]\nname="a"\nhost="h"\nuser="u"\n');
    chmodSync(p, 0o644);
    const warnSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => loadFleetConfig(p)).not.toThrow();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringMatching(/fixed loose permissions.*600/));
    warnSpy.mockRestore();
    // repaired on disk
    expect(statSync(p).mode & 0o777).toBe(0o600);
    expect(() => loadFleetConfig(p)).not.toThrow();
    rmSync(dir, { recursive: true, force: true });
  });

  it("still refuses a config not owned by the current user", async () => {
    if (process.platform === "win32") return;
    if (typeof process.getuid !== "function") return; // no ownership concept
    const { mkdtempSync, writeFileSync, chmodSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { loadFleetConfig } = await import("../src/index.js");
    const dir = mkdtempSync(join(tmpdir(), "flotilla-cfg-"));
    const p = join(dir, "config.toml");
    writeFileSync(p, '[[servers]]\nname="a"\nhost="h"\nuser="u"\n');
    chmodSync(p, 0o644);
    vi.spyOn(process, "getuid").mockReturnValue((process.getuid?.() ?? 0) + 1);
    expect(() => loadFleetConfig(p)).toThrow(/not owned by you/);
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  it("repairs the default-path config directory to 0700, except in Docker", async () => {
    if (process.platform === "win32") return;
    const { mkdtempSync, writeFileSync, chmodSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { repairConfigPermissions } = await import("../src/index.js");
    const dir = mkdtempSync(join(tmpdir(), "flotilla-cfg-"));
    const p = join(dir, "config.toml");
    writeFileSync(p, "", { mode: 0o600 });
    chmodSync(p, 0o600);
    chmodSync(dir, 0o755);
    // Default path (isDefaultPath=true): dir repaired…
    expect(repairConfigPermissions(p, true)).toEqual([expect.stringMatching(/→ 700/)]);
    // …unless inside Docker, where the bind-mount dir mode is not ours.
    process.env.FLOTILLA_IN_DOCKER = "1";
    chmodSync(dir, 0o755);
    expect(repairConfigPermissions(p, true)).toEqual([]);
    delete process.env.FLOTILLA_IN_DOCKER;
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("ensureFleetConfigFile", () => {
  it("creates dir 0700 + file 0600 on first run and is idempotent", async () => {
    if (process.platform === "win32") return;
    const { mkdtempSync, statSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { ensureFleetConfigFile } = await import("../src/index.js");
    const dir = mkdtempSync(join(tmpdir(), "flotilla-init-"));
    const p = join(dir, "sub", "config.toml");
    const first = ensureFleetConfigFile(p);
    expect(first.created).toBe(true);
    expect(first.path).toBe(p);
    expect(statSync(p).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, "sub")).mode & 0o777).toBe(0o700);
    // Idempotent: second call does not touch an existing file.
    const second = ensureFleetConfigFile(p);
    expect(second.created).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});
