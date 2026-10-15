import { describe, expect, it } from "vitest";
import {
  OnboardError,
  buildCreateUserCommand,
  connectPlanned,
  onboardServer,
  parseFleetConfig,
  planServer,
  removeServerFromConfig,
  setServerFields,
  type ProbeResult,
  type ServerConfig,
  type SshEffectiveConfig,
} from "../src/index.js";

function eff(over: Partial<SshEffectiveConfig> = {}): SshEffectiveConfig {
  return {
    alias: "web-1",
    hostname: "10.0.1.11",
    user: "deploy",
    port: 22,
    identityFiles: ["/home/me/.ssh/id_ed25519", "/home/me/.ssh/id_rsa"],
    knownHostsFiles: ["/home/me/.ssh/known_hosts"],
    ...over,
  };
}

const exists = (p: string) => p.endsWith("id_ed25519");

describe("planServer", () => {
  it("fills connection facts from ssh -G and infers the tier from the name", () => {
    const plan = planServer(
      { name: "web-1" },
      { sshG: () => eff(), knownHosts: () => [], exists, env: { SSH_AUTH_SOCK: "/tmp/agent" } },
    );
    expect(plan.server).toMatchObject({
      name: "web-1",
      host: "10.0.1.11",
      user: "deploy",
      port: 22,
      group: "prod",
      role: "operator",
    });
    expect(plan.candidates.map((c) => c.label)).toEqual(["key /home/me/.ssh/id_ed25519", "ssh-agent"]);
  });

  it("lets explicit flags win over ssh config and keeps an explicit key as the only candidate", () => {
    const plan = planServer(
      { name: "lab-dev", host: "192.168.1.9", user: "pi", port: 2200, keyRef: "~/.ssh/pi", role: "admin", tags: ["arm"] },
      { sshG: (alias) => eff({ alias, hostname: alias }), knownHosts: () => [], exists, env: {} },
    );
    expect(plan.server).toMatchObject({ host: "192.168.1.9", user: "pi", port: 2200, group: "dev", role: "admin", tags: ["arm"] });
    expect(plan.candidates).toEqual([{ auth: "key", keyRef: "~/.ssh/pi", label: "key ~/.ssh/pi" }]);
  });

  it("maps ProxyJump onto via when the jump host is already in the fleet", () => {
    const plan = planServer(
      { name: "db-1" },
      { sshG: () => eff({ proxyJump: "ops@bastion:22" }), knownHosts: () => [], exists, env: {}, fleetServers: ["bastion"] },
    );
    expect(plan.server.via).toBe("bastion");
  });

  it("refuses unsupported jump setups with an actionable message", () => {
    const deps = { knownHosts: () => [], exists, env: {} };
    expect(() => planServer({ name: "db-1" }, { ...deps, sshG: () => eff({ proxyJump: "bastion" }) })).toThrow(/import-ssh bastion/);
    expect(() => planServer({ name: "db-1" }, { ...deps, sshG: () => eff({ proxyJump: "a,b" }) })).toThrow(OnboardError);
    expect(() => planServer({ name: "db-1" }, { ...deps, sshG: () => eff({ proxyCommand: "nc %h %p" }) })).toThrow(/ProxyCommand/);
  });

  it("returns no candidates (instead of failing) when there is no key or agent", async () => {
    const plan = planServer({ name: "web-1" }, { sshG: () => eff(), knownHosts: () => [], exists: () => false, env: {} });
    expect(plan.candidates).toEqual([]);
    await expect(connectPlanned(plan, { probe: async () => ({ ok: true }) })).rejects.toMatchObject({ code: "auth-failed" });
  });
});

function probeWith(results: Record<string, ProbeResult>) {
  const seen: string[] = [];
  const probe = async (s: ServerConfig) => {
    const key = s.auth === "key" ? `key ${s.keyRef}` : s.auth;
    seen.push(key);
    return results[key] ?? { ok: false, error: "auth failed" };
  };
  return { probe, seen };
}

describe("connectPlanned", () => {
  const plan = () =>
    planServer({ name: "web-1" }, { sshG: () => eff(), knownHosts: () => ["SHA256:aa", "SHA256:bb"], exists, env: { SSH_AUTH_SOCK: "/a" } });

  it("tries candidates in order and keeps the first that authenticates", async () => {
    const { probe, seen } = probeWith({ agent: { ok: true, hostname: "web-1", uid: 1000, hostKey: "SHA256:bb" } });
    const res = await connectPlanned(plan(), { probe });
    expect(seen).toEqual(["key /home/me/.ssh/id_ed25519", "agent"]);
    expect(res.server.auth).toBe("agent");
    expect(res.server.keyRef).toBeUndefined();
    expect(res.server.trustedHostKey).toBe("SHA256:bb");
    expect(res.hostKeySource).toBe("known_hosts");
  });

  it("refuses a host key that contradicts known_hosts", async () => {
    const { probe } = probeWith({ "key /home/me/.ssh/id_ed25519": { ok: true, hostKey: "SHA256:evil" } });
    await expect(connectPlanned(plan(), { probe })).rejects.toThrow(/HOST KEY MISMATCH/);
  });

  it("falls back to TOFU when known_hosts has no entry", async () => {
    const p = planServer({ name: "web-1" }, { sshG: () => eff(), knownHosts: () => [], exists, env: {} });
    const { probe } = probeWith({ "key /home/me/.ssh/id_ed25519": { ok: true, hostKey: "SHA256:new" } });
    const res = await connectPlanned(p, { probe });
    expect(res.hostKeySource).toBe("tofu");
    expect(res.server.trustedHostKey).toBe("SHA256:new");
  });

  it("stops at the first network error instead of waiting out every candidate", async () => {
    const { probe, seen } = probeWith({ "key /home/me/.ssh/id_ed25519": { ok: false, error: "Timed out while waiting for handshake" } });
    await expect(connectPlanned(plan(), { probe })).rejects.toMatchObject({ code: "unreachable" });
    expect(seen).toEqual(["key /home/me/.ssh/id_ed25519"]);
  });

  it("lists every attempt when nothing authenticates", async () => {
    const { probe } = probeWith({});
    await expect(connectPlanned(plan(), { probe })).rejects.toThrow(/key \/home\/me\/.ssh\/id_ed25519: auth failed[\s\S]*ssh-agent: auth failed/);
  });
});

describe("buildCreateUserCommand", () => {
  const KEY = `ssh-ed25519 ${"A".repeat(68)} flotilla-fleet`;

  it("creates the user, installs the key and writes a validated sudoers allowlist", () => {
    const cmd = buildCreateUserCommand("flotilla", KEY, true);
    expect(cmd).toContain("useradd -m -s /bin/sh");
    expect(cmd).toContain("adduser -D -s /bin/sh");
    expect(cmd).toContain("authorized_keys");
    expect(cmd).toContain("visudo -cf");
    expect(cmd).toContain("command -v systemctl");
    expect(cmd).toContain("restart *");
    expect(cmd).not.toContain("edit *");
    expect(cmd).toContain("FLOTILLA_USER_READY");
  });

  it("can skip sudo entirely", () => {
    expect(buildCreateUserCommand("flotilla", KEY, false)).not.toContain("sudoers");
  });

  it("rejects hostile user names and keys", () => {
    expect(() => buildCreateUserCommand("root", KEY, false)).toThrow(OnboardError);
    expect(() => buildCreateUserCommand("x;rm -rf /", KEY, false)).toThrow(OnboardError);
    expect(() => buildCreateUserCommand("flotilla", "ssh-ed25519 AAAA'; reboot", false)).toThrow(OnboardError);
  });
});

describe("onboardServer", () => {
  const KEY = `ssh-ed25519 ${"B".repeat(68)} flotilla-fleet`;
  const fleetKey = () => ({ publicKey: KEY, privateKeyPath: "/cfg/fleet_ed25519" });
  const scan = async () => ({ fingerprint: "SHA256:k", type: "ssh-ed25519" });
  const planDeps = { sshG: () => eff({ user: "root" }), knownHosts: () => [], exists, env: {}, scan };
  const asked: string[] = [];
  const password = (value: string | undefined) => ({
    obtain: async (t: { user: string; host: string }) => {
      asked.push(`${t.user}@${t.host}`);
      return value;
    },
  });
  const ok = (uid = 0) => ({ ok: true, uid, hostKey: "SHA256:k", hostKeyType: "ssh-ed25519" });
  const denied = { ok: false, error: "All configured authentication methods failed" };

  it("uses the user's key when it works and never asks for a password", async () => {
    asked.length = 0;
    const res = await onboardServer({ name: "web-1" }, { fleet: [], password: password("pw"), deps: { ...planDeps, probe: async () => ok() } });
    expect(res.method).toBe("key");
    expect(asked).toEqual([]);
    expect(res.notes.map((n) => n.code)).toEqual(["tofu", "root-account"]);
  });

  it("fails fast on an unreachable host without trying credentials or asking for a password", async () => {
    asked.length = 0;
    let probes = 0;
    const err = await onboardServer(
      { name: "web-1" },
      {
        fleet: [],
        password: password("pw"),
        deps: {
          ...planDeps,
          scan: async () => { throw new OnboardError("Could not read the host key: ECONNREFUSED", "unreachable"); },
          probe: async () => { probes++; return ok(); },
        },
      },
    ).catch((e) => e);
    expect(err).toMatchObject({ code: "unreachable" });
    expect(probes).toBe(0);
    expect(asked).toEqual([]);
  });

  it("stops at a known_hosts mismatch before any credential is offered", async () => {
    asked.length = 0;
    const err = await onboardServer(
      { name: "web-1" },
      { fleet: [], password: password("pw"), deps: { ...planDeps, knownHosts: () => [{ type: "ssh-ed25519", fingerprint: "SHA256:trusted" }], probe: async () => ok() } },
    ).catch((e) => e);
    expect(err).toMatchObject({ code: "host-key-mismatch" });
    expect(asked).toEqual([]);
  });

  it("only negotiates key types known_hosts holds, so a MITM cannot downgrade to an unverified type", async () => {
    const scanned: Array<string | undefined> = [];
    const err = await onboardServer(
      { name: "web-1" },
      {
        fleet: [],
        password: password("pw"),
        deps: {
          ...planDeps,
          knownHosts: () => [{ type: "ssh-ed25519", fingerprint: "SHA256:trusted" }],
          // A MITM can only answer with its own key; restricted to ed25519 it cannot match.
          scan: async (s) => { scanned.push(s.hostKeyAlgorithm); return { fingerprint: "SHA256:mitm", type: "ssh-ed25519" }; },
          probe: async () => ok(),
        },
      },
    ).catch((e) => e);
    expect(scanned).toEqual(["ssh-ed25519"]);
    expect(err).toMatchObject({ code: "host-key-mismatch" });
  });

  it("verifies servers behind a jump host before any credential, and pins key + algorithm", async () => {
    const order: string[] = [];
    const res = await onboardServer(
      { name: "db-1" },
      {
        fleet: [{ ...BASE_SERVER, name: "bastion" }],
        fleetKey,
        password: password("s3cret"),
        deps: {
          ...planDeps,
          sshG: () => eff({ proxyJump: "bastion" }),
          scan: async (s) => { order.push(`scan via ${s.via}`); return { fingerprint: "SHA256:k", type: "ssh-ed25519" }; },
          probe: async (s, secrets) => {
            order.push(`probe ${s.auth} pinned=${s.trustedHostKey}`);
            return s.auth === "password" ? (secrets ? ok(1000) : denied) : s.keyRef === "/cfg/fleet_ed25519" ? ok(1000) : denied;
          },
          exec: async () => ({ ok: true, stdout: "INSTALLED\n", stderr: "" }),
        },
      },
    );
    expect(order[0]).toBe("scan via bastion");
    expect(order.find((o) => o.startsWith("probe password"))).toBe("probe password pinned=SHA256:k");
    expect(res.server).toMatchObject({ via: "bastion", trustedHostKey: "SHA256:k", hostKeyAlgorithm: "ssh-ed25519" });
  });

  it("falls back to the password once, installs the fleet key and switches to it", async () => {
    asked.length = 0;
    const execs: Array<{ cmd: string; secrets?: unknown }> = [];
    const res = await onboardServer(
      { name: "web-1" },
      {
        fleet: [],
        fleetKey,
        password: password("s3cret"),
        deps: {
          ...planDeps,
          probe: async (s, secrets) => (s.auth === "password" ? (secrets?.password === "s3cret" ? ok(1000) : denied) : s.keyRef === "/cfg/fleet_ed25519" ? ok(1000) : denied),
          exec: async (_s, cmd, o) => { execs.push({ cmd, secrets: o.secrets }); return { ok: true, stdout: "INSTALLED\n", stderr: "" }; },
        },
      },
    );
    expect(asked).toEqual(["root@10.0.1.11"]);
    expect(res.method).toBe("password→key");
    expect(res.server).toMatchObject({ auth: "key", keyRef: "/cfg/fleet_ed25519", trustedHostKey: "SHA256:k" });
    expect(res.passwordToStore).toBeUndefined();
    expect(execs[0]!.cmd).toContain("authorized_keys");
  });

  it("keeps password auth for servers that refuse keys and hands the password back to store", async () => {
    const res = await onboardServer(
      { name: "web-1" },
      {
        fleet: [],
        fleetKey,
        password: password("s3cret"),
        deps: {
          ...planDeps,
          probe: async (s, secrets) => (s.auth === "password" && secrets?.password === "s3cret" ? ok(1000) : denied),
          exec: async () => ({ ok: true, stdout: "INSTALLED\n", stderr: "" }),
        },
      },
    );
    expect(res.method).toBe("password");
    expect(res.server.auth).toBe("password");
    expect(res.server.keyRef).toBeUndefined();
    expect(res.passwordToStore).toBe("s3cret");
    expect(res.notes.map((n) => n.code)).toContain("key-not-accepted");
  });

  it("passwordOnly skips key installation entirely", async () => {
    let execs = 0;
    const res = await onboardServer(
      { name: "web-1" },
      { fleet: [], fleetKey, passwordOnly: true, password: password("s3cret"), deps: { ...planDeps, probe: async () => ok(1000), exec: async () => { execs++; return { ok: true, stdout: "", stderr: "" }; } } },
    );
    expect(res.method).toBe("password");
    expect(execs).toBe(0);
  });

  it("reports a rejected password and a missing password source distinctly", async () => {
    const rejected = await onboardServer(
      { name: "web-1" },
      { fleet: [], fleetKey, password: password("wrong"), deps: { ...planDeps, probe: async () => denied } },
    ).catch((e) => e);
    expect(rejected).toMatchObject({ code: "password-rejected" });
    // A terminal can retry a mistyped password.
    const typed = ["typo", "s3cret"];
    const retried = await onboardServer(
      { name: "web-1" },
      {
        fleet: [],
        password: { maxAttempts: 3, obtain: async () => typed.shift() },
        deps: { ...planDeps, probe: async (s, secrets) => (s.auth === "password" && secrets?.password === "s3cret" ? ok(1000) : denied) },
      },
    );
    expect(retried.method).toBe("password");
    const noSource = await onboardServer({ name: "web-1" }, { fleet: [], deps: { ...planDeps, probe: async () => denied } }).catch((e) => e);
    expect(noSource).toMatchObject({ code: "password-needed" });
    expect(noSource.details.attempts.length).toBeGreaterThan(0);
  });

  it("creates a low-privilege user as root, then switches to it", async () => {
    const execs: Array<{ cmd: string; sudo?: boolean }> = [];
    const probes: string[] = [];
    const res = await onboardServer(
      { name: "web-1" },
      {
        fleet: [],
        fleetKey,
        createUser: { name: "flotilla", sudo: true },
        deps: {
          ...planDeps,
          probe: async (s) => { probes.push(s.user); return ok(s.user === "root" ? 0 : 1001); },
          exec: async (_s, cmd, o) => { execs.push({ cmd, sudo: o.sudo }); return { ok: true, stdout: "FLOTILLA_USER_READY\n", stderr: "" }; },
        },
      },
    );
    expect(execs).toHaveLength(1);
    expect(execs[0]!.sudo).toBe(false);
    expect(probes).toEqual(["root", "flotilla"]);
    expect(res.server).toMatchObject({ user: "flotilla", auth: "key", keyRef: "/cfg/fleet_ed25519" });
    expect(res.createdUser).toBe("flotilla");
  });

  it("creates the user through sudo with the typed password for a non-root account", async () => {
    const execs: Array<{ sudo?: boolean; secrets?: { sudo?: string } }> = [];
    await onboardServer(
      { name: "web-1", user: "admin" },
      {
        fleet: [],
        fleetKey,
        createUser: { name: "flotilla", sudo: true },
        password: password("s3cret"),
        deps: {
          ...planDeps,
          probe: async (s, secrets) => (s.auth === "password" ? (secrets ? ok(1000) : denied) : s.keyRef === "/cfg/fleet_ed25519" ? ok(1000) : denied),
          exec: async (_s, cmd, o) => {
            execs.push({ sudo: o.sudo, secrets: o.secrets });
            return { ok: true, stdout: cmd.includes("FLOTILLA_USER_READY") ? "FLOTILLA_USER_READY\n" : "INSTALLED\n", stderr: "" };
          },
        },
      },
    );
    expect(execs.at(-1)).toMatchObject({ sudo: true, secrets: { sudo: "s3cret" } });
  });

  it("explains create-user failures and refuses them on password-only servers", async () => {
    const failed = await onboardServer(
      { name: "web-1" },
      {
        fleet: [],
        fleetKey,
        createUser: { name: "flotilla", sudo: false },
        deps: { ...planDeps, probe: async () => ok(1000), exec: async () => ({ ok: false, stdout: "", stderr: "sudo: a password is required" }) },
      },
    ).catch((e) => e);
    expect(failed).toMatchObject({ code: "create-user-failed" });
    expect(failed.message).toMatch(/a password is required/);
    const pwOnly = await onboardServer(
      { name: "web-1" },
      { fleet: [], fleetKey, passwordOnly: true, createUser: { name: "flotilla", sudo: true }, password: password("p"), deps: { ...planDeps, probe: async () => ok(1000) } },
    ).catch((e) => e);
    expect(pwOnly).toMatchObject({ code: "create-user-failed" });
  });

  it("refuses duplicate names before touching the network", async () => {
    await expect(
      onboardServer({ name: "web-1" }, { fleet: [{ ...BASE_SERVER }], deps: { ...planDeps, probe: async () => { throw new Error("no"); } } }),
    ).rejects.toMatchObject({ code: "duplicate" });
  });
});

const BASE_SERVER: ServerConfig = {
  name: "web-1", host: "h", port: 22, user: "u", auth: "agent", group: "prod", tags: [], role: "operator", readOnly: false,
};

const CONFIG = `# fleet config
[defaults]
approvalMode = "ask-destructive"

# primary web node
[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
group = "prod"
tags = [
  "web",
  "nginx",
]

[servers.scopes]
paths = ["/opt/app/**"]

[[servers]]
name = "db-1"
host = "10.0.1.21"
user = "deploy"
via = "web-1"

[[servers]]
name = "pi"
host = "192.168.1.9"
user = "pi"
`;

describe("removeServerFromConfig", () => {
  it("removes the block including its sub-tables and keeps comments elsewhere", () => {
    const next = removeServerFromConfig(CONFIG, "pi");
    expect(parseFleetConfig(next).servers.map((s) => s.name)).toEqual(["web-1", "db-1"]);
    expect(next).toContain("# primary web node");
  });

  it("refuses to remove a server that others jump through", () => {
    expect(() => removeServerFromConfig(CONFIG, "web-1")).toThrow(/db-1/);
  });

  it("refuses unknown names", () => {
    expect(() => removeServerFromConfig(CONFIG, "nope")).toThrow(OnboardError);
  });
});

describe("setServerFields", () => {
  it("rewrites existing keys (including multi-line arrays) and inserts missing ones", () => {
    const next = setServerFields(CONFIG, "web-1", { role: "viewer", tags: ["web"], readOnly: true });
    const web = parseFleetConfig(next).servers.find((s) => s.name === "web-1")!;
    expect(web.role).toBe("viewer");
    expect(web.tags).toEqual(["web"]);
    expect(web.readOnly).toBe(true);
    expect(web.scopes?.paths).toEqual(["/opt/app/**"]);
    expect(next).toContain("# primary web node");
  });

  it("changes the tier of a server that had none", () => {
    const next = setServerFields(CONFIG, "pi", { group: "lab" });
    expect(parseFleetConfig(next).servers.find((s) => s.name === "pi")!.group).toBe("lab");
  });

  it("rejects invalid values instead of writing a broken config", () => {
    expect(() => setServerFields(CONFIG, "pi", { role: "root" as never })).toThrow();
  });
});
