import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  fingerprintFromKeyBlob,
  hostKeyMatches,
  knownHostFingerprints,
  listSshConfigAliases,
  parseSshG,
  resolveSshHost,
} from "../src/index.js";

const SSH_G = `
host web-1
hostname 10.0.1.11
user deploy
port 2222
identityfile ~/.ssh/id_ed25519
identityfile %d/.ssh/work_%r@%h
identityfile ~/.ssh/id_rsa
identityagent SSH_AUTH_SOCK
proxyjump none
proxycommand none
userknownhostsfile ~/.ssh/known_hosts ~/.ssh/known_hosts2
`;

describe("parseSshG", () => {
  it("maps the effective ssh config onto connection facts", () => {
    const eff = parseSshG("web-1", SSH_G, { home: "/home/me", localUser: "me" });
    expect(eff.hostname).toBe("10.0.1.11");
    expect(eff.user).toBe("deploy");
    expect(eff.port).toBe(2222);
    expect(eff.identityFiles).toEqual([
      "/home/me/.ssh/id_ed25519",
      "/home/me/.ssh/work_deploy@10.0.1.11",
      "/home/me/.ssh/id_rsa",
    ]);
    expect(eff.proxyJump).toBeUndefined();
    expect(eff.proxyCommand).toBeUndefined();
    expect(eff.knownHostsFiles).toEqual(["/home/me/.ssh/known_hosts", "/home/me/.ssh/known_hosts2"]);
  });

  it("keeps proxyjump / proxycommand when set and drops files with unknown tokens", () => {
    const eff = parseSshG(
      "db",
      "hostname db.internal\nuser root\nport 22\nproxyjump bastion\nproxycommand nc %h %p\nidentityfile ~/.ssh/%C\n",
      { home: "/h", localUser: "me" },
    );
    expect(eff.proxyJump).toBe("bastion");
    expect(eff.proxyCommand).toBe("nc %h %p");
    expect(eff.identityFiles).toEqual([]);
  });
});

describe("resolveSshHost", () => {
  it("runs ssh -G with the alias as a single argument", () => {
    const calls: string[][] = [];
    const eff = resolveSshHost("web-1", (file, args) => {
      calls.push([file, ...args]);
      return SSH_G;
    });
    expect(calls).toEqual([["ssh", "-G", "web-1"]]);
    expect(eff.user).toBe("deploy");
  });

  it("refuses aliases that would be parsed as ssh options", () => {
    expect(() => resolveSshHost("-oProxyCommand=evil", () => SSH_G)).toThrow(/alias/);
    expect(() => resolveSshHost("a b", () => SSH_G)).toThrow(/alias/);
  });
});

describe("listSshConfigAliases", () => {
  it("lists concrete Host aliases, following Include and skipping patterns", () => {
    const home = mkdtempSync(join(tmpdir(), "flotilla-sshcfg-"));
    const ssh = join(home, ".ssh");
    mkdirSync(join(ssh, "conf.d"), { recursive: true });
    writeFileSync(
      join(ssh, "config"),
      [
        "# comment",
        "Include conf.d/*.conf",
        "Host web-1 web-2",
        "  HostName 10.0.0.1",
        "host=db",
        "Host *.internal !secret *",
        "Host pi",
        "Match host foo",
        "",
      ].join("\n"),
    );
    writeFileSync(join(ssh, "conf.d", "lab.conf"), "Host lab-1\n  User root\nHost web-1\n");
    expect(listSshConfigAliases(join(ssh, "config"), home)).toEqual(["lab-1", "web-1", "web-2", "db", "pi"]);
  });

  it("returns an empty list when there is no ssh config", () => {
    expect(listSshConfigAliases(join(tmpdir(), "definitely-missing-ssh-config"))).toEqual([]);
  });
});

const BLOB = Buffer.from("fake-ed25519-host-key-blob").toString("base64");
const HEX = createHash("sha256").update(Buffer.from(BLOB, "base64")).digest("hex");
const B64 = createHash("sha256").update(Buffer.from(BLOB, "base64")).digest("base64").replace(/=+$/, "");

describe("host key fingerprints", () => {
  it("computes the transport's SHA256 hex form from a known_hosts key blob", () => {
    expect(fingerprintFromKeyBlob(BLOB)).toBe(`SHA256:${HEX}`);
  });

  it("matches pins written in either hex or OpenSSH base64 form", () => {
    expect(hostKeyMatches(`SHA256:${HEX}`, HEX)).toBe(true);
    expect(hostKeyMatches(HEX, HEX)).toBe(true);
    expect(hostKeyMatches(`SHA256:${B64}`, HEX)).toBe(true);
    expect(hostKeyMatches("SHA256:somethingelse", HEX)).toBe(false);
  });

  it("looks up known_hosts entries via ssh-keygen -F, with [host]:port for non-22 ports", () => {
    const calls: string[][] = [];
    const run = (file: string, args: string[]) => {
      calls.push([file, ...args]);
      if (args[2] === "/kh2") throw new Error("exit 1: not found");
      return `# Host [10.0.1.11]:2222 found: line 3\n[10.0.1.11]:2222 ssh-ed25519 ${BLOB}\n@revoked [10.0.1.11]:2222 ssh-rsa AAAA\n`;
    };
    const fps = knownHostFingerprints("10.0.1.11", 2222, ["/kh1", "/kh2"], run);
    expect(calls).toEqual([
      ["ssh-keygen", "-F", "[10.0.1.11]:2222", "-f", "/kh1"],
      ["ssh-keygen", "-F", "[10.0.1.11]:2222", "-f", "/kh2"],
    ]);
    expect(fps).toEqual([`SHA256:${HEX}`]);
  });
});
