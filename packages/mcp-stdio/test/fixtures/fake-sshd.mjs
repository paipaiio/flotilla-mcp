#!/usr/bin/env node
/**
 * Test-only SSH server built on ssh2's Server: real handshakes, real exec
 * (sh -c with HOME pointed at a sandbox), real authorized_keys checks.
 *
 *   node fake-sshd.mjs --home <dir> [--password <pw>] [--no-pubkey] [--user <name>]
 *
 * Prints one JSON line {"port":N,"hostKey":"SHA256:<hex>","hostKeyLine":"ssh-ed25519 AAAA..."}
 * once listening. --no-pubkey models a password-only server (sshd with
 * PubkeyAuthentication no). Commands run as the invoking OS user.
 */
import { spawn } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";

// ssh2 is a dependency of flotilla-core, not of this package.
const ssh2 = createRequire(new URL("../../../core/package.json", import.meta.url))("ssh2");

const { Server, utils } = ssh2;
const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const home = opt("--home");
if (!home) throw new Error("--home required");
const password = opt("--password");
const pubkey = !args.includes("--no-pubkey");
const user = opt("--user");

const hostKeys = utils.generateKeyPairSync("ed25519");
const hostPub = utils.parseKey(hostKeys.public);
const hostBlob = hostPub.getPublicSSH();

function authorizedKeys() {
  const file = join(home, ".ssh", "authorized_keys");
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .map((l) => l.replace(/^from="[^"]*"\s+/, "").trim())
    .filter(Boolean)
    .map((l) => utils.parseKey(l))
    .filter((k) => !(k instanceof Error));
}

const sameBuffer = (a, b) => a.length === b.length && timingSafeEqual(a, b);

const server = new Server({ hostKeys: [hostKeys.private] }, (client) => {
  client.on("error", () => {});
  client.on("authentication", (ctx) => {
    const methods = [...(password !== undefined ? ["password"] : []), ...(pubkey ? ["publickey"] : [])];
    const reject = () => ctx.reject(methods);
    if (user && ctx.username !== user) return reject();
    if (ctx.method === "password" && password !== undefined) {
      return ctx.password === password ? ctx.accept() : reject();
    }
    if (ctx.method === "publickey" && pubkey) {
      const match = authorizedKeys().find((k) => k.type === ctx.key.algo && sameBuffer(k.getPublicSSH(), ctx.key.data));
      if (!match) return reject();
      if (!ctx.signature) return ctx.accept(); // key probe
      return match.verify(ctx.blob, ctx.signature, ctx.hashAlgo) === true ? ctx.accept() : reject();
    }
    return reject();
  });
  client.on("ready", () => {
    client.on("session", (accept) => {
      const session = accept();
      session.on("exec", (acceptExec, _reject, info) => {
        const stream = acceptExec();
        const child = spawn("sh", ["-c", info.command], { cwd: home, env: { ...process.env, HOME: home } });
        stream.pipe(child.stdin);
        // end:false — the channel must stay open until exit-status is sent.
        child.stdout.pipe(stream, { end: false });
        child.stderr.pipe(stream.stderr, { end: false });
        child.on("close", (code) => {
          stream.exit(code ?? 1);
          stream.end();
        });
      });
    });
  });
});

server.listen(0, "127.0.0.1", () => {
  const port = server.address().port;
  const hostKey = `SHA256:${createHash("sha256").update(hostBlob).digest("hex")}`;
  const hostKeyLine = `${hostPub.type} ${hostBlob.toString("base64")}`;
  process.stdout.write(JSON.stringify({ port, hostKey, hostKeyLine }) + "\n");
});
