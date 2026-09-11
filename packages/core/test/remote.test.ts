import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RemoteConfigError,
  fetchRemoteConfig,
  parseFleetConfig,
  pullConfigToFile,
} from "../src/index.js";

const GOOD_TOML = `
[[servers]]
name = "web-1"
host = "10.0.1.11"
user = "deploy"
group = "dev"
`;

let server: Server;
let baseUrl: string;
let lastAuth: string | undefined;
let payload = GOOD_TOML;
let status = 200;

beforeAll(async () => {
  server = createServer((req, res) => {
    lastAuth = req.headers.authorization;
    res.statusCode = status;
    res.end(status === 200 ? payload : "error");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no addr");
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise((r) => server.close(r));
});

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "flotilla-remote-"));
}

describe("fetchRemoteConfig", () => {
  it("fetches TOML over HTTP", async () => {
    status = 200;
    payload = GOOD_TOML;
    const text = await fetchRemoteConfig({ url: `${baseUrl}/fleet.toml` });
    expect(text).toBe(GOOD_TOML);
  });

  it("sends the bearer token from the named env var", async () => {
    process.env.FLOTILLA_TEST_TOKEN = "sekrit";
    try {
      await fetchRemoteConfig({ url: `${baseUrl}/fleet.toml`, tokenEnv: "FLOTILLA_TEST_TOKEN" });
      expect(lastAuth).toBe("Bearer sekrit");
    } finally {
      delete process.env.FLOTILLA_TEST_TOKEN;
    }
  });

  it("fails when the token env var is missing", async () => {
    await expect(
      fetchRemoteConfig({ url: `${baseUrl}/fleet.toml`, tokenEnv: "FLOTILLA_NOPE_UNSET" }),
    ).rejects.toThrow(RemoteConfigError);
  });

  it("fails on non-200", async () => {
    status = 404;
    await expect(fetchRemoteConfig({ url: `${baseUrl}/fleet.toml` })).rejects.toThrow(/HTTP 404/);
    status = 200;
  });
});

describe("pullConfigToFile", () => {
  it("installs a valid remote config atomically with 0600", async () => {
    payload = GOOD_TOML;
    const dir = tmpDir();
    try {
      const dest = join(dir, "config.toml");
      const result = await pullConfigToFile({ url: `${baseUrl}/fleet.toml` }, dest);
      expect(result.servers).toEqual(["web-1"]);
      expect(result.backupPath).toBeUndefined();
      expect(readFileSync(dest, "utf8")).toBe(GOOD_TOML);
      expect(statSync(dest).mode & 0o777).toBe(0o600);
      // and it parses
      expect(parseFleetConfig(readFileSync(dest, "utf8")).servers[0]!.name).toBe("web-1");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("backs up the previous config before replacing it", async () => {
    const dir = tmpDir();
    try {
      const dest = join(dir, "config.toml");
      writeFileSync(dest, '[[servers]]\nname = "old"\nhost = "h"\nuser = "u"\n', "utf8");
      const result = await pullConfigToFile({ url: `${baseUrl}/fleet.toml` }, dest);
      expect(result.backupPath).toBeDefined();
      expect(readFileSync(result.backupPath!, "utf8")).toContain('"old"');
      expect(readFileSync(dest, "utf8")).toContain('"web-1"');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects an invalid payload and leaves the local file untouched", async () => {
    payload = "this is not = [valid toml";
    const dir = tmpDir();
    try {
      const dest = join(dir, "config.toml");
      writeFileSync(dest, GOOD_TOML, "utf8");
      await expect(pullConfigToFile({ url: `${baseUrl}/fleet.toml` }, dest)).rejects.toThrow();
      expect(readFileSync(dest, "utf8")).toBe(GOOD_TOML); // untouched
    } finally {
      payload = GOOD_TOML;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a payload that fails schema validation", async () => {
    payload = '[[servers]]\nname = "x"\n'; // missing host/user
    const dir = tmpDir();
    try {
      const dest = join(dir, "config.toml");
      await expect(pullConfigToFile({ url: `${baseUrl}/fleet.toml` }, dest)).rejects.toThrow(
        /Invalid fleet config/,
      );
      expect(existsSync(dest)).toBe(false);
    } finally {
      payload = GOOD_TOML;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
