import { afterEach, describe, expect, it, vi } from "vitest";
import { SshTransport } from "../src/ssh.js";
import type { ServerConfig } from "../src/types.js";

const server: ServerConfig = {
  name: "app-1",
  host: "127.0.0.1",
  user: "deploy",
  auth: "agent",
  group: "dev",
  role: "admin",
  scopes: { paths: ["/etc/app/**"] },
};

const opened: SshTransport[] = [];
afterEach(async () => Promise.all(opened.splice(0).map((transport) => transport.close())));

function transportWith(sftp: Record<string, unknown>): SshTransport {
  const transport = new SshTransport(new Map([[server.name, server]]), { maxSshOutputBytes: 64 });
  opened.push(transport);
  Object.assign(transport as unknown as Record<string, unknown>, {
    connection: vi.fn(async () => ({})),
    touch: vi.fn(),
    openSftp: vi.fn(async () => sftp),
    assertScopedPath: vi.fn(async () => undefined),
    execUntracked: vi.fn(async () => ({ host: server.name, ok: true, exitCode: 0, stdout: "", stderr: "", durationMs: 1 })),
  });
  return transport;
}

describe("SshTransport in-memory file transfer", () => {
  it("reads a bounded remote text file without a local path", async () => {
    const end = vi.fn();
    const transport = transportWith({
      stat: (_path: string, callback: (error: Error | undefined, attrs: { size: number }) => void) => callback(undefined, { size: 12 }),
      readFile: (_path: string, callback: (error: Error | undefined, value: Buffer) => void) => callback(undefined, Buffer.from("token=hidden")),
      end,
    });

    await expect(transport.readText(server, "/etc/app/config", { timeoutMs: 100 })).resolves.toMatchObject({
      host: "app-1", text: "token=hidden", bytes: 12,
    });
    expect(end).toHaveBeenCalledOnce();
  });

  it("writes text directly through SFTP and enforces the memory bound", async () => {
    const writeFile = vi.fn((_path: string, _data: Buffer, callback: (error?: Error) => void) => callback());
    const transport = transportWith({ writeFile, end: vi.fn() });

    await expect(transport.writeText(server, "/etc/app/staged", "secret-value", { timeoutMs: 100 })).resolves.toMatchObject({
      host: "app-1", ok: true, bytes: 12,
    });
    expect(writeFile.mock.calls[0]?.[1]).toEqual(Buffer.from("secret-value"));
    await expect(transport.writeText(server, "/etc/app/staged", "x".repeat(65), { timeoutMs: 100 })).rejects.toThrow(/memory transfer limit/i);
  });
});
