#!/usr/bin/env node
/**
 * Flotilla Gateway CLI — run the fleet engine as a stateless HTTP MCP service.
 *
 *   flotilla-gateway [--config <fleet.toml>] [--host 127.0.0.1] [--port 8080] \
 *                    [--token <bearer>]
 *
 * Auth: every /mcp request needs `Authorization: Bearer <token>`. The token
 * comes from --token or FLOTILLA_GATEWAY_TOKEN; there is no anonymous mode —
 * a fleet gateway that anyone can call is a remote root shell.
 *
 * Config resolution is the engine's usual order (--config here is also
 * exported as FLOTILLA_CONFIG before the engine loads): --config ->
 * FLOTILLA_CONFIG -> platform default.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve as resolvePath } from "node:path";
import { resolveAuditPath } from "flotilla-core";
import { createGateway } from "./http-server.js";
import { createEnrollment } from "./enroll.js";
import { createAuditApi, type AuditApi } from "./audit-api.js";
import { createAuditSink, type AuditSink, type SinkConfig } from "./audit-sink.js";

const GATEWAY_VERSION = (() => {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      version?: unknown;
    };
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
})();

interface CliOptions {
  config?: string;
  host: string;
  port: number;
  token?: string;
  help: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = { host: "127.0.0.1", port: 8080, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`missing value for ${arg}`);
      return v;
    };
    switch (arg) {
      case "--config": opts.config = value(); break;
      case "--host": opts.host = value(); break;
      case "--port": {
        const n = Number(value());
        if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error("--port must be 0-65535");
        opts.port = n;
        break;
      }
      case "--token": opts.token = value(); break;
      case "--help": case "-h": opts.help = true; break;
      default: throw new Error(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

const USAGE = `flotilla-gateway v${GATEWAY_VERSION} — Flotilla fleet engine over stateless HTTP MCP

用法: flotilla-gateway [--config <fleet.toml>] [--host <ip>] [--port <n>] [--token <bearer>]

选项:
  --config <path>  fleet 配置文件（同时导出为 FLOTILLA_CONFIG 给引擎）
  --host <ip>      监听地址，默认 127.0.0.1（只监听本机）
  --port <n>       监听端口，默认 8080；0 = 随机端口
  --token <t>      Bearer token；也可用环境变量 FLOTILLA_GATEWAY_TOKEN
  -h, --help       显示本帮助

端点:
  POST/GET /mcp    MCP Streamable HTTP（需要 Bearer token）
  GET  /healthz    健康检查（无需 token）
`;

async function main(): Promise<void> {
  let opts: CliOptions;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`flotilla-gateway: ${err instanceof Error ? err.message : String(err)}`);
    console.error(USAGE);
    process.exit(2);
  }
  if (opts.help) {
    console.log(USAGE);
    return;
  }

  const token = opts.token ?? process.env.FLOTILLA_GATEWAY_TOKEN;
  if (!token) {
    console.error("flotilla-gateway: 拒绝启动——必须提供 Bearer token（--token 或环境变量 FLOTILLA_GATEWAY_TOKEN）。");
    console.error("一台没有认证的舰队网关等同于一个远程 root shell。");
    process.exit(2);
  }
  if (opts.config) {
    process.env.FLOTILLA_CONFIG = opts.config;
  }

  // Dynamic import AFTER env is set: the engine reads FLOTILLA_CONFIG at
  // module load. Importing flotilla-mcp as a library does not start stdio —
  // the engine only boots its transport when executed as the CLI entrypoint.
  const { flotillaMcpServer, flotillaContext, startFleetBackgroundTasks, shutdownFleet } = await import("flotilla-mcp");

  // Enrollment (§9.1): token-issued one-line join, config append + hot reload
  // via the fleet's own config watcher. Requires a configured fleet — without
  // one there is nothing to append servers to.
  const fleetConfigPath = resolvePath(
    flotillaContext.configPath ?? process.env.FLOTILLA_CONFIG ?? "",
  );
  const enrollment = flotillaContext.config
    ? createEnrollment({
        configPath: fleetConfigPath,
        fleetKeyPath: join(dirname(fleetConfigPath), "fleet_ed25519"),
        audit: (event) => flotillaContext.audit?.log(event),
      })
    : undefined;
  if (flotillaContext.config && !enrollment) {
    console.error("flotilla-gateway: enrollment disabled (no fleet config)");
  }

  // Centralized audit (§v2): compliance export over the hash-chained log,
  // plus optional forwarding sinks (webhook / archive file) from env.
  const auditPath = flotillaContext.config
    ? resolveAuditPath(fleetConfigPath, flotillaContext.config.audit?.path)
    : undefined;
  const auditApi: AuditApi | undefined = auditPath ? createAuditApi({ auditPath }) : undefined;
  const sinkConfigs: SinkConfig[] = [];
  if (process.env.FLOTILLA_AUDIT_WEBHOOK_URL) {
    sinkConfigs.push({
      kind: "webhook",
      url: process.env.FLOTILLA_AUDIT_WEBHOOK_URL,
      token: process.env.FLOTILLA_AUDIT_WEBHOOK_TOKEN,
    });
  }
  if (process.env.FLOTILLA_AUDIT_SINK_FILE) {
    sinkConfigs.push({ kind: "file", path: process.env.FLOTILLA_AUDIT_SINK_FILE });
  }
  const auditSink: AuditSink | undefined =
    auditPath && sinkConfigs.length > 0
      ? createAuditSink({ auditPath, sinks: sinkConfigs })
      : undefined;

  const gateway = createGateway({
    mcpServer: flotillaMcpServer,
    token,
    enrollment,
    auditApi,
    health: () => ({
      version: GATEWAY_VERSION,
      engineVersion: flotillaContext.config ? "configured" : `unconfigured (${flotillaContext.configError ?? "no config"})`,
      servers: flotillaContext.registry?.servers().length ?? 0,
      enrollTokens: enrollment?.listTokens().length ?? 0,
      auditSinks: sinkConfigs.length,
      uptimeSec: Math.round(process.uptime()),
    }),
  });

  await new Promise<void>((resolve) => gateway.server.listen(opts.port, opts.host, resolve));
  const address = gateway.server.address();
  const port = typeof address === "object" && address ? address.port : opts.port;
  startFleetBackgroundTasks();
  auditSink?.start();
  console.error(
    `flotilla-gateway v${GATEWAY_VERSION} listening on http://${opts.host}:${port}/mcp ` +
    `(${flotillaContext.registry ? `${flotillaContext.registry.servers().length} servers configured` : "unconfigured"}` +
    `${auditSink ? `, ${sinkConfigs.length} audit sink(s)` : ""})`,
  );

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    void (async () => {
      auditSink?.stop();
      gateway.server.close();
      await shutdownFleet();
      process.exit(0);
    })();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("flotilla-gateway fatal:", err);
  process.exit(1);
});
