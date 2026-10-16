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
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { defaultConfigPath, resolveAuditPath } from "flotilla-core";
import { createGateway } from "./http-server.js";
import { createEnrollment } from "./enroll.js";
import { createAuditApi, type AuditApi } from "./audit-api.js";
import { createAuditSink, type AuditSink, type SinkConfig } from "./audit-sink.js";
import { createUpstreamManager, loadUpstreamsConfig, type UpstreamManager } from "./upstreams.js";
import { createTokenStore, listTokens } from "./tokens.js";
import { resolveTokensFile, tokenCommand } from "./token-cli.js";

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
  upstreams?: string;
  tokensFile?: string;
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
      case "--upstreams": opts.upstreams = value(); break;
      case "--tokens-file": opts.tokensFile = value(); break;
      case "--help": case "-h": opts.help = true; break;
      default: throw new Error(`unknown argument: ${arg}`);
    }
  }
  return opts;
}

const USAGE = `flotilla-gateway v${GATEWAY_VERSION} — Flotilla fleet engine over stateless HTTP MCP

用法: flotilla-gateway [--config <fleet.toml>] [--host <ip>] [--port <n>] [--token <bearer>]
                       [--upstreams <upstreams.json>] [--tokens-file <path>]

选项:
  --config <path>      fleet 配置文件（同时导出为 FLOTILLA_CONFIG 给引擎）
  --host <ip>          监听地址，默认 127.0.0.1（只监听本机）
  --port <n>           监听端口，默认 8080；0 = 随机端口
  --token <t>          Bearer token；也可用环境变量 FLOTILLA_GATEWAY_TOKEN
  --upstreams <path>   上游 MCP 聚合配置（JSON）；也可用 FLOTILLA_GATEWAY_UPSTREAMS
  --tokens-file <path> 受限 token 文件（JSON，只存哈希）；也可用 FLOTILLA_GATEWAY_TOKENS，
                       默认 fleet 配置同目录 gateway-tokens.json
  -h, --help           显示本帮助

受限 token（只能访问 /mcp；角色上限 + 可见目标，热生效无需重启）:
  flotilla-gateway token create <name> --role viewer|operator|admin (--targets "tag:web,group:edge" | --all)
  flotilla-gateway token list
  flotilla-gateway token revoke <name>

端点:
  POST/GET /mcp    MCP Streamable HTTP（需要 Bearer token）
  GET  /console/   Web 控制台（静态页面，token 在登录页输入）
  GET  /healthz    健康检查（无需 token）
`;

async function main(): Promise<void> {
  if (process.argv[2] === "token") {
    process.exit(tokenCommand(process.argv.slice(3)));
  }
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
    console.error("flotilla-gateway: 拒绝启动——必须提供 Bearer token（推荐环境变量 FLOTILLA_GATEWAY_TOKEN；--token 会出现在 ps 里）。");
    console.error("一台没有认证的舰队网关等同于一个远程 root shell。生成一个：openssl rand -hex 32");
    process.exit(2);
  }
  if (token.length < 16) {
    console.error(`flotilla-gateway: token 太短（${token.length} 字符），至少 16 位。生成一个：openssl rand -hex 32`);
    process.exit(2);
  }
  if (opts.config && !existsSync(resolvePath(opts.config))) {
    console.error(`flotilla-gateway: --config 指向的文件不存在：${resolvePath(opts.config)}`);
    console.error("先用 flotilla add 加一台机器（会自动创建配置），或检查路径。");
    process.exit(2);
  }
  if (opts.config) {
    process.env.FLOTILLA_CONFIG = opts.config;
  }

  // Dynamic import AFTER env is set: the engine reads FLOTILLA_CONFIG at
  // module load. Importing flotilla-mcp as a library does not start stdio —
  // the engine only boots its transport when executed as the CLI entrypoint.
  const { flotillaMcpServer, flotillaContext, startFleetBackgroundTasks, shutdownFleet } = await import("flotilla-mcp");
  if (opts.config && !flotillaContext.config) {
    // An explicit --config that does not load is a mistake, not "unconfigured".
    console.error(`flotilla-gateway: 配置文件有误，拒绝启动：\n${flotillaContext.configError ?? "unknown error"}`);
    process.exit(2);
  }

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

  // Upstream MCP aggregation (§v2): mount external MCP servers (stdio or
  // HTTP) behind this gateway's single /mcp endpoint. A bad upstream never
  // blocks boot — it shows up as "error" in /healthz and can be retried.
  const upstreamsPath = opts.upstreams ?? process.env.FLOTILLA_GATEWAY_UPSTREAMS;
  let upstreamManager: UpstreamManager | undefined;
  if (upstreamsPath) {
    const configs = loadUpstreamsConfig(resolvePath(upstreamsPath));
    upstreamManager = createUpstreamManager(configs);
    await upstreamManager.attach(flotillaMcpServer);
    for (const status of upstreamManager.statuses()) {
      console.error(
        `flotilla-gateway: upstream "${status.name}" (${status.transport}) ` +
          (status.state === "connected"
            ? `${status.tools.length} tool(s) mounted`
            : `FAILED — ${status.error ?? "unknown"}`),
      );
    }
  }

  // Web console (§v2): static ops UI served at /console/. The files ship inside
  // this package (dist/../console/), so resolve relative to the running CLI.
  const consoleDir = fileURLToPath(new URL("../console/", import.meta.url));
  if (!existsSync(join(consoleDir, "index.html"))) {
    console.error(`flotilla-gateway: web console not found at ${consoleDir} — /console/ disabled`);
  }

  const tokensFile = resolveTokensFile(opts.tokensFile, flotillaContext.configPath);
  const scopedTokens = createTokenStore(tokensFile);
  try {
    const count = listTokens(tokensFile).length;
    if (count > 0) console.error(`flotilla-gateway: ${count} scoped token(s) from ${tokensFile}`);
  } catch (err) {
    console.error(`flotilla-gateway: 拒绝启动——${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }

  const gateway = createGateway({
    mcpServer: flotillaMcpServer,
    token,
    scopedTokens,
    enrollment,
    auditApi,
    consoleDir: existsSync(join(consoleDir, "index.html")) ? consoleDir : undefined,
    health: () => ({
      version: GATEWAY_VERSION,
      // /healthz is unauthenticated: state only, no paths or config snippets.
      engineVersion: flotillaContext.config ? "configured" : "unconfigured",
      servers: flotillaContext.registry?.servers().length ?? 0,
      // A corrupt enrollment store must not fail the health check of the whole gateway.
      ...(() => {
        const count = enrollment?.tokenCount();
        return count === null ? { enrollTokens: 0, enrollStore: "corrupt" } : { enrollTokens: count ?? 0 };
      })(),
      auditSinks: sinkConfigs.length,
      upstreams: upstreamManager?.summary(),
      uptimeSec: Math.round(process.uptime()),
    }),
  });

  await new Promise<void>((resolve) => {
    gateway.server.once("error", (err: NodeJS.ErrnoException) => {
      const reason =
        err.code === "EADDRINUSE"
          ? `端口 ${opts.port} 已被占用（另一个网关在跑？换一个：--port <n>）`
          : err.code === "EACCES"
            ? `没有权限监听 ${opts.host}:${opts.port}（1024 以下端口需要 root，建议用 8080 并由反代对外）`
            : err.message;
      console.error(`flotilla-gateway: 无法启动 —— ${reason}`);
      process.exit(2);
    });
    gateway.server.listen(opts.port, opts.host, resolve);
  });
  const address = gateway.server.address();
  const port = typeof address === "object" && address ? address.port : opts.port;
  startFleetBackgroundTasks();
  auditSink?.start();
  console.error(
    `flotilla-gateway v${GATEWAY_VERSION} listening on http://${opts.host}:${port}/mcp  ·  console http://${opts.host}:${port}/console/ ` +
    `(${flotillaContext.registry ? `${flotillaContext.registry.servers().length} servers configured` : "unconfigured"}` +
    `${auditSink ? `, ${sinkConfigs.length} audit sink(s)` : ""}` +
    `${upstreamManager ? `, ${upstreamManager.summary().connected}/${upstreamManager.summary().total} upstream(s)` : ""})`,
  );

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    void (async () => {
      auditSink?.stop();
      upstreamManager?.close();
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
