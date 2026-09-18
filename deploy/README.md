# Flotilla Gateway 常驻部署 / Running the Gateway in production

**全新服务器一条命令**（装运行时 → 镜像预检 → 初始化配置 → 默认把本机免密纳入管理
（回车即完成，不需要 IP/密码；也可改为入网远程机器或 `--skip-enroll` 跳过）→ 起
Gateway → 健康检查）：

```bash
curl -fsSL https://raw.githubusercontent.com/paipaiio/flotilla-mcp/main/deploy/bootstrap.sh -o bootstrap.sh
less bootstrap.sh   # 先审查再跑
bash bootstrap.sh   # 加 --skip-enroll 跳过交互入网
```

下面是与手工等价的分步说明。

Gateway 本身只是 `flotilla-gateway` 一个二进制（npm 全局安装自带，或
`ghcr.io/paipaiio/flotilla-mcp-gateway` 镜像）。常驻化的三件事：**token、
fleet 配置、TLS 暴露**。无论哪种形态，没有 token 它拒绝启动。

## 0. 先决条件

```bash
# 1) 一个强随机 token（也是 systemd/docker 形态共用的环境变量）
openssl rand -hex 32

# 2) fleet 配置文件：本机默认路径，或任何路径 + --config
flotilla add web-1 --host 192.168.1.10   # 还没有的机器先 bootstrap 入网
```

## 1. Docker（推荐，最省事）

```bash
docker run -d --name flotilla-gateway \
  --restart unless-stopped \
  -p 8080:8080 \
  -v ~/.config/flotilla/config.toml:/home/node/.config/flotilla/config.toml:ro \
  -v ~/.ssh:/home/node/.ssh:ro \
  -e FLOTILLA_GATEWAY_TOKEN=<openssl rand -hex 32 的输出> \
  ghcr.io/paipaiio/flotilla-mcp-gateway
```

镜像默认监听容器内 `0.0.0.0:8080`（非 root 用户），自带 `/healthz`
HEALTHCHECK。`-p 8080:8080` 只应绑到本机时写 `-p 127.0.0.1:8080:8080`。
控制台随镜像自带：浏览器访问 `http://<主机>:8080/console/`，用启动 token 登录。
MCP 聚合：把 upstreams JSON 挂进容器并加 `-e FLOTILLA_GATEWAY_UPSTREAMS=/etc/flotilla/upstreams.json`。

## 2. systemd（裸机 / 自有 VM）

```bash
npm install -g flotilla-gateway        # 或 pnpm；二进制即 flotilla-gateway
sudo mkdir -p /etc/flotilla && sudo chmod 700 /etc/flotilla
sudo cp ~/.config/flotilla/config.toml /etc/flotilla/config.toml
sudo sh -c 'umask 377 && printf "FLOTILLA_GATEWAY_TOKEN=%s\n" "$(openssl rand -hex 32)" > /etc/flotilla/gateway.env'
sudo cp flotilla-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now flotilla-gateway
```

unit 默认 `127.0.0.1:8080` + 加固选项（`NoNewPrivileges`、
`ProtectSystem=strict`、审计写权限只放行 `/etc/flotilla`）。日志：
`journalctl -u flotilla-gateway -f`。

## 3. TLS 暴露（二选一）

- **Caddy**（自动证书）：把 [Caddyfile](./Caddyfile) 里的域名换成你的，
  `caddy run --config Caddyfile`。
- **nginx**：参考 [nginx-flotilla-gateway.conf](./nginx-flotilla-gateway.conf)，
  要点是 `proxy_buffering off` + 长 `proxy_read_timeout`（Streamable HTTP
  的 SSE/长轮询需要透传流式响应）。

## 故障排查

| 症状 | 检查 |
|---|---|
| 启动即退出，日志要 token | `FLOTILLA_GATEWAY_TOKEN` 没传到进程 |
| 401 全部请求 | 客户端 `Authorization: Bearer <token>` 头缺失或不匹配 |
| `engineVersion: unconfigured` | `/healthz` 会直接说明；挂载的 config 路径不对 |
| 审批类操作被拒绝 | HTTP 客户端无 elicitation，按提示用 `confirm=true`（策略允许时） |

---

*English quick start:* on a fresh server, `deploy/bootstrap.sh` does the whole
setup in one shot (runtime, config init, optional enrollment, gateway, health
check). Manually: the gateway ships as the `flotilla-gateway` binary
(npm global install) or `ghcr.io/paipaiio/flotilla-mcp-gateway`. It needs three
things to run resident: a bearer token (`openssl rand -hex 32`), a fleet
config, and — for network exposure — TLS in front (Caddyfile or nginx config
in this directory). Without a token it refuses to start, by design.
