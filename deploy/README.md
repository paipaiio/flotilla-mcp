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
flotilla add root@192.168.1.10           # 有密钥就免密，没有会提示输一次密码
```

## 1. Docker（推荐，最省事）

```bash
docker run -d --name flotilla-gateway \
  --restart unless-stopped \
  -u "$(id -u):$(id -g)" \
  --add-host host.docker.internal:host-gateway \
  -p 127.0.0.1:8080:8080 \
  -e HOME=/tmp/flotilla-home \
  -e FLOTILLA_CONFIG=/home/node/.config/flotilla/config.toml \
  -v ~/.config/flotilla:/home/node/.config/flotilla \
  --env-file ~/.config/flotilla/gateway.env \
  ghcr.io/paipaiio/flotilla-mcp-gateway
```

要点（每一条都踩过坑）：

- **挂整个配置目录，不要单挂 config.toml**：`flotilla add`/入网会原子替换文件（写新文件再 rename），
  单文件 bind mount 看不到新文件，热重载失效；舰队密钥 `fleet_ed25519` 也在这个目录里，重启不丢。
- **`-u` 对齐宿主机用户**：配置是 0600，容器默认 uid 1000 读不了别人的文件。
- **只绑 127.0.0.1**，对外由 Caddy/nginx 加 HTTPS（见下文）；明文 8080 不要直接暴露。
- **token 用 `--env-file`**（内容 `FLOTILLA_GATEWAY_TOKEN=...`，0600），不要写在命令行里——会出现在 `ps` 和 shell 历史。

镜像以非 root 运行，自带 `/healthz` HEALTHCHECK（没有可用配置时返回 503）。
控制台随镜像自带：浏览器访问 `http://<主机>:8080/console/`，用启动 token 登录。
MCP 聚合：把 upstreams JSON 挂进容器并加 `-e FLOTILLA_GATEWAY_UPSTREAMS=/etc/flotilla/upstreams.json`。

## 2. systemd（裸机 / 自有 VM）

```bash
npm install -g flotilla-gateway        # 或 pnpm；二进制即 flotilla-gateway
sudo mkdir -p /etc/flotilla && sudo chmod 700 /etc/flotilla
sudo cp ~/.config/flotilla/config.toml /etc/flotilla/config.toml
sudo sh -c 'umask 377 && printf "FLOTILLA_GATEWAY_TOKEN=%s\n" "$(openssl rand -hex 32)" > /etc/flotilla/gateway.env'
# unit 模板在仓库 deploy/flotilla-gateway.service（没有克隆仓库就下载它）：
sudo curl -fsSL -o /etc/systemd/system/flotilla-gateway.service \
  https://raw.githubusercontent.com/paipaiio/flotilla-mcp/main/deploy/flotilla-gateway.service
# 用 nvm 等装的 node 不在 /usr/local/bin：把 unit 里 ExecStart 的路径改成 `command -v flotilla-gateway` 的输出
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
| `/healthz` 返回 503 `unconfigured` | 挂载的 config 路径不对（显式 `--config` 指向坏文件时网关直接拒绝启动并说明原因） |
| 破坏性操作一律被拒 | 网站模式没有审批弹窗：把机器设到 staging/dev（`flotilla set <名字> --tier staging`），或配置 `[defaults] allowConfirmFlag = true` 后勾选/传 `confirm=true` |
| 入网的机器回连地址不对 | 反代不在本机/Docker 网桥上时，`FLOTILLA_TRUSTED_PROXIES=<反代 IP>` 让网关信任它的 X-Forwarded-For |
| 只给某些人/agent 只读权限 | `flotilla-gateway token create <名字> --role viewer [--targets tag:web]`，详见主 README |

---

*English quick start:* on a fresh server, `deploy/bootstrap.sh` does the whole
setup in one shot (runtime, config init, optional enrollment, gateway, health
check). Manually: the gateway ships as the `flotilla-gateway` binary
(npm global install) or `ghcr.io/paipaiio/flotilla-mcp-gateway`. It needs three
things to run resident: a bearer token (`openssl rand -hex 32`), a fleet
config, and — for network exposure — TLS in front (Caddyfile or nginx config
in this directory). Without a token it refuses to start, by design.
