# Flotilla 冷启动排障手册

从一台空白服务器到 Gateway 上线、第一台机器入网，正常 10 分钟。本文档沉淀真实部署中
逐个踩过并修了根因的坑：每个症状给出**诊断命令 → 根因 → 修复**。

> 适用版本：v0.10.4+。旧版本请先升级（见文末「升级」）。

---

## 0. 拓扑速览

```
被管节点 ──join.sh──> nginx/Caddy (TLS 终结) ──> flotilla-gateway 容器 (127.0.0.1:PORT)
                                                          │
                                                          └── SSH ──> 各被管节点:22
```

关键认知：**gateway 容器永远只监听 127.0.0.1**，对外全靠反代；容器在 docker 网桥后，
它看到的「对端 IP」是宿主机网桥地址（如 172.17.0.1），不是真实客户端。

---

## 1. 冷启动 checklist

```bash
# ① 装 gateway（Docker 路线，空白 Debian/Ubuntu）
SHA=$(curl -fsSL "https://api.github.com/repos/paipaiio/flotilla-mcp/commits/main" | grep -m1 '"sha"' | cut -d'"' -f4)
curl -fsSL "https://raw.githubusercontent.com/paipaiio/flotilla-mcp/$SHA/deploy/bootstrap.sh" -o bootstrap.sh
bash bootstrap.sh
#    - raw.githubusercontent 有 CDN 缓存，?v= 参数撞不开，必须用 SHA 拼 URL（勿省）
#    - 端口被占时会交互换端口，记住你选的端口
#    - 全新机器没装 sshd？答 Y 让脚本自动装 openssh-server（v0.10.4+）

# ② 反代 + TLS（Caddy 最省事，自动签发）
cat >/etc/caddy/Caddyfile <<'EOF'
flotilla.example.com
reverse_proxy 127.0.0.1:8091
EOF
systemctl reload caddy
# nginx 则必须用 deploy/nginx-flotilla-gateway.conf 模板（SSE/长超时）

# ③ 验收 gateway
curl -s http://127.0.0.1:PORT/healthz        # engineVersion 应为 "configured"
curl -sI https://flotilla.example.com/join.sh # 200

# ④ 签发入网令牌（控制台「入网管理」或 API）→ 在被管节点上执行 join
curl -fsSL https://flotilla.example.com/join.sh | sudo sh -s -- --token flt_...
```

---

## 2. 症状对照表（按今天真实踩坑顺序）

### ① join 报 301 / ` enrollment refused: <html>...nginx...`

| | |
|---|---|
| 诊断 | `curl -s https://<域名>/join.sh \| grep '^API='` 看嵌的是不是 `http://` |
| 根因 | gateway 在反代后看到的是纯 http 请求，join.sh 嵌了 http 地址，POST 被 nginx 301 跳 https，curl 不跟随 |
| 修复 | v0.10.1：/join.sh 生成时信任 `X-Forwarded-Proto`。nginx 必须配置（见 §3） |

### ② `enrollment refused:` 后面是空白

| | |
|---|---|
| 诊断 | 手动 curl join 接口看响应体（§4 诊断命令） |
| 根因 | join.sh 用 `curl -f`，4xx 的响应体被静默吞掉 |
| 修复 | v0.10.2：join.sh 手动判状态码，gateway 的错误原样打印。升级后再跑即可看到真实原因 |

### ③ `bad request: SSH key setup failed ... spawnSync ssh-keygen ENOENT`

| | |
|---|---|
| 诊断 | 同上，错误体里直接有 |
| 根因 | `node:*-slim` 镜像不带 ssh-keygen；宿主机预生成过 key 的机器不触发，全新 gateway 第一条入网请求才炸 |
| 修复 | v0.10.3：镜像装 openssh-client。**workaround**：宿主机 `ssh-keygen -t ed25519 -N "" -C flotilla-fleet -f ~/.config/flotilla/fleet_ed25519` 预生成 |
| 注意 | 报 400 前令牌计数已提交——令牌作废，控制台吊销后重新签发 |

### ④ 新节点地址记成 `root@172.17.0.1:22`（或 172.18.0.1）

| | |
|---|---|
| 诊断 | `grep host ~/.config/flotilla/config.toml` |
| 根因 | 容器在 docker 网桥后，gateway 看到的对端是宿主机网桥 IP，被当成节点地址 |
| 修复 | v0.10.4：信任 `X-Forwarded-For` 最左一跳 + 排除容器默认网关（读 /proc/net/route） |
| 善后 | 已入网的错误记录：`sed -i 's/host = "172.17.0.1"/host = "真实IP"/' config.toml`，热重载 ~300ms 生效 |

### ⑤ `bash bootstrap.sh` 一跑就退出 / 管道悬挂

| | |
|---|---|
| 根因 | 非交互 stdin 下 read 返回非零被 `set -e` 杀（v0.10.2 修复）；后台 gateway 继承脚本 stdout 导致管道不结束（v0.10.2 修复，日志重定向到 gateway.log） |
| 现状 | 非交互环境自动跳过入网；日志在 `~/.config/flotilla/gateway.log`，PID 在 `gateway.pid` |

### ⑥ 自管节点 exec 报 `ECONNREFUSED 127.0.0.1:22`（gateway 容器形态）

| | |
|---|---|
| 诊断 | `grep host ~/.config/flotilla/config.toml` 里自管节点是 `127.0.0.1` |
| 根因 | 宿主机 CLI 视角 127.0.0.1 是对的；gateway 跑在容器里，容器自己的 127.0.0.1 是容器自身，摸不到宿主 sshd |
| 修复 | bootstrap v1.0 起：容器加 `--add-host host.docker.internal:host-gateway`，自管节点记 `host.docker.internal`。存量错误记录：`sed -i 's/host = "127.0.0.1"/host = "host.docker.internal"/' config.toml`（只限自管那一行） |

---

## 3. 反代必配头（nginx）

```nginx
location / {
    proxy_pass http://127.0.0.1:8091;
    proxy_set_header Host $host;                            # join.sh 嵌对域名
    proxy_set_header X-Forwarded-Proto $scheme;             # 防 301（坑①）
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # 记录真实 IP（坑④）
    proxy_buffering off;                                    # MCP SSE 流式必需
    proxy_read_timeout 3600s;
}
```

缺任何一行对应坑①/④都会复发。Caddy 默认全对，无需手写。

---

## 4. 万能诊断：手动复刻 join 请求

join.sh 报错时，用它看到 gateway 的真实响应体（不依赖 join.sh 版本）：

```bash
curl -sS -w "\nHTTP %{http_code}\n" -X POST https://<域名>/api/enroll/join \
  -H "Authorization: Bearer <flt_令牌>" -H 'Content-Type: application/json' \
  -d '{"hostname":"test-host","user":"root","port":22,"primaryIp":""}'
```

响应体对照：`invalid token` → 令牌作废/过期，重新签发；`hostname is required` / `bad request:` → 看冒号后的具体异常。

---

## 5. 升级

```bash
# 宿主机 Docker 路线：重跑 bootstrap 即自动 pull + 重建（幂等）
bash bootstrap.sh

# npm 路线
npm update -g flotilla-mcp flotilla-gateway
```

升级后旧入网记录、令牌、配置全部保留（都在挂载的配置目录里）。

---

## 6. 彻底重装（清干净从头跑）

```bash
docker rm -f flotilla-gateway 2>/dev/null
docker rmi ghcr.io/paipaiio/flotilla-mcp-gateway:latest ghcr.io/paipaiio/flotilla-mcp:latest 2>/dev/null
rm -rf ~/.config/flotilla            # config.toml / gateway.env / fleet key / 令牌库 / 日志
rm -f ~/bootstrap.sh
# authorized_keys 只移除 fleet 行，别动其他密钥：
grep -v 'flotilla-fleet' ~/.ssh/authorized_keys > /tmp/ak.clean && cat /tmp/ak.clean > ~/.ssh/authorized_keys && rm /tmp/ak.clean
ssh-keygen -R 127.0.0.1 2>/dev/null  # 可选：清探测留下的 known_hosts
```

nginx/Caddy 反代和 DNS 属于基础设施，留着，重跑 bootstrap 后直接复用。
