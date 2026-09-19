#!/usr/bin/env bash
# =============================================================================
# Flotilla 一键装机 —— 空白 Linux 服务器 → Gateway 上线
#
#   curl -fsSL https://raw.githubusercontent.com/paipaiio/flotilla-mcp/main/deploy/bootstrap.sh | bash
#   # 或下载后审查再跑（推荐）：
#   curl -fsSL .../bootstrap.sh -o bootstrap.sh && less bootstrap.sh && bash bootstrap.sh
#
# 流程：检测运行环境（Docker 优先，Node 备选）→ 初始化配置（700/600 自动修）
#       → 引导第一台机器入网（可选，--skip-enroll 跳过）→ 生成 token
#       → 启动 Gateway（Docker 或 systemd）→ 健康检查验收。
# 幂等：重复执行会续走未完成的部分，不会重复建容器/服务。
# =============================================================================
set -euo pipefail

IMAGE_MCP="ghcr.io/paipaiio/flotilla-mcp:latest"
IMAGE_GW="ghcr.io/paipaiio/flotilla-mcp-gateway:latest"
CONFIG_DIR="${FLOTILLA_CONFIG_DIR:-$HOME/.config/flotilla}"
SKIP_ENROLL=0
[ "${1:-}" = "--skip-enroll" ] && SKIP_ENROLL=1

say()  { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- 1. 运行环境
say "检测运行环境"
RUNTIME=""
if have docker && docker info >/dev/null 2>&1; then
  RUNTIME=docker
  ok "Docker 可用"
elif have node && node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' 2>/dev/null; then
  RUNTIME=node
  ok "Node $(node -v) 可用"
else
  warn "没有 Docker，也没有 Node ≥ 20——尝试安装 Docker"
  if have apt-get || have dnf || have yum; then
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER" || true
    warn "已把 $USER 加入 docker 组；如 docker info 仍失败，请重新登录后再跑本脚本"
    docker info >/dev/null 2>&1 || die "Docker 安装后仍不可用（组权限可能需重新登录生效）"
    RUNTIME=docker
  else
    die "无法自动安装运行时。请手动装 Docker 或 Node ≥ 20 后重跑。"
  fi
fi

# 防呆：镜像/CLI 可用性必须在问密码之前就验证，别吞了密码才报拉取失败。
# 保留 docker 的真实报错输出——网络类故障（DNS/IPv6/代理）和权限类故障长得完全不一样。
if [ "$RUNTIME" = docker ]; then
  say "预检镜像可拉取（失败时会打印 docker 的真实报错）"
  PULL_ERR=""
  for img in "$IMAGE_MCP" "$IMAGE_GW"; do
    if ! PULL_ERR=$(docker pull "$img" 2>&1); then
      # 重试一次（偶发的网络抖动）
      sleep 3
      PULL_ERR=$(docker pull "$img" 2>&1 || true)
      if ! docker image inspect "$img" >/dev/null 2>&1; then
        printf '%s\n' "$PULL_ERR" >&2
        die "拉取 $img 失败（上面是 docker 的真实报错）。
  若是 unauthorized/insufficient_scope：GHCR 包是 private。开源后包会跟随仓库变 public；
  或立刻解决：GitHub → 头像 → Your profile → Packages → 该包 Settings → Change visibility → Public；
  或：echo <PAT(read:packages)> | docker login ghcr.io -u paipaiio --password-stdin
  若是网络类错误（timeout/DNS/i/o timeout）：检查本机到 ghcr.io 的连通性（curl -sI https://ghcr.io/v2/），
  IPv6 环境的常见解法是 docker daemon 加 \"ipv6\": false 或配 DNS。"
      fi
    fi
  done
  ok "镜像就绪"
else
  have flotilla || { say "安装 flotilla CLI（npm -g）"; npm install -g flotilla-mcp; }
  # ssh2 的 install script 被 npm 拦下时只有 warn（纯 JS 回退，功能不受影响），
  # 想启用原生加速可补跑一次：npm install -g --allow-scripts=ssh2 flotilla-mcp
  have flotilla-gateway || { say "安装 flotilla-gateway（npm -g）"; npm install -g flotilla-gateway; }
fi

# CLI 封装：docker 形态用临时容器跑 CLI。两个坑都踩过：
# ① 镜像 ENTRYPOINT 是 MCP server——必须 --entrypoint node 显式指到 CLI 脚本；
# ② 容器默认 node 用户（uid 1000）进不了宿主机用户的 700 配置目录——
#    用 -u 对齐宿主机 uid/gid，HOME 指到可写的 /tmp，否则 existsSync 假阴性 → chmod EPERM。
if [ "$RUNTIME" = docker ]; then
  # --config 必须显式指到挂载点：HOME 被改指到 /tmp 后，默认路径推算会写到容器里随容器销毁。
  flotilla_cli() { docker run --rm --entrypoint node -u "$(id -u):$(id -g)" -e HOME=/tmp/flotilla-home -v "$CONFIG_DIR":/home/node/.config/flotilla -v "$HOME/.ssh":/home/node/.ssh:ro "$IMAGE_MCP" /app/bin/fleet.mjs --config /home/node/.config/flotilla/config.toml "$@"; }
else
  flotilla_cli() { flotilla --config "$CONFIG_DIR/config.toml" "$@"; }
fi

# ---------------------------------------------------------------- 2. 初始化配置
say "初始化配置目录 $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
# flotilla 自身有 700/600 守卫，CLI add 会自动修正权限；这里提前收敛一次，防呆双保险
chmod 700 "$CONFIG_DIR" 2>/dev/null || true
[ -f "$CONFIG_DIR/config.toml" ] || { : > "$CONFIG_DIR/config.toml"; chmod 600 "$CONFIG_DIR/config.toml"; }
ok "config.toml 就绪"

# ---------------------------------------------------------------- 3. 入网第一台机器（默认自管本机，免密）
self_enroll() {
  # 本机自管：人已在机器上，fleet 公钥直接追加进本机 authorized_keys（本地文件操作，不需要密码）。
  # 探测仍走 SSH 127.0.0.1 验证 sshd/密钥登录真的可用；docker 形态加 --network host 才能摸到宿主 sshd。
  local key="$CONFIG_DIR/fleet_ed25519"
  if [ ! -f "$key" ]; then
    ssh-keygen -t ed25519 -N "" -C "flotilla-fleet" -f "$key" >/dev/null
    chmod 600 "$key"
  fi
  local pub; pub="$(ssh-keygen -y -f "$key")"
  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
  touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys"
  if grep -qxF "$pub" "$HOME/.ssh/authorized_keys"; then
    echo "  公钥已存在于 $HOME/.ssh/authorized_keys"
  else
    printf '%s\n' "$pub" >> "$HOME/.ssh/authorized_keys"
    echo "  公钥已写入 $HOME/.ssh/authorized_keys"
  fi
  local name; name="$(hostname -s 2>/dev/null || hostname)"
  if [ "$RUNTIME" = docker ]; then
    docker run --rm --network host --entrypoint node -u "$(id -u):$(id -g)" -e HOME=/tmp/flotilla-home \
      -v "$CONFIG_DIR":/home/node/.config/flotilla \
      "$IMAGE_MCP" /app/bin/fleet.mjs --config /home/node/.config/flotilla/config.toml \
      add "$name" --host 127.0.0.1 --user "$(id -un)" \
      --auth key --key /home/node/.config/flotilla/fleet_ed25519 --group prod
  else
    flotilla --config "$CONFIG_DIR/config.toml" add "$name" --host 127.0.0.1 --user "$(id -un)" --auth key --key "$key" --group prod
  fi
  # 防假成功：退出码 0 不代表真的入网（比如容器跑错入口），必须看到配置里的服务器块
  grep -q "^\[\[servers\]\]" "$CONFIG_DIR/config.toml"
}

if [ "$SKIP_ENROLL" = 0 ] && [ ! -s "$CONFIG_DIR/config.toml" ]; then
  say "入网第一台机器"
  if [ ! -t 0 ]; then
    warn "非交互环境（stdin 不是终端），跳过入网；之后手动跑：flotilla add <name> --host <ip> --bootstrap"
    SKIP_ENROLL=1
  fi
  if [ "$SKIP_ENROLL" = 0 ]; then
    read -r -p "  把本机（127.0.0.1）纳入管理？免密，回车即完成 [Y/n]: " SELF
    if [ "${SELF:-Y}" != "n" ] && [ "${SELF:-Y}" != "N" ]; then
      if self_enroll; then
        ok "本机已入网"
        SKIP_ENROLL=1
      else
        warn "本机自管失败：需要本机 sshd 运行且允许密钥登录（Debian/Ubuntu: apt install openssh-server && systemctl enable --now ssh）"
      fi
    fi
  fi
  if [ "$SKIP_ENROLL" = 0 ]; then
    read -r -p "  改为入网远程机器？输入 IP（直接回车跳过）: " HOST
    [ -n "$HOST" ] || { warn "跳过入网；之后可随时手动跑：flotilla add <name> --host <ip> --bootstrap"; SKIP_ENROLL=1; }
  fi
  if [ "$SKIP_ENROLL" = 0 ]; then
    read -r -p "  名称 [web-1]: " NAME; NAME="${NAME:-web-1}"
    read -r -p "  用户 [root]: " USERNAME; USERNAME="${USERNAME:-root}"
    read -r -p "  端口 [22]: " PORT; PORT="${PORT:-22}"
    read -r -s -p "  一次性登录密码（输入不显示; 目标机需允许密码登录）: " PASSWD; echo
    [ -n "$PASSWD" ] || die "空密码，未执行"
    FLOTILLA_BOOTSTRAP_PASSWORD="$PASSWD" flotilla_cli add "$NAME" --host "$HOST" --port "$PORT" \
      --user "$USERNAME" --bootstrap --group prod \
      || die "入网失败：检查地址/密码/目标机 sshd 的 PasswordAuthentication"
    ok "$NAME 已入网"
  fi
fi

# ---------------------------------------------------------------- 4. token + 启动 Gateway
TOKEN_FILE="$CONFIG_DIR/gateway.env"
if [ ! -f "$TOKEN_FILE" ]; then
  printf 'FLOTILLA_GATEWAY_TOKEN=%s\n' "$(openssl rand -hex 32 2>/dev/null || node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
fi
# shellcheck disable=SC1090
. "$TOKEN_FILE"
# 必须 export：前台启动分支靠环境变量把 token 传给 flotilla-gateway 进程，
# 而 source 进来的赋值默认不导出——没 export 时网关会以「缺 token」拒绝启动。
export FLOTILLA_GATEWAY_TOKEN

# 端口：env 可覆盖（FLOTILLA_GATEWAY_PORT），被占用时交互换端口
GW_PORT="${FLOTILLA_GATEWAY_PORT:-8080}"
port_in_use() { (echo > "/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
if port_in_use "$GW_PORT"; then
  warn "端口 $GW_PORT 已被占用"
  (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E "[:.]${GW_PORT}\b" || true
  if [ -t 0 ]; then
    read -r -p "  换哪个端口？[8081]: " PICK
    GW_PORT="${PICK:-8081}"
    while port_in_use "$GW_PORT"; do
      read -r -p "  $GW_PORT 也被占用，再换一个： " PICK
      GW_PORT="${PICK:-$((GW_PORT + 1))}"
    done
  else
    die "端口 $GW_PORT 被占用且非交互环境——用 FLOTILLA_GATEWAY_PORT=<端口> bash bootstrap.sh 重跑"
  fi
fi
ok "Gateway 端口：$GW_PORT"
if [ "$RUNTIME" = docker ]; then
  # 旧容器（含历史失败运行留下的半成品）一律删除重建——重启只会保留旧的
  # 端口映射/环境变量/镜像，继续撞同样的错；重建才能收敛到当前期望状态。
  if docker ps -a --format '{{.Names}}' | grep -qx flotilla-gateway; then
    say "移除旧 flotilla-gateway 容器（按新端口/新配置重建）"
    docker rm -f flotilla-gateway >/dev/null
  fi
  say "启动 Gateway 容器（127.0.0.1:$GW_PORT）"
    # -u 对齐宿主机 uid/gid（否则容器 node 用户进不了 700 的配置目录，热重载都读不到），
    # HOME/FLOTILLA_CONFIG 显式指定，不依赖容器内默认用户的展开路径。
    docker run -d --name flotilla-gateway --restart unless-stopped \
      -u "$(id -u):$(id -g)" \
      -e HOME=/tmp/flotilla-home \
      -e FLOTILLA_CONFIG=/home/node/.config/flotilla/config.toml \
      -p "127.0.0.1:$GW_PORT:8080" \
      -v "$CONFIG_DIR":/home/node/.config/flotilla \
      -v "$HOME/.ssh":/home/node/.ssh:ro \
      -e FLOTILLA_GATEWAY_TOKEN="$FLOTILLA_GATEWAY_TOKEN" \
      "$IMAGE_GW" >/dev/null
else
  have flotilla-gateway || die "flotilla-gateway 命令缺失（npm 安装失败）。重跑本脚本，或手动：npm install -g flotilla-gateway"
  if have systemctl && [ "$(id -u)" = 0 ]; then
    say "安装 systemd 服务 flotilla-gateway"
    GW_BIN="$(command -v flotilla-gateway)"
    cat > /etc/systemd/system/flotilla-gateway.service <<UNIT
[Unit]
Description=Flotilla Gateway
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=$TOKEN_FILE
Environment=FLOTILLA_CONFIG=$CONFIG_DIR/config.toml
ExecStart=$GW_BIN --host 127.0.0.1 --port $GW_PORT
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now flotilla-gateway
  else
    warn "非 root 或无 systemd——前台启动 Gateway（Ctrl+C 停止；常驻请用仓库 deploy/flotilla-gateway.service）"
    FLOTILLA_CONFIG="$CONFIG_DIR/config.toml" flotilla-gateway --host 127.0.0.1 --port "$GW_PORT" &
  fi
fi

# ---------------------------------------------------------------- 5. 健康检查验收
say "健康检查"
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$GW_PORT/healthz" 2>/dev/null | grep -q '"engineVersion"'; then
    ok "Gateway 已上线：http://127.0.0.1:$GW_PORT/healthz"
    ok "控制台：http://127.0.0.1:$GW_PORT/console/  （用 gateway.env 里的 token 登录）"
    echo
    echo "  对外暴露：把 127.0.0.1:$GW_PORT 反代到 Caddy/nginx（模板见 deploy/），"
    echo "  MCP 客户端连接时带 Authorization: Bearer \$FLOTILLA_GATEWAY_TOKEN"
    exit 0
  fi
  sleep 1
done
die "Gateway 未通过健康检查。看日志：$([ "$RUNTIME" = docker ] && echo 'docker logs flotilla-gateway' || echo 'journalctl -u flotilla-gateway -f')"
