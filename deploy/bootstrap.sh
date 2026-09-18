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
IMAGE_GW="ghcr.io/paipaiio/flotilla-gateway:latest"
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

# CLI 封装：docker 形态用临时容器跑 CLI，node 形态用全局安装的 flotilla
if [ "$RUNTIME" = docker ]; then
  flotilla_cli() { docker run --rm -v "$CONFIG_DIR":/home/node/.config/flotilla -v "$HOME/.ssh":/home/node/.ssh:ro "$IMAGE_MCP" flotilla "$@"; }
else
  have flotilla || { say "安装 flotilla CLI（npm -g）"; npm install -g flotilla-mcp flotilla-gateway; }
  flotilla_cli() { flotilla "$@"; }
fi

# ---------------------------------------------------------------- 2. 初始化配置
say "初始化配置目录 $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
# flotilla 自身有 700/600 守卫，CLI add 会自动修正权限；这里提前收敛一次，防呆双保险
chmod 700 "$CONFIG_DIR" 2>/dev/null || true
[ -f "$CONFIG_DIR/config.toml" ] || { : > "$CONFIG_DIR/config.toml"; chmod 600 "$CONFIG_DIR/config.toml"; }
ok "config.toml 就绪"

# ---------------------------------------------------------------- 3. 引导第一台机器（可选）
if [ "$SKIP_ENROLL" = 0 ] && [ ! -s "$CONFIG_DIR/config.toml" ]; then
  say "入网第一台机器（直接回车跳过，之后可随时手动跑：flotilla add <name> --host <ip> --bootstrap）"
  read -r -p "  名称 [web-1]: " NAME; NAME="${NAME:-web-1}"
  read -r -p "  IP/DNS: " HOST; [ -n "$HOST" ] || { warn "未填地址，跳过入网"; SKIP_ENROLL=1; }
  if [ "$SKIP_ENROLL" = 0 ]; then
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

GW_PORT="${FLOTILLA_GATEWAY_PORT:-8080}"
if [ "$RUNTIME" = docker ]; then
  if docker ps -a --format '{{.Names}}' | grep -qx flotilla-gateway; then
    say "容器 flotilla-gateway 已存在，重启应用新配置"
    docker restart flotilla-gateway >/dev/null
  else
    say "启动 Gateway 容器（127.0.0.1:$GW_PORT）"
    docker run -d --name flotilla-gateway --restart unless-stopped \
      -p "127.0.0.1:$GW_PORT:8080" \
      -v "$CONFIG_DIR":/home/node/.config/flotilla \
      -v "$HOME/.ssh":/home/node/.ssh:ro \
      -e FLOTILLA_GATEWAY_TOKEN="$FLOTILLA_GATEWAY_TOKEN" \
      "$IMAGE_GW" >/dev/null
  fi
else
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
