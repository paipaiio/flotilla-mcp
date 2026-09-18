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

# 防呆：镜像/CLI 可用性必须在问密码之前就验证，别吞了密码才报拉取失败
if [ "$RUNTIME" = docker ]; then
  say "预检镜像可拉取（GHCR 私有包需先 docker login，见报错提示）"
  if ! docker pull -q "$IMAGE_MCP" >/dev/null 2>&1 || ! docker pull -q "$IMAGE_GW" >/dev/null 2>&1; then
    die "拉取 $IMAGE_MCP 失败。
  原因通常是 GHCR 包仍为 private（包可见性跟随 GitHub 仓库）。三选一：
  ① 开源后把包设为 public：GitHub → 头像 → Your profile → Packages → 每个包 Settings → Change visibility → Public
  ② 或在本机登录：echo <PAT(read:packages)> | docker login ghcr.io -u paipaiio --password-stdin
  ③ 或改用 Node 运行时装好 Node ≥ 20 后重跑（flotilla-mcp CLI 在 npm 公开，gateway 镜像仍需 ①/②）"
  fi
  ok "镜像就绪"
else
  have flotilla || { say "安装 flotilla CLI（npm -g）"; npm install -g flotilla-mcp; }
  command -v flotilla-gateway >/dev/null 2>&1 || warn "未找到 flotilla-gateway 命令——Gateway 只能用 Docker 镜像起（见上面预检）或等下一条提示"
fi

# CLI 封装：docker 形态用临时容器跑 CLI，node 形态用全局安装的 flotilla（预检阶段已装好）
if [ "$RUNTIME" = docker ]; then
  flotilla_cli() { docker run --rm -v "$CONFIG_DIR":/home/node/.config/flotilla -v "$HOME/.ssh":/home/node/.ssh:ro "$IMAGE_MCP" flotilla "$@"; }
else
  flotilla_cli() { flotilla "$@"; }
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
    docker run --rm --network host \
      -v "$CONFIG_DIR":/home/node/.config/flotilla \
      "$IMAGE_MCP" flotilla add "$name" --host 127.0.0.1 --user "$(id -un)" \
      --auth key --key /home/node/.config/flotilla/fleet_ed25519 --group prod
  else
    flotilla add "$name" --host 127.0.0.1 --user "$(id -un)" --auth key --key "$key" --group prod
  fi
}

if [ "$SKIP_ENROLL" = 0 ] && [ ! -s "$CONFIG_DIR/config.toml" ]; then
  say "入网第一台机器"
  read -r -p "  把本机（127.0.0.1）纳入管理？免密，回车即完成 [Y/n]: " SELF
  if [ "${SELF:-Y}" != "n" ] && [ "${SELF:-Y}" != "N" ]; then
    if self_enroll; then
      ok "本机已入网"
      SKIP_ENROLL=1
    else
      warn "本机自管失败：需要本机 sshd 运行且允许密钥登录（Debian/Ubuntu: apt install openssh-server && systemctl enable --now ssh）"
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
  have flotilla-gateway || die "flotilla-gateway 尚未发布到 npm（仅 GHCR 镜像）。Node 路线的 Gateway 请装 Docker 后重跑，或先 source $TOKEN_FILE 手工拉镜像起容器。"
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
