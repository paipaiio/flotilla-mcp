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
for arg in "$@"; do
  case "$arg" in
    --skip-enroll) SKIP_ENROLL=1 ;;
    -h|--help)
      cat <<'HELP'
Flotilla 网站模式一键部署（Linux 服务器）：装运行时 → 初始化配置 → 纳管第一台机器 → 启动 Gateway。

用法: bash bootstrap.sh [--skip-enroll]
  --skip-enroll   不引导纳管机器，只部署 Gateway

环境变量:
  FLOTILLA_CONFIG_DIR     配置目录（默认 ~/.config/flotilla）
  FLOTILLA_GATEWAY_PORT   Gateway 端口（默认 8080；重跑沿用上次的端口）

只想在自己电脑上用（本地模式）不需要本脚本：
  npm install -g flotilla-mcp && flotilla add root@<服务器IP> && claude mcp add flotilla -- npx -y flotilla-mcp
HELP
      exit 0 ;;
    *) printf '✗ 未知参数: %s（bash bootstrap.sh --help 查看用法）\n' "$arg" >&2; exit 2 ;;
  esac
done
ME="$(id -un)"

say()  { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- 0. 平台
if [ "$(uname -s)" = Darwin ]; then
  say "这是 macOS——本脚本部署的是 Linux 服务器上的网站模式 Gateway。"
  echo "  在自己电脑上用（本地模式）只需要："
  echo "    npm install -g flotilla-mcp"
  echo "    flotilla add root@<服务器IP>        # 有 ~/.ssh/config 的直接 flotilla add <别名>"
  echo "    claude mcp add flotilla -- npx -y flotilla-mcp"
  exit 0
fi
# sudo：root 不需要；非 root 又没有 sudo 时，需要 root 的步骤直接说明。
if [ "$(id -u)" = 0 ]; then SUDO=""; elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else SUDO="__none__"; fi

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
  warn "没有 Docker，也没有 Node ≥ 20"
  if have apt-get || have dnf || have yum; then
    [ "$SUDO" = "__none__" ] && die "安装 Docker 需要 root 或 sudo。请用 root 重跑，或先手动装 Node ≥ 20（https://nodejs.org）"
    if [ -t 0 ]; then
      read -r -p "  用官方脚本（get.docker.com）安装 Docker？[Y/n]: " INSTALL_DOCKER
      case "${INSTALL_DOCKER:-Y}" in n|N) die "已取消。请手动装 Docker 或 Node ≥ 20 后重跑。" ;; esac
    fi
    curl -fsSL https://get.docker.com | $SUDO sh
    $SUDO usermod -aG docker "$ME" || true
    warn "已把 $ME 加入 docker 组；如 docker info 仍失败，请重新登录后再跑本脚本"
    docker info >/dev/null 2>&1 || die "Docker 安装后仍不可用（组权限可能需重新登录生效）"
    RUNTIME=docker
  else
    die "无法自动安装运行时。请手动装 Docker 或 Node ≥ 20 后重跑。"
  fi
fi

# 防呆：镜像/CLI 可用性必须在问密码之前就验证，别吞了密码才报拉取失败。
# 保留 docker 的真实报错输出——网络类故障（DNS/IPv6/代理）和权限类故障长得完全不一样。
if [ "$RUNTIME" = docker ]; then
  say "预检镜像"
  PULL_ERR=""
  for img in "$IMAGE_MCP" "$IMAGE_GW"; do
    if ! PULL_ERR=$(docker pull "$img" 2>&1); then
      # 重试一次（偶发的网络抖动）
      sleep 3
      PULL_ERR=$(docker pull "$img" 2>&1 || true)
      if ! docker image inspect "$img" >/dev/null 2>&1; then
        printf '%s\n' "$PULL_ERR" >&2
        die "拉取 $img 失败。
  unauthorized/insufficient_scope：GHCR 包为 private 或未登录——
    GitHub → 头像 → Packages → 该包 Settings → Change visibility → Public；
    或：echo <PAT(read:packages)> | docker login ghcr.io -u <用户名> --password-stdin
  timeout/DNS 等网络错误：检查本机到 ghcr.io 的连通性（curl -sI https://ghcr.io/v2/），
    IPv6 环境的常见解法是 docker daemon 加 \"ipv6\": false 或配 DNS。"
      fi
    fi
  done
  ok "镜像就绪"
else
  # 重跑本脚本就是升级路径：已装的也升到最新（和 docker 分支拉 latest 镜像一致）。
  say "安装/升级 flotilla CLI 与 flotilla-gateway（npm -g）"
  npm install -g flotilla-mcp@latest flotilla-gateway@latest || die "npm 安装失败。全局目录无写权限时：npm config set prefix ~/.npm-global 后把 ~/.npm-global/bin 加进 PATH 再重跑"
  # ssh2 的 install script 被 npm 拦下时只有 warn（纯 JS 回退，功能不受影响），
  # 想启用原生加速可补跑一次：npm install -g --allow-scripts=ssh2 flotilla-mcp
fi

# CLI 封装：docker 形态用临时容器跑 CLI。两个坑都踩过：
# ① 镜像 ENTRYPOINT 是 MCP server——必须 --entrypoint node 显式指到 CLI 脚本；
# ② 容器默认 node 用户（uid 1000）进不了宿主机用户的 700 配置目录——
#    用 -u 对齐宿主机 uid/gid，HOME 指到可写的 /tmp，否则 existsSync 假阴性 → chmod EPERM。
if [ "$RUNTIME" = docker ]; then
  # --config 必须显式指到挂载点：HOME 被改指到 /tmp 后，默认路径推算会写到容器里随容器销毁。
  # -e FLOTILLA_BOOTSTRAP_PASSWORD：密码只经环境变量进容器（不进 argv）；容器里没有系统钥匙串。
  flotilla_cli() { docker run --rm --entrypoint node -u "$(id -u):$(id -g)" -e HOME=/tmp/flotilla-home -e FLOTILLA_BOOTSTRAP_PASSWORD -e FLOTILLA_KEYCHAIN=off -v "$CONFIG_DIR":/home/node/.config/flotilla "$IMAGE_MCP" /app/bin/fleet.mjs --config /home/node/.config/flotilla/config.toml "$@"; }
  ADD_HINT="docker run --rm -it --entrypoint node -u \$(id -u):\$(id -g) -e HOME=/tmp/flotilla-home -v $CONFIG_DIR:/home/node/.config/flotilla $IMAGE_MCP /app/bin/fleet.mjs --config /home/node/.config/flotilla/config.toml add root@<IP>"
else
  flotilla_cli() { flotilla --config "$CONFIG_DIR/config.toml" "$@"; }
  ADD_HINT="flotilla --config $CONFIG_DIR/config.toml add root@<IP>"
fi

# ---------------------------------------------------------------- 2. 初始化配置
say "初始化配置目录 $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
# flotilla 自身有 700/600 守卫，CLI add 会自动修正权限；这里提前收敛一次，防呆双保险
chmod 700 "$CONFIG_DIR" 2>/dev/null || true
[ -f "$CONFIG_DIR/config.toml" ] || { : > "$CONFIG_DIR/config.toml"; chmod 600 "$CONFIG_DIR/config.toml"; }
ok "config.toml 就绪"

# ---------------------------------------------------------------- 3. 入网第一台机器（默认自管本机，免密）
detect_sshd_ports() {
  # 返回正在监听的 sshd 端口（空格分隔）；非 root 看不到进程名时返回空，由调用方退回 sshd_config
  if have ss; then
    ss -tlnp 2>/dev/null | grep -w sshd | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' '
  elif have netstat; then
    netstat -tlnp 2>/dev/null | grep -w sshd | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un | tr '\n' ' '
  fi
}

self_enroll() {
  # 本机自管：人已在机器上，fleet 公钥直接追加进目标用户的 authorized_keys（本地文件操作，不需要密码）。
  # 探测仍走 SSH 验证 sshd/密钥登录真的可用；docker 形态探测容器加 --network host，
  # 所以探测地址永远用 127.0.0.1——host.docker.internal 只有常驻 gateway 容器里才需要。
  local suser="$1" sport="$2"
  local key="$CONFIG_DIR/fleet_ed25519"
  if [ ! -f "$key" ]; then
    ssh-keygen -t ed25519 -N "" -C "flotilla-fleet" -f "$key" >/dev/null
    chmod 600 "$key"
  fi
  local pub; pub="$(ssh-keygen -y -f "$key")"

  # 公钥落到谁的 authorized_keys：默认当前用户；换用户需要 root 写对方家目录并修正属主
  local auth_dir="$HOME/.ssh"
  if [ "$suser" != "$(id -un)" ]; then
    [ "$(id -u)" = 0 ] || die "以非 root 身份无法写 $suser 的 authorized_keys——请用 root 重跑，或选当前用户"
    local uhome; uhome="$(getent passwd "$suser" | cut -d: -f6)"
    [ -n "$uhome" ] && [ -d "$uhome" ] || die "找不到用户 $suser 的家目录"
    auth_dir="$uhome/.ssh"
    mkdir -p "$auth_dir"
    touch "$auth_dir/authorized_keys"
    chown -R "$suser:$(id -gn "$suser" 2>/dev/null || echo "$suser")" "$auth_dir"
    chmod 700 "$auth_dir"; chmod 600 "$auth_dir/authorized_keys"
  else
    mkdir -p "$auth_dir" && chmod 700 "$auth_dir"
    touch "$auth_dir/authorized_keys" && chmod 600 "$auth_dir/authorized_keys"
  fi
  if grep -qxF "$pub" "$auth_dir/authorized_keys"; then
    echo "  公钥已存在于 $auth_dir/authorized_keys"
  else
    printf '%s\n' "$pub" >> "$auth_dir/authorized_keys"
    echo "  公钥已写入 $auth_dir/authorized_keys"
  fi

  local name; name="$(hostname -s 2>/dev/null || hostname)"
  if [ "$RUNTIME" = docker ]; then
    docker run --rm --network host --entrypoint node -u "$(id -u):$(id -g)" -e HOME=/tmp/flotilla-home \
      -v "$CONFIG_DIR":/home/node/.config/flotilla \
      "$IMAGE_MCP" /app/bin/fleet.mjs --config /home/node/.config/flotilla/config.toml \
      add "$name" --host 127.0.0.1 --port "$sport" --user "$suser" \
      --auth key --key /home/node/.config/flotilla/fleet_ed25519 --tier prod
    # 探测地址（127.0.0.1）只适用于 --network host 的临时容器；常驻 gateway 跑在
    # bridge 网络容器里，容器自己的 127.0.0.1 不是宿主——把刚写入的记录改写成
    # host.docker.internal（gateway 容器带 --add-host host-gateway 才能解析到宿主）。
    awk -v newhost='host.docker.internal' '
      /^\[\[servers\]\]/ { blk = NR }
      { lines[NR] = $0 }
      END {
        for (i = 1; i <= NR; i++) {
          if (i >= blk && lines[i] == "host = \"127.0.0.1\"") lines[i] = "host = \"" newhost "\""
          print lines[i]
        }
      }' "$CONFIG_DIR/config.toml" > "$CONFIG_DIR/config.toml.tmp"
    mv "$CONFIG_DIR/config.toml.tmp" "$CONFIG_DIR/config.toml"
    chmod 600 "$CONFIG_DIR/config.toml"
  else
    flotilla --config "$CONFIG_DIR/config.toml" add "$name" --host 127.0.0.1 --port "$sport" \
      --user "$suser" --auth key --key "$key" --tier prod
  fi
  # 防假成功：退出码 0 不代表真的入网（比如容器跑错入口），必须看到配置里的服务器块
  grep -q "^\[\[servers\]\]" "$CONFIG_DIR/config.toml"
}

if [ "$SKIP_ENROLL" = 0 ] && [ ! -s "$CONFIG_DIR/config.toml" ]; then
  say "入网第一台机器"
  if [ ! -t 0 ]; then
    warn "非交互环境，跳过入网；之后手动加机器：$ADD_HINT（或在控制台「添加机器」用一行命令入网）"
    SKIP_ENROLL=1
  fi
  if [ "$SKIP_ENROLL" = 0 ]; then
    read -r -p "  把本机纳入管理？免密，回车即完成 [Y/n]: " SELF
    if [ "${SELF:-Y}" != "n" ] && [ "${SELF:-Y}" != "N" ]; then
      # sshd 端口自动探测：ss/netstat 的进程名最可靠；非 root 看不到进程名时退回 sshd_config 的 Port 指令
      DETECTED="$(detect_sshd_ports)"
      if [ -z "$DETECTED" ]; then
        DETECTED="$(awk '$1 == "Port" && $2 ~ /^[0-9]+$/ { print $2; exit }' /etc/ssh/sshd_config 2>/dev/null)"
        for f in /etc/ssh/sshd_config.d/*.conf; do
          [ -e "$f" ] || continue
          [ -n "$DETECTED" ] && break
          DETECTED="$(awk '$1 == "Port" && $2 ~ /^[0-9]+$/ { print $2; exit }' "$f" 2>/dev/null)"
        done
      fi
      read -r -a SSHD_PORTS <<< "$DETECTED" || true
      SELF_PORT_HINT="${SSHD_PORTS[0]:-22}"
      [ "${#SSHD_PORTS[@]}" -gt 1 ] && warn "检测到多个 sshd 端口：$DETECTED——默认取第一个，可手动改"
      read -r -p "  本机 SSH 用户 [$(id -un)]: " SELF_USER; SELF_USER="${SELF_USER:-$(id -un)}"
      read -r -p "  本机 SSH 端口 [$SELF_PORT_HINT]: " SELF_PORT; SELF_PORT="${SELF_PORT:-$SELF_PORT_HINT}"
      if [ "$RUNTIME" = docker ] && have ss \
         && ss -tln 2>/dev/null | grep -qE "127\.0\.0\.1:$SELF_PORT\b" \
         && ! ss -tln 2>/dev/null | grep -qE "(\*|0\.0\.0\.0|\[::\]|::):$SELF_PORT\b"; then
        warn "sshd 只在 127.0.0.1:$SELF_PORT 监听：Gateway 容器走宿主网桥地址连不上本机 sshd，"
        warn "建议让 sshd 监听 0.0.0.0:$SELF_PORT，否则自管节点在控制台里会执行失败"
      fi
      if self_enroll "$SELF_USER" "$SELF_PORT"; then
        ok "本机已入网"
        SKIP_ENROLL=1
      else
        warn "本机自管失败：需要本机 sshd 运行且允许密钥登录"
        # 全新服务器常见原因：根本没装 openssh-server。用户已明确要自管本机，
        # 缺 sshd 就代办到位（需 root + apt），而不是把人踢回 shell 手动装。
        if [ "$(id -u)" = 0 ] && have apt-get; then
          read -r -p "  检测为本机 sshd 未运行——自动安装 openssh-server 后重试？[Y/n]: " FIXSSHD
          if [ "${FIXSSHD:-Y}" != "n" ] && [ "${FIXSSHD:-Y}" != "N" ]; then
            say "安装 openssh-server"
            apt-get update -qq || warn "apt-get update 失败（网络源问题），继续尝试安装"
            apt-get install -y openssh-server || die "openssh-server 安装失败，请手动排查后重跑"
            systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || service ssh start 2>/dev/null || true
            sleep 1
            # 装完重新探测端口：有些镜像默认配置就是非 22，别硬编码 22
            DETECTED="$(detect_sshd_ports)"
            read -r -a SSHD_PORTS <<< "$DETECTED" || true
            SELF_PORT="${SSHD_PORTS[0]:-$SELF_PORT}"
            if self_enroll "$SELF_USER" "$SELF_PORT"; then
              ok "本机已入网"
              SKIP_ENROLL=1
            else
              warn "sshd 已安装但仍连不上——用 ss -tlnp | grep sshd 确认端口 $SELF_PORT 和监听地址"
            fi
          fi
        else
          echo "  手动修复：apt install openssh-server && systemctl enable --now ssh" >&2
        fi
      fi
    fi
  fi
  if [ "$SKIP_ENROLL" = 0 ]; then
    read -r -p "  改为入网远程机器？输入 IP（用户/端口稍后会逐项确认；直接回车跳过）: " HOST
    [ -n "$HOST" ] || { warn "跳过入网；之后加机器：$ADD_HINT（或控制台「添加机器」）"; SKIP_ENROLL=1; }
  fi
  if [ "$SKIP_ENROLL" = 0 ]; then
    read -r -p "  名称 [web-1]: " NAME; NAME="${NAME:-web-1}"
    read -r -p "  用户 [root]: " USERNAME; USERNAME="${USERNAME:-root}"
    read -r -p "  端口 [22]: " PORT; PORT="${PORT:-22}"
    read -r -s -p "  一次性登录密码（输入不显示; 目标机需允许密码登录）: " PASSWD; echo
    [ -n "$PASSWD" ] || die "空密码，未执行"
    FLOTILLA_BOOTSTRAP_PASSWORD="$PASSWD" flotilla_cli add "$NAME" --host "$HOST" --port "$PORT" \
      --user "$USERNAME" --bootstrap --tier prod \
      || die "入网失败：连接被拒多半是端口/sshd 问题（用 nc -vz $HOST $PORT 验证），
  认证失败则检查密码与目标机 sshd 的 PasswordAuthentication"
    ok "$NAME 已入网"
  fi
fi

if grep -q '^\[\[servers\]\]' "$CONFIG_DIR/config.toml" 2>/dev/null; then
  echo
  warn "说明：新纳管的机器按最严的 prod 层级登记。网站模式（HTTP）没有审批弹窗，"
  warn "所以默认只能执行只读/安全命令，破坏性命令会被拒绝。要放开（任选其一）："
  echo "    flotilla set <名字> --tier staging                       # 该机器降到 staging"
  echo "    在 $CONFIG_DIR/config.toml 的 [defaults] 加 allowConfirmFlag = true   # 允许控制台勾选 confirm 执行"
  echo
fi

# ---------------------------------------------------------------- 4. token + 启动 Gateway
TOKEN_FILE="$CONFIG_DIR/gateway.env"
if [ ! -f "$TOKEN_FILE" ]; then
  printf 'FLOTILLA_GATEWAY_TOKEN=%s\n' "$(openssl rand -hex 32 2>/dev/null || node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  FIRST_INSTALL=1
fi
# shellcheck disable=SC1090
. "$TOKEN_FILE"
# 必须 export：前台启动分支靠环境变量把 token 传给 flotilla-gateway 进程，
# 而 source 进来的赋值默认不导出——没 export 时网关会以「缺 token」拒绝启动。
export FLOTILLA_GATEWAY_TOKEN
# 首次安装直接把 token 打到终端（仅此一次；重跑脚本不会再显示），
# 方便立刻接 MCP 客户端/控制台，不必再 cat 一次 gateway.env。
if [ "${FIRST_INSTALL:-0}" = 1 ]; then
  printf '\033[1;32m✓\033[0m Gateway token（已写入 %s，仅此一次显示）:\n  %s\n' "$TOKEN_FILE" "$FLOTILLA_GATEWAY_TOKEN"
fi

# 端口：env 可覆盖（FLOTILLA_GATEWAY_PORT）。有现成容器时默认沿用它的端口——
# 重跑 bootstrap 是常规升级路径，不该每次先问一遍端口。
port_in_use() { (echo > "/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
# gateway.pid 只有在仍指向 flotilla-gateway 进程时才算数（重启后 PID 可能被别的进程复用）。
our_gateway_pid() {
  local pid
  [ -f "$CONFIG_DIR/gateway.pid" ] || return 1
  pid="$(cat "$CONFIG_DIR/gateway.pid")"
  kill -0 "$pid" 2>/dev/null && ps -p "$pid" -o args= 2>/dev/null | grep -q flotilla-gateway && echo "$pid"
}
GW_OWN_PORT=""
if [ "$RUNTIME" = docker ] && docker ps -a --format '{{.Names}}' | grep -qx flotilla-gateway; then
  GW_OWN_PORT="$(docker inspect -f '{{json .HostConfig.PortBindings}}' flotilla-gateway 2>/dev/null \
    | grep -oE '"HostPort":"[0-9]+"' | head -1 | grep -oE '[0-9]+' || true)"
fi
if [ "$RUNTIME" = node ]; then
  if [ -f /etc/systemd/system/flotilla-gateway.service ]; then
    GW_OWN_PORT="$(grep -oE -- '--port [0-9]+' /etc/systemd/system/flotilla-gateway.service | grep -oE '[0-9]+' || true)"
  elif [ -f "$CONFIG_DIR/gateway.port" ] && our_gateway_pid >/dev/null; then
    GW_OWN_PORT="$(cat "$CONFIG_DIR/gateway.port")"
  fi
fi
GW_PORT="${FLOTILLA_GATEWAY_PORT:-${GW_OWN_PORT:-8080}}"
# 现有 flotilla-gateway 容器自己就发布在目标端口上——重建会先删容器再绑端口，
# 不算冲突；逼着用户「更新也要换端口」是错的。
if port_in_use "$GW_PORT" && [ "$GW_PORT" != "$GW_OWN_PORT" ]; then
  warn "端口 $GW_PORT 已被占用"
  (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E "[:.]${GW_PORT}\b" || true
  if [ -t 0 ]; then
    read -r -p "  换哪个端口？[8081]: " PICK
    GW_PORT="${PICK:-8081}"
    while port_in_use "$GW_PORT" && [ "$GW_PORT" != "$GW_OWN_PORT" ]; do
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
      --add-host host.docker.internal:host-gateway \
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
    systemctl enable flotilla-gateway >/dev/null 2>&1
    # restart 而不是 enable --now：重跑时服务已在跑，要按新 unit/新版本重启。
    systemctl restart flotilla-gateway
    LOG_HINT="journalctl -u flotilla-gateway -f"
  else
    warn "非 root 或无 systemd——后台启动 Gateway（停止：kill \$(cat $CONFIG_DIR/gateway.pid)）"
    # 重跑：先停掉上次本脚本启动的那个，避免多个网关抢端口。
    if OLD_PID="$(our_gateway_pid)"; then
      kill "$OLD_PID" 2>/dev/null || true
      sleep 1
    fi
    # 输出必须重定向到日志文件：后台进程继承脚本 stdout，会把日志喷进用户的终端，
    # 还会让「bash bootstrap.sh | 其他命令」的管道永远不结束（子进程占着 pipe）。
    FLOTILLA_CONFIG="$CONFIG_DIR/config.toml" nohup flotilla-gateway --host 127.0.0.1 --port "$GW_PORT" \
      >> "$CONFIG_DIR/gateway.log" 2>&1 < /dev/null &
    echo $! > "$CONFIG_DIR/gateway.pid"
    echo "$GW_PORT" > "$CONFIG_DIR/gateway.port"
    LOG_HINT="tail -f $CONFIG_DIR/gateway.log"
    ok "日志：$CONFIG_DIR/gateway.log（PID 见 gateway.pid）"
  fi
fi

# ---------------------------------------------------------------- 5. 健康检查验收
say "健康检查"
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$GW_PORT/healthz" 2>/dev/null | grep -q '"engineVersion"'; then
    ok "Gateway 已上线：http://127.0.0.1:$GW_PORT/healthz"
    ok "控制台：http://127.0.0.1:$GW_PORT/console/（token 见 $TOKEN_FILE）"
    echo
    echo "  从你自己的电脑打开控制台（不用对外暴露）："
    echo "    ssh -L $GW_PORT:127.0.0.1:$GW_PORT $ME@<这台服务器>   然后浏览器开 http://localhost:$GW_PORT/console/"
    echo
    echo "  对外暴露：把 127.0.0.1:$GW_PORT 反代到 Caddy/nginx 并配 HTTPS（模板见 deploy/）。之后接 MCP 客户端："
    echo "    claude mcp add --transport http flotilla https://<你的域名>/mcp --header \"Authorization: Bearer <token>\""
    echo "    codex mcp add flotilla --url https://<你的域名>/mcp --bearer-token-env-var FLOTILLA_GATEWAY_TOKEN"
    echo "  只给某些人只读权限：flotilla-gateway token create <名字> --role viewer"
    exit 0
  fi
  sleep 1
done
die "Gateway 未通过健康检查。看日志：$([ "$RUNTIME" = docker ] && echo 'docker logs flotilla-gateway' || echo "${LOG_HINT:-tail -f $CONFIG_DIR/gateway.log}")"
