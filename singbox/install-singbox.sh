#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  sing-box AnyTLS + Reality 一键部署脚本
#  服务端: 1.12.x  客户端: 1.13.x
#  用法: bash install-singbox.sh <用户名> <密码>
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

if [[ $# -lt 2 ]]; then
    echo -e "${CYAN}用法:${NC}"
    echo -e "  bash <(curl -fsSL URL) <用户名> <密码>"
    echo -e ""
    echo -e "  用户名: anytls 用户标识（任意字符串）"
    echo -e "  密码:   anytls 认证密码"
    exit 1
fi

[[ $EUID -ne 0 ]] && error "请使用 root 权限运行此脚本"

SB_USER="$1"
SB_PASS="$2"
SB_PORT=443
SNI="www.bing.com"
CONFIG_DIR="/etc/sing-box"
CONFIG_FILE="${CONFIG_DIR}/config.json"
CLIENT_FILE="${PWD}/client-config.json"

# ======================== 检测架构 ========================
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        armv7l)         echo "armv7" ;;
        i686|i386)      echo "386"   ;;
        *)              error "不支持的架构: $(uname -m)" ;;
    esac
}

# ======================== 获取服务器 IP ========================
get_server_ip() {
    local ip=""
    ip=$(curl -s4m5 ifconfig.me 2>/dev/null) \
        || ip=$(curl -s4m5 api.ipify.org 2>/dev/null) \
        || ip=$(curl -s4m5 ip.sb 2>/dev/null) \
        || ip=$(curl -s4m5 ipinfo.io/ip 2>/dev/null) \
        || ip=""
    echo "$ip"
}

# ======================== 安装依赖 ========================
install_deps() {
    info "安装必要依赖..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y curl tar jq openssl >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y curl tar jq openssl >/dev/null 2>&1
    elif command -v yum &>/dev/null; then
        yum install -y curl tar jq openssl >/dev/null 2>&1
    else
        warn "无法自动安装依赖，请确保 curl / tar / jq / openssl 已安装"
    fi
}

# ======================== 安装 sing-box (1.12.x 服务端) ========================
install_singbox() {
    if command -v sing-box &>/dev/null; then
        local ver
        ver=$(sing-box version 2>/dev/null | head -1 | awk '{print $NF}')
        info "sing-box 已安装，版本: ${ver}"
        if [[ "$ver" == 1.12.* ]]; then
            info "版本符合要求，跳过安装"
            return 0
        fi
        warn "当前版本不是 1.12.x，将安装 1.12.x..."
    fi

    local arch
    arch=$(detect_arch)

    info "获取 sing-box 1.12.x 最新稳定版本号..."
    local version
    version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" \
        | jq -r '[.[] | select(.prerelease == false) | select(.tag_name | startswith("v1.12."))][0].tag_name' \
        | sed 's/^v//')

    if [[ -z "$version" || "$version" == "null" ]]; then
        version="1.12.25"
        warn "无法获取最新版本，使用默认版本: ${version}"
    fi

    info "下载 sing-box v${version} (${arch})..."
    local url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${arch}.tar.gz"
    curl -Lo /tmp/sing-box.tar.gz "$url" || error "下载失败: ${url}"

    info "解压并安装..."
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    install -Dm755 "/tmp/sing-box-${version}-linux-${arch}/sing-box" /usr/local/bin/sing-box
    rm -rf /tmp/sing-box.tar.gz "/tmp/sing-box-${version}-linux-${arch}"

    info "创建 systemd 服务..."
    cat > /etc/systemd/system/sing-box.service << 'EOF'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
CapabilityBoundSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    info "sing-box v${version} 安装完成（服务端）"
}

# ======================== 验证 handshake 目标连通性 ========================
check_handshake_target() {
    info "验证 handshake 目标 ${SNI}:443 的连通性..."

    if echo | openssl s_client -connect "${SNI}:443" -servername "${SNI}" </dev/null 2>/dev/null | grep -q 'Verify return code: 0'; then
        info "${SNI}:443 TLS 握手成功"
    else
        local alt_sni="itunes.apple.com"
        warn "${SNI}:443 TLS 握手失败，切换到备选: ${alt_sni}"
        if echo | openssl s_client -connect "${alt_sni}:443" -servername "${alt_sni}" </dev/null 2>/dev/null | grep -q 'Verify return code: 0'; then
            SNI="$alt_sni"
            info "备选 ${SNI}:443 TLS 握手成功"
        else
            warn "备选也不通，继续使用原 SNI（部署后请自行验证）"
        fi
    fi
}

# ======================== 生成密钥 ========================
generate_keys() {
    info "生成 Reality 密钥对..."
    local keypair
    keypair=$(sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$keypair" | grep -i 'PrivateKey' | awk '{print $NF}')
    PUBLIC_KEY=$(echo "$keypair" | grep -i 'PublicKey' | awk '{print $NF}')

    info "生成 short_id..."
    SHORT_ID=$(sing-box generate rand 8 --hex)

    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" || -z "$SHORT_ID" ]]; then
        error "密钥生成失败"
    fi

    info "密钥对生成成功"
    info "  PrivateKey: ${PRIVATE_KEY}"
    info "  PublicKey:  ${PUBLIC_KEY}"
    info "  ShortID:    ${SHORT_ID}"
}

# ======================== 写入服务端配置 (1.12.x 格式) ========================
write_server_config() {
    mkdir -p "$CONFIG_DIR"

    info "写入服务端配置到 ${CONFIG_FILE} (1.12.x 格式)..."
    cat > "$CONFIG_FILE" << SEOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "::",
      "listen_port": ${SB_PORT},
      "users": [
        {
          "name": "${SB_USER}",
          "password": "${SB_PASS}"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${SNI}",
            "server_port": 443
          },
          "private_key": "${PRIVATE_KEY}",
          "short_id": [
            "${SHORT_ID}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
SEOF

    info "校验服务端配置..."
    if ! sing-box check -c "$CONFIG_FILE"; then
        error "服务端配置校验失败，请检查配置"
    fi
    info "服务端配置校验通过"
}

# ======================== 写入客户端配置 (1.13.x 格式) ========================
write_client_config() {
    local server_ip="$1"

    info "写入客户端配置到 ${CLIENT_FILE} (1.13.x 格式)..."
    cat > "$CLIENT_FILE" << CEOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "tls",
        "tag": "google",
        "server": "8.8.8.8",
        "detour": "anytls-out"
      },
      {
        "type": "udp",
        "tag": "local",
        "server": "223.5.5.5"
      }
    ],
    "strategy": "ipv4_only",
    "final": "google"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": "172.19.0.1/30",
      "auto_route": true,
      "strict_route": true
    }
  ],
  "outbounds": [
    {
      "type": "anytls",
      "tag": "anytls-out",
      "server": "${server_ip}",
      "server_port": ${SB_PORT},
      "password": "${SB_PASS}",
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "${PUBLIC_KEY}",
          "short_id": "${SHORT_ID}"
        }
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct"
      },
      {
        "action": "route",
        "outbound": "anytls-out"
      }
    ],
    "auto_detect_interface": true,
    "default_domain_resolver": "local"
  }
}
CEOF

    info "客户端配置已生成 (1.13.x 格式)"
}

# ======================== 启动服务 ========================
start_service() {
    info "启动 sing-box 服务..."
    systemctl enable sing-box
    systemctl restart sing-box

    sleep 2
    if systemctl is-active --quiet sing-box; then
        info "sing-box 服务已启动"
    else
        warn "sing-box 服务似乎未正常启动，请检查日志:"
        journalctl -u sing-box --no-pager -n 10
    fi
}

# ======================== 打印信息 ========================
print_result() {
    local server_ip="$1"
    local ver
    ver=$(sing-box version 2>/dev/null | head -1 | awk '{print $NF}')
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${GREEN}  sing-box AnyTLS + Reality 部署完成！${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
    echo -e "  ${YELLOW}服务端版本:${NC}    ${ver} (1.12.x)"
    echo -e "  ${YELLOW}客户端配置:${NC}    1.13.x 格式"
    echo -e "  ${YELLOW}服务器 IP:${NC}      ${server_ip}"
    echo -e "  ${YELLOW}端口:${NC}           ${SB_PORT}"
    echo -e "  ${YELLOW}用户名:${NC}         ${SB_USER}"
    echo -e "  ${YELLOW}密码:${NC}           ${SB_PASS}"
    echo -e "  ${YELLOW}伪装域名:${NC}       ${SNI}"
    echo -e "  ${YELLOW}Private Key:${NC}    ${PRIVATE_KEY}"
    echo -e "  ${YELLOW}Public Key:${NC}     ${PUBLIC_KEY}"
    echo -e "  ${YELLOW}Short ID:${NC}       ${SHORT_ID}"
    echo ""
    echo -e "  ${YELLOW}服务端配置:${NC}     ${CONFIG_FILE}"
    echo -e "  ${YELLOW}客户端配置:${NC}     ${CLIENT_FILE}"
    echo ""
    echo -e "${CYAN}------------------------------------------------------------${NC}"
    echo -e "  ${GREEN}管理命令:${NC}"
    echo -e "    查看状态:  systemctl status sing-box"
    echo -e "    查看日志:  journalctl -u sing-box --no-pager -n 50"
    echo -e "    重启服务:  systemctl restart sing-box"
    echo -e "    停止服务:  systemctl stop sing-box"
    echo -e "${CYAN}------------------------------------------------------------${NC}"
    echo -e "  ${GREEN}客户端使用:${NC}"
    echo -e "    将 ${CLIENT_FILE} 复制到客户端机器"
    echo -e "    客户端需安装 sing-box 1.13.x"
    echo -e "    运行: sing-box run -c client-config.json"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
}

# ======================== 主流程 ========================
main() {
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}  sing-box AnyTLS + Reality 一键部署${NC}"
    echo -e "${CYAN}  服务端: 1.12.x  |  客户端: 1.13.x${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""

    install_deps
    install_singbox
    check_handshake_target
    generate_keys

    local server_ip
    server_ip=$(get_server_ip)
    if [[ -z "$server_ip" ]]; then
        warn "无法自动获取服务器公网 IP，客户端配置中 server 字段需手动填写"
        server_ip="YOUR_SERVER_IP"
    fi
    info "服务器公网 IP: ${server_ip}"

    write_server_config
    write_client_config "$server_ip"
    start_service
    print_result "$server_ip"
}

main
