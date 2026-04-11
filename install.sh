#!/usr/bin/env bash
set -euo pipefail

ROLE=""
ENV_FILE=""
OUTPUT_DIR=""
ASSETS_DIR=""
RENDER_ONLY=0

usage() {
  cat <<'EOF'
Usage:
  install.sh --role <ru-gateway|foreign-exit> --env-file <file> [--assets-dir <dir>] [--render-only --output-dir <dir>]

Examples:
  sudo ./install.sh --role ru-gateway --env-file ./out/my-stack/server/ru.env --assets-dir ./out/my-stack/assets
  sudo ./install.sh --role foreign-exit --env-file ./out/my-stack/server/foreign.env --assets-dir ./out/my-stack/assets
  ./install.sh --role ru-gateway --env-file ./deployments/my-stack.env --render-only --output-dir ./out/my-stack/preview/ru
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      ROLE="${2:-}"
      shift 2
      ;;
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --assets-dir)
      ASSETS_DIR="${2:-}"
      shift 2
      ;;
    --render-only)
      RENDER_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$ROLE" || -z "$ENV_FILE" ]]; then
  usage >&2
  exit 1
fi

if [[ "$ROLE" != "ru-gateway" && "$ROLE" != "foreign-exit" ]]; then
  echo "Unsupported role: $ROLE" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Env file not found: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source <(sed 's/\r$//' "$ENV_FILE")
set +a

if [[ -z "$ASSETS_DIR" ]]; then
  ENV_PARENT_DIR="$(cd "$(dirname "$ENV_FILE")" && pwd)"
  if [[ -d "${ENV_PARENT_DIR}/../assets" ]]; then
    ASSETS_DIR="$(cd "${ENV_PARENT_DIR}/../assets" && pwd)"
  fi
fi

DEPLOY_NAME="${DEPLOY_NAME:-vpn-stack}"
SSH_PORT="${SSH_PORT:-22}"

CLIENT_FLOW="${CLIENT_FLOW:-xtls-rprx-vision}"
RU_LISTEN_PORT="${RU_LISTEN_PORT:-443}"
RU_REALITY_HANDSHAKE_PORT="${RU_REALITY_HANDSHAKE_PORT:-443}"
UTLS_FINGERPRINT="${UTLS_FINGERPRINT:-chrome}"

WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_MTU="${WG_MTU:-1380}"
WG_KEEPALIVE="${WG_KEEPALIVE:-25}"
WG_ROUTE_TABLE="${WG_ROUTE_TABLE:-51820}"
APP_ROUTE_MARK="${APP_ROUTE_MARK:-48}"
WG_TUNNEL_FWMARK="${WG_TUNNEL_FWMARK:-51820}"

RU_DIRECT_DNS_SERVER="${RU_DIRECT_DNS_SERVER:-77.88.8.8}"
RU_DIRECT_DNS_PORT="${RU_DIRECT_DNS_PORT:-53}"
GLOBAL_DOH_SERVER="${GLOBAL_DOH_SERVER:-1.1.1.1}"
GLOBAL_DOH_SERVER_NAME="${GLOBAL_DOH_SERVER_NAME:-cloudflare-dns.com}"
GLOBAL_DOH_PATH="${GLOBAL_DOH_PATH:-/dns-query}"

RULESET_DIR="${RULESET_DIR:-/var/lib/vpn-stack/rules}"
RU_GEOSITE_URL="${RU_GEOSITE_URL:-https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs}"
RU_GEOIP_URL="${RU_GEOIP_URL:-https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs}"
FOREIGN_BLOCK_RU="${FOREIGN_BLOCK_RU:-1}"
FOREIGN_RU_IPV4_LIST_URL="${FOREIGN_RU_IPV4_LIST_URL:-https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone}"
FOREIGN_RU_IPV6_LIST_URL="${FOREIGN_RU_IPV6_LIST_URL:-https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone}"

VPNSTACK_ROOT="/etc/vpn-stack"
SINGBOX_CONFIG_PATH="/etc/sing-box/config.json"
WG_CONFIG_PATH="/etc/wireguard/${WG_INTERFACE}.conf"
NFTABLES_PATH="/etc/nftables.conf"
RULE_SYNC_SCRIPT="/usr/local/lib/vpn-stack/sync-state.sh"

WG_RU_ADDRESS_HOST="${WG_RU_ADDRESS%%/*}"
WG_FOREIGN_ADDRESS_HOST="${WG_FOREIGN_ADDRESS%%/*}"

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required variable: $name" >&2
    exit 1
  fi
}

require_common_env() {
  require_var DEPLOY_NAME
  require_var RU_PUBLIC_IP
  require_var FOREIGN_PUBLIC_IP
  require_var CLIENT_UUID
  require_var RU_REALITY_SERVER_NAME
  require_var RU_REALITY_HANDSHAKE_SERVER
  require_var RU_REALITY_PRIVATE_KEY
  require_var RU_REALITY_PUBLIC_KEY
  require_var RU_REALITY_SHORT_ID
  require_var WG_RU_ADDRESS
  require_var WG_FOREIGN_ADDRESS
  require_var WG_RU_PRIVATE_KEY
  require_var WG_RU_PUBLIC_KEY
  require_var WG_FOREIGN_PRIVATE_KEY
  require_var WG_FOREIGN_PUBLIC_KEY
  require_var WG_PRESHARED_KEY
}

require_ru_env() {
  require_common_env
}

require_foreign_env() {
  require_common_env
}

write_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat >"$path"
}

copy_if_present() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
    return 0
  fi
  return 1
}

render_ru_singbox() {
  cat <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "strategy": "ipv4_only",
    "servers": [
      {
        "type": "udp",
        "tag": "dns-ru-direct",
        "server": "${RU_DIRECT_DNS_SERVER}",
        "server_port": ${RU_DIRECT_DNS_PORT}
      },
      {
        "type": "https",
        "tag": "dns-global",
        "server": "${GLOBAL_DOH_SERVER}",
        "server_port": 443,
        "path": "${GLOBAL_DOH_PATH}",
        "routing_mark": ${APP_ROUTE_MARK},
        "tls": {
          "enabled": true,
          "server_name": "${GLOBAL_DOH_SERVER_NAME}"
        }
      }
    ],
    "rules": [
      {
        "query_type": [
          "AAAA"
        ],
        "action": "reject"
      },
      {
        "rule_set": [
          "geosite-ru"
        ],
        "action": "route",
        "server": "dns-ru-direct",
        "strategy": "ipv4_only"
      }
    ],
    "final": "dns-global",
    "independent_cache": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": ${RU_LISTEN_PORT},
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "name": "${DEPLOY_NAME}-client",
          "uuid": "${CLIENT_UUID}",
          "flow": "${CLIENT_FLOW}"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${RU_REALITY_SERVER_NAME}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${RU_REALITY_HANDSHAKE_SERVER}",
            "server_port": ${RU_REALITY_HANDSHAKE_PORT}
          },
          "private_key": "${RU_REALITY_PRIVATE_KEY}",
          "short_id": [
            "${RU_REALITY_SHORT_ID}"
          ],
          "max_time_difference": "1m"
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-ru"
    },
    {
      "type": "direct",
      "tag": "to-foreign",
      "routing_mark": ${APP_ROUTE_MARK}
    },
    {
      "type": "block",
      "tag": "blocked"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rule_set": [
      {
        "type": "local",
        "tag": "geosite-ru",
        "format": "binary",
        "path": "${RULESET_DIR}/geosite-ru.srs"
      },
      {
        "type": "local",
        "tag": "geoip-ru",
        "format": "binary",
        "path": "${RULESET_DIR}/geoip-ru.srs"
      }
    ],
    "rules": [
      {
        "ip_version": 6,
        "action": "route",
        "outbound": "blocked"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct-ru"
      },
      {
        "rule_set": [
          "geosite-ru"
        ],
        "action": "route",
        "outbound": "direct-ru"
      },
      {
        "rule_set": [
          "geoip-ru"
        ],
        "action": "route",
        "outbound": "direct-ru"
      }
    ],
    "final": "to-foreign"
  }
}
EOF
}

render_foreign_singbox() {
  cat <<'EOF'
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
}

render_ru_wg() {
  cat <<EOF
[Interface]
Address = ${WG_RU_ADDRESS}
PrivateKey = ${WG_RU_PRIVATE_KEY}
MTU = ${WG_MTU}
FwMark = ${WG_TUNNEL_FWMARK}
Table = off
PostUp = ip -4 route add default dev ${WG_INTERFACE} table ${WG_ROUTE_TABLE}
PostUp = ip -4 rule add fwmark ${APP_ROUTE_MARK} table ${WG_ROUTE_TABLE} priority 10000
PreDown = ip -4 rule del fwmark ${APP_ROUTE_MARK} table ${WG_ROUTE_TABLE} priority 10000
PreDown = ip -4 route del default dev ${WG_INTERFACE} table ${WG_ROUTE_TABLE}

[Peer]
PublicKey = ${WG_FOREIGN_PUBLIC_KEY}
PresharedKey = ${WG_PRESHARED_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = ${FOREIGN_PUBLIC_IP}:${WG_PORT}
PersistentKeepalive = ${WG_KEEPALIVE}
EOF
}

render_foreign_wg() {
  cat <<EOF
[Interface]
Address = ${WG_FOREIGN_ADDRESS}
ListenPort = ${WG_PORT}
PrivateKey = ${WG_FOREIGN_PRIVATE_KEY}
MTU = ${WG_MTU}

[Peer]
PublicKey = ${WG_RU_PUBLIC_KEY}
PresharedKey = ${WG_PRESHARED_KEY}
AllowedIPs = ${WG_RU_ADDRESS_HOST}/32
EOF
}

render_foreign_nftables() {
  local wan_iface="$1"
  cat <<EOF
flush ruleset

table inet vpnstack {
  set ru_ipv4 {
    type ipv4_addr
    flags interval
    auto-merge
  }

  set ru_ipv6 {
    type ipv6_addr
    flags interval
    auto-merge
  }

  chain input {
    type filter hook input priority 0;
    policy drop;

    iifname "lo" accept
    ip6 nexthdr icmpv6 accept
    ip protocol icmp accept
    ct state established,related accept
    tcp dport ${SSH_PORT} accept
    udp dport ${WG_PORT} accept
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;

    ct state established,related accept
    iifname "${WG_INTERFACE}" oifname "${wan_iface}" ip daddr @ru_ipv4 drop
    iifname "${WG_INTERFACE}" oifname "${wan_iface}" ip6 daddr @ru_ipv6 drop
    iifname "${WG_INTERFACE}" oifname "${wan_iface}" accept
    iifname "${wan_iface}" oifname "${WG_INTERFACE}" ct state established,related accept
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat;
    ip saddr ${WG_RU_ADDRESS_HOST} oifname "${wan_iface}" masquerade
  }
}
EOF
}

render_ru_firewall_nftables() {
  cat <<EOF
flush ruleset

table inet vpnstack {
  chain input {
    type filter hook input priority 0;
    policy drop;

    iifname "lo" accept
    ip6 nexthdr icmpv6 accept
    ip protocol icmp accept
    ct state established,related accept
    tcp dport ${SSH_PORT} accept
    tcp dport ${RU_LISTEN_PORT} accept
  }
}
EOF
}

render_sync_script() {
  cat <<EOF
#!/usr/bin/env bash
set -euo pipefail

ROLE="\${1:-}"
RULESET_DIR="\${2:-${RULESET_DIR}}"
RU_GEOSITE_URL="\${3:-${RU_GEOSITE_URL}}"
RU_GEOIP_URL="\${4:-${RU_GEOIP_URL}}"
FOREIGN_BLOCK_RU="\${5:-${FOREIGN_BLOCK_RU}}"
FOREIGN_RU_IPV4_LIST_URL="\${6:-${FOREIGN_RU_IPV4_LIST_URL}}"
FOREIGN_RU_IPV6_LIST_URL="\${7:-${FOREIGN_RU_IPV6_LIST_URL}}"

mkdir -p "\$RULESET_DIR"

download() {
  local url="\$1"
  local output="\$2"
  curl -fsSL "\$url" -o "\$output.tmp"
  mv "\$output.tmp" "\$output"
}

if [[ "\$ROLE" == "ru-gateway" ]]; then
  download "\$RU_GEOSITE_URL" "\$RULESET_DIR/geosite-ru.srs"
  download "\$RU_GEOIP_URL" "\$RULESET_DIR/geoip-ru.srs"
  exit 0
fi

if [[ "\$ROLE" == "foreign-exit" && "\$FOREIGN_BLOCK_RU" == "1" ]]; then
  local_v4="\$RULESET_DIR/ru-ipv4.zone"
  local_v6="\$RULESET_DIR/ru-ipv6.zone"

  download "\$FOREIGN_RU_IPV4_LIST_URL" "\$local_v4"
  download "\$FOREIGN_RU_IPV6_LIST_URL" "\$local_v6"

  {
    echo "flush set inet vpnstack ru_ipv4"
    if [[ -s "\$local_v4" ]]; then
      printf 'add element inet vpnstack ru_ipv4 { '
      paste -sd, "\$local_v4"
      echo ' }'
    fi
    echo "flush set inet vpnstack ru_ipv6"
    if [[ -s "\$local_v6" ]]; then
      printf 'add element inet vpnstack ru_ipv6 { '
      paste -sd, "\$local_v6"
      echo ' }'
    fi
  } > "\$RULESET_DIR/nft-ru-block.nft"

  nft -f "\$RULESET_DIR/nft-ru-block.nft"
fi
EOF
}

render_sync_service() {
  cat <<EOF
[Unit]
Description=Sync vpn-stack state for ${ROLE}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${RULE_SYNC_SCRIPT} ${ROLE}
EOF
}

render_sync_timer() {
  cat <<'EOF'
[Unit]
Description=Run vpn-stack state sync daily

[Timer]
OnBootSec=2m
OnUnitActiveSec=1d
RandomizedDelaySec=20m
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

stage_preseed_assets() {
  if [[ -z "${ASSETS_DIR:-}" || ! -d "${ASSETS_DIR}" ]]; then
    return 0
  fi

  mkdir -p "${RULESET_DIR}"

  if [[ "$ROLE" == "ru-gateway" ]]; then
    copy_if_present "${ASSETS_DIR}/geosite-ru.srs" "${RULESET_DIR}/geosite-ru.srs" || true
    copy_if_present "${ASSETS_DIR}/geoip-ru.srs" "${RULESET_DIR}/geoip-ru.srs" || true
  else
    copy_if_present "${ASSETS_DIR}/ru-ipv4.zone" "${RULESET_DIR}/ru-ipv4.zone" || true
    copy_if_present "${ASSETS_DIR}/ru-ipv6.zone" "${RULESET_DIR}/ru-ipv6.zone" || true
  fi
}

have_bootstrap_assets() {
  if [[ "$ROLE" == "ru-gateway" ]]; then
    [[ -s "${RULESET_DIR}/geosite-ru.srs" && -s "${RULESET_DIR}/geoip-ru.srs" ]]
    return
  fi

  if [[ "${FOREIGN_BLOCK_RU}" != "1" ]]; then
    return 0
  fi

  [[ -s "${RULESET_DIR}/ru-ipv4.zone" ]]
}

apply_foreign_ru_block_from_local_assets() {
  local local_v4="${RULESET_DIR}/ru-ipv4.zone"
  local local_v6="${RULESET_DIR}/ru-ipv6.zone"

  if [[ "${FOREIGN_BLOCK_RU}" != "1" || ! -s "${local_v4}" ]]; then
    return 0
  fi

  {
    echo "flush set inet vpnstack ru_ipv4"
    if [[ -s "${local_v4}" ]]; then
      printf 'add element inet vpnstack ru_ipv4 { '
      paste -sd, "${local_v4}"
      echo ' }'
    fi
    echo "flush set inet vpnstack ru_ipv6"
    if [[ -s "${local_v6}" ]]; then
      printf 'add element inet vpnstack ru_ipv6 { '
      paste -sd, "${local_v6}"
      echo ' }'
    fi
  } > "${RULESET_DIR}/nft-ru-block.nft"

  nft -f "${RULESET_DIR}/nft-ru-block.nft"
}

write_preview_files() {
  local base="$1"
  mkdir -p "$base"
  if [[ "$ROLE" == "ru-gateway" ]]; then
    write_file "${base}/sing-box.json" < <(render_ru_singbox)
    write_file "${base}/${WG_INTERFACE}.conf" < <(render_ru_wg)
    write_file "${base}/nftables.conf" < <(render_ru_firewall_nftables)
  else
    local wan_iface="${WAN_INTERFACE:-eth0}"
    write_file "${base}/sing-box.json" < <(render_foreign_singbox)
    write_file "${base}/${WG_INTERFACE}.conf" < <(render_foreign_wg)
    write_file "${base}/nftables.conf" < <(render_foreign_nftables "$wan_iface")
  fi
  write_file "${base}/sync-state.sh" < <(render_sync_script)
  write_file "${base}/vpn-stack-sync.service" < <(render_sync_service)
  write_file "${base}/vpn-stack-sync.timer" < <(render_sync_timer)
}

if [[ "$ROLE" == "ru-gateway" ]]; then
  require_ru_env
else
  require_foreign_env
fi

if [[ "$RENDER_ONLY" == "1" ]]; then
  require_var OUTPUT_DIR
  write_preview_files "$OUTPUT_DIR"
  exit 0
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "install.sh must run as root unless --render-only is used." >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Cannot detect operating system." >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "This installer targets Ubuntu. Detected: ${ID:-unknown}" >&2
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg \
  nftables \
  unattended-upgrades \
  wireguard \
  wireguard-tools

if ! command -v sing-box >/dev/null 2>&1; then
  curl -fsSL https://sing-box.sagernet.org/installation/tools/install.sh | bash
fi

mkdir -p "${VPNSTACK_ROOT}" /etc/sing-box /etc/wireguard "${RULESET_DIR}" /usr/local/lib/vpn-stack /etc/systemd/system

write_file "${VPNSTACK_ROOT}/deployment.env" <"${ENV_FILE}"
write_file "${RULE_SYNC_SCRIPT}" < <(render_sync_script)
chmod 0755 "${RULE_SYNC_SCRIPT}"
write_file "/etc/systemd/system/vpn-stack-sync.service" < <(render_sync_service)
write_file "/etc/systemd/system/vpn-stack-sync.timer" < <(render_sync_timer)

if [[ "$ROLE" == "ru-gateway" ]]; then
  write_file "${SINGBOX_CONFIG_PATH}" < <(render_ru_singbox)
  write_file "${WG_CONFIG_PATH}" < <(render_ru_wg)
  write_file "${NFTABLES_PATH}" < <(render_ru_firewall_nftables)
  cat >/etc/sysctl.d/90-vpn-stack.conf <<EOF
net.ipv4.conf.all.src_valid_mark=1
EOF
else
  WAN_INTERFACE="${WAN_INTERFACE:-$(ip route show default | awk '/default/ {print $5; exit}')}"
  if [[ -z "${WAN_INTERFACE:-}" ]]; then
    echo "Unable to detect WAN interface. Set WAN_INTERFACE in the env file." >&2
    exit 1
  fi
  write_file "${SINGBOX_CONFIG_PATH}" < <(render_foreign_singbox)
  write_file "${WG_CONFIG_PATH}" < <(render_foreign_wg)
  write_file "${NFTABLES_PATH}" < <(render_foreign_nftables "$WAN_INTERFACE")
  cat >/etc/sysctl.d/90-vpn-stack.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
fi

stage_preseed_assets

sysctl --system >/dev/null
systemctl daemon-reload
systemctl enable nftables
systemctl restart nftables
if [[ "$ROLE" == "foreign-exit" ]]; then
  apply_foreign_ru_block_from_local_assets
fi
systemctl enable "wg-quick@${WG_INTERFACE}"
systemctl restart "wg-quick@${WG_INTERFACE}"
systemctl enable vpn-stack-sync.timer
if ! systemctl start vpn-stack-sync.service; then
  if ! have_bootstrap_assets; then
    echo "vpn-stack-sync.service failed and no bootstrap assets are present." >&2
    exit 1
  fi
fi

if [[ "$ROLE" == "ru-gateway" ]]; then
  systemctl enable sing-box
  systemctl restart sing-box
fi

systemctl enable unattended-upgrades || true

echo "Completed ${ROLE} installation for ${DEPLOY_NAME}."
