#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-}"

if [[ -z "$ENV_FILE" || ! -f "$ENV_FILE" ]]; then
  echo "Usage: $0 <deployment-env-file>" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source <(sed 's/\r$//' "$ENV_FILE")
set +a

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_NAME="${DEPLOY_NAME:-$(basename "${ENV_FILE%.env}")}"
OUT_DIR="${ROOT_DIR}/out/${DEPLOY_NAME}/client"

mkdir -p "${OUT_DIR}"

render_client() {
  local enable_auto_redirect="$1"
  local output="$2"

  cat >"${output}" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "strategy": "ipv4_only",
    "servers": [
      {
        "type": "fakeip",
        "tag": "dns-fakeip",
        "inet4_range": "${CLIENT_FAKEIP_V4}",
        "inet6_range": "${CLIENT_FAKEIP_V6}"
      },
      {
        "type": "https",
        "tag": "dns-remote",
        "server": "${GLOBAL_DOH_SERVER}",
        "server_port": 443,
        "path": "${GLOBAL_DOH_PATH}",
        "detour": "ru-gateway",
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
        "query_type": [
          "A"
        ],
        "action": "route",
        "server": "dns-fakeip"
      }
    ],
    "final": "dns-remote",
    "reverse_mapping": true,
    "independent_cache": true
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "${CLIENT_TUN_NAME}",
      "address": [
        "${CLIENT_TUN_ADDRESS_V4}",
        "${CLIENT_TUN_ADDRESS_V6}"
      ],
      "auto_route": true,
      "strict_route": true,
      "auto_redirect": ${enable_auto_redirect}
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "ru-gateway",
      "server": "${RU_PUBLIC_IP}",
      "server_port": ${RU_LISTEN_PORT},
      "uuid": "${CLIENT_UUID}",
      "flow": "${CLIENT_FLOW}",
      "packet_encoding": "xudp",
      "tls": {
        "enabled": true,
        "server_name": "${RU_REALITY_SERVER_NAME}",
        "utls": {
          "enabled": true,
          "fingerprint": "${UTLS_FINGERPRINT}"
        },
        "reality": {
          "enabled": true,
          "public_key": "${RU_REALITY_PUBLIC_KEY}",
          "short_id": "${RU_REALITY_SHORT_ID}"
        }
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "ip_version": 6,
        "action": "route",
        "outbound": "block"
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
        "domain_suffix": [
          "local"
        ],
        "action": "route",
        "outbound": "direct"
      }
    ],
    "final": "ru-gateway"
  }
}
EOF
}

render_client false "${OUT_DIR}/hiddify-cross-platform.json"
render_client true "${OUT_DIR}/linux-sing-box.json"

cat >"${OUT_DIR}/vless-uri.txt" <<EOF
vless://${CLIENT_UUID}@${RU_PUBLIC_IP}:${RU_LISTEN_PORT}?security=reality&sni=${RU_REALITY_SERVER_NAME}&pbk=${RU_REALITY_PUBLIC_KEY}&sid=${RU_REALITY_SHORT_ID}&fp=${UTLS_FINGERPRINT}&type=tcp&flow=${CLIENT_FLOW}#${DEPLOY_NAME}-ru-gateway
EOF

echo "Generated client profiles in ${OUT_DIR}"
