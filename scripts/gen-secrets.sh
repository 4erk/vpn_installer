#!/usr/bin/env bash
set -euo pipefail

OUTPUT_FILE="${1:-}"

if [[ -z "$OUTPUT_FILE" ]]; then
  echo "Usage: $0 <output-env-file>" >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required." >&2
  exit 1
fi

x25519_standard_b64_pair() {
  local pem
  local private_b64
  local public_b64
  pem="$(mktemp)"
  trap 'rm -f "$pem"' RETURN

  openssl genpkey -algorithm X25519 -out "$pem" >/dev/null 2>&1
  private_b64="$(openssl pkey -in "$pem" -outform DER 2>/dev/null | tail -c 32 | base64 -w0)"
  public_b64="$(openssl pkey -in "$pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)"
  printf '%s\n%s\n' "$private_b64" "$public_b64"
}

base64url_nopad() {
  printf '%s' "$1" | tr '+/' '-_' | tr -d '='
}

readarray -t reality_pair < <(x25519_standard_b64_pair)
readarray -t ru_wg_pair < <(x25519_standard_b64_pair)
readarray -t foreign_wg_pair < <(x25519_standard_b64_pair)

client_uuid="$(cat /proc/sys/kernel/random/uuid)"
short_id="$(openssl rand -hex 8)"
preshared_key="$(openssl rand -base64 32 | tr -d '\n')"

mkdir -p "$(dirname "$OUTPUT_FILE")"

cat >"$OUTPUT_FILE" <<EOF
DEPLOY_NAME="$(basename "${OUTPUT_FILE%.env}")"

RU_PUBLIC_IP=""
FOREIGN_PUBLIC_IP=""
SSH_PORT="22"
WAN_INTERFACE=""

CLIENT_UUID="${client_uuid}"
CLIENT_FLOW="xtls-rprx-vision"
RU_LISTEN_PORT="443"
RU_REALITY_SERVER_NAME="www.cloudflare.com"
RU_REALITY_HANDSHAKE_SERVER="www.cloudflare.com"
RU_REALITY_HANDSHAKE_PORT="443"
RU_REALITY_PRIVATE_KEY="$(base64url_nopad "${reality_pair[0]}")"
RU_REALITY_PUBLIC_KEY="$(base64url_nopad "${reality_pair[1]}")"
RU_REALITY_SHORT_ID="${short_id}"
UTLS_FINGERPRINT="chrome"

WG_INTERFACE="wg0"
WG_PORT="51820"
WG_MTU="1380"
WG_KEEPALIVE="25"
WG_ROUTE_TABLE="51820"
APP_ROUTE_MARK="48"
WG_TUNNEL_FWMARK="51820"
WG_RU_ADDRESS="10.74.0.1/32"
WG_FOREIGN_ADDRESS="10.74.0.2/32"
WG_RU_PRIVATE_KEY="${ru_wg_pair[0]}"
WG_RU_PUBLIC_KEY="${ru_wg_pair[1]}"
WG_FOREIGN_PRIVATE_KEY="${foreign_wg_pair[0]}"
WG_FOREIGN_PUBLIC_KEY="${foreign_wg_pair[1]}"
WG_PRESHARED_KEY="${preshared_key}"

RU_DIRECT_DNS_SERVER="77.88.8.8"
RU_DIRECT_DNS_PORT="53"
GLOBAL_DOH_SERVER="1.1.1.1"
GLOBAL_DOH_SERVER_NAME="cloudflare-dns.com"
GLOBAL_DOH_PATH="/dns-query"

RULESET_DIR="/var/lib/vpn-stack/rules"
RU_GEOSITE_URL="https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs"
RU_GEOIP_URL="https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"

FOREIGN_BLOCK_RU="1"
FOREIGN_RU_IPV4_LIST_URL="https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"
FOREIGN_RU_IPV6_LIST_URL="https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone"

CLIENT_TUN_NAME="tun0"
CLIENT_TUN_ADDRESS_V4="172.19.0.1/30"
CLIENT_TUN_ADDRESS_V6="fdfe:dcba:9876::1/126"
CLIENT_FAKEIP_V4="198.18.0.0/15"
CLIENT_FAKEIP_V6="fc00::/18"
CLIENT_ROUTE_EXCLUDE_V4=""
CLIENT_ROUTE_EXCLUDE_V6=""
EOF

echo "Wrote ${OUTPUT_FILE}"
