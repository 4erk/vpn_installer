#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-}"
RU_SSH=""
FOREIGN_SSH=""

shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ru-ssh)
      RU_SSH="${2:-}"
      shift 2
      ;;
    --foreign-ssh)
      FOREIGN_SSH="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 <deployment-env-file> [--ru-ssh user@host] [--foreign-ssh user@host]" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$ENV_FILE" || ! -f "$ENV_FILE" ]]; then
  echo "Usage: $0 <deployment-env-file> [--ru-ssh user@host] [--foreign-ssh user@host]" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source <(sed 's/\r$//' "$ENV_FILE")
set +a

print_ru_commands() {
  cat <<EOF
RU host checks:
  sudo systemctl is-active sing-box nftables wg-quick@${WG_INTERFACE} vpn-stack-sync.timer
  sudo wg show ${WG_INTERFACE}
  sudo ip -4 rule show | grep -F "fwmark ${APP_ROUTE_MARK}"
  sudo ip -4 route show table ${WG_ROUTE_TABLE}
  sudo ip route get 1.1.1.1 mark ${APP_ROUTE_MARK}
  sudo nft list ruleset
EOF
}

print_foreign_commands() {
  cat <<EOF
Foreign host checks:
  sudo systemctl is-active nftables wg-quick@${WG_INTERFACE} vpn-stack-sync.timer
  sudo wg show ${WG_INTERFACE}
  sudo nft list ruleset
  curl -4 https://ifconfig.co
EOF
}

run_remote() {
  local target="$1"
  local script="$2"
  ssh "$target" "bash -s" <<EOF
set -euo pipefail
${script}
EOF
}

if [[ -n "$RU_SSH" ]]; then
  run_remote "$RU_SSH" "
echo '[RU] services'
systemctl is-active sing-box nftables wg-quick@${WG_INTERFACE} vpn-stack-sync.timer
echo '[RU] wireguard'
wg show ${WG_INTERFACE}
echo '[RU] policy rule'
ip -4 rule show | grep -F 'fwmark ${APP_ROUTE_MARK}'
echo '[RU] route table'
ip -4 route show table ${WG_ROUTE_TABLE}
echo '[RU] marked route probe'
ip route get 1.1.1.1 mark ${APP_ROUTE_MARK}
"
else
  print_ru_commands
fi

if [[ -n "$FOREIGN_SSH" ]]; then
  run_remote "$FOREIGN_SSH" "
echo '[FOREIGN] services'
systemctl is-active nftables wg-quick@${WG_INTERFACE} vpn-stack-sync.timer
echo '[FOREIGN] wireguard'
wg show ${WG_INTERFACE}
echo '[FOREIGN] public egress'
curl -4 --fail --silent --show-error https://ifconfig.co
echo
echo '[FOREIGN] nft summary'
nft list ruleset | sed -n '1,160p'
"
else
  print_foreign_commands
fi

cat <<'EOF'

Client-side checks to run manually:
  1. Import out/<deployment>/client/hiddify-cross-platform.json into Hiddify.
  2. Check a RU site such as https://ya.ru and confirm RU IP in the service itself.
  3. Check a global site such as https://ifconfig.co and confirm foreign IP.
  4. Disable the foreign host and verify global traffic fails closed while RU sites still open.
EOF
