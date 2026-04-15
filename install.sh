#!/usr/bin/env bash
set -euo pipefail

ROLE=""
ENV_FILE=""
OUTPUT_DIR=""
ASSETS_DIR=""
RENDER_ONLY=0
ACTION="install"
VPNSTACK_ROOT="/etc/vpn-stack"
VPNSTACK_BACKUP_DIR="${VPNSTACK_ROOT}/backups"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  install.sh --role <ru-gateway|foreign-exit> [--env-file <file>] [--assets-dir <dir>] [--action <install|reinstall|remove|purge|status>] [--render-only --output-dir <dir>]

Examples:
  sudo ./install.sh --role ru-gateway --env-file ./out/my-stack/server/ru.env --assets-dir ./out/my-stack/assets
  sudo ./install.sh --role foreign-exit --env-file ./out/my-stack/server/foreign.env --assets-dir ./out/my-stack/assets
  sudo ./install.sh --role ru-gateway --action remove
  sudo ./install.sh --role foreign-exit --action purge
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
    --action)
      ACTION="${2:-}"
      shift 2
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

if [[ -z "$ROLE" ]]; then
  usage >&2
  exit 1
fi

if [[ "$ROLE" != "ru-gateway" && "$ROLE" != "foreign-exit" ]]; then
  echo "Unsupported role: $ROLE" >&2
  exit 1
fi

if [[ "$ACTION" != "install" && "$ACTION" != "reinstall" && "$ACTION" != "remove" && "$ACTION" != "purge" && "$ACTION" != "status" ]]; then
  echo "Unsupported action: $ACTION" >&2
  exit 1
fi

if [[ -z "$ENV_FILE" && ( "$ACTION" == "remove" || "$ACTION" == "purge" || "$ACTION" == "status" ) && -f "${VPNSTACK_ROOT}/deployment.env" ]]; then
  ENV_FILE="${VPNSTACK_ROOT}/deployment.env"
fi

if [[ ( "$ACTION" == "install" || "$ACTION" == "reinstall" || "$RENDER_ONLY" == "1" ) && -z "$ENV_FILE" ]]; then
  echo "Env file is required for action ${ACTION}." >&2
  exit 1
fi

if [[ -n "$ENV_FILE" && ! -f "$ENV_FILE" ]]; then
  echo "Env file not found: $ENV_FILE" >&2
  exit 1
fi

if [[ -n "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source <(sed 's/\r$//' "$ENV_FILE")
  set +a
fi

if [[ -z "$ASSETS_DIR" ]]; then
  if [[ -n "$ENV_FILE" ]]; then
    ENV_PARENT_DIR="$(cd "$(dirname "$ENV_FILE")" && pwd)"
    if [[ -d "${ENV_PARENT_DIR}/../assets" ]]; then
      ASSETS_DIR="$(cd "${ENV_PARENT_DIR}/../assets" && pwd)"
    fi
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
WG_RU_ADDRESS="${WG_RU_ADDRESS:-10.74.0.1/32}"
WG_FOREIGN_ADDRESS="${WG_FOREIGN_ADDRESS:-10.74.0.2/32}"

RU_DIRECT_DNS_SERVER="${RU_DIRECT_DNS_SERVER:-77.88.8.8}"
RU_DIRECT_DNS_PORT="${RU_DIRECT_DNS_PORT:-53}"
GLOBAL_DOH_SERVER="${GLOBAL_DOH_SERVER:-1.1.1.1}"
GLOBAL_DOH_SERVER_NAME="${GLOBAL_DOH_SERVER_NAME:-cloudflare-dns.com}"
GLOBAL_DOH_PATH="${GLOBAL_DOH_PATH:-/dns-query}"
SUBSCRIPTION_PORT="${SUBSCRIPTION_PORT:-18080}"
SUBSCRIPTION_TOKEN="${SUBSCRIPTION_TOKEN:-}"
RU_FORCE_DIRECT_DOMAIN="${RU_FORCE_DIRECT_DOMAIN:-api.oneme.ru,mtalk.google.com,calls.okcdn.ru,gosuslugi.ru,api.ok.ru,ifconfig.me,ifconfig.co,checkip.amazonaws.com,ipapi.co,ipinfo.io,ident.me,tnedi.me,icanhazip.com,ip.mail.ru,ipv4-internet.yandex.net,ipv6-internet.yandex.net,2ip.ru}"
RU_FORCE_DIRECT_DOMAIN_SUFFIX="${RU_FORCE_DIRECT_DOMAIN_SUFFIX:-.gstatic.com,.gosuslugi.ru,.ipify.org,.ipinfo.io,.ident.me,.tnedi.me,.icanhazip.com}"
RU_FORCE_DIRECT_IP_CIDR="${RU_FORCE_DIRECT_IP_CIDR:-}"

RULESET_DIR="${RULESET_DIR:-/var/lib/vpn-stack/rules}"
RU_GEOSITE_URL="${RU_GEOSITE_URL:-https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-ru.srs}"
RU_GEOIP_URL="${RU_GEOIP_URL:-https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-ru.srs https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-ru.srs}"
FOREIGN_BLOCK_RU="${FOREIGN_BLOCK_RU:-1}"
FOREIGN_RU_IPV4_LIST_URL="${FOREIGN_RU_IPV4_LIST_URL:-https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone https://stat.ripe.net/data/country-resource-list/data.json?resource=ru&v4_format=prefix}"
FOREIGN_RU_IPV6_LIST_URL="${FOREIGN_RU_IPV6_LIST_URL:-https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone https://stat.ripe.net/data/country-resource-list/data.json?resource=ru}"
SINGBOX_CONFIG_PATH="/etc/sing-box/config.json"
WG_CONFIG_PATH="/etc/wireguard/${WG_INTERFACE}.conf"
NFTABLES_PATH="/etc/nftables.conf"
RULE_SYNC_SCRIPT="/usr/local/lib/vpn-stack/sync-state.sh"
SYNC_SERVICE_PATH="/etc/systemd/system/vpn-stack-sync.service"
SYNC_TIMER_PATH="/etc/systemd/system/vpn-stack-sync.timer"
SUBSCRIPTION_SERVICE_PATH="/etc/systemd/system/vpn-stack-subscription.service"
SYSCTL_PATH="/etc/sysctl.d/90-vpn-stack.conf"
SUBSCRIPTION_ROOT="/var/lib/vpn-stack/subscription"
VPNSTACK_ROLE_FILE="${VPNSTACK_ROOT}/role"
VPNSTACK_DEPLOYMENT_FILE="${VPNSTACK_ROOT}/deployment.env"
VPNSTACK_INSTALLED_AT_FILE="${VPNSTACK_ROOT}/installed_at"
VPNSTACK_REMOVED_AT_FILE="${VPNSTACK_ROOT}/removed_at"
VPNSTACK_BASELINE_DIR="${VPNSTACK_BACKUP_DIR}/baseline"
VPNSTACK_SNAPSHOT_DIR="${VPNSTACK_BACKUP_DIR}/snapshots"

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
  require_var SUBSCRIPTION_PORT
  require_var SUBSCRIPTION_TOKEN
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

timestamp_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

current_install_role() {
  if [[ -f "${VPNSTACK_ROLE_FILE}" ]]; then
    tr -d '\r\n' <"${VPNSTACK_ROLE_FILE}"
  fi
}

current_install_deployment() {
  if [[ -f "${VPNSTACK_DEPLOYMENT_FILE}" ]]; then
    grep -E '^DEPLOY_NAME=' "${VPNSTACK_DEPLOYMENT_FILE}" | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//'
  fi
}

is_currently_installed() {
  [[ -f "${VPNSTACK_INSTALLED_AT_FILE}" && -f "${VPNSTACK_ROLE_FILE}" ]]
}

require_managed_install_for_destructive_action() {
  if ! is_currently_installed; then
    echo "vpn-stack metadata not found on this host. Refusing ${ACTION}." >&2
    exit 1
  fi

  local current_role
  current_role="$(current_install_role)"
  if [[ -n "${current_role}" && "${current_role}" != "${ROLE}" ]]; then
    echo "Installed role mismatch: requested ${ROLE}, found ${current_role}." >&2
    exit 1
  fi
}

service_active_flag() {
  local service="$1"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active "${service}" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

service_enabled_flag() {
  local service="$1"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled "${service}" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

write_service_state_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat >"${path}" <<EOF
NFTABLES_ENABLED=$(service_enabled_flag nftables)
NFTABLES_ACTIVE=$(service_active_flag nftables)
WIREGUARD_ENABLED=$(service_enabled_flag "wg-quick@${WG_INTERFACE}")
WIREGUARD_ACTIVE=$(service_active_flag "wg-quick@${WG_INTERFACE}")
SINGBOX_ENABLED=$(service_enabled_flag sing-box)
SINGBOX_ACTIVE=$(service_active_flag sing-box)
SYNC_TIMER_ENABLED=$(service_enabled_flag vpn-stack-sync.timer)
SYNC_TIMER_ACTIVE=$(service_active_flag vpn-stack-sync.timer)
SUBSCRIPTION_ENABLED=$(service_enabled_flag vpn-stack-subscription.service)
SUBSCRIPTION_ACTIVE=$(service_active_flag vpn-stack-subscription.service)
EOF
}

managed_paths() {
  printf '%s\n' \
    "${SINGBOX_CONFIG_PATH}" \
    "${WG_CONFIG_PATH}" \
    "${NFTABLES_PATH}" \
    "${RULE_SYNC_SCRIPT}" \
    "${SYNC_SERVICE_PATH}" \
    "${SYNC_TIMER_PATH}" \
    "${SUBSCRIPTION_SERVICE_PATH}" \
    "${SUBSCRIPTION_ROOT}" \
    "${SYSCTL_PATH}"
}

backup_target_path() {
  local backup_root="$1"
  local original_path="$2"
  printf '%s/%s' "${backup_root}" "${original_path#/}"
}

backup_path_if_present() {
  local backup_root="$1"
  local original_path="$2"
  if [[ -e "${original_path}" ]]; then
    local backup_path
    backup_path="$(backup_target_path "${backup_root}" "${original_path}")"
    mkdir -p "$(dirname "${backup_path}")"
    cp -a "${original_path}" "${backup_path}"
  fi
}

backup_rule_directory_if_present() {
  local backup_root="$1"
  local backup_path
  if [[ -d "${RULESET_DIR}" ]]; then
    backup_path="$(backup_target_path "${backup_root}" "${RULESET_DIR}")"
    mkdir -p "$(dirname "${backup_path}")"
    cp -a "${RULESET_DIR}" "${backup_path}"
  fi
}

create_baseline_backup() {
  rm -rf "${VPNSTACK_BASELINE_DIR}"
  mkdir -p "${VPNSTACK_BASELINE_DIR}"
  write_service_state_file "${VPNSTACK_BASELINE_DIR}/service-state.env"
  while IFS= read -r path; do
    backup_path_if_present "${VPNSTACK_BASELINE_DIR}" "${path}"
  done < <(managed_paths)
  backup_rule_directory_if_present "${VPNSTACK_BASELINE_DIR}"
}

create_revision_snapshot() {
  local snapshot_dir="${VPNSTACK_SNAPSHOT_DIR}/$(timestamp_utc)"
  mkdir -p "${snapshot_dir}"
  write_service_state_file "${snapshot_dir}/service-state.env"
  while IFS= read -r path; do
    backup_path_if_present "${snapshot_dir}" "${path}"
  done < <(managed_paths)
  backup_rule_directory_if_present "${snapshot_dir}"
}

restore_path_from_backup() {
  local backup_root="$1"
  local original_path="$2"
  local backup_path
  backup_path="$(backup_target_path "${backup_root}" "${original_path}")"

  rm -rf "${original_path}"
  if [[ -e "${backup_path}" ]]; then
    mkdir -p "$(dirname "${original_path}")"
    cp -a "${backup_path}" "${original_path}"
  fi
}

apply_service_restore_flags() {
  local service="$1"
  local enabled_flag="$2"
  local active_flag="$3"

  if [[ "${enabled_flag}" == "1" ]]; then
    systemctl enable "${service}" >/dev/null 2>&1 || true
  else
    systemctl disable "${service}" >/dev/null 2>&1 || true
  fi

  if [[ "${active_flag}" == "1" ]]; then
    systemctl restart "${service}" >/dev/null 2>&1 || systemctl start "${service}" >/dev/null 2>&1 || true
  else
    systemctl stop "${service}" >/dev/null 2>&1 || true
  fi
}

restore_service_state() {
  local state_path="$1"
  if [[ ! -f "${state_path}" ]]; then
    return 0
  fi

  # shellcheck disable=SC1090
  source "${state_path}"
  apply_service_restore_flags nftables "${NFTABLES_ENABLED:-0}" "${NFTABLES_ACTIVE:-0}"
  apply_service_restore_flags "wg-quick@${WG_INTERFACE}" "${WIREGUARD_ENABLED:-0}" "${WIREGUARD_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-sync.timer "${SYNC_TIMER_ENABLED:-0}" "${SYNC_TIMER_ACTIVE:-0}"
  apply_service_restore_flags sing-box "${SINGBOX_ENABLED:-0}" "${SINGBOX_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-subscription.service "${SUBSCRIPTION_ENABLED:-0}" "${SUBSCRIPTION_ACTIVE:-0}"
}

stop_managed_services() {
  systemctl stop sing-box >/dev/null 2>&1 || true
  systemctl stop "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
  systemctl stop vpn-stack-sync.service >/dev/null 2>&1 || true
  systemctl stop vpn-stack-sync.timer >/dev/null 2>&1 || true
  systemctl stop vpn-stack-subscription.service >/dev/null 2>&1 || true
  systemctl stop nftables >/dev/null 2>&1 || true
}

disable_managed_services() {
  systemctl disable sing-box >/dev/null 2>&1 || true
  systemctl disable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
  systemctl disable vpn-stack-sync.timer >/dev/null 2>&1 || true
  systemctl disable vpn-stack-subscription.service >/dev/null 2>&1 || true
  systemctl disable nftables >/dev/null 2>&1 || true
}

remove_managed_files() {
  rm -f \
    "${SINGBOX_CONFIG_PATH}" \
    "${WG_CONFIG_PATH}" \
    "${NFTABLES_PATH}" \
    "${RULE_SYNC_SCRIPT}" \
    "${SYNC_SERVICE_PATH}" \
    "${SYNC_TIMER_PATH}" \
    "${SUBSCRIPTION_SERVICE_PATH}" \
    "${SYSCTL_PATH}"
  rm -rf "${SUBSCRIPTION_ROOT}"
  rm -rf "${RULESET_DIR}"
}

record_install_metadata() {
  mkdir -p "${VPNSTACK_ROOT}"
  if [[ -n "${ENV_FILE:-}" ]]; then
    write_file "${VPNSTACK_DEPLOYMENT_FILE}" <"${ENV_FILE}"
    chmod 0600 "${VPNSTACK_DEPLOYMENT_FILE}"
  fi
  printf '%s\n' "${ROLE}" >"${VPNSTACK_ROLE_FILE}"
  date -u +"%Y-%m-%dT%H:%M:%SZ" >"${VPNSTACK_INSTALLED_AT_FILE}"
  rm -f "${VPNSTACK_REMOVED_AT_FILE}"
  chmod 0644 "${VPNSTACK_ROLE_FILE}" "${VPNSTACK_INSTALLED_AT_FILE}"
}

restore_baseline_or_cleanup() {
  stop_managed_services
  disable_managed_services
  remove_managed_files
  systemctl daemon-reload

  if [[ -d "${VPNSTACK_BASELINE_DIR}" ]]; then
    while IFS= read -r path; do
      restore_path_from_backup "${VPNSTACK_BASELINE_DIR}" "${path}"
    done < <(managed_paths)
    restore_path_from_backup "${VPNSTACK_BASELINE_DIR}" "${RULESET_DIR}"
  fi

  sysctl --system >/dev/null 2>&1 || true
  if [[ -d "${VPNSTACK_BASELINE_DIR}" ]]; then
    restore_service_state "${VPNSTACK_BASELINE_DIR}/service-state.env"
  fi

  rm -f "${VPNSTACK_DEPLOYMENT_FILE}" "${VPNSTACK_ROLE_FILE}" "${VPNSTACK_INSTALLED_AT_FILE}"
  date -u +"%Y-%m-%dT%H:%M:%SZ" >"${VPNSTACK_REMOVED_AT_FILE}"
}

purge_managed_state() {
  restore_baseline_or_cleanup
  rm -rf "${VPNSTACK_ROOT}"
  rmdir "/usr/local/lib/vpn-stack" >/dev/null 2>&1 || true
}

print_status() {
  local installed="0"
  local installed_at=""
  local removed_at=""
  local baseline_present="0"
  local snapshots_present="0"
  if is_currently_installed; then
    installed="1"
  fi
  if [[ -f "${VPNSTACK_INSTALLED_AT_FILE}" ]]; then
    installed_at="$(tr -d '\r\n' <"${VPNSTACK_INSTALLED_AT_FILE}")"
  fi
  if [[ -f "${VPNSTACK_REMOVED_AT_FILE}" ]]; then
    removed_at="$(tr -d '\r\n' <"${VPNSTACK_REMOVED_AT_FILE}")"
  fi
  if [[ -d "${VPNSTACK_BASELINE_DIR}" ]]; then
    baseline_present="1"
  fi
  if [[ -d "${VPNSTACK_SNAPSHOT_DIR}" ]]; then
    snapshots_present="$(find "${VPNSTACK_SNAPSHOT_DIR}" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d '[:space:]')"
  fi

  echo "role=${ROLE}"
  echo "installed=${installed}"
  echo "current_role=$(current_install_role)"
  echo "deployment=$(current_install_deployment)"
  echo "installed_at=${installed_at}"
  echo "removed_at=${removed_at}"
  echo "baseline_present=${baseline_present}"
  echo "snapshots_present=${snapshots_present}"
  echo "nftables_active=$(service_active_flag nftables)"
  echo "wireguard_active=$(service_active_flag "wg-quick@${WG_INTERFACE}")"
  echo "sync_timer_active=$(service_active_flag vpn-stack-sync.timer)"
  echo "sing_box_active=$(service_active_flag sing-box)"
  echo "subscription_active=$(service_active_flag vpn-stack-subscription.service)"
}

python_candidate_works() {
  local candidate="$1"
  [[ -n "${candidate}" ]] || return 1
  "${candidate}" -c "import sys; raise SystemExit(0)" >/dev/null 2>&1
}

python_executable() {
  local candidate=""

  if [[ -n "${PYTHON_BIN:-}" ]] && python_candidate_works "${PYTHON_BIN}"; then
    printf '%s\n' "${PYTHON_BIN}"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    candidate="$(command -v python3)"
    if python_candidate_works "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  fi

  if [[ -x "${SCRIPT_DIR}/.runtime/python/windows/python.exe" ]] && python_candidate_works "${SCRIPT_DIR}/.runtime/python/windows/python.exe"; then
    printf '%s\n' "${SCRIPT_DIR}/.runtime/python/windows/python.exe"
    return 0
  fi

  if command -v python >/dev/null 2>&1; then
    candidate="$(command -v python)"
    if python_candidate_works "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  fi

  return 1
}

render_role_with_python() {
  local output_dir="$1"
  local python_bin=""
  local args=()
  if [[ ! -f "${SCRIPT_DIR}/vpn_installer/install_support.py" ]]; then
    echo "Python renderer package not found next to install.sh: ${SCRIPT_DIR}/vpn_installer" >&2
    return 1
  fi
  python_bin="$(python_executable)" || {
    echo "Python is required to render role artifacts." >&2
    return 1
  }
  mkdir -p "${output_dir}"
  if [[ "$ROLE" == "foreign-exit" && -n "${WAN_INTERFACE:-}" ]]; then
    args+=(--set "WAN_INTERFACE=${WAN_INTERFACE}")
  fi
  "${python_bin}" -c 'import sys; sys.path.insert(0, sys.argv[1]); from vpn_installer.install_support import main; raise SystemExit(main(sys.argv[2:]))' \
    "${SCRIPT_DIR}" \
    render-role \
    --role "${ROLE}" \
    --env-file "${ENV_FILE}" \
    --output-dir "${output_dir}" \
    "${args[@]}"
}

find_rendered_role_dir() {
  local env_dir=""
  local candidate=""
  if [[ -n "${ENV_FILE:-}" ]]; then
    env_dir="$(cd "$(dirname "${ENV_FILE}")" && pwd)"
  fi
  for candidate in "${SCRIPT_DIR}/rendered" "${env_dir}/rendered"; do
    if [[ -n "${candidate}" && -d "${candidate}" && -f "${candidate}/sing-box.json" ]]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

prepare_role_artifacts() {
  local rendered_dir=""
  local temp_dir=""
  if rendered_dir="$(find_rendered_role_dir)"; then
    printf '%s' "${rendered_dir}"
    return 0
  fi
  temp_dir="$(mktemp -d)"
  if ! render_role_with_python "${temp_dir}"; then
    rm -rf "${temp_dir}"
    return 1
  fi
  printf '%s' "${temp_dir}"
}

copy_role_artifacts() {
  local source_dir="$1"
  copy_if_present "${source_dir}/sing-box.json" "${SINGBOX_CONFIG_PATH}" || { echo "Missing sing-box.json in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/${WG_INTERFACE}.conf" "${WG_CONFIG_PATH}" || { echo "Missing ${WG_INTERFACE}.conf in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/nftables.conf" "${NFTABLES_PATH}" || { echo "Missing nftables.conf in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/sync-state.sh" "${RULE_SYNC_SCRIPT}" || { echo "Missing sync-state.sh in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/vpn-stack-sync.service" "${SYNC_SERVICE_PATH}" || { echo "Missing vpn-stack-sync.service in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/vpn-stack-sync.timer" "${SYNC_TIMER_PATH}" || { echo "Missing vpn-stack-sync.timer in ${source_dir}" >&2; exit 1; }
  if [[ "$ROLE" == "ru-gateway" ]]; then
    copy_if_present "${source_dir}/vpn-stack-subscription.service" "${SUBSCRIPTION_SERVICE_PATH}" || { echo "Missing vpn-stack-subscription.service in ${source_dir}" >&2; exit 1; }
    if [[ ! -d "${source_dir}/subscription" ]]; then
      echo "Missing subscription directory in ${source_dir}" >&2
      exit 1
    fi
    rm -rf "${SUBSCRIPTION_ROOT}"
    mkdir -p "$(dirname "${SUBSCRIPTION_ROOT}")"
    cp -a "${source_dir}/subscription" "${SUBSCRIPTION_ROOT}"
  fi
  chmod 0755 "${RULE_SYNC_SCRIPT}"
}

write_preview_files() {
  local base="$1"
  render_role_with_python "${base}"
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

  [[ -s "${RULESET_DIR}/ru-ipv4.zone" && -s "${RULESET_DIR}/ru-ipv6.zone" ]]
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

if [[ "$ACTION" == "install" || "$ACTION" == "reinstall" || "$RENDER_ONLY" == "1" ]]; then
  if [[ "$ROLE" == "ru-gateway" ]]; then
    require_ru_env
  else
    require_foreign_env
  fi
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

if [[ "$ACTION" == "status" ]]; then
  print_status
  exit 0
fi

if [[ "$ACTION" == "remove" ]]; then
  require_managed_install_for_destructive_action
  restore_baseline_or_cleanup
  echo "Completed ${ROLE} removal."
  exit 0
fi

if [[ "$ACTION" == "purge" ]]; then
  require_managed_install_for_destructive_action
  purge_managed_state
  echo "Completed ${ROLE} purge."
  exit 0
fi

mkdir -p "${VPNSTACK_ROOT}" "${VPNSTACK_BACKUP_DIR}" "${VPNSTACK_SNAPSHOT_DIR}"
if ! is_currently_installed; then
  create_baseline_backup
elif [[ ! -d "${VPNSTACK_BASELINE_DIR}" ]]; then
  echo "Baseline backup missing, capturing current host state before ${ACTION}." >&2
  create_baseline_backup
else
  create_revision_snapshot
fi

if [[ "$ACTION" == "reinstall" ]]; then
  stop_managed_services
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg \
  nftables \
  python3 \
  unattended-upgrades \
  wireguard \
  wireguard-tools

if ! command -v sing-box >/dev/null 2>&1; then
  curl -fsSL https://sing-box.sagernet.org/installation/tools/install.sh | bash
fi

mkdir -p "${VPNSTACK_ROOT}" /etc/sing-box /etc/wireguard "${RULESET_DIR}" "${SUBSCRIPTION_ROOT}" /usr/local/lib/vpn-stack /etc/systemd/system

if [[ "$ROLE" == "foreign-exit" ]]; then
  WAN_INTERFACE="${WAN_INTERFACE:-$(ip route show default | awk '/default/ {print $5; exit}')}"
  if [[ -z "${WAN_INTERFACE:-}" ]]; then
    echo "Unable to detect WAN interface. Set WAN_INTERFACE in the env file." >&2
    exit 1
  fi
fi

ROLE_ARTIFACTS_DIR="$(prepare_role_artifacts)"
trap 'if [[ -n "${ROLE_ARTIFACTS_DIR:-}" && "${ROLE_ARTIFACTS_DIR}" == /tmp/* ]]; then rm -rf "${ROLE_ARTIFACTS_DIR}"; fi' EXIT
copy_role_artifacts "${ROLE_ARTIFACTS_DIR}"

if [[ "$ROLE" == "ru-gateway" ]]; then
  cat >"${SYSCTL_PATH}" <<EOF
net.ipv4.conf.all.src_valid_mark=1
EOF
else
  cat >"${SYSCTL_PATH}" <<EOF
net.core.default_qdisc=fq_codel
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
fi

stage_preseed_assets
record_install_metadata

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
systemctl restart vpn-stack-sync.timer
if ! systemctl start vpn-stack-sync.service; then
  if ! have_bootstrap_assets; then
    echo "vpn-stack-sync.service failed and no bootstrap assets are present." >&2
    exit 1
  fi
fi

if [[ "$ROLE" == "ru-gateway" ]]; then
  systemctl enable sing-box
  systemctl restart sing-box
  systemctl enable vpn-stack-subscription.service
  systemctl restart vpn-stack-subscription.service
fi

chmod 0600 "${SINGBOX_CONFIG_PATH}" "${WG_CONFIG_PATH}"

systemctl enable unattended-upgrades || true

echo "Completed ${ROLE} installation for ${DEPLOY_NAME}."
