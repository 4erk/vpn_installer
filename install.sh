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

normalize_env_with_python() {
  local candidate=""
  local python_bin=""
  if [[ "$ACTION" != "install" && "$ACTION" != "reinstall" && "$RENDER_ONLY" != "1" ]]; then
    return 0
  fi
  for candidate in "${PYTHON_BIN:-}" python3 python "${SCRIPT_DIR}/.runtime/python/windows/python.exe"; do
    [[ -n "${candidate}" ]] || continue
    if "${candidate}" -c 'import sys; assert sys.version_info >= (3, 9)' >/dev/null 2>&1; then
      python_bin="${candidate}"
      break
    fi
  done
  [[ -n "${python_bin}" ]] || { echo "Python 3.9+ is required to normalize deployment env." >&2; exit 1; }
  [[ -f "${SCRIPT_DIR}/vpn_installer/install_support.py" ]] || { echo "Python renderer package not found next to install.sh." >&2; exit 1; }
  NORMALIZED_ENV_FILE="$(mktemp)"
  "${python_bin}" -c 'import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); from vpn_installer.config import render_env_text; from vpn_installer.install_support import load_runtime_env; print(render_env_text(load_runtime_env(Path(sys.argv[2]))), end="")' "${SCRIPT_DIR}" "${ENV_FILE}" >"${NORMALIZED_ENV_FILE}"
  set -a
  # shellcheck disable=SC1090
  source "${NORMALIZED_ENV_FILE}"
  set +a
}

normalize_env_with_python

APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-900}"
APT_LOCK_RETRY_SECONDS="${APT_LOCK_RETRY_SECONDS:-5}"
SINGBOX_CONFIG_PATH="/etc/sing-box/config.json"
SINGBOX_BASE_CONFIG_PATH="${VPNSTACK_ROOT}/sing-box.base.json"
SINGBOX_REQUIRED_VERSION="1.13.12"
XRAY_CONFIG_PATH="/etc/xray/config.json"
XRAY_SERVICE_PATH="/etc/systemd/system/vpn-stack-xray.service"
XRAY_REQUIRED_VERSION="${XRAY_REQUIRED_VERSION:-26.3.27}"
XRAY_LINUX_AMD64_SHA256="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
WG_CONFIG_PATH="/etc/wireguard/${WG_INTERFACE:-wg0}.conf"
NFTABLES_PATH="/etc/nftables.conf"
SSHD_CONFIG_PATH="/etc/ssh/sshd_config.d/90-vpn-stack.conf"
AGENT_SCRIPT_PATH="/usr/local/lib/vpn-stack/vpn-stack-agent.py"
AGENT_LOG_CLASSIFIER_PATH="/usr/local/lib/vpn-stack/log_classifier.py"
AGENT_TRANSPORT_POLICY_PATH="/usr/local/lib/vpn-stack/interserver_transport.py"
ADMIN_WEB_SCRIPT_PATH="/usr/local/lib/vpn-stack/admin_web.py"
ADMIN_APPLY_SCRIPT_PATH="/usr/local/lib/vpn-stack/admin_apply.py"
HEALTH_SERVICE_PATH="/etc/systemd/system/vpn-stack-health.service"
HEALTH_TIMER_PATH="/etc/systemd/system/vpn-stack-health.timer"
TRANSPORT_SERVICE_PATH="/etc/systemd/system/vpn-stack-transport.service"
LEGACY_SYNC_SCRIPT_PATH="/usr/local/lib/vpn-stack/sync-state.sh"
LEGACY_HEALTH_SCRIPT_PATH="/usr/local/lib/vpn-stack/health-check.sh"
LEGACY_GUARD_SCRIPT_PATH="/usr/local/lib/vpn-stack/guard.sh"
LEGACY_SYNC_SERVICE_PATH="/etc/systemd/system/vpn-stack-sync.service"
LEGACY_SYNC_TIMER_PATH="/etc/systemd/system/vpn-stack-sync.timer"
LEGACY_GUARD_SERVICE_PATH="/etc/systemd/system/vpn-stack-guard.service"
LEGACY_GUARD_TIMER_PATH="/etc/systemd/system/vpn-stack-guard.timer"
ADMIN_WEB_SERVICE_PATH="/etc/systemd/system/vpn-stack-admin.service"
SUBSCRIPTION_SERVICE_PATH="/etc/systemd/system/vpn-stack-subscription.service"
SYSCTL_PATH="/etc/sysctl.d/90-vpn-stack.conf"
MODULES_LOAD_PATH="/etc/modules-load.d/90-vpn-stack.conf"
JOURNALD_DROPIN_PATH="/etc/systemd/journald.conf.d/90-vpn-stack.conf"
APT_PERIODIC_DROPIN_PATH="/etc/apt/apt.conf.d/90-vpn-stack-unattended"
RESOLVED_DROPIN_PATH="/etc/systemd/resolved.conf.d/90-vpn-stack.conf"
RESOLV_CONF_PATH="/etc/resolv.conf"
RESOLVED_STUB_PATH="/run/systemd/resolve/stub-resolv.conf"
SUBSCRIPTION_ROOT="/var/lib/vpn-stack/subscription"
LEGACY_ADAPTIVE_ROUTING_RULES_PATH="/var/lib/vpn-stack/adaptive-routing-rules.json"
LEGACY_DATAPLANE_CACHE_PATH="/var/lib/vpn-stack/dataplane-cache.env"
HEALTH_STATE_PATH="/var/lib/vpn-stack/health-state.json"
TRANSPORT_STATE_PATH="/var/lib/vpn-stack/transport-state.json"
VPNSTACK_ROLE_FILE="${VPNSTACK_ROOT}/role"
VPNSTACK_DEPLOYMENT_FILE="${VPNSTACK_ROOT}/deployment.env"
VPNSTACK_INSTALLED_AT_FILE="${VPNSTACK_ROOT}/installed_at"
VPNSTACK_REMOVED_AT_FILE="${VPNSTACK_ROOT}/removed_at"
VPNSTACK_RENDER_MANIFEST_FILE="${VPNSTACK_ROOT}/render-manifest.json"
VPNSTACK_ADMIN_AUTH_FILE="${VPNSTACK_ROOT}/admin-auth.json"
VPNSTACK_BASELINE_DIR="${VPNSTACK_BACKUP_DIR}/baseline"
VPNSTACK_SNAPSHOT_DIR="${VPNSTACK_BACKUP_DIR}/snapshots"
VPNSTACK_RELEASES_DIR="${VPNSTACK_ROOT}/releases"
VPNSTACK_CURRENT_RELEASE="${VPNSTACK_ROOT}/current"
VPNSTACK_PREVIOUS_RELEASE="${VPNSTACK_ROOT}/previous"
VPNSTACK_ACCEPTANCE_FILE="${VPNSTACK_ROOT}/acceptance.json"
VPNSTACK_FAILED_ACCEPTANCE_FILE="${VPNSTACK_ROOT}/last-failed-acceptance.json"
VPNSTACK_REVISION_SNAPSHOT_RETENTION=10
CURRENT_ROLLBACK_DIR=""
INSTALL_MUTATION_STARTED=0
PREPARED_ARTIFACTS_DIR=""
STAGED_RELEASE_DIR=""
PUBLISHED_RELEASE_DIR=""
NORMALIZED_ENV_FILE="${NORMALIZED_ENV_FILE:-}"

WG_RU_ADDRESS_HOST="${WG_RU_ADDRESS:-}"
WG_RU_ADDRESS_HOST="${WG_RU_ADDRESS_HOST%%/*}"
WG_FOREIGN_ADDRESS_HOST="${WG_FOREIGN_ADDRESS:-}"
WG_FOREIGN_ADDRESS_HOST="${WG_FOREIGN_ADDRESS_HOST%%/*}"
WG_RU_ADDRESS_V6_HOST="${WG_RU_ADDRESS_V6:-}"
WG_RU_ADDRESS_V6_HOST="${WG_RU_ADDRESS_V6_HOST%%/*}"
WG_FOREIGN_ADDRESS_V6_HOST="${WG_FOREIGN_ADDRESS_V6:-}"
WG_FOREIGN_ADDRESS_V6_HOST="${WG_FOREIGN_ADDRESS_V6_HOST%%/*}"

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
  require_var WG_RU_ADDRESS_V6
  require_var WG_FOREIGN_ADDRESS_V6
  require_var WG_IPV6_PREFIX
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
  local tmp
  mkdir -p "$(dirname "$path")"
  tmp="$(mktemp "$(dirname "$path")/.${path##*/}.XXXXXX")"
  cat >"${tmp}"
  mv -f "${tmp}" "${path}"
}

copy_if_present() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    local tmp
    mkdir -p "$(dirname "$dst")"
    tmp="$(mktemp "$(dirname "$dst")/.${dst##*/}.XXXXXX")"
    cp "$src" "$tmp"
    chmod --reference="$src" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$dst"
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
XRAY_ENABLED=$(service_enabled_flag vpn-stack-xray.service)
XRAY_ACTIVE=$(service_active_flag vpn-stack-xray.service)
ADMIN_WEB_ENABLED_STATE=$(service_enabled_flag vpn-stack-admin.service)
ADMIN_WEB_ACTIVE_STATE=$(service_active_flag vpn-stack-admin.service)
SYNC_TIMER_ENABLED=$(service_enabled_flag vpn-stack-sync.timer)
SYNC_TIMER_ACTIVE=$(service_active_flag vpn-stack-sync.timer)
HEALTH_TIMER_ENABLED=$(service_enabled_flag vpn-stack-health.timer)
HEALTH_TIMER_ACTIVE=$(service_active_flag vpn-stack-health.timer)
HEALTH_SERVICE_ENABLED=$(service_enabled_flag vpn-stack-health.service)
HEALTH_SERVICE_ACTIVE=$(service_active_flag vpn-stack-health.service)
TRANSPORT_SERVICE_ENABLED=$(service_enabled_flag vpn-stack-transport.service)
TRANSPORT_SERVICE_ACTIVE=$(service_active_flag vpn-stack-transport.service)
GUARD_TIMER_ENABLED=$(service_enabled_flag vpn-stack-guard.timer)
GUARD_TIMER_ACTIVE=$(service_active_flag vpn-stack-guard.timer)
SYNC_SERVICE_ENABLED=$(service_enabled_flag vpn-stack-sync.service)
SYNC_SERVICE_ACTIVE=$(service_active_flag vpn-stack-sync.service)
GUARD_SERVICE_ENABLED=$(service_enabled_flag vpn-stack-guard.service)
GUARD_SERVICE_ACTIVE=$(service_active_flag vpn-stack-guard.service)
SUBSCRIPTION_ENABLED=$(service_enabled_flag vpn-stack-subscription.service)
SUBSCRIPTION_ACTIVE=$(service_active_flag vpn-stack-subscription.service)
LEGACY_XRAY_VPNSTACK_ENABLED=$(service_enabled_flag xray-vpnstack.service)
LEGACY_XRAY_VPNSTACK_ACTIVE=$(service_active_flag xray-vpnstack.service)
LEGACY_XRAY_ENABLED=$(service_enabled_flag xray.service)
LEGACY_XRAY_ACTIVE=$(service_active_flag xray.service)
LEGACY_V2RAY_ENABLED=$(service_enabled_flag v2ray.service)
LEGACY_V2RAY_ACTIVE=$(service_active_flag v2ray.service)
APT_DAILY_TIMER_ENABLED=$(service_enabled_flag apt-daily.timer)
APT_DAILY_TIMER_ACTIVE=$(service_active_flag apt-daily.timer)
APT_UPGRADE_TIMER_ENABLED=$(service_enabled_flag apt-daily-upgrade.timer)
APT_UPGRADE_TIMER_ACTIVE=$(service_active_flag apt-daily-upgrade.timer)
UNATTENDED_UPGRADES_ENABLED=$(service_enabled_flag unattended-upgrades.service)
UNATTENDED_UPGRADES_ACTIVE=$(service_active_flag unattended-upgrades.service)
SYSTEMD_RESOLVED_ENABLED=$(service_enabled_flag systemd-resolved.service)
SYSTEMD_RESOLVED_ACTIVE=$(service_active_flag systemd-resolved.service)
SSH_SERVICE_ENABLED=$(service_enabled_flag ssh.service)
SSH_SERVICE_ACTIVE=$(service_active_flag ssh.service)
SSH_SOCKET_ENABLED=$(service_enabled_flag ssh.socket)
SSH_SOCKET_ACTIVE=$(service_active_flag ssh.socket)
EOF
}

managed_paths() {
  printf '%s\n' \
    "${SINGBOX_CONFIG_PATH}" \
    "${SINGBOX_BASE_CONFIG_PATH}" \
    "${XRAY_CONFIG_PATH}" \
    "${XRAY_SERVICE_PATH}" \
    "${WG_CONFIG_PATH}" \
    "${NFTABLES_PATH}" \
    "${SSHD_CONFIG_PATH}" \
    "${AGENT_SCRIPT_PATH}" \
    "${AGENT_LOG_CLASSIFIER_PATH}" \
    "${AGENT_TRANSPORT_POLICY_PATH}" \
    "${ADMIN_WEB_SCRIPT_PATH}" \
    "${ADMIN_APPLY_SCRIPT_PATH}" \
    "${HEALTH_SERVICE_PATH}" \
    "${HEALTH_TIMER_PATH}" \
    "${TRANSPORT_SERVICE_PATH}" \
    "${ADMIN_WEB_SERVICE_PATH}" \
    "${SUBSCRIPTION_SERVICE_PATH}" \
    "${SUBSCRIPTION_ROOT}" \
    "${SYSCTL_PATH}" \
    "${MODULES_LOAD_PATH}" \
    "${JOURNALD_DROPIN_PATH}" \
    "${APT_PERIODIC_DROPIN_PATH}" \
    "${RESOLVED_DROPIN_PATH}" \
    "${RESOLV_CONF_PATH}" \
    "${LEGACY_ADAPTIVE_ROUTING_RULES_PATH}" \
    "${LEGACY_DATAPLANE_CACHE_PATH}" \
    "${HEALTH_STATE_PATH}" \
    "${TRANSPORT_STATE_PATH}" \
    "${VPNSTACK_DEPLOYMENT_FILE}" \
    "${VPNSTACK_ROLE_FILE}" \
    "${VPNSTACK_INSTALLED_AT_FILE}" \
    "${VPNSTACK_REMOVED_AT_FILE}" \
    "${VPNSTACK_RENDER_MANIFEST_FILE}" \
    "${VPNSTACK_ADMIN_AUTH_FILE}" \
    "${VPNSTACK_CURRENT_RELEASE}" \
    "${VPNSTACK_PREVIOUS_RELEASE}" \
    "${VPNSTACK_ACCEPTANCE_FILE}"
}

legacy_paths() {
  printf '%s\n' \
    "${LEGACY_SYNC_SCRIPT_PATH}" \
    "${LEGACY_HEALTH_SCRIPT_PATH}" \
    "${LEGACY_GUARD_SCRIPT_PATH}" \
    "${LEGACY_SYNC_SERVICE_PATH}" \
    "${LEGACY_SYNC_TIMER_PATH}" \
    "${LEGACY_GUARD_SERVICE_PATH}" \
    "${LEGACY_GUARD_TIMER_PATH}"
}

rollback_paths() {
  managed_paths
  legacy_paths
}

backup_target_path() {
  local backup_root="$1"
  local original_path="$2"
  printf '%s/%s' "${backup_root}" "${original_path#/}"
}

backup_path_if_present() {
  local backup_root="$1"
  local original_path="$2"
  if [[ -e "${original_path}" || -L "${original_path}" ]]; then
    local backup_path
    backup_path="$(backup_target_path "${backup_root}" "${original_path}")"
    mkdir -p "$(dirname "${backup_path}")"
    cp -a "${original_path}" "${backup_path}"
  fi
}

extend_baseline_contract() {
  local path=""
  local backup_path=""
  for path in "${RESOLVED_DROPIN_PATH}" "${RESOLV_CONF_PATH}" "${AGENT_TRANSPORT_POLICY_PATH}" "${TRANSPORT_SERVICE_PATH}" "${TRANSPORT_STATE_PATH}"; do
    backup_path="$(backup_target_path "${VPNSTACK_BASELINE_DIR}" "${path}")"
    if [[ ! -e "${backup_path}" && ! -L "${backup_path}" ]]; then
      backup_path_if_present "${VPNSTACK_BASELINE_DIR}" "${path}"
    fi
  done
  if ! grep -q '^SYSTEMD_RESOLVED_ENABLED=' "${VPNSTACK_BASELINE_DIR}/service-state.env" 2>/dev/null; then
    cat >>"${VPNSTACK_BASELINE_DIR}/service-state.env" <<EOF
SYSTEMD_RESOLVED_ENABLED=$(service_enabled_flag systemd-resolved.service)
SYSTEMD_RESOLVED_ACTIVE=$(service_active_flag systemd-resolved.service)
EOF
  fi
  if ! grep -q '^TRANSPORT_SERVICE_ENABLED=' "${VPNSTACK_BASELINE_DIR}/service-state.env" 2>/dev/null; then
    cat >>"${VPNSTACK_BASELINE_DIR}/service-state.env" <<EOF
TRANSPORT_SERVICE_ENABLED=$(service_enabled_flag vpn-stack-transport.service)
TRANSPORT_SERVICE_ACTIVE=$(service_active_flag vpn-stack-transport.service)
EOF
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
  CURRENT_ROLLBACK_DIR="${VPNSTACK_BASELINE_DIR}"
  write_service_state_file "${VPNSTACK_BASELINE_DIR}/service-state.env"
  while IFS= read -r path; do
    backup_path_if_present "${VPNSTACK_BASELINE_DIR}" "${path}"
  done < <(rollback_paths)
  backup_rule_directory_if_present "${VPNSTACK_BASELINE_DIR}"
}

prune_revision_snapshots() {
  local keep="${1:-${VPNSTACK_REVISION_SNAPSHOT_RETENTION}}"
  local index=0
  local entry=""
  local snapshot=""
  local snapshots=()
  [[ -d "${VPNSTACK_SNAPSHOT_DIR}" ]] || return 0
  while IFS= read -r -d '' entry; do
    snapshots+=("${entry#* }")
  done < <(find "${VPNSTACK_SNAPSHOT_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\0' | sort -z -nr)
  for ((index = keep; index < ${#snapshots[@]}; index++)); do
    snapshot="${snapshots[index]}"
    [[ "${snapshot}" == "${VPNSTACK_SNAPSHOT_DIR}/"* ]] && rm -rf -- "${snapshot}"
  done
}

create_revision_snapshot() {
  local snapshot_dir="${VPNSTACK_SNAPSHOT_DIR}/$(timestamp_utc)-$$"
  prune_revision_snapshots "$((VPNSTACK_REVISION_SNAPSHOT_RETENTION - 1))"
  mkdir -p "${snapshot_dir}"
  CURRENT_ROLLBACK_DIR="${snapshot_dir}"
  write_service_state_file "${snapshot_dir}/service-state.env"
  while IFS= read -r path; do
    backup_path_if_present "${snapshot_dir}" "${path}"
  done < <(rollback_paths)
  backup_rule_directory_if_present "${snapshot_dir}"
}

restore_path_from_backup() {
  local backup_root="$1"
  local original_path="$2"
  local backup_path
  backup_path="$(backup_target_path "${backup_root}" "${original_path}")"

  rm -rf "${original_path}"
  if [[ -e "${backup_path}" || -L "${backup_path}" ]]; then
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
  apply_service_restore_flags vpn-stack-health.timer "${HEALTH_TIMER_ENABLED:-0}" "${HEALTH_TIMER_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-guard.timer "${GUARD_TIMER_ENABLED:-0}" "${GUARD_TIMER_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-sync.service "${SYNC_SERVICE_ENABLED:-0}" "${SYNC_SERVICE_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-health.service "${HEALTH_SERVICE_ENABLED:-0}" "${HEALTH_SERVICE_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-transport.service "${TRANSPORT_SERVICE_ENABLED:-0}" "${TRANSPORT_SERVICE_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-guard.service "${GUARD_SERVICE_ENABLED:-0}" "${GUARD_SERVICE_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-subscription.service "${SUBSCRIPTION_ENABLED:-0}" "${SUBSCRIPTION_ACTIVE:-0}"
  apply_service_restore_flags sing-box "${SINGBOX_ENABLED:-0}" "${SINGBOX_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-xray.service "${XRAY_ENABLED:-0}" "${XRAY_ACTIVE:-0}"
  apply_service_restore_flags vpn-stack-admin.service "${ADMIN_WEB_ENABLED_STATE:-0}" "${ADMIN_WEB_ACTIVE_STATE:-0}"
  apply_service_restore_flags xray-vpnstack.service "${LEGACY_XRAY_VPNSTACK_ENABLED:-0}" "${LEGACY_XRAY_VPNSTACK_ACTIVE:-0}"
  apply_service_restore_flags xray.service "${LEGACY_XRAY_ENABLED:-0}" "${LEGACY_XRAY_ACTIVE:-0}"
  apply_service_restore_flags v2ray.service "${LEGACY_V2RAY_ENABLED:-0}" "${LEGACY_V2RAY_ACTIVE:-0}"
  apply_service_restore_flags apt-daily.timer "${APT_DAILY_TIMER_ENABLED:-0}" "${APT_DAILY_TIMER_ACTIVE:-0}"
  apply_service_restore_flags apt-daily-upgrade.timer "${APT_UPGRADE_TIMER_ENABLED:-0}" "${APT_UPGRADE_TIMER_ACTIVE:-0}"
  apply_service_restore_flags unattended-upgrades.service "${UNATTENDED_UPGRADES_ENABLED:-0}" "${UNATTENDED_UPGRADES_ACTIVE:-0}"
  apply_service_restore_flags systemd-resolved.service "${SYSTEMD_RESOLVED_ENABLED:-0}" "${SYSTEMD_RESOLVED_ACTIVE:-0}"
  apply_service_restore_flags ssh.service "${SSH_SERVICE_ENABLED:-0}" "${SSH_SERVICE_ACTIVE:-0}"
  apply_service_restore_flags ssh.socket "${SSH_SOCKET_ENABLED:-0}" "${SSH_SOCKET_ACTIVE:-0}"
}

cleanup_role_artifacts() {
  if [[ -n "${PREPARED_ARTIFACTS_DIR:-}" && "${PREPARED_ARTIFACTS_DIR}" == /tmp/* ]]; then
    rm -rf "${PREPARED_ARTIFACTS_DIR}"
  fi
  if [[ -n "${ROLE_ARTIFACTS_DIR:-}" && "${ROLE_ARTIFACTS_DIR}" == /tmp/* ]]; then
    rm -rf "${ROLE_ARTIFACTS_DIR}"
  fi
  if [[ -n "${STAGED_RELEASE_DIR:-}" && "${STAGED_RELEASE_DIR}" == "${VPNSTACK_RELEASES_DIR}/.staging-"* ]]; then
    rm -rf "${STAGED_RELEASE_DIR}"
  fi
  rm -f "${NORMALIZED_ENV_FILE:-}"
}

restore_install_state_on_error() {
  if [[ "${INSTALL_MUTATION_STARTED:-0}" != "1" ]]; then
    return 0
  fi

  if [[ -z "${CURRENT_ROLLBACK_DIR:-}" || ! -d "${CURRENT_ROLLBACK_DIR}" ]]; then
    echo "Install failed after managed services were stopped; no rollback snapshot is available." >&2
    return 0
  fi

  echo "Install failed after applying changes started; restoring previous files and services." >&2
  while IFS= read -r path; do
    restore_path_from_backup "${CURRENT_ROLLBACK_DIR}" "${path}"
  done < <(rollback_paths)
  restore_path_from_backup "${CURRENT_ROLLBACK_DIR}" "${RULESET_DIR}"
  sysctl --system >/dev/null 2>&1 || true
  restore_service_state "${CURRENT_ROLLBACK_DIR}/service-state.env"
}

install_exit_trap() {
  local exit_code="$1"
  if [[ "${exit_code}" -ne 0 ]]; then
    restore_install_state_on_error || true
  fi
  cleanup_role_artifacts
}

stop_managed_services() {
  systemctl stop vpn-stack-transport.service >/dev/null 2>&1 || true
  systemctl stop sing-box >/dev/null 2>&1 || true
  systemctl stop vpn-stack-xray.service >/dev/null 2>&1 || true
  systemctl stop "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
  systemctl stop vpn-stack-health.service >/dev/null 2>&1 || true
  systemctl stop vpn-stack-health.timer >/dev/null 2>&1 || true
  systemctl stop vpn-stack-sync.service vpn-stack-sync.timer vpn-stack-guard.service vpn-stack-guard.timer >/dev/null 2>&1 || true
  systemctl stop vpn-stack-admin.service >/dev/null 2>&1 || true
  systemctl stop vpn-stack-subscription.service >/dev/null 2>&1 || true
  systemctl stop nftables >/dev/null 2>&1 || true
}

cleanup_wireguard_policy_routes() {
  if ! command -v ip >/dev/null 2>&1; then
    return 0
  fi

  ip -4 rule del fwmark "${APP_ROUTE_MARK}" table "${WG_ROUTE_TABLE}" priority 10000 >/dev/null 2>&1 || true
  ip -6 rule del fwmark "${APP_ROUTE_MARK}" table "${WG_ROUTE_TABLE}" priority 10000 >/dev/null 2>&1 || true
  ip -4 route del default dev "${WG_INTERFACE}" table "${WG_ROUTE_TABLE}" >/dev/null 2>&1 || true
  ip -6 route del default dev "${WG_INTERFACE}" table "${WG_ROUTE_TABLE}" >/dev/null 2>&1 || true
}

cleanup_stale_wireguard_interface() {
  if ! command -v ip >/dev/null 2>&1; then
    return 0
  fi
  if systemctl is-active "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1; then
    return 0
  fi

  cleanup_wireguard_policy_routes
  if ip link show "${WG_INTERFACE}" >/dev/null 2>&1; then
    echo "Removing stale WireGuard interface ${WG_INTERFACE} before start." >&2
    ip link delete dev "${WG_INTERFACE}" >/dev/null 2>&1 || true
  fi
}

restart_wireguard_service() {
  systemctl stop "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
  cleanup_stale_wireguard_interface
  systemctl reset-failed "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
  systemctl enable "wg-quick@${WG_INTERFACE}"
  systemctl start "wg-quick@${WG_INTERFACE}"
}

disable_legacy_proxy_services() {
  local legacy_units=(xray-vpnstack.service xray.service v2ray.service)
  local found="0"
  local unit
  for unit in "${legacy_units[@]}"; do
    if systemctl list-unit-files "${unit}" --no-legend 2>/dev/null | grep -q . || systemctl status "${unit}" >/dev/null 2>&1; then
      found="1"
    fi
  done

  if [[ "${found}" == "1" ]]; then
    echo "Disabling legacy Xray/V2Ray services; vpn-stack owns this host." >&2
    for unit in "${legacy_units[@]}"; do
      systemctl disable --now "${unit}" >/dev/null 2>&1 || true
      systemctl reset-failed "${unit}" >/dev/null 2>&1 || true
    done
  fi

}

dpkg_lock_holders() {
  if ! command -v fuser >/dev/null 2>&1; then
    return 0
  fi

  local locks=(
    /var/lib/dpkg/lock-frontend
    /var/lib/dpkg/lock
    /var/cache/apt/archives/lock
    /var/lib/apt/lists/lock
  )
  fuser "${locks[@]}" 2>/dev/null || true
}

wait_for_dpkg_locks() {
  local deadline=$((SECONDS + APT_LOCK_TIMEOUT_SECONDS))
  local holders

  while true; do
    holders="$(dpkg_lock_holders)"
    if [[ -z "${holders//[[:space:]]/}" ]]; then
      return 0
    fi

    if (( SECONDS >= deadline )); then
      echo "Timed out waiting for apt/dpkg lock holders: ${holders}" >&2
      return 1
    fi

    echo "Waiting for apt/dpkg lock holders: ${holders}" >&2
    sleep "${APT_LOCK_RETRY_SECONDS}"
  done
}

run_apt_get() {
  wait_for_dpkg_locks
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout="${APT_LOCK_TIMEOUT_SECONDS}" "$@"
}

disable_managed_services() {
  systemctl disable sing-box >/dev/null 2>&1 || true
  systemctl disable vpn-stack-xray.service >/dev/null 2>&1 || true
  systemctl disable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
  systemctl disable vpn-stack-health.timer >/dev/null 2>&1 || true
  systemctl disable vpn-stack-transport.service >/dev/null 2>&1 || true
  systemctl disable vpn-stack-sync.timer vpn-stack-guard.timer >/dev/null 2>&1 || true
  systemctl disable vpn-stack-admin.service >/dev/null 2>&1 || true
  systemctl disable vpn-stack-subscription.service >/dev/null 2>&1 || true
  systemctl disable nftables >/dev/null 2>&1 || true
  systemctl disable systemd-resolved.service >/dev/null 2>&1 || true
}

remove_managed_files() {
  rm -f \
    "${SINGBOX_CONFIG_PATH}" \
    "${SINGBOX_BASE_CONFIG_PATH}" \
    "${XRAY_CONFIG_PATH}" \
    "${XRAY_SERVICE_PATH}" \
    "${WG_CONFIG_PATH}" \
    "${NFTABLES_PATH}" \
    "${SSHD_CONFIG_PATH}" \
    "${AGENT_SCRIPT_PATH}" \
    "${AGENT_LOG_CLASSIFIER_PATH}" \
    "${AGENT_TRANSPORT_POLICY_PATH}" \
    "${ADMIN_WEB_SCRIPT_PATH}" \
    "${ADMIN_APPLY_SCRIPT_PATH}" \
    "${HEALTH_SERVICE_PATH}" \
    "${HEALTH_TIMER_PATH}" \
    "${TRANSPORT_SERVICE_PATH}" \
    "${LEGACY_SYNC_SCRIPT_PATH}" \
    "${LEGACY_HEALTH_SCRIPT_PATH}" \
    "${LEGACY_GUARD_SCRIPT_PATH}" \
    "${LEGACY_SYNC_SERVICE_PATH}" \
    "${LEGACY_SYNC_TIMER_PATH}" \
    "${LEGACY_GUARD_SERVICE_PATH}" \
    "${LEGACY_GUARD_TIMER_PATH}" \
    "${ADMIN_WEB_SERVICE_PATH}" \
    "${SUBSCRIPTION_SERVICE_PATH}" \
    "${SYSCTL_PATH}" \
    "${MODULES_LOAD_PATH}" \
    "${RESOLVED_DROPIN_PATH}" \
    "${RESOLV_CONF_PATH}" \
    "${LEGACY_ADAPTIVE_ROUTING_RULES_PATH}" \
    "${LEGACY_DATAPLANE_CACHE_PATH}" \
    "${HEALTH_STATE_PATH}" \
    "${TRANSPORT_STATE_PATH}" \
    "/var/lib/vpn-stack/transport-shadow-state.json"
  rm -rf "${SUBSCRIPTION_ROOT}"
  rm -rf "${RULESET_DIR}"
}

reset_install_runtime_state() {
  rm -f "${LEGACY_DATAPLANE_CACHE_PATH}" "${HEALTH_STATE_PATH}" "${TRANSPORT_STATE_PATH}" "/var/lib/vpn-stack/transport-shadow-state.json"
  if [[ "${ROLE}" == "ru-gateway" ]]; then
    rm -f "${LEGACY_ADAPTIVE_ROUTING_RULES_PATH}"
  fi
}

reset_public_front_tcp_metrics() {
  if [[ "${ROLE}" == "ru-gateway" ]]; then
    ip tcp_metrics flush all >/dev/null
  fi
}

record_install_metadata() {
  mkdir -p "${VPNSTACK_ROOT}"
  if [[ -z "${NORMALIZED_ENV_FILE:-}" || ! -s "${NORMALIZED_ENV_FILE}" ]]; then
    echo "Normalized deployment env is missing; refusing to record ambiguous install metadata." >&2
    return 1
  fi
  copy_if_present "${NORMALIZED_ENV_FILE}" "${VPNSTACK_DEPLOYMENT_FILE}"
  chmod 0600 "${VPNSTACK_DEPLOYMENT_FILE}"
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
    done < <(rollback_paths)
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
  if [[ -x "${AGENT_SCRIPT_PATH}" ]] && command -v python3 >/dev/null 2>&1; then
    exec python3 "${AGENT_SCRIPT_PATH}" snapshot
  fi

  printf 'role=%s\n' "${ROLE}"
  printf 'installed=%s\n' "$(is_currently_installed && echo 1 || echo 0)"
  printf 'current_role=%s\n' "$(current_install_role)"
  printf 'deployment=%s\n' "$(current_install_deployment)"
  printf 'wireguard=%s\n' "$(service_active_flag "wg-quick@${WG_INTERFACE}")"
  printf 'nftables=%s\n' "$(service_active_flag nftables)"
  printf 'sing_box=%s\n' "$(service_active_flag sing-box)"
  printf 'xray=%s\n' "$(service_active_flag vpn-stack-xray.service)"
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
  if [[ -n "${ASSETS_DIR:-}" && -d "${ASSETS_DIR}" ]]; then
    args+=(--assets-dir "${ASSETS_DIR}")
  fi
  "${python_bin}" -c 'import sys; sys.path.insert(0, sys.argv[1]); from vpn_installer.install_support import main; raise SystemExit(main(sys.argv[2:]))' \
    "${SCRIPT_DIR}" \
    render-role \
    --role "${ROLE}" \
    --env-file "${ENV_FILE}" \
    --output-dir "${output_dir}" \
    "${args[@]}"
}

detect_primary_interface() {
  ip route show default | awk '/default/ {print $5; exit}'
}

configure_ssh_daemon_mode() {
  systemctl disable --now ssh.socket >/dev/null 2>&1 || true
  systemctl enable ssh.service >/dev/null 2>&1 || true
  systemctl restart ssh.service >/dev/null 2>&1 || systemctl start ssh.service >/dev/null 2>&1 || true
}

configure_journald_limits() {
  systemctl restart systemd-journald >/dev/null 2>&1 || true
  if [[ "${JOURNAL_LIMIT_ENABLED,,}" == "0" || "${JOURNAL_LIMIT_ENABLED,,}" == "false" || "${JOURNAL_LIMIT_ENABLED,,}" == "no" || "${JOURNAL_LIMIT_ENABLED,,}" == "off" ]]; then
    return 0
  fi
  journalctl --vacuum-size="${JOURNAL_SYSTEM_MAX_USE}" >/dev/null 2>&1 || true
  journalctl --vacuum-time="${JOURNAL_MAX_RETENTION_SEC}" >/dev/null 2>&1 || true
}

configure_unattended_security_updates() {
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
}

configure_system_resolver() {
  systemctl enable systemd-resolved.service
  systemctl restart systemd-resolved.service
  if [[ ! -e "${RESOLVED_STUB_PATH}" ]]; then
    echo "systemd-resolved did not create ${RESOLVED_STUB_PATH}" >&2
    return 1
  fi
  ln -sfn "../run/systemd/resolve/stub-resolv.conf" "${RESOLV_CONF_PATH}"
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
  copy_if_present "${source_dir}/sing-box.json" "${SINGBOX_BASE_CONFIG_PATH}" || { echo "Missing sing-box.json in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/render-manifest.json" "${VPNSTACK_RENDER_MANIFEST_FILE}" || { echo "Missing render-manifest.json in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/vpn-stack-agent.py" "${AGENT_SCRIPT_PATH}" || { echo "Missing vpn-stack-agent.py in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/log_classifier.py" "${AGENT_LOG_CLASSIFIER_PATH}" || { echo "Missing log_classifier.py in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/interserver_transport.py" "${AGENT_TRANSPORT_POLICY_PATH}" || { echo "Missing interserver_transport.py in ${source_dir}" >&2; exit 1; }
  if [[ "$ROLE" == "ru-gateway" ]]; then
    mkdir -p "$(dirname "${XRAY_CONFIG_PATH}")"
    copy_if_present "${source_dir}/xray.json" "${XRAY_CONFIG_PATH}" || { echo "Missing xray.json in ${source_dir}" >&2; exit 1; }
    copy_if_present "${source_dir}/vpn-stack-xray.service" "${XRAY_SERVICE_PATH}" || { echo "Missing vpn-stack-xray.service in ${source_dir}" >&2; exit 1; }
    copy_if_present "${source_dir}/admin_web.py" "${ADMIN_WEB_SCRIPT_PATH}" || { echo "Missing admin_web.py in ${source_dir}" >&2; exit 1; }
    copy_if_present "${source_dir}/admin_apply.py" "${ADMIN_APPLY_SCRIPT_PATH}" || { echo "Missing admin_apply.py in ${source_dir}" >&2; exit 1; }
    copy_if_present "${source_dir}/vpn-stack-admin.service" "${ADMIN_WEB_SERVICE_PATH}" || { echo "Missing vpn-stack-admin.service in ${source_dir}" >&2; exit 1; }
    copy_if_present "${source_dir}/vpn-stack-transport.service" "${TRANSPORT_SERVICE_PATH}" || { echo "Missing vpn-stack-transport.service in ${source_dir}" >&2; exit 1; }
  else
    rm -f "${XRAY_CONFIG_PATH}" "${XRAY_SERVICE_PATH}"
    rm -f "${ADMIN_WEB_SCRIPT_PATH}" "${ADMIN_APPLY_SCRIPT_PATH}" "${ADMIN_WEB_SERVICE_PATH}"
    rm -f "${TRANSPORT_SERVICE_PATH}" "${TRANSPORT_STATE_PATH}"
  fi
  copy_if_present "${source_dir}/${WG_INTERFACE}.conf" "${WG_CONFIG_PATH}" || { echo "Missing ${WG_INTERFACE}.conf in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/nftables.conf" "${NFTABLES_PATH}" || { echo "Missing nftables.conf in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/sshd-vpn-stack.conf" "${SSHD_CONFIG_PATH}" || { echo "Missing sshd-vpn-stack.conf in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/sysctl-vpn-stack.conf" "${SYSCTL_PATH}" || { echo "Missing sysctl-vpn-stack.conf in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/modules-vpn-stack.conf" "${MODULES_LOAD_PATH}" || { echo "Missing modules-vpn-stack.conf in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/apt-vpn-stack-unattended.conf" "${APT_PERIODIC_DROPIN_PATH}" || { echo "Missing apt-vpn-stack-unattended.conf in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/resolved-vpn-stack.conf" "${RESOLVED_DROPIN_PATH}" || { echo "Missing resolved-vpn-stack.conf in ${source_dir}" >&2; exit 1; }
  if [[ -f "${source_dir}/journald-vpn-stack.conf" ]]; then
    copy_if_present "${source_dir}/journald-vpn-stack.conf" "${JOURNALD_DROPIN_PATH}"
  else
    rm -f "${JOURNALD_DROPIN_PATH}"
  fi
  copy_if_present "${source_dir}/vpn-stack-health.service" "${HEALTH_SERVICE_PATH}" || { echo "Missing vpn-stack-health.service in ${source_dir}" >&2; exit 1; }
  copy_if_present "${source_dir}/vpn-stack-health.timer" "${HEALTH_TIMER_PATH}" || { echo "Missing vpn-stack-health.timer in ${source_dir}" >&2; exit 1; }
  rm -f "${SUBSCRIPTION_SERVICE_PATH}"
  rm -rf "${SUBSCRIPTION_ROOT}"
  chmod 0644 "${SSHD_CONFIG_PATH}"
  if [[ "$ROLE" == "ru-gateway" ]]; then
    chmod 0644 "${XRAY_SERVICE_PATH}"
    chmod 0644 "${ADMIN_WEB_SERVICE_PATH}"
    chmod 0644 "${TRANSPORT_SERVICE_PATH}"
    chmod 0755 "${ADMIN_WEB_SCRIPT_PATH}" "${ADMIN_APPLY_SCRIPT_PATH}"
  fi
  rm -f "${LEGACY_SYNC_SCRIPT_PATH}" "${LEGACY_HEALTH_SCRIPT_PATH}" "${LEGACY_GUARD_SCRIPT_PATH}" "${LEGACY_SYNC_SERVICE_PATH}" "${LEGACY_SYNC_TIMER_PATH}" "${LEGACY_GUARD_SERVICE_PATH}" "${LEGACY_GUARD_TIMER_PATH}"
  chmod 0755 "${AGENT_SCRIPT_PATH}"
}

release_id_from_manifest() {
  local source_dir="$1"
  sed -n 's/.*"release_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${source_dir}/render-manifest.json" | head -n1
}

stage_release() {
  local source_dir="$1"
  local release_id=""
  local staging_dir=""
  release_id="$(release_id_from_manifest "${source_dir}")"
  if [[ -z "${release_id}" ]]; then
    echo "render-manifest.json is missing release_id" >&2
    return 1
  fi
  if [[ ! "${release_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "render-manifest.json contains unsafe release_id: ${release_id}" >&2
    return 1
  fi
  staging_dir="${VPNSTACK_RELEASES_DIR}/.staging-${release_id}-$$"
  STAGED_RELEASE_DIR="${staging_dir}"
  mkdir -p "${VPNSTACK_RELEASES_DIR}"
  rm -rf "${staging_dir}"
  mkdir -p "${staging_dir}"
  cp -a "${source_dir}/." "${staging_dir}/"
  if [[ -n "${ASSETS_DIR:-}" && -d "${ASSETS_DIR}" ]]; then
    mkdir -p "${staging_dir}/assets"
    cp -a "${ASSETS_DIR}/." "${staging_dir}/assets/"
  fi
  normalize_staged_release_permissions "${staging_dir}"
}

release_tree_digest() {
  local source_dir="$1"
  (
    cd "${source_dir}"
    find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'
  )
}

publish_staged_release() {
  local source_dir="$1"
  local release_id=""
  local tree_digest=""
  local release_dir=""
  release_id="$(release_id_from_manifest "${source_dir}")"
  tree_digest="$(release_tree_digest "${source_dir}")"
  [[ -n "${release_id}" && -n "${tree_digest}" ]] || { echo "Unable to identify staged release" >&2; return 1; }
  release_dir="${VPNSTACK_RELEASES_DIR}/${release_id}-${tree_digest:0:12}"
  if [[ -e "${release_dir}" ]]; then
    if ! diff -qr "${source_dir}" "${release_dir}" >/dev/null; then
      echo "Immutable release digest collision: ${release_dir}" >&2
      return 1
    fi
    rm -rf "${source_dir}"
  else
    mv "${source_dir}" "${release_dir}"
  fi
  STAGED_RELEASE_DIR=""
  PUBLISHED_RELEASE_DIR="${release_dir}"
}

normalize_staged_release_permissions() {
  local source_dir="$1"
  find "${source_dir}" -type d -exec chmod 0755 {} +
  find "${source_dir}" -type f -exec chmod 0644 {} +
  if [[ -f "${source_dir}/sing-box.json" ]]; then
    chmod 0600 "${source_dir}/sing-box.json"
  fi
  chmod 0600 "${source_dir}/${WG_INTERFACE}.conf"
  if [[ "${ROLE}" == "ru-gateway" ]]; then
    chmod 0600 "${source_dir}/xray.json"
  fi
}

validate_staged_release() {
  local source_dir="$1"
  local xray_config="${source_dir}/xray.json"
  [[ -s "${source_dir}/render-manifest.json" ]] || { echo "missing render manifest" >&2; return 1; }
  [[ -s "${source_dir}/vpn-stack-agent.py" ]] || { echo "missing server agent" >&2; return 1; }
  [[ -s "${source_dir}/log_classifier.py" ]] || { echo "missing log classifier" >&2; return 1; }
  [[ -s "${source_dir}/interserver_transport.py" ]] || { echo "missing interserver transport policy" >&2; return 1; }
  python3 -m py_compile "${source_dir}/vpn-stack-agent.py" "${source_dir}/log_classifier.py" "${source_dir}/interserver_transport.py"
  PYTHONPATH="${source_dir}${PYTHONPATH:+:${PYTHONPATH}}" python3 "${source_dir}/vpn-stack-agent.py" --help >/dev/null
  python3 - "${source_dir}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest = json.loads((root / "render-manifest.json").read_text(encoding="utf-8"))
if int(manifest.get("schema_version", 0)) < 2:
    raise SystemExit("unsupported render manifest")
for name, entry in manifest.get("assets", {}).items():
    asset = root / "assets" / name
    if not asset.is_file():
        raise SystemExit(f"missing staged asset: {name}")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    if digest != entry.get("sha256"):
        raise SystemExit(f"staged asset digest mismatch: {name}")
PY
  sing-box check -c "${source_dir}/sing-box.json"
  nft -c -f "${source_dir}/nftables.conf"
  if [[ "${ROLE}" == "ru-gateway" ]]; then
    [[ -s "${xray_config}" ]] || { echo "missing Xray config" >&2; return 1; }
    xray run -test -c "${xray_config}"
  fi
  wg-quick strip "${source_dir}/${WG_INTERFACE}.conf" >/dev/null
  systemd-analyze verify "${source_dir}/vpn-stack-health.service" "${source_dir}/vpn-stack-health.timer" >/dev/null
  if [[ "${ROLE}" == "ru-gateway" ]]; then
    systemd-analyze verify "${source_dir}/vpn-stack-transport.service" >/dev/null
  fi
}

activate_staged_release() {
  local release_dir="$1"
  local link_tmp="${VPNSTACK_ROOT}/.current.$$.tmp"
  local previous_tmp="${VPNSTACK_ROOT}/.previous.$$.tmp"
  local previous_release=""
  if [[ -L "${VPNSTACK_CURRENT_RELEASE}" ]]; then
    previous_release="$(readlink -f "${VPNSTACK_CURRENT_RELEASE}" 2>/dev/null || true)"
  fi
  if [[ -n "${previous_release}" && -d "${previous_release}" ]]; then
    ln -s "${previous_release}" "${previous_tmp}"
    mv -Tf "${previous_tmp}" "${VPNSTACK_PREVIOUS_RELEASE}"
  fi
  ln -s "${release_dir}" "${link_tmp}"
  mv -Tf "${link_tmp}" "${VPNSTACK_CURRENT_RELEASE}"
  copy_role_artifacts "${release_dir}"
}

verify_active_release() {
  local report_tmp="${VPNSTACK_ROOT}/.acceptance.$$.json"
  rm -f "${VPNSTACK_ROOT}"/.acceptance.*.json
  if ! python3 "${AGENT_SCRIPT_PATH}" snapshot --live-probes --profile acceptance >"${report_tmp}"; then
    rm -f "${report_tmp}"
    return 1
  fi
  if ! python3 - "${report_tmp}" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
verdicts = payload.get("verdicts", {})
if verdicts.get("server_path") != "verified":
    raise SystemExit(f"post-activation server path failed: {verdicts.get('reasons', [])}")
if payload.get("role") == "ru-gateway" and verdicts.get("public_front") != "verified":
    raise SystemExit("post-activation public VLESS front is not verified")
if verdicts.get("host_integrity") != "verified":
    raise SystemExit(f"post-activation host integrity failed: {verdicts.get('host_integrity')}")
if payload.get("artifacts", {}).get("drift") != "none":
    raise SystemExit("post-activation artifact drift detected")
PY
  then
    mv -f "${report_tmp}" "${VPNSTACK_FAILED_ACCEPTANCE_FILE}"
    return 1
  fi
  mv -f "${report_tmp}" "${VPNSTACK_ACCEPTANCE_FILE}"
  rm -f "${VPNSTACK_FAILED_ACCEPTANCE_FILE}"
}

write_preview_files() {
  local base="$1"
  render_role_with_python "${base}"
}

stage_preseed_assets() {
  local source_assets="${1:-${ASSETS_DIR:-}}"
  if [[ -z "${source_assets}" || ! -d "${source_assets}" ]]; then
    return 0
  fi

  mkdir -p "${RULESET_DIR}"

  if [[ "$ROLE" == "ru-gateway" ]]; then
    copy_if_present "${source_assets}/geosite-ru.srs" "${RULESET_DIR}/geosite-ru.srs" || true
    copy_if_present "${source_assets}/geoip-ru.srs" "${RULESET_DIR}/geoip-ru.srs" || true
  else
    copy_if_present "${source_assets}/ru-ipv4.zone" "${RULESET_DIR}/ru-ipv4.zone" || true
    copy_if_present "${source_assets}/ru-ipv6.zone" "${RULESET_DIR}/ru-ipv6.zone" || true
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

if [[ "${VPNSTACK_INSTALL_LIBRARY_ONLY:-0}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi

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
  extend_baseline_contract
  create_revision_snapshot
fi

ROLE_ARTIFACTS_DIR="$(prepare_role_artifacts)"
PREPARED_ARTIFACTS_DIR="${ROLE_ARTIFACTS_DIR}"
trap 'exit_code=$?; install_exit_trap "${exit_code}"; trap - EXIT; exit "${exit_code}"' EXIT
INSTALL_MUTATION_STARTED=1

run_apt_get update
run_apt_get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  e2fsprogs \
  ethtool \
  gnupg \
  iperf3 \
  iputils-ping \
  mtr-tiny \
  nftables \
  python3 \
  systemd-resolved \
  unzip \
  unattended-upgrades \
  wireguard \
  wireguard-tools

install_sing_box() {
  curl -fsSL https://sing-box.sagernet.org/installation/tools/install.sh | bash -s -- --version "${SINGBOX_REQUIRED_VERSION}"
}

current_singbox_version() {
  if ! command -v sing-box >/dev/null 2>&1; then
    return 1
  fi
  sing-box version 2>/dev/null | awk 'NR == 1 {print $3}'
}

install_xray() {
  local archive=""
  local temp_dir=""
  if [[ "$(uname -m)" != "x86_64" ]]; then
    echo "Pinned Xray package currently supports x86_64 only." >&2
    return 1
  fi
  temp_dir="$(mktemp -d)"
  archive="${temp_dir}/Xray-linux-64.zip"
  curl -fsSL --connect-timeout 10 --max-time 120 "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_REQUIRED_VERSION}/Xray-linux-64.zip" -o "${archive}"
  echo "${XRAY_LINUX_AMD64_SHA256}  ${archive}" | sha256sum -c -
  unzip -q "${archive}" xray -d "${temp_dir}"
  install -m 0755 "${temp_dir}/xray" /usr/local/bin/xray
  rm -rf "${temp_dir}"
}

current_xray_version() {
  if ! command -v xray >/dev/null 2>&1; then
    return 1
  fi
  xray version 2>/dev/null | awk 'NR == 1 {print $2}'
}

record_binary_digests() {
  local source_dir="$1"
  local singbox_bin=""
  local xray_bin=""
  singbox_bin="$(command -v sing-box)"
  if [[ "$ROLE" == "ru-gateway" ]]; then
    xray_bin="$(command -v xray)"
  fi
  python3 - "${source_dir}/render-manifest.json" "${singbox_bin}" "${xray_bin}" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
paths = {"sing-box": sys.argv[2], "xray": sys.argv[3]}
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
for name, path_text in paths.items():
    entry = manifest.get("binaries", {}).get(name)
    if entry is None:
        continue
    path = Path(path_text)
    if not path.is_file():
        raise SystemExit(f"required binary is missing: {name}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    digest = digest.hexdigest()
    entry.update({"path": str(path), "sha256": digest})
os_release = {}
try:
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
except OSError:
    pass
manifest["runtime"] = {
    "kernel": os.uname().release,
    "os_id": os_release.get("ID", ""),
    "os_version": os_release.get("VERSION_ID", ""),
}
tmp = manifest_path.with_suffix(".tmp")
tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(tmp, manifest_path)
PY
}

if [[ "$(current_singbox_version || true)" != "${SINGBOX_REQUIRED_VERSION}" ]]; then
  install_sing_box
fi
if [[ "$ROLE" == "ru-gateway" && "$(current_xray_version || true)" != "${XRAY_REQUIRED_VERSION}" ]]; then
  install_xray
fi

mkdir -p "${VPNSTACK_ROOT}" /etc/sing-box /etc/xray /etc/wireguard /etc/ssh/sshd_config.d "${RULESET_DIR}" /usr/local/lib/vpn-stack /etc/systemd/system

PRIMARY_INTERFACE="$(detect_primary_interface)"

if [[ "$ROLE" == "foreign-exit" ]]; then
  WAN_INTERFACE="${WAN_INTERFACE:-${PRIMARY_INTERFACE}}"
  if [[ -z "${WAN_INTERFACE:-}" ]]; then
    echo "Unable to detect WAN interface. Set WAN_INTERFACE in the env file." >&2
    exit 1
  fi
fi

stage_release "${ROLE_ARTIFACTS_DIR}"
ROLE_ARTIFACTS_DIR="${STAGED_RELEASE_DIR}"
record_binary_digests "${ROLE_ARTIFACTS_DIR}"
stage_preseed_assets "${ROLE_ARTIFACTS_DIR}/assets"
validate_staged_release "${ROLE_ARTIFACTS_DIR}"
publish_staged_release "${ROLE_ARTIFACTS_DIR}"
ROLE_ARTIFACTS_DIR="${PUBLISHED_RELEASE_DIR}"
if [[ "$ACTION" == "reinstall" ]]; then
  stop_managed_services
fi
reset_install_runtime_state
activate_staged_release "${ROLE_ARTIFACTS_DIR}"

record_install_metadata

modprobe nf_conntrack
sysctl --system >/dev/null
configure_journald_limits
configure_unattended_security_updates
configure_system_resolver
systemctl daemon-reload
disable_legacy_proxy_services
configure_ssh_daemon_mode
systemctl enable nftables
systemctl restart nftables
if [[ "$ROLE" == "foreign-exit" ]]; then
  apply_foreign_ru_block_from_local_assets
fi
restart_wireguard_service
systemctl disable --now vpn-stack-sync.timer vpn-stack-sync.service >/dev/null 2>&1 || true
systemctl disable --now vpn-stack-guard.timer vpn-stack-guard.service >/dev/null 2>&1 || true
systemctl enable vpn-stack-health.timer
systemctl restart vpn-stack-health.timer
systemctl reset-failed vpn-stack-health.service >/dev/null 2>&1 || true

systemctl enable sing-box
systemctl restart sing-box

if [[ "$ROLE" == "ru-gateway" ]]; then
  systemctl enable vpn-stack-transport.service
  systemctl restart vpn-stack-transport.service
  if [[ ! -f "${VPNSTACK_ROOT}/admin-auth.json" || "${ADMIN_WEB_USERNAME}" != "user" || "${ADMIN_WEB_PASSWORD}" != "password" ]]; then
    if [[ "${ADMIN_WEB_USERNAME}" != "user" || "${ADMIN_WEB_PASSWORD}" != "password" ]]; then
      python3 "${ADMIN_WEB_SCRIPT_PATH}" init-auth "${ADMIN_WEB_USERNAME}" "${ADMIN_WEB_PASSWORD}" --force
    else
      python3 "${ADMIN_WEB_SCRIPT_PATH}" init-auth "${ADMIN_WEB_USERNAME}" "${ADMIN_WEB_PASSWORD}"
    fi
  fi
  python3 "${ADMIN_APPLY_SCRIPT_PATH}" --no-restart
  systemctl enable vpn-stack-xray.service
  systemctl restart vpn-stack-xray.service
  if [[ "${ADMIN_WEB_ENABLED,,}" != "0" && "${ADMIN_WEB_ENABLED,,}" != "false" && "${ADMIN_WEB_ENABLED,,}" != "no" && "${ADMIN_WEB_ENABLED,,}" != "off" ]]; then
    systemctl enable vpn-stack-admin.service
    systemctl restart vpn-stack-admin.service
  else
    systemctl disable vpn-stack-admin.service >/dev/null 2>&1 || true
    systemctl stop vpn-stack-admin.service >/dev/null 2>&1 || true
  fi
fi

reset_public_front_tcp_metrics
verify_active_release

chmod 0600 "${SINGBOX_CONFIG_PATH}" "${WG_CONFIG_PATH}"
if [[ "$ROLE" == "ru-gateway" ]]; then
  chmod 0600 "${XRAY_CONFIG_PATH}"
fi

systemctl enable unattended-upgrades || true

echo "Completed ${ROLE} installation for ${DEPLOY_NAME}."
