#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPNSTACK_ROOT="${VPNSTACK_ROOT:-/etc/vpn-stack}"
VPNSTACK_RELEASES_DIR="${VPNSTACK_ROOT}/releases"
VPNSTACK_CURRENT_RELEASE="${VPNSTACK_ROOT}/current"
VPNSTACK_PREVIOUS_RELEASE="${VPNSTACK_ROOT}/previous"
VPNSTACK_BACKUP_DIR="${VPNSTACK_ROOT}/backups"
VPNSTACK_BASELINE_DIR="${VPNSTACK_BACKUP_DIR}/baseline"
VPNSTACK_REVISION_DIR="${VPNSTACK_BACKUP_DIR}/revisions"
VPNSTACK_LATEST_SNAPSHOT="${VPNSTACK_BACKUP_DIR}/latest"
VPNSTACK_MANIFEST_PATH="${VPNSTACK_ROOT}/render-manifest.json"
VPNSTACK_INSTALL_PLAN_PATH="${VPNSTACK_ROOT}/install-plan.json"
VPNSTACK_DEPLOYMENT_PATH="${VPNSTACK_ROOT}/deployment.env"
VPNSTACK_NODE_PATH="${VPNSTACK_ROOT}/node-id"
VPNSTACK_INSTALLED_AT_PATH="${VPNSTACK_ROOT}/installed-at"
VPNSTACK_LEGACY_ROLE_PATH="${VPNSTACK_ROOT}/role"
VPNSTACK_LEGACY_INSTALLED_AT_PATH="${VPNSTACK_ROOT}/installed_at"
VPNSTACK_REMOVED_AT_PATH="${VPNSTACK_ROOT}/removed-at"
VPNSTACK_ACCEPTANCE_PATH="${VPNSTACK_ROOT}/last-acceptance.json"
VPNSTACK_FAILED_ACCEPTANCE_PATH="${VPNSTACK_ROOT}/last-failed-acceptance.json"
VPNSTACK_LEGACY_ACCEPTANCE_PATH="${VPNSTACK_ROOT}/acceptance.json"
INSTALL_LOCK_PATH="${VPNSTACK_INSTALL_LOCK_PATH:-/run/lock/vpn-stack-install.lock}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"

NODE=""
LEGACY_ROLE=""
ENV_FILE=""
OUTPUT_DIR=""
ASSETS_DIR=""
ACTION="install"
RENDER_ONLY=0
PYTHON_BIN="${PYTHON_BIN:-}"
TRANSACTION_ACTIVE=0
TRANSACTION_SNAPSHOT=""
STAGED_RELEASE_DIR=""
PUBLISHED_RELEASE_DIR=""
PREVIOUS_RELEASE_DIR=""
WORK_DIR=""
FAILED_ACCEPTANCE_STASH=""

usage() {
  cat <<'EOF'
Usage:
  install.sh --node <gateway|exit> --env-file <file> [--assets-dir <dir>]
             [--action <install|reinstall|rollback|remove|purge|status>]
  install.sh --node <gateway|exit> --env-file <file> --render-only --output-dir <dir>

Deprecated for one release:
  --role ru-gateway      maps to --node gateway
  --role foreign-exit   maps to --node exit
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

warn() {
  echo "WARNING: $*" >&2
}

require_value() {
  local option="$1"
  local value="${2:-}"
  [[ -n "${value}" ]] || die "${option} requires a value"
}

find_python() {
  local candidate=""
  for candidate in "${PYTHON_BIN:-}" python3 python "${SCRIPT_DIR}/.runtime/python/windows/python.exe"; do
    [[ -n "${candidate}" ]] || continue
    if "${candidate}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
      PYTHON_BIN="${candidate}"
      return 0
    fi
  done
  die "Python 3.9+ is required"
}

parse_cli() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --node)
        require_value "$1" "${2:-}"
        NODE="$2"
        shift 2
        ;;
      --role)
        require_value "$1" "${2:-}"
        LEGACY_ROLE="$2"
        shift 2
        ;;
      --env-file)
        require_value "$1" "${2:-}"
        ENV_FILE="$2"
        shift 2
        ;;
      --output-dir)
        require_value "$1" "${2:-}"
        OUTPUT_DIR="$2"
        shift 2
        ;;
      --assets-dir)
        require_value "$1" "${2:-}"
        ASSETS_DIR="$2"
        shift 2
        ;;
      --action)
        require_value "$1" "${2:-}"
        ACTION="$2"
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
        die "unknown argument: $1"
        ;;
    esac
  done

  case "${NODE}" in
    ""|gateway|exit) ;;
    *) die "unsupported node: ${NODE}" ;;
  esac
  if [[ -n "${LEGACY_ROLE}" ]]; then
    local mapped=""
    case "${LEGACY_ROLE}" in
      ru-gateway) mapped="gateway" ;;
      foreign-exit) mapped="exit" ;;
      *) die "unsupported legacy role: ${LEGACY_ROLE}" ;;
    esac
    warn "--role is deprecated; use --node ${mapped}"
    if [[ -n "${NODE}" && "${NODE}" != "${mapped}" ]]; then
      die "--node and --role select different nodes"
    fi
    NODE="${mapped}"
  fi
  case "${ACTION}" in
    install|reinstall|rollback|remove|purge|status) ;;
    *) die "unsupported action: ${ACTION}" ;;
  esac
  if [[ "${RENDER_ONLY}" == "1" && "${ACTION}" != "install" ]]; then
    die "--render-only cannot be combined with --action ${ACTION}"
  fi
}

infer_installed_node() {
  [[ -f "${VPNSTACK_MANIFEST_PATH}" ]] || return 1
  "${PYTHON_BIN}" - "${VPNSTACK_MANIFEST_PATH}" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
node = manifest.get("node_id") or (manifest.get("node") or {}).get("id")
if node not in {"gateway", "exit"}:
    raise SystemExit("installed manifest has no canonical node id")
print(node)
PY
}

render_node_bundle() {
  local destination="$1"
  [[ -f "${SCRIPT_DIR}/vpn_installer/install_support.py" ]] ||
    die "vpn_installer.install_support is missing next to install.sh"
  mkdir -p "${destination}"
  local args=(
    -c
    'import sys; sys.path.insert(0, sys.argv[1]); from vpn_installer.install_support import main; raise SystemExit(main(sys.argv[2:]))'
    "${SCRIPT_DIR}"
    render-node
    --node "${NODE}"
    --env-file "${ENV_FILE}"
    --output-dir "${destination}"
  )
  if [[ -n "${ASSETS_DIR}" ]]; then
    args+=(--assets-dir "${ASSETS_DIR}")
  fi
  "${PYTHON_BIN}" "${args[@]}"
}

validate_bundle() {
  local bundle="$1"
  local expected_node="$2"
  local contract_dir="$3"
  local external_assets="${4:-}"
  local require_assets="${5:-0}"
  local require_binaries="${6:-0}"
  rm -rf -- "${contract_dir}"
  mkdir -p "${contract_dir}"

  local args=(
    -c
    'import sys; sys.path.insert(0, sys.argv[1]); from vpn_installer.install_support import main; raise SystemExit(main(sys.argv[2:]))'
    "${SCRIPT_DIR}"
    validate-bundle
    --bundle "${bundle}"
    --expected-node "${expected_node}"
    --contract-dir "${contract_dir}"
  )
  if [[ -n "${external_assets}" ]]; then
    args+=(--external-assets "${external_assets}")
  fi
  if [[ "${require_assets}" == "1" ]]; then
    args+=(--require-assets)
  fi
  if [[ "${require_binaries}" == "1" ]]; then
    args+=(--require-binaries)
  fi
  "${PYTHON_BIN}" "${args[@]}"
}

adapt_schema2_contract() {
  local current_release="$1"
  local deployment_env="$2"
  local contract_dir="$3"
  rm -rf -- "${contract_dir}"
  mkdir -p "${contract_dir}"
  "${PYTHON_BIN}" -c \
    'import sys; sys.path.insert(0, sys.argv[1]); from vpn_installer.install_support import main; raise SystemExit(main(sys.argv[2:]))' \
    "${SCRIPT_DIR}" adapt-schema2 \
    --current-release "${current_release}" \
    --deployment-env "${deployment_env}" \
    --contract-dir "${contract_dir}"
}

contract_value() {
  local contract_dir="$1"
  local key="$2"
  awk -F '\t' -v key="${key}" '$1 == key {print $2; found=1; exit} END {if (!found) exit 1}' "${contract_dir}/meta.tsv"
}

contract_has_service() {
  local contract_dir="$1"
  local name="$2"
  awk -F '\t' -v name="${name}" '$1 == name {found=1} END {exit !found}' "${contract_dir}/services.tsv"
}

contract_has_path() {
  local contract_dir="$1"
  local path="$2"
  awk -F '\t' -v path="${path}" '$2 == path {found=1} END {exit !found}' "${contract_dir}/artifacts.tsv" "${contract_dir}/assets.tsv"
}

render_only_action() {
  [[ -n "${NODE}" ]] || die "--node is required with --render-only"
  [[ -n "${ENV_FILE}" ]] || die "--env-file is required with --render-only"
  [[ -f "${ENV_FILE}" ]] || die "env file not found: ${ENV_FILE}"
  [[ -n "${OUTPUT_DIR}" ]] || die "--output-dir is required with --render-only"
  if [[ -n "${ASSETS_DIR}" && ! -d "${ASSETS_DIR}" ]]; then
    die "assets directory not found: ${ASSETS_DIR}"
  fi

  local output_parent=""
  local output_name=""
  local temporary=""
  local contract=""
  output_parent="$(cd "$(dirname "${OUTPUT_DIR}")" 2>/dev/null && pwd || true)"
  if [[ -z "${output_parent}" ]]; then
    mkdir -p "$(dirname "${OUTPUT_DIR}")"
    output_parent="$(cd "$(dirname "${OUTPUT_DIR}")" && pwd)"
  fi
  output_name="$(basename "${OUTPUT_DIR}")"
  temporary="$(mktemp -d "${output_parent}/.${output_name}.render.XXXXXX")"
  contract="$(mktemp -d)"
  trap 'rm -rf -- "${temporary:-}" "${contract:-}"' RETURN

  render_node_bundle "${temporary}"
  validate_bundle "${temporary}" "${NODE}" "${contract}" "${ASSETS_DIR}" 0 0

  local old_output=""
  if [[ -e "${OUTPUT_DIR}" || -L "${OUTPUT_DIR}" ]]; then
    old_output="${output_parent}/.${output_name}.old.$$"
    mv -- "${OUTPUT_DIR}" "${old_output}"
  fi
  if ! mv -- "${temporary}" "${OUTPUT_DIR}"; then
    [[ -n "${old_output}" ]] && mv -- "${old_output}" "${OUTPUT_DIR}"
    return 1
  fi
  temporary=""
  [[ -n "${old_output}" ]] && rm -rf -- "${old_output}"
  rm -rf -- "${contract}"
  contract=""
  trap - RETURN
  echo "Rendered schema-3 node bundle: ${OUTPUT_DIR}"
}

safe_operational_path() {
  local path="$1"
  [[ -n "${path}" && "${path}" == /* && "${path}" != "/" ]] || return 1
  case "${path}" in
    "${VPNSTACK_ROOT}"/*|/etc/sing-box/*|/etc/xray/*|/etc/wireguard/*|/etc/systemd/system/*|/etc/ssh/sshd_config.d/*|/etc/sysctl.d/*|/etc/modules-load.d/*|/etc/systemd/journald.conf.d/*|/etc/apt/apt.conf.d/*|/etc/systemd/resolved.conf.d/*|/usr/local/lib/vpn-stack/*|/var/lib/vpn-stack/*)
      return 0
      ;;
  esac
  return 1
}

build_operation_scope() {
  local new_contract="$1"
  local previous_contract="$2"
  local scope_dir="$3"
  mkdir -p "${scope_dir}"
  : >"${scope_dir}/paths.list"
  : >"${scope_dir}/services.tsv"

  local contract=""
  for contract in "${new_contract}" "${previous_contract}"; do
    [[ -n "${contract}" && -d "${contract}" ]] || continue
    awk -F '\t' '{print $2}' "${contract}/artifacts.tsv" "${contract}/assets.tsv" \
      >>"${scope_dir}/paths.list"
    cat "${contract}/services.tsv" >>"${scope_dir}/services.tsv"
  done

  cat >>"${scope_dir}/paths.list" <<EOF
${VPNSTACK_CURRENT_RELEASE}
${VPNSTACK_PREVIOUS_RELEASE}
${VPNSTACK_MANIFEST_PATH}
${VPNSTACK_INSTALL_PLAN_PATH}
${VPNSTACK_NODE_PATH}
${VPNSTACK_INSTALLED_AT_PATH}
${VPNSTACK_LEGACY_ROLE_PATH}
${VPNSTACK_LEGACY_INSTALLED_AT_PATH}
${VPNSTACK_REMOVED_AT_PATH}
${VPNSTACK_ACCEPTANCE_PATH}
${VPNSTACK_FAILED_ACCEPTANCE_PATH}
${VPNSTACK_LEGACY_ACCEPTANCE_PATH}
${VPNSTACK_ROOT}/health-state.json
/etc/sing-box/config.json
EOF
  local has_admin=0
  local has_operator_routes=0
  local has_interserver=0
  for contract in "${new_contract}" "${previous_contract}"; do
    [[ -n "${contract}" && -d "${contract}" ]] || continue
    contract_has_service "${contract}" admin && has_admin=1
    contract_artifact_path "${contract}" admin_apply.py >/dev/null 2>&1 && has_operator_routes=1
    if contract_has_service "${contract}" wireguard || contract_has_service "${contract}" transport; then
      has_interserver=1
    fi
  done
  if [[ "${has_admin}" == "1" ]]; then
    printf '%s\n' "${VPNSTACK_ROOT}/admin-auth.json" >>"${scope_dir}/paths.list"
  fi
  if [[ "${has_operator_routes}" == "1" ]]; then
    printf '%s\n' "${VPNSTACK_ROOT}/admin-routing-rules.json" "${VPNSTACK_ROOT}/operator-state.json" >>"${scope_dir}/paths.list"
  fi
  if [[ "${has_interserver}" == "1" ]]; then
    printf '%s\n' "/var/lib/vpn-stack/transport-state.json" "/var/lib/vpn-stack/transport-shadow-state.json" >>"${scope_dir}/paths.list"
  fi
  LC_ALL=C sort -u "${scope_dir}/paths.list" -o "${scope_dir}/paths.list"
  awk -F '\t' '!seen[$2]++' "${scope_dir}/services.tsv" >"${scope_dir}/services.unique.tsv"
  mv "${scope_dir}/services.unique.tsv" "${scope_dir}/services.tsv"
  while IFS= read -r path; do
    safe_operational_path "${path}" || die "unsafe operation scope path: ${path}"
  done <"${scope_dir}/paths.list"
}

snapshot_has_path() {
  local snapshot="$1"
  local path="$2"
  [[ -f "${snapshot}/paths.tsv" ]] &&
    awk -F '\t' -v path="${path}" '$3 == path {found=1} END {exit !found}' "${snapshot}/paths.tsv"
}

snapshot_has_service() {
  local snapshot="$1"
  local unit="$2"
  [[ -f "${snapshot}/service-state.tsv" ]] &&
    awk -F '\t' -v unit="${unit}" '$2 == unit {found=1} END {exit !found}' "${snapshot}/service-state.tsv"
}

capture_snapshot() {
  local snapshot="$1"
  local scope_dir="$2"
  local append="${3:-0}"
  mkdir -p "${snapshot}/files"
  if [[ "${append}" != "1" ]]; then
    : >"${snapshot}/paths.tsv"
    : >"${snapshot}/service-state.tsv"
    : >"${snapshot}/sysctl-state.tsv"
  else
    touch "${snapshot}/paths.tsv" "${snapshot}/service-state.tsv" "${snapshot}/sysctl-state.tsv"
  fi

  local path=""
  local id=""
  local state=""
  local count=0
  count="$(wc -l <"${snapshot}/paths.tsv")"
  while IFS= read -r path; do
    [[ -n "${path}" ]] || continue
    snapshot_has_path "${snapshot}" "${path}" && continue
    count=$((count + 1))
    printf -v id '%06d' "${count}"
    state="missing"
    if [[ -e "${path}" || -L "${path}" ]]; then
      state="present"
      cp -a -- "${path}" "${snapshot}/files/${id}"
    fi
    printf '%s\t%s\t%s\n' "${id}" "${state}" "${path}" >>"${snapshot}/paths.tsv"
  done <"${scope_dir}/paths.list"

  local name=""
  local unit=""
  local ownership=""
  local enabled=""
  local active=""
  while IFS=$'\t' read -r name unit ownership; do
    [[ -n "${unit}" ]] || continue
    snapshot_has_service "${snapshot}" "${unit}" && continue
    enabled="$("${SYSTEMCTL_BIN}" is-enabled "${unit}" 2>/dev/null || true)"
    active="$("${SYSTEMCTL_BIN}" is-active "${unit}" 2>/dev/null || true)"
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "${name}" "${unit}" "${ownership}" "${enabled:-unknown}" "${active:-unknown}" \
      >>"${snapshot}/service-state.tsv"
  done <"${scope_dir}/services.tsv"
}

capture_sysctl_state() {
  local snapshot="$1"
  shift
  command -v sysctl >/dev/null 2>&1 || return 0
  local config=""
  local key=""
  local value=""
  for config in "$@"; do
    [[ -f "${config}" ]] || continue
    while IFS= read -r key; do
      [[ -n "${key}" ]] || continue
      if awk -F '\t' -v key="${key}" '$1 == key {found=1} END {exit !found}' "${snapshot}/sysctl-state.tsv"; then
        continue
      fi
      value="$(sysctl -n "${key}" 2>/dev/null || true)"
      [[ -n "${value}" ]] || continue
      [[ "${key}" != *$'\t'* && "${value}" != *$'\t'* && "${value}" != *$'\n'* ]] ||
        die "unsafe sysctl snapshot value"
      printf '%s\t%s\n' "${key}" "${value}" >>"${snapshot}/sysctl-state.tsv"
    done < <(awk -F= '/^[[:space:]]*[A-Za-z0-9_.]+[[:space:]]*=/ {key=$1; gsub(/[[:space:]]/, "", key); print key}' "${config}")
  done
}

restore_sysctl_state() {
  local snapshot="$1"
  [[ -f "${snapshot}/sysctl-state.tsv" ]] || return 0
  command -v sysctl >/dev/null 2>&1 || return 0
  local key=""
  local value=""
  while IFS=$'\t' read -r key value; do
    [[ -n "${key}" ]] || continue
    sysctl -q -w "${key}=${value}" >/dev/null
  done <"${snapshot}/sysctl-state.tsv"
}

stop_services_from_file() {
  local services_file="$1"
  [[ -f "${services_file}" ]] || return 0
  local name=""
  local unit=""
  local ownership=""
  while IFS=$'\t' read -r name unit ownership _rest; do
    [[ -n "${unit}" ]] || continue
    "${SYSTEMCTL_BIN}" stop "${unit}" >/dev/null 2>&1 || true
  done <"${services_file}"
}

delete_owned_nftables_runtime() {
  local apply_script="/usr/local/lib/vpn-stack/nft-apply.sh"
  if [[ -x "${apply_script}" ]]; then
    "${apply_script}" --delete >/dev/null 2>&1 || true
  fi
}

restore_service_state() {
  local snapshot="$1"
  [[ -f "${snapshot}/service-state.tsv" ]] || return 0
  local name=""
  local unit=""
  local ownership=""
  local enabled=""
  local active=""
  while IFS=$'\t' read -r name unit ownership enabled active; do
    [[ -n "${unit}" ]] || continue
    case "${enabled}" in
      masked|masked-runtime)
        "${SYSTEMCTL_BIN}" mask "${unit}" >/dev/null
        ;;
      enabled|enabled-runtime)
        "${SYSTEMCTL_BIN}" unmask "${unit}" >/dev/null 2>&1 || true
        "${SYSTEMCTL_BIN}" enable "${unit}" >/dev/null
        ;;
      disabled)
        "${SYSTEMCTL_BIN}" unmask "${unit}" >/dev/null 2>&1 || true
        "${SYSTEMCTL_BIN}" disable "${unit}" >/dev/null 2>&1 || true
        ;;
      *)
        ;;
    esac
    case "${active}" in
      active|activating|reloading)
        "${SYSTEMCTL_BIN}" restart "${unit}" >/dev/null
        ;;
      *)
        "${SYSTEMCTL_BIN}" stop "${unit}" >/dev/null 2>&1 || true
        ;;
    esac
    "${SYSTEMCTL_BIN}" reset-failed "${unit}" >/dev/null 2>&1 || true
  done <"${snapshot}/service-state.tsv"
}

restore_managed_runtime_state() {
  local agent_path="/usr/local/lib/vpn-stack/vpn-stack-agent.py"
  [[ -f "${agent_path}" ]] || return 0
  "${PYTHON_BIN}" "${agent_path}" network-apply >/dev/null ||
    die "restored managed network profile could not be applied"
}

normalize_service_enabled_state() {
  case "$1" in
    enabled|enabled-runtime) printf 'enabled\n' ;;
    masked|masked-runtime) printf 'masked\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

normalize_service_active_state() {
  case "$1" in
    active|activating|reloading) printf 'active\n' ;;
    inactive|failed|deactivating) printf 'inactive\n' ;;
    *) printf '%s\n' "$1" ;;
  esac
}

verify_snapshot_service_states() {
  local snapshot="$1"
  [[ -f "${snapshot}/service-state.tsv" ]] ||
    die "rollback service snapshot is missing: ${snapshot}"
  local name=""
  local unit=""
  local ownership=""
  local expected_enabled=""
  local expected_active=""
  local actual_enabled=""
  local actual_active=""
  while IFS=$'\t' read -r name unit ownership expected_enabled expected_active; do
    [[ -n "${unit}" ]] || continue
    case "${ownership}" in
      managed|borrowed) ;;
      *) die "invalid rollback service ownership for ${unit}: ${ownership:-missing}" ;;
    esac
    actual_enabled="$("${SYSTEMCTL_BIN}" is-enabled "${unit}" 2>/dev/null || true)"
    actual_active="$("${SYSTEMCTL_BIN}" is-active "${unit}" 2>/dev/null || true)"
    actual_enabled="${actual_enabled:-unknown}"
    actual_active="${actual_active:-unknown}"
    [[ "$(normalize_service_enabled_state "${actual_enabled}")" == "$(normalize_service_enabled_state "${expected_enabled}")" ]] ||
      die "restored service enablement differs from snapshot: ${unit} expected=${expected_enabled} actual=${actual_enabled}"
    [[ "$(normalize_service_active_state "${actual_active}")" == "$(normalize_service_active_state "${expected_active}")" ]] ||
      die "restored service activity differs from snapshot: ${unit} expected=${expected_active} actual=${actual_active}"
  done <"${snapshot}/service-state.tsv"
}

restore_snapshot() {
  local snapshot="$1"
  [[ -d "${snapshot}" && -f "${snapshot}/paths.tsv" ]] ||
    die "rollback snapshot is incomplete: ${snapshot}"
  stop_services_from_file "${snapshot}/service-state.tsv"
  delete_owned_nftables_runtime

  local id=""
  local state=""
  local path=""
  while IFS=$'\t' read -r id state path; do
    safe_operational_path "${path}" || die "unsafe rollback path: ${path}"
    if [[ -e "${path}" || -L "${path}" ]]; then
      rm -rf -- "${path}"
    fi
    if [[ "${state}" == "present" ]]; then
      [[ -e "${snapshot}/files/${id}" || -L "${snapshot}/files/${id}" ]] ||
        die "rollback payload is missing for ${path}"
      mkdir -p "$(dirname "${path}")"
      cp -a -- "${snapshot}/files/${id}" "${path}"
    elif [[ "${state}" != "missing" ]]; then
      die "unknown rollback state for ${path}: ${state}"
    fi
  done <"${snapshot}/paths.tsv"

  "${SYSTEMCTL_BIN}" daemon-reload
  restore_sysctl_state "${snapshot}"
  restore_service_state "${snapshot}"
  restore_managed_runtime_state
}

create_transaction_snapshots() {
  local scope_dir="$1"
  local new_bundle="$2"
  local timestamp=""
  timestamp="$(date -u +'%Y%m%dT%H%M%SZ')-$$"
  mkdir -p "${VPNSTACK_BACKUP_DIR}" "${VPNSTACK_REVISION_DIR}"

  capture_snapshot "${VPNSTACK_BASELINE_DIR}" "${scope_dir}" 1
  capture_sysctl_state "${VPNSTACK_BASELINE_DIR}" "${new_bundle}/sysctl-vpn-stack.conf" "/etc/sysctl.d/90-vpn-stack.conf"

  TRANSACTION_SNAPSHOT="${VPNSTACK_REVISION_DIR}/${timestamp}"
  capture_snapshot "${TRANSACTION_SNAPSHOT}" "${scope_dir}" 0
  capture_sysctl_state "${TRANSACTION_SNAPSHOT}" "${new_bundle}/sysctl-vpn-stack.conf" "/etc/sysctl.d/90-vpn-stack.conf"

  local latest_tmp="${VPNSTACK_BACKUP_DIR}/.latest.$$.tmp"
  ln -s "${TRANSACTION_SNAPSHOT}" "${latest_tmp}"
  mv -Tf "${latest_tmp}" "${VPNSTACK_LATEST_SNAPSHOT}"
  TRANSACTION_ACTIVE=1
}

cleanup_work() {
  if [[ -n "${STAGED_RELEASE_DIR}" && -d "${STAGED_RELEASE_DIR}" ]]; then
    case "${STAGED_RELEASE_DIR}" in
      "${VPNSTACK_RELEASES_DIR}"/.staging-*) rm -rf -- "${STAGED_RELEASE_DIR}" ;;
    esac
  fi
  [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]] && rm -rf -- "${WORK_DIR}"
}

on_exit() {
  local status=$?
  trap - EXIT
  if [[ "${status}" -ne 0 && "${TRANSACTION_ACTIVE}" == "1" && -n "${TRANSACTION_SNAPSHOT}" ]]; then
    TRANSACTION_ACTIVE=0
    echo "Installation failed; restoring the pre-install snapshot." >&2
    restore_snapshot "${TRANSACTION_SNAPSHOT}" || status=1
  fi
  if [[ "${status}" -ne 0 && -n "${FAILED_ACCEPTANCE_STASH}" && -f "${FAILED_ACCEPTANCE_STASH}" ]]; then
    install -m 0600 "${FAILED_ACCEPTANCE_STASH}" "${VPNSTACK_FAILED_ACCEPTANCE_PATH}" || status=1
  fi
  cleanup_work
  exit "${status}"
}

install_packages_from_plan() {
  local contract_dir="$1"
  local packages=()
  mapfile -t packages <"${contract_dir}/packages.tsv"
  (("${#packages[@]}" > 0)) || return 0
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
}

verify_sha256() {
  local path="$1"
  local expected="$2"
  "${PYTHON_BIN}" - "${path}" "${expected}" <<'PY'
import hashlib
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected = sys.argv[2]
digest = hashlib.sha256(path.read_bytes()).hexdigest()
if digest != expected:
    raise SystemExit(f"sha256 mismatch for {path.name}: expected {expected}, got {digest}")
PY
}

binary_contract_row() {
  local contract_dir="$1"
  local binary="$2"
  awk -F '\t' -v binary="${binary}" '$1 == binary {print; found=1; exit} END {if (!found) exit 1}' "${contract_dir}/binaries.tsv"
}

reuse_current_binary() {
  local name="$1"
  local expected_sha="$2"
  local destination="$3"
  local current="${VPNSTACK_CURRENT_RELEASE}/bin/${name}"
  [[ -x "${current}" ]] || return 1
  verify_sha256 "${current}" "${expected_sha}" >/dev/null 2>&1 || return 1
  cp -a -- "${current}" "${destination}"
}

stage_sing_box_binary() {
  local version="$1"
  local archive_sha="$2"
  local binary_sha="$3"
  local destination="$4"
  [[ "$(uname -m)" == "x86_64" ]] || die "sing-box pinned package supports x86_64 only"
  if reuse_current_binary "sing-box" "${binary_sha}" "${destination}"; then
    return 0
  fi
  local temp=""
  temp="$(mktemp -d)"
  curl -fsSL --connect-timeout 10 --max-time 120 "https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-amd64.tar.gz" -o "${temp}/sing-box.tar.gz"
  verify_sha256 "${temp}/sing-box.tar.gz" "${archive_sha}"
  tar -xzf "${temp}/sing-box.tar.gz" -C "${temp}"
  install -m 0755 "${temp}/sing-box-${version}-linux-amd64/sing-box" "${destination}"
  verify_sha256 "${destination}" "${binary_sha}"
  rm -rf -- "${temp}"
}

stage_xray_binary() {
  local version="$1"
  local archive_sha="$2"
  local binary_sha="$3"
  local destination="$4"
  [[ "$(uname -m)" == "x86_64" ]] || die "Xray pinned package supports x86_64 only"
  if reuse_current_binary "xray" "${binary_sha}" "${destination}"; then
    return 0
  fi
  local temp=""
  temp="$(mktemp -d)"
  curl -fsSL --connect-timeout 10 --max-time 120 "https://github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-64.zip" -o "${temp}/xray.zip"
  verify_sha256 "${temp}/xray.zip" "${archive_sha}"
  unzip -q "${temp}/xray.zip" xray -d "${temp}"
  install -m 0755 "${temp}/xray" "${destination}"
  verify_sha256 "${destination}" "${binary_sha}"
  rm -rf -- "${temp}"
}

stage_binaries() {
  local release_dir="$1"
  local contract_dir="$2"
  mkdir -p "${release_dir}/bin"
  local name=""
  local version=""
  local archive_sha=""
  local binary_sha=""
  local path=""
  local service=""
  while IFS=$'\t' read -r name version archive_sha binary_sha path service; do
    case "${name}" in
      sing-box)
        stage_sing_box_binary "${version}" "${archive_sha}" "${binary_sha}" "${release_dir}/bin/sing-box"
        ;;
      xray)
        stage_xray_binary "${version}" "${archive_sha}" "${binary_sha}" "${release_dir}/bin/xray"
        ;;
      *)
        die "unknown binary in validated plan: ${name}"
        ;;
    esac
  done <"${contract_dir}/binaries.tsv"
}

copy_planned_assets() {
  local release_dir="$1"
  local source_bundle="$2"
  local contract_dir="$3"
  local name=""
  local path=""
  local ownership=""
  local expected_sha=""
  while IFS=$'\t' read -r name path ownership expected_sha; do
    [[ -n "${name}" ]] || continue
    local source=""
    if [[ -f "${source_bundle}/assets/${name}" ]]; then
      source="${source_bundle}/assets/${name}"
    elif [[ -n "${ASSETS_DIR}" && -f "${ASSETS_DIR}/${name}" ]]; then
      source="${ASSETS_DIR}/${name}"
    else
      die "required asset is missing: ${name}"
    fi
    mkdir -p "${release_dir}/assets"
    cp -a -- "${source}" "${release_dir}/assets/${name}"
    verify_sha256 "${release_dir}/assets/${name}" "${expected_sha}"
  done <"${contract_dir}/assets.tsv"
}

record_runtime_manifest_facts() {
  local release_dir="$1"
  "${PYTHON_BIN}" - "${release_dir}/render-manifest.json" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
manifest = json.loads(path.read_text(encoding="utf-8"))
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
temporary = path.with_name(path.name + ".tmp")
temporary.write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
os.replace(temporary, path)
PY
}

stage_release() {
  local source_bundle="$1"
  local contract_dir="$2"
  local release_id=""
  release_id="$(contract_value "${contract_dir}" release_id)"
  STAGED_RELEASE_DIR="${VPNSTACK_RELEASES_DIR}/.staging-${release_id}-$$"
  mkdir -p "${VPNSTACK_RELEASES_DIR}"
  [[ ! -e "${STAGED_RELEASE_DIR}" ]] || die "staging directory already exists"
  mkdir -p "${STAGED_RELEASE_DIR}"

  local name=""
  local path=""
  local ownership=""
  local digest=""
  local capability=""
  while IFS=$'\t' read -r name path ownership digest capability; do
    cp -a -- "${source_bundle}/${name}" "${STAGED_RELEASE_DIR}/${name}"
  done <"${contract_dir}/artifacts.tsv"
  cp -a -- "${source_bundle}/render-manifest.json" "${STAGED_RELEASE_DIR}/render-manifest.json"
  cp -a -- "${source_bundle}/install-plan.json" "${STAGED_RELEASE_DIR}/install-plan.json"
  copy_planned_assets "${STAGED_RELEASE_DIR}" "${source_bundle}" "${contract_dir}"
  stage_binaries "${STAGED_RELEASE_DIR}" "${contract_dir}"
  record_runtime_manifest_facts "${STAGED_RELEASE_DIR}"

  find "${STAGED_RELEASE_DIR}" -type d -exec chmod 0755 {} +
  find "${STAGED_RELEASE_DIR}" -type f -exec chmod 0644 {} +
  find "${STAGED_RELEASE_DIR}" -maxdepth 1 -type f \( -name '*.py' -o -name '*.sh' \) -exec chmod 0755 {} +
  find "${STAGED_RELEASE_DIR}/bin" -type f -exec chmod 0755 {} +
  chmod 0600 "${STAGED_RELEASE_DIR}/node.env" "${STAGED_RELEASE_DIR}/sing-box.json"
  [[ ! -f "${STAGED_RELEASE_DIR}/xray.json" ]] || chmod 0600 "${STAGED_RELEASE_DIR}/xray.json"
  while IFS=$'\t' read -r name path ownership digest capability; do
    case "${path}" in
      /etc/wireguard/*.conf) chmod 0600 "${STAGED_RELEASE_DIR}/${name}" ;;
    esac
  done <"${contract_dir}/artifacts.tsv"
}

validate_staged_payloads() {
  local release_dir="$1"
  local contract_dir="$2"
  "${PYTHON_BIN}" - "${release_dir}" "${contract_dir}" <<'PY'
import configparser
import sys
from pathlib import Path

root = Path(sys.argv[1])
contract = Path(sys.argv[2])
for raw in (contract / "artifacts.tsv").read_text(encoding="utf-8").splitlines():
    if not raw:
        continue
    name = raw.split("\t", 1)[0]
    path = root / name
    if name.endswith(".py"):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    if name.endswith((".service", ".timer")):
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.optionxform = str
        parser.read(path, encoding="utf-8")
        required = {"Unit", "Timer" if name.endswith(".timer") else "Service"}
        missing = required - set(parser.sections())
        if missing:
            raise SystemExit(f"invalid systemd unit {name}: missing {sorted(missing)}")
PY

  local name=""
  local path=""
  local ownership=""
  local digest=""
  local capability=""
  while IFS=$'\t' read -r name path ownership digest capability; do
    case "${name}" in
      *.sh) bash -n "${release_dir}/${name}" ;;
    esac
    case "${path}" in
      /etc/wireguard/*.conf)
        wg-quick strip "${release_dir}/${name}" >/dev/null
        ;;
    esac
  done <"${contract_dir}/artifacts.tsv"

  local binary=""
  local version=""
  local archive_sha=""
  local binary_sha=""
  local binary_path=""
  local service=""
  while IFS=$'\t' read -r binary version archive_sha binary_sha binary_path service; do
    verify_sha256 "${release_dir}/bin/${binary}" "${binary_sha}"
    case "${binary}" in
      sing-box)
        "${release_dir}/bin/sing-box" version 2>&1 | head -n 3 | grep -F "${version}" >/dev/null ||
          die "staged sing-box version mismatch"
        ;;
      xray)
        "${release_dir}/bin/xray" version 2>&1 | head -n 3 | grep -F "${version}" >/dev/null ||
          die "staged Xray version mismatch"
        ;;
      *)
        die "unknown staged binary: ${binary}"
        ;;
    esac
  done <"${contract_dir}/binaries.tsv"

  local check_config="${release_dir}/.sing-box-check.json"
  "${PYTHON_BIN}" - "${release_dir}" "${check_config}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
destination = Path(sys.argv[2])
manifest = json.loads((root / "render-manifest.json").read_text(encoding="utf-8"))
config = json.loads((root / "sing-box.json").read_text(encoding="utf-8"))
for item in config.get("route", {}).get("rule_set", []):
    path = Path(str(item.get("path", "")))
    if path.name in manifest.get("assets", {}):
        item["path"] = str(root / "assets" / path.name)
destination.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
  "${release_dir}/bin/sing-box" check -c "${check_config}"
  rm -f -- "${check_config}"

  if [[ -x "${release_dir}/vpn-stack-nft-apply.sh" && -f "${release_dir}/nftables.conf" ]]; then
    "${release_dir}/vpn-stack-nft-apply.sh" --check "${release_dir}/nftables.conf"
  fi
  if [[ -x "${release_dir}/bin/xray" ]]; then
    [[ -f "${release_dir}/xray.json" ]] || die "Xray binary is planned without xray.json"
    "${release_dir}/bin/xray" run -test -c "${release_dir}/xray.json"
  fi
}

release_tree_digest() {
  local release_dir="$1"
  "${PYTHON_BIN}" -c \
    'import sys; sys.path.insert(0, sys.argv[1]); from vpn_installer.release_integrity import main; raise SystemExit(main(sys.argv[2:]))' \
    "${SCRIPT_DIR}" "${release_dir}"
}

publish_staged_release() {
  local release_dir="$1"
  local contract_dir="$2"
  local release_id=""
  local tree_digest=""
  release_id="$(contract_value "${contract_dir}" release_id)"
  tree_digest="$(release_tree_digest "${release_dir}")"
  PUBLISHED_RELEASE_DIR="${VPNSTACK_RELEASES_DIR}/${release_id}-${tree_digest:0:12}"
  if [[ -e "${PUBLISHED_RELEASE_DIR}" ]]; then
    [[ -d "${PUBLISHED_RELEASE_DIR}" ]] || die "release path is not a directory"
    diff -qr "${release_dir}" "${PUBLISHED_RELEASE_DIR}" >/dev/null ||
      die "immutable release collision: ${PUBLISHED_RELEASE_DIR}"
    rm -rf -- "${release_dir}"
  else
    mv -- "${release_dir}" "${PUBLISHED_RELEASE_DIR}"
  fi
  STAGED_RELEASE_DIR=""
}

manifest_schema() {
  local manifest="$1"
  "${PYTHON_BIN}" - "${manifest}" <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(value.get("schema_version", 0))
PY
}

manifest_node() {
  local manifest="$1"
  "${PYTHON_BIN}" - "${manifest}" <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
node = value.get("node_id") or (value.get("node") or {}).get("id")
if node not in {"gateway", "exit"}:
    raise SystemExit("manifest has no canonical node")
print(node)
PY
}

PREVIOUS_CONTRACT=""

prepare_previous_contract() {
  local current=""
  if [[ ! -L "${VPNSTACK_CURRENT_RELEASE}" ]]; then
    return 0
  fi
  current="$(readlink -f "${VPNSTACK_CURRENT_RELEASE}")"
  [[ -d "${current}" && -f "${current}/render-manifest.json" ]] ||
    die "current release link is incomplete"
  PREVIOUS_RELEASE_DIR="${current}"
  local schema=""
  schema="$(manifest_schema "${current}/render-manifest.json")"
  if [[ "${schema}" == "3" ]]; then
    local current_node=""
    current_node="$(manifest_node "${current}/render-manifest.json")"
    PREVIOUS_CONTRACT="${WORK_DIR}/previous-contract"
    validate_bundle "${current}" "${current_node}" "${PREVIOUS_CONTRACT}" "" 1 1
  elif [[ "${schema}" == "2" ]]; then
    [[ -f "${VPNSTACK_DEPLOYMENT_PATH}" ]] ||
      die "schema-2 deployment metadata is missing: ${VPNSTACK_DEPLOYMENT_PATH}"
    PREVIOUS_CONTRACT="${WORK_DIR}/previous-contract"
    adapt_schema2_contract "${current}" "${VPNSTACK_DEPLOYMENT_PATH}" "${PREVIOUS_CONTRACT}"
  else
    die "unsupported installed manifest schema: ${schema}"
  fi
}

contract_artifact_path() {
  local contract_dir="$1"
  local name="$2"
  awk -F '\t' -v name="${name}" '$1 == name {print $2; found=1; exit} END {if (!found) exit 1}' "${contract_dir}/artifacts.tsv"
}

previous_owned_entry() {
  local contract_dir="$1"
  local path="$2"
  local row=""
  [[ -n "${contract_dir}" && -d "${contract_dir}" ]] || return 1
  row="$(awk -F '\t' -v path="${path}" '$2 == path && $3 == "managed" {print "artifact\t" $1 "\t" $4; found=1; exit} END {if (!found) exit 1}' "${contract_dir}/artifacts.tsv" 2>/dev/null || true)"
  if [[ -z "${row}" ]]; then
    row="$(awk -F '\t' -v path="${path}" '$2 == path && $3 == "managed" {print "asset\t" $1 "\t" $4; found=1; exit} END {if (!found) exit 1}' "${contract_dir}/assets.tsv" 2>/dev/null || true)"
  fi
  if [[ -z "${row}" && "${path}" == "${VPNSTACK_MANIFEST_PATH}" ]]; then
    row=$'control\trender-manifest.json\t'
  elif [[ -z "${row}" && "${path}" == "${VPNSTACK_INSTALL_PLAN_PATH}" ]]; then
    row=$'control\tinstall-plan.json\t'
  fi
  [[ -n "${row}" ]] || return 1
  printf '%s\n' "${row}"
}

verify_previous_owned_path() {
  local contract_dir="$1"
  local path="$2"
  local row=""
  local kind=""
  local name=""
  local digest=""
  local expected=""
  row="$(previous_owned_entry "${contract_dir}" "${path}" || true)"
  [[ -n "${row}" ]] ||
    die "refusing to overwrite a path without previous manifest ownership: ${path}"
  IFS=$'\t' read -r kind name digest <<<"${row}"
  case "${kind}" in
    artifact|control) expected="${PREVIOUS_RELEASE_DIR}/${name}" ;;
    asset) expected="${PREVIOUS_RELEASE_DIR}/assets/${name}" ;;
    *) die "invalid previous ownership kind for ${path}: ${kind}" ;;
  esac

  if [[ -L "${path}" ]]; then
    [[ -e "${expected}" ]] ||
      die "previous release payload is missing for managed symlink: ${path}"
    [[ "$(readlink -f "${path}")" == "$(readlink -f "${expected}")" ]] ||
      die "managed symlink was modified; refusing overwrite: ${path}"
    return 0
  fi
  [[ -f "${path}" ]] ||
    die "managed path has an unexpected type; refusing overwrite: ${path}"
  if [[ -f "${expected}" ]]; then
    cmp -s -- "${path}" "${expected}" ||
      die "managed file was modified; refusing overwrite: ${path}"
    return 0
  fi
  [[ -n "${digest}" ]] ||
    die "previous payload is missing and no digest is available for ${path}"
  verify_sha256 "${path}" "${digest}" >/dev/null ||
    die "managed file was modified; refusing overwrite: ${path}"
}

atomic_managed_link() {
  local target="$1"
  local path="$2"
  local previous_contract="$3"
  safe_operational_path "${path}" || die "unsafe managed link path: ${path}"
  mkdir -p "$(dirname "${path}")"

  if [[ -L "${path}" && "$(readlink "${path}")" == "${target}" ]]; then
    return 0
  fi
  if [[ -e "${path}" || -L "${path}" ]]; then
    verify_previous_owned_path "${previous_contract}" "${path}"
    rm -rf -- "${path}"
  fi
  local temporary="$(dirname "${path}")/.$(basename "${path}").vpn-stack.$$"
  ln -s "${target}" "${temporary}"
  mv -Tf "${temporary}" "${path}"
}

install_planned_links() {
  local contract_dir="$1"
  local previous_contract="$2"
  local name=""
  local path=""
  local ownership=""
  local digest=""
  local capability=""
  while IFS=$'\t' read -r name path ownership digest capability; do
    [[ "${ownership}" == "managed" ]] || die "unknown artifact ownership: ${ownership}"
    atomic_managed_link "${VPNSTACK_CURRENT_RELEASE}/${name}" "${path}" "${previous_contract}"
  done <"${contract_dir}/artifacts.tsv"
  while IFS=$'\t' read -r name path ownership digest; do
    [[ "${ownership}" == "managed" ]] || die "unknown asset ownership: ${ownership}"
    atomic_managed_link "${VPNSTACK_CURRENT_RELEASE}/assets/${name}" "${path}" "${previous_contract}"
  done <"${contract_dir}/assets.tsv"
  atomic_managed_link "${VPNSTACK_CURRENT_RELEASE}/render-manifest.json" "${VPNSTACK_MANIFEST_PATH}" "${previous_contract}"
  atomic_managed_link "${VPNSTACK_CURRENT_RELEASE}/install-plan.json" "${VPNSTACK_INSTALL_PLAN_PATH}" "${previous_contract}"
}

switch_current_release() {
  local release_dir="$1"
  local current_tmp="${VPNSTACK_ROOT}/.current.$$.tmp"
  local previous_tmp="${VPNSTACK_ROOT}/.previous.$$.tmp"
  local current=""
  if [[ -L "${VPNSTACK_CURRENT_RELEASE}" ]]; then
    current="$(readlink -f "${VPNSTACK_CURRENT_RELEASE}")"
  fi
  if [[ -n "${current}" && -d "${current}" ]]; then
    ln -s "${current}" "${previous_tmp}"
    mv -Tf "${previous_tmp}" "${VPNSTACK_PREVIOUS_RELEASE}"
  fi
  ln -s "${release_dir}" "${current_tmp}"
  mv -Tf "${current_tmp}" "${VPNSTACK_CURRENT_RELEASE}"
}

new_contract_has_unit() {
  local contract_dir="$1"
  local unit="$2"
  awk -F '\t' -v unit="${unit}" '$2 == unit {found=1} END {exit !found}' "${contract_dir}/services.tsv"
}

retire_previous_services() {
  local previous_contract="$1"
  local new_contract="$2"
  [[ -n "${previous_contract}" ]] || return 0
  local name=""
  local unit=""
  local ownership=""
  while IFS=$'\t' read -r name unit ownership; do
    new_contract_has_unit "${new_contract}" "${unit}" && continue
    [[ "${ownership}" == "managed" ]] ||
      die "refusing to retire borrowed service: ${unit}"
    "${SYSTEMCTL_BIN}" disable --now "${unit}" >/dev/null
  done <"${previous_contract}/services.tsv"
}

safe_remove_previous_payload() {
  local name="$1"
  local path="$2"
  local digest="$3"
  local asset="${4:-0}"
  safe_operational_path "${path}" || die "unsafe retired path: ${path}"
  [[ -e "${path}" || -L "${path}" ]] || return 0
  local expected_target="${VPNSTACK_CURRENT_RELEASE}/${name}"
  [[ "${asset}" != "1" ]] || expected_target="${VPNSTACK_CURRENT_RELEASE}/assets/${name}"
  if [[ -L "${path}" && "$(readlink "${path}")" == "${expected_target}" ]]; then
    rm -- "${path}"
    return 0
  fi
  if [[ -f "${path}" ]]; then
    verify_sha256 "${path}" "${digest}" >/dev/null 2>&1 ||
      die "retired managed path was modified; refusing removal: ${path}"
    rm -- "${path}"
    return 0
  fi
  die "retired managed path has an unexpected type: ${path}"
}

retire_previous_payloads() {
  local previous_contract="$1"
  local new_contract="$2"
  [[ -n "${previous_contract}" ]] || return 0
  local name=""
  local path=""
  local ownership=""
  local digest=""
  local capability=""
  while IFS=$'\t' read -r name path ownership digest capability; do
    contract_has_path "${new_contract}" "${path}" && continue
    [[ "${ownership}" == "managed" ]] ||
      die "refusing to remove borrowed artifact: ${path}"
    safe_remove_previous_payload "${name}" "${path}" "${digest}" 0
  done <"${previous_contract}/artifacts.tsv"
  while IFS=$'\t' read -r name path ownership digest; do
    contract_has_path "${new_contract}" "${path}" && continue
    [[ "${ownership}" == "managed" ]] ||
      die "refusing to remove borrowed asset: ${path}"
    safe_remove_previous_payload "${name}" "${path}" "${digest}" 1
  done <"${previous_contract}/assets.tsv"
}

record_install_metadata() {
  local node="$1"
  printf '%s\n' "${node}" >"${VPNSTACK_NODE_PATH}"
  date -u +'%Y-%m-%dT%H:%M:%SZ' >"${VPNSTACK_INSTALLED_AT_PATH}"
  rm -f -- "${VPNSTACK_REMOVED_AT_PATH}" "${VPNSTACK_LEGACY_ROLE_PATH}" "${VPNSTACK_LEGACY_INSTALLED_AT_PATH}"
  chmod 0644 "${VPNSTACK_NODE_PATH}" "${VPNSTACK_INSTALLED_AT_PATH}"
}

apply_planned_host_files() {
  local contract_dir="$1"
  local modules_path=""
  local sysctl_path=""
  modules_path="$(contract_artifact_path "${contract_dir}" modules-vpn-stack.conf || true)"
  if [[ -n "${modules_path}" ]]; then
    local module=""
    while IFS= read -r module; do
      module="${module%%#*}"
      module="${module//[[:space:]]/}"
      [[ -n "${module}" ]] || continue
      modprobe "${module}"
    done <"${modules_path}"
  fi
  sysctl_path="$(contract_artifact_path "${contract_dir}" sysctl-vpn-stack.conf || true)"
  if [[ -n "${sysctl_path}" ]]; then
    sysctl -q -p "${sysctl_path}" >/dev/null
  fi
  if contract_artifact_path "${contract_dir}" sshd-vpn-stack.conf >/dev/null 2>&1; then
    sshd -t
  fi
}

service_row() {
  local contract_dir="$1"
  local name="$2"
  awk -F '\t' -v name="${name}" '$1 == name {print; found=1; exit} END {if (!found) exit 1}' "${contract_dir}/services.tsv"
}

start_one_planned_service() {
  local name="$1"
  local unit="$2"
  local ownership="$3"
  case "${ownership}" in
    managed)
      "${SYSTEMCTL_BIN}" enable "${unit}" >/dev/null
      "${SYSTEMCTL_BIN}" restart "${unit}"
      ;;
    borrowed)
      "${SYSTEMCTL_BIN}" restart "${unit}"
      ;;
    *)
      die "unknown service ownership: ${ownership}"
      ;;
  esac
}

start_planned_services() {
  local contract_dir="$1"
  local agent_path=""
  local network_applied=0
  local order=(resolver nftables wireguard sing-box transport xray admin health_timer)
  local name=""
  local row=""
  local unit=""
  local ownership=""
  for name in "${order[@]}"; do
    if [[ "${name}" == "sing-box" && "${network_applied}" == "0" ]]; then
      agent_path="$(contract_artifact_path "${contract_dir}" vpn-stack-agent.py)"
      "${PYTHON_BIN}" "${agent_path}" network-apply >/dev/null
      network_applied=1
    fi
    row="$(service_row "${contract_dir}" "${name}" || true)"
    [[ -n "${row}" ]] || continue
    IFS=$'\t' read -r _name unit ownership <<<"${row}"
    start_one_planned_service "${name}" "${unit}" "${ownership}"
  done
  [[ "${network_applied}" == "1" ]] || die "sing-box service is absent from the plan"
}

verify_active_release() {
  local contract_dir="$1"
  local agent_path=""
  local report_tmp="${VPNSTACK_ROOT}/.acceptance.$$.json"
  rm -f -- "${VPNSTACK_ROOT}"/.acceptance.*.json
  agent_path="$(contract_artifact_path "${contract_dir}" vpn-stack-agent.py)"
  "${PYTHON_BIN}" "${agent_path}" snapshot --live-probes --profile acceptance >"${report_tmp}"
  if ! "${PYTHON_BIN}" - "${report_tmp}" "${PUBLISHED_RELEASE_DIR}/render-manifest.json" "${SCRIPT_DIR}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, sys.argv[3])
from vpn_installer.install_contract import is_planned_install_maintenance

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if payload.get("schema_version") != 4:
    raise SystemExit("post-activation agent did not return diagnostics schema 4")
for field in ("topology", "node_id", "location", "capabilities"):
    if payload.get(field) != manifest.get(field):
        raise SystemExit(f"post-activation canonical field mismatch: {field}")
try:
    generated = datetime.fromisoformat(str(payload["generated_at"]).replace("Z", "+00:00"))
except (KeyError, TypeError, ValueError) as exc:
    raise SystemExit("post-activation timestamp is invalid") from exc
age = (datetime.now(timezone.utc) - generated.astimezone(timezone.utc)).total_seconds()
if age < -30 or age > 180:
    raise SystemExit(f"post-activation snapshot is stale: {age:.1f}s")
collectors = payload.get("collectors")
if not isinstance(collectors, dict) or not collectors:
    raise SystemExit("post-activation collectors are missing")
invalid_collectors = {
    name: value
    for name, value in collectors.items()
    if not isinstance(value, dict) or value.get("status") not in {"ok", "not_applicable"}
}
if invalid_collectors:
    raise SystemExit(f"post-activation collectors failed: {invalid_collectors}")
required_services = manifest.get("required_services", [])
services = payload.get("services", {})
failed_services = {name: services.get(name) for name in required_services if services.get(name) != "active"}
if failed_services:
    raise SystemExit(f"post-activation services failed: {failed_services}")
verdicts = payload.get("component_verdicts", {})
if verdicts.get("server_path") != "verified":
    raise SystemExit(f"post-activation server path failed: {payload.get('reasons', [])}")
if "public-front" in manifest.get("capabilities", []) and verdicts.get("public_front") != "verified":
    raise SystemExit("post-activation public front is not verified")
if verdicts.get("host_integrity") != "verified":
    raise SystemExit(f"post-activation host integrity is {verdicts.get('host_integrity')}")
if payload.get("artifacts", {}).get("drift") != "none":
    raise SystemExit("post-activation artifact drift detected")
if payload.get("network", {}).get("profile_mismatches"):
    raise SystemExit("post-activation network profile drift detected")
if payload.get("verdict") != "verified" and not is_planned_install_maintenance(payload):
    raise SystemExit(f"post-activation verdict is {payload.get('verdict')}: {payload.get('reasons', [])}")
PY
  then
    FAILED_ACCEPTANCE_STASH="${WORK_DIR}/failed-acceptance.json"
    mv -f -- "${report_tmp}" "${FAILED_ACCEPTANCE_STASH}"
    return 1
  fi
  mv -f -- "${report_tmp}" "${VPNSTACK_ACCEPTANCE_PATH}"
  rm -f -- "${VPNSTACK_FAILED_ACCEPTANCE_PATH}"
}

verify_target_units() {
  local contract_dir="$1"
  command -v systemd-analyze >/dev/null 2>&1 || return 0
  local name=""
  local unit=""
  local ownership=""
  local path=""
  while IFS=$'\t' read -r name unit ownership; do
    [[ "${ownership}" == "managed" ]] || continue
    path="/etc/systemd/system/${unit}"
    contract_has_path "${contract_dir}" "${path}" || continue
    systemd-analyze verify "${path}" >/dev/null
  done <"${contract_dir}/services.tsv"
}

install_action() {
  [[ -n "${NODE}" ]] || die "--node is required for ${ACTION}"
  [[ -n "${ENV_FILE}" ]] || die "--env-file is required for ${ACTION}"
  [[ -f "${ENV_FILE}" ]] || die "env file not found: ${ENV_FILE}"
  if [[ -n "${ASSETS_DIR}" && ! -d "${ASSETS_DIR}" ]]; then
    die "assets directory not found: ${ASSETS_DIR}"
  fi
  if [[ "${ACTION}" == "reinstall" && ! -L "${VPNSTACK_CURRENT_RELEASE}" ]]; then
    die "reinstall requires an installed current release"
  fi

  WORK_DIR="$(mktemp -d)"
  local source_bundle="${WORK_DIR}/rendered"
  local source_contract="${WORK_DIR}/source-contract"
  local staged_contract="${WORK_DIR}/staged-contract"
  local scope_dir="${WORK_DIR}/scope"

  render_node_bundle "${source_bundle}"
  validate_bundle "${source_bundle}" "${NODE}" "${source_contract}" "${ASSETS_DIR}" 1 0
  prepare_previous_contract
  if [[ -n "${PREVIOUS_CONTRACT}" ]]; then
    local previous_deployment=""
    local requested_deployment=""
    local previous_node=""
    local requested_node=""
    previous_deployment="$(contract_value "${PREVIOUS_CONTRACT}" deployment)"
    requested_deployment="$(contract_value "${source_contract}" deployment)"
    [[ "${previous_deployment}" == "${requested_deployment}" ]] ||
      die "installed deployment ${previous_deployment} does not match requested deployment ${requested_deployment}"
    previous_node="$(contract_value "${PREVIOUS_CONTRACT}" node_id)"
    requested_node="$(contract_value "${source_contract}" node_id)"
    [[ "${previous_node}" == "${requested_node}" ]] ||
      die "installed node ${previous_node} does not match requested node ${requested_node}"
  fi

  # APT packages are monotonic host prerequisites, outside managed release rollback.
  install_packages_from_plan "${source_contract}"
  build_operation_scope "${source_contract}" "${PREVIOUS_CONTRACT}" "${scope_dir}"
  create_transaction_snapshots "${scope_dir}" "${source_bundle}"

  stage_release "${source_bundle}" "${source_contract}"
  validate_bundle "${STAGED_RELEASE_DIR}" "${NODE}" "${staged_contract}" "" 1 1
  validate_staged_payloads "${STAGED_RELEASE_DIR}" "${staged_contract}"
  publish_staged_release "${STAGED_RELEASE_DIR}" "${staged_contract}"

  install_planned_links "${staged_contract}" "${PREVIOUS_CONTRACT}"
  switch_current_release "${PUBLISHED_RELEASE_DIR}"

  "${SYSTEMCTL_BIN}" daemon-reload
  verify_target_units "${staged_contract}"
  apply_planned_host_files "${staged_contract}"
  start_planned_services "${staged_contract}"
  retire_previous_services "${PREVIOUS_CONTRACT}" "${staged_contract}"
  retire_previous_payloads "${PREVIOUS_CONTRACT}" "${staged_contract}"
  record_install_metadata "${NODE}"
  verify_active_release "${staged_contract}"
  rm -f -- "${VPNSTACK_LEGACY_ACCEPTANCE_PATH}"

  TRANSACTION_ACTIVE=0
  echo "Installed node ${NODE} from schema-3 plan $(contract_value "${staged_contract}" release_id)."
}

current_release_contract() {
  local output_contract="$1"
  [[ -L "${VPNSTACK_CURRENT_RELEASE}" ]] || die "no current release is installed"
  local current=""
  current="$(readlink -f "${VPNSTACK_CURRENT_RELEASE}")"
  [[ -d "${current}" ]] || die "current release link is invalid"
  local schema=""
  schema="$(manifest_schema "${current}/render-manifest.json")"
  [[ "${schema}" == "3" ]] ||
    die "operation requires explicit schema-3 ownership; installed schema is ${schema}"
  local current_node=""
  current_node="$(manifest_node "${current}/render-manifest.json")"
  if [[ -n "${NODE}" && "${NODE}" != "${current_node}" ]]; then
    die "installed node is ${current_node}, not ${NODE}"
  fi
  NODE="${current_node}"
  validate_bundle "${current}" "${NODE}" "${output_contract}" "" 1 1
}

rollback_action() {
  [[ -L "${VPNSTACK_LATEST_SNAPSHOT}" ]] || die "no rollback snapshot is available"
  local snapshot=""
  snapshot="$(readlink -f "${VPNSTACK_LATEST_SNAPSHOT}")"
  case "${snapshot}" in
    "${VPNSTACK_REVISION_DIR}"/*) ;;
    *) die "rollback snapshot points outside the revision directory" ;;
  esac
  restore_snapshot "${snapshot}"
  verify_snapshot_service_states "${snapshot}"

  if [[ -L "${VPNSTACK_CURRENT_RELEASE}" ]]; then
    WORK_DIR="$(mktemp -d)"
    local contract="${WORK_DIR}/rollback-contract"
    local current=""
    current="$(readlink -f "${VPNSTACK_CURRENT_RELEASE}")"
    local schema=""
    schema="$(manifest_schema "${current}/render-manifest.json")"
    if [[ "${schema}" == "3" ]]; then
      local current_node=""
      current_node="$(manifest_node "${current}/render-manifest.json")"
      validate_bundle "${current}" "${current_node}" "${contract}" "" 1 1
      PUBLISHED_RELEASE_DIR="${current}"
      verify_active_release "${contract}"
    elif [[ "${schema}" == "2" ]]; then
      [[ -f "${VPNSTACK_DEPLOYMENT_PATH}" ]] ||
        die "restored schema-2 deployment metadata is missing"
      adapt_schema2_contract "${current}" "${VPNSTACK_DEPLOYMENT_PATH}" "${contract}"
      NODE="$(contract_value "${contract}" node_id)"
    else
      die "rollback restored unsupported manifest schema: ${schema}"
    fi
  fi
  echo "Rollback snapshot restored: ${snapshot}"
}

remove_action() {
  WORK_DIR="$(mktemp -d)"
  local current_contract="${WORK_DIR}/current-contract"
  local scope_dir="${WORK_DIR}/scope"
  local current=""
  current_release_contract "${current_contract}"
  current="$(readlink -f "${VPNSTACK_CURRENT_RELEASE}")"
  build_operation_scope "" "${current_contract}" "${scope_dir}"
  create_transaction_snapshots "${scope_dir}" "${current}"
  restore_snapshot "${VPNSTACK_BASELINE_DIR}"
  mkdir -p "${VPNSTACK_ROOT}"
  date -u +'%Y-%m-%dT%H:%M:%SZ' >"${VPNSTACK_REMOVED_AT_PATH}"
  TRANSACTION_ACTIVE=0

  if [[ "${ACTION}" == "purge" ]]; then
    case "${VPNSTACK_ROOT}" in
      /etc/vpn-stack|*/vpn-stack) ;;
      *) die "refusing to purge unsafe vpn-stack root: ${VPNSTACK_ROOT}" ;;
    esac
    rm -rf -- "${VPNSTACK_ROOT}"
    echo "Purged schema-3 managed node ${NODE}."
  else
    echo "Removed schema-3 managed node ${NODE}; releases and rollback data were retained."
  fi
}

status_action() {
  [[ -f "${VPNSTACK_MANIFEST_PATH}" ]] || die "vpn-stack is not installed"
  local agent="/usr/local/lib/vpn-stack/vpn-stack-agent.py"
  if [[ -f "${agent}" ]]; then
    "${PYTHON_BIN}" "${agent}" snapshot --compact
    return 0
  fi
  "${PYTHON_BIN}" - "${VPNSTACK_MANIFEST_PATH}" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = {
    "schema_version": manifest.get("schema_version"),
    "version": manifest.get("version"),
    "release_id": manifest.get("release_id"),
    "topology": manifest.get("topology"),
    "node_id": manifest.get("node_id"),
    "location": manifest.get("location"),
    "capabilities": manifest.get("capabilities"),
}
print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
PY
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "action ${ACTION} must run as root"
}

acquire_install_lock() {
  command -v flock >/dev/null 2>&1 || die "flock is required before installation"
  mkdir -p "$(dirname "${INSTALL_LOCK_PATH}")"
  exec 9>"${INSTALL_LOCK_PATH}"
  flock -w 60 9 || die "another vpn-stack installation did not finish within 60 seconds"
}

main() {
  parse_cli "$@"
  find_python

  if [[ "${RENDER_ONLY}" == "1" ]]; then
    render_only_action
    return 0
  fi

  if [[ -z "${NODE}" && "${ACTION}" != "install" && "${ACTION}" != "reinstall" ]]; then
    NODE="$(infer_installed_node || true)"
  fi

  case "${ACTION}" in
    status)
      status_action
      ;;
    install|reinstall)
      require_root
      acquire_install_lock
      trap on_exit EXIT
      install_action
      ;;
    rollback)
      require_root
      acquire_install_lock
      trap on_exit EXIT
      rollback_action
      ;;
    remove|purge)
      require_root
      acquire_install_lock
      trap on_exit EXIT
      remove_action
      ;;
  esac
}

if [[ "${VPNSTACK_INSTALL_LIBRARY_ONLY:-0}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi

main "$@"
