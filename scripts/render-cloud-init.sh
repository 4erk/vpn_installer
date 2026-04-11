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
OUT_DIR="${ROOT_DIR}/out/${DEPLOY_NAME}"
SERVER_DIR="${OUT_DIR}/server"
CLOUD_INIT_DIR="${OUT_DIR}/cloud-init"

mkdir -p "${CLOUD_INIT_DIR}"

if [[ ! -f "${SERVER_DIR}/ru.env" || ! -f "${SERVER_DIR}/foreign.env" ]]; then
  bash "${ROOT_DIR}/scripts/render-config.sh" "$ENV_FILE"
fi

bash "${ROOT_DIR}/scripts/fetch-assets.sh" "$ENV_FILE" >/dev/null || true

emit_asset_write_files() {
  local deploy_assets_dir="$1"
  local asset_path
  local asset_name
  local asset_b64

  for asset_path in \
    "${deploy_assets_dir}/geosite-ru.srs" \
    "${deploy_assets_dir}/geoip-ru.srs" \
    "${deploy_assets_dir}/ru-ipv4.zone" \
    "${deploy_assets_dir}/ru-ipv6.zone"; do
    if [[ -f "${asset_path}" ]]; then
      asset_name="$(basename "${asset_path}")"
      asset_b64="$(base64 -w0 < "${asset_path}")"
      cat <<EOF
  - path: /root/vpn-stack/assets/${asset_name}
    permissions: '0644'
    encoding: b64
    content: ${asset_b64}
EOF
    fi
  done
}

render_cloud_init() {
  local role="$1"
  local env_path="$2"
  local output_path="$3"
  local install_b64
  local env_b64
  local assets_snippet
  local deploy_assets_dir

  install_b64="$(base64 -w0 < "${ROOT_DIR}/install.sh")"
  env_b64="$(base64 -w0 < "${env_path}")"
  deploy_assets_dir="${OUT_DIR}/assets"
  assets_snippet="$(emit_asset_write_files "${deploy_assets_dir}")"

  cat >"${output_path}" <<EOF
#cloud-config
package_update: true
write_files:
  - path: /root/vpn-stack/install.sh
    permissions: '0755'
    encoding: b64
    content: ${install_b64}
  - path: /root/vpn-stack/deployment.env
    permissions: '0600'
    encoding: b64
    content: ${env_b64}
${assets_snippet}
runcmd:
  - [bash, -lc, "cd /root/vpn-stack && ./install.sh --role ${role} --env-file /root/vpn-stack/deployment.env --assets-dir /root/vpn-stack/assets"]
EOF
}

render_cloud_init "ru-gateway" "${SERVER_DIR}/ru.env" "${CLOUD_INIT_DIR}/ru.yaml"
render_cloud_init "foreign-exit" "${SERVER_DIR}/foreign.env" "${CLOUD_INIT_DIR}/foreign.yaml"

echo "Generated cloud-init files in ${CLOUD_INIT_DIR}"
