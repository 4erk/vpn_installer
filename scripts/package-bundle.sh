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
ASSETS_DIR="${OUT_DIR}/assets"
BUNDLE_DIR="${OUT_DIR}/bundle"

bash "${ROOT_DIR}/scripts/render-config.sh" "$ENV_FILE" >/dev/null
bash "${ROOT_DIR}/scripts/fetch-assets.sh" "$ENV_FILE" >/dev/null || true

mkdir -p "${BUNDLE_DIR}/ru-gateway/assets" "${BUNDLE_DIR}/foreign-exit/assets"

cp "${ROOT_DIR}/install.sh" "${BUNDLE_DIR}/ru-gateway/install.sh"
cp "${ROOT_DIR}/install.sh" "${BUNDLE_DIR}/foreign-exit/install.sh"
cp "${SERVER_DIR}/ru.env" "${BUNDLE_DIR}/ru-gateway/deployment.env"
cp "${SERVER_DIR}/foreign.env" "${BUNDLE_DIR}/foreign-exit/deployment.env"

for asset in geosite-ru.srs geoip-ru.srs; do
  if [[ -f "${ASSETS_DIR}/${asset}" ]]; then
    cp "${ASSETS_DIR}/${asset}" "${BUNDLE_DIR}/ru-gateway/assets/${asset}"
  fi
done

for asset in ru-ipv4.zone ru-ipv6.zone; do
  if [[ -f "${ASSETS_DIR}/${asset}" ]]; then
    cp "${ASSETS_DIR}/${asset}" "${BUNDLE_DIR}/foreign-exit/assets/${asset}"
  fi
done

tar -C "${BUNDLE_DIR}/ru-gateway" -czf "${BUNDLE_DIR}/ru-gateway.tar.gz" .
tar -C "${BUNDLE_DIR}/foreign-exit" -czf "${BUNDLE_DIR}/foreign-exit.tar.gz" .

cat >"${BUNDLE_DIR}/README.txt" <<EOF
ru-gateway:
  tar -xzf ru-gateway.tar.gz
  sudo ./install.sh --role ru-gateway --env-file ./deployment.env --assets-dir ./assets

foreign-exit:
  tar -xzf foreign-exit.tar.gz
  sudo ./install.sh --role foreign-exit --env-file ./deployment.env --assets-dir ./assets
EOF

echo "Packaged bundles in ${BUNDLE_DIR}"
