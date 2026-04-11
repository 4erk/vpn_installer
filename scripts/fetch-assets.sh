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
OUT_DIR="${ROOT_DIR}/out/${DEPLOY_NAME}/assets"

mkdir -p "${OUT_DIR}"

download_to() {
  local url="$1"
  local output="$2"
  curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "${output}.tmp"
  mv "${output}.tmp" "${output}"
}

download_to "${RU_GEOSITE_URL}" "${OUT_DIR}/geosite-ru.srs"
download_to "${RU_GEOIP_URL}" "${OUT_DIR}/geoip-ru.srs"

if [[ "${FOREIGN_BLOCK_RU:-1}" == "1" ]]; then
  download_to "${FOREIGN_RU_IPV4_LIST_URL}" "${OUT_DIR}/ru-ipv4.zone"
  download_to "${FOREIGN_RU_IPV6_LIST_URL}" "${OUT_DIR}/ru-ipv6.zone"
fi

echo "Fetched assets into ${OUT_DIR}"
