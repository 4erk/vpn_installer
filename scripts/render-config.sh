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
PREVIEW_DIR="${OUT_DIR}/preview"

mkdir -p "${SERVER_DIR}" "${PREVIEW_DIR}"

sed 's/\r$//' "$ENV_FILE" >"${SERVER_DIR}/ru.env"
sed 's/\r$//' "$ENV_FILE" >"${SERVER_DIR}/foreign.env"

bash "${ROOT_DIR}/scripts/fetch-assets.sh" "$ENV_FILE" >/dev/null || true

bash "${ROOT_DIR}/install.sh" \
  --role ru-gateway \
  --env-file "${SERVER_DIR}/ru.env" \
  --assets-dir "${OUT_DIR}/assets" \
  --render-only \
  --output-dir "${PREVIEW_DIR}/ru"

bash "${ROOT_DIR}/install.sh" \
  --role foreign-exit \
  --env-file "${SERVER_DIR}/foreign.env" \
  --assets-dir "${OUT_DIR}/assets" \
  --render-only \
  --output-dir "${PREVIEW_DIR}/foreign"

echo "Rendered server previews to ${OUT_DIR}"
