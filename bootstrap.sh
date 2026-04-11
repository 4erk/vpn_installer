#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
  exec python3 "${ROOT_DIR}/scripts/orchestrate.py" bootstrap "$@"
fi

if command -v python >/dev/null 2>&1; then
  exec python "${ROOT_DIR}/scripts/orchestrate.py" bootstrap "$@"
fi

echo "Python 3 не найден. Для Linux нужен локально установленный python3." >&2
exit 1
