#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Подсказка: основной вход теперь через ./vpn.sh audit."
exec "${ROOT_DIR}/vpn.sh" audit "$@"
