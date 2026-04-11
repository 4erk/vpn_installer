#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_manage_help() {
  cat <<'EOF'
Использование:
  ./manage.sh status --deployment my-vpn
  ./manage.sh reinstall --deployment my-vpn
  ./manage.sh remove --deployment my-vpn
  ./manage.sh purge --deployment my-vpn
  ./manage.sh cleanup-local --deployment my-vpn

Если нужна одна роль:
  ./manage.sh status --deployment my-vpn --role ru-gateway
  ./manage.sh reinstall --deployment my-vpn --role foreign-exit
EOF
}

if [[ "$#" -eq 0 ]]; then
  show_manage_help
  exit 0
fi

if [[ "$1" == "--help" || "$1" == "-h" || "$1" == "help" ]]; then
  show_manage_help
  exit 0
fi

if command -v python3 >/dev/null 2>&1; then
  exec python3 "${ROOT_DIR}/scripts/orchestrate.py" "$@"
fi

if command -v python >/dev/null 2>&1; then
  exec python "${ROOT_DIR}/scripts/orchestrate.py" "$@"
fi

echo "Python 3 не найден. Для Linux нужен локально установленный python3." >&2
exit 1
