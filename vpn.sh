#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_vpn_help() {
  cat <<'EOF'
Использование:
  ./vpn.sh
  ./vpn.sh install
  ./vpn.sh status --deployment my-vpn
  ./vpn.sh reinstall --deployment my-vpn --role ru-gateway

Если запустить без аргументов:
  откроется пошаговое меню с действиями:
  - Установить или обновить VPN
  - Проверить текущее состояние
  - Переустановить
  - Удалить с серверов
  - Полная очистка
  - Локальная очистка
  - Самопроверка

Что нужно заранее:
  - 2 VPS на Ubuntu 24.04
  - публичный IPv4 у каждого
  - SSH-доступ по ключу или паролю
  - установленный Hiddify на клиентском устройстве
EOF
}

if [[ "$#" -gt 0 && ( "$1" == "--help" || "$1" == "-h" || "$1" == "help" ) ]]; then
  show_vpn_help
  exit 0
fi

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  echo "Python 3 не найден. Для Linux нужен локально установленный python3." >&2
  exit 1
fi

if [[ "$#" -eq 0 ]]; then
  exec "$PYTHON_BIN" "${ROOT_DIR}/scripts/orchestrate.py" menu
fi

if [[ "$1" == "audit" ]]; then
  shift
  if [[ "$#" -eq 0 ]]; then
    exec "$PYTHON_BIN" "${ROOT_DIR}/scripts/audit.py" quick
  fi
  exec "$PYTHON_BIN" "${ROOT_DIR}/scripts/audit.py" "$@"
fi

exec "$PYTHON_BIN" "${ROOT_DIR}/scripts/orchestrate.py" "$@"
