#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_vpn_help() {
  cat <<'EOF'
Использование:
  ./vpn.sh
  ./vpn.sh install
  ./vpn.sh status --deployment my-vpn

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
  - российский и зарубежный сервер на Ubuntu 24.04
  - публичный IPv4 у каждого
  - SSH-доступ по ключу или паролю
  - установленный Hiddify на клиентском устройстве
  - Как выбрать серверы: docs/PROVIDERS.md
  - Что внутри проекта: docs/PROJECT.md
  - При ошибке подробный лог: out/logs/runtime/latest-error.log
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

export VPN_REPO_ROOT="${ROOT_DIR}"
LAUNCHER_PATH="${ROOT_DIR}/vpn_installer/launcher.py"

if [[ "$#" -eq 0 ]]; then
  exec "$PYTHON_BIN" "$LAUNCHER_PATH"
fi

exec "$PYTHON_BIN" "$LAUNCHER_PATH" "$@"
