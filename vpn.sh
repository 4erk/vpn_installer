#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_vpn_help() {
  cat <<'EOF'
Использование:
  ./vpn.sh
  ./vpn.sh --version
  ./vpn.sh install
  ./vpn.sh status --deployment home-vpn

Основные команды:
  install, status, admin, verify live, diagnose, routes,
  reinstall, maintain, remove, purge, cleanup-local, audit

Если запустить без аргументов:
  откроется пошаговое меню с действиями:
  - Установить или обновить VPN
  - Проверить текущее состояние
  - Показать адрес web-admin для двойной схемы
  - Переустановить
  - Удалить с серверов
  - Полная очистка
  - Локальная очистка
  - Самопроверка

Что нужно заранее:
  - один сервер для одиночной схемы или два для двойной
  - Ubuntu 24.04 и публичный IPv4 у каждого используемого сервера
  - SSH-доступ по ключу или паролю
  - VPN-клиент с поддержкой VLESS/Reality
  - Список команд: docs/COMMANDS.md
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
