#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_bootstrap_help() {
  cat <<'EOF'
Использование:
  ./bootstrap.sh
  ./bootstrap.sh --deployment my-vpn

Что делает bootstrap:
  1. Выбирает существующий deployment или создаёт новый
  2. Запрашивает RU и Foreign SSH-подключения
  3. Проверяет SSH, ОС, права sudo/root и текущее состояние обоих серверов
  4. Собирает локальные артефакты
  5. Выполняет install/reinstall/remove/purge по выбранным ролям

Что нужно заранее:
  - 2 VPS на Ubuntu 24.04
  - публичный IPv4 у каждого
  - рабочий SSH-доступ по ключу
EOF
}

if [[ "$#" -gt 0 && ( "$1" == "--help" || "$1" == "-h" || "$1" == "help" ) ]]; then
  show_bootstrap_help
  exit 0
fi

if command -v python3 >/dev/null 2>&1; then
  exec python3 "${ROOT_DIR}/scripts/orchestrate.py" bootstrap "$@"
fi

if command -v python >/dev/null 2>&1; then
  exec python "${ROOT_DIR}/scripts/orchestrate.py" bootstrap "$@"
fi

echo "Python 3 не найден. Для Linux нужен локально установленный python3." >&2
exit 1
