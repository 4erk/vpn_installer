# VPN Installer: проектный документ

## Назначение

Проект разворачивает переносимый приватный контур:

`client -> RU gateway -> Foreign exit`

Цель:

- клиент в РФ подключается только к `RU` узлу
- русский трафик выходит через `RU IP`
- остальной трафик выходит через `Foreign IP`
- итоговый клиентский профиль сохраняется локально

## Публичный интерфейс

Поддерживаются только:

- `vpn.ps1`
- `vpn.sh`

Команды:

- `install`
- `status`
- `reinstall`
- `remove`
- `purge`
- `cleanup-local`
- `audit`

Без аргументов `vpn` открывает интерактивное меню.

## Кодовая структура

Основной Python-код находится в пакете `vpn_installer/`.

Ключевые модули:

- `cli.py`: парсер команд и вход в menu mode
- `models.py`: роли, dataclass-модели, ошибки
- `config.py`: env defaults, load/save, validation
- `state.py`: локальное состояние deployment
- `prompts.py`: интерактивные wizard-подсказки
- `remote.py`: SSH transport, preflight, privilege handling
- `render.py`: генерация server/client/cloud-init/bundle артефактов
- `workflows.py`: install/status/reinstall/remove/purge/cleanup-local/menu
- `clipboard.py`: копирование Hiddify URI
- `audit/`: quick/docker/lab проверки

## Рабочий контракт

### Порядок действий мастера

На вводе и проверке:

1. `RU`
2. `Foreign`

На установке:

1. `Foreign`
2. `RU`

На удалении:

1. `RU`
2. `Foreign`

### Аутентификация

Поддерживаются:

- `SSH key`
- `SSH password`
- `sudo password`, если нет passwordless sudo

Пароли живут только в памяти текущего запуска и не сохраняются в `env/state`.

### Основные локальные артефакты

Для каждого deployment создаются:

- `deployments/<name>.env`
- `state/<name>.json`
- `out/<name>/assets`
- `out/<name>/bundle`
- `out/<name>/cloud-init`
- `out/<name>/preview`
- `out/<name>/client`
- `out/<name>/NEXT-STEPS.txt`

Основные клиентские файлы:

- `out/<name>/client/hiddify-uri.txt`
- `out/<name>/client/hiddify-cross-platform.json`
- `out/<name>/client/linux-sing-box.json`

## Серверная схема

### RU gateway

- публичный вход `443/tcp`
- `sing-box` с `VLESS + REALITY`
- `WireGuard` до foreign узла
- маршрутизация:
  - `RU domains + RU IP -> direct`
  - всё остальное -> `WireGuard`

### Foreign exit

- публичный клиентский VPN-вход не поднимается
- работает как `WireGuard` peer + NAT egress
- может блокировать обратный выход на RU CIDR

## Lifecycle

### install / reinstall

- собирает локальные артефакты
- загружает bundle на сервер
- запускает `install.sh` с нужной ролью
- выполняет postcheck по сервисам

### status

- читает только существующий deployment
- не создаёт новый deployment
- не переписывает локальные `env/state`

### remove / purge

- требуют server-side metadata стека
- на unmanaged host жёстко отказываются
- `purge` дополнительно удаляет server-side metadata

### cleanup-local

- работает только с уже существующим deployment
- удаляет локальные артефакты и state
- по флагам может удалить `env` и portable runtime

## Assets и fail-fast

Локальная сборка прерывается сразу, если обязательный asset недоступен и нет валидного локального cache.

Обязательные assets:

- для `RU`: `geosite-ru.srs`, `geoip-ru.srs`
- для `Foreign`: `ru-ipv4.zone`
- дополнительно `ru-ipv6.zone`, если `FOREIGN_BLOCK_RU=1`

## Тестовый слой

### Unit

Основной тестовый стек: `stdlib unittest`.

Покрыты:

- config/state validation
- prompt order и reuse logic
- remote transport decisions
- render contract и fail-fast
- workflow ordering
- clipboard fallback
- CLI dispatch

### Audit

`vpn audit quick`

- `unittest`
- launcher smoke
- рендер артефактов
- JSON / tar / cloud-init validation

`vpn audit docker`

- guard для `remove/purge`
- role-scoped read-only `status`
- role-scoped lifecycle без зависимости от второго узла
- asset fail-fast/cache fallback

`vpn audit lab`

- dataplane `client -> RU -> Foreign`
- реальные `sing-box`, `WireGuard`, `nftables`
- `RU direct`
- `global via foreign`
- `fail-closed`, если foreign недоступен

Целевой acceptance для локальной проверки:

- `vpn audit all`

## Что ещё не доказывается без живых VPS

- first boot у конкретного VPS-провайдера
- реальный `root/sudo` путь на удалённые серверы
- реальный публичный `RU/Foreign egress`
- DNS leak в обычной сети вне Docker
- импорт профиля в `Hiddify` на реальных клиентах

Итог: локальный и Docker-контур покрыт, но финальный production-подтверждающий шаг всё равно остаётся за live staging на двух реальных `Ubuntu 24.04` VPS.
