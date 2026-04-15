# Что внутри проекта

## Как читать этот документ

- `README.md` — быстрый старт для обычного пользователя
- [Как выбрать серверы](./PROVIDERS.md) — подбор провайдеров и готовые пары
- [История версий](../CHANGELOG.md) — изменения по релизам
- этот документ — техническая карта проекта

## Назначение

Проект разворачивает переносимый приватный контур:

`клиент -> российский сервер -> зарубежный сервер`

Смысл схемы:

- клиент подключается только к российскому серверу
- российские сайты выходят через российский IP
- остальной трафик уходит через зарубежный IP
- итоговый профиль клиента сохраняется локально

Технические роли:

- `российский сервер` = `ru-gateway`
- `зарубежный сервер` = `foreign-exit`

## Публичный интерфейс

Поддерживаются только:

- `vpn.cmd` для Windows
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

Для Windows пользовательский путь по умолчанию: `vpn.cmd`.

## Архитектура

### Российский сервер

- публичный вход `443/tcp`
- `sing-box` с `VLESS + REALITY`
- `WireGuard` до зарубежного сервера
- маршрутизация:
  - российские домены и IP идут напрямую
  - остальной трафик уходит через `WireGuard`

### Зарубежный сервер

- клиентский VPN-вход не поднимается
- работает как `WireGuard` peer + NAT egress
- может резать обратный выход на российские подсети

## Порядок работы мастера

На вводе и проверке:

1. `российский сервер`
2. `зарубежный сервер`

На установке:

1. `зарубежный сервер`
2. `российский сервер`

На удалении:

1. `российский сервер`
2. `зарубежный сервер`

## Аутентификация

Поддерживаются:

- `SSH key`
- `SSH password`
- `sudo password`, если нет passwordless sudo

Пароли живут только в памяти текущего запуска и не сохраняются в `env/state`.

## Локальные артефакты

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

Локальная сборка останавливается сразу, если обязательный asset недоступен и нет валидного локального cache.

Обязательные assets:

- для российского сервера: `geosite-ru.srs`, `geoip-ru.srs`
- для зарубежного сервера: `ru-ipv4.zone`
- дополнительно `ru-ipv6.zone`, если `FOREIGN_BLOCK_RU=1`

Стратегия устойчивости по источникам:

- для `geosite` и `geoip` по умолчанию используется цепочка из нескольких URL, а не один источник
- для RU CIDR-листов по умолчанию используются `IPdeny` и fallback через `RIPE Stat country-resource-list`
- если обновление не удалось, локальная сборка использует уже сохранённый cache
- bundle и `cloud-init` всегда несут preseed-копии assets с собой
- server-side `vpn-stack-sync` при неудачном обновлении оставляет последнюю рабочую копию, если она уже есть
- при желании можно задать свои URL-источники прямо в `deployment env`

## Проверки и тесты

### Unit

Основной стек: `stdlib unittest`.

Покрыты:

- config/state validation
- порядок wizard-шагов и reuse logic
- SSH transport decisions
- render contract и fail-fast
- порядок install/remove
- clipboard fallback
- CLI dispatch

### Audit

`vpn audit quick`

- пользовательская быстрая самопроверка
- launcher smoke для текущей платформы
- рендер артефактов
- JSON / tar / cloud-init validation
- dev-only проверки (`unittest`, `coverage`, Docker/container, cross-platform regression) в обычном `quick` переходят в `skipped`
- для полного developer/regression контура используется `vpn audit all`

`vpn audit docker`

- guard для `remove/purge`
- role-scoped read-only `status`
- role-scoped lifecycle без зависимости от второго узла
- asset fail-fast/cache fallback

`vpn audit lab`

- dataplane `клиент -> российский сервер -> зарубежный сервер`
- реальные `sing-box`, `WireGuard`, `nftables`
- российский трафик идёт напрямую
- глобальный трафик идёт через зарубежный сервер
- при падении зарубежного сервера работает `fail-closed`

## Что ещё не доказывается без живых VPS

- first boot у конкретного VPS-провайдера
- реальный `root/sudo` путь на удалённые серверы
- реальный публичный российский и зарубежный egress
- DNS leak в обычной сети вне Docker
- импорт профиля в `Hiddify` на реальных клиентах

Итог: локальный и Docker-контур покрыт, но финальный production-подтверждающий шаг всё равно остаётся за live staging на двух реальных `Ubuntu 24.04` VPS.

## Версионирование

Проект использует `SemVer`: `major.minor.patch`.

- `major` — несовместимые изменения в поведении или публичном интерфейсе
- `minor` — новые пользовательские возможности и заметные доработки без обязательной ломки старого сценария
- `patch` — исправления ошибок и точечные улучшения

## Релизы

- история изменений ведётся в [CHANGELOG.md](../CHANGELOG.md)
- релизный тег должен совпадать с `SemVer`, например `0.2.1`
- GitHub Release создаётся автоматически по push такого тега через workflow в `.github/workflows/release.yml`
