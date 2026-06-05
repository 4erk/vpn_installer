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

- публичный вход `443/tcp` для VLESS/Reality
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
- `deployments/<name>.ru-direct-domains.txt`
- `deployments/<name>.ru-direct-suffixes.txt`
- `deployments/<name>.ru-direct-cidrs.txt`
- `state/<name>.json`
- `out/<name>/assets`
- `out/<name>/bundle`
- `out/<name>/cloud-init`
- `out/<name>/preview`
- `out/<name>/client`
- `out/<name>/NEXT-STEPS.txt`

Основные клиентские файлы:

- `out/<name>/client/vless-uri.txt`
- `out/<name>/client/windows-xray.json`
- `out/<name>/client/hiddify-cross-platform.json`
- `out/<name>/client/hiddify-android.json`
- `out/<name>/client/hiddify-uri.txt`
- `out/<name>/client/linux-sing-box.json`

Пользовательский контракт:

- основной публичный артефакт — `vless-uri.txt`
- на Android эталонные клиенты: `v2rayNG` и `NekoBox`
- `Hiddify`-артефакты остаются совместимым вторичным путём, а не основным контрактом
- для `Hiddify` на Windows/Linux основной локальный путь — `hiddify-cross-platform.json`
- для `Hiddify` на Android — `hiddify-android.json`
- server-hosted subscription path больше не считается штатной частью продукта
- `hiddify-uri.txt` — совместимый alias того же `VLESS URI`
- клиентские профили intentionally простые: без product-critical split-routing на клиенте; вся маршрутизация живёт на серверной стороне
- локальные JSON-профили исключают IP самих `российского` и `зарубежного` серверов из клиентского туннеля, чтобы `status/reinstall/remove` не упирались в SSH hairpin при уже активном VPN
- сырой `VLESS URI` не умеет кодировать route-exclude; для TUN/full VPN клиент должен сам bypass'ить IP серверов или использовать generated JSON с такими правилами
- `vpn client-check` проверяет локальный маршрут до серверов; если он показывает `BAD: self-tunnel`, удалённые действия намеренно блокируются до исправления маршрута или явного emergency override
- `windows-route-bypass.ps1` добавляет active `/32` routes до IP серверов через физический Windows gateway; это операторский helper для обслуживания, а не часть server-side маршрутизации
- optional `ru-direct` overlay-файлы мерджатся только в server-side routing и не переписывают основной `deployments/<name>.env`

## Lifecycle

### install / reinstall

- собирает локальные артефакты
- загружает bundle на сервер
- запускает `install.sh` с нужной ролью
- выполняет postcheck по сервисам
- затем делает deployment-level dataplane health pass:
  - свежесть `WireGuard` handshake
  - прямой IPv4 egress на `зарубежном сервере`
  - IPv4 egress на `российском сервере` через `wg0`
- при неуспехе делает один repair cycle и только потом валится с явной причиной вроде `wg_handshake_stale` или `ru_wg_egress_failed`

### Фоновое самовосстановление

На каждом сервере работает `vpn-stack-health.timer`. Он раз в несколько минут применяет безопасный runtime tuning, проверяет дешёвые признаки деградации и пишет состояние в `/var/lib/vpn-stack/health-state.env`.

Самовосстановление включено по умолчанию, но ограничено:
- SSH не рестартуется
- `WireGuard` перезапускается только при подтверждённой деградации туннельного пути
- `nftables` на `зарубежном сервере` перезапускается только при локальных egress-проблемах
- перед действием требуется несколько одинаковых наблюдений
- после действия действует cooldown и лимит действий в час

Параметры: `HEALTH_SELF_HEAL`, `HEALTH_SELF_HEAL_CONFIRMATIONS`, `HEALTH_SELF_HEAL_COOLDOWN_MINUTES`, `HEALTH_SELF_HEAL_MAX_ACTIONS_PER_HOUR`.

### status

- читает только существующий deployment
- не создаёт новый deployment
- не переписывает `state`
- если локальный `deployments/<name>.env` разъехался с уже установленным сервером, синхронизирует его из живого `/etc/vpn-stack/deployment.env` и сразу пересобирает локальные клиентские артефакты
- печатает runtime-диагностику по сети и тюнингу:
  - default/WAN interface
  - активный `qdisc`
  - активный TCP congestion control
  - `netdev backlog`
  - drops по интерфейсу
  - `WireGuard` transfer/handshake summary
  - observed public IPv4 на `зарубежном сервере`
  - observed public IPv4 на `российском сервере` через `wg0`
  - target probes по `HEALTH_TARGET_PROBE_URLS`: `reachable`, `blocked` или `broken`
  - итоговый `health verdict`

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
- поведение каждого конкретного стороннего клиента на реальных устройствах

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
