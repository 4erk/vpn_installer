# Документация проекта

## Назначение

Репозиторий разворачивает переносимый приватный VPN-контур по схеме:

`клиент -> RU gateway -> Foreign exit`

Цель:

- клиент из РФ подключается только к `RU IP`
- русский трафик выходит через `RU`
- остальной трафик выходит через `Foreign`
- ключи, deployment env и клиентские артефакты сохраняются локально

## Архитектура

### RU gateway

- публичный вход `443/tcp`
- `sing-box` с `VLESS + REALITY`
- `WireGuard` до Foreign
- маршрутизация:
  - `RU domains + RU IP -> direct`
  - всё остальное -> через `WireGuard` на Foreign

### Foreign exit

- публичный клиентский VPN-вход не поднимается
- работает как `WireGuard` peer + NAT egress
- может блокировать обратный выход на RU CIDR

### Клиент

- основной клиент: `Hiddify`
- основной пользовательский артефакт: одна `VLESS/Reality URI`
- JSON-профили сохраняются как резерв

## Пользовательский интерфейс

### Основной вход

- Windows: `vpn.ps1`
- Linux: `vpn.sh`

Без аргументов:

- открывает интерактивное меню

С аргументами:

- `install`
- `status`
- `reinstall`
- `remove`
- `purge`
- `cleanup-local`
- `audit`

### Совместимость

Оставлены shim-обёртки:

- `bootstrap.ps1`, `bootstrap.sh`
- `manage.ps1`, `manage.sh`
- `audit.ps1`, `audit.sh`

Они только перекидывают пользователя на `vpn.ps1/.sh` и не считаются основным UX.

## Что делает install wizard

Порядок шагов:

1. Выбор или создание deployment
2. Ввод и проверка `RU`
3. Ввод и проверка `Foreign`
4. Сводка
5. Локальная сборка артефактов
6. Установка на `Foreign`
7. Установка на `RU`
8. Финализация для Hiddify

Порядок проверки серверов:

- всегда сначала `RU`
- потом `Foreign`

Порядок deploy для `install/reinstall`:

- всегда сначала `Foreign`
- потом `RU`

Порядок для `remove/purge`:

- `RU`
- потом `Foreign`

## SSH и привилегии

Поддерживаются оба варианта:

- `SSH key`
- `SSH password`

Дополнительно:

- если вход уже под `root`, используется он
- если есть `passwordless sudo`, используется он
- если нужен `sudo password`, он спрашивается интерактивно

Правила хранения:

- в `state/<deployment>.json` сохраняется только `auth_mode`
- `SSH password` не сохраняется
- `sudo password` не сохраняется

Транспорт:

- для обычного key-path по умолчанию используется системный `ssh/scp`
- для password-path и fallback-сценариев используется Python SSH backend на `paramiko`
- `paramiko` ставится лениво только при необходимости в `.runtime/python-packages`

## Локальные артефакты

Для каждого deployment создаются:

- `deployments/<name>.env`
- `state/<name>.json`
- `out/<name>/assets`
- `out/<name>/bundle`
- `out/<name>/preview`
- `out/<name>/cloud-init`
- `out/<name>/client`
- `out/<name>/NEXT-STEPS.txt`

Основные клиентские файлы:

- `out/<name>/client/hiddify-uri.txt`
- `out/<name>/client/hiddify-cross-platform.json`
- `out/<name>/client/linux-sing-box.json`

## Серверный lifecycle

### install / reinstall

- ставит пакеты
- выкладывает конфиги и systemd units
- поднимает `nftables`, `wg-quick`, `vpn-stack-sync`
- на `RU` поднимает ещё и `sing-box`
- сохраняет metadata роли и deployment на сервере

### status

- проверяет установлен ли стек
- показывает роль, deployment и состояние сервисов
- не создаёт новый deployment
- не переписывает локальные `env/state`

### remove

- останавливает сервисы стека
- удаляет конфиги стека
- восстанавливает baseline, если он был сохранён
- если metadata стека не найдена, команда жёстко отказывается

### purge

- делает всё то же, что `remove`
- дополнительно вычищает серверное состояние в `/etc/vpn-stack`
- если metadata стека не найдена, команда жёстко отказывается

## Сборка артефактов

- локальная сборка fail-fast по обязательным assets
- если обязательный asset недоступен и локального cache нет, сборка завершается ошибкой сразу
- warning остаётся только в сценарии “обновление не удалось, но валидная локальная копия уже есть”

Обязательные assets:

- для `RU`: `geosite-ru.srs`, `geoip-ru.srs`
- для `Foreign`: `ru-ipv4.zone`, а при `FOREIGN_BLOCK_RU=1` ещё и `ru-ipv6.zone`

## Что проверяет audit

### quick

- syntax / help / entrypoints
- `vpn.ps1`, `vpn.sh`
- compatibility shims
- генерацию всех артефактов
- JSON / tar / cloud-init schema
- `Hiddify URI` и `NEXT-STEPS.txt`
- clean-room запуск Windows launcher без заранее установленного Python
- Linux launcher с Python и без Python

### docker

- guard для `remove/purge` на неинициализированном хосте
- `render-only` для обеих ролей
- fail-fast по assets
- role-scoped read-only `status`
- role-scoped `reinstall/remove/purge`

### lab

- изолированный dataplane `client -> RU -> Foreign`
- реальные `sing-box`, `WireGuard`, `nftables`
- детерминированный DNS
- `RU -> direct`
- `global -> Foreign`
- `fail-closed` при падении `Foreign`

## Что уже доказано

Подтверждено локально и через Docker:

- единый launcher `vpn.ps1/.sh` работает
- compatibility shims не отвалились
- lifecycle guard не ломает неинициализированный сервер
- role-scoped операции не зависят от второго сервера
- `status` действительно read-only
- dataplane в Docker-lab соответствует схеме проекта

Последние успешные summary:

- quick: `out/audit/20260411T234447Z-quick/summary.json`
- docker: `out/audit/20260411T234525Z-docker/summary.json`
- lab: `out/audit/20260411T234550Z-lab/summary.json`

## Что ещё требует живых VPS

- first boot у реального VPS-провайдера
- реальный `root/sudo` SSH path к удалённым узлам
- публичный `RU/Foreign egress`
- DNS leak вне Docker Desktop
- боевой импорт в `Hiddify` на Windows/Linux/Android в реальной сети

## Ограничения

- baseline-восстановление надёжно только для установок, сделанных новой версией установщика
- системные пакеты при `purge` специально не удаляются
- локальный audit не считается доказательством реального публичного `IP`, особенно если на хосте есть selective-VPN, proxy или Docker Desktop networking
