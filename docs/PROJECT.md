# Документация проекта

## Назначение

Репозиторий разворачивает переносимый приватный VPN-контур со схемой:

`клиент -> RU gateway -> foreign exit`

Цель:

- клиент из РФ подключается только к российскому IP
- русский трафик выходит через RU-сервер
- остальной трафик выходит через foreign-сервер
- все ключи, env и клиентские профили сохраняются локально

## Компоненты

### RU gateway

- публичный вход `443/tcp`
- `sing-box` с `VLESS + REALITY`
- `WireGuard` до foreign-узла
- маршрутизация:
  - `RU domains + RU IP -> direct через RU uplink`
  - всё остальное -> через `wg0` на foreign
- DNS-логика держится на RU-сервере

### Foreign exit

- публичный клиентский вход не поднимается
- работает как `WireGuard` peer + NAT egress
- может блокировать выход на RU CIDR, чтобы не было обратной петли

### Клиент

- основной клиент: `Hiddify`
- профили генерируются локально
- отдельной клиентской логики split tunneling нет

## Что делает локальная автоматизация

### bootstrap

- запускается с Windows и Linux
- на Windows умеет тихо поставить portable Python локально
- создаёт или обновляет `deployments/<name>.env`
- генерирует ключи `REALITY`, `WireGuard`, `UUID`
- запрашивает IP и SSH-доступ к обоим серверам
- делает preflight
- рендерит локальные артефакты
- выполняет установку, переустановку, удаление или зачистку

### manage

Это пользовательская обёртка над `scripts/orchestrate.py`, чтобы не вызывать Python вручную.

- `manage.ps1` для Windows
- `manage.sh` для Linux

Через неё пользователь должен запускать:

- `status`
- `reinstall`
- `remove`
- `purge`
- `cleanup-local`

### audit

Запускается через:

- `audit.ps1` на Windows
- `audit.sh` на Linux
- `scripts/audit.py` как общий Python-core

Режимы:

- `quick`
- `docker`
- `lab`
- `all`

Что проверяет `quick`:

- `install.sh` syntax
- `orchestrate.py` compile/help
- `bootstrap.ps1`, `bootstrap.sh`, `manage.ps1`, `manage.sh`
- `render-all`, `render-config`, `gen-client-profiles`, `render-cloud-init`, `package-bundle`
- валидность JSON-артефактов, состава tarball и `cloud-init schema`
- bootstrap smoke path на Windows и Linux

Что проверяет `docker`:

- guard для `remove/purge` на неинициализированном хосте
- `render-only` для обеих ролей
- fail-fast по обязательным assets и fallback на локальный cache
- role-scoped/read-only поведение `status`
- role-scoped `reinstall/remove/purge` без зависимости от второго узла

Что проверяет `lab`:

- изолированный Docker-стенд `client -> RU -> foreign`
- реальные процессы `sing-box`, `wg-quick`, `nftables`
- детерминированный DNS для RU и global доменов
- dataplane-маршрутизацию `RU -> direct`, `global -> foreign`
- `fail-closed` для global при падении foreign
- сохранение прямого RU-path при остановке foreign
- RU-block на foreign через lab-specific deny list

### install.sh

Поддерживает действия:

- `install`
- `reinstall`
- `status`
- `remove`
- `purge`

### Состояние и артефакты

Локально:

- `deployments/<name>.env`
- `state/<name>.json`
- `out/<name>/assets`
- `out/<name>/bundle`
- `out/<name>/client`
- `out/<name>/cloud-init`
- `out/<name>/preview`

На сервере:

- `/etc/vpn-stack`
- `/var/lib/vpn-stack/rules`
- конфиги `sing-box`, `wireguard`, `nftables`

## Lifecycle

### install / reinstall

- ставит пакеты
- выкладывает конфиги и systemd units
- поднимает `nftables`, `wg-quick`, `vpn-stack-sync`, а на RU ещё и `sing-box`
- сохраняет deployment metadata на сервере

### status

- проверяет, установлен ли стек
- показывает роль, deployment, время установки
- показывает состояние сервисов
- не создаёт новый deployment и не переписывает локальные `env/state`

### remove

- останавливает сервисы стека
- удаляет его конфиги
- пытается восстановить baseline, который был сохранён перед первой установкой новой версией установщика
- если metadata стека на сервере нет, команда жёстко отказывается вместо destructive cleanup

### purge

- делает то же, что `remove`
- дополнительно вычищает серверное состояние в `/etc/vpn-stack`
- если metadata стека на сервере нет, команда жёстко отказывается вместо destructive cleanup

## Сборка артефактов

- локальная сборка теперь fail-fast по обязательным rule-set/CIDR assets
- warning остаётся только если обновление asset не удалось, но валидная локальная копия уже есть
- role-scoped `status/reinstall/remove/purge` работают только с выбранной ролью и не требуют второй сервер

## Что доказано и что ещё нет

### Доказано локально

- CLI и bootstrap-path работают на Windows и Linux
- локальная генерация всех артефактов воспроизводима
- JSON/tar/cloud-init проходят базовую валидацию
- lifecycle/orchestration-guard покрыты локальными regression tests

### Доказано в Docker-lab

- dataplane в изолированной сети соответствует схеме проекта
- `RU`-трафик идёт напрямую через RU-path
- `global`-трафик уходит через foreign-hop
- при падении foreign global-path рвётся `fail-closed`, а RU-path остаётся рабочим

### Всё ещё требует живых VPS

- first boot у реального VPS-провайдера
- реальный `root`/`sudo` SSH path к удалённым узлам
- реальный публичный `RU/foreign` egress
- DNS leak вне Docker Desktop
- импорт профилей в Hiddify на Windows/Linux/Android в боевой сети
- поведение под реальными провайдерскими ограничениями

### Важное ограничение

- Docker-lab не используется как доказательство реального публичного `IP/egress`
- если на хосте включён selective-VPN, прокси или Docker Desktop networking, audit намеренно не делает из этого выводы о реальной внешней сети

## Ограничения

- baseline-восстановление надёжно только для установок, сделанных уже текущей версией установщика
- системные пакеты при `purge` не удаляются специально
- автоматический `SSH password login` не реализован
- автоматическое создание отдельного deploy-user пока не доведено
- живой end-to-end прогон на боевых VPS ещё нужен

## Основные команды

Linux:

```bash
./bootstrap.sh
./manage.sh --help
./manage.sh status --deployment my-stack
./manage.sh reinstall --deployment my-stack
./manage.sh remove --deployment my-stack
./manage.sh purge --deployment my-stack
./manage.sh cleanup-local --deployment my-stack
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
powershell -ExecutionPolicy Bypass -File .\manage.ps1 --help
powershell -ExecutionPolicy Bypass -File .\manage.ps1 status --deployment my-stack
```
