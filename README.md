# Переносимый установщик приватного VPN-контура

Репозиторий разворачивает схему `клиент -> RU gateway -> foreign exit` и теперь умеет полноценно запускаться как с Linux, так и с Windows без WSL. Локальная автоматизация собрана вокруг одного `Python` core, а server-side установка по-прежнему делается через `install.sh` на Ubuntu.

## Что умеет

- Запускаться с Linux через `./bootstrap.sh`.
- Запускаться с Windows через `.\bootstrap.ps1` без WSL.
- Если на Windows нет Python, тихо скачать portable CPython в локальную папку `.runtime/python/windows`.
- Хранить локальный deployment `.env`, состояние SSH-подключений и все собранные артефакты.
- Проверять оба сервера по SSH перед установкой.
- Понимать, установлен ли стек раньше, и предлагать обновление, переустановку или пропуск.
- Работать как с `root`, так и с обычным SSH-пользователем с `sudo`.
- Автоматически собирать и переносить на серверы нужные артефакты.

## Основные файлы

- [bootstrap.sh](./bootstrap.sh) — Linux launcher.
- [bootstrap.ps1](./bootstrap.ps1) — Windows launcher без WSL, с auto-bootstrap portable Python.
- [scripts/orchestrate.py](./scripts/orchestrate.py) — основной локальный orchestration layer.
- [install.sh](./install.sh) — server-side установщик роли `ru-gateway` или `foreign-exit` на Ubuntu.
- [deployments/deployment.env.example](./deployments/deployment.env.example) — пример deployment env.
- [cloud-init/ru.yaml](./cloud-init/ru.yaml) и [cloud-init/foreign.yaml](./cloud-init/foreign.yaml) — шаблонные заглушки, реальные файлы рендерятся в `out/<deployment>/cloud-init/`.

## Требования

### Локальная машина

Linux:
- `python3`
- `ssh`
- `scp`

Windows:
- PowerShell 5.1+ или PowerShell 7+
- `ssh.exe`
- `scp.exe`

Примечание:
- На Windows Python локально не обязателен, launcher подтянет portable runtime сам.
- На Linux bootstrap ожидает установленный `python3`.

### Целевые серверы

- `Ubuntu` на обоих VPS
- SSH-доступ до обоих серверов
- Логин либо под `root`, либо под пользователем с `sudo`

## Быстрый старт

### Linux

```bash
./bootstrap.sh
```

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
```

## Как работает bootstrap

1. Предлагает выбрать существующий deployment или создать новый.
2. Создаёт или обновляет `deployments/<name>.env`.
3. Генерирует и сохраняет локально:
   - UUID клиента
   - ключи `REALITY`
   - ключи `WireGuard`
   - `short_id`
4. Запрашивает по каждому серверу:
   - публичный IP
   - SSH host
   - SSH port
   - SSH user
   - путь к приватному ключу, если нужен явный `-i`
5. Делает preflight на RU и foreign:
   - доступность по SSH
   - кто пользователь входа
   - есть ли `sudo`
   - какая ОС и версия
   - установлен ли стек
   - какая роль уже стоит
   - какой WAN interface определился на foreign
6. Собирает локальные артефакты:
   - `out/<name>/assets`
   - `out/<name>/preview`
   - `out/<name>/client`
   - `out/<name>/cloud-init`
   - `out/<name>/bundle`
7. Загружает role-specific bundle на серверы и запускает установку.
8. После установки делает post-check сервисов.

## Где лежит локальное состояние

После первого прогона всё нужное остаётся локально:

```text
deployments/<name>.env
state/<name>.json
out/<name>/
  assets/
  bundle/
  client/
  cloud-init/
  preview/
  server/
.runtime/
  python/
```

Это позволяет не генерировать заново ключи, не спрашивать по кругу SSH-параметры и сразу иметь готовые клиентские профили.

## Ручные команды

Все ручные действия можно запускать через `Python` core напрямую:

```bash
python3 ./scripts/orchestrate.py init-env ./deployments/my-stack.env
python3 ./scripts/orchestrate.py fetch-assets ./deployments/my-stack.env
python3 ./scripts/orchestrate.py render-config ./deployments/my-stack.env
python3 ./scripts/orchestrate.py gen-client-profiles ./deployments/my-stack.env
python3 ./scripts/orchestrate.py render-cloud-init ./deployments/my-stack.env
python3 ./scripts/orchestrate.py package-bundle ./deployments/my-stack.env
python3 ./scripts/orchestrate.py render-all ./deployments/my-stack.env
```

Под Windows это то же самое, только через:

```powershell
.\.runtime\python\windows\python.exe .\scripts\orchestrate.py render-all .\deployments\my-stack.env
```

или через скачанный portable runtime из `.runtime`.

## Что важно про portable Python на Windows

- Runtime ставится только локально в репозиторий, без системной установки.
- По умолчанию используется embeddable CPython с `python.org`.
- URL и версия можно переопределить переменными окружения:
  - `VPN_BOOTSTRAP_PYTHON_VERSION`
  - `VPN_BOOTSTRAP_PYTHON_URL`

## Ограничения v1

- Основной путь сейчас `IPv4-only fail-closed`, чтобы не словить утечки через IPv6 в обход foreign-hop.
- Server-side установщик ориентирован на `Ubuntu`, базово тестируется под `Ubuntu 24.04`.
- SSH-аутентификация со стороны локального bootstrap сейчас рассчитана на ключ или `ssh-agent`. Интерактивный SSH password login не автоматизирован.
- Если SSH-пользователь не `root`, у него должен быть `sudo`. Без `root` или `sudo` установка не продолжится.

## Что проверить после деплоя

- `ya.ru`, `vk.com`, `gosuslugi.ru` выходят с RU IP.
- `google.com`, `youtube.com`, `github.com` выходят с foreign IP.
- При падении foreign-сервера нероссийский трафик падает `fail-closed`.
- Клиент из РФ светит только соединение к RU IP на `443/tcp`.
