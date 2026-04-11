# Приватный VPN-контур в 3 шага

Этот репозиторий поднимает схему:

`твой компьютер или телефон -> RU сервер -> foreign сервер`

Что это даёт:

- провайдер в РФ видит только подключение к российскому серверу
- русские сайты идут через `RU IP`
- остальной трафик идёт через `foreign IP`
- вся настройка и готовые клиентские профили сохраняются у тебя локально

Ручная настройка серверов не нужна. Основной сценарий уже автоматизирован.

## Что нужно подготовить

Нужны два VPS.

`RU сервер`:

- `Ubuntu 24.04`
- публичный `IPv4`
- вход по `SSH key`
- для старта обычно хватает `1 vCPU`, `1 GB RAM`, `10+ GB disk`
- пример: [Timeweb Cloud](https://timeweb.cloud/services/cloud-servers/)

`Foreign сервер`:

- `Ubuntu 24.04`
- публичный `IPv4`
- вход по `SSH key`
- для старта обычно хватает `1 vCPU`, `1 GB RAM`, `10+ GB disk`
- примеры: `Koara`, `FirstByte`, `RuWeb`, `THE.Hosting`

Подробное сравнение провайдеров: [docs/PROVIDERS.md](./docs/PROVIDERS.md)

## Шаг 1. Установи клиент

Основной клиент: `Hiddify`.

- Windows: [Hiddify install page](https://hiddify.com/app/How-to-install-Hiddify-app/), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)
- Linux: [Hiddify install page](https://hiddify.com/app/How-to-install-Hiddify-app/), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)
- Android: [Google Play](https://play.google.com/store/apps/details?id=app.hiddify.com), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)

## Шаг 2. Запусти bootstrap

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 --help
```

Linux:

```bash
./bootstrap.sh
./bootstrap.sh --help
```

Что он сделает сам:

- предложит создать новый `deployment` или выбрать уже существующий
- сгенерирует ключи и UUID
- явно спросит `RU` и `Foreign` SSH-подключения
- проверит оба сервера по SSH
- проверит ОС, текущую роль и права `root/sudo`
- соберёт локальные артефакты
- установит стек на оба сервера

Важно:

- если у тебя уже есть старые `deployment`, bootstrap по умолчанию предлагает создать новый, а не молча брать первый попавшийся
- если по роли уже есть сохранённое SSH-подключение, bootstrap теперь явно покажет его и спросит: использовать или изменить

На Windows заранее ставить Python не обязательно. Если его нет, bootstrap сам подтянет portable runtime в `.runtime/python/windows`.

## Шаг 3. Импортируй готовый профиль

После bootstrap у тебя появятся локальные файлы:

- `out/<deployment>/client/hiddify-cross-platform.json`
- `out/<deployment>/client/linux-sing-box.json`
- `deployments/<deployment>.env`
- `state/<deployment>.json`

Для Windows, Linux и Android обычно нужен именно:

`out/<deployment>/client/hiddify-cross-platform.json`

Импортируй этот файл в `Hiddify`.

## Обычные команды после установки

Используй обёртку `manage`, а не внутренние Python-команды.

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\manage.ps1 --help
powershell -ExecutionPolicy Bypass -File .\manage.ps1 status --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\manage.ps1 reinstall --deployment my-vpn
```

Linux:

```bash
./manage.sh --help
./manage.sh status --deployment my-vpn
./manage.sh reinstall --deployment my-vpn
```

Полезные действия:

- `status`: проверить оба сервера без изменений
- `reinstall`: переустановить стек
- `remove`: удалить стек с серверов и восстановить baseline
- `purge`: удалить стек и его серверное состояние
- `cleanup-local`: удалить локальные артефакты

Если нужно работать только с одной ролью:

```bash
./manage.sh status --deployment my-vpn --role ru-gateway
./manage.sh reinstall --deployment my-vpn --role foreign-exit
```

## Если хочешь прогнать локальную самопроверку

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\audit.ps1 all
```

Linux:

```bash
./audit.sh all
```

Это проверяет локальную сборку и Docker-эмуляцию, но не заменяет живой прогон на реальных VPS.

Важно:

- если на хосте включён selective-VPN, прокси или Docker Desktop networking, локальный audit не считается доказательством реального публичного `IP`
- реальный `RU/foreign` egress и поведение на настоящих провайдерских сетях всё равно проверяются только на живых VPS

## Если что-то пошло не так

- проверь, что оба сервера действительно на `Ubuntu 24.04`
- проверь, что у обоих серверов есть публичный `IPv4`
- проверь, что вход по `SSH key` работает вручную
- для Windows используй `bootstrap.ps1`, `manage.ps1`, `audit.ps1`
- для Linux используй `bootstrap.sh`, `manage.sh`, `audit.sh`

## Где лежат подробности

- Полная техническая документация: [docs/PROJECT.md](./docs/PROJECT.md)
- Провайдеры и цены: [docs/PROVIDERS.md](./docs/PROVIDERS.md)
