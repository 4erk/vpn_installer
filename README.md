# VPN Installer

Этот репозиторий поднимает схему:

`твой компьютер или телефон -> RU сервер -> Foreign сервер`

Пользовательский вход только один:

- Windows: `vpn.ps1`
- Linux: `vpn.sh`

## Что подготовить

Нужны:

- `RU` сервер с `Ubuntu 24.04`, публичным `IPv4` и доступом по `SSH`
- `Foreign` сервер с `Ubuntu 24.04`, публичным `IPv4` и доступом по `SSH`
- клиент `Hiddify`

Подходят оба варианта входа на сервер:

- `SSH key`
- `SSH password`

Если вход не под `root`, нужен `sudo`.

## Установи Hiddify

- Windows / Linux / Android: [Hiddify install page](https://hiddify.com/app/How-to-install-Hiddify-app/)
- GitHub Releases: [hiddify-app releases](https://github.com/hiddify/hiddify-app/releases/latest)
- Android в Google Play: [Hiddify on Google Play](https://play.google.com/store/apps/details?id=app.hiddify.com)

## Запуск

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1
```

Linux:

```bash
chmod +x ./vpn.sh
./vpn.sh
```

Если хочешь обойти меню:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 install
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 status --deployment my-vpn
```

```bash
./vpn.sh install
./vpn.sh status --deployment my-vpn
```

## Что спросит мастер

Сначала всегда `RU`, потом `Foreign`.

Для каждого сервера мастер спрашивает:

- `Public IP`
- `SSH port`
- `SSH user`
- способ входа: `key` или `password`

Примеры:

- `Public IP`: `203.0.113.10`
- `SSH port`: `22`
- `SSH user`: `root` или `ubuntu`
- путь к ключу: `C:\Users\you\.ssh\id_ed25519` или `~/.ssh/id_ed25519`

Если `SSH host` отличается от публичного IP, мастер спросит его отдельно.

Важно:

- `Enter` оставляет показанное значение
- пароль не сохраняется на диск
- на Windows `vpn.ps1` сам поднимет portable Python, если его нет
- на Linux нужен `python3`

## Что делает мастер

Автоматически:

1. Проверяет `RU` сервер
2. Проверяет `Foreign` сервер
3. Собирает локальные артефакты
4. Устанавливает сначала `Foreign`, потом `RU`
5. Готовит строку для `Hiddify`

## Что получится в конце

После успешной установки будут созданы:

- `out/<deployment>/client/hiddify-uri.txt`
- `out/<deployment>/client/hiddify-cross-platform.json`
- `out/<deployment>/client/linux-sing-box.json`
- `out/<deployment>/NEXT-STEPS.txt`

Основной результат:

- строка `Hiddify URI` копируется в буфер обмена
- та же строка сохраняется в `hiddify-uri.txt`

## Как импортировать в Hiddify

Основной путь:

1. Открой `Hiddify`
2. Выбери добавление профиля из буфера обмена
3. Если буфер не сработал, открой `hiddify-uri.txt` и вставь строку вручную

JSON-файлы нужны только как запасной вариант.

## Полезные команды

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 status --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 reinstall --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 remove --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 purge --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 cleanup-local --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 audit all
```

Linux:

```bash
./vpn.sh status --deployment my-vpn
./vpn.sh reinstall --deployment my-vpn
./vpn.sh remove --deployment my-vpn
./vpn.sh purge --deployment my-vpn
./vpn.sh cleanup-local --deployment my-vpn
./vpn.sh audit all
```

## Если что-то не сработало

Проверь:

- оба сервера действительно на `Ubuntu 24.04`
- у обоих серверов есть публичный `IPv4`
- `SSH` работает вручную теми же данными
- у пользователя есть `root` или `sudo`
- путь к ключу указан правильно

Если установка дошла до конца, смотри:

- `out/<deployment>/NEXT-STEPS.txt`
- `out/<deployment>/client/hiddify-uri.txt`

Технические детали проекта: [docs/PROJECT.md](./docs/PROJECT.md)
