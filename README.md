# VPN Installer

Self-hosted VPN для личного использования и своего круга людей. Этот проект поднимает приватный контур из двух узлов: российский сервер даёт российский IP для российских сайтов, а зарубежный сервер выпускает остальной трафик через зарубежный IP. Это закрывает типовые проблемы публичных VPN: нестабильность, блокировки, зависимость от чужого сервиса и отсутствие контроля над своей инфраструктурой.

Важно: решение рассчитано на приватное использование. Чем шире и бесконтрольнее его распространять, тем выше риск блокировок, компрометации доступа и лишнего внимания к контуру.

- [Как выбрать серверы](./docs/PROVIDERS.md)
- [Что внутри проекта](./docs/PROJECT.md)

## Что нужно заранее

- один `российский сервер` с `Ubuntu 24.04`, публичным `IPv4` и доступом по `SSH`
- один `зарубежный сервер` с `Ubuntu 24.04`, публичным `IPv4` и доступом по `SSH`
- установленный клиент `Hiddify`

Подходят оба варианта доступа:

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

Если нужно сразу открыть установку без меню:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 install
```

```bash
./vpn.sh install
```

## Что спросит мастер

Сначала всегда проверяется `российский сервер`, потом `зарубежный сервер`.

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

Подсказки:

- `Enter` оставляет показанное значение
- пароль не сохраняется на диск
- на Windows `vpn.ps1` сам поднимет portable Python, если его нет
- на Linux нужен локально установленный `python3`

## Что получится в конце

После успешной установки появятся:

- `out/<deployment>/client/hiddify-uri.txt`
- `out/<deployment>/client/hiddify-cross-platform.json`
- `out/<deployment>/client/linux-sing-box.json`
- `out/<deployment>/NEXT-STEPS.txt`

Главный результат:

- строка для `Hiddify` копируется в буфер обмена
- та же строка сохраняется в `hiddify-uri.txt`

## Как подключить в Hiddify

1. Открой `Hiddify`
2. Выбери добавление профиля из буфера обмена
3. Если буфер не сработал, открой `hiddify-uri.txt` и вставь строку вручную

JSON-файлы нужны только как запасной вариант.

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

Для быстрой проверки после установки:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 status --deployment my-vpn
```

```bash
./vpn.sh status --deployment my-vpn
```
