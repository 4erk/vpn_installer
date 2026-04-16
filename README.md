# VPN Installer

Self-hosted VPN для личного использования и своего круга людей. Этот проект поднимает приватный контур из двух узлов: российский сервер даёт российский IP для российских сайтов, а зарубежный сервер выпускает остальной трафик через зарубежный IP. Это закрывает типовые проблемы публичных VPN: нестабильность, блокировки, зависимость от чужого сервиса и отсутствие контроля над своей инфраструктурой.

Важно: решение рассчитано на приватное использование. Чем шире и бесконтрольнее его распространять, тем выше риск блокировок, компрометации доступа и лишнего внимания к контуру.

- [Как выбрать серверы](./docs/PROVIDERS.md)
- [Что внутри проекта](./docs/PROJECT.md)
- [История версий](./CHANGELOG.md)

## Что нужно заранее

- один `российский сервер` с `Ubuntu 24.04`, публичным `IPv4` и доступом по `SSH`
- один `зарубежный сервер` с `Ubuntu 24.04`, публичным `IPv4` и доступом по `SSH`
- установленный клиент, который умеет `VLESS/Reality`

Подходят оба варианта доступа:

- `SSH key`
- `SSH password`

Если вход не под `root`, нужен `sudo`.

Рекомендуемые клиенты:

- Android: `v2rayNG` или `NekoBox`
- Windows / Linux: любой клиент с поддержкой `VLESS/Reality`; `Hiddify` остаётся совместимым вариантом, но не обязательным
- `Hiddify`-артефакты по-прежнему генерируются, но считаются вторичным удобным путём

## Запуск

Windows:

```powershell
.\vpn.cmd
```

Запуск через ярлык или двойной клик на Windows тоже лучше делать именно через `vpn.cmd`.

Linux:

```bash
chmod +x ./vpn.sh
./vpn.sh
```

Если нужно сразу открыть установку без меню:

```powershell
.\vpn.cmd install
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
- на Windows лучше запускать `vpn.cmd`: он держит окно открытым и пишет отдельный console log
- `vpn.ps1` тоже можно запускать вручную из PowerShell; он сам поднимет portable Python, если его нет
- на Linux нужен локально установленный `python3`

## Что получится в конце

После успешной установки появятся:

- `out/<deployment>/client/vless-uri.txt`
- `out/<deployment>/client/hiddify-subscription-url.txt`
- `out/<deployment>/client/hiddify-android-subscription-url.txt`
- `out/<deployment>/client/hiddify-import-url.txt`
- `out/<deployment>/client/hiddify-android-import-url.txt`
- `out/<deployment>/client/hiddify-cross-platform.json`
- `out/<deployment>/client/hiddify-android.json`
- `out/<deployment>/client/hiddify-uri.txt`
- `out/<deployment>/client/linux-sing-box.json`
- `out/<deployment>/NEXT-STEPS.txt`

Главный результат:

- основной `VLESS URI` копируется в буфер обмена
- основной нейтральный файл: `vless-uri.txt`
- на Android эталонный путь: вставить `vless-uri.txt` в `v2rayNG` или `NekoBox`
- `hiddify-subscription-url.txt` и `hiddify-android-subscription-url.txt` остаются как совместимый вторичный путь для `Hiddify`
- `hiddify-import-url.txt` — deeplink для клиентов, которые понимают схему `hiddify://import/...`
- `hiddify-android-import-url.txt` — Android-safe deeplink для Hiddify
- `hiddify-cross-platform.json` — fallback, если нужен локальный файл
- `hiddify-android.json` — Android-safe fallback
- `hiddify-uri.txt` — совместимый alias того же `VLESS URI` для старых сценариев

## Как подключить клиент

1. На любой платформе сначала попробуй `vless-uri.txt`
2. На Android предпочтительны `v2rayNG` или `NekoBox`
3. Если используешь `Hiddify` на Windows/Linux, добавляй профиль по `hiddify-subscription-url.txt` или `hiddify-import-url.txt`
4. Если используешь `Hiddify` на Android, сначала пробуй `hiddify-android-subscription-url.txt` или `hiddify-android-import-url.txt`
5. Если URL-подписка для `Hiddify` не подходит, используй `hiddify-cross-platform.json`; на Android сначала пробуй `hiddify-android.json`
6. `hiddify-uri.txt` оставлен как совместимый alias того же `VLESS URI`

Основной путь теперь — сырой `VLESS URI`. `Hiddify`-подписка и JSON остаются как вторичный совместимый путь.

Сервер остаётся источником истины для split-маршрутизации: клиенту не нужно знать, что считать российским или зарубежным трафиком. Он просто даёт туннель до `российского сервера`, а сама логика маршрутов живёт на серверной стороне.

IP самих `российского` и `зарубежного` серверов автоматически исключаются из клиентского туннеля. Это нужно, чтобы можно было запускать `vpn status/reinstall/remove` с того же компьютера даже при уже активном VPN-подключении.

## Если что-то не сработало

Проверь:

- оба сервера действительно на `Ubuntu 24.04`
- у обоих серверов есть публичный `IPv4`
- `SSH` работает вручную теми же данными
- у пользователя есть `root` или `sudo`
- путь к ключу указан правильно

Если установка дошла до конца, смотри:

- `out/<deployment>/NEXT-STEPS.txt`
- `out/<deployment>/client/vless-uri.txt`

Если сценарий упал или окно закрылось слишком быстро, смотри лог ошибки:

- `out/logs/runtime/latest-error.log`
- `out/logs/runtime/latest-transcript.log`
- `out/logs/runtime/latest-console.log`

Где что смотреть:

- `latest-transcript.log` — основной подробный лог запуска на Windows
- `latest-error.log` — traceback и детали необработанной ошибки
- `latest-console.log` — краткий wrapper-log от `vpn.cmd`

Для быстрой проверки после установки:

```powershell
.\vpn.cmd status --deployment my-vpn
```

```bash
./vpn.sh status --deployment my-vpn
```

Для самопроверки на обычном пользовательском ПК:

- `quick` — это пользовательская быстрая проверка, без unit/coverage, Docker и lab-контуров
- `quick` можно запускать без `docker`
- dev-only проверки в `quick` будут помечены как `skipped`, а не как ошибка
- полный контур для разработки и регрессий — это `vpn audit all`
