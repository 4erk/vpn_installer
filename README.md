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
- `out/<deployment>/client/android-v2rayng-xray.json`
- `out/<deployment>/client/windows-xray.json`
- `out/<deployment>/client/hiddify-cross-platform.json`
- `out/<deployment>/client/hiddify-android.json`
- `out/<deployment>/client/hiddify-uri.txt`
- `out/<deployment>/client/linux-sing-box.json`
- `out/<deployment>/NEXT-STEPS.txt`

Главный результат:

- быстрый `VLESS URI` копируется в буфер обмена
- на Android основной стабильный путь: импортировать `android-v2rayng-xray.json` в `v2rayNG`
- этот Android/v2rayNG профиль принудительно использует IPv4 DNS и блокирует клиентский IPv6
- `vless-uri.txt` — простой URI fallback для клиентов, которые не ломаются на локальном IPv6 DNS
- `windows-xray.json` — полный Xray-профиль для Windows/v2rayN
- `hiddify-cross-platform.json` — fallback, если нужен локальный файл
- `hiddify-android.json` — Android-safe fallback
- `hiddify-uri.txt` — совместимый alias того же `VLESS URI` для старых сценариев

## Как подключить клиент

1. На Android/v2rayNG сначала импортируй `android-v2rayng-xray.json`
2. На Windows/v2rayN в режиме TUN/full VPN используй `windows-xray.json`, потому что там включён sniffing и явно исключены IP обоих серверов
3. Если клиент точно корректно отдаёт домены серверу, можно использовать простой `vless-uri.txt`
4. Если используешь `Hiddify` на Windows/Linux, добавляй локальный `hiddify-cross-platform.json`
5. Если используешь `Hiddify` на Android, сначала пробуй локальный `hiddify-android.json`
6. Если нужен максимально нейтральный низкоуровневый путь, используй `vless-uri.txt`, но учитывай ограничение ниже
7. `hiddify-uri.txt` оставлен как совместимый alias того же `VLESS URI`

Сырой `VLESS URI` не универсален: некоторые клиенты сначала локально резолвят сайт в IPv6 literal и отправляют на сервер уже IP-адрес вместо домена. Серверный fallback отправит такой IPv6 через зарубежный сервер, но доменные российские исключения в этом режиме могут не сработать. Поэтому для Android/v2rayNG штатный путь — полный `android-v2rayng-xray.json` с IPv4-only DNS, блокировкой `::/0` и включённым sniffing.

Внешняя подписка с сервера больше не считается штатным путём; локальные JSON остаются управляемым вариантом.

Сервер остаётся источником истины для split-маршрутизации: клиенту не нужно знать, что считать российским или зарубежным трафиком. Он просто даёт туннель до `российского сервера`, а сама логика маршрутов живёт на серверной стороне.

В локальных JSON-профилях IP самих `российского` и `зарубежного` серверов автоматически исключаются из клиентского туннеля. Это нужно, чтобы можно было запускать `vpn status/reinstall/remove` с того же компьютера даже при уже активном VPN-подключении. Сырой `VLESS URI` сам по себе такие исключения не кодирует; если клиент в TUN/full VPN заворачивает IP сервера в свой же туннель, используй JSON-профиль или добавь bypass/direct rule в клиенте.

Быстрая проверка этой проблемы:

```powershell
.\vpn.cmd client-check --deployment 1
```

Если команда пишет `BAD: self-tunnel`, отключи текущий VPN перед обслуживанием серверов или импортируй route-safe JSON из `out/<deployment>/client`.

Если нужно быстро починить именно Windows TUN/full VPN маршрут, запусти PowerShell от администратора:

```powershell
.\out\1\client\windows-route-bypass.ps1
.\vpn.cmd client-check --deployment 1
```

Скрипт добавляет только active `/32` routes до IP серверов через физический gateway Windows. После перезагрузки Windows такие routes исчезают.

Если нужно локально добавить ещё домены или CIDR, которые должны идти через `российский сервер`, не редактируй клиент: создай рядом с `deployments/<name>.env` один или несколько файлов:

- `deployments/<name>.ru-direct-domains.txt`
- `deployments/<name>.ru-direct-suffixes.txt`
- `deployments/<name>.ru-direct-cidrs.txt`

В них можно держать по одному значению на строку, пустые строки и строки с `#` игнорируются. Эти overlay-файлы мерджатся в server-side routing на следующем `reinstall` роли `российского сервера`.

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

Если начались потери, высокий ping или просадка скорости, собери сетевой отчёт:

```powershell
.\vpn.cmd diagnose path --deployment my-vpn --iperf
```

Отчёт сохраняется в `out/diagnostics`. Флаг `--iperf` временно открывает диагностический порт только внутри `wg0` и удаляет правило после проверки.

Для самопроверки на обычном пользовательском ПК:

- `quick` — это пользовательская быстрая проверка, без unit/coverage, Docker и lab-контуров
- `quick` можно запускать без `docker`
- dev-only проверки в `quick` будут помечены как `skipped`, а не как ошибка
- полный контур для разработки и регрессий — это `vpn audit all`

`vpn status` теперь печатает не только состояние сервисов, но и live dataplane health:

- observed public IPv4 на `зарубежном сервере`
- observed public IPv4 для `российского сервера` через `wg0`
- возраст `WireGuard` handshake
- итоговый `health verdict`

Если локальный `deployments/<name>.env` разъехался с уже установленным сервером, `status/install/reinstall/remove/purge` сначала подтянут живой `/etc/vpn-stack/deployment.env` и пересоберут локальные клиентские артефакты, чтобы `vless-uri.txt` снова совпадал с сервером.
