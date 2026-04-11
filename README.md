# Приватный VPN-контур без ручной настройки серверов

Этот репозиторий поднимает схему:

`твой компьютер или телефон -> RU сервер -> Foreign сервер`

Что это даёт:

- провайдер в РФ видит только подключение к российскому серверу
- русские сайты выходят через `RU IP`
- остальной трафик выходит через `Foreign IP`
- готовый клиентский профиль сохраняется у тебя локально

Главный вход для пользователя:

- Windows: `vpn.ps1`
- Linux: `vpn.sh`

Старые `bootstrap` и `manage` оставлены только для совместимости.

## Что подготовить заранее

Нужны два VPS.

`RU сервер`:

- `Ubuntu 24.04`
- публичный `IPv4`
- обычно хватает `1 vCPU`, `1 GB RAM`, `10+ GB disk`

`Foreign сервер`:

- `Ubuntu 24.04`
- публичный `IPv4`
- обычно хватает `1 vCPU`, `1 GB RAM`, `10+ GB disk`

Примеры провайдеров и цены: [docs/PROVIDERS.md](./docs/PROVIDERS.md)

## Шаг 1. Установи Hiddify

Основной клиент: `Hiddify`.

- Windows: [Hiddify install page](https://hiddify.com/app/How-to-install-Hiddify-app/), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)
- Linux: [Hiddify install page](https://hiddify.com/app/How-to-install-Hiddify-app/), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)
- Android: [Google Play](https://play.google.com/store/apps/details?id=app.hiddify.com), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)

## Шаг 2. Запусти мастер установки

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1
```

Linux:

```bash
chmod +x ./vpn.sh
./vpn.sh
```

Если хочешь сразу конкретную команду без меню:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 install
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 status --deployment my-vpn
```

```bash
./vpn.sh install
./vpn.sh status --deployment my-vpn
```

Что мастер спросит:

1. Имя deployment.
Пример: `my-vpn`, `home-stack`

2. `RU сервер`.
Что нужно ввести:
- `Public IP`
- `SSH port`
- `SSH user`
- способ входа: `SSH key` или `SSH password`

3. `Foreign сервер`.
Те же поля, в том же порядке.

Если `SSH host` отличается от `Public IP`, мастер сам спросит это отдельным вопросом.

Примеры значений:

- `Public IP`: `203.0.113.10`
- `SSH port`: `22`
- `SSH user`: `root` или `ubuntu`
- путь к ключу: `C:\Users\you\.ssh\id_ed25519` или `~/.ssh/id_ed25519`

Что происходит дальше автоматически:

- проверка подключения к `RU`
- проверка `Ubuntu`, `root/sudo`, уже установленной роли и deployment
- проверка подключения к `Foreign`
- сборка локальных артефактов
- установка сначала на `Foreign`, потом на `RU`

Важно:

- `RU` спрашивается и проверяется первым
- если вход по `SSH password`, пароль не сохраняется на диск
- если нужен `sudo password`, он тоже спрашивается только на время текущего запуска
- на Windows заранее ставить Python не нужно: `vpn.ps1` сам поднимет portable runtime в `.runtime/python/windows`, если локального Python нет

## Шаг 3. Импортируй профиль в Hiddify

После успешной установки мастер:

- попытается скопировать `Hiddify URI` в буфер обмена
- сохранит URI в `out/<deployment>/client/hiddify-uri.txt`
- сохранит запасной JSON в `out/<deployment>/client/hiddify-cross-platform.json`
- создаст `out/<deployment>/NEXT-STEPS.txt`

Основной путь:

1. Открой `Hiddify`
2. Выбери импорт профиля из буфера обмена
3. Если буфер не сработал, открой `hiddify-uri.txt` и вставь URI вручную

JSON нужен только как запасной вариант.

## Основные команды после установки

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 status --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 reinstall --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 remove --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 purge --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 cleanup-local --deployment my-vpn
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 audit
```

Linux:

```bash
./vpn.sh status --deployment my-vpn
./vpn.sh reinstall --deployment my-vpn
./vpn.sh remove --deployment my-vpn
./vpn.sh purge --deployment my-vpn
./vpn.sh cleanup-local --deployment my-vpn
./vpn.sh audit
```

Если нужно затронуть только одну роль:

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 status --deployment my-vpn --role ru-gateway
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 reinstall --deployment my-vpn --role foreign-exit
```

## Если что-то пошло не так

- Проверь, что оба сервера действительно на `Ubuntu 24.04`
- Проверь, что у обоих серверов есть публичный `IPv4`
- Проверь `SSH` вручную теми же данными, которые вводишь в мастер
- Если используешь ключ, проверь путь к файлу ключа
- Если используешь пароль, проверь, что сервер разрешает password login
- Если окно Windows раньше закрывалось, запускай через `vpn.ps1`: он теперь держит окно открытым до `Enter`
- Если не понял, что импортировать в `Hiddify`, используй сначала буфер обмена, потом `hiddify-uri.txt`, и только потом JSON

## Локальная самопроверка

```powershell
powershell -ExecutionPolicy Bypass -File .\vpn.ps1 audit
```

```bash
./vpn.sh audit
```

Это проверяет локальную сборку, lifecycle-guard и Docker-эмуляцию. Но это всё ещё не заменяет живой прогон на реальных VPS.

## Где лежат подробности

- Техническая документация: [docs/PROJECT.md](./docs/PROJECT.md)
- Провайдеры и цены: [docs/PROVIDERS.md](./docs/PROVIDERS.md)
