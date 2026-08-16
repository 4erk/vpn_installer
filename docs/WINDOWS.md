# Windows: запуск и диагностика

В примерах `home-vpn` — имя установки. Оно предложено по умолчанию при первой установке; замени его в командах, если было выбрано другое имя.

## Точка входа

Запускай проект из корня репозитория только через `vpn.cmd`:

```powershell
.\vpn.cmd
.\vpn.cmd status --deployment home-vpn --role all
.\vpn.cmd verify live --deployment home-vpn
```

`vpn.cmd` поднимает portable Python при необходимости, запускает интерфейс и записывает логи. `vpn.ps1` является внутренним bootstrap-файлом и не считается пользовательской точкой входа. Пункт `Выход` закрывает только установщик и не останавливает серверный VPN.

Для автоматического запуска без ожидания клавиши после завершения:

```powershell
$env:VPN_NO_PAUSE="1"
.\vpn.cmd status --deployment home-vpn --role all --non-interactive
```

## SSH-доступ

Мастер предлагает два взаимоисключающих режима.

### SSH key

- пустое значение: ssh-agent и стандартный поиск ключей OpenSSH;
- `id_ed25519`: стандартный путь `%USERPROFILE%\.ssh\id_ed25519`;
- `C:\Keys\vpn-prod`: полный путь;
- `.\keys\vpn-prod`: явный путь относительно текущего каталога.

Этот режим строго `publickey-only`. Установщик не переходит к password-аутентификации и не показывает ручной prompt `root@host's password`. Если ключ не принят сервером, интерфейс предлагает исправить параметры или явно выбрать `SSH password`.

### SSH password

Пароль принимает встроенный Python backend, без запуска `ssh.exe`. Он используется только в памяти процесса и не сохраняется в `state` или deployment env. Для non-interactive запуска пароль передаётся через `VPN_RU_SSH_PASSWORD`, `VPN_FOREIGN_SSH_PASSWORD` либо общий `VPN_SSH_PASSWORD`.

Host keys обоих режимов проверяются по управляемому файлу `state/known_hosts`. Старый state без явного `auth_mode` не угадывается: мастер заново спрашивает способ входа.

## Ошибки и логи

Интерфейс показывает одну краткую причину и путь к логу. Технические детали находятся в:

- `out/logs/runtime/latest-error.log` — последняя ошибка, SSH stderr и traceback;
- `out/logs/runtime/error-*.log` — архив ошибок Python;
- `out/logs/runtime/error-*-powershell.log` — архив bootstrap-ошибок;
- `out/logs/runtime/latest-transcript.log` — transcript текущего запуска;
- `out/logs/runtime/latest-console.log` — итог CMD wrapper;
- `out/logs/runtime/latest-bootstrap.log` — каталог, аргументы и bootstrap-контекст.

Большой вывод `OpenSSH_for_Windows ... debug1` и ручной password prompt означают, что был запущен сырой `ssh`, устаревшая копия проекта либо прямой внутренний скрипт. Повтори операцию из актуального корня проекта через `vpn.cmd` и явно выбери режим аутентификации.

## Базовая проверка

```powershell
.\vpn.cmd status --deployment home-vpn --role all
.\vpn.cmd diagnose path --deployment home-vpn
.\vpn.cmd verify live --deployment home-vpn
```

`status` и `diagnose` не меняют локальный VPN-клиент. `verify live` строит эфемерный probe из основного `vless-uri.txt`; он также не перезапускает установленный на компьютере VPN-клиент.
