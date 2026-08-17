# Windows: запуск и диагностика

В примерах `home-vpn` — имя установки. Оно предложено по умолчанию при первой установке; замени его в командах, если было выбрано другое имя.

## Точка входа

Запускай проект из корня репозитория только через `.\vpn.cmd`:

```powershell
.\vpn.cmd
.\vpn.cmd --version
.\vpn.cmd status --deployment home-vpn --node all
.\vpn.cmd verify live --deployment home-vpn
```

`.\vpn.cmd` поднимает portable Python при необходимости, запускает интерфейс и записывает логи. `vpn.ps1` является внутренним bootstrap-файлом и не считается пользовательской точкой входа. Пункт `Выход` закрывает только установщик и не останавливает серверный VPN.

Для автоматического запуска без ожидания клавиши после завершения:

```powershell
$env:VPN_NO_PAUSE="1"
.\vpn.cmd status --deployment home-vpn --node all --non-interactive
```

## SSH-доступ

Мастер предлагает два взаимоисключающих режима. Пароль показан первым, потому что большинство VPS первоначально выдаёт именно его; выбор ключа остаётся доступен вторым пунктом.

### SSH password

Пароль принимает встроенный Python backend без запуска `ssh.exe` и без вывода символов на экран. После успешной SSH-проверки мастер предлагает сохранить пароль в Диспетчере учётных данных Windows. Запись привязана к текущему Windows-пользователю и сочетанию `SSH user + host + port`.

Пароль не сохраняется в `deployments`, `state`, `out`, transcript или Git. Если сохранение не выбрано, он существует только в памяти текущего процесса. Сохранённый пароль автоматически доступен последующим интерактивным и `--non-interactive` командам.

Удалить запись вручную можно через `Панель управления -> Диспетчер учётных данных -> Учётные данные Windows`; имя начинается с `vpn-installer:ssh:`.

Для временной CI-автоматизации поддерживаются `VPN_GATEWAY_SSH_PASSWORD`, `VPN_EXIT_SSH_PASSWORD` и общий `VPN_SSH_PASSWORD`. Не записывай эти значения в файлы проекта или shell history.

### SSH key

- пустое значение: ssh-agent и стандартный поиск ключей OpenSSH;
- `id_ed25519`: стандартный путь `%USERPROFILE%\.ssh\id_ed25519`;
- `C:\Keys\vpn-prod`: полный путь;
- `.\keys\vpn-prod`: явный путь относительно текущего каталога.

Этот режим строго `publickey-only`. Установщик не переходит к password-аутентификации и не показывает ручной prompt `root@host's password`. Если ключ не принят сервером, интерфейс предлагает исправить параметры или явно выбрать `SSH password`.

Host keys обоих режимов проверяются по управляемому файлу `state/known_hosts`. Старый state без явного `auth_mode` не угадывается: мастер заново спрашивает способ входа.

## Ошибки и логи

Интерфейс показывает одну краткую причину и путь к логу. Технические детали находятся в:

- `out\logs\runtime\latest-error.log` — последняя ошибка, SSH stderr и traceback;
- `out\logs\runtime\error-*.log` — архив ошибок Python;
- `out\logs\runtime\error-*-powershell.log` — архив bootstrap-ошибок;
- `out\logs\runtime\latest-transcript.log` — transcript текущего запуска;
- `out\logs\runtime\latest-console.log` — итог CMD wrapper;
- `out\logs\runtime\latest-bootstrap.log` — каталог, аргументы и bootstrap-контекст.

Большой вывод `OpenSSH_for_Windows ... debug1` и ручной prompt `root@host's password` означают, что был запущен сырой `ssh`, устаревшая копия проекта либо прямой внутренний скрипт. Повтори операцию из актуального корня проекта через `.\vpn.cmd` и явно выбери режим аутентификации.

## Базовая проверка

```powershell
.\vpn.cmd status --deployment home-vpn --node all
.\vpn.cmd diagnose path --deployment home-vpn
.\vpn.cmd verify live --deployment home-vpn
```

`status` и `diagnose` не меняют локальный VPN-клиент. `verify live` строит эфемерный probe из основного `vless-uri.txt`; он также не перезапускает установленный на компьютере VPN-клиент.

## Веб-панель

Веб-панель существует только у двойной установки. Адрес печатается после успешной установки. Позже выбери `Показать адрес web-admin` в главном меню либо выполни:

```powershell
.\vpn.cmd admin --deployment home-vpn --open-browser
```

Без `--open-browser` открой напечатанный публичный адрес вручную. Команда только показывает URL, при запросе открывает его в браузере и не меняет текущий VPN-клиент. Firewall разрешает web-порт только source IP, недавно достигшему TCP/UDP VPN ingress; допуск ограничен по времени, а вход дополнительно требует логин и пароль панели. В одиночной установке команда завершится сообщением, что web-admin неприменим.

## Команды и совместимость

Полный список команд с пояснениями: [COMMANDS.md](./COMMANDS.md). Точное окно обновления текущего релиза: [DEPRECATIONS.md](./DEPRECATIONS.md).

Все команды принимают только `--node gateway|exit|all`; `--role` удалён.
