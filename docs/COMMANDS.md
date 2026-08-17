# Команды VPN Installer

Для обычной работы запускай интерактивное меню без аргументов:

| Система | Запуск |
| --- | --- |
| Windows PowerShell | `.\vpn.cmd` |
| Linux shell | `./vpn.sh` |

Команды ниже нужны для автоматизации, диагностики и точного выбора действия. В примерах `home-vpn` — имя установки.

## Пути и синтаксис

- Windows использует обратный слеш: `.\vpn.cmd`, `out\home-vpn\client`.
- Linux использует прямой слеш: `./vpn.sh`, `out/home-vpn/client`.
- Аргументы после точки входа одинаковы на обеих системах.
- `gateway` — сервер, к которому подключается VPN-клиент.
- `exit` — второй, зарубежный сервер двойной схемы.
- `all` — все узлы текущей установки.
- `deployment` — именованная установка, например `home-vpn`.

Версия и встроенная помощь:

```powershell
.\vpn.cmd --version
.\vpn.cmd --help
```

```bash
./vpn.sh --version
./vpn.sh --help
```

## Основные команды

| Команда | Что делает | Изменяет сервер |
| --- | --- | --- |
| `install` | Создаёт или обновляет установку | Да |
| `status` | Показывает сервисы, маршруты, drift и свежие ошибки | Нет |
| `admin` | Показывает адрес web-admin двойной схемы | Нет |
| `verify live` | Проверяет публичный VLESS-путь, DNS, маршруты и загрузку | Нет |
| `diagnose path` | Сохраняет подробный структурный snapshot | Нет |
| `reinstall` | Транзакционно переустанавливает выбранные узлы | Да |
| `maintain` | Показывает обновления; с `--apply` применяет их | Только с `--apply` |
| `remove` | Удаляет серверный стек, сохраняя baseline для восстановления | Да |
| `purge` | Полностью удаляет управляемое серверное состояние | Да |
| `cleanup-local` | Удаляет локальные generated-артефакты | Нет |

Windows:

```powershell
.\vpn.cmd status --deployment home-vpn --node all
.\vpn.cmd verify live --deployment home-vpn
.\vpn.cmd diagnose path --deployment home-vpn --node all
.\vpn.cmd admin --deployment home-vpn --open-browser
```

Linux:

```bash
./vpn.sh status --deployment home-vpn --node all
./vpn.sh verify live --deployment home-vpn
./vpn.sh diagnose path --deployment home-vpn --node all
./vpn.sh admin --deployment home-vpn --open-browser
```

`status` выполняет короткий read-only снимок. `verify live` создаёт временный клиент из основного `vless-uri.txt` и действительно проходит через публичный Reality-вход. Поэтому после установки итог подтверждает именно `verify live`, а не только зелёный `status`.

## Диагностика

| Команда | Когда использовать |
| --- | --- |
| `diagnose path` | Сайты, DNS или межсерверный путь работают нестабильно |
| `diagnose front` | Клиенты не подключаются к публичному gateway |
| `diagnose client --source <IP>` | Проблема проявляется у конкретной внешней сети или устройства за NAT |
| `diagnose client-log --path <файл>` | Нужно разобрать локальный журнал Hiddify/sing-box |
| `client-check` | Нужно проверить, не направляет ли локальный TUN путь до сервера обратно в VPN |
| `android-diagnose` | Android-устройство подключено по USB и нужен bounded ADB logcat |

Пример для Windows:

```powershell
.\vpn.cmd diagnose front --deployment home-vpn
.\vpn.cmd diagnose client --deployment home-vpn --source 203.0.113.25
.\vpn.cmd diagnose client-log --deployment home-vpn --path "C:\Logs\client.log"
```

Пример для Linux:

```bash
./vpn.sh diagnose front --deployment home-vpn
./vpn.sh diagnose client --deployment home-vpn --source 203.0.113.25
./vpn.sh diagnose client-log --deployment home-vpn --path /home/user/client.log
```

`--source` принимает публичный IP проблемной сети, а не локальный адрес вида `192.168.x.x`.

## Правила маршрутизации

В двойной схеме удобнее использовать web-admin. Команды нужны для автоматизации и для одиночной схемы, где панели нет.

```powershell
.\vpn.cmd routes list --deployment home-vpn
.\vpn.cmd routes add --deployment home-vpn --value example.com --outbound direct-ru --include-subdomains
.\vpn.cmd routes remove --deployment home-vpn --id <rule-id>
```

```bash
./vpn.sh routes list --deployment home-vpn
./vpn.sh routes add --deployment home-vpn --value example.com --outbound direct-ru --include-subdomains
./vpn.sh routes remove --deployment home-vpn --id <rule-id>
```

В двойной схеме `direct-ru` означает российский выход, `to-foreign` — зарубежный. В одиночной схеме `--outbound` можно не указывать.

## Обновление и удаление

```powershell
.\vpn.cmd reinstall --deployment home-vpn --node all
.\vpn.cmd maintain --deployment home-vpn
.\vpn.cmd maintain --deployment home-vpn --apply --yes
.\vpn.cmd remove --deployment home-vpn --node all
```

```bash
./vpn.sh reinstall --deployment home-vpn --node all
./vpn.sh maintain --deployment home-vpn
./vpn.sh maintain --deployment home-vpn --apply --yes
./vpn.sh remove --deployment home-vpn --node all
```

`remove` и `purge` требуют подтверждения. `purge` используй только когда baseline и серверное состояние этой установки больше не нужны.

## Non-interactive режим

`--non-interactive` запрещает вопросы и использует connection state. При password-аутентификации пароль берётся из системного хранилища или из `VPN_GATEWAY_SSH_PASSWORD`, `VPN_EXIT_SSH_PASSWORD`, `VPN_SSH_PASSWORD`.

Переменные окружения предназначены для временной автоматизации и CI. Не записывай их в `.env`, shell history или файлы проекта. Для обычной работы сохрани проверенный пароль через интерактивное меню.

## Самопроверка проекта

- `audit quick` — короткая проверка compiler, schemas, contracts и syntax;
- `audit docker` — Docker regression;
- `audit lab` — сетевые и failure-injection сценарии;
- `audit all` — полный release gate.

```powershell
.\vpn.cmd audit quick
```

```bash
./vpn.sh audit quick
```

Эти команды проверяют проект и лабораторные сценарии. Они не заменяют `verify live` на реально установленных серверах.
