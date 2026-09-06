# Команды VPN Installer

Для обычной работы запускай интерактивное меню без аргументов:

| Система | Запуск |
| --- | --- |
| Windows PowerShell | `.\vpn.cmd` |
| Терминал Linux | `./vpn.sh` |

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

## Серверная платформа

Перед установкой программа проверяет сервер, не меняя его настройки. Она определяет дистрибутив Linux и автоматически выбирает средство установки пакетов. Указывать ОС отдельным аргументом не нужно.

| Серверная ОС | Средство установки пакетов |
| --- | --- |
| Ubuntu 22.04/24.04/26.04, Debian 12/13 | `apt` |
| AlmaLinux/Rocky Linux 9/10 | `dnf` (DNF4) |
| Fedora 43/44 | `dnf5` |

Для всех перечисленных ОС обязательны архитектура `x86_64`, система запуска служб `systemd` и отсутствие активного `ufw`/`firewalld`. Установщик не отключает сторонний сетевой экран: он создаёт только собственные правила через `nftables`. DNS-кеш запускается отдельной службой проекта и не заменяет системную службу разрешения доменных имён.

Подробные требования к платформе, порядок установки пакетов и перечень управляемых настроек описаны в [PLATFORMS.md](./PLATFORMS.md).

## Основные команды

| Команда | Что делает | Изменяет сервер |
| --- | --- | --- |
| `install` | Создаёт или обновляет установку | Да |
| `status` | Показывает службы, маршруты, отклонения от установленной конфигурации и свежие ошибки | Нет |
| `admin` | Показывает адрес веб-панели двойной схемы | Нет |
| `verify live` | Проверяет подключение по VLESS, DNS, маршруты и загрузку данных | Нет |
| `diagnose path` | Сохраняет подробный снимок состояния для диагностики | Нет |
| `reinstall` | Переустанавливает выбранные серверы с возвратом предыдущего состояния при неудаче | Да |
| `maintain` | Показывает обновления; с `--apply` применяет их | Только с `--apply` |
| `remove` | Удаляет серверную часть VPN, сохраняя копию исходного состояния для восстановления | Да |
| `purge` | Полностью удаляет управляемое серверное состояние | Да |
| `cleanup-local` | Удаляет созданные установщиком файлы на компьютере | Нет |

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

`status` собирает краткое состояние сервера без изменения настроек. `verify live` создаёт временный клиент из основного `vless-uri.txt` и проверяет соединение через тот же порт Reality, к которому подключаются устройства. Поэтому после установки соединение подтверждает именно `verify live`, а не только успешный результат `status`.

## Диагностика

| Команда | Когда использовать |
| --- | --- |
| `diagnose path` | Сайты, DNS или межсерверный путь работают нестабильно |
| `diagnose front` | Клиенты не подключаются к серверу входа |
| `diagnose client --source <IP>` | Проблема проявляется у конкретной внешней сети или устройства за NAT |
| `diagnose client-log --path <файл>` | Нужно разобрать локальный журнал Hiddify/sing-box |
| `diagnose telegram --destination <IP>` | Telegram зависает на подключении; проверить конкретный адрес из журнала |
| `client-check` | Нужно проверить, не направляет ли виртуальный сетевой интерфейс клиента (TUN) соединение с сервером обратно в VPN |
| `android-diagnose` | Android-устройство подключено по USB и нужен ограниченный фрагмент журнала Android через ADB |

Пример для Windows:

```powershell
.\vpn.cmd diagnose front --deployment home-vpn
.\vpn.cmd diagnose client --deployment home-vpn --source 203.0.113.25
.\vpn.cmd diagnose client-log --deployment home-vpn --path "C:\Logs\client.log"
.\vpn.cmd diagnose telegram --deployment home-vpn --node all --destination 149.154.167.41
```

Пример для Linux:

```bash
./vpn.sh diagnose front --deployment home-vpn
./vpn.sh diagnose client --deployment home-vpn --source 203.0.113.25
./vpn.sh diagnose client-log --deployment home-vpn --path /home/user/client.log
./vpn.sh diagnose telegram --deployment home-vpn --node all --destination 149.154.167.41
```

`--source` принимает публичный IP проблемной сети, а не локальный адрес вида `192.168.x.x`.

`diagnose path` сохраняет отдельный JSON-отчёт для каждого сервера. Код завершения `0` означает, что отчёты собраны, а не что все подключения исправны. Код `1` означает, что хотя бы один обязательный отчёт получить не удалось; причина записана в его JSON, остальные отчёты сохраняются. Проверка сайтов через `verify live` не заменяет проверку конкретного приложения, например протокола Telegram.

`diagnose telegram` не требует входа в аккаунт. В двойной схеме команда сравнивает ответ через маршрутизатор сервера входа и напрямую с сервера выхода. Вместо адреса из примера укажи проблемный IP из журнала; можно повторить `--destination` до восьми раз. По умолчанию используется порт `443`, другой порт записывается как `IP:порт`, IPv6 как `[IPv6]:порт`. Отчёт `telegram.json` сохраняется в указанном командой каталоге `out/diagnostics`.

Для этой команды код `0` означает ответ протокола от всех выбранных адресов, `1` означает отказ хотя бы одной проверки, `2` означает неполную или некорректную диагностику. Ответ протокола не доказывает отправку сообщений, загрузку медиа или работоспособность сети телефона. Команда не меняет маршруты и не запускает фоновое наблюдение.

## Правила маршрутизации

В двойной схеме правилами управляют через веб-панель или команды. Команды также доступны для автоматизации и для одиночной схемы, где панели нет.

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

`remove` и `purge` требуют подтверждения. `purge` используй только когда копия исходного состояния и серверные данные этой установки больше не нужны.

## Режим без вопросов

`--non-interactive` отключает вопросы и использует сохранённые параметры подключения. При входе по паролю он берётся из системного хранилища или из `VPN_GATEWAY_SSH_PASSWORD`, `VPN_EXIT_SSH_PASSWORD`, `VPN_SSH_PASSWORD`. ОС, архитектура, система запуска служб и сетевой экран проверяются так же, как при работе через меню.

Переменные окружения предназначены для временного использования в автоматических запусках. Не записывай их значения в `.env`, историю команд терминала или файлы проекта. Для обычной работы сохрани проверенный пароль через интерактивное меню.

## Самопроверка проекта

- `audit quick` — короткая проверка генерации настроек, форматов данных, интерфейсов компонентов и синтаксиса;
- `audit docker` — проверка компонентов в Docker на ошибки после изменений;
- `audit lab` — сетевые сценарии, в том числе с искусственно вызванными отказами;
- `audit all` — полный набор проверок перед выпуском версии.

```powershell
.\vpn.cmd audit quick
```

```bash
./vpn.sh audit quick
```

Эти команды проверяют проект и лабораторные сценарии. Они не заменяют `verify live` на реально установленных серверах.
