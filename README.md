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

Если нужно переустановить без вопросов из консоли, используй штатный CLI, а не временные скрипты:

```powershell
$env:VPN_RU_SSH_PASSWORD="пароль-российского-сервера"
$env:VPN_FOREIGN_SSH_PASSWORD="пароль-зарубежного-сервера"
$env:VPN_NO_PAUSE="1"
.\vpn.cmd reinstall --deployment 1 --role all --non-interactive --yes
.\vpn.cmd status --deployment 1 --role all --non-interactive
```

Пароли из этих переменных используются только в текущем запуске и не сохраняются в `deployments` или `state`.

Если активный TUN направляет IP серверов в самого себя, но у компьютера есть физический интернет-адрес, можно оставить VPN-клиент нетронутым и привязать только SSH control plane к нему:

```powershell
$env:VPN_SSH_BIND_ADDRESS="192.168.0.101"
.\vpn.cmd reinstall --deployment 1 --role all --non-interactive --yes
```

Переменная действует только на текущий запуск и не меняет серверный dataplane, профиль клиента или таблицу маршрутов Windows.

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
- `out/<deployment>/client/hysteria2-uri.txt`
- `out/<deployment>/client/hiddify-android.json`
- `out/<deployment>/client/hiddify-uri.txt`
- `out/<deployment>/client/linux-sing-box.json`
- `out/<deployment>/NEXT-STEPS.txt`

Главный результат:

- простой `VLESS URI` копируется в буфер обмена и считается основным профилем
- `vless-uri.txt` — главный низкоуровневый артефакт для клиентов с поддержкой `VLESS/Reality`
- `windows-xray.json` и `android-v2rayng-xray.json` — JSON fallback, если конкретный клиент не умеет нормально импортировать URI
- `hiddify-cross-platform.json` — route-safe VLESS/Reality-профиль с явно выключенным multiplex
- `hysteria2-uri.txt` — стандартный дополнительный QUIC URI для импорта в Hiddify/v2rayN
- `hiddify-android.json` — Android-safe вариант того же mux-free VLESS-профиля
- `hiddify-uri.txt` — совместимый alias того же `VLESS URI` для старых сценариев
- `v2rayn-uri.txt` — удобный alias того же `VLESS URI` для v2rayN

## Как подключить клиент

1. Сначала импортируй простой `vless-uri.txt`
2. Если клиент поддерживает JSON, `hiddify-cross-platform.json` и `hiddify-android.json` задают тот же VLESS/Reality-контракт, route bypass и `multiplex.enabled=false`; это исключает TCP head-of-line blocking между независимыми загрузками
3. Для отдельного QUIC-узла в Hiddify/v2rayN используй `hysteria2-uri.txt`; сертификат проверяется SHA-256 pin, а `vless-uri.txt` остаётся основным контрактом
4. Ручное переключение клиентского VLESS/Hysteria2 узла применяется только к новым соединениям; серверный межсерверный failover работает ниже TCP внутри стабильного WireGuard overlay и не повторяет application payload
5. Для v2rayN скопируй URI из `v2rayn-uri.txt` и выбери импорт share link из буфера; отдельный custom-config слой не добавляется
6. Клиентский multiplex для VLESS должен оставаться выключенным: он сокращает handshakes, но объединяет независимые загрузки в один TCP-поток; `vpn diagnose client` показывает такое объединение по активному outer socket
7. Если сайты висят, сначала смотри `vpn status --deployment <name> --role ru-gateway`, затем запускай свежую acceptance-проверку `vpn verify live --deployment <name>`
8. `vpn status` выводит отдельные счётчики DNS, domain, IPv4-literal, IPv6-literal и private/fake ошибок за свежее и историческое окна
9. Если включён TUN/full VPN и `client-check` показывает self-tunnel, используй route bypass helper ниже

Основной публичный вход принимает обычный VLESS/Reality tunnel через Xray TCP `:443` и передаёт трафик во внутренний `sing-box` router. На UDP того же порта работает дополнительный Hysteria2 ingress для стандартного `hysteria2://` URI; он использует ту же routing policy. Если клиент отправляет private/fake IP вроде `fdfd::...` без домена, такие случаи явно группируются в `status/diagnose`.

Внешняя подписка с сервера больше не считается штатным путём; локальные JSON остаются управляемым вариантом.

Сервер остаётся источником истины для split-маршрутизации: клиенту не нужно знать, что считать российским или зарубежным трафиком. Он просто даёт туннель до `российского сервера`, а сама логика маршрутов живёт на серверной стороне.

Между серверами foreign-трафик идёт внутри одного стабильного kernel WireGuard overlay. Его локальный endpoint может без перезапуска интерфейса переключаться между userspace WireGuard и Hysteria2/QUIC до того же foreign egress. Agent проверяет оба underlay bounded-probe каждые `2s`, подтверждает отказ дважды и закрывает только старую локальную UDP-association; уже открытые TCP-потоки остаются внутри overlay. Изменение по задержке требует преимущества больше `30 ms` три цикла подряд. Оба underlay заканчиваются на одном зарубежном VPS, поэтому это transport redundancy, а не второй независимый egress. Публичный клиентский контракт остаётся тем же VLESS/Reality URI; дополнительно выпускаются mux-free VLESS JSON и стандартный `hysteria2://` URI.

Системные DNS-запросы серверов проходят через локальный cache `systemd-resolved` с независимыми Cloudflare, Quad9 и Google upstreams. При кратком отказе upstream известные positive records могут обслуживаться из stale cache до одного часа; этот resolver является частью manifest и откатывается вместе с release.

В локальных JSON-профилях IP самих `российского` и `зарубежного` серверов автоматически исключаются из клиентского туннеля. Это нужно, чтобы можно было запускать `vpn status/reinstall/remove` с того же компьютера даже при уже активном VPN-подключении. Сырой `VLESS URI` сам по себе такие исключения не кодирует; если клиент в TUN/full VPN заворачивает IP сервера в свой же туннель, используй JSON-профиль или добавь bypass/direct rule в клиенте.

Быстрая проверка этой проблемы:

```powershell
.\vpn.cmd client-check --deployment 1
```

Если команда пишет `BAD: self-tunnel`, сначала попробуй временно задать `VPN_SSH_BIND_ADDRESS` на IPv4 физического интерфейса. Если отдельного физического пути нет, отключи VPN перед обслуживанием серверов или используй route-safe JSON из `out/<deployment>/client`.

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

## Веб-интерфейс исключений

После установки на `российском сервере` поднимается простой web admin для изменения server-side исключений без ручного редактирования env-файлов. По умолчанию он слушает `0.0.0.0:11333`, но firewall и приложение пускают только текущих активных VPN-клиентов.

Открой, когда VPN уже подключён:

```text
http://<ip-российского-сервера>:11333
```

Стартовый доступ: `user` / `password`. Сразу поменяй его на странице `Доступ`.

В разделе `Исключения` можно добавить домен, `*.example.com` или CIDR и выбрать, через какой сервер открывать: `российский сервер` или `зарубежный сервер`. После сохранения правило проверяется и применяется на сервере сразу.

Как работает доступ:

- `ADMIN_WEB_ACTIVE_CLIENT_REQUIRED=1` — порт доступен только IP-адресам с активной Xray/TCP-сессией или подтверждённой Hysteria2/QUIC-сессией к VPN-порту российского сервера; одиночный неаутентифицированный UDP-пакет доступ не открывает.
- `ADMIN_WEB_ALLOW_TUNNEL_CLIENTS=1` — если браузер пришёл в админку через VPN/hairpin и сервер видит source как свой или соседний серверный IP, такой вход разрешён только пока есть хотя бы один активный VPN-клиент.
- `ADMIN_WEB_ALLOWED_CIDR` и `ADMIN_WEB_ALLOW_WG` остаются аварийными ручными allowlist-настройками.

SSH-туннель остаётся запасным способом администрирования: `ssh -L 11333:127.0.0.1:11333 root@<ip-российского-сервера>` и затем `http://127.0.0.1:11333`.

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

Для быстрой структурной проверки после установки:

```powershell
.\vpn.cmd status --deployment my-vpn
```

```bash
./vpn.sh status --deployment my-vpn
```

Для обязательной live-приёмки после `install/reinstall`:

```powershell
.\vpn.cmd verify live --deployment my-vpn --non-interactive
```

`status` читает services, manifest, WireGuard, оба public transport и журналы без нагрузочных скачиваний. `verify live` дополнительно запускает свежие DNS/domain/literal probes и два эфемерных внешних sing-box client: канонический из `vless-uri.txt` проходит Reality/TCP, второй проходит Hysteria2/QUIC. Каждый подтверждает HTTP, UDP DNS, TCP IPv6 literal, обе egress identity и девять независимых first-load запросов. Только эта команда может подтвердить dataplane после переустановки.

Для release throughput acceptance запусти короткое 60-секундное измерение через тот же VLESS path. Первые 30 секунд проверяют доступную capacity без rate limit, оставшееся окно держит одно HTTPS-соединение с cap 16 Mbit/s и требует не менее 10 Mbit/s без обрывов. Runner использует два Hetzner endpoint и независимый Cloudflare payload; минимум два источника должны реально передать данные, а отказ одного CDN сохраняется в `source_metrics` без ложного verdict о поломке VPN. Global lock исключает конкурирующие запуски, а controller lease и target-side deadline завершают process group при потере управляющей команды. Нагрузка запускается только явным флагом:

```powershell
.\vpn.cmd verify live --deployment my-vpn --non-interactive --throughput-seconds 60
```

Если начались потери, высокий ping или просадка скорости, собери структурный snapshot:

```powershell
.\vpn.cmd diagnose path --deployment my-vpn
```

Отчёт сохраняется в `out/diagnostics` как JSON. Для конкретного устройства используй `vpn diagnose client --source <public-ip>`: он группирует TCP socket state, retransmitted bytes/ratio, PMTU, MSS, cwnd, delivery rate, reordering и Xray events именно по этому source IP. IPv4-mapped IPv6 из kernel `ss` нормализуется к тому же IPv4 ключу. Активные `ESTAB` flows и closing states учитываются раздельно: накопленная потеря активного сокета выводится как `loss_observed`, свежая потеря считается по монотонным дельтам того же kernel socket ID, а `FIN-WAIT` churn не подменяет собой потерю данных. Только измеренная потеря текущего интервала или подтверждённый RTT/RTO stall дают `client_specific/degraded`; agent не закрывает потоки и не меняет маршрут по этому soft signal.

Для самопроверки на обычном пользовательском ПК:

- `quick` — это пользовательская быстрая проверка, без unit/coverage, Docker и lab-контуров
- `quick` можно запускать без `docker`
- dev-only проверки в `quick` будут помечены как `skipped`, а не как ошибка
- полный контур для разработки и регрессий — это `vpn audit all`

`vpn status` печатает состояние сервисов и последние наблюдения:

- observed public IPv4 на `зарубежном сервере`
- observed public IPv4 для `российского сервера` через `wg0`
- возраст `WireGuard` handshake
- выбранный межсерверный transport, результат последней проверки выбранного пути и состояние failover/recovery
- состояние server DNS stub/cache и список managed upstreams
- root filesystem: ext4 state/error counters, загрузочный `fsck` и отдельный `host_integrity`
- отдельные verdict: `server_path`, `public_front`, `client_observation`, `host_integrity`
- debt/maintenance: доступные security updates и reboot-required

Если локальный `deployments/<name>.env` разъехался с уже установленным сервером, lifecycle-команды сначала подтянут живой `/etc/vpn-stack/deployment.env`. Read-only `status`, `verify` и `diagnose` не меняют локальные клиентские артефакты.

Плановое обслуживание серверов отделено от runtime health:

```powershell
.\vpn.cmd maintain --deployment my-vpn
.\vpn.cmd maintain --deployment my-vpn --apply --yes --non-interactive
```

`maintain` сначала только показывает обновления. Применение идёт по ролям и после каждой роли требует свежую verification; web-admin и его явные rules при этом сохраняются.
