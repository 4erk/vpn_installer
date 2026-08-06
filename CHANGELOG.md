# Changelog

Проект использует `SemVer`: `major.minor.patch`.

- `major` — несовместимые изменения в публичном поведении
- `minor` — новые возможности без обязательной ломки старого сценария
- `patch` — исправления багов и точечные доработки

## [0.15.2] - 2026-08-06

### Fixed

- Существующие `hiddify-cross-platform.json`, `hiddify-android.json` и `linux-sing-box.json` теперь используют основной VLESS/Reality transport с явно выключенным multiplex. Это не даёт нескольким загрузкам делить один внешний TCP congestion window и одновременно сохраняет UDP/XUDP для DNS; дополнительные файлы и timeout-параметры не добавлены.
- `vpn diagnose client` определяет multiplex по нескольким Xray TCP accept-событиям на одном активном outer socket и отдельно выводит риск `tcp_head_of_line`. UDP-события и закрытые сокеты в этот признак не попадают.

### Changed

- Основной `vless-uri.txt` и серверный dataplane не изменены. Отдельный `hysteria2-uri.txt` сохранён как явный дополнительный QUIC transport; web-admin сохранён.

## [0.15.1] - 2026-08-06

### Fixed

- Throughput acceptance больше не зависит от двух endpoint одного Hetzner-контура. Capacity измеряется по Hetzner FSN, Hetzner NBG и независимому Cloudflare payload; для доказательства доступны должны быть минимум два источника.
- Отказ отдельного speed-source остаётся в `source_metrics`, но не объявляет VPN сломанным, если два независимых источника успешно передают данные. Нулевая передача, недостаточное покрытие источников, обрыв stability-окна и скорость ниже release floor по-прежнему дают `failed`.

### Changed

- Dataplane, `vless-uri.txt`, Hysteria2 URI, server routing и web-admin не изменены. Патч исправляет только ложный release verdict, обнаруженный сравнением `RU direct`, `wg0`, sing-box router и public transport на одинаковом payload.

## [0.15.0] - 2026-08-06

### Added

- Добавлен стандартный `hysteria2-uri.txt` для прямого импорта дополнительного QUIC transport в Hiddify/v2rayN. Self-signed TLS не остаётся без проверки: URI содержит certificate SHA-256 pin и SNI; существующие JSON продолжают использовать pinned SPKI.

### Fixed

- Health больше не объявляет generic `/sys/class/net/*/rx_dropped`, host-wide TCP retransmissions или TCP timeouts деградацией VPN. На production foreign эти counters стабильно росли из-за виртуального WAN и посторонних host sockets при нулевых `virtio_net rx_queue drops`, `rx_missed`, softnet drops и исправном dataplane. Сырые дельты остаются в snapshot как явно unscoped informational telemetry; verdict формируют scoped Xray-flow, UDP buffer/softnet/missed, conntrack и route evidence.
- Fresh TCP-front interval с несколькими служебными байтами теперь помечается `insufficient`, а не показывает высокий процент retransmit как полноценное наблюдение. Порог деградации для реального payload не ослаблен.

### Changed

- `audit quick` проверяет стандартную схему и certificate pin нового Hysteria2 URI. Самописный client selector/controller не добавляется: sing-box selector управляет только новыми соединениями и не может безопасно повторить частично переданный запрос.
- Основной `vless-uri.txt`, публичные TCP/UDP ingress, server routing, web-admin и локальный VPN-клиент не изменены.

## [0.14.2] - 2026-08-04

### Fixed

- Основным межсерверным transport снова стал измеренно стабильный WireGuard. Hysteria2 сохранён как автоматически проверяемый резерв: после двух подтверждённых отказов WG selector переводит только новые соединения на Hysteria2 и возвращается после двух успешных WG-проб, не прерывая существующие потоки и не используя RU-direct.
- Из публичного Xray inbound удалён socket-local `TCP_USER_TIMEOUT=30s`. Он преждевременно завершал established-потоки при краткой потере подтверждений и не устранял наблюдавшийся `FIN-WAIT-1`; штатные TCP recovery и keepalive снова отвечают за восстановление соединения.
- Восстановлено кеширование TCP destination metrics (`tcp_no_metrics_save=0`). Installer больше не выполняет безусловный `ip tcp_metrics flush all`, поэтому частые короткие Reality-соединения сохраняют выученные RTT/MSS, а PLPMTUD по-прежнему адаптируется к реальному path failure.
- Fresh-interval диагностика публичного TCP-front больше не ждёт накопления одного мегабайта lifetime-трафика: подтверждённые retransmissions и loss ratio классифицируются в текущем health cycle. Интерфейсные RX drops, host-wide TCP retransmissions и TCP timeouts выводятся как soft degradation и никогда сами не запускают restart или смену маршрута.
- В управляемых sing-box и Xray client JSON multiplex явно выключен. Это исключает объединение независимых загрузок в один VLESS substream; основной простой VLESS URI при этом не меняется.
- Audit runner получил атомарный repository lock и run-specific Docker labels. Параллельный или переживший timeout процесс больше не удаляет контейнеры другого запуска; stale cleanup пропускает ресурсы текущего run, а уже начатое идемпотентное удаление не считается дефектом dataplane.
- Полный audit больше не зависит от повторного скачивания rule assets из внешних CDN: runtime/render проверки используют уже проверенный локальный cache, а отказ и rollback загрузки остаются отдельным Docker-сценарием. Это убирает три последовательных TLS timeout из каждого запуска без сокращения acceptance-покрытия.
- Загрузка уже существующего deployment env больше не генерирует и не устанавливает через PyPI новую межсерверную certificate identity, которая затем всё равно перезаписывалась сохранённой. Identity обрабатывается как атомарный набор: полная существующая сохраняется, полная fallback используется для миграции, а несовместимые частичные фрагменты не смешиваются.
- Единый audit image теперь обязательно проверяется на наличие `cryptography`, а role-scoped workflow использует его вместо голого `python:3.13`; transport certificate валидируется без runtime-установки из PyPI. Lab dataplane после явного seed также использует только локальные assets, поэтому внешний network outage больше не превращается в многоминутный тестовый timeout.
- Проверка transport certificate поддерживает timezone-aware validity API `cryptography 41..46`; Ubuntu 24.04 package больше не падает на поле, появившемся только в поздних версиях, при этом проверки соответствия cert/key, pin, SAN и срока действия сохранены.
- Из Hiddify/sing-box JSON удалён latency-based `urltest`. Физический A/B показал, что он может выбрать кратковременно быстрый TCP path, но не повторяет зависший запрос по QUIC. Управляемые JSON теперь напрямую используют Hysteria2/QUIC для DNS и данных; неиспользуемый VLESS outbound и selector knobs удалены.

### Changed

- Agent, status, verifier и тесты используют одну семантику `WireGuard primary -> Hysteria2 fallback`; transport state schema повышена до `4`, policy/version — до `0.14.2`.
- Hiddify/sing-box JSON для деградирующего TCP path стал детерминированным Hysteria2/QUIC-профилем. Имена артефактов сохранены; основной `vless-uri.txt` остаётся отдельным Reality/TCP-контрактом для сетей без UDP.
- Основной `out/1/client/vless-uri.txt`, публичный Reality/Vision front, web-admin и server-side split routing не изменены.

## [0.14.1] - 2026-08-04

### Fixed

- Удалено ошибочное принудительное RU-direct направление глобального CDN `*.gstatic.com`, Google messaging и Microsoft connectivity endpoints. Они снова используют общий foreign-route и не зависят от доступности глобальных сервисов из российского дата-центра.
- Нормализация deployment env и operator overlays удаляет устаревшие `.gstatic.com`/`mtalk.google.com`; renderer дополнительно не допускает их возврата из старого server-authoritative env.

### Changed

- Класс маршрутизации `connectivity_check` удалён: разрешённые точные RU-домены, suffix-правила и `ru-geosite` теперь компилируются единым `ru_direct_domain` без дублирования route-решений.
- Runtime-аудит запрещает попадание глобальных CDN в `direct-ru` и проверяет порядок explicit foreign overrides перед `ru-geosite`; основной `vless-uri.txt` остаётся неизменным.
- Четыре дублирующих Docker lifecycle-сценария объединены в одну role-scoped matrix для `status`, `reinstall`, `remove` и `purge`; внешний asset network больше не влияет на этот тест.
- Адаптивные Hiddify/sing-box профили ставят канонический VLESS перед Hysteria2: нативный `urltest` сохраняет основной путь при сопоставимом latency и использует QUIC как доступный fallback, а не как безусловительный speed preference.
- Throughput acceptance разделён по роли: основной VLESS сохраняет floor `50 Mbit/s`, резервный Hysteria2 обязан обеспечить минимум `10 Mbit/s`; общий stability floor остаётся `10 Mbit/s` без transfer failures.

## [0.14.0] - 2026-08-04

### Changed

- Межсерверный supervisor переведён на selected-path priority policy. В штатном состоянии он проверяет только выбранный Hysteria2 раз в две секунды; лёгкий health также не зондирует dormant WireGuard. Первый отказ немедленно подтверждается второй попыткой, одновременно проверяется fallback, поэтому подтверждённый переход занимает не больше одного короткого confirmation cycle. WireGuard отдельно доказывается обязательной release acceptance.
- Переключение больше не зависит от synthetic RTT, rolling median/MAD, socket-drop counters или quality tolerance. Эти сигналы полезны для диагностики, но не доказывают отказ пользовательского пути и больше не вызывают route churn.
- Возврат с WireGuard на Hysteria2 требует двух последовательных успехов. `interrupt_exist_connections=false` сохраняет уже установленные потоки; новый transport применяется только к новым соединениям.

### Security

- Внутренний Hysteria2 между RU и foreign использует Salamander с отдельным ключом, детерминированно выведенным из deployment secret. Публичный VLESS URI и ранее импортированные клиентские профили не меняются.
- Foreign nftables принимает WireGuard и Hysteria2 только от RU public IP. `PersistentKeepalive` удалён: оба VPS имеют прямые публичные адреса, а резервный tunnel активируется реальным probe/traffic по необходимости.

### Removed

- Удалены transport shadow mode, дублирующее shadow-state, rolling history/scoring и decision logic на общесистемных UDP counters. Миграция удаляет старый state-файл при штатной переустановке.

### Fixed

- `diagnose client` больше не возвращает process failure для одного `loss_observed`: это lifetime counters открытых сокетов, а не доказанная свежая деградация. Verdict и метрики сохраняются в отчёте; ненулевой код остаётся для текущего `degraded`, front rejection и отсутствующего ожидаемого server evidence.
- Transport state сохраняет `checked=false` для dormant fallback; нормализация больше не превращает явно непроверенный кандидат в проверенный только из-за наличия структурных полей.

Основной `out/1/client/vless-uri.txt`, публичные TCP/UDP ingress, web-admin, routing classes, WireGuard MTU и локальный VPN-клиент не изменены.

## [0.13.0] - 2026-08-03

### Added

- RU получил второй публичный transport на том же `:443`: Xray продолжает принимать основной VLESS/Reality по TCP, а sing-box принимает аутентифицированный Hysteria2 по UDP. Оба входа используют одну server-side routing policy, foreign-трафик не переводится в `direct-ru`.
- `hiddify-cross-platform.json`, `hiddify-android.json` и `linux-sing-box.json` теперь содержат нативный sing-box `urltest` из QUIC и канонического VLESS/Reality. QUIC стоит первым при сопоставимом delay, недоступный UDP автоматически оставляет новые соединения на TCP, а `interrupt_exist_connections=false` не обрывает уже установленные потоки.
- `verify live` независимо строит и запускает два эфемерных внешних клиента: из неизменного `vless-uri.txt` и из публичного Hysteria2 transport. Оба обязаны подтвердить RU/foreign identity, HTTP, UDP DNS, IPv6 literal, private/fake reject и first-load reliability; явный throughput-флаг проверяет оба пути.
- Manifest/agent/activation gate проверяют public Hysteria2 config, UDP listener и nftables allow/notrack. `status` показывает этот transport отдельно от межсерверного Hysteria2/WireGuard selector.
- Web-admin сохранён: active-client gate объединяет установленные Xray/TCP-сокеты с аутентифицированными `public-hy2-in` sessions из локального Clash API. Неаутентифицированный UDP traffic не добавляет source IP в firewall allow-set.

### Fixed

- TCP-front telemetry больше не смешивает `ESTAB` с `FIN-WAIT-*`, `LAST-ACK` и другими closing states. Fresh interval считает только монотонные counters активных data sockets; неподтверждённое закрытие выводится отдельным `closing_churn` и не выдаётся за потерю пользовательской передачи.
- Общесистемные TCP retransmit counters явно помечены как host-wide. Public-front verdict по-прежнему деградирует на измеренной потере активных flows, но closing churn остаётся soft evidence и не запускает restart или route switch.
- Health timer сохраняет полный structured state на диске, но пишет в journald только bounded summary без списка TCP flows. Web-admin обновляет nft allow-set с интервалом, производным от уже существующего element timeout, вместо постоянного односекундного polling.

Основной `out/1/client/vless-uri.txt`, его Hiddify/v2rayN URI aliases, Xray/Reality TCP front, web-admin, server-side split-routing, WireGuard MTU и локальный VPN-клиент не изменены.

## [0.12.8] - 2026-08-01

### Fixed

- `host_integrity` разрешает kernel alias корневого block device (`/dev/root`, mapper и обычные device paths) через его `major:minor` и `/sys/dev/block/.../uevent`. Ext4 counters на RU больше не ищутся по ошибочному имени `/sys/fs/ext4/root`.
- Регрессия воспроизводит production layout `/dev/root -> DEVNAME=vda1`; обязательный activation gate остаётся fail-closed при действительно отсутствующем runtime counter.

Dataplane-конфиги и клиентские артефакты не изменены относительно `0.12.7`.

## [0.12.7] - 2026-08-01

### Fixed

- Snapshot schema 2 и `status` получили отдельный `host_integrity`: agent читает ext4 state и error counters корневого раздела, а также обязательный `fs_passno` из `/etc/fstab`. Повреждение metadata теперь даёт hard failure и блокирует release acceptance вместо ложного green-verdict.
- Health не пытается исправлять повреждение файловой системы перезапуском VPN-сервисов. После двух подтверждений состояние становится `failed` с причиной `host_integrity`; восстановление требует offline fsck.
- Свежая потеря публичного Xray TCP-front теперь агрегируется по source IP между всеми продолжающимися kernel socket ID. Потеря, распределённая по нескольким небольшим потокам одного клиента, больше не скрывается из-за per-flow порога.
- `diagnose client` различает свежую деградацию и накопленные counters открытых сокетов: первый случай даёт `degraded`, второй — явный `loss_observed`. `status` дополнительно показывает свежие interface drop/error deltas без автоматической смены маршрутов или sysctl.
- Target-side activation требует `host_integrity=verified`; `e2fsprogs` закреплён как install dependency.
- Внешние команды audit получили bounded timeout с сохранением partial stdout/stderr; зависший Docker CLI теперь даёт определённый failed-result и cleanup вместо бесконечного full-audit.

На foreign сервере перед выпуском выполнен offline fsck подтверждённо повреждённого ext4 root, сброшены error counters и включена загрузочная проверка. Routing policy, основной `vless-uri.txt`, Xray/Reality, web-admin, WireGuard MTU и локальный VPN-клиент не изменены.

## [0.12.6] - 2026-07-31

### Fixed

- Нагрузочный VLESS verifier передаёт `timeout` точный наносекундный остаток каждой capacity/stability-фазы. Последняя capacity-загрузка больше не округляется вверх до целой секунды и не создаёт ложный `failed` из-за укороченного stability-окна при исправном dataplane.

Маршрутизация, серверные сервисы, основной `vless-uri.txt`, web-admin и локальный VPN-клиент не изменены.

## [0.12.5] - 2026-07-31

### Added

- Transport supervisor получил безопасный `--shadow` режим: он собирает те же парные Hysteria2/WireGuard probes и сохраняет отдельное состояние, но не вызывает selector `PUT`.
- Public-front telemetry считает свежие retransmit-дельты по стабильному kernel socket ID. Закрытый, повторно использованный, сбросивший счётчики или оставшийся после паузы health socket не склеивается с новым потоком.
- Генерируется `v2rayn-uri.txt` как точная копия основного `vless-uri.txt` для импорта share link в v2rayN из буфера обмена. Второй клиентский transport, DNS policy или локальные сетевые настройки не добавляются.

### Fixed

- Hysteria2 и WireGuard теперь проверяются одновременно в каждом transport cycle. Решение использует bounded rolling median и требует подтверждения; одиночный delay outlier не меняет selector.
- Общесистемные `UdpRcvbufErrors` остаются диагностикой и больше не могут сами вызвать transport switch. Passive loss участвует в решении только как свежая дельта конкретного Hysteria-сокета и только когда парная проверка подтверждает худший путь.
- Возврат с WireGuard на Hysteria2 требует трёх подтверждений, а внешнее изменение selector сбрасывает незавершённое решение. Существующие соединения не прерываются, foreign traffic не переводится в RU-direct.
- Status помечает устаревшие selector measurements и adaptive/shadow state как stale вместо выдачи старой рекомендации за текущую.
- `audit quick` использует уже проверенный локальный asset cache и больше не ждёт последовательные сетевые timeout. Канонический клиентский config check выполняется параллельно в существующем RU runtime-контейнере; эквивалентность Hiddify-варианта проверяется структурно, а полный аудит по-прежнему компилирует оба. Обновление rule assets остаётся явной операцией полного аудита, рендера или maintenance.
- Внешний VLESS verifier гарантированно закрывает SOCKS control и UDP probe sockets также при ошибке; unit-run больше не маскирует утечки дескрипторов `ResourceWarning`.

Публичный `vless-uri.txt`, Xray/Reality, web-admin, WireGuard MTU и локальный VPN-клиент не изменены.

## [0.12.4] - 2026-07-27

### Fixed

- Публичный Xray inbound теперь задаёт socket-local `TCP_USER_TIMEOUT=30s`. Здоровые и idle-соединения не затрагиваются, но TCP-flow с неподтверждёнными данными больше не остаётся в `ESTAB`/`FIN-WAIT-1` на системном WAN timeout после краткого обрыва клиентского маршрута.
- `public_front` больше не считается `verified` только по active/listening Xray: подтверждённые RTT/RTO/retransmit и socket churn дают отдельный `degraded`, не запуская restart сервисов и не переводя foreign-трафик в RU-direct.
- Snapshot и live acceptance проверяют установленную Xray liveness-policy вместе с manifest. Основной `vless-uri.txt`, Reality/Vision, маршрутизация, межсерверный transport, WireGuard и web-admin не изменены.

## [0.12.3] - 2026-07-25

### Fixed

- Исправлено подтверждённое переполнение receive buffer RU Hysteria2: в трёх burst-окнах за сутки накопилось `12205` новых `UdpRcvbufErrors`. Единый managed profile увеличивает `rmem_default` с 4 до 8 MiB при прежнем ceiling 16 MiB; route policy, transport selector и MTU не меняются.
- PLPMTUD больше не может уменьшить MSS публичного Xray TCP-flow до наблюдавшихся `48/256`: managed minimum закреплён на `536`.
- Новые подключения больше не наследуют повреждённые RTT, cwnd и reordering из TCP destination cache после краткого сбоя клиентского маршрута. RU front отключает сохранение таких метрик, а штатная установка один раз очищает прежний cache перед acceptance.
- Snapshot, status и live acceptance проверяют фактические UDP buffer, PLPMTUD floor и TCP metrics policy. Отсутствующий runtime-инвариант даёт явный `degraded`.

Публичный `vless-uri.txt`, Reality, web-admin, routing policy, WireGuard MTU и локальный VPN-клиент не изменены.

## [0.12.2] - 2026-07-23

### Fixed

- Удалён не срабатывавший на production механизм принудительного закрытия Xray TCP-flow через `ss -K`. Восстановлением соединения снова управляет transport; health не вмешивается в пользовательские сокеты.
- Lifetime retransmit-счётчики открытого сокета больше не превращаются в текущую `client_specific/degraded`. Такое состояние требует совместных признаков retransmit, высокого RTT и RTO одного активного flow; накопленная потеря остаётся видимой как `loss_observed`.
- Одиночный timeout primary transport probe теперь даёт `suspect` без переключения selector. Переход с Hysteria2 на WireGuard выполняется после двух последовательных отказов, а следующий успешный probe сбрасывает подозрение.

Релиз уменьшает agent и тестовый compatibility-код. Routing policy, публичный `vless-uri.txt`, Xray Reality front и локальный VPN-клиент не изменены.

## [0.12.1] - 2026-07-22

### Fixed

- Health-agent теперь распознаёт один подтверждённо зависший TCP-flow публичного Xray-фронта по совместным признакам RTT, RTO и retransmit. После двух свежих циклов закрывается только точный `source:port`; сервисы, маршруты и остальные клиентские соединения не перезапускаются.
- Точечное восстановление имеет собственный 15-минутный cooldown и не блокирует отдельный recovery серверного dataplane. Одиночная потеря пакета, общий сетевой инцидент и короткий поток не запускают действие.

## [0.12.0] - 2026-07-22

### Added

- Межсерверный dataplane получил Hysteria2/QUIC transport между RU и foreign с pinned self-signed identity и auth, детерминированно производным от deployment secret. Fixed bandwidth не задаётся: sing-box использует собственный BBR congestion control, который в живом сравнении на том же lossy path дал около 81 Мбит/с против примерно 10 Мбит/с у TCP внутри WireGuard.
- WireGuard сохранён как независимый transport fallback и control path. Один selector `to-foreign` по умолчанию использует Hysteria2; отдельный bounded supervisor каждые 5 секунд проверяет raw transport и переключает только новые соединения на WireGuard после подтверждённого отказа. Возврат на Hysteria2 требует двух успешных проверок, foreign traffic никогда не переводится в `direct-ru`, существующие соединения не прерываются.
- Локальная Clash API-интроспекция на RU показывает фактически выбранный transport и последние delay обоих кандидатов. Snapshot отдельно сообщает transport redundancy и по-прежнему честно показывает отсутствие второго независимого foreign egress.
- Quick audit получил реальный Docker contract `SOCKS -> selector -> Hysteria2/TLS/auth -> foreign HTTP`, включая проверку выбранного outbound через API; валидность JSON без handshake больше недостаточна.
- Host DNS обеих ролей переведён на manifest-owned `systemd-resolved`: независимые Cloudflare/Quad9/Google upstreams, локальный positive cache и `StaleRetentionSec=1h`. Drop-in, `/etc/resolv.conf` symlink и исходное состояние сервиса входят в транзакционный rollback.

### Fixed

- Устранён подтверждённый узкий участок foreign-to-RU: 10-секундный iperf давал около 9.7 Мбит/с и 1630 retransmissions, тогда как CPU, conntrack и PMTU оставались исправны. Потери теперь переживаются QUIC loss recovery внутри межсерверного соединения, а не повторным HTTP-запросом клиента.
- WireGuard fallback больше не использует `dns-global`, который сам шёл через `to-foreign` и создавал рекурсивную зависимость при отказе primary transport; bootstrap resolver теперь `dns-ru-direct`.
- Xray Reality inbound включает TCP keepalive `90/15s`, чтобы kernel удалял давно умершие accepted sockets после потери NAT/клиента. Диагностика выводит keepalive timers и stale-сокеты `5m/1h`.
- Managed UDP profile дополняет receive limits значением `net.core.wmem_max=16 MiB`; agent проверяет send-buffer drift и новые `UdpSndbufErrors` отдельно.
- Foreign Hysteria2 listener разрешён nftables только с публичного RU IP. Сертификат, private key и pin валидируются как единая identity до рендера, а sing-box config внутри immutable release хранится с правами `0600`.
- Foreign `sing-box` стал обязательным service/install/manifest invariant. Неисправный WG fallback даёт degradation при живом router path, но не запускает ложный rollback или restart.
- Устранена ложная каскадная диагностика foreign acceptance: literal `1.1.1.1` больше не следует redirect к домену, egress identity проверяется через DNS-independent trace endpoint, а domain connect budget отделён от dataplane timeout. На live foreign старый статический resolver дал воспроизводимый 5-секундный stall и содержал пустые `nameserver` строки.
- Agent сохраняет адаптивное состояние на диске и сообщает причину каждого перехода `healthy -> fallback -> recovering`. Ошибка primary немедленно выбирает исправный WireGuard, а краткое восстановление primary не вызывает route flapping.
- Release acceptance сокращён до 60 секунд: 30-секундный uncapped capacity phase подтверждает не менее 50 Мбит/с, затем одно 30-секундное соединение с cap 16 Мбит/с подтверждает не менее 10 Мбит/с без повторных клиентских запросов и обрывов.
- Компактный `status` больше не включает ошибки предыдущего процесса в current-release окно во время поочерёдной установки ролей. QUIC transport loss и отказ конечного upstream имеют отдельные buckets `transport_unavailable` и `upstream_refused`; неизвестная задержка fallback выводится как `not-probed`, а не `None ms`.
- Live verifier использует только HTTPS throughput origins, считает ошибки отдельно по каждому источнику и всегда сохраняет полный public-VLESS result, runner events и post-run snapshots в `out/diagnostics`; неуспех больше не теряется после удаления remote temp directory.
- Throughput acceptance больше не создаёт серию коротких запросов к speed origin: capacity использует bounded 10-секундные streams, а stability держит одно 30-секундное HTTPS-соединение. Это исключает ложный failure из-за origin rate-limit и проверяет именно отсутствие обрыва длительной загрузки.
- Capacity phase не запускает новый stream в последние три секунды окна, поэтому короткий boundary timeout без полученного body больше не считается отказом dataplane.
- Штатное закрытие Hysteria upload stream (`write on closed stream`) классифицируется как `client_reset_eof`, а не как необъяснённая серверная ошибка.
- TCP front parser больше не принимает опциональное поле `ss timer:(keepalive,...)` за IP клиента; endpoint определяется по локальному порту и валидной удалённой IP-паре. Штатный Hysteria stream cancel с error code `0` относится к client-close bucket.

Основной `out/1/client/vless-uri.txt`, публичный Xray/Reality `RU:443`, WireGuard MTU `1360`, routing classes и web-admin не изменены. Локальный VPN-клиент не меняется и не перезапускается.

## [0.11.12] - 2026-07-20

### Fixed

- External `verify live` теперь имеет единственный глобальный lock, target-side deadline и короткую controller lease. Потеря управляющего процесса завершает всю process group, освобождает SOCKS port и не оставляет скрытую throughput-нагрузку на production.
- Runner работает только в собственном временном каталоге и больше не смешивает `curl`/sing-box логи параллельных или прежних запусков. Результат читается только после завершения процесса, а устаревшие временные каталоги удаляются ограниченно.
- Полный VLESS contract дополнен девятью последовательными first-load GET через RU-direct и foreign origins. Приёмка требует успеха каждой попытки не дольше пяти секунд и сохраняет origin, HTTP/curl status и latency каждой загрузки, поэтому обрывы первого запроса больше не скрываются одной успешной проверкой.
- Public-front telemetry распознаёт подтверждённую высокую retransmit-долю на небольших TCP-потоках, не дожидаясь прежнего порога в 1 MB. Source-specific loss даёт только soft degradation и никогда не запускает restart либо смену маршрута.
- Health сохраняет ограниченный снимок последней front-деградации с source, потоком, RTT, retransmitted bytes, reordering и DSACK; `status` отдельно выводит TCP segment/recovery deltas и это evidence после закрытия проблемного сокета.
- Эквивалентные `context canceled/cancelled` и `operation was canceled/cancelled` при закрытии клиента или штатном restart относятся к одному cancellation bucket и больше не создают ложный `unclassified_error`.

Основной `out/1/client/vless-uri.txt`, routing/DNS policy, WireGuard MTU, Xray transport и web-admin не изменены. Foreign traffic остаётся fail-closed; локальный VPN-клиент не меняется и не перезапускается.

## [0.11.11] - 2026-07-20

### Fixed

- Устранено подтверждённое переполнение `nf_conntrack` на публичном RU-фронте. Локально завершаемые TCP-соединения Xray исключены из conntrack симметричными nftables raw-hook правилами; stateful WireGuard/NAT, SSH и web-admin остаются под штатным tracking.
- Managed network profile резервирует `32768` записей conntrack без сокращения TCP timeout'ов и без ограничения валидных VLESS-клиентов. Runtime-значение входит в проверку профиля и транзакционный release gate.
- Agent собирает kernel-события `nf_conntrack: table full` одним чтением журнала в раздельные окна `5m/30m/24h`, проверяет фактическую загрузку Xray bypass и переводит свежие drops в soft degradation без бессмысленного restart.
- После двух подтверждённых hard-failure циклов agent может восстановить сброшенный managed sysctl или отсутствующий runtime nftables bypass из manifest-проверенных файлов; при любом drift автоматическое применение блокируется.
- `status` показывает текущую загрузку conntrack, runtime bypass, свежие/исторические переполнения и причины последнего health-цикла.
- Web-admin HTML, auth и redirect ответы теперь всегда передают точный `Content-Length`; это устраняет редкий TCP reset при чтении ответа в медленном/инструментированном исполнении.
- Linux console bootstrap больше не вызывает `ensurepip` и не пытается менять PEP 668-managed system Python: `pip` и SSH-зависимости устанавливаются в проектный `.runtime/python-packages` и запускаются оттуда явным isolated runner.
- `remove`/`purge` удаляет managed modules-load drop-in и восстанавливает прежний sysctl/module-loading baseline; загруженный общий kernel-модуль принудительно не выгружается.
- Manifest больше не считает произвольный неизвестный `*.conf` конфигом WireGuard: все managed-артефакты имеют явный install path, а неполное описание останавливает сборку до установки.
- `verify live` формирует итог из обязательных acceptance snapshots после публичного VLESS/throughput-run, поэтому длинный тест больше не завершается verdict по устаревшим TCP-сокетам, снятым до нагрузки.

Основной `out/1/client/vless-uri.txt`, routing/DNS policy, WireGuard MTU и web-admin не изменены. Foreign traffic остаётся fail-closed и не переводится через RU direct.

## [0.11.10] - 2026-07-18

### Fixed

- Для каждого доменного traffic class компилируется отдельная последовательность `resolve -> block/private guard -> terminal route`. Direct terminal завершается до foreign resolve, поэтому выбранный resolver вызывается ровно один раз; connection manager получает готовые адреса. Lab поднимает доступные private endpoints на обеих сторонах и доказывает отсутствие соединения до них через global и RU-direct доменные правила.
- `context canceled` при закрытии запроса или restart больше не считается отказом DNS: событие относится к клиентскому cancellation bucket, тогда как реальные deadline/timeout остаются `dns_timeout`.
- `status` явно отделяет накопительные kernel counters от положительных дельт последнего health-цикла. `diagnose client` показывает aggregate TCP quality и основание source-specific verdict вместо противоречивой пары `degraded`/`active flows degraded=0`.

Основной `vless-uri.txt`, web-admin и fail-closed foreign invariant не изменены. Web-admin компилирует operator rules в те же resolve/guard/terminal фазы и не разрешает переопределить private CIDR guard.

## [0.11.9] - 2026-07-18

### Fixed

- Исправлен клиентозависимый порядок RU-маршрутов. Настоящий IPv4 literal из `ru-geoip` теперь идёт через `direct-ru` до global literal catchall; hostname завершается доменным правилом раньше и не может случайно стать literal после route-level DNS. Это устраняет лишний foreign round-trip для RU CDN/IP, который один клиент передавал доменом, а другой готовым адресом.
- Удалены дублирующие `resolve -> route` и мёртвый класс `resolved_ru_ip`. DNS выполняется только resolver выбранного outbound; web-admin использует тот же terminal-route контракт и сохранён.
- Global DNS отклоняет private-ответы до соединения. Lab проверяет это доступным внутренним HTTP, а также отдельно доказывает raw RU direct, raw global foreign и отсутствие аварийной утечки foreign-трафика через RU при остановке egress.
- Public VLESS throughput verifier использует Cloudflare и Tele2, ограничивает отдельную попытку десятью секундами и выводит per-origin метрики. Capacity gate использует лучший подтверждённый origin, поэтому rate limit одного download-сервера больше не выдаётся за ограничение VPN path.
- Явная WireGuard-диагностика измеряет TCP P1/P4 и UDP 25/100 Mbit/s в обе стороны вместо одного P4 и недостаточного UDP 10 Mbit/s.

Основной `out/1/client/vless-uri.txt` не менялся. Foreign traffic остаётся fail-closed и никогда не переводится в `direct-ru` при отказе foreign-egress.

## [0.11.8] - 2026-07-18

### Fixed

- Foreign-трафик закреплён за `to-foreign` как fail-closed инвариант: health/recovery не переключает его на `direct-ru`, даже если RU uplink исправен, а единственный foreign-egress недоступен.
- Устранён подтверждённый WireGuard receive overflow. На foreign при штатных `net.core.rmem_default/max=212992` накопилось `22341 UdpRcvbufErrors`; managed network profile теперь даёт UDP socket 4 MiB по умолчанию при 16 MiB ceiling. Необоснованные backlog, MTU, timeout и send-buffer настройки не добавлялись.
- Health snapshot сохраняет дельты UDP receive errors, softnet drops и interface missed packets между двухминутными циклами. Новые drops дают `degraded` без restart; hard route failure по-прежнему требует двух циклов и восстанавливает только отказавший managed service.
- `diagnose front` запускает свежие RU/WG/router probes и выводит раздельные `public_front` и `server_path`. Активный Xray больше не даёт ложный общий `verified`, когда downstream foreign-path уже упал.
- TCP front telemetry разделена по `source IP:port`, а затем агрегируется по IP. Устройства за одним NAT больше не смешиваются в один поток; source-specific отчёт связывает Xray destinations с активными socket metrics.
- Парсер Xray корректно удаляет префиксы `tcp:`/`udp:` из source и сохраняет source port. `status` использует честный компактный 5-минутный snapshot и не перечитывает 24 часа журнала; глубокие окна остаются в `diagnose path`.
- Независимые direct/WG/router probes выполняются ограниченно параллельно, поэтому отказ одного сегмента не умножает timeout диагностики на число путей.
- Исправлен неполный rollback установки: manifest, health/legacy state, admin auth и состояния всех затрагиваемых сервисов теперь входят в revision snapshot. Release сначала создаётся в отдельном staging-каталоге и публикуется как immutable content-addressed tree; повторный reinstall больше не удаляет каталог активного release до успешной приёмки.
- Release gate отделён от внешних capabilities. Временный отказ единственного raw IPv6 endpoint больше не откатывает идентичный конфиг при исправных WG, доменах, IPv4, identities и policy; snapshot остаётся `degraded`, а полный `verify live` продолжает считать IPv6 failure ошибкой. Failed acceptance хранится одним bounded-файлом вместо накопления временных `.acceptance.*.json`.
- Route acceptance больше не скачивает полные страницы внешних сайтов. Probe проверяет DNS/TCP/TLS/HTTP через `HEAD`; успешный GitHub HTTP 200 не считается route failure только потому, что произвольное тело страницы не успело целиком загрузиться за шестисекундное диагностическое окно. Полноценный GET и throughput остаются в public VLESS verifier.
- Локальный `verify live` использует тот же release-gate contract, что и target-side activation: core failure остаётся `failed`, отдельная внешняя capability становится `degraded` и не маскирует результат более полного public VLESS probe.
- Итог verifier использует иерархию доказательств: успешный end-to-end VLESS IPv6 probe снимает противоречащую ему деградацию внутреннего raw probe. Он не снимает drift, core route failure, front retransmission или другие независимые причины.
- Proxy route probe больше не передаёт `curl -4/-6` при соединении с IPv4 loopback SOCKS. Family constraint относился к proxy connection и давал ложный мгновенный IPv6 failure; IP literal уже задаёт family назначения, а для домена её выбирает серверная routing policy.
- Revision snapshots ограничены десятью последними транзакциями. Baseline и immutable releases не затрагиваются; многократные reinstall больше не создают неограниченный слой backup-каталогов.

## [0.11.7] - 2026-07-18

### Fixed

- Восстановлен удалённый при рефакторинге `0.11.0` kernel PLPMTUD (`net.ipv4.tcp_mtu_probing=1`). TCP-потоки снова адаптируют MSS при ICMP/PMTU black hole и штатно перепроверяют больший размер вместо зависания на длинных retransmission timeout. Фиксированный MSS, новый timeout и старые неподтверждённые buffer sysctl не добавлялись.
- Front diagnostics теперь разбирает `bytes_sent`, `bytes_retrans`, PMTU, MSS, cwnd, delivery rate и reordering из `ss -ti`. Измеренная retransmit-доля не маскируется общим `verified`: один плохой source получает `client_specific/degraded`, а деградация нескольких источников становится общей.
- `status` и `verify live` показывают фактические congestion control, qdisc, PLPMTUD state и probe interval. Отключённая runtime-адаптация даёт `degraded`, даже если services и route probes формально зелёные.
- Явный throughput-run больше не ограничивает сам себя 15 Мбит/с и проверяет фактическую пропускную способность полного VLESS path с floor 50 Мбит/с. Обычный `verify live` по-прежнему не создаёт нагрузку без `--throughput-seconds`.
- Client front quality учитывает подтверждённое раздувание RTT вместе с RTO от 1 секунды. Длинные зависания одного source теперь дают `client_specific/degraded`, даже если короткоживущие сокеты ещё не передали мегабайт данных.

## [0.11.6] - 2026-07-18

### Fixed

- External private/fake acceptance полностью читает SOCKS reply. Для `sing-box reject` допустимы явный SOCKS failure либо быстрый EOF после успешного SOCKS handshake и первого application byte; timeout или ответ от destination остаются failure. Это исключает ложный rollback на корректном full VLESS path.

## [0.11.5] - 2026-07-18

### Fixed

- Удалён legacy-route `client_dns_dot`, который перенаправлял private/TUN `:853` на внешний DNS и порождал искусственные пятисекундные hangs. Private и fake IP, включая `172.19.0.2:853`, теперь сразу отклоняются единым policy rule. External `verify live` проходит этот reject через VLESS URI, а не доверяет только локальному router probe.

## [0.11.4] - 2026-07-18

### Fixed

- `vpn diagnose client --source` и TCP front telemetry приводят IPv4, IPv6 и kernel-формат `::ffff:<IPv4>` к одному каноническому адресу. Активный socket больше не исчезает из source-specific отчёта при IPv4-mapped IPv6 представлении `ss`; Xray events и socket metrics коррелируются по одному ключу.

## [0.11.3] - 2026-07-17

### Fixed

- Внешний VLESS throughput gate переведён с расчёта размера range на фиксированное окно наблюдения. Он суммирует реально переданные байты до deadline, повторяет завершённый range, ограниченно завершает ephemeral sing-box и отдаёт фазу runner при ошибке. Controlled load составляет 15 Мбит/с, что на 50% выше acceptance floor 10 Мбит/с и не создаёт многогигабайтную нагрузку на действующих пользователей.
- Bash runner теперь доставляется байт-в-байт с LF из Windows control host; CRLF не может сломать remote Bash. Тесты проверяют исполняемый runner, syntax и структуру его JSON-метрик.
- Длительный public VLESS runner отделён от SSH control-plane: он запускается в собственной session/process group, пишет result/stderr на foreign role, а локальный workflow читает короткие status snapshots. Зависший HTTP origin больше не удерживает один Paramiko exec channel; timeout удаляет всю группу runner и возвращает диагностическую фазу.
- Acceptance больше не делает rollback по одному краткому failed probe cycle. Первый failure обязательных route-инвариантов подтверждается вторым независимым циклом. Telegram остаётся в structured observations, но его изолированная внешняя недоступность не объявляет конфигурацию регрессивной и не откатывает рабочий release.
- Добавлен self-contained `tests/run_tests.py`: unit suite теперь одинаково запускается системным и isolated portable Python без неявной зависимости от `PYTHONPATH`.
- Read-only `vpn status` теперь явно объясняет `inconclusive`, когда live route probes намеренно не запускались; это не маскируется под серверный failure.

## [0.11.2] - 2026-07-17

### Fixed

- Уточнён acceptance predicate UDP/443: он анализирует только правила, которые явно ограничивают `network` или `port`. Обычное DNS `resolve` rule без transport selector больше не может ложно объявить release небезопасным; реальный глобальный UDP/443 reject по-прежнему останавливает activation и возвращает предыдущий release.

## [0.11.1] - 2026-07-17

### Fixed

- Убран legacy-запрет всего UDP/443 из RU `sing-box` и из вновь генерируемых fallback JSON-профилей. Он конфликтовал с основным VLESS/Reality контрактом: живые Xray access logs подтверждали принятый UDP/443, а router затем намеренно его отклонял. Обычный `vless-uri.txt` не менялся, установленный локальный клиент не модифицируется.
- `RU_BLOCK_QUIC` стал deprecated migration key и удаляется при следующем штатном `install/reinstall`; он больше не может включить глобальный reject транспорта.
- `vpn verify live` теперь доказывает полный URI-путь для HTTP, UDP DNS и TCP IPv6 literal. RU acceptance также проверяет, что policy UDP/443 находится в состоянии `routed`.
- Исправлена классификация sing-box timeout: ошибки `direct-ru` больше не попадают в IPv4-literal bucket только потому, что после DNS в строке оказался IP. Если request trace сохранил домен, status показывает исходное имя и порт.
- TCP front больше не объявляет старые lifetime `ss retrans` свежей деградацией. Суммарные метрики считаются по всем активным источникам, а source-specific verdict использует только текущее socket churn.

### Changed

- `log_classifier.py` стал самостоятельным stdlib-модулем, который используют локальная диагностика и server agent. Он доставляется вместе с agent и фиксируется в release manifest, поэтому формат buckets не зависит от случайного порядка скриптов на сервере.
- `vpn diagnose front` и `vpn diagnose client` показывают раздельно accepted TCP, UDP и UDP/443, а также фактическую policy UDP/443.
- SSH control plane умеет явно привязать исходящий сокет к физическому адресу через временную `VPN_SSH_BIND_ADDRESS`. Это позволяет обслуживать серверы при активном TUN, не меняя VPN-клиент, его профиль или локальную route table.

## [0.11.0] - 2026-07-15

### Changed

- Введены типизированные `DeploymentSpec`, `RoleSpec` и `RoutingPolicy`. Все классы RU traffic, outbounds, resolver и route order определяются одной Python-моделью; renderer только сериализует её.
- Серверная диагностика сведена к stdlib-only `vpn-stack-agent` и snapshot schema 2. Статус, health, diagnose и verify используют один structured payload с разделёнными окнами `fresh`, `30m` и `24h`.
- Парные `dns: lookup failed` и `router: lookup` строки одного sing-box request дедуплицируются по request ID и классифицируются как DNS, а не ложный `unclassified_error`.
- `vpn verify live` теперь строит эфемерный sing-box client непосредственно из главного `vless-uri.txt` и проверяет public `RU:443 -> Reality/Xray -> sing-box -> WireGuard -> foreign` path. Acceptance требует обе identity: RU direct IP-check и foreign Cloudflare trace; локальные client profiles и deployment env при status/verify/diagnose не изменяются.
- `vpn verify live --throughput-seconds 600` добавляет controlled десятиминутный VLESS throughput gate: range-capable download держится на 12 Mbit/s и проверяется минимум 10 Mbit/s без короткого synthetic burst.
- Server-side acceptance разделяет наблюдаемую прямую доступность RU и обязательные пользовательские пути: foreign-домены и IPv4 literal проверяются через WG и router, IPv6 literal через router и foreign egress. Недоступность заблокированного прямого RU Telegram или IPv6 bind на `wg0` больше не даёт ложный rollback.
- Install/reinstall доставляет staged release в `/etc/vpn-stack/releases`, валидирует конфиги и manifest до atomic switch `current`, а при server-side acceptance failure возвращает предыдущие artifacts и service state.
- Runtime health стал state machine с двухцикловым hard-failure gate, 15-minute recovery cooldown и обязательным post-check. Soft degradation не перезапускает dataplane.
- `vpn maintain` отделяет отчёт об APT/security/reboot от применения обновлений; обновление roles и refresh assets выполняются только транзакционно и последовательно.
- Web-admin сохранён. Его правила остаются единственным поддерживаемым server-side runtime overlay; CLI `vpn routes` использует тот же backend.

### Removed

- Удалены log-based guard, `abuse_ipv4`, background asset sync, adaptive route cache и ручные runtime knobs qdisc/offload/timeout. Они меняли состояние без независимого egress и не могли надёжно восстановить route.
- Удалены дублирующие Bash collectors, legacy health wrapper и модульный coverage-loop: полный audit запускает один branch-coverage test run вместо повторного запуска каждого test module.

## [0.10.0] - 2026-07-14

### Changed

- RU routing сведён к детерминированной `RoutingPolicy` с двумя реальными путями: `direct-ru` и `to-foreign`. Удалены дублирующие literal-outbound, runtime promotion и route cache, которые меняли конфиг, но не меняли физический egress.
- Публичные IPv4/IPv6 literals и обычные foreign-домены идут через один `to-foreign` без искусственного connect timeout. `RU_*LITERAL_POLICY`, `RU_IPV6_POLICY` и `TO_FOREIGN_*CONNECT_TIMEOUT` больше не участвуют в policy и удаляются при миграции.
- DNS cache RU `sing-box` увеличен до 4096 записей; убран `independent_cache`. NXDOMAIN, transport timeout и прочие DNS-отказы классифицируются раздельно.
- `vpn status` стал структурной и дешёвой проверкой; тяжёлые route/throughput/IPv6 probes выполняет только `vpn verify live`. Verify использует один fresh snapshot на роль без повторных SSH-обходов.
- RU route targets и throughput в `verify live` проходят через `socks5h://127.0.0.1:<router-port>`: acceptance проверяет тот же sing-box DNS/routing path, что и клиент, а не подменяет его `curl --interface wg0` с системным DNS VPS.
- `DiagnosticsSnapshot` обновлён до schema 2: вместо удалённого dataplane cache он хранит только явные admin runtime overrides; legacy JSON читается через migration path.

### Fixed

- Устранён главный источник периодических обрывов: health/adaptive loop больше не перезапускает RU `sing-box` из-за timeout destination и не мутирует `qdisc`/offload каждые несколько минут.
- Soft loss/speed degradation больше не запускает restart. Self-heal допускает только восстановление WireGuard после двух последовательных hard-failure cycles; любой успешный или soft-cycle сбрасывает confirmation.
- Убран автоматический shotgun-repair `WireGuard + nftables + sync`; provider/direct egress failure теперь завершается диагнозом без разрушающих действий.
- Deep probe больше не затирает health-state, не запускается каждые две минуты после degradation и не объявляет весь path медленным по худшему из нескольких download-источников.
- Reinstall удаляет устаревшие `/var/lib/vpn-stack/adaptive-routing-rules.json` и `/var/lib/vpn-stack/dataplane-cache.env`, чтобы старое runtime-состояние не влияло на новую policy.
- Preflight больше не падает под `set -euo pipefail`, когда после успешной миграции в installed env нет deprecated routing fields; failed `curl -w` больше не склеивает два невалидных probe results.
- Reinstall больше не угадывает происхождение настроек по их значениям и не переписывает явные operator overrides как «старые defaults»; удаляются только ключи с формально завершённым deprecated-контрактом.
- Guard больше не может добавить RU/foreign public IP в общий abuse set из-за hairpin SSH `banner exchange`: инфраструктурные адреса выводятся из set на каждом цикле и не учитываются как выполненная блокировка.
- Удалён конфликтующий с собственным workflow nft SSH meter `6/minute burst 3`: последовательные preflight/upload/reinstall/verify больше не блокируют сами себя. Ограничение параллельных handshakes оставлено OpenSSH, а guard реагирует только на authentication failures.
- Xray/Reality interop audit изолирован от внешнего DNS: lab-router использует встроенный hosts resolver для локального TLS target, поэтому тест проверяет front/router контракт, а не доступность Docker DNS.
- `dns-ru-direct` больше не зависит от единственного `77.88.8.8:53`: sing-box использует системный resolver RU-хоста с управляемым списком upstream и failover. Дублирующие `RU_DIRECT_DNS_SERVER/PORT` удалены из Python/shell/env и мигрируют как deprecated keys.
- `ipv6-internet.yandex.net` перенесён из общего direct-списка в централизованный класс IPv6-only connectivity probes: IPv4-only DNS policy теперь отклоняет такой probe до lookup и не пишет ложный `empty result`.
- Install/reinstall начинает health с чистого state-файла: старые self-heal actions и deep-probe verdict больше не отображаются как события новой установки; исторические и fresh счётчики запусков sing-box выводятся отдельно.

## [0.9.24] - 2026-07-12

### Fixed

- RU `sing-box` теперь маршрутизирует домены, которые после `dns-global` резолвятся в `ru-geoip`, напрямую через `direct-ru`; это убирает лишнюю петлю `RU -> foreign -> RU CDN` для части media/CDN трафика.
- Raw IPv4 literal catchall остается перед global DNS resolve и по-прежнему идет через `to-foreign-ip-literal`, поэтому fail-fast для IP-literal трафика не смешивается с новым resolved-CDN маршрутом.
- В `RoutingPolicy` добавлен отдельный traffic class `resolved_ru_ip`, чтобы порядок правил и назначение CDN/proximity маршрута были покрыты моделью и тестами, а не ручным списком доменов.

## [0.9.23] - 2026-07-11

### Fixed

- `install.sh` теперь сбрасывает `/var/lib/vpn-stack/adaptive-routing-rules.json` на RU при `install/reinstall`, чтобы runtime adaptive cache не переживал смену rendered base config и не переносил ошибочные learned routes из предыдущего патча.
- Managed remove/purge также удаляет adaptive routing cache вместе с остальными server-side runtime artifacts.
- Неполные HTTP downloads rule-set assets (`IncompleteRead`) теперь конвертируются в контролируемый failed source, чтобы `fetch_assets` мог перейти к следующему URL или cache fallback вместо падения audit/install посередине загрузки.

## [0.9.22] - 2026-07-11

### Fixed

- Adaptive IPv4 literal promotion теперь требует majority-проверку: минимум 2 успешных WG probe из 3, а не один случайный успешный connect. Это не дает продвигать нестабильный literal в более длинный route.
- Health теперь снимает adaptive IPv4 literal rule, если уже promoted destination начинает timeout'иться через обычный `to-foreign`; runtime overlay больше не остается висеть до TTL при свежем доказательстве деградации.
- `admin_apply.py` получил typed remove-путь для adaptive CIDR rules и сохраняет остальные свежие adaptive entries при удалении одного destination.

## [0.9.21] - 2026-07-11

### Fixed

- Убран скрытый default `connect_timeout=2s` с обычного `to-foreign`: пустой `TO_FOREIGN_CONNECT_TIMEOUT` снова означает отсутствие глобального timeout для доменных foreign routes, как и заявлено в env-контракте.
- Добавлен runtime adaptive overlay для IPv4 literals: если health видит повторяющиеся timeout'ы на `to-foreign-ip-literal`, он проверяет top destination напрямую через `wg0`; если endpoint живой, пишет TTL-rule в `/var/lib/vpn-stack/adaptive-routing-rules.json` и применяет checked `sing-box` config через существующий `admin_apply.py`.
- `admin_apply.py` теперь объединяет ручные admin routing rules и adaptive runtime rules в один проверяемый `/etc/sing-box/config.json`, при этом expired/bad adaptive rules отбрасываются до применения.

## [0.9.20] - 2026-07-11

### Fixed

- Target/env resolution вынесен из `workflows.py` в `vpn_installer.targets`: построение `RemoteTarget`, unattended SSH overrides, синхронизация public IP и remote-env match теперь живут в одном чистом модуле. `diagnose` и `audit.quick` больше не импортируют workflow-монолит ради target helpers.

## [0.9.19] - 2026-07-11

### Fixed

- Role selection helpers вынесены из `workflows.py` в `vpn_installer.roles`: `verify live` и `diagnose` больше не зависят от workflow-монолита ради `requested_roles()`, а install/remove orchestration использует тот же общий helper без дублирования.

## [0.9.18] - 2026-07-11

### Fixed

- Dataplane health policy вынесена из `workflows.py` в отдельный модуль `vpn_installer.health`: расчёт verdict, parsing probe-результатов, границы soft/hard деградации и форматирование health больше не смешаны с install/status/self-heal orchestration. `verify live` и `diagnose path` используют health-модуль напрямую.

## [0.9.17] - 2026-07-11

### Fixed

- `verify live` вынесен из общего `workflows.py` в отдельный модуль `vpn_installer.verify`: policy принятия verdict, parsing probe-результатов и live orchestration больше не смешаны с install/status/remove workflows. CLI-контракт `vpn verify live` не изменён, тесты переведены на новый модуль.

## [0.9.16] - 2026-07-11

### Fixed

- Добавлен структурный тест дрейфа между bootstrap defaults в `install.sh` и Python `generate_default_env()`: совпадающие runtime-параметры теперь сравниваются автоматически, а допустимые shell-only/python-only ключи перечислены явно. Это закрывает слой техдолга, где duplicated defaults могли расходиться без сигнала от тестов и ломать reinstall/server-authoritative env незаметно для audit.
- `vpn verify live` больше не использует обычное 30-минутное status-окно как verdict-window: workflow передаёт в `remote_preflight` timestamp старта проверки, а Xray/sing-box fresh buckets для verify считаются от этого якоря. Исторические ошибки остаются видимыми в `status`, но больше не валят live verification как будто они появились во время проверки.

## [0.9.15] - 2026-07-11

### Fixed

- Убран остаточный legacy-read в `remote_preflight`: compatibility counters `reality_invalid_recent_count`/`reality_invalid_recent_sources` больше не читают Xray journal отдельным жёстким окном `-30 minutes`, а переиспользуют уже собранный `xray_recent_log` с post-install `xray_recent_effective_since`. Это закрывает ещё один путь, где старые pre-install invalid REALITY могли попасть в fresh status после reinstall.

## [0.9.14] - 2026-07-11

### Fixed

- Runtime route-fail cache больше не завязан только на literal-трафик: health теперь ведёт единый adaptive bucket по классам `domain_foreign`, `ipv4_literal` и `ipv6_literal`, сбрасывает их независимо при чистом окне и показывает каждый класс в `status`/`DiagnosticsSnapshot`. Это убирает старый перекос, где доменные подвисания попадали в логи, но не становились частью runtime-памяти системы.
- `status` показывает cached деградацию доменного foreign route вместе с literal-бакетами, чтобы повторяющиеся сбои вроде resolved `googlevideo` IP были видны как отдельный класс, а не как очередной повод вручную крутить timeout/env.
- Health route-fail collector теперь считает окно от `installed_at + 10s`, если reinstall был свежее обычного TTL, поэтому старые `sing-box` ошибки больше не попадают в новый post-install runtime cache и не создают ложный `degraded`.
- `diagnose path` стал bounded и быстрее: RU/foreign отчёты собираются параллельно, тяжёлые `ping`/`mtr`/`curl` пробы укорочены до representative samples, а зависший SSH capture сохраняет partial report с `diagnose_error` вместо молчаливого зависания диагностики.
- `diagnose path` теперь использует то же post-install recent window, что и `status`: grouped Xray/sing-box sections и raw sing-box tail считаются от `installed_at + 10s`, если reinstall свежее 30-минутного окна, и печатают `window_since`.
- Общий `ssh_capture` и `run_command` получили явный command timeout для обоих backend’ов (`Paramiko` и системный `ssh`), чтобы диагностика деградации сети не могла сама стать бесконечной операцией.
- `vpn audit interop` добавлен как отдельный быстрый gate для Xray/Reality domain path: проверка больше не использует искусственный IPv6 `--connect-to`, а при сбое сохраняет логи router/front/client контейнеров.

## [0.9.13] - 2026-07-10

### Fixed

- Доменный foreign path получил внутренний connect budget `2s`: свежий сбой после `0.9.12` был не только IP-literal, а `rr2---sn-aj5go5-5i.googlevideo.com` -> `173.194.160.162`, где один resolved address повис на `5.0s` через RU->WG->foreign, хотя сам endpoint был жив при повторной проверке. `TO_FOREIGN_CONNECT_TIMEOUT` остаётся deprecated operator override; пустое env-значение больше не означает неограниченный domain connect.
- `status` теперь коррелирует fresh domain timeouts по sing-box connection id и показывает исходный домен вместе с resolved IP, например `rr2---...googlevideo.com:443->[173.194.160.162]`, чтобы диагностика не прятала проблему за голым `[ip]`.

## [0.9.12] - 2026-07-10

### Fixed

- IPv4 literal fail-fast budget снижен с `2s` до `750ms`, а старый default `TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT=2s` мигрирует в `750ms`. Свежие live-логи после проверки клиента показали не доменную проблему YouTube, а повторяющиеся dead IPv4 literals разных приложений: `91.108.56.103:80/443` timeout'ится даже с foreign path, тогда как доменные `googlevideo`, `static.yani.tv`, `solodcdn`, `telegram.org` и `api.telegram.org` с foreign path отвечают. Доменный `to-foreign` по-прежнему без глобального connect timeout.
- Диагностика deprecated routing overrides теперь считает `TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT=750ms` штатным значением, чтобы `status` не помечал новый default как ручное отклонение.
- Admin web routing rules теперь планируют restart `sing-box` внутри успешного `commit_rules()`, а не после HTTP response, чтобы применённые правила не зависели от клиентского соединения с web UI.
- Docker audit Xray/Reality interop больше не зависит от фиксированной подсети `172.31.240.0/24`: smoke использует Docker DNS aliases, явно ждёт готовность router listener и повторяет только холодный interop probe.

## [0.9.11] - 2026-07-10

### Fixed

- IPv6 literal traffic теперь fail-fast reject по умолчанию и старый `RU_IPV6_LITERAL_POLICY=route-with-budget` мигрирует в `reject`: live-логи после `0.9.10` снова показали десятки IPv6 literal destinations от клиента и свежие timeouts на `[2001:67c:4e8:f002::a]:443`, что ухудшало YouTube/Telegram/media path. Явный operator mode `route-with-budget` оставлен в routing model, но больше не является deployment default.
- Клиентские sing-box/Hiddify JSON и Xray JSON теперь локально блокируют UDP/443, чтобы QUIC/HTTP3 не ехал через TCP-based VLESS path и быстрее переходил на HTTPS/TCP. Основной `vless-uri.txt` не меняется.
- `DISABLE_NIC_OFFLOADS` теперь default `0`, старое default-значение `1` мигрирует в `0`, а install/health явно включает GRO/GSO/TSO в этом режиме: live A/B на текущих VPS показал, что включённые offloads дают стабильный RU-over-WG throughput около `17.8-18.4 MB/s` на Cloudflare без свежих `sing-box` ошибок.

## [0.9.10] - 2026-07-10

### Fixed

- Стабилизирован performance path для TCP-based VLESS: `RU_BLOCK_QUIC` теперь по умолчанию и при миграции старого env равен `1`, чтобы браузеры/видео не пытались гонять QUIC/HTTP3 UDP/443 поверх VLESS TCP и быстро переходили на обычный HTTPS/TCP.
- Foreign `nftables` теперь clamp'ит TCP MSS на forward между `wg0` и WAN до `WG_MTU - 40` (`1320` при текущем `WG_MTU=1360`), чтобы большие TCP-передачи не зависели от PMTUD/ICMP и не ловили MTU blackhole.
- Install sysctl включает `net.netfilter.nf_conntrack_tcp_be_liberal=1`, чтобы `ct state invalid drop` не рвал живые TCP-потоки при packet reordering/loss на VPS-сети.

## [0.9.9] - 2026-07-10

### Fixed

- IPv6 literal routing стал port-aware: `route-with-budget` теперь маршрутизирует через `to-foreign-ipv6-literal` только IPv6 literal `:443`, а остальные IPv6 literal порты reject'ятся fail-fast. Live-проверка показала, что медиа/CDN IPv6 literal `:80` вроде `[2a0a:f280:203:a:5000::100]:80` timeout'ится даже на foreign path и создаёт 2-секундные подвисания видео/медиа; без домена сервер не может пере-resolve такой literal в IPv4, поэтому правильное поведение — немедленный fallback клиента, а не ожидание TCP timeout.

## [0.9.8] - 2026-07-10

### Fixed

- IPv6 literal traffic остаётся маршрутизируемым, но его internal fail-fast budget снижен с `3s` до `2s`: live-проверка показала, что часть внешних Meta IPv6 literal endpoints timeout'ится уже на foreign-provider path, и держать пользовательский поток 3 секунды для таких literal destinations нельзя. Старый default `TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT=3s` мигрирует в новый `2s`, явный пустой override по-прежнему сохраняется.
- `deployment_health_snapshot` теперь берёт fresh `FAST_FOREIGN_RU_PING_LOSS_PCT` перед deep-cache `DEEP_FOREIGN_RU_PING_LOSS_PCT`, чтобы старый deep snapshot не давал ложный `foreign_ru_ping_loss_degraded` после свежего восстановления пути.
- `verify live` больше не валит роль только по устаревшему `deep_probe_verdict=degraded`: deep metrics учитываются через общий deployment health, где есть fresh download/ping probes и fallback logic.
- IPv6 literal TCP probe теперь считает весь IPv6-literal path сломанным только если нет ни одного reachable/http результата. Один проблемный внешний IPv6 target больше не приравнивается к поломке всего VPN, но свежие runtime timeout buckets остаются видимыми отдельно.
- SSH control-plane для install/status/verify больше не падает от первого TCP connect timeout: Paramiko повторяет такие подключения и явно отделяет SSH timeout от VLESS dataplane failure. Default `sshd` лимиты подняты с `MaxStartups 5:30:20`/`PerSourceMaxStartups 2` до `10:30:60`/`6`, старые default-значения мигрируют при reinstall.
- Исправлен ошибочный `private_dot_recovery`: клиентский private/TUN DNS-over-TLS (`172.19.0.x:853`/`fd00::/8:853`) больше не уходит через `to-foreign`, потому что live-проверка показала timeout DoT на RU->wg0->foreign path. Для этого класса введён явный `client_dns_dot` route через `direct-ru` с override на `GLOBAL_DOH_SERVER:853`; заблокированные private DoT leaks остаются отдельным `private_dns_leak` и переводят `verify live` в `degraded`.

## [0.9.7] - 2026-07-10

### Fixed

- `vpn verify live` больше не может завершиться `verified`, если свежие post-install логи RU `sing-box` содержат DNS/domain/IPv4-literal/IPv6-literal timeout buckets или `invalid_reality`: такие события теперь переводят live verification в `degraded` и возвращают ненулевой код.
- Свежий runtime-window для Xray/sing-box теперь считается от последнего reinstall, если reinstall был позднее стандартного 30-минутного окна. Старые ошибки остаются в отдельном 4h historical block и больше не маскируются под свежие post-install failures.
- `DiagnosticsSnapshot` разделяет `log_buckets` и `historical_log_buckets`, а top destinations для IPv6 literal timeout берутся из fresh timeout destinations, а не из общего routed traffic списка.
- Live verification учитывает общий deployment health verdict: soft degradation по packet loss/download/target probes теперь попадает в итоговый `degraded`, hard failure остаётся `failed`.
- `status`/`preflight` показывают runtime overlay для `/etc/sing-box/config.json` и активные admin routing rules отдельно от manifest drift, чтобы runtime-mutated config не выглядел как чистый штатный render.

## [0.9.6] - 2026-07-09

### Fixed

- Отменён ошибочный default `RU_IPV6_LITERAL_POLICY=reject` из `0.9.5`: live packet/TCP checks 9 июля подтвердили, что RU -> WireGuard -> foreign NAT66 path для IPv6 literals рабочий, поэтому IPv6 literal destinations снова маршрутизируются через выделенный `to-foreign-ipv6-literal` с отдельным бюджетом `TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT=3s`.
- Reinstall/remote-env sync теперь мигрирует `RU_IPV6_LITERAL_POLICY=reject` обратно в `route-with-budget`, если общая `RU_IPV6_POLICY=to-foreign`; это убирает застрявший server-authoritative default из `0.9.5` без сохранения сломанного reject после переустановки.
- `remote_preflight`, `DiagnosticsSnapshot` и `vpn verify live` теперь проверяют отдельный TCP IPv6 literal route probe через временный локальный `sing-box` с `bind_interface=wg0` и `routing_mark=48`. Если этот exact path сломан, live verification получает `degraded`, а не зелёный статус по одним service/audit checks.
- Parser live-probe результатов теперь корректно распознаёт broken targets в `;`-разделённых probe строках и не теряет IPv6 literal TCP failures из-за формата вывода.

## [0.9.5] - 2026-07-09

### Fixed

- RU `sing-box` больше не маршрутизирует клиентские IPv6 literal destinations через `to-foreign-ipv6-literal` по умолчанию. Live-логи 9 июля показали свежие массовые `3.0s` timeout'ы на IPv6 literals после успешного VLESS/Reality входа, что давало поведение "VPN подключён, но сайты открываются через раз".
- Default `RU_IPV6_LITERAL_POLICY` изменён на `reject`; старый default `route-with-budget` при merge/reinstall мигрирует в `reject`. IPv4/domain маршруты и основной `out/1/client/vless-uri.txt` не меняются.

## [0.9.4] - 2026-07-08

### Fixed

- RU `sing-box` теперь отдельно обрабатывает утечку DNS-over-TLS на адрес клиентского TUN (`CLIENT_TUN_ADDRESS_V4`, порт `853`) до общего private/fake блокера: такой трафик перенаправляется на штатный global DNS через `to-foreign`, а остальные private/fake назначения остаются заблокированы.
- Добавлена регрессия на порядок правил: восстановление `CLIENT_TUN /30 :853` обязано стоять перед `ip_is_private`, чтобы клиенты с локальным Private DNS не получали рабочий VLESS handshake с последующей поломкой DNS/сайтов.

## [0.9.3] - 2026-07-08

### Added

- Добавлена команда `vpn diagnose front --deployment <name> [--source-ip <ip>]`: она проверяет публичный RU `VLESS/Reality` front, Xray, nftables/guard, socket-state и source-specific counters, чтобы отличать `reached_xray`, `rejected_by_front`, `blocked_by_guard`, `tcp_reached_no_xray_accept` и `not_seen_on_server`.
- Добавлена команда `vpn diagnose client-log --path <log> [--deployment <name>]`: клиентские `sing-box`/Hiddify/v2rayN логи теперь отдельно классифицируют `client_front_connect_failed`, когда клиент не может подключиться к public VPN endpoint до входа в Xray, и не смешивают это с серверным DNS/routing.

### Fixed

- `status`/`diagnose path` больше не остаются единственным источником истины для кейса "одно устройство подключается, другое нет": теперь есть отдельный front-gate, который требует source IP конкретного устройства и честно возвращает `inconclusive`, если такого идентификатора нет.
- Основной клиентский контракт `out/<deployment>/client/vless-uri.txt` не изменён; JSON-профили остаются fallback-артефактами, а диагностика проверяет именно public `RU:443` вход для URI-клиентов.

## [0.9.2] - 2026-07-08

### Fixed

- RU `RoutingPolicy` получил явные классы `connectivity_check` и `connectivity_check_ipv6_only`: `www.msftconnecttest.com`/`www.msftncsi.com` теперь резолвятся через быстрый `dns-ru-direct` и маршрутизируются через `direct-ru` до global DoH, а IPv6-only probe-домены `ipv6.msftconnecttest.com`/`ipv6.msftncsi.com` reject'ятся до DNS lookup. Это убирает 10-30 секундные DNS подвисы и быстрый `empty result` шум на IPv4-only серверной DNS policy.
- `log_classifier.py`, `preflight` и `diagnose path` теперь распознают не только `dns: lookup failed`, но и `dns: exchange failed ... IN A/AAAA`, сохраняют query type в top destinations и не смешивают DNS deadline с IP-literal/domain-route timeout.
- DNS policy для устойчивых probe-доменов вынесена в общий модуль без новых публичных timeout/env-параметров; старый клиентский контракт `out/<deployment>/client/vless-uri.txt` не меняется.

## [0.9.1] - 2026-07-08

### Fixed

- Health-check получил отдельный `/var/lib/vpn-stack/dataplane-cache.env`: свежий подтверждённый `WireGuard` path теперь хранится с TTL и подавляет hard self-heal при одиночном probe miss, но не скрывает реальную потерю маршрута.
- RU route diagnostics пишет soft buckets для повторяющихся IPv4/IPv6 literal timeout'ов с top destination и TTL. Эти destination failures больше не смешиваются с отказом всего VPN path и не запускают restart loop.
- `status`, `preflight`, `DiagnosticsSnapshot` и `verify live` теперь показывают dataplane cache: возраст последнего рабочего WG path, TTL, источник probe и route-fail cache по literal-классам.

## [0.9.0] - 2026-07-06

### Changed

- RU `sing-box` теперь строится из единой Python-модели `RoutingPolicy`: классы `ru_direct_domain`, `ru_direct_ip`, `private_or_fake`, `dns_global`, `domain_foreign`, `ipv4_literal_foreign`, `ipv6_literal_foreign`, `blocked` описывают outbound, resolver, timeout policy, log bucket и fallback в одном месте.
- Публичная политика IP literal сведена к high-level полям `RU_LITERAL_POLICY=fail-fast|route|reject` и `RU_IPV6_LITERAL_POLICY=route-with-budget|reject`; старые `TO_FOREIGN_*CONNECT_TIMEOUT` сохранены как deprecated operator override и показываются в диагностике.
- Каждый install теперь переносит `/etc/vpn-stack/render-manifest.json` с version, env/config hash, policy version и artifact hashes; `status` показывает drift `none|server-mutated|unknown`.

### Added

- Добавлен структурный диагностический слой `DiagnosticsSnapshot` и отдельный `log_classifier.py` с взаимоисключающими bucket'ами: `dns_failed`, `domain_to_foreign_timeout`, `ipv4_literal_timeout`, `ipv6_literal_timeout`, `blocked_private_fake`, `client_reset_eof`, `invalid_reality`, `disabled_invalid`.
- Добавлена штатная команда `vpn verify live --deployment <name>` для acceptance-проверки installed config, manifest drift, сервисов, WireGuard/probe состояния и свежих логовых bucket'ов после reinstall.

## [0.8.9] - 2026-07-06

### Fixed

- IPv6 literal traffic на российском `sing-box` вынесен в отдельный outbound `to-foreign-ipv6-literal` с новым публичным env `TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT=3s`. Live-проверка 6 июля показала, что часть IPv6 endpoints через foreign открывается примерно за `2.1s`, поэтому общий `2s` timeout из `to-foreign-ip-literal` резал живые подключения и давал зависания сайтов.
- IPv4 literal traffic остаётся на `to-foreign-ip-literal` с прежним `TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT=2s`, чтобы не возвращать длинные подвисы на реально недоступных IPv4 literals.
- `status` и `diagnose path` теперь разделяют IPv4-literal и IPv6-literal outbound counters/destinations, чтобы следующий инцидент не смешивал разные классы timeout'ов.

## [0.8.8] - 2026-07-03

### Fixed

- IPv6 literal destinations на российском `sing-box` больше не блокируются дефолтным `RU_IPV6_POLICY=fast-fail`: live-проверка отдельным `sing-box` на `wg0` с `routing_mark=48` подтвердила рабочий foreign IPv6 path, поэтому дефолт возвращён к `RU_IPV6_POLICY=to-foreign`.
- IPv6 literal трафик идёт не через обычный доменный `to-foreign`, а через `to-foreign-ip-literal` с коротким `TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT=2s`, чтобы рабочие IPv6 endpoints открывались, а битые literals не подвешивали сайты.
- `install.sh` снова синхронизирован с Python defaults: `GLOBAL_DOH_SERVER=8.8.8.8`, `GLOBAL_DOH_SERVER_NAME=dns.google`, `RU_SNIFF_TIMEOUT=250ms`, `RU_IPV6_POLICY=to-foreign`.

## [0.8.7] - 2026-07-03

### Fixed

- Глобальный DoH resolver для российского `sing-box` переведён с `1.1.1.1/cloudflare-dns.com` на `8.8.8.8/dns.google`: live-пробы показали периодические `dns: lookup failed ... context deadline exceeded` на текущем Cloudflare DoH path, из-за чего часть сайтов открывалась с 10-секундными DNS подвисаниями.
- Старый server-authoritative env с `GLOBAL_DOH_SERVER=1.1.1.1` и `GLOBAL_DOH_SERVER_NAME=cloudflare-dns.com` мигрирует на новый resolver при штатном reinstall.
- `status` теперь печатает текущий global DoH рядом с DNS timeout counters, чтобы следующий DNS-сбой был привязан к конкретному upstream resolver.

## [0.8.6] - 2026-07-03

### Fixed

- `sing-box` на российском сервере снова использует `info` как дефолтный уровень логов, а промежуточный плохой default `warn` мигрирует обратно в `info`: routed diagnostics в `status`/`diagnose path` завязаны на connection log и не должны тихо слепнуть.
- Убран runtime override `SING_BOX_LOG_LEVEL` поверх server-authoritative deployment env. Штатная установка снова берёт конфигурацию из синхронизированного deployment env без скрытой подмены.
- `status` теперь предупреждает, если на `ru-gateway` вручную выставлен `SING_BOX_LOG_LEVEL` выше `info`, потому в таком режиме top routed destinations будут неполными.

## [0.8.5] - 2026-07-01

### Fixed

- Голые публичные IPv4 назначения на российском `sing-box` теперь идут через отдельный outbound `to-foreign-ip-literal` с коротким `TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT=2s`. Это сокращает подвисы на недоступных IP literal, но не возвращает глобальный timeout для обычного доменного `to-foreign`.
- `status` и `diagnose path` теперь отдельно показывают timeout'ы `to-foreign-ip-literal`, обычного `to-foreign`, `direct-ru` и DNS, а Xray `disabled.invalid` больше не смешивается с invalid REALITY.
- Foreign health-check повторяет быструю WG-проверку и не пишет hard failure на одиночный промах, если предыдущий профильный WireGuard path свежий и живой.
- Installer добавляет управляемый journald drop-in (`SystemMaxUse=256M`, `MaxRetentionSec=14day`) и bounded vacuum, чтобы серверные журналы не разрастались до сотен мегабайт на малых VPS.

## [0.8.4] - 2026-06-22

### Changed

- Web admin navbar теперь остаётся горизонтальным и на мобильной ширине.
- Предупреждение web admin про foreign-side RU block теперь показывается только если `FOREIGN_BLOCK_RU=1`, а загрузка списка исключений отображается явно.
- Foreign-side RU block отключён по умолчанию (`FOREIGN_BLOCK_RU=0`), чтобы правила web admin могли отправлять выбранные российские домены через зарубежный сервер без дополнительного deny на foreign host.
- Старый foreign RU block сохранён как явный opt-in: при `FOREIGN_BLOCK_RU=1` рендерятся `ru_ipv4/ru_ipv6` sets, загружаются CIDR assets и включаются drop-правила на зарубежном сервере.

## [0.8.3] - 2026-06-22

### Changed

- Web admin теперь сначала проверяет и записывает routing-исключения, возвращает JSON-ответ браузеру и только после этого отложенно перезапускает `sing-box`. Это убирает ложные `status 0`/`Ошибка сохранения`, когда сам запрос к админке проходил через перезапускаемый dataplane.
- На странице исключений можно временно включать/выключать правило, менять режим поддоменов и выбирать сервер выхода без удаления правила.
- Во время сохранения, обновления или удаления блокируются только участвующие элементы формы/строки, а таблица обновляется из ответа API без лишнего запроса.

## [0.8.2] - 2026-06-22

### Fixed

- Web admin active-client gate теперь корректно распознаёт клиентов из `ss`, когда Linux показывает IPv4-подключения как IPv4-mapped IPv6 (`::ffff:x.x.x.x`). Без этого `admin_clients_ipv4` оставался пустым, и вход в админку с телефона через VPN закрывался.
- Российский `sing-box` теперь маршрутизирует собственный `RU_PUBLIC_IP/32` через `direct-ru` до общего `0.0.0.0/0 -> to-foreign`, чтобы запросы к `http://<ip-российского-сервера>:11333` из VPN не уходили на зарубежный выход и не таймаутились.

## [0.8.1] - 2026-06-22

### Changed

- Web admin теперь по умолчанию слушает `0.0.0.0:11333`, но доступ получает только множество текущих активных VPN-клиентов российского сервера.
- Доступ к web admin больше не завязан на один operator IP: `vpn-stack-admin.service` синхронизирует динамический nftables set `admin_clients_ipv4` из established TCP-пиров на VPN-порту.
- Hairpin/tunneled вход в web admin разрешён только пока есть хотя бы один активный VPN-клиент, чтобы source вида `RU_PUBLIC_IP`/`FOREIGN_PUBLIC_IP` не становился постоянным обходом.

### Security

- Без активного VPN-клиента соединение к web admin закрывается без обычного HTTP-ответа.
- Публичный bind с дефолтными `user/password` разрешён только при включённой защите `ADMIN_WEB_ACTIVE_CLIENT_REQUIRED=1`; если её отключить, сервис откажется стартовать до смены учётки или явного allowlist.

## [0.8.0] - 2026-06-22

### Added

- Добавлен web admin на `российском сервере` для server-side исключений маршрутизации: домен, wildcard-поддомены или CIDR можно добавить/удалить через простой Bootstrap 5 + jQuery интерфейс.
- Добавлены настройки `ADMIN_WEB_ENABLED`, `ADMIN_WEB_BIND`, `ADMIN_WEB_PORT`, `ADMIN_WEB_ALLOWED_CIDR`, `ADMIN_WEB_ALLOW_WG`, `ADMIN_WEB_USERNAME` и `ADMIN_WEB_PASSWORD`.
- Правила web admin сохраняются в `/etc/vpn-stack/admin-routing-rules.json`, накладываются поверх `/etc/vpn-stack/sing-box.base.json`, проверяются через `sing-box check` и применяются перезапуском `sing-box`.

### Security

- По умолчанию web admin слушает только `127.0.0.1:11333`; штатный доступ с компьютера оператора — через SSH-туннель.
- Если web admin явно привязать к публичному адресу, приложение откажется стартовать с дефолтными `user/password`, а доступ дополнительно ограничивается `ADMIN_WEB_ALLOWED_CIDR`.

## [0.7.0] - 2026-06-22

### Added

- Добавлен штатный non-interactive CLI для `install`, `reinstall`, `status` и `diagnose path`: теперь обслуживание можно запускать через `vpn.cmd`/`vpn.sh` без ручных временных скриптов.
- Добавлены runtime-only env-переменные для SSH-доступа в консольном режиме: `VPN_RU_SSH_PASSWORD`, `VPN_FOREIGN_SSH_PASSWORD`, общий fallback `VPN_SSH_PASSWORD` и role-scoped overrides для host/port/user/auth/key.

### Changed

- Packet loss теперь участвует в итоговом `health verdict`, а не теряется в необработанных числах диагностики.
- Фоновое самовосстановление больше не перезапускает WireGuard/NAT из-за мягких speed/ping degradation reasons. Такие симптомы логируются и видны в `status/diagnose`, но не запускают restart loop без подтверждённой поломки dataplane.

## [0.6.5] - 2026-06-21

### Fixed

- Российский сервер теперь маршрутизирует публичные IPv4 literal назначения напрямую в `to-foreign` до общего `dns-global resolve`. Это убирает лишний DNS-resolve слой для клиентов, которые присылают на сервер уже готовый IP вместо домена, и сохраняет server-side split-routing для обычных доменных подключений.
- Private IP, forced-direct CIDR, blocked CIDR, IPv6 policy и optional `RU_GEOIP_DIRECT` остаются выше нового IPv4-literal правила, поэтому российские исключения и запреты не перекрываются общим зарубежным выходом.
- Дефолт `RU_SNIFF_TIMEOUT` снижен с `1s` до `250ms`, а старые env со значением `1s` мигрируют на новый дефолт. Это убирает секундную задержку на каждом IP-only соединении, но оставляет короткую попытку восстановить домен из трафика.

## [0.6.4] - 2026-06-21

### Fixed

- Управляемые Xray JSON fallback-профили (`windows-xray.json`, `android-v2rayng-xray.json`) больше не включают клиентский DNS `1.1.1.1/8.8.8.8` и `IPIfNonMatch`: доменные подключения передаются на российский сервер как домены, чтобы серверный split-router, а не клиентский резолв, принимал решение `российский сервер`/`зарубежный сервер`.
- Quick-audit теперь запрещает возврат клиентского DNS в Xray JSON и требует `routing.domainStrategy=AsIs`, чтобы старый источник зависаний не вернулся регрессией.

## [0.6.3] - 2026-06-21

### Fixed

- Убран дефолтный `TO_FOREIGN_CONNECT_TIMEOUT=2s` из пользовательского `to-foreign` outbound: короткий timeout ускорял отказ мёртвых endpoints, но мог рвать медленные рабочие соединения и ухудшать видео/CDN-нагрузку.
- Старые значения `TO_FOREIGN_CONNECT_TIMEOUT=1s` и `2s` теперь мигрируют в пустое значение. Короткие timeout остаются только у диагностических target probes.

## [0.6.2] - 2026-06-21

### Fixed

- `status`/preflight больше не проверяет глобальные сайты прямым российским каналом: глобальные target probes остаются на зарубежном пути, а прямой российский путь проверяется отдельным коротким списком `HEALTH_RU_DIRECT_TARGET_PROBE_URLS`.
- Target probes получили короткие настраиваемые таймауты `HEALTH_TARGET_CONNECT_TIMEOUT_SECONDS=2` и `HEALTH_TARGET_MAX_TIME_SECONDS=4`, чтобы диагностика не зависала на каждом недоступном endpoint.

## [0.6.1] - 2026-06-21

### Fixed

- `TO_FOREIGN_CONNECT_TIMEOUT` теперь по умолчанию `2s`, а старые пустое значение и `1s` мигрируют на этот дефолт. Это уменьшает подвисания страниц и видео, когда отдельные внешние endpoints не отвечают с текущего зарубежного выхода.
- `status` и preflight снова смотрят invalid Reality handshakes в правильном месте: `vpn-stack-xray.service`, а не во внутреннем `sing-box` router.
- В `status` и `vpn diagnose path` добавлены отдельные группы для Xray front и timeout destinations `sing-box`, чтобы видеть, на какой стадии и какие домены/IP реально сбоят.

## [0.6.0] - 2026-06-20

### Changed

- Российский сервер переведён на двухслойную схему: публичный `VLESS/Reality` вход обслуживает Xray с `sniffing.destOverride`, а `sing-box` остаётся внутренним split-router'ом через локальный SOCKS/mixed вход.
- `vless-uri.txt` остаётся основным способом подключения и не меняет формат. Изменение находится на серверной стороне: Xray восстанавливает домен из TLS/HTTP/QUIC SNI даже когда клиент прислал IP/IPv6 literal, а затем передаёт доменный destination во внутренний `sing-box` router.
- Внутренний `sing-box` router на российском сервере слушает локальный `RU_ROUTER_LISTEN_PORT=2080`, использует IPv4-only `domain_resolver` для `direct-ru` и `to-foreign`, а публичный порт `RU_LISTEN_PORT=443` остаётся за Xray.
- `status`, preflight и postcheck теперь учитывают `vpn-stack-xray.service`, чтобы публичный вход не выпадал из диагностики.

## [0.5.9] - 2026-06-20

### Fixed

- IPv6 literal destinations на российском сервере теперь fast-fail до любых `direct-ru` правил. Это закрывает свежий live-сбой, где Google/YouTube/Opera IPv6-адреса попадали в forced-direct маршрут и висели на `i/o timeout` через российский сервер.
- Обновлена регрессия порядка правил: `sniff` и DNS hijack остаются первыми, но `ip_version: 6` теперь стоит перед forced-direct domain/geosite/CIDR routes и перед общим IPv4 resolve.

## [0.5.8] - 2026-06-20

### Fixed

- `ru-geoip` больше не является дефолтным прямым fallback-маршрутом для неизвестных IP-literal соединений. Российский выход сохраняется для доменов, суффиксов, `ru-geosite` и явных `RU_FORCE_DIRECT_IP_CIDR`, а неизвестные IP теперь уходят через зарубежный сервер по `route.final`.
- Добавлен явный opt-in `RU_GEOIP_DIRECT=1` для операторов, которым всё же нужен старый geoip-based fallback.

## [0.5.7] - 2026-06-20

### Fixed

- Пользовательский трафик переведён в IPv4-first режим: клиентские JSON-профили больше не добавляют IPv6 TUN-адрес по умолчанию, DNS продолжает отклонять AAAA, а российский сервер после `sniff` сначала делает IPv4 `resolve` для доменных соединений и только потом быстро отклоняет оставшиеся IPv6 literal destinations.
- Убран дефолтный `TO_FOREIGN_CONNECT_TIMEOUT=1s`: короткий connect-timeout ломал медленные, но рабочие IPv4 endpoints. Поле осталось только как явный диагностический override.
- Добавлен `RU_SNIFF_TIMEOUT=1s`, чтобы сервер успевал считать TLS/SNI и не превращал нормальные доменные сайты в слепой IPv6 reject.
- Первичный `vpn-stack-sync.service` во время установки больше не может зависнуть на внешнем rule-set источнике: downloads ограничены по времени, а installer продолжает работу с bootstrap assets.
- Client JSON переведён на route-level `sniff`, совместимый с sing-box 1.13, без legacy inbound sniff fields.
- Добавлена регрессия на quoting удалённых команд с heredoc/одинарными кавычками, чтобы диагностика и workflow не собирали `bash -lc` вручную.

## [0.5.6] - 2026-06-20

### Fixed

- Российский сервер теперь после `sniff` сначала применяет доменные правила и общий `dns-global` IPv4 resolve, и только потом делает IPv6 fast-fail. Это снижает зависания на доменных TLS/SNI соединениях, но сохраняет normal server-side routing для доменных соединений.
- Добавлен выключенный по умолчанию диагностический флаг `RU_BLOCK_QUIC=0/1`; после live-проверки QUIC-блок не включается дефолтом, потому отдельные сайты могут зависеть от UDP/443.
- Outbound `to-foreign` временно получил короткий `connect_timeout=1s` для diagnostic/override режима.
- `install.sh` и Python defaults снова согласованы: `RU_IPV6_POLICY=fast-fail` является единым дефолтом, а legacy `block`/`to-foreign` мигрируют в текущий стабильный профиль.
- После `sniff` добавлены серверные `hijack-dns` и `udp_disable_domain_unmapping`, чтобы UDP/DNS-клиенты с fakeIP не тянули на российский сервер бесполезные `fdfd::...` назначения вместо доменного запроса.
- `status/preflight` и `diagnose path` дополнительно показывают успешные свежие маршруты `to-foreign`/`direct-ru`, top destinations, источники `mux connection closed` и IPv6 literal destinations. Это отделяет реальный отказ dataplane от клиентских IPv6/fakeIP попыток.

## [0.5.5] - 2026-06-20

### Fixed

- Российский VLESS/Reality вход снова рендерится как простой серверный профиль без inbound `multiplex`; это убирает добавленную позднее нестабильную точку, которая коррелировала с сериями `mux connection closed` в живых логах.
- `sing-box` на российском сервере по умолчанию пишет `info`, чтобы в следующем сбое были видны реальные входящие соединения и маршруты, а не только редкие warning/error строки.
- `status/preflight` и `diagnose path` теперь группируют свежие серверные ошибки `sing-box`: `blocked`, `mux_closed`, `EOF`, DNS failures, timeout'ы, invalid Reality источники, top client sources и примеры заблокированных направлений, включая fake/private IP destinations вида `fdfd::...`.
- Финальный экран, `NEXT-STEPS.txt`, README и `docs/PROJECT.md` снова фиксируют простой `vless-uri.txt` как основной клиентский контракт; JSON-файлы оставлены как fallback.

## [0.5.4] - 2026-06-19

### Fixed

- `RU_IPV6_POLICY` переведён в явный стабильный режим `fast-fail`: клиентские IPv6 literal destinations больше не уходят в нестабильный IPv6 path зарубежного сервера и не дают частые 5-секундные подвисы сайтов.
- Legacy env со значениями `RU_IPV6_POLICY=block` и `RU_IPV6_POLICY=to-foreign` при merge/reinstall мигрирует в `fast-fail`; `to-foreign` оставлен только как низкоуровневый render override для диагностики.
- `status/preflight` теперь показывает счётчики недавних `sing-box` timeout'ов по `to-foreign`, `direct-ru` и DNS, плюс последний пример строки из журнала.

## [0.5.3] - 2026-06-18

### Fixed

- `RU_IPV6_POLICY` снова по умолчанию `to-foreign`: живые логи российского сервера показали блокировку IPv6 destinations от клиентов, а проверочный запуск `sing-box` подтвердил, что IPv6 fallback через `wg0 -> зарубежный сервер` работает.
- Убрана старая нормализация `to-foreign -> block`; legacy env с `RU_IPV6_POLICY=block` при merge/reinstall мигрирует обратно на рабочий fallback.
- README и `docs/PROJECT.md` разделяли клиентскую IPv4-only защиту и серверный IPv6 fallback; это поведение признано нестабильным в `0.5.4`.

## [0.5.2] - 2026-06-18

### Fixed

- `vpn audit quick/all` теперь проверяет не только наличие `android-v2rayng-xray.json`, но и сам критичный контракт профиля: `dns.queryStrategy=UseIPv4`, первое routing-правило `::/0 -> block`, sniffing `http/tls/quic` с `routeOnly=false`.
- Это закрепляет финальное решение по Android/v2rayNG: клиентский IPv6 гасится до входа в VLESS/Reality, а sniffing остаётся дополнительной страховкой для доменных TLS/QUIC соединений.

## [0.5.1] - 2026-06-18

### Fixed

- Управляемый Xray/v2rayNG профиль теперь явно отключает IPv6 на клиентской стороне: `dns.queryStrategy=UseIPv4`, а первое routing-правило отправляет `::/0` в `blackhole`. Это убирает зависимость от локального IPv6 DNS/IPv6 destination до входа в VLESS/Reality.
- `android-v2rayng-xray.json` сохраняет sniffing для `http/tls/quic`, но больше не полагается только на sniffing: IPv6-трафик клиента блокируется заранее.

## [0.5.0] - 2026-06-18

### Changed

- Для Android/v2rayNG добавлен отдельный управляемый артефакт `android-v2rayng-xray.json`. Он использует полный Xray JSON с inbound sniffing для `http`, `tls` и `quic`, поэтому клиент не отправляет на российский сервер локально разрешённый IPv6 literal вместо домена.
- Финальный экран, `NEXT-STEPS.txt`, `README.md` и `docs/PROJECT.md` больше не обещают универсальность сырого `VLESS URI`: он остаётся быстрым fallback, но стабильный Android-путь теперь полный Xray JSON.

### Fixed

- Xray/v2rayN профиль теперь явно задаёт `routeOnly=false` и sniffing для `quic` наряду с `http/tls`, чтобы TLS/QUIC SNI мог заменить IP-literal destination на домен до отправки в VLESS/Reality.
- Российский `sing-box` сначала делает `sniff` TLS/HTTP-домена, затем применяет доменные правила и только потом выполняет IPv4-only `resolve` перед IP-правилами. Это сохраняет корректный server-side routing для клиентов, которые отправляют домен, но не подменяет универсально произвольный IPv6 literal.

## [0.4.7] - 2026-06-18

### Fixed

- `RU_IPV6_POLICY` снова по умолчанию `block`: серверные логи показали массовые `sing-box` IPv6 dial timeout'ы через `to-foreign`, которые давали медленное открытие сайтов
- `vpn-stack-guard` больше не блокирует Reality-invalid источники по умолчанию; события остаются в диагностике, но клиентский IP не попадает в 6-часовой nftables blocklist из-за серии старых/оборванных подключений
- Добавлен явный флаг `GUARD_REALITY_BLOCK_ENABLED=0/1`: SSH brute-force guard остаётся активным, Reality block включается только оператором после подтверждения внешнего сканера

## [0.4.6] - 2026-06-18

### Fixed

- Откатан опасный дефолт `RU_BLOCK_IP_CIDR=91.108.56.0/22`: service-owned Telegram CIDR больше не блокируется сервером по умолчанию, потому блок мог ломать клиентов вместо надёжного fallback
- `RU_IPV6_POLICY` снова по умолчанию `to-foreign`; `block` остаётся только явной операторской диагностикой
- Старые deployment env, уже получившие опасные значения из `0.4.5`, автоматически мигрируют обратно на безопасный профиль при следующем render/reinstall

## [0.4.5] - 2026-06-18

### Fixed

- Российский сервер теперь fail-fast блокирует наблюдавшийся проблемный Telegram DC CIDR `91.108.56.0/22`, чтобы Telegram Desktop и похожие клиенты не зависали на долгом TCP timeout и быстрее переходили к рабочим Telegram endpoints
- IPv6 literal traffic на российском сервере по умолчанию быстро блокируется вместо попытки идти через нестабильный foreign IPv6 path; при необходимости старое поведение можно вернуть через `RU_IPV6_POLICY=to-foreign`
- health target probes расширены Telegram-доменами, чтобы runtime-диагностика покрывала не только общие сайты, но и реальный пользовательский сценарий Telegram

## [0.4.4] - 2026-06-18

### Fixed

- SSH backend больше не выделяет pseudo-TTY для любого stdin: `bash -s` диагностика и служебные remote-команды больше не превращаются в интерактивную сессию с prompt/echo и не зависают на чтении канала
- `paramiko_exec` получил общий command timeout и теперь возвращает понятную `AppError` с частичным remote output вместо бесконечного ожидания зависшей команды
- install/reinstall исправляет failed `rc-local.service`, если он сломан из-за non-executable `/etc/rc.local`, и сбрасывает failed-state после исправления
- install/reinstall отключает legacy Xray/V2Ray services на управляемом хосте, чтобы старые прокси-сервисы не оставались активными рядом с `vpn-stack`
- `vpn-stack-health.service` больше не оставляет ложный failed-state во время штатного reinstall, когда второй сервер ещё не поднят; hard failure логируется и передаётся self-heal без загрязнения `systemctl --failed`

## [0.4.3] - 2026-06-17

### Fixed

- `vpn-stack-health` больше не считает `wg_handshake_stale` hard-failure, если сам WireGuard path живой: это убирает ложные рестарты `wg0` на кратком timer/jitter около старой границы 120 секунд
- effective handshake grace теперь вычисляется динамически: максимум из явного значения, минимального порога и `WG_KEEPALIVE * HEALTH_HANDSHAKE_GRACE_MULTIPLIER`
- старые deployment env с `HEALTH_HANDSHAKE_GRACE_SECONDS=120` и `HEALTH_DEEP_PROBE_INTERVAL_MINUTES=30` мигрируют на более устойчивый runtime profile при следующем render/reinstall

### Added

- health-state теперь сохраняет runtime profile: возраст handshake, effective grace, факт живого `wg0` path, fast ping-loss и stale-handshake-with-live-path marker
- `status` / preflight выводят runtime profile, чтобы отличать настоящую поломку dataplane от безопасного handshake jitter

## [0.4.2] - 2026-06-15

### Added

- добавлен `vpn-stack-guard.service` + `vpn-stack-guard.timer`: серверы теперь сами читают последние журналы `ssh` и, на российском сервере, invalid `REALITY` handshakes, после чего временно блокируют шумные IPv4 через nftables set `abuse_ipv4`
- `status`, preflight и `vpn diagnose path` теперь показывают состояние guard, последний запуск и счётчики временно заблокированных источников

### Changed

- nftables-конфиги обеих ролей получили ранний drop по `ip saddr @abuse_ipv4`; dataplane, WireGuard и клиентские артефакты не менялись

## [0.4.1] - 2026-06-12

### Fixed

- preflight теперь проверяет локальный self-tunnel маршрут после ручного ввода параметров сервера, а не только для сохранённых подключений
- deployment health теперь учитывает `target_probe` по ключевым внешним сайтам и показывает `*_target_degraded`, если серверный dataplane жив, но конкретный сайт возвращает blocked/broken
- runtime health больше не держит stale `DEEP_PROBE_VERDICT=degraded` до конца интервала: после деградации следующий health-check сразу запускает deep probe и очищает состояние при восстановлении

## [0.4.0] - 2026-06-11

### Added

- добавлена команда `vpn diagnose path`, которая собирает path/qdisc/WireGuard/MTR/curl/health диагностику в `out/diagnostics`
- добавлен bounded `--iperf` режим для проверки TCP/UDP между серверами через `wg0` с временным firewall-правилом и обязательной очисткой

### Changed

- default runtime network profile переведён на `RUNTIME_QDISC=fq` с fallback на `fq_codel`, чтобы лучше использовать pacing при `bbr`
- default `WG_MTU` снижен с `1380` до `1360`; legacy env со старым default автоматически мигрирует при следующем merge/reinstall
- установщик теперь ставит `mtr-tiny` и `iperf3`, чтобы диагностика пути была доступна после обычного `reinstall`

## [0.3.14] - 2026-06-11

### Fixed

- runtime health-check больше не запускает self-heal на soft-деградации канала (`*_ping_loss_fast`, throughput ниже порога), потому что packet loss между провайдерами не чинится рестартом WireGuard и такие рестарты могут рвать клиентские сессии
- legacy SSH rate-limit `12/minute burst 6` мигрирует к более жёсткому дефолту `6/minute burst 3`, чтобы снизить влияние публичного SSH brute-force на banner/auth path без отключения password-входа

## [0.3.13] - 2026-06-06

### Fixed

- IPv6 literal-трафик, не заданный явно в `RU_FORCE_DIRECT_IP_CIDR`, теперь маршрутизируется через зарубежный сервер до проверки `ru-geoip`, чтобы ошибочные geoip-матчи не уводили зарубежные IPv6-адреса напрямую с российского сервера
- добавлена регрессия на порядок правил `ip_version: 6` и `ru-geoip`

## [0.3.12] - 2026-06-06

### Fixed

- российский REALITY вход теперь принимает основной short_id и пустой short_id, чтобы мобильные клиенты не отваливались, если импорт профиля теряет `sid`
- добавлена настройка `RU_REALITY_ACCEPT_EMPTY_SHORT_ID=1` для управляемой совместимости без изменения основного VLESS URI
- Docker runtime smoke теперь проверяет mux-клиент без `sid`

## [0.3.11] - 2026-06-06

### Fixed

- российский VLESS/Reality вход теперь явно включает inbound multiplex, чтобы клиенты с mux не рвали соединение после успешного handshake
- добавлен Docker runtime smoke для mux-подключения к российскому `sing-box`
- audit Docker image теперь закреплён на той же версии `sing-box`, что и серверный установщик

## [0.3.10] - 2026-06-05

### Fixed

- российский сервер больше не блокирует IPv6 literal-трафик от клиентов, а отправляет его через зарубежный сервер
- WireGuard между серверами получил внутренний IPv6, а зарубежный сервер теперь рендерит NAT66 для этого туннеля
- self-heal для российского WireGuard восстанавливает IPv4 и IPv6 policy routes вместе

## [0.3.9] - 2026-06-05

### Fixed

- `vless-uri.txt` и `hiddify-uri.txt` возвращены к URI-формату `0.2.37`: без `encryption=none`
- это откатывает клиентский импорт для мобильных VLESS/Reality клиентов к последней подтверждённо рабочей форме, при этом JSON/Xray profiles сохраняют свой явный `encryption: none`

## [0.3.8] - 2026-06-05

### Fixed

- убран совместимый VLESS/Reality listener `8443/tcp`: российский сервер снова рендерит только один публичный вход `443/tcp`
- `RU_COMPAT_LISTEN_PORTS` признан deprecated и удаляется из deployment env при следующем merge/reinstall
- возвращён явный `RU_REALITY_MAX_TIME_DIFFERENCE=24h`, чтобы внешние клиенты не отваливались на REALITY handshake из-за рассинхрона системного времени

## [0.3.7] - 2026-06-05

### Fixed

- основной VLESS/Reality вход российского сервера возвращён на стабильный публичный `443/tcp`; смена primary-порта на `8443/tcp` в `0.3.5` признана ошибочной, потому что ломала уже импортированные клиентские профили
- `8443/tcp` теперь рендерится только как совместимый дополнительный вход, чтобы профили из `0.3.5`/`0.3.6` не отвалились сразу
- существующие deployment env с `RU_LISTEN_PORT=8443` автоматически мигрируются обратно на `443`, а клиентские артефакты снова генерируются с каноническим портом `443`

## [0.3.6] - 2026-06-05

### Added

- `vpn client-check` теперь ищет локально импортированные stale-профили Hiddify/v2rayN/старые JSON в типовых местах и сравнивает их с текущим deployment: порт, UUID, REALITY public key и short_id
- при найденном drift команда прямо печатает, какой локальный профиль устарел, и показывает свежие `vless-uri.txt` / `hiddify-cross-platform.json` для повторного импорта

## [0.3.5] - 2026-06-05

### Fixed

- российский VLESS/Reality вход переносится с публичного `443/tcp` на `8443/tcp`: live-проверка показала, что на текущем маршруте `:443` Xray-клиент получает реальный сертификат fallback-сайта и Reality-handshake ломается, а тот же конфиг на `:8443` проходит
- существующие deployment env с `RU_LISTEN_PORT=443` автоматически мигрируются на новый рабочий порт при загрузке локального или серверного env, поэтому обычный `reinstall` пересобирает актуальный `vless-uri.txt`
- убрано неподтверждённое принудительное `RU_REALITY_MAX_TIME_DIFFERENCE=24h` из дефолтного серверного Reality-конфига; параметр остаётся доступен как явный override, но больше не маскирует реальные транспортные сбои

### Added

- в полный аудит добавлен Docker interop-тест `Xray client -> sing-box Reality server -> HTTP target`, который проверяет не только валидность JSON, но и реальный VLESS/Reality handshake с Xray

## [0.3.4] - 2026-06-05

### Fixed

- убран неудачный fallback `vless-uri-compatible.txt` и второй VLESS user: продукт снова отдаёт один канонический `VLESS URI`, чтобы не плодить разные профили для одного подключения
- в RU `sing-box` Reality inbound теперь явно задаётся `max_time_difference=24h`, чтобы сервер не отбрасывал Android/v2rayNG handshake как `REALITY: processed invalid connection` из-за расхождения времени клиента
- устаревший `CLIENT_COMPAT_UUID` удаляется при merge env и не попадает в новые локальные/серверные deployment env

## [0.3.3] - 2026-06-05

### Added

- добавлен второй VLESS/Reality пользователь без `xtls-rprx-vision` flow и клиентский файл `vless-uri-compatible.txt` для мобильных и сторонних клиентов, которые ломают или не поддерживают Vision flow при импорте URI

## [0.3.2] - 2026-06-05

### Changed

- клиентский рендер вынесен из общего серверного `render.py` в отдельный модуль, чтобы дальше безопасно менять клиентские артефакты без риска задеть серверные конфиги

### Fixed

- на российском сервере больше не применяется nftables rate-limit к публичному VLESS/Reality порту: легальные клиенты и клиенты с большим числом параллельных/повторных TCP-сессий больше не должны получать случайные дропы после активной работы

## [0.3.1] - 2026-06-04

### Added

- генерируется `out/<deployment>/client/windows-route-bypass.ps1`: Windows helper для active `/32` routes до IP `российского` и `зарубежного` серверов через физический gateway, когда TUN/full VPN клиент заворачивает серверы в self-tunnel

### Fixed

- `vpn client-check` теперь сразу показывает путь к `windows-route-bypass.ps1`, если обнаруживает `BAD: self-tunnel`
- итоговый экран и `NEXT-STEPS.txt` теперь дают практический следующий шаг для Windows self-tunnel, а не только предупреждение про direct/bypass

## [0.3.0] - 2026-06-04

### Added

- добавлена команда `vpn client-check`, которая проверяет локальный маршрут до IP серверов и сразу показывает self-tunnel ситуацию, когда сервер доступен через VPN-интерфейс самого клиента
- перед `status/reinstall/remove/purge` для сохранённых подключений добавлен preflight-guard: мастер останавливается до SSH, если IP сервера уходит через `singbox`/`Hiddify`/`v2ray`/другой self-tunnel интерфейс

### Fixed

- primary `vless-uri.txt` теперь явно включает `encryption=none`, чтобы разные VLESS-клиенты не импортировали профиль неоднозначно и не ломали Reality handshake
- `windows-xray.json` теперь явно отправляет IP `российского` и `зарубежного` серверов в `direct`, чтобы TUN/full VPN клиенты не заворачивали подключение к самому VPN внутрь VPN
- локальная генерация клиентских артефактов больше не удаляет `out/<deployment>/client` целиком, поэтому открытая в Explorer/клиенте папка не блокирует `install/reinstall`
- `nftables` правила публичных TCP-входов теперь имеют счётчики accept/drop, чтобы в `status`/ручной диагностике было видно, режется ли вход firewall'ом или запрос доходит до `sing-box`

## [0.2.37] - 2026-05-24

### Fixed

- генерация клиентских артефактов теперь очищает старые `hiddify-subscription-url.txt` / import-url файлы, чтобы пользователям не уходили устаревшие subscription-ссылки вместо актуального `vless-uri.txt`
- render preview/server/cloud-init директорий теперь удаляет старые generated-файлы перед записью новых, чтобы legacy `preview/.../subscription/...` не попадал в bundle после смены SNI/ключей
- asset loader теперь использует локальный cache из других `out/*/assets`, если внешние `geosite/geoip` источники временно отдают connection reset

## [0.2.36] - 2026-05-19

### Fixed

- `ru-gateway` health теперь явно проверяет main-route до WireGuard IP `foreign-exit`; если маршрут исчез после рестарта интерфейса, причина фиксируется как `ru_wg_peer_route_missing`
- server-side self-heal для `ru-gateway` умеет восстановить runtime host-route до `foreign-exit`, вместо ложного зелёного статуса при сломанном обратном WG path

## [0.2.35] - 2026-05-19

### Fixed

- primary VLESS/Reality URI снова использует `fp=chrome` при текущем `sni=www.bing.com`: live-проверка показала, что серверный вход с этим профилем работает, а `fp=randomized` давал высокий риск invalid Reality handshake у пользовательских клиентов
- server-side health больше не считает stale WireGuard handshake самостоятельным hard-failure до проверки реального WireGuard dataplane, чтобы таймер не перезапускал `wg0` на живом канале
- `ru-gateway` теперь добавляет явный host-route до `foreign-exit` WireGuard IP в main table, чтобы `foreign-exit` мог проверять обратный WG path и не запускал ложный self-heal
- `status` / preflight теперь показывают недавние `REALITY: processed invalid connection` по российскому серверу, чтобы отличать неправильный клиентский URI от проблем `WireGuard` или `foreign` egress

## [0.2.34] - 2026-05-19

### Fixed

- RU WireGuard hooks теперь безопасны для повторного `reinstall`: `PreDown` не валит остановку, если policy rule/route уже отсутствуют, а `PostUp` использует idempotent route replace
- `install.sh` перед стартом `wg-quick@<iface>` удаляет stale WireGuard interface после неудачного предыдущего stop, чтобы ошибка `wg-quick: 'wg0' already exists` не блокировала переустановку

## [0.2.33] - 2026-05-19

### Fixed

- `reinstall` больше не останавливает управляемые сервисы до успешного `apt-get`: если Ubuntu держит `dpkg` lock через `unattended-upgr`, сервер не остается с остановленным VPN-стеком
- `install.sh` теперь ждёт освобождения `apt/dpkg` locks и запускает `apt-get` с `DPkg::Lock::Timeout`, вместо мгновенного падения на фоновых обновлениях Ubuntu
- при ошибке после начала применения файлов `install.sh` восстанавливает предыдущие конфиги и service state из snapshot/baseline, вместо оставления частично применённой установки

## [0.2.32] - 2026-05-19

### Fixed

- существующие deployment env со старым `www.cloudflare.com` теперь мигрируют на рабочий Reality SNI/handshake `www.bing.com`, чтобы reinstall не возвращал сломанный публичный вход

## [0.2.31] - 2026-05-19

### Added

- default `UTLS_FINGERPRINT` изменён на `randomized`, потому что публичный sing-box Reality client с `chrome` зависал на handshake с sing-box server
- default Reality camouflage SNI/handshake изменён на `www.bing.com`: публичный вход на RU с `www.cloudflare.com` давал `REALITY: processed invalid connection`, а `www.bing.com` прошёл live-проверку через foreign
- `status` теперь проверяет список контрольных зарубежных целей (`HEALTH_TARGET_PROBE_URLS`) напрямую с `зарубежного сервера` и через `российский сервер -> wg0 -> зарубежный сервер`
- target-probe явно классифицирует ответ как `reachable`, `blocked` или `broken`, чтобы отличать падение dataplane от блокировки конкретного выходного IP сайтом
- клиентские артефакты теперь включают `windows-xray.json` для v2rayN/Xray core

### Fixed

- Windows/v2rayN сценарий больше не завязан на sing-box client core для VLESS/REALITY; проверенный Xray JSON не требует `geoip.dat` и проходит live-туннель через RU
- `install.sh` перед запуском sing-box на RU останавливает legacy Xray, если он занимает публичный VLESS порт

## [0.2.29] - 2026-05-08

### Added

- серверный `vpn-stack-health.timer` получил ограниченное самовосстановление для деградации dataplane: быстрый ping-loss probe между серверами, подтверждение повтором, cooldown и лимит действий в час
- health-state и `status` теперь показывают последние fast ping-loss метрики и последнее self-heal действие, чтобы было видно, что именно пытался чинить сервер

### Fixed

- самовосстановление больше не может уйти в бесконечный цикл: SSH не рестартуется, WireGuard/nftables перезапускаются только для подходящих классов причин и только после rate-limit проверки
- `vpn audit quick` теперь пропускает Docker-зависимые проверки, если CLI установлен, но Docker daemon не запущен, вместо ложного падения пользовательской проверки

## [0.2.28] - 2026-04-29

### Fixed

- `vpn-stack-health.timer` больше не перезапускает `ssh`, `WireGuard`, `sing-box`, `nftables` или sync-service из фонового таймера: серверный health теперь только применяет безвредный runtime tuning, обновляет диагностический state и сообщает hard/soft verdict
- install/reinstall больше не ломаются от non-zero server-side health script до deployment-level проверки: мастер пишет предупреждение и дальше сам принимает решение по полному health snapshot
- убраны фоновые repair-действия, которые не могли исправить packet loss до шлюза VPS-провайдера и только маскировали реальную причину деградации `foreign`

## [0.2.27] - 2026-04-28

### Fixed

- `status` / `preflight` / post-install health теперь отдельно показывают loss до default gateway `зарубежного сервера`, чтобы сразу отличать провайдерскую деградацию узла от проблем `WireGuard` или внешних сайтов
- soft verdict `foreign_gateway_ping_loss_degraded` добавлен в health-модель: если `foreign` теряет пакеты уже до собственного шлюза, мастер помечает это как деградацию канала VPS-провайдера, а не как ошибку конфигов проекта

## [0.2.26] - 2026-04-28

### Fixed

- install/reinstall больше не падают на soft-деградации `download/upload/ping-loss`, если dataplane уже живой: свежий `WireGuard` handshake, правильный foreign egress и совпадающий `RU over WG` IP теперь считаются достаточным условием для завершения сценария
- repair-cycle больше не пытается “чинить провайдера”: при soft-деградации мастер пишет предупреждение с метриками и возвращает управление, а hard-фейлы (`egress`, `ip mismatch`, `stale handshake`) по-прежнему останавливают сценарий

## [0.2.25] - 2026-04-28

### Fixed

- `Dataplane repair` больше не зависает на синхронном `systemctl restart ...` по SSH: repair-cycle отправляет рестарты через `--no-block`, сразу печатает следующий статус и дальше ждёт восстановление уже через обычный health polling
- в workflow добавлены явные сообщения о запуске repair units на `зарубежном` и `российском` сервере, чтобы этап восстановления не выглядел как немая остановка мастера

## [0.2.24] - 2026-04-28

### Fixed

- `vpn-stack-health` больше не перезапускает `wg` и сервисы только из-за `deep probe`-деградации throughput/loss: soft-проблемы теперь сохраняются как диагностический state для `status`, но не флапают туннель без жёсткого сбоя
- локальный repair-cycle теперь ждёт восстановления `WireGuard` handshake после рестарта, вместо ложного `wg_handshake_stale=999999` сразу же на том же запуске health-script
- в логах health-check отдельно видны `hard failure` и последний `deep degradation snapshot`, чтобы отличать реальный runtime-фейл от внешней route-specific просадки провайдера

## [0.2.23] - 2026-04-24

### Fixed

- recurring speed degradation больше не маскируется одним `Cloudflare` probe: runtime health получил deep probe по нескольким origin'ам, отдельные upload-проверки и packet-loss checks на `foreign`, чтобы частично битые внешние маршруты было видно заранее
- `status` / `preflight` теперь читают последнее сохранённое deep-health состояние с сервера и показывают min download, upload и ping-loss вместо голого “service active”, так что деградация части внешних направлений больше не выглядит как полностью зелёный контур
- после `install/reinstall` мастер теперь сам запускает runtime health script на обеих ролях, чтобы сразу засеять deep-health state и не ждать таймер, пока проблема проявится у пользователя
- installer теперь ставит `iputils-ping`, чтобы `foreign` мог реально мерить loss до `RU` и до внешнего интернета, а не оставаться слепым к этой части деградации

## [0.2.22] - 2026-04-23

### Fixed

- `status` / deployment health теперь проверяют не только свежий WireGuard handshake и IPv4 egress, но и реальную скорость HTTP download на `зарубежном сервере` и через `российский сервер -> wg0 -> зарубежный сервер`
- деградация bulk-пути теперь получает явные verdict'ы `foreign_direct_download_degraded` и `ru_wg_download_degraded`, чтобы плохой маршрут провайдера больше не выглядел как исправный контур
- `preflight` показывает download B/s рядом с qdisc/offload/WireGuard counters, чтобы диагностика долгоживущих VPS не упиралась только в ручной speedtest

## [0.2.21] - 2026-04-22

### Fixed

- `reinstall` теперь жёстче закрепляет runtime-сетевой контур на публичных интерфейсах обоих серверов: installer ставит `ethtool` и отключает `gro/gso/tso` на WAN/default iface, а не только настраивает `fq_codel` и sysctl
- `vpn-stack-health` больше не зависит от одного `api.ipify.org`: runtime health использует несколько IPv4 HTTP probes и на каждом запуске повторно накатывает NIC/qdisc hardening, чтобы долгоживущие VPS меньше деградировали по пингу и throughput через несколько дней работы
- `status` / `preflight` теперь показывают состояние WAN offload (`gro/gso/tso`) вместе с `qdisc` и drops, чтобы деградацию интерфейса было видно сразу, а не только по жалобам клиента

## [0.2.20] - 2026-04-17

### Changed

- внешний subscription-сервис на `российском сервере` больше не является частью штатного сценария: новые рендеры не открывают отдельный HTTP-порт и не публикуют server-hosted профили
- пользовательский контракт теперь окончательно локальный: основной артефакт `vless-uri.txt`, совместимые локальные fallback-файлы — `hiddify-cross-platform.json`, `hiddify-android.json` и `hiddify-uri.txt`

### Fixed

- `reinstall` теперь сам удаляет старый `vpn-stack-subscription.service` и каталог с опубликованными профилями, так что переход на локальные артефакты не требует ручной чистки сервера
- `RU` firewall больше не держит лишний публичный subscription-порт, а быстрый аудит и bundle-проверки больше не ожидают hosted subscription artifacts

## [0.2.19] - 2026-04-17

### Fixed

- публичные порты `RU` и `foreign` теперь больше не живут на голом `accept` в `nftables`: installer добавляет rate-limit на новые TCP-подключения к `ssh`, `RU 443` и `subscription`-порту, чтобы слабые VPS меньше деградировали под внешним шумом и invalid REALITY / brute-force попытками
- в firewall добавлен явный `ct state invalid drop`, чтобы раньше отбрасывать мусорные соединения вместо лишней нагрузки на userspace
- runtime sysctl усилен `net.core.somaxconn=4096` и `net.ipv4.tcp_syncookies=1`, чтобы `reinstall` докручивал и TCP backlog hardening, а не только `fq_codel`/`bbr`

## [0.2.18] - 2026-04-17

### Fixed

- `зарубежный сервер` после деградации больше не должен оставаться в состоянии «TCP до 22 есть, но SSH banner не отдаётся»: installer теперь переводит `ssh` с socket activation на обычный `ssh.service`
- для `sshd` добавлен managed hardening-конфиг с более жёсткими preauth-лимитами (`LoginGraceTime`, `MaxAuthTries`, `MaxStartups`, `PerSourceMaxStartups`, `PerSourceNetBlockSize`), чтобы слабый foreign VPS меньше залипал под внешним password-bruteforce шумом
- добавлен `vpn-stack-health.service` + `vpn-stack-health.timer`: после `reinstall` сервер теперь сам проверяет `ssh banner`, `WireGuard` handshake и dataplane egress и делает один локальный repair-cycle, вместо ситуации «лечится только ребутом из панели»
- `postcheck` и `preflight/status` теперь учитывают `vpn-stack-health.timer`, `ssh.service` и `ssh.socket`, чтобы такие деградации было видно сразу, а не по косвенным таймаутам с клиента

## [0.2.17] - 2026-04-16

### Fixed

- runtime-тюнинг по сети на серверах расширен и теперь через обычный `reinstall` включает `fq_codel`, `bbr`, `tcp_mtu_probing`, backlog и UDP buffer sysctl, чтобы не оставлять `зарубежный сервер` на узких receive-side настройках после переустановки
- `status`/preflight теперь показывают runtime-сетевые значения, которые реально нужны для диагностики: интерфейс, `qdisc`, TCP CC, backlog, drops и `WireGuard` counters
- `reinstall`/`install` теперь переживают recoverable SSH-disconnect во время remote action: после разрыва сессии мастер ждёт возврата сервера и добивает итоговый postcheck, вместо ложного общего фейла

### Changed

- публичный клиентский контракт переведён на `URI-first`: основной артефакт и clipboard теперь используют `vless-uri.txt`
- `Hiddify`-подписки, deeplink и JSON сохранены как совместимые вторичные артефакты
- Android reference path в документации теперь `v2rayNG/NekoBox`, а не обязательный `Hiddify`

## [0.2.16] - 2026-04-16

### Fixed

- клиентские профили теперь автоматически исключают IP `российского` и `зарубежного` серверов из VPN-туннеля
- это позволяет запускать `status/reinstall/remove` с того же компьютера даже при уже активном VPN-подключении и не упираться в SSH hairpin / timeout до собственных серверов

## [0.2.15] - 2026-04-16

### Fixed

- для Android добавлен отдельный `Hiddify` subscription profile без IPv6 tun-адреса и с Android-safe route options
- это обходит класс проблем, когда `Hiddify` на Android показывает `connected`, но системный трафик реально не забирается VPN-сервисом из-за несовместимого tun-конфига

### Added

- новый USB-диагностический путь `vpn android-diagnose` для съёма состояния Android / Hiddify через `adb` в `out/android/<run_id>/`

## [0.2.14] - 2026-04-15

## [0.2.13] - 2026-04-15

### Fixed

- `foreign` reinstall теперь явно настраивает `net.core.default_qdisc=fq_codel`, чтобы не скатываться на дистровый `pfifo_fast`
- на живом контуре это даёт заметно более ровный и в среднем более высокий upload через цепочку `RU -> wg -> foreign`

## [0.2.12] - 2026-04-15

### Fixed

- существующие `deployment.env` теперь дообогащаются новыми встроенными списками `RU_FORCE_DIRECT_*` и fallback-источниками assets вместо полного замораживания старых строк
- это закрывает апгрейдный сценарий, где после новых patch-релизов старый deployment продолжал жить без новых direct-исключений даже после `install/reinstall`
- shell-дефолты в `install.sh` синхронизированы с актуальным Python-контрактом для direct-доменов российского сервера

## [0.2.11] - 2026-04-15

### Fixed

- для `SSH password` режима увеличен `auth_timeout` Paramiko и добавлен автоматический retry при `Authentication timeout`
- теперь медленные VPS с паролем должны реже падать на повторных подключениях в lifecycle-сценариях вроде `remove/reinstall`
- если timeout всё же сохраняется, ошибка теперь явно указывает, что проблема именно в password-аутентификации или SSH policy хоста

## [0.2.10] - 2026-04-15

### Fixed

- в прямые исключения российского сервера добавлены `2ip.ru`, `ip.mail.ru`, `ipv4-internet.yandex.net` и `ipv6-internet.yandex.net`
- эти домены теперь должны резолвиться и маршрутизироваться через `российский сервер`, а не пытаться уходить в общий foreign-path

## [0.2.9] - 2026-04-15

### Fixed

- клиентский профиль для `Hiddify` упрощён до обычного туннеля без `fakeip` и `reverse_mapping`
- основная логика split-routing окончательно закреплена на серверной стороне, чтобы URL подписки работал предсказуемее после обычной вставки в `Hiddify`

## [0.2.8] - 2026-04-15

### Added

- российский сервер теперь может отдавать профиль подписки по отдельному URL на отдельном порту через `vpn-stack-subscription.service`
- локально теперь генерируются:
  - `hiddify-subscription-url.txt`
  - `hiddify-import-url.txt`

### Changed

- основной пользовательский путь для `Hiddify` снова переведён на URL подписки
- `hiddify-cross-platform.json` оставлен как fallback
- `hiddify-uri.txt` оставлен как сырой низкоуровневый fallback без гарантии split-routing

## [0.2.7] - 2026-04-15

### Fixed

- клиентский сценарий для `Hiddify` больше не продвигает сырой `VLESS URI` как основной путь: главным артефактом теперь считается `hiddify-cross-platform.json`, потому что именно он содержит TUN и split-routing
- финальный вывод и буфер обмена теперь ориентированы на JSON-профиль `Hiddify`, а URI оставлен только как запасной низкоуровневый вариант
- документация теперь явно предупреждает, что на Windows `Hiddify` нужно запускать с правами администратора и с включённым `TUN/VPN` режимом, иначе сайты могут видеть реальный ISP IP

## [0.2.6] - 2026-04-15

### Fixed

- устранён фатальный сбой `sing-box` на российском сервере: `dns-ru-direct` больше не рендерится с некорректным `detour` на пустой `direct` outbound
- быстрый аудит теперь умеет ловить этот класс ошибок не только через `sing-box check`, но и через runtime smoke запуска RU preview-конфига в Docker

## [0.2.5] - 2026-04-15

### Fixed

- `remove` и `purge` больше не падают с `KeyError`, если после preflight-фильтрации одна или все роли были исключены как неустановленные
- remote execution теперь работает только по реально доступным целям, а не по исходному набору запрошенных ролей
- сценарий `role=all`, где установлен только один сервер, теперь выполняет действие только для него и не пытается обратиться ко второй отсутствующей роли

## [0.2.4] - 2026-04-15

### Fixed

- postcheck после установки стал ролевым:
  - на `российском сервере` `sing-box` обязателен
  - на `зарубежном сервере` `sing-box` больше не считается обязательным активным сервисом
- `vpn-stack-sync.timer` теперь не только включается, но и сразу запускается на сервере, чтобы postcheck не падал из-за неактивного timer unit
- `remove` и `purge` из мастера больше не валятся ошибкой на сервере, где стек вообще не был установлен: такое действие теперь безопасно пропускается с понятным сообщением
- postcheck при сбое теперь печатает, какой именно сервис не прошёл проверку, вместе с `systemctl status` и хвостом `journalctl`

## [0.2.3] - 2026-04-15

### Fixed

- `vpn audit quick` переведён в user-safe режим: на обычном пользовательском ПК больше не требует `docker`, `coverage` и developer-only regression checks
- dev-only шаги быстрой самопроверки теперь корректно помечаются как `skipped`, а не валят запуск
- ошибки контура самопроверки больше не должны уходить в общий runtime лог как `menu.unhandled`
- тест на `deployment.env.example` больше не ломает полный аудит, если файл удалён локально в рабочем дереве

## [0.2.2] - 2026-04-15

### Changed

- тестовый patch-релиз для проверки автоматического GitHub Release по тегу

## [0.2.1] - 2026-04-15

### Fixed

- `vpn.cmd` больше не прячет весь пользовательский вывод в файл и не даёт пустой экран
- Windows launcher теперь оставляет полезные логи даже в ранних сценариях запуска:
  - `latest-bootstrap.log`
  - `latest-transcript.log`
  - `latest-error.log`

### Added

- автоматический GitHub Release по push тега через GitHub Actions

## [0.2.0] - 2026-04-15

### Added

- отдельный Windows launcher `vpn.cmd` для обычного пользовательского запуска
- ранний PowerShell transcript и дополнительные runtime-логи:
  - `out/logs/runtime/latest-bootstrap.log`
  - `out/logs/runtime/latest-console.log`
  - `out/logs/runtime/latest-transcript.log`
  - `out/logs/runtime/latest-error.log`

### Changed

- на Windows основной рекомендуемый путь запуска переведён на `vpn.cmd`
- документация обновлена под новый Windows-сценарий и правила версионирования

## [0.1.1] - 2026-04-15

### Added

- файловый лог ошибок для launcher/menu/PowerShell path

### Changed

- сообщения об ошибках теперь показывают путь к сохранённому логу
