# Changelog

Проект использует `SemVer`: `major.minor.patch`.

- `major` — несовместимые изменения в публичном поведении
- `minor` — новые возможности без обязательной ломки старого сценария
- `patch` — исправления багов и точечные доработки

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
