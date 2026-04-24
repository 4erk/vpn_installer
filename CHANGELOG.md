# Changelog

Проект использует `SemVer`: `major.minor.patch`.

- `major` — несовместимые изменения в публичном поведении
- `minor` — новые возможности без обязательной ломки старого сценария
- `patch` — исправления багов и точечные доработки

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
