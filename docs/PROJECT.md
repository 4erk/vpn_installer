# Техническая карта проекта

## Как читать документацию

- [README](../README.md) — установка и обычная эксплуатация.
- [PROVIDERS](./PROVIDERS.md) — выбор провайдеров и серверов.
- [CHANGELOG](../CHANGELOG.md) — история релизов.
- Этот файл — границы архитектуры, policy, health и диагностики.

## Назначение

Проект разворачивает контур:

```text
клиент -> RU Xray/Reality -> RU sing-box -> direct-ru
                                      \-> WireGuard -> foreign-exit
```

- Клиент всегда подключается к российскому серверу.
- Российские ресурсы выходят через RU IP.
- Остальной трафик выходит через foreign IP.
- Основной клиентский контракт — `out/<deployment>/client/vless-uri.txt`.
- Split routing — server-side policy. Клиентский URI не несёт критическую логику маршрутизации.

Роли:

- `ru-gateway` — публичный VLESS/Reality front, внутренний router и WireGuard peer.
- `foreign-exit` — WireGuard peer, NAT44/NAT66 и зарубежный egress.

## CLI

Публичные entrypoint: `vpn.cmd`, `vpn.ps1`, `vpn.sh`. Без аргументов открывается меню.

Основные команды:

- `install`, `reinstall`, `remove`, `purge`, `cleanup-local` — lifecycle.
- `status` — быстрый read-only snapshot без тяжёлых сетевых проб.
- `verify live` — свежая acceptance-проверка конфигов, DNS, route и throughput.
- `diagnose path` — подробный path/qdisc/WireGuard/MTR отчёт.
- `diagnose front` — анализ RU `443/tcp` и конкретного client source IP.
- `diagnose client-log` и `android-diagnose` — клиентские журналы.
- `client-check` — локальный self-tunnel check до IP серверов.
- `audit quick|docker|lab|interop|all` — регрессионные контуры.

Пример без вопросов:

```powershell
.\vpn.cmd reinstall --deployment 1 --role all --non-interactive --yes
.\vpn.cmd verify live --deployment 1 --non-interactive
```

Данные SSH можно передать через `VPN_RU_*` и `VPN_FOREIGN_*`. Пароли живут только в памяти процесса; `state/<deployment>.json` хранит адрес, порт, user, auth mode и путь к ключу.

## Источники истины

- `deployments/<name>.env` — declarative deployment input.
- `RoutingPolicy` в `vpn_installer/routing_policy.py` — единственное место, где RU трафик классифицируется и привязывается к outbound.
- `render.py` сериализует модели в sing-box, Xray, WireGuard, nftables и systemd artifacts. Он не должен принимать route-решения.
- `install.sh` делает server bootstrap, package installation и атомарную установку уже rendered artifacts. Route defaults в shell не дублируются.
- `/etc/vpn-stack/render-manifest.json` хранит version, policy version, env hash и hashes installed artifacts.
- `status` сравнивает local/rendered/installed state и показывает drift, а не маскирует его перезапуском.

Явные operator rules из web admin хранятся в `/etc/vpn-stack/admin-routing-rules.json`. Это единственный поддерживаемый runtime overlay; автоматические learned routes и route cache удалены.

## RU dataplane

### Публичный front

- Xray слушает public `443/tcp` и владеет VLESS/Reality contract.
- Xray передаёт accepted stream в local mixed inbound `sing-box`.
- RU `sing-box` не слушает public `443`; его router inbound привязан к `127.0.0.1`.
- Sniffing в Xray и sing-box восстанавливает HTTP/TLS/QUIC domain, когда протокол его действительно несёт. Raw IP без domain остаётся literal.

### Маршруты

Policy имеет два outbound:

- `direct-ru` — прямой RU egress.
- `to-foreign` — `bind_interface=wg0`, policy routing mark и foreign egress.

Порядок правил стабилен и покрыт unit-тестами:

1. Sniff и route options.
2. DNS hijack и optional QUIC policy.
3. Явные RU domain/suffix/geosite/CIDR -> `direct-ru`.
4. Явные block CIDR и private/fake destination -> `reject`.
5. Публичный raw IPv6 literal -> `to-foreign`.
6. Публичный raw IPv4 literal -> `to-foreign`.
7. Обычный domain -> `dns-global` с IPv4 answer.
8. Resolved RU geoip -> `direct-ru`; остальное -> final `to-foreign`.

Доменный трафик резолвится IPv4-only, чтобы избежать client-dependent Happy Eyeballs и недетерминированного IPv6 fallback. Это не блокирует raw IPv6 literals: они идут через foreign IPv6 path.

Отдельные literal-outbound и connect timeout удалены: они ссылались на тот же `wg0`, поэтому не давали fallback, а только обрывали медленные живые endpoints.

## DNS

- `dns-ru-direct` — системный resolver RU-хоста для direct classes. На Linux sing-box 1.13 использует API systemd-resolved и получает его список upstream и failover вместо привязки к одному UDP-адресу.
- `dns-global` — DoH через `to-foreign` для global classes.
- `cache_capacity=4096` включает единый LRU cache.
- `independent_cache` не используется: он дробит cache по серверам и deprecated в актуальном sing-box.
- NXDOMAIN означает отрицательный DNS-ответ, а не transport failure. Диагностика не смешивает его с `context deadline exceeded`.
- Публичных `RU_DIRECT_DNS_SERVER/PORT` нет: upstream direct DNS принадлежит сетевой конфигурации сервера и не дублируется в installer env.

Модель следует актуальным опциям [sing-box DNS](https://sing-box.sagernet.org/configuration/dns/), [Local DNS](https://sing-box.sagernet.org/configuration/dns/server/local/) и [DNS over HTTPS](https://sing-box.sagernet.org/configuration/dns/server/https/).

## Health и self-heal

Health не является route controller. Он не меняет sing-box policy, `qdisc`, NIC offload и nftables.

Быстрый timer-cycle проверяет:

- SSH banner;
- наличие route до peer;
- фактический HTTP egress через WireGuard;
- handshake age, но не считает старый handshake отказом, если path уже доказан свежей пробой;
- direct egress foreign role как диагноз без попытки "починить" провайдера рестартом firewall.

Deep-cycle по отдельному интервалу меряет download, upload и 10-packet ping loss. Из нескольких download sources берётся лучший доступный результат; медленный отдельный CDN не маскирует работоспособную полосу как общий отказ.

Классы:

- `soft/degraded` — speed, upload, packet loss и target availability. Только запись в state/log, без restart.
- `hard` — доказанная потеря WireGuard route/path. Действие допустимо только после двух последовательных одинаковых cycles.

Любой good или soft-cycle сбрасывает hard confirmation. Действия ограничены WireGuard restart или восстановление явно отсутствующих RU policy routes. Cooldown и hourly cap защищают от restart loop.

`PersistentKeepalive=25` поддерживает NAT mapping в соответствии с [WireGuard Quick Start](https://www.wireguard.com/quickstart/).

Параллельные SSH handshakes ограничиваются OpenSSH через `MaxStartups`, `PerSourceMaxStartups` и `MaxAuthTries`. Guard временно помещает в `abuse_ipv4` только источники повторяющихся authentication failures; сетевые `banner exchange` и timeouts не считаются атакой. Public IP RU и foreign являются защищенным topology-инвариантом: guard очищает их из set и никогда не блокирует повторно.

## Диагностика

### status

`status` показывает services, installed version/manifest, drift, interfaces, WireGuard, сохранённый health-state и классифицированные журналы. Он не качает тестовые файлы и не запускает временные sing-box instances.

Журналы делятся на взаимоисключающие buckets: DNS timeout, DNS NXDOMAIN, DNS other, domain timeout, IPv4 literal timeout, IPv6 literal timeout, private/fake block, client reset/EOF, invalid Reality, disabled/invalid noise.

### verify live

`verify live` всегда собирает fresh snapshot и проверяет:

- installed manifest и config hash;
- Xray front, sing-box router, WireGuard и foreign NAT;
- direct и foreign domain routes;
- DNS transport;
- raw IPv4 и IPv6 literals;
- private/fake reject;
- target routes и bounded throughput;
- новые ошибки только за окно этой проверки.

Вердикты: `verified`, `degraded`, `failed`, `inconclusive`. Green `status` не заменяет `verify live` после install/reinstall.

### diagnose path

Сохраняет отчёт в `out/diagnostics`: `ip -s link`, `tc -s qdisc`, sysctl, WireGuard, MTR/ping/curl и health journal. `--iperf` временно открывает порт только в `wg0` и удаляет правило после теста.

## Lifecycle и безопасность

- Install order: `foreign-exit`, затем `ru-gateway`.
- Remove order: `ru-gateway`, затем `foreign-exit`.
- `remove/purge` отказываются работать на unmanaged host.
- Reinstall удаляет legacy adaptive/cache state и пишет новый manifest.
- Journald ограничен managed drop-in: 256 MB и 14 дней по умолчанию; reinstall выполняет bounded vacuum.
- Admin rules применяются только после `sing-box check`, затем config заменяется атомарно.
- Public web admin по умолчанию доступен только active VPN clients; дефолтный пароль нужно сменить после первого входа.

## Артефакты

Локально:

- `deployments/<name>.env` и optional `.ru-direct-*.txt` overlays;
- `state/<name>.json`;
- `out/<name>/assets`, `bundle`, `cloud-init`, `preview`, `client`;
- `out/<name>/NEXT-STEPS.txt`.

Клиенты:

- `vless-uri.txt` — основной контракт;
- `windows-xray.json`, `android-v2rayng-xray.json` — Xray fallback;
- `hiddify-uri.txt`, `hiddify-*.json` — Hiddify fallback;
- `linux-sing-box.json` — Linux fallback;
- `windows-route-bypass.ps1` — operator helper для SSH self-tunnel, а не часть VPN policy.

Assets имеют несколько upstream URLs и валидный local cache. Неполный или невалидный asset не попадает в bundle.

## Карта кода

- `config.py`, `models.py`, `state.py` — declarative input и validation.
- `routing_policy.py`, `dns_policy.py` — domain models.
- `render.py`, `client_artifacts.py`, `manifest.py` — pure artifact generation.
- `targets.py`, `remote.py` — SSH target resolution и remote snapshot collection.
- `log_classifier.py`, `diagnostics.py`, `status_output.py` — structured diagnostics и presentation.
- `health.py`, `verify.py`, `diagnose.py` — verdict policies и read-only/live workflows.
- `workflows.py`, `install_support.py`, `roles.py` — lifecycle orchestration.
- `admin_web.py`, `admin_apply.py` — явные operator overrides.
- `audit/` — quick, Docker, lab и cross-platform regression.

Большие функции `render_health_script()` и `preflight_script()` остаются генераторами единых shell-артефактов. Их не следует дробить на модули только ради числа строк: граница ответственности здесь — один generated executable artifact и его tests.

## Проверки и релиз

Минимальный developer gate:

```powershell
python -m unittest discover -s tests -p "test_*.py"
.\vpn.cmd audit quick
.\vpn.cmd audit all
```

Production gate:

1. Reinstall обеих ролей только штатным CLI.
2. `verify live` с `verified` и без manifest drift.
3. Проверка свежих RU Xray/sing-box журналов после reinstall.
4. Наблюдение нескольких health cycles: нет новых sing-box restart и необоснованных self-heal actions.
5. Только после этого commit, SemVer tag и push.

Локальные тесты не доказывают first boot конкретного VPS, provider path и поведение каждого стороннего клиента. Эти границы в релизном отчёте нужно называть явно.
