# Техническая карта проекта

## Контракт и границы

```text
клиент с vless-uri.txt -> RU Xray/Reality :443 -> RU sing-box :2080
                                                   -> direct-ru
                                                   -> Hysteria2/QUIC -> foreign sing-box -> foreign egress
                                                   -> WireGuard fallback -> foreign egress
```

- `out/<deployment>/client/vless-uri.txt` является главным и неизменным клиентским контрактом.
- Xray владеет публичным VLESS/Reality front. `sing-box` на RU является только локальным router.
- Routing policy, health и проверка не меняют локальные VPN-клиенты и их профили.
- Web-admin на RU сохраняется. Он управляет только явными operator rules; rules проходят validation и применяются атомарно.
- `VPN_SSH_BIND_ADDRESS` - временный control-plane input, не часть deployment env. Он привязывает SSH/SFTP к физическому локальному адресу, когда default route клиента находится в TUN, и не меняет client/server dataplane.

Роли:

- `ru-gateway`: public Xray front, локальный sing-box, peer WireGuard.
- `foreign-exit`: Hysteria2 endpoint, peer WireGuard, NAT и foreign egress.

## Источники истины

- `deployments/<name>.env` - декларативный input deployment.
- `DeploymentSpec`, `RoleSpec` и `RoutingPolicy` - единственная Python-модель конфигурации и traffic classes.
- renderer сериализует эту модель в sing-box, Xray, WireGuard, nftables, systemd и managed OS drop-ins. Он не принимает route decisions.
- `install.sh` только bootstrap и транзакционная доставка уже rendered artifacts; у него нет собственных routing defaults.
- `/etc/vpn-stack/render-manifest.json` schema 2 хранит release, policy, env/config hashes, binary digests, OS/kernel и hashes artifacts.

Серверные runtime rules web-admin хранятся отдельно в `/etc/vpn-stack/admin-routing-rules.json`. Это единственный поддерживаемый overlay. Автоматических learned-routes, timeout promotion, qdisc/offload mutation и log-based blocking нет.

## Network adaptation

- Public Reality TCP и оба серверных WAN используют BBR с `fq`; это pacing, а не route policy.
- `net.ipv4.tcp_mtu_probing=1` является обязательным runtime-инвариантом. Нижний предел MSS закреплён на `536`, чтобы PLPMTUD не сохранял практически неработоспособные значения `48/256` после краткого path failure. На публичном туннельном фронте `tcp_no_metrics_save=1`: новый reconnect заново измеряет путь и не наследует повреждённые RTT/cwnd/reordering из destination cache. См. [Linux IP sysctl](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html), [ip tcp_metrics](https://man7.org/linux/man-pages/man8/ip-tcp_metrics.8.html) и [RFC 4821](https://datatracker.ietf.org/doc/html/rfc4821).
- WireGuard MTU не меняется по журналам или одиночному endpoint. Он остаётся частью deployment spec и меняется только сравнительным acceptance-тестом.
- Buffer/backlog sysctl не применяются без `softnet`, UDP buffer или interface delta evidence. После трёх воспроизводимых burst-окон `UdpRcvbufErrors` RU transport использует единый managed profile: `rmem_default=8 MiB`, `rmem_max=16 MiB`, `wmem_max=16 MiB`; backlog не меняется без собственных drops. Это не публичные ручки для оперативного лечения. QUIC implementations рекомендуют UDP buffers около 7.5 MiB для высокоскоростных соединений: [quic-go UDP buffer sizes](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes).
- CAKE/HTB не включаются по одному высокому RTT. CAKE управляет очередью только перед известным общим bottleneck и для egress требует обоснованного bandwidth; его `autorate-ingress` не оценивает участок сети ниже qdisc. При source-specific деградации глобальный shaper урежет исправных клиентов, не исправляя удалённую очередь. См. [tc-cake(8)](https://man7.org/linux/man-pages/man8/tc-cake.8.html).
- Между теми же RU/foreign узлами работают два transport: основной Hysteria2/QUIC и резервный WireGuard. Hysteria2 не получает статических `up_mbps/down_mbps`, поэтому использует BBR congestion control ([sing-box Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)). Один sing-box selector закреплён за Hysteria2; отдельный supervisor проверяет raw outbounds с жёстко ограниченным временем, переводит только новые соединения на исправный WireGuard после двух последовательных отказов primary и возвращается после двух успешных primary probes. Одиночный неуспешный probe оставляет выбранный transport без изменений. QUIC восстанавливает потерянные пакеты внутри transport; уже созданный TCP stream намеренно не мигрирует между transport.
- Host resolver не зависит от одного провайдерского DNS: renderer создаёт единый `systemd-resolved` drop-in с тремя независимыми upstreams, локальным cache и часовым stale retention. Это сокращает повторные сетевые DNS-запросы и позволяет использовать известные positive records при кратком отказе upstream; NXDOMAIN не подменяется stale-ответом ([resolved.conf](https://www.freedesktop.org/software/systemd/man/resolved.conf.html)).
- Transport redundancy не является egress redundancy: оба пути заканчиваются на одном foreign VPS. Snapshot поэтому отдельно выводит `redundancy.transport` и `redundancy.egress`; второй независимый foreign сервер по-прежнему не выдумывается.
- Один статический VLESS URI не может автоматически сменить публичный AS, TCP port или transport. Для отказоустойчивости client-to-RU path нужен второй независимый RU ingress либо новый клиентский transport contract. RAW/Reality/Vision не заменяется на XHTTP вслепую: полевые отчёты показывают и обход ISP policing, и отдельные compatibility/latency regressions ([net4people/bbs #546](https://github.com/net4people/bbs/issues/546), [Xray-core #5332](https://github.com/XTLS/Xray-core/issues/5332)).

## Routing policy

Policy явно различает следующие классы:

| Класс | Назначение |
| --- | --- |
| `ru_direct_domain`, `ru_direct_ip` | `direct-ru` |
| `private_or_fake`, `blocked` | `reject` |
| `dns_global` | DoH с detour через `to-foreign` |
| `domain_foreign` | `to-foreign`, DNS выполняет resolver класса до guard |
| `ipv4_literal_foreign`, `ipv6_literal_foreign` | `to-foreign` без искусственного connect timeout |

Для каждого доменного класса компилируется отдельная последовательность `resolve -> block/private guard -> terminal route`. Direct terminal завершается до foreign resolve, поэтому имя разрешается ровно один раз resolver своего класса. Полученные адреса передаются dialer напрямую. Настоящий IP literal фазу DNS пропускает: после block/private сначала проверяется `ru-geoip`, затем global catchall. DNS cache sing-box имеет ёмкость 4096, а DNS failures классифицируются отдельно от route timeout.

Foreign-классы всегда остаются на `to-foreign`. Health и recovery не имеют права переводить их в `direct-ru`: при отказе единственного foreign-egress состояние становится `failed` и трафик остаётся fail-closed. Автоматический route failover допустим только между независимыми foreign-egress.

## Server agent и диагностика

`vpn-stack-agent` - stdlib-only серверный executable. Он предоставляет команды `snapshot`, `probe`, `health`, `front`, `client`, `routes` и `assets`. Нормализация log buckets вынесена в отдельный `log_classifier.py`, который поставляется и хешируется вместе с agent.

Snapshot schema 2 содержит:

- service state, manifest drift и hashes всех managed artifacts, включая resolver drop-in и состояние `/etc/resolv.conf` stub;
- WireGuard, выбранный межсерверный transport и delay кандидатов, interface/conntrack, protocol и softnet counters; health хранит дельты UDP receive/send overflow, softnet drops и missed packets;
- TCP front telemetry: socket states, RTT, retransmitted bytes/ratio, PMTU, MSS, cwnd, delivery rate, reordering и unacked по каждому `source IP:port` с последующей агрегацией по canonical IPv4/IPv6 адресу, включая kernel-формат `::ffff:<IPv4>`; lifetime loss остаётся наблюдением, а текущая деградация требует совместных признаков retransmit, RTT и RTO одного активного flow;
- fresh, 30-minute и 24-hour log windows;
- mutually exclusive buckets: DNS timeout, domain timeout, IPv4 literal timeout, IPv6 literal timeout, private/fake block, client reset/EOF, invalid Reality и disabled-invalid;
- парные DNS/router сообщения sing-box одного request ID дедуплицируются в одном DNS bucket;
- maintenance state и отдельные `server_path`, `public_front`, `client_observation` verdicts.

`vpn status` собирает компактный snapshot за последние 5 минут без live probes и исторического сканирования. `vpn diagnose path` сохраняет полный structured JSON с окнами 5m/30m/24h. `vpn diagnose front` одновременно проверяет публичный listener и свежие RU/WG/router paths. `vpn diagnose client --source <public-ip>` показывает потоки и Xray destinations проблемного источника, не смешивая устройства за одним NAT.

## Health и восстановление

Health выполняется раз в две минуты и имеет состояния `healthy|degraded -> suspect -> failed -> recovering`.

- Soft degradation (новые UDP/softnet/interface drops, медленный источник или socket churn) не вызывает restart.
- Hard failure требует двух свежих независимых failure cycles.
- Recovery имеет 15-minute cooldown, перезапускает только inactive/failed required service и обязательно делает post-check.
- Throughput tests не входят в периодический health. Они запускаются только явно через live verification или диагностику.

## Установка и обслуживание

Install/reinstall собирает release во временном каталоге внутри `/etc/vpn-stack/releases`, проверяет sing-box, Xray, nftables, WireGuard, systemd, manifest и assets, затем публикует immutable content-addressed tree и атомарно переключает `current`. Revision snapshot охватывает manifest, configs, rules/assets, resolver drop-in и `/etc/resolv.conf`, runtime health state, admin auth, `current`/`previous` и состояния всех затрагиваемых сервисов. Неудачные service start, drift или core route acceptance возвращают весь этот набор; уже опубликованный release не перезаписывается повторной установкой. Внешние capability probes выводятся отдельно: временный отказ raw IPv6 при исправном core path даёт `degraded` и проваливает полный live verify, но не откатывает тот же конфиг, который не может изменить состояние внешнего endpoint.

Хранятся последние 10 revision snapshots плюс отдельный baseline. Snapshot текущей транзакции никогда не удаляется её собственным rollback; pruning выполняется до создания нового snapshot.

`vpn maintain` по умолчанию только показывает APT/security/reboot state. С `--apply --yes` роли обновляются последовательно, после каждой выполняется fresh verification. `--refresh-assets` использует тот же транзакционный reinstall workflow; background asset mutation отсутствует.

Journald ограничивается managed drop-in. APT periodic settings включают unattended security updates, но плановая установка пакетов остаётся явной командой `maintain`.

## Live verification

`vpn verify live --deployment <name>` обязателен после install/reinstall. Он собирает agent acceptance snapshots на обеих ролях и запускает эфемерный sing-box client, построенный напрямую из `vless-uri.txt`. Этот client соединяется с RU `:443`, проходит VLESS/Reality/Xray/sing-box и выбранный Hysteria2/WireGuard transport, затем проверяет egress identity, GitHub, Google, UDP DNS, TCP IPv6 literal, быстрый SOCKS reject private/fake destinations и девять отдельных first-load GET через RU/foreign routes.

Дополнительно проверяются DNS, direct/domain routes, IPv4 literal, IPv6 literal и reject private/fake. Итог только один из `verified`, `degraded`, `failed`, `inconclusive`; зелёный `status` не является acceptance доказательством.

Server-side route acceptance использует HTTP `HEAD`: его задача доказать DNS, TCP, TLS, HTTP и выбранный route, не скачивая неограниченное тело сторонней страницы внутри короткого health/activation окна. Полные GET, передача данных и скорость проверяются отдельным public VLESS runner.

Для RU acceptance прямой egress подтверждается отдельной identity-проверкой. Foreign-домены обязаны пройти через `wg0` и local router, IPv4 literal через оба пути, а IPv6 literal через router и проверенный IPv6 egress foreign. Прямой запрос RU к заблокированному foreign-домену и raw `curl --interface wg0 -6` не являются пользовательским dataplane и записываются как наблюдения, но не вызывают ложный rollback.

`verify live --throughput-seconds 60` дополнительно проверяет public VLESS path на нескольких HTTPS download endpoints: 30-секундный uncapped burst должен подтвердить capacity не менее 50 Mbit/s, затем одно непрерывное bounded-соединение держит до 16 Mbit/s и требует не менее 10 Mbit/s без обрывов. Один global lock защищает SOCKS port от конкурирующих запусков; target-side deadline и обновляемая SSH controller lease завершают remote process group при аварийном исчезновении локального процесса. Проверка не входит в health timer и не должна длительно насыщать production path.

Проверяющий runner сейчас запускается на foreign role, поэтому он проверяет полный публичный VLESS path и server capacity, но не измеряет маршрут конкретного пользователя до RU. Одновременный `client_specific/degraded` не маскируется успешным runner: это два разных component verdict.

## CLI

- `status`: read-only agent snapshot. Без live probes его `inconclusive` означает только отсутствие route acceptance; это явно выводится вместе с командой `verify live`.
- `verify live`: full server acceptance plus public VLESS contract.
- `diagnose path|front|client`: structured incident evidence.
- `routes list|add|remove`: CLI к тому же backend, который использует web-admin.
- `maintain`: security-update/reboot reporting and controlled rollout.
- `audit quick`: быстрые compiler/contracts checks; `audit all`: единственный instrumented branch-coverage run с minimum 80% плюс Docker/lab failure injection. Критические policy, health recovery, manifest, public VLESS и transaction paths дополнительно закреплены behaviour tests.

## Проверки релиза

1. `python tests/run_tests.py` (на Windows с bundled runtime: `& .\.runtime\python\windows\python.exe tests\run_tests.py`). Runner сам добавляет repo root до discovery, поэтому portable embedded Python не зависит от `PYTHONPATH`.
2. `vpn audit quick`, затем `vpn audit all`.
3. Reinstall foreign, затем RU только штатным workflow.
4. `vpn verify live --deployment <name> --non-interactive`. Acceptance подтверждает первую ошибку обязательного route-инварианта повторным циклом; Telegram и другие проблемные направления выводятся отдельно как observations.
5. Проверить 30-minute fresh logs, front retransmit telemetry, manifest drift, идентичности обоих egress и проблемные destinations.

Локальный audit не доказывает provider path, конкретную сеть клиента или IPv6 availability. Такие ограничения фиксируются как `degraded`/`inconclusive`, а не маскируются restart или timeout override.
