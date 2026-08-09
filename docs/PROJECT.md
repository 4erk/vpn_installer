# Техническая карта проекта

## Контракт и границы

```text
клиент с vless-uri.txt ------> RU Xray/Reality TCP :443 --┐
Hysteria2 URI ---------------> RU Hysteria2 UDP :443 -----┴-> RU sing-box routing policy
                                                              -> direct-ru
                                                              -> stable kernel WireGuard overlay
                                                                 -> local relay -> Hysteria2 -> foreign egress
                                                                                -> WireGuard  -> foreign egress
```

- `out/<deployment>/client/vless-uri.txt` является главным и неизменным клиентским контрактом.
- Xray владеет основным публичным VLESS/Reality TCP front. RU `sing-box` владеет локальным router и дополнительным публичным Hysteria2/UDP ingress; оба входа завершаются одной routing policy.
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

Серверные runtime rules web-admin хранятся отдельно в `/etc/vpn-stack/admin-routing-rules.json`. Это единственный поддерживаемый routing overlay. Автоматических learned-routes, timeout promotion, offload mutation и log-based blocking нет; qdisc является декларативной частью единого managed network profile, а не реакцией на журнальные строки.

## Network adaptation

- Публичный Xray inbound задаёт только TCP keepalive `90s/15s`. Socket-local `TCP_USER_TIMEOUT` не форсируется: established-flow переживает краткую потерю подтверждений по штатной Linux TCP recovery policy вместо серверного обрыва через 30 секунд. Reality SNI остаётся частью клиентского контракта, а server-side target фиксируется policy-моделью и сериализуется каноническим ключом `target`; старые env overrides удаляются при нормализации. Agent отдельно показывает накопившиеся Xray `SYN-SENT` к target как soft degradation без restart. См. [Xray REALITY](https://xtls.github.io/en/config/transports/reality.html), [Xray Sockopt](https://xtls.github.io/en/config/transports/sockopt.html) и [Linux tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- Public Reality TCP и оба серверных WAN используют BBR с `fq limit=10000 flow_limit=512`; это pacing и достаточный per-flow queue budget, а не route policy. Стандартный `flow_limit=100` оказался меньше измеренного bandwidth-delay product межсерверной QUIC-сессии: в одном 30-секундном full-path run рост foreign `UdpSndbufErrors` и `fq drops` совпал (`+252`), а все накопленные qdisc drops были `flows_plimit`. Agent применяет профиль только при drift и проверяет результат через structured `tc -j -s`; [tc-fq](https://man7.org/linux/man-pages/man8/tc-fq.8.html) описывает `limit` и hard per-flow `flow_limit` отдельно.
- `net.ipv4.tcp_mtu_probing=1` является обязательным runtime-инвариантом. Нижний предел MSS закреплён на `536`, чтобы PLPMTUD не сохранял практически неработоспособные значения `48/256` после краткого path failure. `tcp_no_metrics_save=0` сохраняет выученные RTT/MSS для повторных коротких Reality-соединений; kernel default `tcp_no_ssthresh_metrics_save=1` не переносит устаревший slow-start threshold. Installer не очищает TCP metrics при обновлении. См. [Linux IP sysctl](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html), [ip tcp_metrics](https://man7.org/linux/man-pages/man8/ip-tcp_metrics.8.html) и [RFC 4821](https://datatracker.ietf.org/doc/html/rfc4821).
- WireGuard MTU не меняется по журналам или одиночному endpoint. Он остаётся частью deployment spec и меняется только сравнительным acceptance-тестом.
- Buffer/backlog sysctl не применяются без `softnet`, UDP buffer или interface delta evidence. Managed UDP profile использует симметричные `rmem_default=8 MiB`, `wmem_default=8 MiB` и ceiling `16 MiB`. Receive default устраняет подтверждённые `UdpRcvbufErrors`; send default нужен, потому что sing-box Hysteria2 фактически наследовал `212992` байта и под нагрузкой дал рост `UdpSndbufErrors` и потерю UDP DNS. Backlog не меняется без собственных drops. Это не публичные ручки для оперативного лечения. QUIC implementations рекомендуют многомегабайтные UDP buffers для высокоскоростных соединений: [quic-go optimizations](https://quic-go.net/docs/quic/optimizations/).
- Generic NIC `rx_dropped` выводится как unscoped informational delta, но сам по себе не меняет health verdict: virtio/kernel может учитывать там локально отброшенные кадры без queue overflow. Host-wide TCP retransmit/timeout counters также остаются только телеметрией, потому что включают SSH-сканирование, maintenance и сторонние сокеты. Для degradation требуется конкретный `rx_missed_errors`, softnet/UDP buffer drop, измеренная потеря Xray flow или failed route probe.
- CAKE/HTB не включаются по одному высокому RTT. CAKE управляет очередью только перед известным общим bottleneck и для egress требует обоснованного bandwidth; его `autorate-ingress` не оценивает участок сети ниже qdisc. При source-specific деградации глобальный shaper урежет исправных клиентов, не исправляя удалённую очередь. См. [tc-cake(8)](https://man7.org/linux/man-pages/man8/tc-cake.8.html).
- Foreign-трафик всегда идёт через один kernel WireGuard overlay с постоянными адресами и routing policy. Kernel peer смотрит на одну локальную relay-точку, поэтому смена внешнего transport не пересоздаёт интерфейс и не меняет сокеты приложений. Selector под relay доставляет зашифрованные overlay-пакеты через userspace WireGuard либо Hysteria2/QUIC; Hysteria2 не получает статических `up_mbps/down_mbps`, а его Salamander-ключ выводится из deployment secret ([sing-box Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/), [WireGuard roaming](https://www.wireguard.com/)).
- Agent каждые `2s` проверяет фактический kernel `wg0` overlay малым ICMP. При отказе альтернативный raw underlay обязан вернуть синтетический `localhost A` по UDP от управляемого foreign relay `10.75.0.2:1053` через свой локальный SOCKS endpoint с budget `1200ms`; запрос обслуживается foreign `systemd-resolved` без внешнего DNS, CDN, SSH или публичного health URL. Два свежих failure/health цикла разрешают переключение. Пока fallback исправен, предпочтительный userspace WireGuard проверяется раз в `10s` и возвращается после трёх подтверждений. RTT/throughput не переключают маршрут.
- Endpoint внутреннего `wg0` фиксирован на одном localhost relay. Под ним sing-box selector выбирает userspace WireGuard либо Hysteria2; `wg set` в runtime отсутствует. После смены selector локальный Clash API закрывает только association `direct/interserver-overlay-in`, потому что WireGuard endpoint fast-path sing-box не прерывает её автоматически. Новый путь обязан пройти единый `1280`-byte liveness/MTU probe с двусторонним ростом WG counters; неуспех возвращает прежний selector и доказывает rollback. Ни Xray, ни sing-box router, ни интерфейс `wg0`, ни клиентские TCP-потоки не перезапускаются.
- Внутренний overlay использует `PersistentKeepalive=1`. Внешний userspace WireGuard имеет отдельную детерминированную identity и отдельный peer на том же закрытом foreign listener; новых публичных портов нет. Failure-injection lab требует завершения одного `7.5 MiB` TCP-потока без повторного HTTP-запроса после потери прямого underlay и проверяет обратный переход после восстановления.
- Для client-to-RU доступны два транспорта на одном номере порта: канонический VLESS/Reality использует TCP, Hysteria2 использует UDP. Hiddify/sing-box JSON использует основной VLESS/Reality-контракт и явно выключает multiplex, чтобы независимые загрузки не делили один TCP congestion window; UDP/XUDP для DNS остаётся доступен. Дополнительный стандартный `hysteria2://` URI использует certificate SHA-256 pin для импорта в Hiddify/v2rayN. Client JSON не использует latency-based selector: ingress transport выбирает сам пользователь, а сервер не может безопасно повторить уже частично переданный payload ([Xray Mux](https://xtls.github.io/en/config/outbound.html#MuxObject), [Hysteria2 URI](https://v2.hysteria.network/docs/developers/URI-Scheme/)). Static bandwidth и connect timeout не задаются.
- Host resolver не зависит от одного провайдерского DNS: renderer создаёт единый `systemd-resolved` drop-in с тремя независимыми upstreams, локальным cache и часовым stale retention. Это сокращает повторные сетевые DNS-запросы и позволяет использовать известные positive records при кратком отказе upstream; NXDOMAIN не подменяется stale-ответом ([resolved.conf](https://www.freedesktop.org/software/systemd/man/resolved.conf.html)).
- Transport redundancy не является egress redundancy: оба пути заканчиваются на одном foreign VPS. Snapshot поэтому отдельно выводит `redundancy.transport` и `redundancy.egress`; второй независимый foreign сервер по-прежнему не выдумывается.
- Один статический VLESS URI не может сменить transport и поэтому остаётся совместимым TCP-контрактом. Mux не кодируется стандартным URI и должен оставаться выключенным в клиенте; JSON фиксирует это явно. Дополнительный Hysteria2 URI даёт отдельный QUIC-транспорт для сетей с потерями на TCP-пути. Это не per-request retry: произвольный частично переданный запрос нельзя безопасно воспроизвести на другом transport. RAW/Reality/Vision не заменяется на XHTTP вслепую: полевые отчёты показывают и обход ISP policing, и отдельные compatibility/latency regressions ([net4people/bbs #546](https://github.com/net4people/bbs/issues/546), [Xray-core #5332](https://github.com/XTLS/Xray-core/issues/5332)).

## Routing policy

Policy явно различает следующие классы:

| Класс | Назначение |
| --- | --- |
| `ru_direct_domain`, `ru_direct_ip` | `direct-ru` |
| `private_or_fake`, `blocked` | `reject` |
| `dns_global` | foreign TCP DNS relay через `to-foreign` |
| `domain_foreign` | `to-foreign`, DNS выполняет resolver класса до guard |
| `ipv4_literal_foreign`, `ipv6_literal_foreign` | `to-foreign` без искусственного connect timeout |

Для каждого доменного класса компилируется отдельная последовательность `resolve -> block/private guard -> terminal route`. Direct terminal завершается до foreign resolve, поэтому имя разрешается ровно один раз resolver своего класса. Полученные адреса передаются dialer напрямую. Настоящий IP literal фазу DNS пропускает: после block/private сначала проверяется `ru-geoip`, затем global catchall. DNS cache sing-box имеет ёмкость 4096, а DNS failures классифицируются отдельно от route timeout.

Foreign-классы всегда остаются на `to-foreign`. Health и recovery не имеют права переводить их в `direct-ru`: при отказе единственного foreign-egress состояние становится `failed` и трафик остаётся fail-closed. Автоматический route failover допустим только между независимыми foreign-egress.

## Server agent и диагностика

`vpn-stack-agent` - stdlib-only серверный executable. Он предоставляет operator-команды `snapshot`, `probe`, `health`, `front`, `client`, `routes` и `assets`; внутренние `transport-reconcile`/`transport-watch` управляют только endpoint стабильного overlay. Transport probe проверяет внутренний WG независимо от DNS, а холодный relay подтверждается ответом удалённого SSH, а не локальным SOCKS accept. Старую association agent закрывает только после proof нового пути; ошибка активации атомарно возвращает старый endpoint и открывает bounded circuit breaker. Нормализация log buckets вынесена в отдельный `log_classifier.py`, который поставляется и хешируется вместе с agent.

Snapshot schema 3 содержит:

- service state, manifest drift и hashes всех managed artifacts, включая resolver drop-in и состояние `/etc/resolv.conf` stub;
- root filesystem source/type, ext4 state и runtime error counters, время последней проверки и `fs_passno` загрузочного `fsck`;
- WireGuard, выбранный межсерверный transport и delay кандидатов, interface/conntrack, protocol, softnet и structured qdisc counters; health хранит дельты UDP receive/send overflow, `fq`/per-flow drops, softnet drops и missed packets;
- TCP front telemetry: active `ESTAB` и closing states разнесены до агрегации; RTT, retransmitted bytes/ratio, PMTU, MSS, cwnd, delivery rate, reordering и unacked считаются по каждому активному `source IP:port`, а `FIN-WAIT/LAST-ACK/CLOSING` формируют отдельный `closing_churn`; lifetime counters остаются исторической телеметрией, текущий verdict использует только flow с активностью не старше `30s` или монотонные counters того же socket ID в свежем интервале;
- fresh, 30-minute и 24-hour log windows;
- mutually exclusive buckets: DNS timeout, domain timeout, IPv4 literal timeout, IPv6 literal timeout, private/fake block, client reset/EOF, invalid Reality и disabled-invalid;
- problem-записи bounded-обогащаются inbound/DNS INFO-контекстом совпадающего sing-box event ID; парные сообщения одного request ID дедуплицируются, а IP timeout связывается с исходным доменом без полного INFO-сканирования;
- maintenance state и отдельные `server_path`, `public_front`, `public_quic`, `client_observation`, `closing_churn`, `host_integrity` verdicts.

`vpn status` собирает компактный snapshot за последние 5 минут без live probes и исторического сканирования. `vpn diagnose path` сохраняет полный structured JSON с окнами 5m/30m/24h. `vpn diagnose front` одновременно проверяет публичный listener и свежие RU/WG/router paths. `vpn diagnose client --source <public-ip>` показывает потоки и Xray destinations проблемного источника, не смешивая устройства за одним NAT.

## Health и восстановление

Health выполняется раз в две минуты и имеет состояния `healthy|degraded -> suspect -> failed -> recovering`.

- Soft degradation (новые UDP-buffer/softnet/missed drops, измеренная потеря Xray flow или socket churn) не вызывает restart.
- Hard failure требует двух свежих независимых failure cycles.
- Recovery имеет 15-minute cooldown, перезапускает только inactive/failed required service и обязательно делает post-check.
- `host_integrity=failed` является hard failure, но не запускает service recovery: ext4 metadata repair выполняется только offline fsck после резервной копии.
- Throughput tests не входят в периодический health. Они запускаются только явно через live verification или диагностику.

## Установка и обслуживание

Install/reinstall собирает release во временном каталоге внутри `/etc/vpn-stack/releases`, проверяет sing-box, Xray, nftables, WireGuard, systemd, manifest и assets, затем публикует immutable content-addressed tree и атомарно переключает `current`. Target-side acceptance дополнительно требует чистый ext4 root и включённую загрузочную проверку. Revision snapshot охватывает manifest, configs, rules/assets, resolver drop-in и `/etc/resolv.conf`, runtime health state, admin auth, `current`/`previous` и состояния всех затрагиваемых сервисов. Неудачные service start, drift или core route acceptance возвращают весь этот набор; уже опубликованный release не перезаписывается повторной установкой. Внешние capability probes выводятся отдельно: временный отказ raw IPv6 при исправном core path даёт `degraded` и проваливает полный live verify, но не откатывает тот же конфиг, который не может изменить состояние внешнего endpoint.

Хранятся последние 10 revision snapshots плюс отдельный baseline. Snapshot текущей транзакции никогда не удаляется её собственным rollback; pruning выполняется до создания нового snapshot.

`vpn maintain` по умолчанию только показывает APT/security/reboot state. С `--apply --yes` роли обновляются последовательно, после каждой выполняется fresh verification. `--refresh-assets` использует тот же транзакционный reinstall workflow; background asset mutation отсутствует.

Journald ограничивается managed drop-in. APT periodic settings включают unattended security updates, но плановая установка пакетов остаётся явной командой `maintain`.

## Live verification

`vpn verify live --deployment <name>` обязателен после install/reinstall. Он собирает agent acceptance snapshots на обеих ролях и запускает на внешнем runner два эфемерных sing-box client: первый строится напрямую из `vless-uri.txt` и проходит VLESS/Reality/Xray, второй независимо проходит публичный Hysteria2 ingress. Оба затем используют одну RU routing policy и выбранный межсерверный Hysteria2/WireGuard transport, проверяя egress identity, GitHub, Google, UDP DNS, TCP IPv6 literal, быстрый SOCKS reject private/fake destinations и девять first-load GET.

Дополнительно проверяются DNS, direct/domain routes, IPv4 literal, IPv6 literal и reject private/fake. Итог только один из `verified`, `degraded`, `failed`, `inconclusive`; зелёный `status` не является acceptance доказательством.

Server-side route acceptance использует HTTP `HEAD`: его задача доказать DNS, TCP, TLS, HTTP и выбранный route, не скачивая неограниченное тело сторонней страницы внутри короткого health/activation окна. Полные GET, передача данных и скорость проверяются отдельным public VLESS runner.

Для RU acceptance прямой egress подтверждается отдельной identity-проверкой. Foreign-домены обязаны пройти через `wg0` и local router, IPv4 literal через оба пути, а IPv6 literal через router и проверенный IPv6 egress foreign. Прямой запрос RU к заблокированному foreign-домену и raw `curl --interface wg0 -6` не являются пользовательским dataplane и записываются как наблюдения, но не вызывают ложный rollback.

`verify live` по умолчанию выполняет `30s` throughput acceptance канонического VLESS/TCP; `--throughput-seconds 60` задаёт более длинное ручное окно, а `0` оставляет только функциональные probes. Runner циклически использует Hetzner FSN, Hetzner NBG и независимый Cloudflare payload. Hard gate требует sustained goodput не ниже `10 Mbit/s`, минимум два успешных источника, полный requested interval, отсутствие transfer failures и пауз прогресса длиннее budget. Peak сравнивается с reference `50 Mbit/s` и сохраняется как telemetry, но CDN-зависимый sample не вызывает rollback. Публичный Hysteria2 проходит отдельный функциональный контракт без автоматической throughput-нагрузки. Один global lock сериализует runner-профили; target-side deadline и SSH controller lease завершают process group при исчезновении локального процесса. Проверка не входит в health timer.

Проверяющий runner сейчас запускается на foreign role, поэтому он проверяет полный публичный VLESS path и server capacity, но не измеряет маршрут конкретного пользователя до RU. Одновременный `client_specific/degraded` не маскируется успешным runner: это два разных component verdict.

## CLI

- `status`: read-only agent snapshot. Без live probes его `inconclusive` означает только отсутствие route acceptance; это явно выводится вместе с командой `verify live`.
- `verify live`: full server acceptance plus independent public VLESS/TCP and Hysteria2/QUIC contracts.
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
