# Техническая карта проекта

## Контракт и границы

```text
клиент с vless-uri.txt -> RU Xray/Reality :443 -> RU sing-box :2080
                                                   -> direct-ru
                                                   -> WireGuard -> foreign egress
```

- `out/<deployment>/client/vless-uri.txt` является главным и неизменным клиентским контрактом.
- Xray владеет публичным VLESS/Reality front. `sing-box` на RU является только локальным router.
- Routing policy, health и проверка не меняют локальные VPN-клиенты и их профили.
- Web-admin на RU сохраняется. Он управляет только явными operator rules; rules проходят validation и применяются атомарно.
- `VPN_SSH_BIND_ADDRESS` - временный control-plane input, не часть deployment env. Он привязывает SSH/SFTP к физическому локальному адресу, когда default route клиента находится в TUN, и не меняет client/server dataplane.

Роли:

- `ru-gateway`: public Xray front, локальный sing-box, peer WireGuard.
- `foreign-exit`: peer WireGuard, NAT и foreign egress.

## Источники истины

- `deployments/<name>.env` - декларативный input deployment.
- `DeploymentSpec`, `RoleSpec` и `RoutingPolicy` - единственная Python-модель конфигурации и traffic classes.
- renderer сериализует эту модель в sing-box, Xray, WireGuard, nftables, systemd и managed OS drop-ins. Он не принимает route decisions.
- `install.sh` только bootstrap и транзакционная доставка уже rendered artifacts; у него нет собственных routing defaults.
- `/etc/vpn-stack/render-manifest.json` schema 2 хранит release, policy, env/config hashes, binary digests, OS/kernel и hashes artifacts.

Серверные runtime rules web-admin хранятся отдельно в `/etc/vpn-stack/admin-routing-rules.json`. Это единственный поддерживаемый overlay. Автоматических learned-routes, timeout promotion, qdisc/offload mutation и log-based blocking нет.

## Network adaptation

- Public Reality TCP и оба серверных WAN используют BBR с `fq`; это pacing, а не route policy.
- `net.ipv4.tcp_mtu_probing=1` является обязательным runtime-инвариантом. Linux включает PLPMTUD для конкретного TCP-потока после признаков ICMP black hole и с системным `tcp_probe_interval` периодически пробует восстановить больший PMTU. См. [Linux IP sysctl](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html) и [RFC 4821](https://datatracker.ietf.org/doc/html/rfc4821).
- WireGuard MTU не меняется по журналам или одиночному endpoint. Он остаётся частью deployment spec и меняется только сравнительным acceptance-тестом.
- Buffer/backlog sysctl не применяются без `softnet`, UDP buffer или interface delta evidence. После подтверждённых `UdpRcvbufErrors` WireGuard использует единый managed receive profile: `rmem_default=4 MiB`, `rmem_max=16 MiB`; send buffer и backlog не меняются без собственных drops. Это не публичные ручки для оперативного лечения. Семантика UDP receive limits описана в [Linux IP sysctl](https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html).
- CAKE/HTB не включаются по одному высокому RTT. CAKE управляет очередью только перед известным общим bottleneck и для egress требует обоснованного bandwidth; его `autorate-ingress` не оценивает участок сети ниже qdisc. При source-specific деградации глобальный shaper урежет исправных клиентов, не исправляя удалённую очередь. См. [tc-cake(8)](https://man7.org/linux/man-pages/man8/tc-cake.8.html).
- URLTest активируется только при двух независимых foreign egress. Он выбирает выход для новых соединений и не прерывает существующие; при одном сервере snapshot честно сообщает `redundancy: unavailable`. См. [sing-box URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/).
- Один статический VLESS URI не может автоматически сменить публичный AS, TCP port или transport. Для отказоустойчивости client-to-RU path нужен второй независимый RU ingress либо новый клиентский transport contract. RAW/Reality/Vision не заменяется на XHTTP вслепую: полевые отчёты показывают и обход ISP policing, и отдельные compatibility/latency regressions ([net4people/bbs #546](https://github.com/net4people/bbs/issues/546), [Xray-core #5332](https://github.com/XTLS/Xray-core/issues/5332)).

## Routing policy

Policy явно различает следующие классы:

| Класс | Назначение |
| --- | --- |
| `ru_direct_domain`, `ru_direct_ip` | `direct-ru` |
| `private_or_fake`, `blocked` | `reject` |
| `dns_global` | DoH с detour через `to-foreign` |
| `domain_foreign` | `to-foreign` после global DNS |
| `ipv4_literal_foreign`, `ipv6_literal_foreign` | `to-foreign` без искусственного connect timeout |

Domain routing использует глобальный DNS и затем направляет DNS-resolved RU geoip обратно в `direct-ru`. Raw literals не подменяются доменными правилами. DNS cache sing-box имеет ёмкость 4096, а DNS failures классифицируются отдельно от route timeout.

Foreign-классы всегда остаются на `to-foreign`. Health и recovery не имеют права переводить их в `direct-ru`: при отказе единственного foreign-egress состояние становится `failed` и трафик остаётся fail-closed. Автоматический route failover допустим только между независимыми foreign-egress.

## Server agent и диагностика

`vpn-stack-agent` - stdlib-only серверный executable. Он предоставляет команды `snapshot`, `probe`, `health`, `front`, `client`, `routes` и `assets`. Нормализация log buckets вынесена в отдельный `log_classifier.py`, который поставляется и хешируется вместе с agent.

Snapshot schema 2 содержит:

- service state, manifest drift и hashes всех managed artifacts;
- WireGuard, interface/conntrack, protocol и softnet counters; health хранит дельты UDP receive overflow, softnet drops и missed packets;
- TCP front telemetry: socket states, RTT, retransmitted bytes/ratio, PMTU, MSS, cwnd, delivery rate, reordering и unacked по каждому `source IP:port` с последующей агрегацией по canonical IPv4/IPv6 адресу, включая kernel-формат `::ffff:<IPv4>`;
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

Install/reinstall собирает release во временном каталоге внутри `/etc/vpn-stack/releases`, проверяет sing-box, Xray, nftables, WireGuard, systemd, manifest и assets, затем публикует immutable content-addressed tree и атомарно переключает `current`. Revision snapshot охватывает manifest, configs, rules/assets, runtime health state, admin auth, `current`/`previous` и состояния всех затрагиваемых сервисов. Неудачные service start, drift или core route acceptance возвращают весь этот набор; уже опубликованный release не перезаписывается повторной установкой. Внешние capability probes выводятся отдельно: временный отказ raw IPv6 при исправном core path даёт `degraded` и проваливает полный live verify, но не откатывает тот же конфиг, который не может изменить состояние внешнего endpoint.

Хранятся последние 10 revision snapshots плюс отдельный baseline. Snapshot текущей транзакции никогда не удаляется её собственным rollback; pruning выполняется до создания нового snapshot.

`vpn maintain` по умолчанию только показывает APT/security/reboot state. С `--apply --yes` роли обновляются последовательно, после каждой выполняется fresh verification. `--refresh-assets` использует тот же транзакционный reinstall workflow; background asset mutation отсутствует.

Journald ограничивается managed drop-in. APT periodic settings включают unattended security updates, но плановая установка пакетов остаётся явной командой `maintain`.

## Live verification

`vpn verify live --deployment <name>` обязателен после install/reinstall. Он собирает agent acceptance snapshots на обеих ролях и запускает эфемерный sing-box client, построенный напрямую из `vless-uri.txt`. Этот client соединяется с RU `:443`, проходит VLESS/Reality/Xray/sing-box/WireGuard path и проверяет egress identity, GitHub, Google, UDP DNS, TCP IPv6 literal и быстрый SOCKS reject private/fake destinations.

Дополнительно проверяются DNS, direct/domain routes, IPv4 literal, IPv6 literal и reject private/fake. Итог только один из `verified`, `degraded`, `failed`, `inconclusive`; зелёный `status` не является acceptance доказательством.

Server-side route acceptance использует HTTP `HEAD`: его задача доказать DNS, TCP, TLS, HTTP и выбранный route, не скачивая неограниченное тело сторонней страницы внутри короткого health/activation окна. Полные GET, передача данных и скорость проверяются отдельным public VLESS runner.

Для RU acceptance прямой egress подтверждается отдельной identity-проверкой. Foreign-домены обязаны пройти через `wg0` и local router, IPv4 literal через оба пути, а IPv6 literal через router и проверенный IPv6 egress foreign. Прямой запрос RU к заблокированному foreign-домену и raw `curl --interface wg0 -6` не являются пользовательским dataplane и записываются как наблюдения, но не вызывают ложный rollback.

`verify live --throughput-seconds 600` дополнительно держит public VLESS path десять минут на range-capable download и требует не менее 50 Mbit/s. Runner считает реальные байты в фиксированном окне, повторяет завершённый range и не ограничивает сам измеряемую скорость; он запускается в отдельной remote process group, а SSH control-plane читает только короткие status snapshots и при deadline завершает всю runner group. Нагрузка запускается только явным флагом, использует доступную production-полосу и не входит в health timer.

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
