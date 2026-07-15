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

## Server agent и диагностика

`vpn-stack-agent` - stdlib-only серверный executable. Он предоставляет команды `snapshot`, `probe`, `health`, `front`, `client`, `routes` и `assets`.

Snapshot schema 2 содержит:

- service state, manifest drift и hashes всех managed artifacts;
- WireGuard и interface/conntrack counters;
- TCP front telemetry: socket states, RTT, retransmits, unacked и source grouping;
- fresh, 30-minute и 24-hour log windows;
- mutually exclusive buckets: DNS, domain timeout, IPv4 literal timeout, IPv6 literal timeout, private/fake block, client reset/EOF, invalid Reality и disabled-invalid;
- парные DNS/router сообщения sing-box одного request ID дедуплицируются в одном DNS bucket;
- maintenance state и отдельные `server_path`, `public_front`, `client_observation` verdicts.

`vpn status` только собирает этот snapshot. `vpn diagnose path` сохраняет structured JSON. `vpn diagnose client --source <public-ip>` показывает evidence именно для проблемного источника, не смешивая его с другими клиентами.

## Health и восстановление

Health выполняется раз в две минуты и имеет состояния `healthy -> suspect -> failed -> recovering`.

- Soft degradation (packet loss, медленный источник или socket churn) не вызывает restart.
- Hard failure требует двух свежих независимых failure cycles.
- Recovery имеет 15-minute cooldown, перезапускает только inactive/failed required service и обязательно делает post-check.
- Throughput tests не входят в периодический health. Они запускаются только явно через live verification или диагностику.

## Установка и обслуживание

Install/reinstall собирает release в `/etc/vpn-stack/releases/<release-id>`, проверяет sing-box, Xray, nftables, WireGuard, systemd, manifest и assets до activation, затем атомарно переключает `current`. Неудачные service start или server-side acceptance возвращают прежние artifacts и service state.

`vpn maintain` по умолчанию только показывает APT/security/reboot state. С `--apply --yes` роли обновляются последовательно, после каждой выполняется fresh verification. `--refresh-assets` использует тот же транзакционный reinstall workflow; background asset mutation отсутствует.

Journald ограничивается managed drop-in. APT periodic settings включают unattended security updates, но плановая установка пакетов остаётся явной командой `maintain`.

## Live verification

`vpn verify live --deployment <name>` обязателен после install/reinstall. Он собирает agent acceptance snapshots на обеих ролях и запускает эфемерный sing-box client, построенный напрямую из `vless-uri.txt`. Этот client соединяется с RU `:443`, проходит VLESS/Reality/Xray/sing-box/WireGuard path и проверяет egress identity, GitHub и Google.

Дополнительно проверяются DNS, direct/domain routes, IPv4 literal, IPv6 literal и reject private/fake. Итог только один из `verified`, `degraded`, `failed`, `inconclusive`; зелёный `status` не является acceptance доказательством.

Для RU acceptance прямой egress подтверждается отдельной identity-проверкой. Foreign-домены обязаны пройти через `wg0` и local router, IPv4 literal через оба пути, а IPv6 literal через router и проверенный IPv6 egress foreign. Прямой запрос RU к заблокированному foreign-домену и raw `curl --interface wg0 -6` не являются пользовательским dataplane и записываются как наблюдения, но не вызывают ложный rollback.

`verify live --throughput-seconds 600` дополнительно держит public VLESS path десять минут на range-capable, rate-limited 12 Mbit/s download и требует не менее 10 Mbit/s. Эта нагрузка не входит в health timer.

Проверяющий runner сейчас запускается на foreign role, поэтому он проверяет полный публичный VLESS path, но не заменяет наблюдение с независимой внешней сети. Этот предел явно указывается в release verification.

## CLI

- `status`: read-only agent snapshot.
- `verify live`: full server acceptance plus public VLESS contract.
- `diagnose path|front|client`: structured incident evidence.
- `routes list|add|remove`: CLI к тому же backend, который использует web-admin.
- `maintain`: security-update/reboot reporting and controlled rollout.
- `audit quick`: быстрые compiler/contracts checks; `audit all`: единственный instrumented branch-coverage run с minimum 80% плюс Docker/lab failure injection. Критические policy, health recovery, manifest, public VLESS и transaction paths дополнительно закреплены behaviour tests.

## Проверки релиза

1. `unittest discover -s tests -p "test_*.py"`.
2. `vpn audit quick`, затем `vpn audit all`.
3. Reinstall foreign, затем RU только штатным workflow.
4. `vpn verify live --deployment <name> --non-interactive`.
5. Проверить 30-minute fresh logs, front retransmit telemetry, manifest drift, идентичности обоих egress и проблемные destinations.

Локальный audit не доказывает provider path, конкретную сеть клиента или IPv6 availability. Такие ограничения фиксируются как `degraded`/`inconclusive`, а не маскируются restart или timeout override.
