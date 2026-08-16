# Переходные интерфейсы 0.20.0

Новый runtime использует только `CONFIG_SCHEMA=2`, topology `single|dual`, узлы `gateway|exit`, manifest/install-plan schema 3 и diagnostics schema 4. Совместимость ниже существует только для одного штатного обновления и не участвует в принятии routing-решений.

## Удаляется в 0.20.1

| Переходный вход | Где разрешён в 0.20.0 | Условие удаления |
| --- | --- | --- |
| `RU_PUBLIC_IP`, `FOREIGN_PUBLIC_IP` | локальная миграция старого deployment env | все сохранённые deployments записаны с `CONFIG_SCHEMA=2` и canonical IP fields |
| state keys `ru-gateway`, `foreign-exit` и старый state env | однократное чтение local state | state JSON каждого deployment содержит `nodes.gateway|exit` |
| CLI `--role ru-gateway|foreign-exit` | parser `vpn` и `install.sh`, с предупреждением | документация, generated commands и automation используют `--node` |
| process env `VPN_RU_*`, `VPN_FOREIGN_*` | SSH connection adapter после canonical `VPN_GATEWAY_*`, `VPN_EXIT_*` | operator scripts используют node-based имена |
| `render-role`, `for_role()` и role-based Python wrappers | граница старых bundle/dev callers | audit и production вызывают только node APIs |
| top-level manifest field `role` | внешний schema-2 reader | установленные manifest имеют schema 3 и canonical `node_id`/`capabilities` |
| installed manifest schema 2 | `legacy_install_contract.py` с полной проверкой payload/live SHA256 | оба production node успешно переустановлены на schema 3 |
| diagnostics/runtime role fallback | чтение старого установленного agent state | свежий snapshot каждого node имеет schema 4 и canonical capability contract |
| metadata-файлы `role`, `installed_at` и import alias `select_role_for_menu` | bootstrap старого runtime и старые Python callers | каждый node содержит `node-id`/`installed-at`, а menu вызывает только `select_node_for_menu` |
| `ADMIN_WEB_BIND`, `ADMIN_WEB_ACTIVE_CLIENT_REQUIRED`, `ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS`, `ADMIN_WEB_ALLOW_TUNNEL_CLIENTS`, `ADMIN_WEB_ALLOWED_CIDR`, `ADMIN_WEB_ALLOW_WG` | однократное чтение старого deployment env; значения удаляются при нормализации | все deployments переустановлены с loopback-only admin и используют `vpn admin` SSH tunnel |

## Инварианты миграции

- Старые поля никогда не записываются в новый deployment env или `node.env`.
- Новый target-side renderer принимает только точный schema-2 `node.env`: compatibility normalization, defaults и генерация identity на сервере запрещены.
- Schema-2 install adapter не угадывает ownership: неизвестный artifact, путь, digest, service или изменённый live-файл останавливает установку до cutover.
- Известный schema-2 дефект foreign `sing-box` path исправляется только после проверки фактического `/etc/sing-box/config.json`.
- Schema-2 WireGuard/transport paths и services входят в transaction snapshot и могут быть удалены только после успешного schema-3 activation. Публичный workflow не меняет физическую topology существующего deployment.
- Имя deployment должно совпадать у установленного и нового contract; смена topology или node не разрешает затереть другую установку.
- После успешного обновления серверный runtime не читает legacy env и не содержит межсерверные artifacts в topology `single`.
- Legacy public-admin inputs никогда не открывают порт: renderer их игнорирует, web-процесс всегда слушает `127.0.0.1`, а новый env их не записывает.

## Release gate 0.20.1

Перед удалением адаптеров release audit обязан подтвердить:

1. `vpn status --node all` показывает manifest schema 3, diagnostics schema 4 и `drift: none` на всех существующих nodes.
2. Ни один canonical deployment/state/generated artifact не содержит старые IP fields или role keys.
3. Повторный reinstall и rollback проходят без вызова schema-2 adapter.
4. Отдельный fixture сохраняет отказ на неизвестной старой схеме, чтобы удаление compatibility-кода не превратилось в permissive fallback.
