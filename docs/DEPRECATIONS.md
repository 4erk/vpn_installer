# Граница совместимости 0.20.1

Релиз `0.20.1` записывает только текущие форматы:

- `CONFIG_SCHEMA=3` и state schema `3`;
- manifest schema `4`;
- install-plan schema `4`;
- diagnostics schema `5`;
- topology `single|dual` и узлы `gateway|exit`.

В manifest явно записывается окно установленных версий `installed_min=0.20.0` и `installed_max=0.20.1`. Чистая установка не имеет предыдущей версии и разрешена отдельно.

| Состояние сервера до запуска `0.20.1` | Допустимое действие |
| --- | --- |
| Управляемой установки нет | Fresh install |
| Установлен точный `0.20.0` | Переход `0.20.0 -> 0.20.1` |
| Установлен точный `0.20.1` | Same-version reinstall |
| Любая другая или нераспознаваемая версия | Отказ до изменения managed runtime |

Для неподдерживаемого релиза требуется установщик из совпадающего Git-тега. Запусти его `vpn.cmd` или `vpn.sh`, выполни поддерживаемую той версией операцию `remove`/`purge`, затем установи `0.20.1` с нуля. Текущий установщик не угадывает ownership, схемы или команды удаления чужого поколения.

## Единственный переходный модуль

Весь разбор форматов `0.20.0` сосредоточен только в `vpn_installer/upgrade_0200.py`. Общих цепочек миграций, permissive fallback и role-based runtime adapters в `0.20.1` нет.

| Функция | Точная переходная проверка |
| --- | --- |
| `upgrade_env()` | Принимает только строковый env с `CONFIG_SCHEMA=2`, canonical topology/node IP fields и согласованными `single|dual`/location. Отклоняет поля поколений до `0.20.0`, удаляет retired inputs и dual-only данные из `single`, переносит прежний common `WAN_INTERFACE` в ownership exit, затем выдаёт schema `3`. |
| `upgrade_state()` | Принимает только state schema `2` с canonical `nodes.gateway|exit`; состав nodes обязан совпадать с topology. Выдаёт state schema `3` без migration metadata. |
| `previous_node_plan()` | Восстанавливает только capability-plan, который мог скомпилировать `0.20.0`, чтобы проверить ownership прежнего bundle до транзакции. |
| `previous_role()` | Сопоставляет canonical node с обязательным историческим manifest field только во время проверки bundle `0.20.0`. |
| `upgrade_diagnostics_snapshot()` | Принимает только diagnostics schema `4`, у которого `release.version=0.20.0`; удаляет retired top-level metadata и адаптирует snapshot для upgrade preflight schema `5`. |
| `transition_metadata()` | Фиксирует единственный переход `from=0.20.0`, target config schema `3` и удаление boundary в `0.20.2`. |

## Переходные точки вызова

- `config.py` вызывает `upgrade_env()` только для schema `2`; schema `3` читается напрямую, любая иная схема отклоняется.
- `state.py` вызывает `upgrade_state()` только для state schema `2`; текущая schema `3` не проходит через adapter.
- `remote.py` вызывает `upgrade_diagnostics_snapshot()` только для read-only preflight/status snapshot точного релиза `0.20.0`; acceptance, health и maintenance остаются strict-native, а `0.20.1` обязан вернуть diagnostics schema `5`.
- `install_contract.py` сначала проверяет версию manifest по диапазону `0.20.0..0.20.1`. Точный `0.20.0` направляется в `validate_previous_0200_bundle()`, который требует config `2`, manifest/plan `3`, правильный node, прежний capability-plan, hashes, assets и binaries. Точный `0.20.1` проверяется только текущим validator с config `3`, manifest/plan `4`.
- `install_support.py` предоставляет внутренние target-side команды `validate-installed` и `validate-previous-0200`; публичный installer вызывает version dispatcher, а не выбирает старую схему по догадке.
- `render.py` включает `upgrade_0200.py` в self-contained server support bundle только для rollback и проверки установленного `0.20.0`.
- `tests/test_upgrade_0200.py` и compatibility fixtures закрепляют единственную разрешённую границу и обязательный отказ для более старых или более новых версий.

`vpn_installer/compatibility.py` является общим строгим version-range guard, а не вторым legacy adapter. В `0.20.2` он остаётся, но его минимальная версия и transition metadata меняются.

## Полное удаление в 0.20.2

В `0.20.2` удаляются целиком, одним изменением:

1. файл `vpn_installer/upgrade_0200.py`;
2. все его imports и schema-2/schema-3 compatibility branches в `config.py`, `state.py`, `remote.py` и `install_contract.py`;
3. внутренний command `validate-previous-0200` и previous-bundle dispatcher;
4. упаковка переходного модуля в server support bundle;
5. fixtures и tests, проверяющие чтение форматов `0.20.0`.

После удаления окно `0.20.2` становится `installed_min=0.20.1`, `installed_max=0.20.2`: разрешены fresh install, переход `0.20.1 -> 0.20.2` и same-version reinstall `0.20.2`. Установленный `0.20.0` должен удаляться установщиком из тега `0.20.0` перед чистой установкой.

Для `0.20.2` не планируется повышение схем: остаются config/state `3`, manifest/install-plan `4` и diagnostics `5`. Удаление compatibility boundary не должно менять topology, client URI, routing policy или runtime payload.
