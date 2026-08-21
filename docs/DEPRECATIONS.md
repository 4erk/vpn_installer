# Совместимость версий

## Текущее окно

Релиз `0.21.3` записывает только текущие форматы:

- config/state schema `3`;
- manifest/install-plan schema `4`;
- diagnostics schema `5`;
- topology `single|dual` и узлы `gateway|exit`.

Manifest каждого узла объявляет `installed_min=0.21.2` и `installed_max=0.21.3`.

| Состояние сервера | Допустимое действие |
| --- | --- |
| Управляемой установки нет | Fresh install |
| Установлен точный `0.21.2` | Обновление на `0.21.3` тем же current-schema validator |
| Установлен точный `0.21.3` | Same-version reinstall |
| Любая другая или нераспознаваемая версия | Отказ до изменения managed runtime |

Для неподдерживаемого релиза используй `.\vpn.cmd` на Windows или `./vpn.sh` на Linux из совпадающего Git-тега. Выполни доступную в той версии команду `remove`/`purge`, затем установи текущий релиз с нуля. Новый установщик не угадывает ownership или формат чужого поколения.

## Инварианты

- Проверка установленной версии выполняется до package install, upload, transaction snapshot и переключения `current`.
- `0.21.2` и `0.21.3` проходят один validator config/state `3`, manifest/install-plan `4` и diagnostics `5`; version-specific schema adapters отсутствуют.
- Current bundle обязан публиковать точное текущее окно. Предыдущий совместимый bundle обязан иметь корректное собственное окно, включающее его версию.
- Любой неизвестный schema, retired `role` field, неканонический node env, изменённый artifact или несовпадающий hash завершает проверку ошибкой.
- Rollback проверяет восстановленный релиз тем же installed-bundle validator и повторяет native acceptance; отдельного compatibility runtime нет.

## Следующие релизы

Каждый релиз явно задаёт минимальную и максимальную обновляемую версию. Если следующий релиз сохраняет схемы, достаточно передвинуть окно и проверить previous/current одним validator. Если схема действительно меняется, переход должен быть отдельным ограниченным модулем с указанной версией удаления; цепочки миграций и permissive fallback запрещены.

Одношаговая граница `0.21.2 -> 0.21.3` знает только три точных различия: прежний штатный `SING_BOX_LOG_LEVEL=info` нормализуется в `warn`, validator учитывает отсутствие новых resource-control artifacts и пакета `logrotate` в старом install plan, а после успешной acceptance удаляется больше не используемый project-owned каталог `backups/snapshots`. Пользовательское значение не угадывается и не переписывается. Эти записи удаляются в `0.21.4` вместе с поддержкой обновления с `0.21.2`. Других deprecated env-ключей, role aliases, readers старых схем и migration chains в `0.21.3` нет.
