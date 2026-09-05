# Совместимость версий

## Текущее окно 0.22.3

`0.22.3` поддерживает fresh install, повторную установку той же версии и один последовательный переход с точного `0.22.2`.

| Формат | `0.22.2` | `0.22.3` |
| --- | --- | --- |
| config/state | `3` | `3` |
| manifest/install-plan | `5` | `5` |
| diagnostics | `6` | `6` |

Manifest `0.22.3` объявляет `installed_min=0.22.2`, `installed_max=0.22.3`. Переход не меняет schemas и не имеет adapter: старый bundle проходит тот же fail-closed validator topology/capabilities, package/service/artifact ownership, hashes, binaries и acceptance snapshot. Неиспользуемая расширенная metadata adapters удалена; разрешены только точные поля `from/to`. Неизвестные версии и приблизительно похожие manifests отклоняются до изменения managed runtime.

Runtime не содержит readers старых schemas или цепочки миграций. Host-owned SSH, APT и system resolver не входят в install plan, managed roots или transaction scope.

## Следующая граница

Каждый следующий несовместимый schema-шаг обязан иметь ровно один явно ограниченный переход с непосредственно предыдущего релиза. Совместимый релиз может сохранить текущие schemas и использовать общий validator без adapter.

## Неподдерживаемая версия

Для любой версии вне текущего окна используй `.\vpn.cmd` на Windows или `./vpn.sh` на Linux из совпадающего Git-тега, выполни доступную там команду `remove`/`purge`, затем сделай fresh install текущей версии. Новый установщик не угадывает ownership неизвестного поколения.

Основной `out/<deployment>/client/vless-uri.txt` этим переходом не меняется.
