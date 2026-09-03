# Совместимость версий

## Переходный релиз 0.22.0

`0.22.0` поддерживает fresh install, повторную установку той же версии и один последовательный переход с точного `0.21.8`.

| Формат | `0.21.8` | `0.22.0` |
| --- | --- | --- |
| config/state | `3` | `3` |
| manifest/install-plan | `4` | `5` |
| diagnostics | `5` | `6` |

Manifest `0.22.0` объявляет `installed_min=0.21.8`, `installed_max=0.22.0`. Старый bundle проверяет отдельный fail-closed adapter `transition_0218`: точную версию, schemas, topology/capabilities, package/service/artifact ownership, hashes, binaries и acceptance snapshot. Неизвестные версии и приблизительно похожие manifests отклоняются до изменения managed runtime.

Переход удаляет из установленного состояния прежние SSH, APT и `systemd-resolved` drop-ins. Старые SSH env-поля принимаются только как одноразовый input `0.21.8` и не попадают в новый `node.env`. Adapter и этот input cleanup имеют `remove_in=0.22.1`.

## Следующий релиз 0.22.1

`0.22.1` должен обновляться только с `0.22.0` и записывать те же текущие schemas `3/5/6`. В нём удаляются:

- `transition_0218` и чтение diagnostics schema `5`;
- retired renderer `system_resolver`;
- обработка deprecated SSH env-полей;
- разрешения installer на старые `/etc/ssh`, `/etc/apt` и `/etc/systemd/resolved` artifacts;
- Docker fixtures и тесты перехода `0.21.8`.

После этого runtime не содержит цепочки миграций. Каждый следующий несовместимый шаг снова обязан иметь ровно один явно ограниченный переход с непосредственно предыдущего релиза.

## Неподдерживаемая версия

Для любой версии вне текущего окна используй `.\vpn.cmd` на Windows или `./vpn.sh` на Linux из совпадающего Git-тега, выполни доступную там команду `remove`/`purge`, затем сделай fresh install текущей версии. Новый установщик не угадывает ownership неизвестного поколения.

Основной `out/<deployment>/client/vless-uri.txt` этим переходом не меняется.
