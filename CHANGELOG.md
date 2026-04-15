# Changelog

Проект использует `SemVer`: `major.minor.patch`.

- `major` — несовместимые изменения в публичном поведении
- `minor` — новые возможности без обязательной ломки старого сценария
- `patch` — исправления багов и точечные доработки

## [0.2.1] - 2026-04-15

### Fixed

- `vpn.cmd` больше не прячет весь пользовательский вывод в файл и не даёт пустой экран
- Windows launcher теперь оставляет полезные логи даже в ранних сценариях запуска:
  - `latest-bootstrap.log`
  - `latest-transcript.log`
  - `latest-error.log`

### Added

- автоматический GitHub Release по push тега через GitHub Actions

## [0.2.0] - 2026-04-15

### Added

- отдельный Windows launcher `vpn.cmd` для обычного пользовательского запуска
- ранний PowerShell transcript и дополнительные runtime-логи:
  - `out/logs/runtime/latest-bootstrap.log`
  - `out/logs/runtime/latest-console.log`
  - `out/logs/runtime/latest-transcript.log`
  - `out/logs/runtime/latest-error.log`

### Changed

- на Windows основной рекомендуемый путь запуска переведён на `vpn.cmd`
- документация обновлена под новый Windows-сценарий и правила версионирования

## [0.1.1] - 2026-04-15

### Added

- файловый лог ошибок для launcher/menu/PowerShell path

### Changed

- сообщения об ошибках теперь показывают путь к сохранённому логу
