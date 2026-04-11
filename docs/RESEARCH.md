# Ресерч и ревью реализации

## Текущий практический план

- `RU gateway`: брать в РФ, чтобы клиент из России ходил только на российский IP.
- `foreign exit`: брать у отдельного зарубежного VPS-провайдера, чтобы внешний egress был не с российского адреса.
- Клиент: `Hiddify` на Windows, Linux и Android.
- Локальный запуск: единый `Python`-core, потому что без этого пришлось бы поддерживать отдельные реализации под `PowerShell` и `bash`.

## Где брать сервера

### RU

- [Timeweb Cloud](https://timeweb.cloud/services/cloud-servers/)
- Почему подходит:
  - на странице облачных серверов есть регионы `Москва`, `Санкт-Петербург`, `Новосибирск`, `Казахстан`, `Нидерланды`, `Германия`
  - есть публичный `IPv4`
  - есть `cloud-init`
  - есть явная документация по созданию сервера и подключению `SSH key`
- Что выбирать:
  - `Ubuntu 24.04 LTS`
  - публичный `IPv4`
  - вход по `SSH key`
  - если нужен максимально предсказуемый сценарий, не отключай публичный IPv4 на этапе заказа
- Документация:
  - [создание сервера](https://timeweb.cloud/docs/cloud-servers/manage-servers/create-server)
  - [cloud-init](https://timeweb.cloud/docs/cloud-servers/manage-servers/cloud-init)

### Foreign

- Основной вариант: [THE.Hosting VPS configurator](https://the.hosting/en/vps-configurator)
- Почему подходит:
  - на конфигураторе и партнёрской странице видны многочисленные зарубежные локации, включая `Netherlands`, `Germany`, `Finland`, `United Kingdom`, `USA`
  - есть отдельная официальная партнёрская программа
- Что выбирать:
  - `Ubuntu 24.04 LTS`
  - публичный `IPv4`
  - вход по `SSH key`
  - стартовая локация: `Netherlands` или `Germany`

### Альтернатива

- [Hetzner Cloud](https://docs.hetzner.com/cloud/servers/getting-started/creating-a-server/)
- Смысл:
  - сильная документация
  - аккуратный cloud workflow
- Ограничение:
  - в этом проходе я не закладывал его как основной foreign-вариант, потому что для текущего сценария важнее был быстрый старт с понятной affiliate/partner частью и максимально простым подбором дешёвых VPS

## Что по реферальным программам

- Timeweb:
  - реферальная программа есть: [Timeweb partner page](https://timeweb.com/ru/partners/webmasters/)
  - на странице программы указано, что для платформы `ТАЙМВЭБ.КЛАУД` вознаграждение составляет `20%` по всем сервисам, кроме доменов и `ispmanager`
  - отдельная справка по реферальной ссылке: [программа вебмастер](https://timeweb.com/ru/docs/partnerskie-programmy/programma-webmaster/)
- THE.Hosting:
  - реферальная программа есть: [THE.Hosting Affiliate Program](https://the.hosting/en/partners)
  - на официальной странице указано `Up to 20% of each payment`
  - также там расписана сетка уровней от `3%` до `20%`
- Hetzner:
  - как рабочий primary-провайдер для этого репозитория не выбран
  - отдельную официальную реферальную схему я в этом проходе не закладывал в рекомендации, чтобы не смешивать быстрый operational path и дополнительный ресерч

## Где брать клиенты

- Официальная страница установки: [How to install HiddifyApp](https://hiddify.com/app/How-to-install-Hiddify-app/)
- Официальные релизы: [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)
- Android: [Google Play](https://play.google.com/store/apps/details?id=app.hiddify.com)

Практический сценарий:

- Windows: GitHub Releases
- Linux: GitHub Releases или инструкция с AppImage на официальной странице
- Android: Google Play, а GitHub держать как fallback на случай проблем с магазином

## Что уже автоматизировано

- запуск с Windows без `WSL`
- тихая локальная установка portable Python на Windows
- интерактивный bootstrap
- сохранение локального `deployment env`, `state` и всех артефактов
- preflight обоих серверов
- установка через `root` или пользователя с `sudo`
- переустановка ролей
- `status`, `remove`, `purge`
- локальная очистка артефактов командой `cleanup-local`
- удаление временных bundle-папок с серверов после remote action

## Что было исправлено в этой итерации

- Исправлен баг с remote workdir:
  - раньше использовался путь вида `~/vpn-installer/...` внутри `shlex.quote`, из-за чего `~` не разворачивался как `$HOME`
  - теперь используется нормальная временная директория в домашнем каталоге без этой ошибки
- Доделан lifecycle в `install.sh`:
  - `install`
  - `reinstall`
  - `status`
  - `remove`
  - `purge`
- Добавлен baseline backup серверных файлов перед управлением стеком.
- Добавлены revision snapshots перед повторной установкой.
- README сокращён до практической инструкции.

## Текущие ограничения

- Полностью точное восстановление исходного состояния сервера гарантируется только для установок, сделанных уже новой версией инсталлятора с baseline backup.
- `purge` чистит серверное состояние стека, но не пытается автоматически удалять системные пакеты вроде `wireguard` или `nftables`, потому что это слишком рискованно для уже используемого VPS.
- Автоматический `SSH password login` со стороны локального bootstrap по-прежнему не реализован.
- Автоматическое создание отдельного deploy-user на сервере пока не доведено до готового сценария.
- Реальный end-to-end прогон на боевых VPS в этом окружении не выполнялся.

## Что делать дальше

1. Поднять тестовый RU и foreign VPS и прогнать `bootstrap`.
2. Проверить `status`, затем `reinstall`, затем `remove` и `purge` на живых серверах.
3. Проверить клиентские профили на Windows, Linux и Android.
4. После первого живого прогона решить, нужен ли отдельный шаг автоматического создания deploy-user.
