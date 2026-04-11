# Переносимый установщик приватного VPN-контура

Схема: `клиент -> RU gateway -> foreign exit`. Клиент из РФ подключается только к RU-серверу на `443/tcp`, а нероссийский трафик уходит дальше через foreign-узел.

## 1. Закажи 2 VPS

- RU-сервер: `Ubuntu 24.04`, публичный `IPv4`, вход по `SSH key`.
  - Основной вариант: [Timeweb Cloud](https://timeweb.cloud/services/cloud-servers/)
  - Если нужна реферальная ссылка: у Timeweb есть партнёрская программа, и для платформы `ТАЙМВЭБ.КЛАУД` на странице программы указано вознаграждение `20%` по сервисам Cloud. Бери свою ссылку из кабинета вебмастера, не используй чужую вслепую: [партнёрская программа](https://timeweb.com/ru/partners/webmasters/), [документация по реферальной ссылке](https://timeweb.com/ru/docs/partnerskie-programmy/programma-webmaster/)
- Foreign-сервер: `Ubuntu 24.04`, публичный `IPv4`, вход по `SSH key`.
  - Основной вариант: [THE.Hosting VPS configurator](https://the.hosting/en/vps-configurator)
  - Если нужна реферальная ссылка: у THE.Hosting есть официальная партнёрская страница, условия смотри там: [THE.Hosting partners](https://the.hosting/en/partners)
- Если нужен самый быстрый старт без зоопарка провайдеров, можно взять оба сервера у одного провайдера, а потом уже вынести foreign отдельно.

Что выбрать при заказе:

- ОС: `Ubuntu 24.04 LTS`
- Доступ: `SSH key`
- Сеть: обязательно публичный `IPv4`
- Для foreign лучше сразу выбирать ближайшую к тебе нормальную внешнюю локацию `NL/DE/FI/PL/UK`

## 2. Скачай клиент

- Windows: [Hiddify install page](https://hiddify.com/app/How-to-install-Hiddify-app/), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)
- Linux: [Hiddify install page](https://hiddify.com/app/How-to-install-Hiddify-app/), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)
- Android: [Google Play](https://play.google.com/store/apps/details?id=app.hiddify.com), [GitHub Releases](https://github.com/hiddify/hiddify-app/releases/latest)

Основной клиент здесь один: `Hiddify`. Этого достаточно для Windows, Linux и Android.

## 3. Запусти bootstrap

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
```

Linux:

```bash
./bootstrap.sh
```

На Windows локальный Python не обязателен: bootstrap сам подтянет portable runtime в `.runtime/python/windows`.

## 4. Ответь на вопросы bootstrap

Он сам:

- создаст или обновит `deployments/<name>.env`
- сгенерирует ключи и UUID
- спросит IP и SSH-доступ к RU и foreign
- проверит оба сервера
- соберёт локальные артефакты
- установит или переустановит роли на серверах

Поддерживаются варианты:

- вход под `root`
- вход под обычным пользователем с `sudo`

## 5. Забери готовые артефакты

После прогона всё остаётся локально:

- `deployments/<name>.env`
- `state/<name>.json`
- `out/<name>/client/`
- `out/<name>/cloud-init/`
- `out/<name>/bundle/`

Для клиента обычно нужен профиль из `out/<name>/client/`.

## Основные команды обслуживания

На Linux используй `python3`, на Windows после первого запуска используй `.\.runtime\python\windows\python.exe`.

Проверка серверов:

```bash
python3 ./scripts/orchestrate.py status --deployment my-stack
```

Переустановка:

```bash
python3 ./scripts/orchestrate.py reinstall --deployment my-stack
```

Удаление стека с серверов с восстановлением baseline:

```bash
python3 ./scripts/orchestrate.py remove --deployment my-stack
```

Полная серверная зачистка состояния стека:

```bash
python3 ./scripts/orchestrate.py purge --deployment my-stack
```

Удаление локальных артефактов:

```bash
python3 ./scripts/orchestrate.py cleanup-local --deployment my-stack
```

Если нужно действовать только на одну роль, добавь `--role ru-gateway` или `--role foreign-exit`.

## Что ещё посмотреть

- Детальный ресерч по провайдерам, клиентам и текущим ограничениям: [docs/RESEARCH.md](./docs/RESEARCH.md)
