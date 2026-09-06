from __future__ import annotations

import argparse
import sys

from . import VERSION
from .admin_access import admin_access_workflow
from .android import DEFAULT_HIDDIFY_PACKAGE, android_diagnose
from .common import cli_entrypoint, error_summary
from .config import load_existing_deployment_env
from .diagnose import diagnose_client_log_workflow, diagnose_front_workflow, diagnose_path_workflow, diagnose_server_client_workflow, diagnose_telegram_workflow
from .models import AppError, UserCancelled
from .prompts import select_existing_deployment
from .verify import verify_live_workflow
from .workflows import cleanup_local_workflow, client_check_workflow, install_workflow, maintain_workflow, menu_workflow, remote_action_workflow, routes_workflow, status_workflow
from .topology import LOCATIONS, NODE_EXIT, NODE_GATEWAY, TOPOLOGIES, TopologySpec

CANONICAL_NODE_CHOICES = ["all", NODE_GATEWAY, NODE_EXIT]


def add_node_selector(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--node", choices=CANONICAL_NODE_CHOICES, help="Какой узел затронуть: gateway, exit или all.")


def selected_node(args: argparse.Namespace) -> str:
    return str(getattr(args, "node", None) or "all")


def resolve_route_outbound(env: dict[str, str], requested: str | None) -> str:
    topology = TopologySpec.from_env(env, require_addresses=False)
    available = topology.route_egresses
    outbound = (requested or "").strip()
    if not outbound:
        if len(available) == 1:
            return available[0]
        raise AppError(f"Для topology={topology.mode} укажи --outbound: {', '.join(available)}")
    if outbound not in available:
        raise AppError(
            f"Outbound {outbound!r} недоступен для topology={topology.mode}; "
            f"доступны: {', '.join(available)}"
        )
    return outbound


def dispatch_routes(args: argparse.Namespace, action: str) -> int:
    deployment = select_existing_deployment(args.deployment)
    _env_path, env = load_existing_deployment_env(deployment)
    outbound = getattr(args, "outbound", "")
    if action == "add":
        outbound = resolve_route_outbound(env, outbound)
    return routes_workflow(
        deployment,
        action,
        value=getattr(args, "value", ""),
        outbound=outbound,
        rule_type=getattr(args, "rule_type", "domain"),
        include_subdomains=getattr(args, "include_subdomains", False),
        rule_id=getattr(args, "rule_id", ""),
        non_interactive=args.non_interactive,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=cli_entrypoint(), description="Установка и управление VPN через один или два сервера.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command")

    menu = subparsers.add_parser("menu", help="Показать интерактивное меню.")
    menu.set_defaults(func=lambda _args: menu_workflow())

    install = subparsers.add_parser("install", help="Интерактивная установка или обновление.")
    install.add_argument("--deployment", help="Имя deployment.")
    install.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; брать подключение из state/env.")
    install.add_argument("--yes", action="store_true", help="Не спрашивать финальное подтверждение.")
    install.add_argument("--topology", choices=sorted(TOPOLOGIES), help="single или dual при создании deployment.")
    install.add_argument("--gateway-location", choices=sorted(LOCATIONS), help="Расположение gateway; dual всегда использует ru.")
    install.set_defaults(
        func=lambda args: install_workflow(
            args.deployment,
            non_interactive=args.non_interactive,
            yes=args.yes,
            topology_mode=args.topology,
            gateway_location=args.gateway_location,
        )
    )

    status = subparsers.add_parser("status", help="Проверить состояние серверов без изменений.")
    status.add_argument("--deployment", help="Имя deployment.")
    add_node_selector(status)
    status.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; брать подключение из state/env.")
    status.set_defaults(func=lambda args: status_workflow(args.deployment, selected_node(args), non_interactive=args.non_interactive))

    admin = subparsers.add_parser("admin", help="Показать адрес web-admin для dual topology.")
    admin.add_argument("--deployment", help="Имя deployment.")
    admin.add_argument("--open-browser", action="store_true", help="Открыть web-admin в браузере.")
    admin.set_defaults(
        func=lambda args: admin_access_workflow(
            args.deployment,
            open_browser=args.open_browser,
        )
    )

    routes = subparsers.add_parser("routes", help="Управлять runtime-правилами web-админки через серверный backend.")
    routes_sub = routes.add_subparsers(dest="routes_command", required=True)
    for action in ("list", "remove", "add"):
        item = routes_sub.add_parser(action)
        item.add_argument("--deployment", help="Имя deployment.")
        item.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; брать подключение из state/env.")
        if action == "add":
            item.add_argument("--value", required=True)
            item.add_argument("--outbound", help="Egress tag; для single topology определяется автоматически.")
            item.add_argument("--type", dest="rule_type", choices=["domain", "cidr"], default="domain")
            item.add_argument("--include-subdomains", action="store_true")
        if action == "remove":
            item.add_argument("--id", dest="rule_id", required=True)
        item.set_defaults(func=lambda args, action_name=action: dispatch_routes(args, action_name))

    client_check = subparsers.add_parser("client-check", help="Проверить локальные маршруты клиента до серверов.")
    client_check.add_argument("--deployment", help="Имя deployment.")
    add_node_selector(client_check)
    client_check.set_defaults(func=lambda args: client_check_workflow(args.deployment, selected_node(args)))

    for action, help_text in (
        ("reinstall", "Переустановить одну роль или обе."),
        ("remove", "Удалить стек с сервера и восстановить baseline."),
        ("purge", "Удалить стек и вычистить его серверное состояние."),
    ):
        sub = subparsers.add_parser(action, help=help_text)
        sub.add_argument("--deployment", help="Имя deployment.")
        add_node_selector(sub)
        sub.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; брать подключение из state/env.")
        sub.add_argument("--yes", action="store_true", help="Не спрашивать подтверждение действия.")
        sub.set_defaults(func=lambda args, action_name=action: remote_action_workflow(args.deployment, selected_node(args), action_name, non_interactive=args.non_interactive, yes=args.yes))

    cleanup = subparsers.add_parser("cleanup-local", help="Удалить локальные артефакты deployment.")
    cleanup.add_argument("--deployment", help="Имя deployment.")
    cleanup.add_argument("--drop-env", action="store_true", help="Удалить и deployment env.")
    cleanup.add_argument("--drop-runtime", action="store_true", help="Удалить общий portable Python runtime.")
    cleanup.set_defaults(func=lambda args: cleanup_local_workflow(args.deployment, drop_env=args.drop_env, drop_runtime=args.drop_runtime))

    audit = subparsers.add_parser("audit", help="Запустить self-check.")
    audit.add_argument("mode", nargs="?", choices=["quick", "docker", "lab", "interop", "all"], default="quick")
    audit.add_argument("--json", action="store_true", help="Печатать итоговую summary в JSON.")
    audit.add_argument("--keep-docker", action="store_true", help="Не удалять Docker-контейнеры и сети после тестов.")
    audit.set_defaults(func=lambda args: _run_audit(args.mode, json_output=args.json, keep_docker=args.keep_docker))

    maintain = subparsers.add_parser("maintain", help="Проверить или по очереди применить обновления серверов.")
    maintain.add_argument("--deployment", help="Имя deployment.")
    maintain.add_argument("--apply", action="store_true", help="Применить обновления; без флага команда только показывает состояние.")
    maintain.add_argument("--refresh-assets", action="store_true", help="Транзакционно обновить rule assets через normal reinstall workflow.")
    maintain.add_argument("--reboot", action="store_true", help="Перезагрузить роль только если после обновления требуется reboot.")
    maintain.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; для --apply также укажи --yes.")
    maintain.add_argument("--yes", action="store_true", help="Подтвердить применение обновлений.")
    maintain.set_defaults(
        func=lambda args: maintain_workflow(
            args.deployment,
            apply_updates=args.apply,
            refresh_assets=args.refresh_assets,
            reboot=args.reboot,
            non_interactive=args.non_interactive,
            yes=args.yes,
        )
    )

    android = subparsers.add_parser("android-diagnose", help="Снять USB-диагностику Android / Hiddify через adb.")
    android.add_argument("--serial", help="ADB serial, если подключено несколько устройств.")
    android.add_argument("--package", default=DEFAULT_HIDDIFY_PACKAGE, help="Android package name Hiddify.")
    android.add_argument("--logcat-lines", type=int, default=400, help="Сколько последних строк logcat собирать.")
    android.set_defaults(func=lambda args: android_diagnose(serial=args.serial, package_name=args.package, logcat_lines=args.logcat_lines))

    diagnose = subparsers.add_parser("diagnose", help="Снять диагностику сети и серверного dataplane.")
    diagnose_subparsers = diagnose.add_subparsers(dest="diagnose_command", required=True)
    telegram = diagnose_subparsers.add_parser("telegram", help="Проверить ответ MTProto к IP из ошибок: через router и непосредственно с exit.")
    telegram.add_argument("--deployment", help="Имя deployment.")
    add_node_selector(telegram)
    telegram.add_argument("--destination", action="append", required=True, help="IP[:port] или [IPv6]:port; по умолчанию порт 443; до 8 адресов повторением флага.")
    telegram.add_argument("--non-interactive", action="store_true", help="Брать подключение из state/env без вопросов.")
    telegram.set_defaults(func=lambda args: diagnose_telegram_workflow(args.deployment, selected_node(args), args.destination, non_interactive=args.non_interactive))
    path = diagnose_subparsers.add_parser("path", help="Собрать структурный snapshot маршрутов, WireGuard, front и журналов.")
    path.add_argument("--deployment", help="Имя deployment.")
    add_node_selector(path)
    path.add_argument("--iperf", action="store_true", help="Дополнительно выполнить явный iperf test; runtime-policy и firewall не меняются.")
    path.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; брать подключение из state/env.")
    path.set_defaults(func=lambda args: diagnose_path_workflow(args.deployment, selected_node(args), iperf=args.iperf, non_interactive=args.non_interactive))
    client_log = diagnose_subparsers.add_parser("client-log", help="Разобрать локальный sing-box/Hiddify log и проверить route self-tunnel.")
    client_log.add_argument("--path", required=True, help="Путь к текстовому client log.")
    client_log.add_argument("--deployment", help="Имя deployment для проверки маршрута до серверов.")
    add_node_selector(client_log)
    client_log.set_defaults(func=lambda args: diagnose_client_log_workflow(args.path, deployment=args.deployment, node=selected_node(args)))
    front = diagnose_subparsers.add_parser("front", help="Проверить публичный RU:443 front и source IP конкретного клиента.")
    front.add_argument("--deployment", help="Имя deployment.")
    front.add_argument("--source-ip", help="Публичный IP проблемного устройства/сети, если известен.")
    front.add_argument("--minutes", type=int, default=120, help="Окно journalctl/nft анализа, 5..1440 минут.")
    front.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; брать подключение из state/env.")
    front.set_defaults(func=lambda args: diagnose_front_workflow(args.deployment, source_ip=args.source_ip, minutes=args.minutes, non_interactive=args.non_interactive))
    client = diagnose_subparsers.add_parser("client", help="Серверная диагностика публичного TCP/Xray пути конкретного клиента.")
    client.add_argument("--deployment", help="Имя deployment.")
    client.add_argument("--source", required=True, help="Публичный IP проблемного клиента или сети.")
    client.add_argument("--since", type=int, default=15, help="Окно анализа в минутах, 5..1440.")
    client.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; брать подключение из state/env.")
    client.set_defaults(func=lambda args: diagnose_server_client_workflow(args.deployment, source_ip=args.source, minutes=args.since, non_interactive=args.non_interactive))

    verify = subparsers.add_parser("verify", help="Проверить live dataplane после установки.")
    verify_subparsers = verify.add_subparsers(dest="verify_command", required=True)
    live = verify_subparsers.add_parser("live", help="Свежая live-проверка installed config, маршрутов и логов.")
    live.add_argument("--deployment", help="Имя deployment.")
    live.add_argument("--non-interactive", action="store_true", help="Не задавать вопросы; брать подключение из state/env.")
    live.add_argument("--throughput-seconds", type=int, default=30, help="Длительность bounded speed/stability проверки основного VLESS path; 0 выполняет только функциональные пробы.")
    live.set_defaults(func=lambda args: verify_live_workflow(args.deployment, non_interactive=args.non_interactive, throughput_seconds=args.throughput_seconds))

    return parser


def _run_audit(mode: str, *, json_output: bool, keep_docker: bool) -> int:
    from .audit.runner import main as audit_main

    argv = []
    if json_output:
        argv.append("--json")
    if keep_docker:
        argv.append("--keep-docker")
    argv.append(mode)
    return audit_main(argv)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        return menu_workflow()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except UserCancelled as exc:
        print(str(exc) or "Операция отменена пользователем.", file=sys.stderr)
        raise SystemExit(130)
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.", file=sys.stderr)
        raise SystemExit(130)
    except AppError as exc:
        print(f"Ошибка: {error_summary(exc)}", file=sys.stderr)
        raise SystemExit(1)
