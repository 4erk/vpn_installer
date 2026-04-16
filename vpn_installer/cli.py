from __future__ import annotations

import argparse
import sys

from .android import DEFAULT_HIDDIFY_PACKAGE, android_diagnose
from .models import AppError, ROLE_FOREIGN, ROLE_RU, UserCancelled
from .workflows import cleanup_local_workflow, install_workflow, menu_workflow, remote_action_workflow, status_workflow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpn", description="Portable VPN installer.")
    subparsers = parser.add_subparsers(dest="command")

    menu = subparsers.add_parser("menu", help="Показать интерактивное меню.")
    menu.set_defaults(func=lambda _args: menu_workflow())

    install = subparsers.add_parser("install", help="Интерактивная установка или обновление.")
    install.add_argument("--deployment", help="Имя deployment.")
    install.set_defaults(func=lambda args: install_workflow(args.deployment))

    status = subparsers.add_parser("status", help="Проверить состояние серверов без изменений.")
    status.add_argument("--deployment", help="Имя deployment.")
    status.add_argument("--role", choices=["all", ROLE_RU, ROLE_FOREIGN], default="all", help="Какую роль проверять.")
    status.set_defaults(func=lambda args: status_workflow(args.deployment, args.role))

    for action, help_text in (
        ("reinstall", "Переустановить одну роль или обе."),
        ("remove", "Удалить стек с сервера и восстановить baseline."),
        ("purge", "Удалить стек и вычистить его серверное состояние."),
    ):
        sub = subparsers.add_parser(action, help=help_text)
        sub.add_argument("--deployment", help="Имя deployment.")
        sub.add_argument("--role", choices=["all", ROLE_RU, ROLE_FOREIGN], default="all", help="Какую роль затронуть.")
        sub.set_defaults(func=lambda args, action_name=action: remote_action_workflow(args.deployment, args.role, action_name))

    cleanup = subparsers.add_parser("cleanup-local", help="Удалить локальные артефакты deployment.")
    cleanup.add_argument("--deployment", help="Имя deployment.")
    cleanup.add_argument("--drop-env", action="store_true", help="Удалить и deployment env.")
    cleanup.add_argument("--drop-runtime", action="store_true", help="Удалить общий portable Python runtime.")
    cleanup.set_defaults(func=lambda args: cleanup_local_workflow(args.deployment, drop_env=args.drop_env, drop_runtime=args.drop_runtime))

    audit = subparsers.add_parser("audit", help="Запустить self-check.")
    audit.add_argument("mode", nargs="?", choices=["quick", "docker", "lab", "all"], default="quick")
    audit.add_argument("--json", action="store_true", help="Печатать итоговую summary в JSON.")
    audit.add_argument("--keep-docker", action="store_true", help="Не удалять Docker-контейнеры и сети после тестов.")
    audit.set_defaults(func=lambda args: _run_audit(args.mode, json_output=args.json, keep_docker=args.keep_docker))

    android = subparsers.add_parser("android-diagnose", help="Снять USB-диагностику Android / Hiddify через adb.")
    android.add_argument("--serial", help="ADB serial, если подключено несколько устройств.")
    android.add_argument("--package", default=DEFAULT_HIDDIFY_PACKAGE, help="Android package name Hiddify.")
    android.add_argument("--logcat-lines", type=int, default=400, help="Сколько последних строк logcat собирать.")
    android.set_defaults(func=lambda args: android_diagnose(serial=args.serial, package_name=args.package, logcat_lines=args.logcat_lines))

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
        print(f"Ошибка: {exc}", file=sys.stderr)
        raise SystemExit(1)
