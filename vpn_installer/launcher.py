from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from vpn_installer.cli import main  # noqa: E402
from vpn_installer.error_logging import log_exception  # noqa: E402
from vpn_installer.models import AppError, UserCancelled  # noqa: E402


def run(argv: list[str] | None = None) -> int:
    try:
        return main(argv)
    except UserCancelled as exc:
        print(str(exc) or "Операция отменена пользователем.", file=sys.stderr)
        return 130
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.", file=sys.stderr)
        return 130
    except EOFError as exc:
        log_path = log_exception("launcher.eof", exc, argv=argv)
        print("\nВвод прерван. Запусти vpn в интерактивном режиме или передай команду аргументами.", file=sys.stderr)
        if log_path:
            print(f"Подробности сохранены в: {log_path}", file=sys.stderr)
        return 1
    except AppError as exc:
        log_path = log_exception("launcher.app_error", exc, argv=argv)
        print(f"Ошибка: {exc}", file=sys.stderr)
        if log_path:
            print(f"Подробности сохранены в: {log_path}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        log_path = log_exception("launcher.unhandled", exc, argv=argv)
        print(f"Непредвиденная ошибка: {exc}", file=sys.stderr)
        if log_path:
            print(f"Подробности сохранены в: {log_path}", file=sys.stderr)
        if os.environ.get("VPN_DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
