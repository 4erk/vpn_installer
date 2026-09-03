from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AppError

ROOT_DIR = Path(__file__).resolve().parents[1]
DEPLOYMENTS_DIR = ROOT_DIR / "deployments"
STATE_DIR = ROOT_DIR / "state"
OUT_DIR = ROOT_DIR / "out"
RUNTIME_DIR = ROOT_DIR / ".runtime"
RUNTIME_SITE_PACKAGES = RUNTIME_DIR / "python-packages"
INSTALL_SCRIPT_PATH = ROOT_DIR / "install.sh"


def cli_entrypoint(platform_name: str | None = None) -> str:
    return r".\vpn.cmd" if (platform_name or os.name) == "nt" else "./vpn.sh"


def cli_command(command: str = "", *, platform_name: str | None = None) -> str:
    entrypoint = cli_entrypoint(platform_name)
    return f"{entrypoint} {command}" if command else entrypoint


def error_summary(error: BaseException, *, max_length: int = 240) -> str:
    line = next((line.strip() for line in str(error).splitlines() if line.strip()), type(error).__name__)
    return line if len(line) <= max_length else line[: max_length - 3].rstrip() + "..."


def print_header(title: str) -> None:
    print(f"\n== {title} ==")


def warn(message: str) -> None:
    print(f"Предупреждение: {message}", file=os.sys.stderr)


def fail(message: str) -> None:
    raise AppError(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sanitize_name(raw_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", raw_name).strip("-")


def ensure_directories() -> None:
    for path in (DEPLOYMENTS_DIR, STATE_DIR, OUT_DIR, RUNTIME_DIR, RUNTIME_SITE_PACKAGES):
        path.mkdir(parents=True, exist_ok=True)


def ensure_file_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    ensure_file_parent(path)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def write_private_text(path: Path, content: str) -> None:
    """Atomically publish local credentials without a world-readable creation window."""

    ensure_file_parent(path)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(content)
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def write_json(path: Path, payload: Any) -> None:
    write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def write_private_json(path: Path, payload: Any) -> None:
    write_private_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def shell_env_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def env_line(key: str, value: str) -> str:
    return f"{key}={shell_env_quote(value)}"


def parse_env_value(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw[0] in ('"', "'"):
        try:
            return str(ast.literal_eval(raw))
        except (SyntaxError, ValueError) as exc:
            raise AppError(f"Не удалось разобрать значение env: {raw}") from exc
    return raw


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(
    args: list[str],
    *,
    capture_output: bool = False,
    capture_stderr: bool = False,
    input_text: str | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    timeout: int | float | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            args,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output or capture_stderr else None,
            cwd=str(cwd) if cwd else None,
            env=env,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise AppError(f"Не найдена команда: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        detail = ""
        if capture_output or capture_stderr:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            detail = (stderr or stdout or "").strip()
        suffix = f"\n{detail}" if detail else ""
        raise AppError(f"Команда не завершилась за {timeout} сек.: {' '.join(args)}{suffix}") from exc
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip() if capture_output or capture_stderr else ""
        if detail:
            raise AppError(f"Команда завершилась с ошибкой: {' '.join(args)}\n{detail}")
        raise AppError(f"Команда завершилась с ошибкой (код {completed.returncode}): {' '.join(args)}")
    return completed
