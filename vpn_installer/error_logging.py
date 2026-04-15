from __future__ import annotations

import json
import platform
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import OUT_DIR, ensure_file_parent, write_text

ERROR_LOG_DIR = OUT_DIR / "logs" / "runtime"
LATEST_ERROR_LOG = ERROR_LOG_DIR / "latest-error.log"


def _timestamp_for_filename() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _stringify(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _render_report(context: str, exc: BaseException, *, argv: list[str] | None, extra: dict[str, Any] | None) -> str:
    lines = [
        f"timestamp_utc: {datetime.now(timezone.utc).isoformat()}",
        f"context: {context}",
        f"cwd: {Path.cwd()}",
        f"python_executable: {sys.executable}",
        f"python_version: {sys.version.replace(chr(10), ' ')}",
        f"platform: {platform.platform()}",
        f"argv: {_stringify(argv if argv is not None else sys.argv[1:])}",
        f"exception_type: {type(exc).__name__}",
        f"exception: {exc}",
    ]
    if extra:
        for key, value in extra.items():
            lines.append(f"{key}: {_stringify(value)}")
    lines.append("")
    lines.append("traceback:")
    lines.append("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).rstrip())
    lines.append("")
    return "\n".join(lines)


def log_exception(context: str, exc: BaseException, *, argv: list[str] | None = None, extra: dict[str, Any] | None = None) -> Path | None:
    try:
        ERROR_LOG_DIR.mkdir(parents=True, exist_ok=True)
        report = _render_report(context, exc, argv=argv, extra=extra)
        archived_path = ERROR_LOG_DIR / f"error-{_timestamp_for_filename()}.log"
        ensure_file_parent(archived_path)
        write_text(archived_path, report)
        write_text(LATEST_ERROR_LOG, report)
        return archived_path
    except Exception:  # noqa: BLE001
        return None
