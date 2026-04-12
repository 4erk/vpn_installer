from __future__ import annotations

import importlib
import sys
import urllib.error
import urllib.request

from .common import RUNTIME_DIR, RUNTIME_SITE_PACKAGES, run_command
from .models import AppError

if str(RUNTIME_SITE_PACKAGES) not in sys.path:
    sys.path.insert(0, str(RUNTIME_SITE_PACKAGES))


def ensure_pip_available() -> None:
    if run_command([sys.executable, "-m", "pip", "--version"], capture_output=True, check=False).returncode == 0:
        return
    if run_command([sys.executable, "-m", "ensurepip", "--upgrade"], capture_output=True, check=False).returncode == 0:
        if run_command([sys.executable, "-m", "pip", "--version"], capture_output=True, check=False).returncode == 0:
            return
    downloads_dir = RUNTIME_DIR / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    get_pip_path = downloads_dir / "get-pip.py"
    get_pip_url = "https://bootstrap.pypa.io/get-pip.py"
    try:
        urllib.request.urlretrieve(get_pip_url, get_pip_path)
    except (urllib.error.URLError, OSError) as exc:
        raise AppError(f"Не удалось скачать get-pip.py: {exc}") from exc
    completed = run_command([sys.executable, str(get_pip_path)], capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise AppError(f"Не удалось подготовить pip для Python runtime.\n{detail}")


def ensure_python_package(module_name: str, pip_spec: str):
    try:
        return importlib.import_module(module_name)
    except ImportError:
        ensure_pip_available()
        completed = run_command(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--target",
                str(RUNTIME_SITE_PACKAGES),
                pip_spec,
            ],
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise AppError(f"Не удалось подготовить Python dependency {module_name}.\n{detail}")
        importlib.invalidate_caches()
        return importlib.import_module(module_name)
