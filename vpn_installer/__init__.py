"""Portable VPN installer package."""

from __future__ import annotations

from typing import Any

__all__ = ["main"]
VERSION = "0.5.8"


def main(argv: list[str] | None = None) -> int:
    from .cli import main as cli_main

    return cli_main(argv)


def __getattr__(name: str) -> Any:
    if name == "__version__":
        return VERSION
    raise AttributeError(name)
