from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Iterable


DERIVED_SUFFIXES = frozenset({".pyc", ".pyo"})
DERIVED_DIRECTORIES = frozenset({"__pycache__"})


def release_tree_files(root: Path) -> Iterable[Path]:
    """Return immutable release files in deterministic bytewise path order."""

    root = root.resolve(strict=True)
    files: list[Path] = []
    for entry in root.rglob("*"):
        relative = entry.relative_to(root)
        if DERIVED_DIRECTORIES.intersection(relative.parts) or entry.suffix in DERIVED_SUFFIXES:
            continue
        if entry.is_symlink():
            raise ValueError(f"release tree contains a symlink: {relative.as_posix()}")
        if entry.is_file():
            files.append(entry)
    return sorted(files, key=lambda entry: entry.relative_to(root).as_posix().encode("utf-8"))


def release_tree_digest(root: Path) -> str:
    """Hash paths and payloads using the release publication contract."""

    try:
        resolved = root.resolve(strict=True)
        files = release_tree_files(resolved)
        digest = hashlib.sha256()
        for entry in files:
            relative = entry.relative_to(resolved).as_posix().encode("utf-8")
            payload = entry.read_bytes()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
        return digest.hexdigest()
    except (OSError, ValueError):
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="release-integrity")
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    digest = release_tree_digest(args.path)
    if not digest:
        parser.error("release tree is unreadable or contains unsupported entries")
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
