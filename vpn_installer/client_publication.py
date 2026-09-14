"""Generation publication on local NTFS/POSIX filesystems.

Subsequent pointer switches are process-interruption safe on qualified platforms.
First legacy-directory migration has a recoverable missing-path window. Neither
process-kill tests nor successful flush calls constitute a power-loss guarantee.
Operator files are copied, not merged with uncoordinated external writers.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Mapping

from .common import write_private_text
from .models import AppError

GENERATIONS = ".client-generations"
MANIFEST = ".generation.json"
JOURNAL = ".client-publication.json"
STATE_DIRECTORY = ".client-state"
ROUTE_STATE = "windows-route-bypass.state.json"
MAX_GENERATIONS = 32
MAX_GENERATION_BYTES = 32 * 1024 * 1024
_ID = re.compile(r"(?:generation|legacy)-[0-9a-f]{32}\Z")
_FORWARD = "Current client instructions: client/NEXT-STEPS.txt\n"


def _checkpoint(name: str) -> None:
    """Fault-injection boundary; production has no checkpoint side effects."""


def _windows_api():
    import ctypes as c
    from ctypes import wintypes as w

    api = c.WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    api.CreateFileW.restype = w.HANDLE
    api.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
    api.DeviceIoControl.restype = w.BOOL
    api.CloseHandle.argtypes = [w.HANDLE]
    api.FlushFileBuffers.argtypes = [w.HANDLE]
    api.FlushFileBuffers.restype = w.BOOL
    return c, w, api


@contextmanager
def _windows_handle(path: Path, *, state_lock: bool = False, read_only: bool = False):
    c, _, api = _windows_api()
    handle = api.CreateFileW(str(path), 0x80000000 if read_only else 0xC0000000, 4 if state_lock else 7, None,
                             4 if state_lock else 3, 0x80 if state_lock else 0x02200000, None)
    if handle == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        yield handle
    finally:
        api.CloseHandle(handle)


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        c, _, api = _windows_api()
        with _windows_handle(path) as handle:
            if not api.FlushFileBuffers(handle):
                raise c.WinError(c.get_last_error())
    else:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _write_durable(path: Path, payload: str) -> None:
    write_private_text(path, payload)
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())
    _sync_directory(path.parent)


def _write_durable_bytes(path: Path, payload: bytes) -> None:
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    if os.name == "nt" and path.exists():
        return bool(path.lstat().st_file_attributes & 0x400)
    return False


def _owned_directory(path: Path) -> None:
    if _is_link(path):
        raise AppError(f"Publication storage must not be a link/reparse point: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def _require_ntfs(root: Path) -> None:
    if os.name != "nt":
        return
    c, _, api = _windows_api()
    volume = c.create_unicode_buffer(32768)
    filesystem = c.create_unicode_buffer(64)
    if not api.GetVolumePathNameW(str(root), volume, len(volume)):
        raise c.WinError(c.get_last_error())
    if not api.GetVolumeInformationW(volume.value, None, 0, None, None, None, filesystem, len(filesystem)):
        raise c.WinError(c.get_last_error())
    if filesystem.value != "NTFS" or str(root).startswith("\\\\"):
        raise AppError("Client publication requires a qualified local NTFS volume on Windows.")


def _set_junction(path: Path, target: Path) -> None:
    c, w, api = _windows_api()
    substitute = ("\\??\\" + str(target)).encode("utf-16-le")
    printed = str(target).encode("utf-16-le")
    data = struct.pack("<HHHH", 0, len(substitute), len(substitute) + 2, len(printed))
    data += substitute + b"\0\0" + printed + b"\0\0"
    if len(data) + 8 > 16384:
        raise AppError("Client generation path exceeds the reparse-data limit.")
    buffer = struct.pack("<IHH", 0xA0000003, len(data), 0) + data
    with _windows_handle(path) as handle:
        returned = w.DWORD()
        if not api.DeviceIoControl(handle, 0x900A4, buffer, len(buffer), None, 0, c.byref(returned), None):
            raise c.WinError(c.get_last_error())
        _checkpoint("pointer-set")
        if not api.FlushFileBuffers(handle):
            raise c.WinError(c.get_last_error())


def _pointer_target(client: Path) -> Path:
    if os.name == "nt":
        c, w, api = _windows_api()
        with _windows_handle(client, read_only=True) as handle:
            buffer = c.create_string_buffer(16384)
            returned = w.DWORD()
            if not api.DeviceIoControl(handle, 0x900A8, None, 0, buffer, len(buffer), c.byref(returned), None):
                raise c.WinError(c.get_last_error())
            tag, length, _ = struct.unpack_from("<IHH", buffer.raw)
            if tag != 0xA0000003 or length + 8 > returned.value:
                raise AppError("Client pointer is not an owned NTFS junction.")
            offset, size, _, _ = struct.unpack_from("<HHHH", buffer.raw, 8)
            target = buffer.raw[16 + offset:16 + offset + size].decode("utf-16-le")
            if not target.startswith("\\??\\"):
                raise AppError("Client junction has an unsupported target.")
            selected = Path(target[4:])
    else:
        selected = client.parent / os.readlink(client)
    expected = client.parent / GENERATIONS
    if selected.parent != expected or not _ID.fullmatch(selected.name) or not selected.name.startswith("generation-"):
        raise AppError("Client pointer escapes the owned generation directory.")
    if _is_link(expected) or _is_link(selected):
        raise AppError("Client generation storage must not contain reparse points.")
    return selected


def _validate_generation(path: Path) -> dict[str, str]:
    metadata_path = path / MANIFEST
    if _is_link(metadata_path):
        raise AppError("Client generation manifest must not be a link.")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if set(metadata) != {"schema", "files"} or metadata["schema"] != 1 or not isinstance(metadata["files"], dict):
        raise AppError("Invalid client generation manifest.")
    for name, digest in metadata["files"].items():
        if Path(name).name != name or name in {"", ".", "..", MANIFEST}:
            raise AppError("Invalid client artifact name.")
        artifact = path / name
        if _is_link(artifact) or hashlib.sha256(artifact.read_bytes()).hexdigest() != digest:
            raise AppError(f"Incomplete client generation: {name}")
    if not metadata["files"]:
        raise AppError("Client generation is empty.")
    return metadata["files"]


@contextmanager
def publication_lock(client: Path) -> Iterator[None]:
    with (client.parent / ".client-artifacts.lock").open("a+b") as lock:
        if lock.tell() == 0:
            lock.write(b"\0")
            lock.flush()
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise AppError("Client artifacts are being published by another process; retry later.") from exc
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _journal(root: Path) -> dict[str, str] | None:
    path = root / JOURNAL
    if not path.exists():
        return None
    if _is_link(path):
        raise AppError("Client recovery journal must not be a link.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != {"target", "previous", "legacy"}:
        raise AppError("Unknown client recovery journal.")
    for key, value in data.items():
        if not isinstance(value, str) or (value and not _ID.fullmatch(value)) or (key == "target" and not value.startswith("generation-")):
            raise AppError("Unsafe client recovery journal.")
    return data


def _legacy_path(root: Path, identifier: str) -> Path:
    return root / (".client-" + identifier)


def _finish(root: Path) -> None:
    _write_durable(root / "NEXT-STEPS.txt", _FORWARD)
    _checkpoint("before-journal-clear")
    (root / JOURNAL).unlink(missing_ok=True)
    _sync_directory(root)


def recover_locked(client: Path) -> None:
    """Reconcile a previous process death while holding publication_lock."""
    root = client.parent
    data = _journal(root)
    if data is None:
        return
    storage = root / GENERATIONS
    if _is_link(storage):
        raise AppError("Client recovery storage must not be a link.")
    if _is_link(client):
        selected = _pointer_target(client)
        if selected.name not in {data["target"], data["previous"]}:
            raise AppError("Client recovery journal does not own the active generation.")
        _validate_generation(selected)
        _finish(root)
        return
    legacy = _legacy_path(root, data["legacy"]) if data["legacy"] else None
    if not client.exists() and legacy is not None and legacy.is_dir() and not _is_link(legacy):
        legacy.rename(client)
        _sync_directory(storage)
        _sync_directory(root)
    if client.exists() and not client.is_dir():
        raise AppError("Client recovery encountered an unexpected file.")
    if not client.exists() and legacy is not None:
        raise AppError("Client legacy backup is missing; publication requires manual recovery.")
    (root / JOURNAL).unlink()
    _sync_directory(root)


@contextmanager
def snapshot(client: Path) -> Iterator[Path]:
    """Pin one retained generation, never repair on a read path."""
    client = Path(os.path.abspath(client))
    if _is_link(client):
        selected = _pointer_target(client)
        _validate_generation(selected)
        yield selected
        return
    with publication_lock(client):
        if _is_link(client):
            selected = _pointer_target(client)
            _validate_generation(selected)
        elif client.is_dir():
            selected = client
        else:
            data = _journal(client.parent)
            if not data or not data["legacy"]:
                raise AppError("Client artifacts are not published.")
            selected = _legacy_path(client.parent, data["legacy"])
            if not selected.is_dir() or _is_link(selected):
                raise AppError("Client migration requires recovery.")
        yield selected


def _copy_operator(source: Path, destination: Path, excluded: set[str], budget: list[int]) -> None:
    excluded = {name.casefold() for name in excluded} if os.name == "nt" else excluded
    for entry in source.iterdir():
        name = entry.name.casefold() if os.name == "nt" else entry.name
        if name in excluded:
            continue
        if _is_link(entry):
            raise AppError(f"Cannot snapshot unowned operator link: {entry.name}")
        if entry.is_dir():
            (destination / entry.name).mkdir(mode=0o700)
            _copy_operator(entry, destination / entry.name, set(), budget)
        elif entry.is_file():
            before = entry.stat()
            budget[0] -= before.st_size
            if budget[0] < 0:
                raise AppError("Client generation exceeds the 32 MiB operator snapshot limit; current output is unchanged.")
            shutil.copy2(entry, destination / entry.name)
            after = entry.stat()
            if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                raise AppError(f"Operator file changed during publication: {entry.name}")
            with (destination / entry.name).open("r+b") as handle:
                os.fsync(handle.fileno())
        else:
            raise AppError(f"Unsupported operator entry: {entry.name}")
    _sync_directory(destination)


@contextmanager
def _legacy_route_state(client: Path) -> Iterator[None]:
    state_dir = client.parent / STATE_DIRECTORY
    _owned_directory(state_dir)
    source = client / ROUTE_STATE
    if not client.is_dir() or _is_link(client) or not source.exists():
        yield
        return
    if _is_link(source) or not source.is_file():
        raise AppError("Legacy route ownership state is not a regular file.")
    old_lock = client / (ROUTE_STATE + ".lock")
    if _is_link(old_lock):
        raise AppError("Legacy route lock must not be a link.")
    def adopt() -> None:
        destination = state_dir / ROUTE_STATE
        payload = source.read_bytes()
        if _is_link(destination) or (destination.exists() and destination.read_bytes() != payload):
            raise AppError("Existing stable route state conflicts with legacy state; neither was replaced.")
        _write_durable_bytes(destination, payload)
    if os.name == "nt":
        # Deny competing helpers, but allow the containing legacy directory rename.
        with _windows_handle(old_lock, state_lock=True):
            adopt()
            yield
    else:
        import fcntl
        with old_lock.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            adopt()
            yield


def _activate(client: Path, generation: Path) -> None:
    if os.name == "nt" and _is_link(client):
        _set_junction(client, generation)
    else:
        temporary = client.parent / (".client-pointer-" + uuid.uuid4().hex)
        try:
            if os.name == "nt":
                temporary.mkdir()
                _set_junction(temporary, generation)
                temporary.rename(client)
            else:
                temporary.symlink_to(generation.relative_to(client.parent), target_is_directory=True)
                os.replace(temporary, client)
            _checkpoint("pointer-set")
        finally:
            if _is_link(temporary):
                temporary.rmdir() if os.name == "nt" else temporary.unlink()
        _sync_directory(client.parent)


def publish_locked(client: Path, payloads: Mapping[str, str], stale: tuple[str, ...], *,
                   render_instructions: Callable[[Path], str] | None = None) -> Path:
    """Publish validated payloads; caller owns publication_lock.

    No generation garbage collection occurs here. A pinned reader or explicit
    rollback may still need an older generation after the pointer has changed.
    """
    client = Path(os.path.abspath(client))
    root = client.parent
    if (root / "NEXT-STEPS.txt").is_dir():
        raise AppError("Legacy NEXT-STEPS.txt is a directory; preserve and resolve it before migration.")
    _require_ntfs(root)
    storage = root / GENERATIONS
    _owned_directory(storage)
    recover_locked(client)
    previous = _pointer_target(client) if _is_link(client) else None
    if previous is not None:
        previous_hashes = _validate_generation(previous)
        desired = {**payloads, "NEXT-STEPS.txt": render_instructions(previous)} if render_instructions else payloads
        desired_hashes = {name: hashlib.sha256(value.encode("utf-8")).hexdigest() for name, value in desired.items()}
        if previous_hashes == desired_hashes and not any(os.path.lexists(previous / name) for name in stale):
            return previous
    elif client.exists() and not client.is_dir():
        raise AppError("Client output is not a directory.")
    if sum(1 for entry in storage.iterdir()) >= MAX_GENERATIONS:
        raise AppError("Client generation retention limit reached (32). Quiesce readers and explicitly clean unreferenced generations before retrying; current output is unchanged.")
    source = previous or (client if client.exists() else None)
    generation = storage / ("generation-" + uuid.uuid4().hex)
    if render_instructions is not None:
        payloads = {**payloads, "NEXT-STEPS.txt": render_instructions(generation)}
    budget = [MAX_GENERATION_BYTES - sum(len(value.encode("utf-8")) for value in payloads.values())]
    if budget[0] < 0:
        raise AppError("Client generation payload exceeds 32 MiB.")
    keys = [name.casefold() if os.name == "nt" else name for name in payloads]
    if len(set(keys)) != len(keys) or MANIFEST.casefold() in {key.casefold() for key in keys}:
        raise AppError("Client artifact names collide with another artifact or the generation manifest.")
    generation.mkdir(mode=0o700)
    expected_hashes = {name: hashlib.sha256(payload.encode("utf-8")).hexdigest() for name, payload in payloads.items()}
    for name, payload in payloads.items():
        if Path(name).name != name or name in {"", ".", "..", MANIFEST}:
            raise AppError("Invalid client artifact name.")
        if not payload.strip():
            raise AppError(f"Client artifact is empty: {name}")
        _write_durable(generation / name, payload)
        if (generation / name).read_text(encoding="utf-8") != payload:
            raise AppError(f"Client artifact is incomplete: {name}")
        _checkpoint("staged:" + name)
    if source is not None:
        _copy_operator(source, generation, set(payloads) | set(stale) | {MANIFEST, ROUTE_STATE, ROUTE_STATE + ".lock"}, budget)
    metadata = {"schema": 1, "files": expected_hashes}
    _write_durable(generation / MANIFEST, json.dumps(metadata, sort_keys=True) + "\n")
    _validate_generation(generation)
    _sync_directory(storage)
    _checkpoint("generation-ready")
    legacy = "legacy-" + uuid.uuid4().hex if source is not None and previous is None else ""
    data = {"target": generation.name, "previous": previous.name if previous else "", "legacy": legacy}
    _write_durable(root / JOURNAL, json.dumps(data, sort_keys=True) + "\n")
    try:
        _checkpoint("journal-ready")
        if legacy:
            client.rename(_legacy_path(root, legacy))
            _sync_directory(root)
            _checkpoint("legacy-moved")
        with _legacy_route_state(_legacy_path(root, legacy) if legacy else client):
            _checkpoint("before-switch")
            _activate(client, generation)
            _checkpoint("after-switch")
            _finish(root)
    except BaseException:
        # Resolve the actual pointer, not an in-memory "committed" flag: the
        # process may be interrupted after the kernel changed the pointer.
        recover_locked(client)
        raise
    return generation


def rollback(client: Path, generation: Path, *, stale: tuple[str, ...] = ()) -> Path:
    """Republish old generated bytes while retaining current operator data/state."""
    client = Path(os.path.abspath(client))
    generation = Path(os.path.abspath(generation))
    if generation.parent != client.parent / GENERATIONS or not generation.name.startswith("generation-") or not _ID.fullmatch(generation.name):
        raise AppError("Rollback generation is outside owned storage.")
    with publication_lock(client):
        recover_locked(client)
        if _is_link(generation):
            raise AppError("Rollback generation must not be a link.")
        files = _validate_generation(generation)
        payloads = {name: (generation / name).read_text(encoding="utf-8") for name in files}
        instructions = payloads.get("NEXT-STEPS.txt")
        return publish_locked(client, payloads, stale, render_instructions=(
            (lambda selected: instructions.replace(str(generation), str(selected))) if instructions is not None else None
        ))
