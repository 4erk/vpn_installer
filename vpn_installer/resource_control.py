from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping


MIB = 1024 * 1024
LOW_MEMORY_SWAP_THRESHOLD_BYTES = 1024 * MIB
MANAGED_SWAP_BYTES = 512 * MIB
ROUTER_MIN_GO_MEMORY_BYTES = 128 * MIB
ROUTER_RESERVED_MEMORY_BYTES = 384 * MIB
BTMP_ROTATE_BYTES = 64 * MIB
DISK_DEGRADED_PERCENT = 85.0
DISK_FAILED_PERCENT = 95.0

STATE_DIR = Path("/var/lib/vpn-stack")
ROOT = Path("/etc/vpn-stack")
RELEASES_PATH = ROOT / "releases"
CURRENT_RELEASE_PATH = ROOT / "current"
PREVIOUS_RELEASE_PATH = ROOT / "previous"
BACKUPS_PATH = ROOT / "backups"
REVISION_BACKUPS_PATH = BACKUPS_PATH / "revisions"
BASELINE_BACKUP_PATH = BACKUPS_PATH / "baseline"
PROC_MEMINFO_PATH = Path("/proc/meminfo")
PROC_SWAPS_PATH = Path("/proc/swaps")
CGROUP_MEMORY_MAX_PATH = Path("/sys/fs/cgroup/memory.max")
MANAGED_SWAP_PATH = STATE_DIR / "swapfile"
BTMP_PATH = Path("/var/log/btmp")
BTMP_LOGROTATE_CONFIG_PATH = Path("/usr/local/lib/vpn-stack/btmp-logrotate.conf")
BTMP_LOGROTATE_STATE_PATH = STATE_DIR / "btmp-logrotate.status"
JOURNAL_PATH = Path("/var/log/journal")
APT_ARCHIVES_PATH = Path("/var/cache/apt/archives")
APT_LISTS_PATH = Path("/var/lib/apt/lists")


def _run(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def _require_command(args: list[str], *, timeout: int = 30) -> None:
    result = _run(args, timeout=timeout)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"command failed: {' '.join(args)}: {detail}")


def _parse_timestamp(raw: str) -> datetime | None:
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def meminfo_snapshot(path: Path = PROC_MEMINFO_PATH) -> dict[str, int]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values: dict[str, int] = {}
    for line in lines:
        key, separator, raw = line.partition(":")
        fields = raw.split()
        if not separator or not fields:
            continue
        try:
            value = int(fields[0])
        except ValueError:
            continue
        values[key] = value * 1024 if len(fields) > 1 and fields[1].lower() == "kb" else value
    return values


def effective_memory_bytes(total_bytes: int, cgroup_path: Path = CGROUP_MEMORY_MAX_PATH) -> int:
    try:
        cgroup_limit = int(cgroup_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        cgroup_limit = 0
    return min(total_bytes, cgroup_limit) if total_bytes > 0 and cgroup_limit > 0 else cgroup_limit or total_bytes


def router_go_memory_limit_bytes(total_bytes: int) -> int:
    if total_bytes <= 0:
        raise ValueError("effective memory capacity is unavailable")
    if total_bytes < 256 * MIB:
        return max(64 * MIB, total_bytes // 2) // MIB * MIB
    usable = min(total_bytes * 2 // 3, total_bytes - ROUTER_RESERVED_MEMORY_BYTES)
    upper = max(ROUTER_MIN_GO_MEMORY_BYTES, total_bytes - 64 * MIB)
    return min(max(ROUTER_MIN_GO_MEMORY_BYTES, usable), upper) // MIB * MIB


def active_swap_paths(path: Path = PROC_SWAPS_PATH) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return set()
    return {fields[0] for line in lines if (fields := line.split())}


def prepare_memory_reserve(
    *,
    meminfo_path: Path = PROC_MEMINFO_PATH,
    swaps_path: Path = PROC_SWAPS_PATH,
    swap_path: Path = MANAGED_SWAP_PATH,
    swap_bytes: int = MANAGED_SWAP_BYTES,
) -> dict[str, Any]:
    memory = meminfo_snapshot(meminfo_path)
    total = int(memory.get("MemTotal", 0))
    required = 0 < total < LOW_MEMORY_SWAP_THRESHOLD_BYTES and int(memory.get("SwapTotal", 0)) < swap_bytes
    active = str(swap_path) in active_swap_paths(swaps_path)
    if not required or active:
        return {"changed": False, "required": required, "active": active, "path": str(swap_path)}

    swap_path.parent.mkdir(parents=True, exist_ok=True)
    if swap_path.is_symlink() or (swap_path.exists() and not swap_path.is_file()):
        raise RuntimeError(f"managed swap path has an unsafe type: {swap_path}")
    if swap_path.exists() and swap_path.stat().st_size != swap_bytes:
        swap_path.unlink()
    if not swap_path.exists():
        if shutil.disk_usage(swap_path.parent).free < swap_bytes + 256 * MIB:
            raise RuntimeError("not enough free disk space for the low-memory swap reserve")
        _require_command(["fallocate", "-l", str(swap_bytes), str(swap_path)], timeout=60)
    os.chmod(swap_path, 0o600)
    _require_command(["mkswap", "-f", str(swap_path)])
    _require_command(["swapon", str(swap_path)])
    return {"changed": True, "required": True, "active": True, "path": str(swap_path), "bytes": swap_bytes}


def _process_environment(pid: int) -> dict[str, str]:
    try:
        entries = (Path("/proc") / str(pid) / "environ").read_bytes().split(b"\0") if pid > 0 else []
    except OSError:
        entries = []
    return {
        key.decode(errors="replace"): value.decode(errors="replace")
        for entry in entries
        for key, separator, value in (entry.partition(b"="),)
        if separator
    }


def _service_resources(unit: str) -> dict[str, Any]:
    fields = ("MainPID", "NRestarts", "MemoryCurrent", "MemoryPeak", "TasksCurrent", "ActiveState")
    result = _run(["systemctl", "show", unit, *(f"--property={field}" for field in fields)], timeout=8)
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line) if result.returncode == 0 else {}

    def integer(name: str) -> int:
        try:
            return int(values.get(name, "0"))
        except ValueError:
            return 0

    pid = integer("MainPID")
    return {
        "active_state": values.get("ActiveState", "unknown"),
        "main_pid": pid,
        "automatic_restarts": integer("NRestarts"),
        "memory_current_bytes": integer("MemoryCurrent"),
        "memory_peak_bytes": integer("MemoryPeak"),
        "tasks": integer("TasksCurrent"),
        "go_memory_limit": _process_environment(pid).get("GOMEMLIMIT", ""),
    }


def memory_runtime_snapshot() -> dict[str, Any]:
    values = meminfo_snapshot()
    total = int(values.get("MemTotal", 0))
    effective = effective_memory_bytes(total)
    desired_bytes = router_go_memory_limit_bytes(effective) if effective > 0 else 0
    desired = f"{desired_bytes // MIB}MiB" if desired_bytes else ""
    router = _service_resources("sing-box.service")
    swap_total = int(values.get("SwapTotal", 0))
    reserve_required = 0 < total < LOW_MEMORY_SWAP_THRESHOLD_BYTES
    managed_swap_active = str(MANAGED_SWAP_PATH) in active_swap_paths()
    return {
        "total_bytes": total,
        "effective_bytes": effective,
        "available_bytes": int(values.get("MemAvailable", 0)),
        "swap_total_bytes": swap_total,
        "swap_free_bytes": int(values.get("SwapFree", 0)),
        "reserve_required": reserve_required,
        "reserve_ready": not reserve_required or managed_swap_active or swap_total >= MANAGED_SWAP_BYTES - MIB,
        "managed_swap_active": managed_swap_active,
        "router": {
            **router,
            "desired_go_memory_limit": desired,
            "go_memory_limit_active": bool(desired and router.get("go_memory_limit") == desired),
        },
    }


def exec_router(command: list[str]) -> None:
    command = command[1:] if command[:1] == ["--"] else command
    if not command:
        raise ValueError("exec-router requires the sing-box command")
    total = int(meminfo_snapshot().get("MemTotal", 0))
    limit = router_go_memory_limit_bytes(effective_memory_bytes(total))
    environment = os.environ.copy()
    environment["GOMEMLIMIT"] = f"{limit // MIB}MiB"
    os.execvpe(command[0], command, environment)


def _allocated_bytes(stat_result: os.stat_result) -> int:
    blocks = getattr(stat_result, "st_blocks", None)
    if isinstance(blocks, int) and blocks >= 0:
        return blocks * 512
    return int(stat_result.st_size)


def path_tree_disk_usage(path: Path) -> int:
    try:
        if path.is_symlink():
            return 0
        allocated = _allocated_bytes(path.stat())
        if path.is_file():
            return allocated
        return allocated + sum(path_tree_disk_usage(entry) for entry in path.iterdir())
    except OSError:
        return 0


def _managed_releases_snapshot() -> dict[str, Any]:
    try:
        releases = [path for path in RELEASES_PATH.iterdir() if path.is_dir() and not path.is_symlink()]
    except OSError:
        releases = []
    retained: set[str] = set()
    for link in (CURRENT_RELEASE_PATH, PREVIOUS_RELEASE_PATH):
        try:
            resolved = link.resolve(strict=True)
        except OSError:
            continue
        if resolved.parent == RELEASES_PATH.resolve():
            retained.add(resolved.name)
    sizes = {path.name: path_tree_disk_usage(path) for path in releases}
    stale = set(sizes) - retained
    return {
        "count": len(releases),
        "bytes": sum(sizes.values()),
        "retained": sorted(retained),
        "stale_count": len(stale),
        "stale_bytes": sum(sizes[name] for name in stale),
    }


def _transaction_backups_snapshot() -> dict[str, Any]:
    try:
        revisions = [path for path in REVISION_BACKUPS_PATH.iterdir() if path.is_dir() and not path.is_symlink()]
    except OSError:
        revisions = []
    revision_bytes = sum(path_tree_disk_usage(path) for path in revisions)
    baseline_bytes = path_tree_disk_usage(BASELINE_BACKUP_PATH)
    return {
        "revision_count": len(revisions),
        "revision_bytes": revision_bytes,
        "baseline_bytes": baseline_bytes,
        "bytes": revision_bytes + baseline_bytes,
    }


def _disk_capacity_snapshot() -> dict[str, Any]:
    usage = shutil.disk_usage("/")
    used_percent = round(100.0 * usage.used / usage.total, 2) if usage.total else 0.0
    verdict = "failed" if used_percent >= DISK_FAILED_PERCENT else "degraded" if used_percent >= DISK_DEGRADED_PERCENT else "verified"
    return {
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "used_percent": used_percent,
        "verdict": verdict,
    }


def _kernel_oom_snapshot(installed_at: str, *, full_logs: bool) -> dict[str, Any]:
    installed = _parse_timestamp(installed_at)
    now = datetime.now(timezone.utc)
    since = installed.isoformat() if installed is not None and now - installed <= timedelta(days=14) else "24 hours ago" if full_logs else "30 minutes ago"
    result = _run(
        ["journalctl", "-k", "--since", since, "--no-pager", "-o", "json", "--grep=Out of memory: Killed process"],
        timeout=20,
    )
    events: list[dict[str, Any]] = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
                epoch = int(record.get("__REALTIME_TIMESTAMP", 0)) / 1_000_000
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            events.append({"timestamp": datetime.fromtimestamp(epoch, timezone.utc).isoformat(), "message": str(record.get("MESSAGE", ""))[:500], "epoch": epoch})
    now_epoch = now.timestamp()
    counts = {
        "5m": sum(now_epoch - event["epoch"] <= 300 for event in events),
        "30m": sum(now_epoch - event["epoch"] <= 1800 for event in events),
        "24h": sum(now_epoch - event["epoch"] <= 86400 for event in events),
        "since_release": len(events),
    }
    latest = max(events, key=lambda event: event["epoch"], default={})
    latest.pop("epoch", None)
    error = "" if result.returncode in {0, 1} else result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
    return {"counts": counts, "latest": latest, "collector_error": error}


def storage_snapshot(root_filesystem: Mapping[str, Any], installed_at: str, *, full_logs: bool) -> dict[str, Any]:
    security_paths = [BTMP_PATH, *Path("/var/log").glob("btmp.*"), *Path("/var/log").glob("auth.log*")]
    apt_archives_bytes = path_tree_disk_usage(APT_ARCHIVES_PATH)
    apt_lists_bytes = path_tree_disk_usage(APT_LISTS_PATH)
    return {
        "root_filesystem": dict(root_filesystem),
        "capacity": _disk_capacity_snapshot(),
        "managed_releases": _managed_releases_snapshot(),
        "transaction_backups": _transaction_backups_snapshot(),
        "managed_swap_file_bytes": path_tree_disk_usage(MANAGED_SWAP_PATH),
        "journal_bytes": path_tree_disk_usage(JOURNAL_PATH),
        "security_log_bytes": sum(path_tree_disk_usage(path) for path in security_paths),
        "package_cache": {
            "archives_bytes": apt_archives_bytes,
            "lists_bytes": apt_lists_bytes,
            "total_bytes": apt_archives_bytes + apt_lists_bytes,
        },
        "memory": memory_runtime_snapshot(),
        "runtime_events": {"oom_kills": _kernel_oom_snapshot(installed_at, full_logs=full_logs)},
    }


def storage_maintenance(env: Mapping[str, str], *, deep: bool = False) -> dict[str, Any]:
    actions: list[str] = []
    if BTMP_PATH.is_file() and BTMP_PATH.stat().st_size > BTMP_ROTATE_BYTES:
        if not BTMP_LOGROTATE_CONFIG_PATH.is_file():
            raise RuntimeError("managed btmp logrotate policy is missing")
        BTMP_LOGROTATE_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _require_command(
            ["logrotate", "--force", "--state", str(BTMP_LOGROTATE_STATE_PATH), str(BTMP_LOGROTATE_CONFIG_PATH)],
            timeout=120,
        )
        actions.append("btmp-rotated")
    if deep and str(env.get("JOURNAL_LIMIT_ENABLED", "1")).strip().lower() not in {"0", "false", "no", "off"}:
        rotate = _run(["journalctl", "--rotate"], timeout=30)
        vacuum = _run(
            [
                "journalctl",
                f"--vacuum-size={env.get('JOURNAL_SYSTEM_MAX_USE', '256M')}",
                f"--vacuum-time={env.get('JOURNAL_MAX_RETENTION_SEC', '14day')}",
            ],
            timeout=120,
        )
        if rotate.returncode == 0 and vacuum.returncode == 0:
            actions.append("journal-vacuumed")
    return {"changed": bool(actions), "actions": actions}
