from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

if __package__:
    from .network_profile import wireguard_policy_spec
else:
    from network_profile import wireguard_policy_spec

try:
    import fcntl
except ImportError:  # pragma: no cover - local Windows tests only
    class _NoopFcntl:
        LOCK_EX = 0
        LOCK_SH = 0
        LOCK_NB = 0
        LOCK_UN = 0

        @staticmethod
        def flock(_handle: Any, _operation: int) -> None:
            return None

    fcntl = _NoopFcntl()  # type: ignore[assignment]

ROOT = Path("/etc/vpn-stack")
MANIFEST_PATH = ROOT / "render-manifest.json"
ENV_PATH = ROOT / "deployment.env"
STATE_DIR = Path("/var/lib/vpn-stack")
HEALTH_STATE_PATH = STATE_DIR / "health-state.json"
TRANSPORT_STATE_PATH = STATE_DIR / "transport-state.json"
LOCK_PATH = Path("/run/vpn-stack-agent.lock")
TRANSPORT_LOCK_PATH = Path("/run/vpn-stack-transport.lock")
INSTALL_LOCK_PATH = Path("/run/lock/vpn-stack-install.lock")
SINGBOX_CONFIG_PATH = Path("/etc/sing-box/config.json")
NFTABLES_CONFIG_PATH = ROOT / "nftables.conf"
NFTABLES_SERVICE = "vpn-stack-nftables.service"
SYSCTL_PATH = Path("/etc/sysctl.d/90-vpn-stack.conf")
MANIFEST_CAPABILITY_SCHEMA_VERSION = 5
TOPOLOGY_SINGLE = "single"
TOPOLOGY_DUAL = "dual"
NODE_GATEWAY = "gateway"
NODE_EXIT = "exit"
LOCATION_RU = "ru"
LOCATION_FOREIGN = "foreign"
CAP_PUBLIC_FRONT = "public-front"
CAP_ROUTER = "router"
CAP_WEB_ADMIN = "web-admin"
CAP_LOCAL_EGRESS = "local-egress"
CAP_RU_SPLIT_ROUTING = "ru-split-routing"
CAP_INTERSERVER_CLIENT = "interserver-client"
CAP_INTERSERVER_SERVER = "interserver-server"
CAP_NAT_EXIT = "nat-exit"
INTERSERVER_CAPABILITIES = frozenset({CAP_INTERSERVER_CLIENT, CAP_INTERSERVER_SERVER})
SERVICE_UNIT_DEFAULTS = {
    "wireguard": "wg-quick@{wg_interface}.service",
    "nftables": NFTABLES_SERVICE,
    "sing-box": "sing-box.service",
    "resolver": "vpn-stack-dns.service",
    "xray": "vpn-stack-xray.service",
    "admin": "vpn-stack-admin.service",
    "health_timer": "vpn-stack-health.timer",
    "transport": "vpn-stack-transport.service",
}


def contract_has(contract: Mapping[str, Any], capability: str) -> bool:
    return capability in contract.get("capabilities", ())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def acquire_install_read_lock():
    if os.name == "nt":  # Unit tests do not share the Linux installer lock.
        return tempfile.TemporaryFile(mode="w+")
    INSTALL_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = INSTALL_LOCK_PATH.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        handle.close()
        return None
    return handle


def release_install_read_lock(handle: Any) -> None:
    try:
        fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()


def parse_iso_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _observation_age_seconds(value: str, *, now: datetime | None = None) -> float | None:
    parsed = parse_iso_datetime(value)
    if parsed is None:
        return None
    return ((now or datetime.now(timezone.utc)) - parsed).total_seconds()


def iso_age_seconds(value: str, *, now: datetime | None = None) -> float | None:
    # Policy timers retain their existing clamping; evidence must retain clock skew.
    age = _observation_age_seconds(value, now=now)
    return max(0.0, age) if age is not None else None


def run(args: list[str], *, timeout: int = 15, check: bool = False, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout, check=check)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        if check:
            raise RuntimeError(f"command failed: {' '.join(args)}: {exc}") from exc
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def write_json_atomic(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def parse_env(path: Path = ENV_PATH) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def read_json_text(payload: str, default: Any) -> Any:
    try:
        return json.loads(payload)
    except (ValueError, TypeError):
        return default


def default_interface() -> str:
    result = run(["ip", "-j", "route", "show", "default"], timeout=5)
    routes = read_json_text(result.stdout, [])
    return str(routes[0].get("dev", "")) if routes else ""


def _wireguard_policy_rule_present(family: int, spec: Mapping[str, str | int]) -> bool:
    result = run(
        ["ip", f"-{family}", "rule", "show", "priority", str(spec["priority"])],
        timeout=3,
    )
    mark = f"fwmark {int(spec['mark']):#x}"
    table = f"lookup {spec['table']}"
    return result.returncode == 0 and any(mark in line and table in line for line in result.stdout.splitlines())


def _wireguard_policy_route_present(
    family: int,
    destination: str,
    spec: Mapping[str, str | int],
    *,
    table: int | None = None,
) -> bool:
    args = ["ip", f"-{family}", "route", "show"]
    if table is not None:
        args.extend(("table", str(table)))
    args.append(destination)
    result = run(args, timeout=3)
    interface = f"dev {spec['interface']}"
    return result.returncode == 0 and any(interface in line for line in result.stdout.splitlines())


def wireguard_policy_snapshot(env: Mapping[str, str], *, managed: bool) -> dict[str, Any]:
    if not managed:
        return {"managed": False, "ok": True, "checks": {}, "missing": []}
    try:
        spec = wireguard_policy_spec(env)
    except (KeyError, ValueError) as exc:
        return {"managed": True, "ok": False, "checks": {}, "missing": ["spec"], "error": str(exc)[:240]}
    checks = {
        "ipv4_peer_route": _wireguard_policy_route_present(4, f"{spec['ipv4_peer']}/32", spec),
        "ipv6_peer_route": _wireguard_policy_route_present(6, f"{spec['ipv6_peer']}/128", spec),
        "ipv4_default_route": _wireguard_policy_route_present(4, "default", spec, table=int(spec["table"])),
        "ipv6_default_route": _wireguard_policy_route_present(6, "default", spec, table=int(spec["table"])),
        "ipv4_rule": _wireguard_policy_rule_present(4, spec),
        "ipv6_rule": _wireguard_policy_rule_present(6, spec),
    }
    missing = sorted(name for name, present in checks.items() if not present)
    return {
        "managed": True,
        "ok": not missing,
        "interface": spec["interface"],
        "table": spec["table"],
        "mark": spec["mark"],
        "priority": spec["priority"],
        "checks": checks,
        "missing": missing,
    }


def qdisc_snapshot(interface: str) -> dict[str, Any]:
    if not interface:
        return {"qdisc": "", "qdisc_limit": 0, "qdisc_flow_limit": 0, "qdisc_drops": 0, "qdisc_flow_limit_drops": 0}
    result = run(["tc", "-j", "-s", "qdisc", "show", "dev", interface], timeout=3)
    payload = read_json_text(result.stdout, [])
    root = next((item for item in payload if isinstance(item, dict) and item.get("root") is True), {}) if isinstance(payload, list) else {}
    if root:
        options = root.get("options", {}) if isinstance(root.get("options"), dict) else {}
        return {
            "qdisc": str(root.get("kind", "")),
            "qdisc_limit": int(options.get("limit", 0) or 0),
            "qdisc_flow_limit": int(options.get("flow_limit", 0) or 0),
            "qdisc_drops": int(root.get("drops", 0) or 0),
            "qdisc_flow_limit_drops": int(root.get("flows_plimit", 0) or 0),
        }
    fields = result.stdout.split()
    return {
        "qdisc": fields[1] if len(fields) > 1 and fields[0] == "qdisc" else "",
        "qdisc_limit": 0,
        "qdisc_flow_limit": 0,
        "qdisc_drops": 0,
        "qdisc_flow_limit_drops": 0,
    }


def failed_requirements(probes: dict[str, Any]) -> list[str]:
    requirements = probes.get("requirements", {})
    if not isinstance(requirements, dict):
        return []
    return sorted(str(name) for name, passed in requirements.items() if passed is not True)


def probe_requirement(probes: dict[str, Any], name: str) -> bool:
    requirements = probes.get("requirements", {})
    return isinstance(requirements, dict) and requirements.get(name) is True


def probe_path_ok(probes: dict[str, Any], *requirement_names: str) -> bool:
    return any(probe_requirement(probes, name) for name in requirement_names)
