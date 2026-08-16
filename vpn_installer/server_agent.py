from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.dont_write_bytecode = True

try:
    from .log_classifier import (
        BUCKETS,
        accepted_destination_from_line,
        event_id_from_line,
        inbound_destination_from_line,
        inbound_tag_from_line,
        normalize_source,
        source_endpoint_from_line,
        source_from_line,
        split_endpoint,
        summarize_lines,
    )
except ImportError:  # Installed agent runs as a standalone script.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from log_classifier import (  # type: ignore[no-redef]
        BUCKETS,
        accepted_destination_from_line,
        event_id_from_line,
        inbound_destination_from_line,
        inbound_tag_from_line,
        normalize_source,
        source_endpoint_from_line,
        source_from_line,
        split_endpoint,
        summarize_lines,
    )

try:
    from .interserver_transport import (
        HY2_PORT,
        TRANSPORT_CANDIDATE_TAGS,
        TRANSPORT_FAILURE_CONFIRMATIONS,
        TRANSPORT_HY2_TAG,
        TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS,
        TRANSPORT_PREFERRED_TAG,
        TRANSPORT_PROBE_INTERVAL_SECONDS,
        TRANSPORT_RELAY_INBOUND_TAG,
        TRANSPORT_RELAY_PORT,
        TRANSPORT_SELECTOR_TAG,
        TRANSPORT_STATE_SCHEMA_VERSION,
        TRANSPORT_SWITCH_RETRY_BASE_SECONDS,
        TRANSPORT_SWITCH_RETRY_MAX_SECONDS,
        TRANSPORT_WG_TAG,
        evaluate_transport_policy,
        transport_candidate_probe,
        transport_topology_configured,
    )
    TRANSPORT_MODULE_AVAILABLE = True
except ImportError:  # Optional on nodes without an interserver capability.
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from interserver_transport import (  # type: ignore[no-redef]
            HY2_PORT,
            TRANSPORT_CANDIDATE_TAGS,
            TRANSPORT_FAILURE_CONFIRMATIONS,
            TRANSPORT_HY2_TAG,
            TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS,
            TRANSPORT_PREFERRED_TAG,
            TRANSPORT_PROBE_INTERVAL_SECONDS,
            TRANSPORT_RELAY_INBOUND_TAG,
            TRANSPORT_RELAY_PORT,
            TRANSPORT_SELECTOR_TAG,
            TRANSPORT_STATE_SCHEMA_VERSION,
            TRANSPORT_SWITCH_RETRY_BASE_SECONDS,
            TRANSPORT_SWITCH_RETRY_MAX_SECONDS,
            TRANSPORT_WG_TAG,
            evaluate_transport_policy,
            transport_candidate_probe,
            transport_topology_configured,
        )
        TRANSPORT_MODULE_AVAILABLE = True
    except ImportError:
        HY2_PORT = 18443
        TRANSPORT_WG_TAG = "interserver-underlay-wg"
        TRANSPORT_HY2_TAG = "interserver-underlay-hy2"
        TRANSPORT_CANDIDATE_TAGS = (TRANSPORT_WG_TAG, TRANSPORT_HY2_TAG)
        TRANSPORT_FAILURE_CONFIRMATIONS = 2
        TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS = 10
        TRANSPORT_PREFERRED_TAG = TRANSPORT_HY2_TAG
        TRANSPORT_PROBE_INTERVAL_SECONDS = 2
        TRANSPORT_RELAY_INBOUND_TAG = "interserver-overlay-in"
        TRANSPORT_RELAY_PORT = 19091
        TRANSPORT_SELECTOR_TAG = "interserver-underlay-select"
        TRANSPORT_STATE_SCHEMA_VERSION = 11
        TRANSPORT_SWITCH_RETRY_BASE_SECONDS = 30
        TRANSPORT_SWITCH_RETRY_MAX_SECONDS = 300
        TRANSPORT_MODULE_AVAILABLE = False

        def _missing_transport_module(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("interserver transport capability is not installed on this node")

        evaluate_transport_policy = _missing_transport_module
        transport_candidate_probe = _missing_transport_module
        transport_topology_configured = _missing_transport_module

try:
    from .network_profile import FQ_FLOW_LIMIT, FQ_KIND, FQ_PACKET_LIMIT, wireguard_policy_spec
except ImportError:  # Installed agent runs as a standalone script.
    from network_profile import FQ_FLOW_LIMIT, FQ_KIND, FQ_PACKET_LIMIT, wireguard_policy_spec  # type: ignore[no-redef]

try:
    from .diagnostics import SCHEMA_VERSION as DIAGNOSTICS_SCHEMA_VERSION, COLLECTOR_NAMES, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot, classify_interserver_adaptation
except ImportError:  # Installed agent runs as a standalone script.
    from diagnostics import SCHEMA_VERSION as DIAGNOSTICS_SCHEMA_VERSION, COLLECTOR_NAMES, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot, classify_interserver_adaptation  # type: ignore[no-redef]

try:
    from .release_integrity import release_tree_digest
except ImportError:  # Installed agent runs as a standalone script.
    from release_integrity import release_tree_digest  # type: ignore[no-redef]

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

SCHEMA_VERSION = DIAGNOSTICS_SCHEMA_VERSION
ACCEPTANCE_REQUIRED_TARGETS = ("https://github.com/", "https://www.google.com/generate_204")
ACCEPTANCE_OBSERVED_TARGETS = ("https://telegram.org/",)
PROBE_CONFIRMATION_DELAY_SECONDS = 2
EXTERNAL_CAPABILITY_REQUIREMENTS = frozenset({"ipv6_literal", "ipv6_literal_via_router"})
OPTIONAL_TRANSPORT_REQUIREMENTS = frozenset(
    {
        "foreign_domains_via_wg",
        "wireguard_candidate_ipv4",
        "wireguard_candidate_identity",
        "hysteria_candidate_reachable",
    }
)
COMPLETE_LOG_RETENTION_MINUTES = 14 * 24 * 60
PRIVATE_REJECT_CORRELATION_MAX_AGE_SECONDS = 900
PRIVATE_REJECT_INBOUND_TAGS = ("router-in", "public-hy2-in")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
FRONT_LOSS_MIN_BYTES = 1_000_000
FRONT_LOSS_DEGRADED_PERCENT = 2.0
FRONT_INTERVAL_LOSS_MIN_BYTES = 256 * 1024
FRONT_INTERVAL_LOSS_MIN_RETRANSMISSIONS = 3
FRONT_INTERVAL_LOSS_DEGRADED_PERCENT = 1.0
FRONT_SMALL_FLOW_MIN_BYTES = 8_192
FRONT_SMALL_FLOW_MIN_RETRANSMISSIONS = 3
FRONT_SMALL_FLOW_DEGRADED_PERCENT = 10.0
FRONT_RTT_MIN_SAMPLES = 3
FRONT_RTT_DEGRADED_MS = 250
FRONT_RTT_INFLATION_FACTOR = 3
FRONT_RTO_DEGRADED_MS = 1_000
FRONT_COUNTER_MAX_INTERVAL_SECONDS = 300
FRONT_CURRENT_ACTIVITY_MAX_IDLE_MS = 30_000
REALITY_PENDING_HANDSHAKE_DEGRADED = 5
LOG_CONTEXT_MAX_EVENT_IDS = 500
PROBLEM_LOG_GREP = (
    "ERROR|FATAL|processed invalid connection|accepted tcp:disabled[.]invalid|"
    "connection rejected|mux connection closed|EOF|connection reset|using outbound/vless"
)
XRAY_FRONT_LOG_GREP = "accepted (tcp|udp):|REALITY: processed invalid connection"
CONNTRACK_FULL_GREP = "nf_conntrack.*table full"
ROOT = Path("/etc/vpn-stack")
MANIFEST_PATH = ROOT / "render-manifest.json"
ENV_PATH = ROOT / "deployment.env"
RELEASES_PATH = ROOT / "releases"
CURRENT_RELEASE_PATH = ROOT / "current"
OPERATOR_MANIFEST_PATH = ROOT / "operator-state.json"
ADMIN_RULES_PATH = ROOT / "admin-routing-rules.json"
STATE_DIR = Path("/var/lib/vpn-stack")
HEALTH_STATE_PATH = STATE_DIR / "health-state.json"
TRANSPORT_STATE_PATH = STATE_DIR / "transport-state.json"
LOCK_PATH = Path("/run/vpn-stack-agent.lock")
TRANSPORT_LOCK_PATH = Path("/run/vpn-stack-transport.lock")
INSTALL_LOCK_PATH = Path("/run/lock/vpn-stack-install.lock")
SINGBOX_CONFIG_PATH = Path("/etc/sing-box/config.json")
XRAY_CONFIG_PATH = Path("/etc/xray/config.json")
NFTABLES_CONFIG_PATH = ROOT / "nftables.conf"
NFTABLES_SERVICE = "vpn-stack-nftables.service"
SYSCTL_PATH = Path("/etc/sysctl.d/90-vpn-stack.conf")
RESOLV_CONF_PATH = Path("/etc/resolv.conf")
RESOLVED_DROPIN_PATH = Path("/etc/systemd/resolved.conf.d/90-vpn-stack.conf")
RESOLVED_STUB_PATH = "/run/systemd/resolve/stub-resolv.conf"
FSTAB_PATH = Path("/etc/fstab")
PROC_MOUNTS_PATH = Path("/proc/self/mounts")
EXT4_SYSFS_ROOT = Path("/sys/fs/ext4")
SYS_DEV_BLOCK_ROOT = Path("/sys/dev/block")

MANIFEST_CAPABILITY_SCHEMA_VERSION = 3
LEGACY_RUNTIME_REMOVE_IN = "0.20.1"
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
LEGACY_ROLE_GATEWAY = "ru-gateway"
LEGACY_ROLE_EXIT = "foreign-exit"
SERVICE_UNIT_DEFAULTS = {
    "wireguard": "wg-quick@{wg_interface}.service",
    "nftables": NFTABLES_SERVICE,
    "sing-box": "sing-box.service",
    "resolver": "systemd-resolved.service",
    "xray": "vpn-stack-xray.service",
    "admin": "vpn-stack-admin.service",
    "health_timer": "vpn-stack-health.timer",
    "transport": "vpn-stack-transport.service",
}


def _string_array(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise RuntimeError(f"manifest {field} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise RuntimeError(f"manifest {field} must not contain duplicates")
    return tuple(value)


def _expected_capabilities(
    topology: str,
    node_id: str,
    *,
    admin_web_enabled: bool = True,
) -> frozenset[str]:
    if node_id == NODE_GATEWAY:
        capabilities = {CAP_PUBLIC_FRONT, CAP_ROUTER, CAP_LOCAL_EGRESS}
        if admin_web_enabled:
            capabilities.add(CAP_WEB_ADMIN)
        if topology == TOPOLOGY_DUAL:
            capabilities.update({CAP_RU_SPLIT_ROUTING, CAP_INTERSERVER_CLIENT})
        return frozenset(capabilities)
    if topology == TOPOLOGY_DUAL and node_id == NODE_EXIT:
        return frozenset({CAP_INTERSERVER_SERVER, CAP_NAT_EXIT})
    raise RuntimeError(f"node {node_id!r} is invalid for {topology!r} topology")


def _expected_required_services(capabilities: frozenset[str]) -> tuple[str, ...]:
    services = ["nftables", "sing-box", "resolver", "health_timer"]
    if CAP_PUBLIC_FRONT in capabilities:
        services.append("xray")
    if CAP_WEB_ADMIN in capabilities:
        services.append("admin")
    if capabilities & INTERSERVER_CAPABILITIES:
        services.append("wireguard")
    if CAP_INTERSERVER_CLIENT in capabilities:
        services.append("transport")
    return tuple(services)


def _compatibility_role_for_node(node_id: str) -> str:
    return LEGACY_ROLE_GATEWAY if node_id == NODE_GATEWAY else LEGACY_ROLE_EXIT


def _adapt_legacy_runtime_manifest(manifest: Mapping[str, Any], env: Mapping[str, str]) -> dict[str, Any] | None:
    """Boundary adapter for schema 1/2 manifests. Remove in 0.20.1."""

    raw_schema = manifest.get("schema_version")
    try:
        schema = int(raw_schema)
    except (TypeError, ValueError):
        schema = 0
    if schema not in {0, 1, 2}:
        return None
    role = str(manifest.get("role") or env.get("ROLE") or "")
    if schema == 0 and role not in {LEGACY_ROLE_GATEWAY, LEGACY_ROLE_EXIT}:
        return None

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or not artifacts:
        legacy_hashes = manifest.get("artifact_sha256", {})
        artifacts = {
            str(name): {"sha256": str(digest), "install_path": ""}
            for name, digest in legacy_hashes.items()
        } if isinstance(legacy_hashes, Mapping) else {}

    if role == LEGACY_ROLE_GATEWAY:
        node_id = NODE_GATEWAY
        location = LOCATION_RU
        capabilities = _expected_capabilities(TOPOLOGY_DUAL, node_id)
        required_services = ("wireguard", "nftables", "sing-box", "resolver", "xray", "admin", "health_timer", "transport")
    elif role == LEGACY_ROLE_EXIT:
        node_id = NODE_EXIT
        location = LOCATION_FOREIGN
        capabilities = _expected_capabilities(TOPOLOGY_DUAL, node_id)
        required_services = ("wireguard", "nftables", "sing-box", "resolver", "health_timer")
    else:
        return {
            "contract": None,
            "artifacts": dict(artifacts),
            "drift_manifest_valid": schema >= 2,
            "error": "legacy manifest does not identify a supported role",
        }
    return {
        "contract": {
            "topology": TOPOLOGY_DUAL,
            "node_id": node_id,
            "location": location,
            "capabilities": capabilities,
            "required_services": required_services,
            "service_units": {
                name: SERVICE_UNIT_DEFAULTS[name]
                for name in required_services
            },
            "role": role,
            "migration": {
                "state": "deprecated",
                "source_schema": schema,
                "target_schema": MANIFEST_CAPABILITY_SCHEMA_VERSION,
                "remove_in": LEGACY_RUNTIME_REMOVE_IN,
                "message": "legacy role manifest is accepted only at the runtime boundary",
            },
        },
        "artifacts": dict(artifacts),
        "drift_manifest_valid": schema >= 2,
    }


def runtime_contract(manifest: Mapping[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    """Validate the installed node contract without importing installer code."""

    legacy = _adapt_legacy_runtime_manifest(manifest, env)
    if legacy is not None:
        if not isinstance(legacy.get("contract"), Mapping):
            raise RuntimeError(str(legacy.get("error") or "legacy manifest is invalid"))
        return dict(legacy["contract"])
    raw_schema = manifest.get("schema_version")
    try:
        schema = int(raw_schema)
    except (TypeError, ValueError):
        schema = 0
    if schema != MANIFEST_CAPABILITY_SCHEMA_VERSION:
        raise RuntimeError(f"unsupported render manifest schema: {raw_schema!r}")

    topology = str(manifest.get("topology", ""))
    node_id = str(manifest.get("node_id", ""))
    location = str(manifest.get("location", ""))
    if topology not in {TOPOLOGY_SINGLE, TOPOLOGY_DUAL}:
        raise RuntimeError(f"unsupported manifest topology: {topology!r}")
    if node_id not in {NODE_GATEWAY, NODE_EXIT}:
        raise RuntimeError(f"unsupported manifest node: {node_id!r}")
    if location not in {LOCATION_RU, LOCATION_FOREIGN}:
        raise RuntimeError(f"unsupported manifest location: {location!r}")
    if topology == TOPOLOGY_SINGLE and node_id != NODE_GATEWAY:
        raise RuntimeError("single topology cannot install an exit node")
    if topology == TOPOLOGY_DUAL and ((node_id == NODE_GATEWAY and location != LOCATION_RU) or (node_id == NODE_EXIT and location != LOCATION_FOREIGN)):
        raise RuntimeError("dual topology node location does not match the contract")

    capabilities = frozenset(_string_array(manifest.get("capabilities"), "capabilities"))
    admin_web_enabled = str(env.get("ADMIN_WEB_ENABLED", "1")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    expected_capabilities = _expected_capabilities(
        topology,
        node_id,
        admin_web_enabled=admin_web_enabled,
    )
    if capabilities != expected_capabilities:
        raise RuntimeError("manifest capabilities do not match topology and node")
    required_services = _string_array(manifest.get("required_services"), "required_services")
    if required_services != _expected_required_services(capabilities):
        raise RuntimeError("manifest required services do not match node capabilities")
    node = manifest.get("node")
    if not isinstance(node, Mapping):
        raise RuntimeError("manifest node descriptor is missing")
    node_contract = (
        str(node.get("id", "")),
        str(node.get("location", "")),
        frozenset(_string_array(node.get("capabilities"), "node.capabilities")),
        _string_array(node.get("required_services"), "node.required_services"),
    )
    if node_contract != (node_id, location, capabilities, required_services):
        raise RuntimeError("manifest node descriptor conflicts with canonical fields")

    install_plan = manifest.get("install_plan")
    if not isinstance(install_plan, Mapping):
        raise RuntimeError("manifest install plan is missing")
    for field, expected in (("topology", topology), ("node_id", node_id), ("location", location)):
        if str(install_plan.get(field, "")) != expected:
            raise RuntimeError(f"install plan {field} conflicts with manifest")
    if frozenset(_string_array(install_plan.get("capabilities"), "install_plan.capabilities")) != capabilities:
        raise RuntimeError("install plan capabilities conflict with manifest")
    if _string_array(install_plan.get("required_services"), "install_plan.required_services") != required_services:
        raise RuntimeError("install plan required services conflict with manifest")
    raw_services = install_plan.get("services")
    if not isinstance(raw_services, list) or not all(isinstance(item, Mapping) for item in raw_services):
        raise RuntimeError("install plan services must be an array of objects")
    service_units: dict[str, str] = {}
    for item in raw_services:
        name = str(item.get("name", ""))
        unit = str(item.get("unit", ""))
        if not name or not unit or name in service_units:
            raise RuntimeError("install plan contains an invalid service entry")
        service_units[name] = unit
    if tuple(service_units) != required_services:
        raise RuntimeError("install plan service entries conflict with required services")
    if capabilities & INTERSERVER_CAPABILITIES and not TRANSPORT_MODULE_AVAILABLE:
        raise RuntimeError("interserver transport module is missing for an interserver-capable node")

    return {
        "topology": topology,
        "node_id": node_id,
        "location": location,
        "capabilities": capabilities,
        "required_services": required_services,
        "service_units": service_units,
        "role": _compatibility_role_for_node(node_id),
        "migration": {"state": "native", "source_schema": schema, "target_schema": schema},
    }


def contract_has(contract: Mapping[str, Any], capability: str) -> bool:
    return capability in contract.get("capabilities", ())


def installed_runtime_contract() -> dict[str, Any]:
    manifest = read_json(MANIFEST_PATH, {})
    return runtime_contract(manifest if isinstance(manifest, Mapping) else {}, parse_env())

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


def iso_age_seconds(value: str, *, now: datetime | None = None) -> float | None:
    parsed = parse_iso_datetime(value)
    if parsed is None:
        return None
    age = ((now or datetime.now(timezone.utc)) - parsed.astimezone(timezone.utc)).total_seconds()
    return max(0.0, age)


def recent_observation(payload: Any, *, max_age_seconds: int) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    age = iso_age_seconds(str(payload.get("observed_at", "")))
    return payload if age is not None and age <= max_age_seconds else {}


def release_scoped_observation(payload: dict[str, Any], installed_at: str) -> dict[str, Any]:
    """Exclude health evidence collected before the active release was installed."""

    if not payload or not installed_at:
        return payload
    observed = parse_iso_datetime(str(payload.get("observed_at", "")))
    release_started = parse_iso_datetime(installed_at)
    if release_started is None:
        return payload
    if observed is None or observed < release_started:
        return {}
    return payload


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def release_tree_snapshot(
    current_path: Path | None = None,
    releases_path: Path | None = None,
    *,
    require_symlink: bool = True,
) -> dict[str, str]:
    current = current_path or CURRENT_RELEASE_PATH
    releases = releases_path or RELEASES_PATH
    result = {
        "path": str(current),
        "resolved_path": "",
        "digest": "",
        "expected_suffix": "",
        "state": "missing",
    }
    if require_symlink and not current.is_symlink():
        result["state"] = "not-symlink" if current.exists() else "missing"
        return result
    try:
        resolved = current.resolve(strict=True)
        releases_resolved = releases.resolve(strict=True)
    except OSError:
        return result
    result["resolved_path"] = str(resolved)
    if not resolved.is_dir() or resolved.parent != releases_resolved:
        result["state"] = "outside-releases"
        return result
    tree_digest = release_tree_digest(resolved)
    if not tree_digest:
        result["state"] = "unreadable"
        return result
    expected_suffix = f"-{tree_digest[:12]}"
    result["digest"] = tree_digest
    result["expected_suffix"] = expected_suffix
    result["state"] = "ok" if resolved.name.endswith(expected_suffix) else "mutated"
    return result


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


def service_state(name: str) -> str:
    result = run(["systemctl", "is-active", name], timeout=5)
    return result.stdout.strip() or "unknown"


def journal_lines_since(unit: str, since: str) -> list[str]:
    result = run(["journalctl", "-u", unit, "--since", since, "--no-pager", "-o", "short-iso"], timeout=20)
    return result.stdout.splitlines() if result.returncode == 0 else []


def journal_lines(unit: str, minutes: int) -> list[str]:
    return journal_lines_since(unit, f"{minutes} minutes ago")


def journal_filtered_lines(unit: str, minutes: int, pattern: str) -> list[str]:
    result = run(
        ["journalctl", "-u", unit, "--since", f"{minutes} minutes ago", "--no-pager", "-o", "short-iso", f"--grep={pattern}"],
        timeout=30,
    )
    return result.stdout.splitlines() if result.returncode == 0 else []


def journal_record_message(record: Mapping[str, Any]) -> str:
    raw_message = record.get("MESSAGE", "")
    if isinstance(raw_message, str):
        message = raw_message
    elif isinstance(raw_message, list):
        try:
            message = bytes(raw_message).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return ""
    else:
        return ""
    return ANSI_ESCAPE_RE.sub("", message)


def journal_command_error(result: subprocess.CompletedProcess[str]) -> str:
    if result.returncode == 0 or (result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip()):
        return ""
    return (result.stderr.strip() or f"journalctl exited with {result.returncode}")[:240]


def _parse_journal_events(result: subprocess.CompletedProcess[str]) -> tuple[list[tuple[float, str]], int]:
    events: list[tuple[float, str]] = []
    malformed = 0
    for raw_line in result.stdout.splitlines():
        try:
            record = json.loads(raw_line)
            timestamp = float(record["__REALTIME_TIMESTAMP"]) / 1_000_000
            message = journal_record_message(record)
            unit = str(record.get("_SYSTEMD_UNIT") or record.get("SYSLOG_IDENTIFIER") or "unknown")
            if not message:
                raise ValueError("journal message is empty or malformed")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            malformed += 1
            continue
        events.append((timestamp, f"[unit={unit}] {message}"))
    return events, malformed


def _journal_event_context(minutes: int, problem_events: list[tuple[float, str]]) -> list[tuple[float, str]]:
    event_ids = list(
        dict.fromkeys(
            event_id
            for _timestamp, line in problem_events
            if "[unit=sing-box.service]" in line and (event_id := event_id_from_line(line))
        )
    )[-LOG_CONTEXT_MAX_EVENT_IDS:]
    if not event_ids:
        return []
    event_pattern = "|".join(re.escape(event_id) for event_id in event_ids)
    result = run(
        [
            "journalctl",
            "-u",
            "sing-box.service",
            "--since",
            f"{minutes} minutes ago",
            "--no-pager",
            "--output=json",
            rf"--grep=\[(?:\x1B\[[0-9;]*m)*(?:{event_pattern})\b",
        ],
        timeout=30,
    )
    if journal_command_error(result):
        return []
    context, _malformed = _parse_journal_events(result)
    return [
        event
        for event in context
        if inbound_destination_from_line(event[1]) or "dns: lookup succeed for " in event[1]
    ]


def journal_problem_events(minutes: int) -> tuple[list[tuple[float, str]], str]:
    result = run(
        [
            "journalctl",
            "-u",
            "sing-box.service",
            "-u",
            "vpn-stack-xray.service",
            "--since",
            f"{minutes} minutes ago",
            "--no-pager",
            "--output=json",
            f"--grep={PROBLEM_LOG_GREP}",
        ],
        timeout=30,
    )
    command_error = journal_command_error(result)
    if command_error:
        return [], command_error
    events, malformed = _parse_journal_events(result)
    events.extend(_journal_event_context(minutes, events))
    if malformed:
        return events, f"journalctl returned {malformed} malformed JSON record(s)"
    return events, ""


def _private_reject_policy(config: Any, manifest: dict[str, Any], contract: Mapping[str, Any]) -> dict[str, Any]:
    rules = config.get("route", {}).get("rules", []) if isinstance(config, dict) else []
    if not isinstance(rules, list):
        rules = []
    catchall_index = next(
        (
            index
            for index, rule in enumerate(rules)
            if isinstance(rule, dict)
            and isinstance(rule.get("ip_cidr"), list)
            and "0.0.0.0/0" in rule["ip_cidr"]
        ),
        len(rules),
    )
    guard_indexes = [
        index
        for index, rule in enumerate(rules)
        if isinstance(rule, dict)
        and rule.get("ip_is_private") is True
        and rule.get("action") == "reject"
        and rule.get("method") == "default"
        and rule.get("no_drop") is True
    ]
    drift = str(manifest.get("drift", "unknown"))
    ordered = any(index < catchall_index for index in guard_indexes)
    has_router = contract_has(contract, CAP_ROUTER)
    verified = has_router and drift == "none" and ordered
    reason = ""
    if not has_router:
        reason = f"installed role is {contract.get('role') or 'unknown'}"
    elif drift != "none":
        reason = f"installed drift is {drift}"
    elif not ordered:
        reason = "private/fake reject guard is missing or ordered after the IPv4 catch-all"
    return {
        "verified": verified,
        "reason": reason,
        "drift": drift,
        "config_sha256": sha256_file(SINGBOX_CONFIG_PATH),
        "guard_indexes": guard_indexes,
        "ipv4_catchall_index": catchall_index if catchall_index < len(rules) else None,
    }


def private_reject_correlations(since: str, inbound: str, targets: Iterable[str]) -> dict[str, Any]:
    if inbound not in PRIVATE_REJECT_INBOUND_TAGS:
        raise ValueError(f"unsupported private reject inbound: {inbound}")
    marker = parse_iso_datetime(since)
    if marker is None:
        raise ValueError("private reject correlation marker is invalid")
    age_seconds = (datetime.now(timezone.utc) - marker).total_seconds()
    if age_seconds < -30 or age_seconds > PRIVATE_REJECT_CORRELATION_MAX_AGE_SECONDS:
        raise ValueError(f"private reject correlation marker age is out of range: {age_seconds:.1f}s")

    normalized_targets: list[str] = []
    for target in targets:
        host, port = split_endpoint(target)
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError(f"private reject target is not an IP literal: {target}") from exc
        if port is None or not 1 <= port <= 65535 or not address.is_private:
            raise ValueError(f"private reject target is outside the guarded private address space: {target}")
        endpoint = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
        if endpoint not in normalized_targets:
            normalized_targets.append(endpoint)
    if not normalized_targets:
        raise ValueError("at least one private reject target is required")

    manifest = manifest_snapshot()
    raw_manifest = manifest.get("manifest", {})
    try:
        contract = runtime_contract(raw_manifest if isinstance(raw_manifest, Mapping) else {}, parse_env())
    except RuntimeError:
        contract = {}
    policy = _private_reject_policy(read_json(SINGBOX_CONFIG_PATH, {}), manifest, contract)
    evidence = {
        target: {"target": target, "correlated": False, "correlation_id": ""}
        for target in normalized_targets
    }
    response: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "since": marker.isoformat(),
        "inbound": inbound,
        "policy": policy,
        "targets": list(evidence.values()),
        "verdict": "failed" if not policy["verified"] else "inconclusive",
    }
    if not policy["verified"]:
        response["reason"] = policy["reason"]
        return response

    journal = run(
        [
            "journalctl",
            "-u",
            "sing-box.service",
            "--since",
            marker.isoformat(),
            "--no-pager",
            "--output=json",
            "--grep=inbound connection to",
        ],
        timeout=20,
    )
    command_error = journal_command_error(journal)
    if command_error:
        response["verdict"] = "failed"
        response["reason"] = command_error
        return response

    marker_epoch = marker.timestamp()
    latest: dict[str, tuple[float, str, str]] = {}
    for raw_line in journal.stdout.splitlines():
        try:
            record = json.loads(raw_line)
            timestamp = float(record["__REALTIME_TIMESTAMP"]) / 1_000_000
            message = journal_record_message(record)
            if not message:
                raise ValueError("journal message is empty or malformed")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        destination = inbound_destination_from_line(message)
        event_id = event_id_from_line(message)
        if timestamp < marker_epoch or inbound_tag_from_line(message) != inbound or not event_id:
            continue
        host, port = split_endpoint(destination)
        if port is None:
            continue
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            continue
        endpoint = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
        if endpoint in evidence and (endpoint not in latest or timestamp > latest[endpoint][0]):
            latest[endpoint] = (timestamp, event_id, str(record.get("__CURSOR", "")))

    for target, (timestamp, event_id, cursor) in latest.items():
        item = evidence[target]
        item.update(
            {
                "correlated": True,
                "correlation_id": f"sing-box:{event_id}:{int(timestamp * 1_000_000)}",
                "event_id": event_id,
                "journal_cursor": cursor,
            }
        )
    response["targets"] = list(evidence.values())
    if all(item["correlated"] for item in evidence.values()):
        response["verdict"] = "verified"
    else:
        response["reason"] = "one or more private/fake probe events were not observed after the marker"
    return response


def summarize_problem_windows(*, full_logs: bool, fresh_since: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    windows = (5, 30, 1440) if full_logs else (5,)
    now = time.time()
    try:
        fresh_epoch = datetime.fromisoformat(fresh_since.replace("Z", "+00:00")).timestamp()
    except ValueError:
        fresh_epoch = now - 300
    fresh_age_minutes = max(0, int((now - fresh_epoch + 59) // 60))
    query_minutes = max(windows)
    if fresh_age_minutes <= COMPLETE_LOG_RETENTION_MINUTES:
        query_minutes = max(query_minutes, fresh_age_minutes)
    events, collector_error = journal_problem_events(query_minutes)
    summaries = {
        str(minutes): summarize_lines(line for timestamp, line in events if timestamp >= now - minutes * 60)
        for minutes in windows
    }
    fresh = summarize_lines(line for timestamp, line in events if timestamp >= fresh_epoch)
    return summaries, fresh, collector_error


def fresh_log_since() -> tuple[str, int]:
    value = installed_at_value()
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        age_minutes = max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds() / 60))
        if age_minutes <= COMPLETE_LOG_RETENTION_MINUTES:
            return value, age_minutes
    except (OSError, TypeError, ValueError):
        pass
    return "5 minutes ago", 5


def installed_at_value() -> str:
    for name in ("installed-at", "installed_at"):
        try:
            return (ROOT / name).read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return ""


def service_exec_path(service: str) -> str:
    result = run(["systemctl", "show", service, "--property=ExecStart", "--value"], timeout=5)
    if result.returncode != 0:
        return ""
    match = re.search(r"(?:^|[ {;])path=([^ ;}]+)", result.stdout)
    return match.group(1) if match else ""


def manifest_snapshot() -> dict[str, Any]:
    manifest = read_json(MANIFEST_PATH, {})
    manifest_mapping = manifest if isinstance(manifest, Mapping) else {}
    env = parse_env()
    legacy = _adapt_legacy_runtime_manifest(manifest_mapping, env)
    try:
        legacy_contract = legacy.get("contract") if legacy is not None else None
        contract = dict(legacy_contract) if isinstance(legacy_contract, Mapping) else runtime_contract(manifest_mapping, env)
    except RuntimeError:
        contract = {}
    entries = legacy["artifacts"] if legacy is not None else manifest_mapping.get("artifacts", {})
    checked: dict[str, dict[str, str]] = {}
    mismatches: list[str] = []
    for name, raw_entry in sorted(entries.items()):
        entry = raw_entry if isinstance(raw_entry, dict) else {"sha256": str(raw_entry)}
        expected = str(entry.get("sha256", ""))
        install_path = str(entry.get("install_path", ""))
        actual_path = Path(install_path) if install_path else None
        actual = sha256_file(actual_path) if actual_path else ""
        state = "untracked"
        if actual_path:
            state = "ok" if actual == expected and actual else "missing" if not actual else "mutated"
            if state != "ok":
                mismatches.append(name)
        checked[name] = {"expected_sha256": expected, "actual_sha256": actual, "path": install_path, "state": state}
    asset_entries = manifest.get("assets", {}) if isinstance(manifest, dict) else {}
    checked_assets: dict[str, dict[str, str]] = {}
    for name, raw_entry in sorted(asset_entries.items()):
        entry = raw_entry if isinstance(raw_entry, dict) else {"sha256": str(raw_entry)}
        expected = str(entry.get("sha256", ""))
        actual_path = Path(str(entry.get("install_path", "")))
        actual = sha256_file(actual_path)
        state = "ok" if actual == expected and actual else "missing" if not actual else "mutated"
        if state != "ok":
            mismatches.append(f"asset:{name}")
        checked_assets[name] = {"expected_sha256": expected, "actual_sha256": actual, "path": str(actual_path), "state": state}
    binary_entries = manifest.get("binaries", {}) if isinstance(manifest, dict) else {}
    checked_binaries: dict[str, dict[str, str]] = {}
    for name, raw_entry in sorted(binary_entries.items()):
        if not isinstance(raw_entry, dict):
            continue
        expected = str(raw_entry.get("sha256", ""))
        actual_path = Path(str(raw_entry.get("path", "")))
        actual = sha256_file(actual_path) if expected and actual_path else ""
        state = "ok" if actual and actual == expected else "missing" if not actual else "mutated"
        service = str(raw_entry.get("service", ""))
        runtime_exec_path = service_exec_path(service) if service else ""
        if state == "ok" and service and runtime_exec_path != str(actual_path):
            state = "wrong-exec"
        if state != "ok":
            mismatches.append(f"binary:{name}")
        checked_binaries[name] = {
            "expected_sha256": expected,
            "actual_sha256": actual,
            "path": str(actual_path),
            "service": service,
            "runtime_exec_path": runtime_exec_path,
            "state": state,
        }
    installed_env_sha256 = sha256_file(ENV_PATH)
    expected_env_sha256 = str(manifest.get("env_sha256", "")) if isinstance(manifest, dict) else ""
    if not installed_env_sha256 or installed_env_sha256 != expected_env_sha256:
        mismatches.append("deployment.env")

    release_tree = release_tree_snapshot()
    if release_tree["state"] != "ok":
        mismatches.append("release-tree")

    manifest_capabilities = frozenset(str(value) for value in contract.get("capabilities", ()))
    has_operator_state = CAP_WEB_ADMIN in manifest_capabilities
    operator: dict[str, Any] = {"state": "not-applicable"}
    if has_operator_state:
        operator_manifest = read_json(OPERATOR_MANIFEST_PATH, {})
        actual_hashes = {
            "base_sha256": sha256_file(ROOT / "sing-box.base.json"),
            "rules_sha256": sha256_file(ADMIN_RULES_PATH),
            "effective_config_sha256": sha256_file(SINGBOX_CONFIG_PATH),
        }
        operator_mismatches = [
            name
            for name, actual in actual_hashes.items()
            if not actual or actual != str(operator_manifest.get(name, ""))
        ]
        operator = {
            "state": "ok" if operator_manifest and not operator_mismatches else "mutated" if operator_manifest else "missing",
            "generation": str(operator_manifest.get("generation", "")),
            "mismatches": operator_mismatches,
            "actual": actual_hashes,
        }
        if operator["state"] != "ok":
            mismatches.append("operator-state")
    elif contract.get("node_id") == NODE_EXIT:
        expected_config = str(manifest.get("config_sha256", ""))
        active_config = sha256_file(SINGBOX_CONFIG_PATH)
        operator = {
            "state": "ok" if expected_config and active_config == expected_config else "mutated",
            "effective_config_sha256": active_config,
        }
        if operator["state"] != "ok":
            mismatches.append("effective-config")
    manifest_valid = bool(legacy.get("drift_manifest_valid")) if legacy is not None else bool(contract)
    return {
        "manifest": manifest,
        "files": checked,
        "assets": checked_assets,
        "binaries": checked_binaries,
        "release_tree": release_tree,
        "operator": operator,
        "mismatches": mismatches,
        "drift": "none" if manifest_valid and not mismatches else "server-mutated" if mismatches else "unknown",
        "installed_env_sha256": installed_env_sha256,
        "expected_env_sha256": expected_env_sha256,
    }


def wireguard_snapshot(interface: str) -> dict[str, Any]:
    result = run(["wg", "show", interface, "dump"], timeout=5)
    peers: list[dict[str, Any]] = []
    if result.returncode == 0:
        for line in result.stdout.splitlines()[1:]:
            fields = line.split("\t")
            if len(fields) < 8:
                continue
            handshake = int(fields[4] or 0)
            peers.append({
                "public_key": fields[0],
                "endpoint": fields[2],
                "allowed_ips": fields[3],
                "latest_handshake": handshake,
                "handshake_age_s": max(0, int(time.time()) - handshake) if handshake else None,
                "transfer_rx": int(fields[5] or 0),
                "transfer_tx": int(fields[6] or 0),
            })
    link = run(["ip", "-j", "link", "show", "dev", interface], timeout=5)
    link_data = read_json_text(link.stdout, []) if link.returncode == 0 else []
    return {"interface": interface, "state": "up" if link_data and "UP" in link_data[0].get("flags", []) else "down", "peers": peers}


def read_json_text(payload: str, default: Any) -> Any:
    try:
        return json.loads(payload)
    except (ValueError, TypeError):
        return default


def interface_counters(names: Iterable[str]) -> dict[str, dict[str, int]]:
    fields = (
        "rx_bytes",
        "rx_packets",
        "rx_dropped",
        "rx_errors",
        "rx_missed_errors",
        "rx_nohandler",
        "rx_otherhost_dropped",
        "tx_bytes",
        "tx_packets",
        "tx_dropped",
        "tx_errors",
    )
    result: dict[str, dict[str, int]] = {}
    for name in dict.fromkeys(value for value in names if value):
        stats: dict[str, int] = {}
        for field in fields:
            try:
                stats[field] = int((Path("/sys/class/net") / name / "statistics" / field).read_text().strip())
            except (OSError, ValueError):
                stats[field] = 0
        result[name] = stats
    return result


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


def apply_wireguard_policy(env: Mapping[str, str]) -> dict[str, Any]:
    spec = wireguard_policy_spec(env)
    before = wireguard_policy_snapshot(env, managed=True)
    commands = {
        "ipv4_peer_route": ["ip", "-4", "route", "replace", f"{spec['ipv4_peer']}/32", "dev", str(spec["interface"])],
        "ipv6_peer_route": ["ip", "-6", "route", "replace", f"{spec['ipv6_peer']}/128", "dev", str(spec["interface"])],
        "ipv4_default_route": ["ip", "-4", "route", "replace", "default", "dev", str(spec["interface"]), "table", str(spec["table"])],
        "ipv6_default_route": ["ip", "-6", "route", "replace", "default", "dev", str(spec["interface"]), "table", str(spec["table"])],
        "ipv4_rule": ["ip", "-4", "rule", "add", "fwmark", str(spec["mark"]), "table", str(spec["table"]), "priority", str(spec["priority"])],
        "ipv6_rule": ["ip", "-6", "rule", "add", "fwmark", str(spec["mark"]), "table", str(spec["table"]), "priority", str(spec["priority"])],
    }
    for name in before.get("missing", []):
        command = commands.get(str(name))
        if command is None:
            continue
        result = run(command, timeout=10)
        if result.returncode != 0:
            raise RuntimeError(f"unable to apply WireGuard policy {name}: {result.stderr.strip()[:240]}")
    after = wireguard_policy_snapshot(env, managed=True)
    if not after.get("ok"):
        raise RuntimeError(f"WireGuard policy did not converge: {','.join(after.get('missing', []))}")
    return {**after, "changed": bool(before.get("missing"))}


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


def apply_interface_qdisc(interface: str) -> dict[str, Any]:
    before = qdisc_snapshot(interface)
    expected = {"qdisc": FQ_KIND, "qdisc_limit": FQ_PACKET_LIMIT, "qdisc_flow_limit": FQ_FLOW_LIMIT}
    if all(before.get(name) == value for name, value in expected.items()):
        return {"changed": False, **before}
    result = run(
        ["tc", "qdisc", "replace", "dev", interface, "root", FQ_KIND, "limit", str(FQ_PACKET_LIMIT), "flow_limit", str(FQ_FLOW_LIMIT)],
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"unable to apply managed qdisc profile: {result.stderr.strip()[:240]}")
    after = qdisc_snapshot(interface)
    mismatches = [name for name, value in expected.items() if after.get(name) != value]
    if mismatches:
        raise RuntimeError(f"managed qdisc profile did not converge: {','.join(mismatches)}")
    return {"changed": True, **after}


def apply_qdisc_profile(*, include_overlay: bool = True) -> dict[str, Any]:
    interface = default_interface()
    if not interface:
        raise RuntimeError("default interface is unavailable")
    public = apply_interface_qdisc(interface)
    result = {
        "interface": interface,
        "changed": public["changed"],
        **{name: value for name, value in public.items() if name != "changed"},
    }
    if not include_overlay:
        return result
    overlay_interface = parse_env().get("WG_INTERFACE", "").strip() or "wg0"
    if overlay_interface == interface:
        overlay = public
    elif (Path("/sys/class/net") / overlay_interface).exists():
        overlay = apply_interface_qdisc(overlay_interface)
    else:
        overlay = {"changed": False, **qdisc_snapshot("")}
    result.update(
        {
            "changed": public["changed"] or overlay["changed"],
            "overlay_interface": overlay_interface,
            **{f"overlay_{name}": value for name, value in overlay.items() if name != "changed"},
        }
    )
    return result


def apply_network_profile() -> dict[str, Any]:
    env = parse_env()
    manifest = read_json(MANIFEST_PATH, {})
    contract = runtime_contract(manifest if isinstance(manifest, Mapping) else {}, env)
    has_interserver = bool(contract.get("capabilities", frozenset()) & INTERSERVER_CAPABILITIES)
    qdisc = apply_qdisc_profile(include_overlay=has_interserver)
    if contract_has(contract, CAP_INTERSERVER_CLIENT):
        policy = apply_wireguard_policy(env)
    else:
        policy = {"managed": False, "ok": True, "not_applicable": True}
    return {
        "changed": bool(qdisc.get("changed") or policy.get("changed")),
        "qdisc": qdisc,
        "wireguard_policy": policy,
    }


def tcp_adaptation_snapshot(interface: str, overlay_interface: str = "") -> dict[str, Any]:
    values: dict[str, Any] = {}
    for field, name in (
        ("congestion_control", "net.ipv4.tcp_congestion_control"),
        ("mtu_probing", "net.ipv4.tcp_mtu_probing"),
        ("mtu_probe_floor", "net.ipv4.tcp_mtu_probe_floor"),
        ("probe_interval_seconds", "net.ipv4.tcp_probe_interval"),
        ("metrics_save_disabled", "net.ipv4.tcp_no_metrics_save"),
        ("udp_rmem_default", "net.core.rmem_default"),
        ("udp_rmem_max", "net.core.rmem_max"),
        ("udp_wmem_default", "net.core.wmem_default"),
        ("udp_wmem_max", "net.core.wmem_max"),
    ):
        result = run(["sysctl", "-n", name], timeout=3)
        value = result.stdout.strip()
        values[field] = int(value) if value.isdigit() else value
    values.update(qdisc_snapshot(interface))
    if overlay_interface:
        values.update({f"overlay_{name}": value for name, value in qdisc_snapshot(overlay_interface).items()})
    return values


def managed_network_profile(path: Path = SYSCTL_PATH, *, include_overlay: bool = True) -> dict[str, Any]:
    field_names = {
        "net.core.rmem_default": "udp_rmem_default",
        "net.core.rmem_max": "udp_rmem_max",
        "net.core.wmem_default": "udp_wmem_default",
        "net.core.wmem_max": "udp_wmem_max",
        "net.netfilter.nf_conntrack_max": "conntrack_max",
        "net.ipv4.tcp_mtu_probe_floor": "mtu_probe_floor",
        "net.ipv4.tcp_no_metrics_save": "metrics_save_disabled",
    }
    values: dict[str, int] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw_line in lines:
        key, separator, raw_value = raw_line.partition("=")
        field = field_names.get(key.strip())
        if not separator or not field:
            continue
        try:
            values[field] = int(raw_value.strip())
        except ValueError:
            continue
    profile = {
        **values,
        "qdisc": FQ_KIND,
        "qdisc_limit": FQ_PACKET_LIMIT,
        "qdisc_flow_limit": FQ_FLOW_LIMIT,
    }
    if include_overlay:
        profile.update(
            {
                "overlay_qdisc": FQ_KIND,
                "overlay_qdisc_limit": FQ_PACKET_LIMIT,
                "overlay_qdisc_flow_limit": FQ_FLOW_LIMIT,
            }
        )
    return profile


def network_profile_mismatches(actual: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    return sorted(name for name, value in expected.items() if actual.get(name) != value)


def protocol_counters_snapshot() -> dict[str, int]:
    tracked = {
        "IpInDiscards",
        "IpOutNoRoutes",
        "Ip6InDiscards",
        "Ip6OutNoRoutes",
        "TcpOutSegs",
        "TcpRetransSegs",
        "TcpExtTCPDSACKRecv",
        "TcpExtTCPSACKReorder",
        "TcpExtTCPSpuriousRTOs",
        "TcpExtTCPTimeouts",
        "TcpExtListenDrops",
        "TcpExtListenOverflows",
        "UdpInErrors",
        "UdpRcvbufErrors",
        "UdpSndbufErrors",
        "Udp6InErrors",
        "Udp6RcvbufErrors",
        "Udp6SndbufErrors",
    }
    result = run(["nstat", "-az"], timeout=5)
    counters: dict[str, int] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] in tracked:
            try:
                counters[fields[0]] = int(fields[1])
            except ValueError:
                continue
    return {name: counters.get(name, 0) for name in sorted(tracked)}


def softnet_counters_snapshot() -> dict[str, int]:
    totals = {"processed": 0, "dropped": 0, "time_squeeze": 0}
    try:
        lines = Path("/proc/net/softnet_stat").read_text(encoding="ascii").splitlines()
    except OSError:
        return totals
    for line in lines:
        fields = line.split()
        if len(fields) < 3:
            continue
        for index, name in enumerate(("processed", "dropped", "time_squeeze")):
            try:
                totals[name] += int(fields[index], 16)
            except ValueError:
                pass
    return totals


def socket_endpoint(peer: str) -> tuple[str, int | None]:
    return split_endpoint(peer)


def tcp_socket_peer(fields: list[str], local_port: int) -> tuple[str, int | None]:
    """Return the remote endpoint without relying on optional ss column positions."""
    for index, field in enumerate(fields):
        _local_host, candidate_port = socket_endpoint(field)
        if candidate_port != local_port:
            continue
        for peer_field in fields[index + 1 :]:
            peer_host, peer_port = socket_endpoint(peer_field)
            if not peer_host or peer_port is None:
                continue
            try:
                ipaddress.ip_address(peer_host)
            except ValueError:
                continue
            return peer_host, peer_port
    return "", None


def endpoint_key(source: str, port: int | None) -> str:
    host = f"[{source}]" if ":" in source else source
    return f"{host}:{port}" if port is not None else host


def client_transport_observation(tcp_events: dict[str, Counter[str]], *, active_outer_flows: int) -> dict[str, Any]:
    multiplexed_flows = {
        key: {
            "accepted_tcp_requests": sum(destinations.values()),
            "destinations": dict(destinations.most_common(10)),
        }
        for key, destinations in tcp_events.items()
        if sum(destinations.values()) > 1
    }
    detected = bool(multiplexed_flows)
    observed_tcp_requests = sum(sum(destinations.values()) for destinations in tcp_events.values())
    if detected:
        status = "detected"
    elif active_outer_flows and observed_tcp_requests:
        status = "not_observed"
    else:
        status = "inconclusive"
    return {
        "status": status,
        "multiplex_detected": detected,
        "multiplexed_flow_count": len(multiplexed_flows),
        "active_outer_flows": active_outer_flows,
        "observed_tcp_requests": observed_tcp_requests,
        "risk": "tcp_head_of_line" if detected else "unknown" if status == "inconclusive" else "none_observed",
        "basis": "multiple_xray_tcp_accepts_on_one_active_outer_socket" if detected else "active_flow_window" if status == "not_observed" else "no_active_flow_evidence",
        "flows": multiplexed_flows,
    }


def empty_tcp_metrics() -> dict[str, Any]:
    return {
        "connections": 0,
        "states": Counter(),
        "rtts": [],
        "rtos": [],
        "retransmissions": 0,
        "bytes_sent": 0,
        "bytes_retrans": 0,
        "data_segs_out": 0,
        "reord_seen": 0,
        "dsack_dups": 0,
        "rcv_ooopack": 0,
        "reordering_levels": [],
        "pmtus": [],
        "msses": [],
        "cwnds": [],
        "delivery_rates_bps": [],
        "unacked": 0,
        "keepalive_timers": 0,
        "idle_ms": [],
    }


ACTIVE_TCP_STATES = frozenset({"ESTAB"})
CLOSING_TCP_STATES = frozenset({"FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "TIME-WAIT"})


def tcp_socket_phase(states: dict[str, int]) -> str:
    if any(int(states.get(state, 0)) for state in ACTIVE_TCP_STATES):
        return "active"
    if any(int(states.get(state, 0)) for state in CLOSING_TCP_STATES):
        return "closing"
    return "handshake"


def add_tcp_info(metrics: dict[str, Any], line: str) -> None:
    float_values = ((r"\brtt:([0-9.]+)", "rtts"),)
    scalar_values = (
        (r"\bretrans:\d+/(\d+)", "retransmissions"),
        (r"\bbytes_sent:(\d+)", "bytes_sent"),
        (r"\bbytes_retrans:(\d+)", "bytes_retrans"),
        (r"\bdata_segs_out:(\d+)", "data_segs_out"),
        (r"\breord_seen:(\d+)", "reord_seen"),
        (r"\bdsack_dups:(\d+)", "dsack_dups"),
        (r"\brcv_ooopack:(\d+)", "rcv_ooopack"),
        (r"\bunacked:(\d+)", "unacked"),
    )
    list_values = (
        (r"\brto:(\d+)", "rtos"),
        (r"\bpmtu:(\d+)", "pmtus"),
        (r"\bmss:(\d+)", "msses"),
        (r"\bcwnd:(\d+)", "cwnds"),
        (r"\bdelivery_rate (\d+)bps", "delivery_rates_bps"),
        (r"\breordering:(\d+)", "reordering_levels"),
    )
    for pattern, key in float_values:
        match = re.search(pattern, line)
        if match:
            metrics[key].append(float(match.group(1)))
    for pattern, key in scalar_values:
        match = re.search(pattern, line)
        if match:
            metrics[key] += int(match.group(1))
    for pattern, key in list_values:
        match = re.search(pattern, line)
        if match:
            metrics[key].append(int(match.group(1)))
    metrics["idle_ms"].extend(int(value) for value in re.findall(r"\b(?:lastsnd|lastrcv|lastack):(\d+)", line))


def merge_tcp_metrics(target: dict[str, Any], source: dict[str, Any]) -> None:
    target["connections"] += source["connections"]
    target["states"].update(source["states"])
    for key in ("retransmissions", "bytes_sent", "bytes_retrans", "data_segs_out", "reord_seen", "dsack_dups", "rcv_ooopack", "unacked", "keepalive_timers"):
        target[key] += source[key]
    for key in ("rtts", "rtos", "pmtus", "msses", "cwnds", "delivery_rates_bps", "reordering_levels", "idle_ms"):
        target[key].extend(source[key])


def render_tcp_metrics(values: dict[str, Any]) -> dict[str, Any]:
    rtts = values["rtts"]
    bytes_sent = int(values["bytes_sent"])
    bytes_retrans = int(values["bytes_retrans"])
    rendered = {
        "connections": values["connections"],
        "states": dict(values["states"]),
        "rtt_ms": {
            "min": min(rtts) if rtts else None,
            "median": percentile(rtts, 50),
            "p95": percentile(rtts, 95),
            "max": max(rtts) if rtts else None,
            "samples": len(rtts),
        },
        "rto_ms": {"p95": percentile(values["rtos"], 95), "max": max(values["rtos"]) if values["rtos"] else None},
        "retransmissions": values["retransmissions"],
        "bytes_sent": bytes_sent,
        "bytes_retrans": bytes_retrans,
        "retransmit_ratio_pct": round(bytes_retrans * 100 / bytes_sent, 3) if bytes_sent else 0.0,
        "data_segs_out": values["data_segs_out"],
        "reord_seen": values["reord_seen"],
        "dsack_dups": values["dsack_dups"],
        "rcv_ooopack": values["rcv_ooopack"],
        "reordering": max(values["reordering_levels"]) if values["reordering_levels"] else None,
        "pmtu": min(values["pmtus"]) if values["pmtus"] else None,
        "mss": min(values["msses"]) if values["msses"] else None,
        "cwnd": {"median": percentile(values["cwnds"], 50), "max": max(values["cwnds"]) if values["cwnds"] else None},
        "delivery_rate_bps": {
            "median": percentile(values["delivery_rates_bps"], 50),
            "max": max(values["delivery_rates_bps"]) if values["delivery_rates_bps"] else None,
        },
        "unacked": values["unacked"],
        "keepalive_timer_connections": values["keepalive_timers"],
        "idle_ms_p95": percentile(values["idle_ms"], 95),
    }
    rendered["phase"] = tcp_socket_phase(rendered["states"])
    rendered["quality"] = client_front_quality(rendered)
    return rendered


def tcp_front_snapshot(port: int) -> dict[str, Any]:
    states = Counter()
    clients = Counter()
    sockets = run(["ss", "-Htan", f"sport = :{port}"], timeout=8)
    for line in sockets.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        states[fields[0]] += 1
        host, _source_port = tcp_socket_peer(fields, port)
        if host:
            clients[host] += 1
    per_flow: dict[str, dict[str, Any]] = {}
    current_flow: dict[str, Any] | None = None
    for raw_line in run(["ss", "-Htoein", f"sport = :{port}"], timeout=8).stdout.splitlines():
        line = raw_line.strip()
        fields = line.split()
        if len(fields) >= 5 and fields[0] in {"ESTAB", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "TIME-WAIT"}:
            source, source_port = tcp_socket_peer(fields, port)
            if not source:
                current_flow = None
                continue
            current_flow = empty_tcp_metrics()
            socket_id_match = re.search(r"\bsk:([0-9a-fA-F]+)\b", line)
            current_flow.update(
                {
                    "source": source,
                    "source_port": source_port,
                    "socket_id": socket_id_match.group(1).lower() if socket_id_match else "",
                }
            )
            current_flow["connections"] = 1
            current_flow["states"][fields[0]] = 1
            current_flow["keepalive_timers"] = int("timer:(keepalive" in line)
            per_flow[endpoint_key(source, source_port)] = current_flow
            continue
        if current_flow is None:
            continue
        add_tcp_info(current_flow, line)
    per_client: dict[str, dict[str, Any]] = {}
    active_per_client: dict[str, dict[str, Any]] = {}
    for values in per_flow.values():
        merge_tcp_metrics(per_client.setdefault(values["source"], empty_tcp_metrics()), values)
        if tcp_socket_phase(values["states"]) == "active":
            merge_tcp_metrics(active_per_client.setdefault(values["source"], empty_tcp_metrics()), values)
    all_client_socket_metrics = {source: render_tcp_metrics(values) for source, values in per_client.items()}
    all_client_metrics = {
        source: render_tcp_metrics(active_per_client.get(source, values))
        for source, values in per_client.items()
    }
    all_flow_metrics = {
        key: {
            "source": values["source"],
            "source_port": values["source_port"],
            "socket_id": values.get("socket_id", ""),
            **render_tcp_metrics(values),
        }
        for key, values in per_flow.items()
    }
    client_metrics = {
        source: all_client_metrics[source]
        for source, _metrics in sorted(all_client_metrics.items(), key=lambda item: (-item[1]["connections"], item[0]))[:20]
    }
    flow_metrics = dict(
        sorted(
            all_flow_metrics.items(),
            key=lambda item: (item[1]["quality"] != "degraded", -int(item[1]["bytes_retrans"]), item[0]),
        )[:100]
    )
    active_flows = [metrics for metrics in all_flow_metrics.values() if metrics["phase"] == "active"]
    closing_flows = [metrics for metrics in all_flow_metrics.values() if metrics["phase"] == "closing"]
    rtts = [
        rtt
        for endpoint, values in per_flow.items()
        if all_flow_metrics[endpoint]["phase"] == "active"
        for rtt in values["rtts"]
    ]
    retrans = sum(int(value["retransmissions"]) for value in active_flows)
    bytes_sent = sum(int(value["bytes_sent"]) for value in active_flows)
    bytes_retrans = sum(int(value["bytes_retrans"]) for value in active_flows)
    unacked = sum(int(value["unacked"]) for value in active_flows)
    keepalive_timers = sum(int(value["keepalive_timer_connections"]) for value in active_flows)
    stale_5m = sum(1 for value in active_flows if float(value.get("idle_ms_p95") or 0) >= 300_000)
    stale_1h = sum(1 for value in active_flows if float(value.get("idle_ms_p95") or 0) >= 3_600_000)
    closing_churn_sources = sorted(
        source
        for source, values in all_client_socket_metrics.items()
        if int(values["states"].get("FIN-WAIT-1", 0)) >= 25
    )
    degraded_sources = {
        str(metrics["source"])
        for metrics in all_flow_metrics.values()
        if metrics["phase"] == "active" and metrics["quality"] == "degraded"
    }
    recent_degraded_sources = {
        str(metrics["source"])
        for metrics in all_flow_metrics.values()
        if (
            metrics["phase"] == "active"
            and metrics["quality"] == "degraded"
            and float(metrics.get("idle_ms_p95") or 0) < FRONT_CURRENT_ACTIVITY_MAX_IDLE_MS
        )
    }
    loss_observed_sources = sorted(
        source
        for source in all_client_metrics
        if any(
            metrics["source"] == source and metrics["phase"] == "active" and metrics["quality"] == "loss_observed"
            for metrics in all_flow_metrics.values()
        )
    )
    listener = run(["ss", "-Hltn", f"sport = :{port}"], timeout=5)
    return {
        "port": port,
        "listening": bool(listener.stdout.strip()),
        "state_counts": dict(states),
        "connections": sum(states.values()),
        "active_connections": len(active_flows),
        "closing_connections": len(closing_flows),
        "top_sources": dict(clients.most_common(20)),
        "clients": client_metrics,
        "flows": flow_metrics,
        "rtt_ms": {"min": min(rtts) if rtts else None, "median": percentile(rtts, 50), "p95": percentile(rtts, 95), "max": max(rtts) if rtts else None},
        "socket_retransmissions": retrans,
        "socket_retransmissions_scope": "lifetime counters of currently active ESTAB sockets",
        "bytes_sent": bytes_sent,
        "bytes_retrans": bytes_retrans,
        "retransmit_ratio_pct": round(bytes_retrans * 100 / bytes_sent, 3) if bytes_sent else 0.0,
        "degraded_sources": sorted(degraded_sources),
        "recent_degraded_sources": sorted(recent_degraded_sources),
        "loss_observed_sources": loss_observed_sources,
        "unacked": unacked,
        "keepalive_timer_connections": keepalive_timers,
        "stale_connections_5m": stale_5m,
        "stale_connections_1h": stale_1h,
        "closing_churn_sources": closing_churn_sources,
        **xray_front_socket_policy(port),
    }


def client_front_quality(metrics: dict[str, Any]) -> str:
    if metrics.get("phase") == "closing":
        return "closing"
    if metrics.get("phase") == "handshake":
        return "handshake"
    bytes_sent = int(metrics.get("bytes_sent", 0))
    retransmissions = int(metrics.get("retransmissions", 0))
    retransmit_ratio_pct = float(metrics.get("retransmit_ratio_pct", 0.0))
    rtt = metrics.get("rtt_ms", {})
    rto = metrics.get("rto_ms", {})
    samples = int(rtt.get("samples", 0) or 0)
    minimum = float(rtt.get("min", 0) or 0)
    p95 = float(rtt.get("p95", 0) or 0)
    max_rto = float(rto.get("max", 0) or 0)
    if (
        samples >= FRONT_RTT_MIN_SAMPLES
        and minimum > 0
        and p95 >= FRONT_RTT_DEGRADED_MS
        and p95 >= minimum * FRONT_RTT_INFLATION_FACTOR
        and max_rto >= FRONT_RTO_DEGRADED_MS
    ):
        return "degraded"
    if (
        retransmissions >= FRONT_SMALL_FLOW_MIN_RETRANSMISSIONS
        and p95 >= FRONT_RTT_DEGRADED_MS
        and max_rto >= FRONT_RTO_DEGRADED_MS
    ):
        return "degraded"
    if bytes_sent >= FRONT_LOSS_MIN_BYTES and retransmit_ratio_pct >= FRONT_LOSS_DEGRADED_PERCENT:
        return "loss_observed"
    if (
        bytes_sent >= FRONT_SMALL_FLOW_MIN_BYTES
        and retransmissions >= FRONT_SMALL_FLOW_MIN_RETRANSMISSIONS
        and retransmit_ratio_pct >= FRONT_SMALL_FLOW_DEGRADED_PERCENT
    ):
        return "loss_observed"
    return "observed"


FRONT_COUNTER_KEYS = ("bytes_sent", "bytes_retrans", "retransmissions", "data_segs_out")


def front_counter_snapshot(front: dict[str, Any], observed_at: str) -> dict[str, Any]:
    flows: dict[str, dict[str, Any]] = {}
    for endpoint, metrics in front.get("flows", {}).items():
        if not isinstance(metrics, dict):
            continue
        if metrics.get("phase", "active") != "active":
            continue
        flow_id = str(metrics.get("socket_id") or endpoint)
        flows[flow_id] = {
            "endpoint": endpoint,
            "source": str(metrics.get("source", "")),
            "source_port": metrics.get("source_port"),
            **{key: int(metrics.get(key, 0) or 0) for key in FRONT_COUNTER_KEYS},
        }
    return {"observed_at": observed_at, "flows": flows}


def _monotonic_flow_deltas(current: dict[str, Any], previous: dict[str, Any]) -> dict[str, int] | None:
    deltas: dict[str, int] = {}
    for key in FRONT_COUNTER_KEYS:
        value = int(current.get(key, 0) or 0)
        old = int(previous.get(key, 0) or 0)
        if value < old:
            return None
        deltas[key] = value - old
    return deltas


def front_interval_metrics(counters: dict[str, int]) -> dict[str, Any]:
    activity_bytes = max(counters["bytes_sent"], counters["bytes_retrans"])
    ratio = round(counters["bytes_retrans"] * 100 / activity_bytes, 3) if activity_bytes else 0.0
    degraded = (
        activity_bytes >= FRONT_INTERVAL_LOSS_MIN_BYTES
        and counters["retransmissions"] >= FRONT_INTERVAL_LOSS_MIN_RETRANSMISSIONS
        and ratio >= FRONT_INTERVAL_LOSS_DEGRADED_PERCENT
    ) or (
        activity_bytes >= FRONT_SMALL_FLOW_MIN_BYTES
        and counters["retransmissions"] >= FRONT_SMALL_FLOW_MIN_RETRANSMISSIONS
        and ratio >= FRONT_SMALL_FLOW_DEGRADED_PERCENT
    )
    return {
        "activity_bytes": activity_bytes,
        "retransmit_ratio_pct": ratio,
        "quality": "degraded" if degraded else "observed" if activity_bytes >= FRONT_SMALL_FLOW_MIN_BYTES else "insufficient",
    }


def front_interval_snapshot(
    front: dict[str, Any],
    previous_counters: dict[str, Any],
    observed_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    counters = front_counter_snapshot(front, observed_at)
    previous_flows = previous_counters.get("flows", {}) if isinstance(previous_counters, dict) else {}
    previous_age = iso_age_seconds(
        str(previous_counters.get("observed_at", "")),
        now=parse_iso_datetime(observed_at),
    )
    baseline_reason = ""
    if not previous_flows:
        baseline_reason = "missing"
    elif previous_age is None or previous_age > FRONT_COUNTER_MAX_INTERVAL_SECONDS:
        previous_flows = {}
        baseline_reason = "stale"
    interval_flows: dict[str, dict[str, Any]] = {}
    degraded_sources: set[str] = set()
    aggregate = {key: 0 for key in FRONT_COUNTER_KEYS}
    source_counters: dict[str, dict[str, int]] = {}
    for flow_id, current in counters["flows"].items():
        previous = previous_flows.get(flow_id) if isinstance(previous_flows, dict) else None
        if not isinstance(previous, dict):
            continue
        if (
            str(previous.get("endpoint", "")) != str(current.get("endpoint", ""))
            or str(previous.get("source", "")) != str(current.get("source", ""))
        ):
            continue
        deltas = _monotonic_flow_deltas(current, previous)
        if deltas is None:
            continue
        for key, value in deltas.items():
            aggregate[key] += value
        source = str(current.get("source", ""))
        if source:
            combined = source_counters.setdefault(source, {key: 0 for key in FRONT_COUNTER_KEYS})
            for key, value in deltas.items():
                combined[key] += value
        metrics = front_interval_metrics(deltas)
        if metrics["quality"] == "degraded" and source:
            degraded_sources.add(source)
        interval_flows[str(current.get("endpoint") or flow_id)] = {
            "socket_id": flow_id,
            "source": source,
            "source_port": current.get("source_port"),
            **deltas,
            **metrics,
        }
    interval_sources = {
        source: {**counters_by_source, **front_interval_metrics(counters_by_source)}
        for source, counters_by_source in source_counters.items()
    }
    degraded_sources.update(
        source
        for source, metrics in interval_sources.items()
        if metrics["quality"] == "degraded"
    )
    sources = sorted(degraded_sources)
    aggregate_metrics = front_interval_metrics(aggregate)
    if len(sources) >= 3:
        observation = "degraded"
    elif sources:
        observation = "client_specific"
    elif aggregate_metrics["quality"] == "insufficient":
        observation = "insufficient"
    else:
        observation = "observed"
    interval = {
        "observed_at": observed_at,
        "baseline": not bool(previous_flows),
        "baseline_reason": baseline_reason,
        "sampled_flows": len(interval_flows),
        "observation": observation,
        "degraded_sources": sources,
        "aggregate": {**aggregate, **aggregate_metrics},
        "sources": interval_sources,
        "flows": interval_flows,
    }
    return interval, counters


def xray_reality_pending_handshakes(target: str) -> int | None:
    _host, target_port = split_endpoint(target)
    if target_port is None:
        return None
    sockets = run(["ss", "-Htanp", "state", "syn-sent"], timeout=5)
    if sockets.returncode != 0:
        return None
    return sum(
        '"xray"' in line.lower()
        and any(split_endpoint(field)[1] == target_port for field in line.split())
        for line in sockets.stdout.splitlines()
    )


def xray_front_socket_policy(port: int) -> dict[str, Any]:
    config = read_json(XRAY_CONFIG_PATH, {})
    for inbound in config.get("inbounds", []) if isinstance(config, dict) else []:
        if not isinstance(inbound, dict):
            continue
        try:
            inbound_port = int(inbound.get("port", 0))
        except (TypeError, ValueError):
            continue
        if inbound_port != port:
            continue
        stream_settings = inbound.get("streamSettings", {})
        if not isinstance(stream_settings, dict):
            return {}
        sockopt = stream_settings.get("sockopt", {})
        sockopt = sockopt if isinstance(sockopt, dict) else {}
        result: dict[str, Any] = {}
        for output_name, config_name in (
            ("tcp_keepalive_idle_seconds", "tcpKeepAliveIdle"),
            ("tcp_keepalive_interval_seconds", "tcpKeepAliveInterval"),
        ):
            try:
                result[output_name] = int(sockopt.get(config_name, 0))
            except (TypeError, ValueError):
                result[output_name] = 0
        reality = stream_settings.get("realitySettings", {})
        if isinstance(reality, dict):
            target_key = "target" if reality.get("target") else "dest" if reality.get("dest") else ""
            target = str(reality.get(target_key, "")) if target_key else ""
            server_names = reality.get("serverNames", [])
            result.update(
                {
                    "reality_target": target,
                    "reality_target_config_key": target_key or "missing",
                    "reality_server_names": [str(value) for value in server_names] if isinstance(server_names, list) else [],
                    "reality_pending_handshakes": xray_reality_pending_handshakes(target) if target else None,
                }
            )
        return result
    return {}


def public_hy2_snapshot(port: int) -> dict[str, Any]:
    config = read_json(SINGBOX_CONFIG_PATH, {})
    inbound: dict[str, Any] = {}
    for candidate in config.get("inbounds", []) if isinstance(config, dict) else []:
        if not isinstance(candidate, dict):
            continue
        try:
            candidate_port = int(candidate.get("listen_port", 0))
        except (TypeError, ValueError):
            continue
        if candidate.get("type") == "hysteria2" and candidate.get("tag") == "public-hy2-in" and candidate_port == port:
            inbound = candidate
            break
    listener = run(["ss", "-Hlun", f"sport = :{port}"], timeout=5)
    ruleset = run(["nft", "list", "table", "inet", "vpnstack"], timeout=8)
    rules = ruleset.stdout
    firewall = (
        ruleset.returncode == 0
        and "vpnstack-hy2-in-notrack" in rules
        and "vpnstack-hy2-out-notrack" in rules
        and re.search(rf"\budp dport {port}\b.*\baccept\b", rules) is not None
    )
    tls = inbound.get("tls", {}) if isinstance(inbound, dict) else {}
    users = inbound.get("users", []) if isinstance(inbound, dict) else []
    return {
        "port": port,
        "protocol": "hysteria2",
        "configured": bool(inbound and isinstance(users, list) and len(users) == 1 and isinstance(tls, dict) and tls.get("enabled") is True),
        "listening": listener.returncode == 0 and bool(listener.stdout.strip()),
        "firewall": firewall,
    }


def front_observation(front: dict[str, Any], interval: dict[str, Any] | None = None) -> str:
    """Classify active data-path loss without conflating socket teardown."""
    degraded_sources = set(
        interval.get("degraded_sources", [])
        if interval is not None and interval.get("baseline") is not True
        else front.get("recent_degraded_sources", [])
    )
    pending_handshakes = front.get("reality_pending_handshakes")
    if isinstance(pending_handshakes, int) and pending_handshakes >= REALITY_PENDING_HANDSHAKE_DEGRADED:
        return "degraded"
    if int(front.get("stale_connections_5m", 0)) >= 25 and int(front.get("keepalive_timer_connections", 0)) < int(front.get("stale_connections_5m", 0)):
        return "degraded"
    if len(degraded_sources) >= 3:
        return "degraded"
    if degraded_sources:
        return "client_specific"
    return "observed"


def closing_churn_observation(front: dict[str, Any]) -> str:
    sources = front.get("closing_churn_sources", [])
    if not isinstance(sources, list):
        return "observed"
    if len(sources) >= 3:
        return "shared"
    if sources:
        return "client_specific"
    return "observed"


def public_front_verdict(
    xray_state: str,
    front: dict[str, Any],
    interval: dict[str, Any] | None = None,
) -> str:
    if xray_state != "active" or not front.get("listening"):
        return "failed"
    return "degraded" if front_observation(front, interval) in {"client_specific", "degraded"} else "verified"


def front_degradation_evidence(
    front: dict[str, Any],
    observed_at: str,
    interval: dict[str, Any] | None = None,
) -> dict[str, Any]:
    interval_supplied = interval is not None and interval.get("baseline") is not True
    current_sources = set(
        interval.get("degraded_sources", [])
        if interval_supplied and interval is not None
        else front.get("recent_degraded_sources", [])
    )
    evidence_flows = (interval or {}).get("flows", {}) if interval_supplied else front.get("flows", {})
    degraded_flows = dict(
        sorted(
            (
                (key, metrics)
                for key, metrics in evidence_flows.items()
                if isinstance(metrics, dict) and metrics.get("quality") == "degraded" and metrics.get("source") in current_sources
            ),
            key=lambda item: -int(item[1].get("bytes_retrans", 0)),
        )[:20]
    )
    interval_data = interval or {}
    interval_flows = {
        key: metrics
        for key, metrics in interval_data.get("flows", {}).items()
        if isinstance(metrics, dict) and metrics.get("quality") == "degraded"
    }
    degraded_sources = sorted(current_sources)
    closing_sources = sorted(set(front.get("closing_churn_sources", [])))
    if not degraded_sources and not degraded_flows and not interval_flows and not closing_sources:
        return {}
    return {
        "observed_at": observed_at,
        "observation": front_observation(front, interval_data if interval_supplied else None),
        "degraded_sources": degraded_sources,
        "closing_churn": {
            "observation": closing_churn_observation(front),
            "sources": closing_sources,
            "connections": front.get("closing_connections", 0),
        },
        "aggregate": {
            "connections": front.get("connections", 0),
            "bytes_sent": front.get("bytes_sent", 0),
            "bytes_retrans": front.get("bytes_retrans", 0),
            "retransmit_ratio_pct": front.get("retransmit_ratio_pct", 0.0),
            "rtt_ms": front.get("rtt_ms", {}),
            "keepalive_timer_connections": front.get("keepalive_timer_connections", 0),
            "stale_connections_5m": front.get("stale_connections_5m", 0),
            "stale_connections_1h": front.get("stale_connections_1h", 0),
        },
        "flows": degraded_flows,
        "interval": {
            "aggregate": interval_data.get("aggregate", {}),
            "flows": interval_flows,
        },
    }


def source_in_log_line(line: str, source: str) -> bool:
    return source_from_line(line) == normalize_source(source)


def udp_443_policy() -> str:
    config = read_json(SINGBOX_CONFIG_PATH, {})
    rules = config.get("route", {}).get("rules", []) if isinstance(config, dict) else []
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        network = rule.get("network")
        networks = [network] if isinstance(network, str) else network if isinstance(network, list) else []
        port = rule.get("port")
        if network is None and port is None:
            continue
        if network is not None and "udp" not in networks:
            continue
        ports = [port] if isinstance(port, (str, int)) else port if isinstance(port, list) else []
        if port is not None and 443 not in {int(value) for value in ports if str(value).isdigit()}:
            continue
        selector_keys = set(rule) - {
            "action", "network", "port", "outbound", "override_address", "override_port", "server", "strategy",
        }
        if selector_keys:
            continue
        return "rejected" if rule.get("action") == "reject" else "overridden"
    return "routed"


def clash_api_json(
    controller: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 3,
) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"http://{controller}{path}",
        method=method,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        body = response.read()
    if not body:
        return {}
    decoded = json.loads(body.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("local Clash API returned a non-object response")
    return decoded


def wireguard_overlay_relay(env: dict[str, str]) -> dict[str, Any]:
    interface = env.get("WG_INTERFACE", "wg0")
    peer = env.get("WG_FOREIGN_PUBLIC_KEY", "")
    if not peer:
        return {"available": False, "endpoint": "", "reason": "WireGuard peer is not configured"}
    result = run(["wg", "show", interface, "endpoints"], timeout=3)
    if result.returncode != 0:
        return {
            "available": False,
            "endpoint": "",
            "reason": (result.stderr.strip() or "WireGuard endpoint is unavailable")[:240],
        }
    endpoint = ""
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == peer:
            endpoint = fields[1]
            break
    host, port = split_endpoint(endpoint)
    available = normalize_source(host) in {"127.0.0.1", "::1"} and port == TRANSPORT_RELAY_PORT
    return {
        "available": available,
        "endpoint": endpoint,
        "reason": "" if available else "WireGuard overlay endpoint is not the fixed managed relay",
    }


def transport_selector_selection(controller: str) -> dict[str, Any]:
    try:
        selector = clash_api_json(
            controller,
            f"/proxies/{urllib.parse.quote(TRANSPORT_SELECTOR_TAG, safe='')}",
            timeout=2,
        )
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return {"available": False, "selected": "", "reason": f"selector state is unavailable: {exc}"[:240]}
    selected = str(selector.get("now", ""))
    available = selected in TRANSPORT_CANDIDATE_TAGS
    return {
        "available": available,
        "selected": selected,
        "reason": "" if available else "selector returned an invalid underlay",
    }


def transport_selection_snapshot(config: dict[str, Any], env: dict[str, str], controller: str) -> dict[str, Any]:
    def tags(items: Any) -> set[str]:
        if not isinstance(items, list):
            return set()
        return {
            str(item.get("tag", ""))
            for item in items
            if isinstance(item, dict) and item.get("tag")
        }

    outbound_tags = tags(config.get("outbounds", []))
    endpoint_tags = tags(config.get("endpoints", []))
    candidates = {
        TRANSPORT_WG_TAG: {"configured": TRANSPORT_WG_TAG in endpoint_tags},
        TRANSPORT_HY2_TAG: {"configured": TRANSPORT_HY2_TAG in outbound_tags},
    }
    relay = wireguard_overlay_relay(env)
    selector = transport_selector_selection(controller)
    selected = str(selector.get("selected", ""))
    topology_configured = transport_topology_configured(config, env)
    available = relay.get("available") is True and selector.get("available") is True and topology_configured
    return {
        "available": available,
        "selected": selected,
        "endpoint": relay.get("endpoint", ""),
        "selector": TRANSPORT_SELECTOR_TAG,
        "candidates": candidates,
        "reason": "" if available else str(
            relay.get("reason") or selector.get("reason") or "transport topology is incomplete"
        ),
    }


def preferred_transport_probe_due(previous: dict[str, Any], observed_at: str) -> bool:
    now = parse_iso_datetime(observed_at)
    age = iso_age_seconds(str(previous.get("preferred_probe_at", "")), now=now) if now else None
    return age is None or age >= TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS


def ping_failure_reason(result: subprocess.CompletedProcess[str], fallback: str) -> str:
    detail = " ".join((result.stderr.strip() or result.stdout.strip() or fallback).split())
    lowered = detail.lower()
    if "100% packet loss" in lowered or "0 received" in lowered:
        return f"{fallback} timed out"
    return detail[:240]


def transport_overlay_path_probe(env: dict[str, str]) -> dict[str, Any]:
    """Probe only the active interserver overlay, independent of DNS and Internet services."""

    started = time.monotonic()
    interface = env.get("WG_INTERFACE", "wg0")
    target = str(env.get("WG_FOREIGN_ADDRESS", "")).split("/", 1)[0]
    if not target:
        return {
            "checked": True,
            "ok": False,
            "attempts": 1,
            "delay_ms": 0,
            "elapsed_ms": 0,
            "scope": "overlay-icmp",
            "target": "",
            "error": "foreign WireGuard address is missing",
        }
    result = run(
        ["ping", "-n", "-I", interface, "-c", "1", "-W", "1", "-s", "32", target],
        timeout=2,
    )
    elapsed_ms = max(1, round((time.monotonic() - started) * 1000))
    error = ""
    if result.returncode != 0:
        error = ping_failure_reason(result, "WireGuard overlay liveness probe")
    return {
        "checked": True,
        "ok": not error,
        "attempts": 1,
        "delay_ms": 0 if error else elapsed_ms,
        "elapsed_ms": elapsed_ms,
        "scope": "overlay-icmp",
        "target": target,
        "error": error,
    }


def collect_transport_probes(
    selected: str,
    previous: dict[str, Any],
    *,
    env: dict[str, str],
    observed_at: str,
) -> dict[str, dict[str, Any]]:
    probes = {tag: {"checked": False, "ok": False, "attempts": 0} for tag in TRANSPORT_CANDIDATE_TAGS}
    if selected not in probes:
        return probes
    probes[selected] = transport_overlay_path_probe(env)
    if probes[selected].get("ok") is not True:
        alternate = next(tag for tag in TRANSPORT_CANDIDATE_TAGS if tag != selected)
        if transport_switch_backoff_active(previous, alternate, observed_at) is None:
            probes[alternate] = transport_candidate_probe(alternate)
    elif selected != TRANSPORT_PREFERRED_TAG and preferred_transport_probe_due(previous, observed_at):
        probes[TRANSPORT_PREFERRED_TAG] = transport_candidate_probe(TRANSPORT_PREFERRED_TAG)
    return probes


def prove_wireguard_overlay(env: dict[str, str]) -> None:
    interface = env.get("WG_INTERFACE", "wg0")
    peer = env.get("WG_FOREIGN_PUBLIC_KEY", "")
    target = str(env.get("WG_FOREIGN_ADDRESS", "")).split("/", 1)[0]
    if not target or not peer:
        raise RuntimeError("foreign WireGuard proof identity is missing")

    def transfer() -> tuple[int, int]:
        result = run(["wg", "show", interface, "transfer"], timeout=3)
        if result.returncode != 0:
            raise RuntimeError((result.stderr.strip() or "WireGuard transfer counters are unavailable")[:240])
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0] == peer:
                return int(fields[1]), int(fields[2])
        raise RuntimeError("WireGuard peer transfer counters are missing")

    before_rx, before_tx = transfer()
    path_result = run(
        ["ping", "-n", "-M", "do", "-s", "1280", "-I", interface, "-c", "3", "-i", "0.2", "-W", "1", target],
        timeout=3,
    )
    if path_result.returncode != 0:
        raise RuntimeError(ping_failure_reason(path_result, "WireGuard overlay liveness and MTU proof"))
    after_rx, after_tx = transfer()
    if after_rx <= before_rx or after_tx <= before_tx:
        raise RuntimeError("new WireGuard overlay path produced no bidirectional transfer delta")


def reset_transport_relay(controller: str) -> int:
    """Close only the inner-WireGuard relay association so it follows the new selector."""

    payload = clash_api_json(controller, "/connections", timeout=2)
    connections = payload.get("connections", [])
    expected_type = f"direct/{TRANSPORT_RELAY_INBOUND_TAG}"
    closed = 0
    for connection in connections if isinstance(connections, list) else []:
        if not isinstance(connection, dict):
            continue
        chains = connection.get("chains", [])
        metadata = connection.get("metadata", {})
        connection_id = str(connection.get("id", ""))
        if (
            not isinstance(chains, list)
            or TRANSPORT_SELECTOR_TAG not in chains
            or not isinstance(metadata, dict)
            or metadata.get("network") != "udp"
            or metadata.get("type") != expected_type
            or not connection_id
        ):
            continue
        clash_api_json(
            controller,
            f"/connections/{urllib.parse.quote(connection_id, safe='')}",
            method="DELETE",
            timeout=2,
        )
        closed += 1
    return closed


def select_transport(env: dict[str, str], controller: str, tag: str) -> None:
    if tag not in TRANSPORT_CANDIDATE_TAGS:
        raise ValueError(f"unknown transport candidate: {tag}")
    current = transport_selector_selection(controller)
    old_tag = str(current.get("selected", ""))
    if old_tag == tag:
        return
    if old_tag not in TRANSPORT_CANDIDATE_TAGS:
        raise RuntimeError("current underlay selector state is not recoverable")

    def set_selector(value: str) -> None:
        clash_api_json(
            controller,
            f"/proxies/{urllib.parse.quote(TRANSPORT_SELECTOR_TAG, safe='')}",
            method="PUT",
            payload={"name": value},
            timeout=2,
        )
        selected = transport_selector_selection(controller)
        if selected.get("selected") != value:
            raise RuntimeError("underlay selector did not apply the requested path")
        reset_transport_relay(controller)

    try:
        set_selector(tag)
        prove_wireguard_overlay(env)
    except (OSError, RuntimeError, ValueError, urllib.error.URLError) as exc:
        rollback_errors: list[str] = []
        try:
            set_selector(old_tag)
        except (OSError, RuntimeError, ValueError, urllib.error.URLError) as rollback_exc:
            rollback_errors.append(f"selector restore failed: {rollback_exc}")
        else:
            try:
                prove_wireguard_overlay(env)
            except (OSError, RuntimeError, ValueError, urllib.error.URLError) as rollback_exc:
                rollback_errors.append(f"restored overlay proof failed: {rollback_exc}")
        if rollback_errors:
            raise RuntimeError(f"{exc}; rollback failed: {'; '.join(rollback_errors)}") from exc
        raise RuntimeError(f"{exc}; previous selector path restored and verified") from exc


def transport_switch_backoff_active(
    previous: dict[str, Any],
    target: str,
    observed_at: str,
) -> dict[str, Any] | None:
    backoff = previous.get("switch_backoff", {})
    if not isinstance(backoff, dict) or backoff.get("target") != target:
        return None
    retry_at = parse_iso_datetime(str(backoff.get("retry_at", "")))
    observed = parse_iso_datetime(observed_at)
    if retry_at is None or observed is None or observed >= retry_at:
        return None
    return backoff


def next_transport_switch_failure(
    previous: dict[str, Any],
    target: str,
    reason: str,
    observed_at: str,
) -> dict[str, Any]:
    prior = previous.get("switch_backoff", {})
    attempts = int(prior.get("attempts", 0) or 0) + 1 if isinstance(prior, dict) and prior.get("target") == target else 1
    delay = min(
        TRANSPORT_SWITCH_RETRY_MAX_SECONDS,
        TRANSPORT_SWITCH_RETRY_BASE_SECONDS * (2 ** min(attempts - 1, 8)),
    )
    observed = parse_iso_datetime(observed_at) or datetime.now(timezone.utc)
    return {
        "target": target,
        "attempts": attempts,
        "failed_at": observed_at,
        "retry_at": (observed + timedelta(seconds=delay)).isoformat(),
        "reason": reason[:240],
    }


def current_transport_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != TRANSPORT_STATE_SCHEMA_VERSION:
        return {}
    return value


def reconcile_interserver_transport() -> dict[str, Any]:
    install_lock = acquire_install_read_lock()
    if install_lock is None:
        previous = current_transport_state(read_json(TRANSPORT_STATE_PATH, {}))
        payload = {
            **(previous if isinstance(previous, dict) else {}),
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": utc_now(),
            "state": "maintenance",
            "changed": False,
            "would_switch": False,
            "reason": "install transaction is active",
        }
        write_json_atomic(TRANSPORT_STATE_PATH, payload)
        return payload
    try:
        return _reconcile_interserver_transport_unlocked()
    finally:
        release_install_read_lock(install_lock)


def _reconcile_interserver_transport_unlocked() -> dict[str, Any]:
    TRANSPORT_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with TRANSPORT_LOCK_PATH.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = read_json(SINGBOX_CONFIG_PATH, {})
        env = parse_env()
        controller = str(config.get("experimental", {}).get("clash_api", {}).get("external_controller", "")) if isinstance(config, dict) else ""
        previous_state = current_transport_state(read_json(TRANSPORT_STATE_PATH, {}))
        if not isinstance(config, dict) or not transport_topology_configured(config, env) or not controller:
            payload = {
                "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
                "updated_at": utc_now(),
                "state": "failed",
                "selected": "",
                "recommended": "",
                "would_switch": False,
                "reason": "stable WireGuard overlay relays are not configured",
            }
            write_json_atomic(TRANSPORT_STATE_PATH, payload)
            return payload

        selection = transport_selection_snapshot(config, env, controller)
        selected = str(selection.get("selected", ""))
        if not selection.get("available"):
            payload = {
                "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
                "updated_at": utc_now(),
                "state": "failed",
                "selected": selected,
                "recommended": selected,
                "would_switch": False,
                "reason": str(selection.get("reason", "transport endpoint state is unavailable")),
            }
            write_json_atomic(TRANSPORT_STATE_PATH, payload)
            return payload

        observed_at = utc_now()
        probes = collect_transport_probes(
            selected,
            previous_state,
            env=env,
            observed_at=observed_at,
        )
        payload = evaluate_transport_policy(
            selected=selected,
            probes=probes,
            previous=previous_state,
            observed_at=observed_at,
        )
        payload["overlay_probe"] = probes.get(selected, {})
        last_switch_failure = previous_state.get("last_switch_failure")
        if isinstance(last_switch_failure, dict):
            payload["last_switch_failure"] = last_switch_failure
        alternate = next((tag for tag in TRANSPORT_CANDIDATE_TAGS if tag != selected), "")
        switch_backoff = transport_switch_backoff_active(previous_state, alternate, observed_at)
        if switch_backoff is not None and probes.get(selected, {}).get("ok") is not True:
            payload["switch_backoff"] = switch_backoff
            if payload.get("would_switch"):
                payload.update(
                    {
                        "state": "failed",
                        "recommended": selected,
                        "would_switch": False,
                        "changed": False,
                        "reason": (
                            f"{payload.get('reason', '')}; fallback activation is paused until "
                            f"{switch_backoff.get('retry_at', 'the next retry window')}"
                        ),
                    }
                )
        if payload.get("would_switch"):
            target = str(payload.get("recommended", ""))
            try:
                select_transport(env, controller, target)
            except (OSError, RuntimeError, ValueError) as exc:
                failure_reason = f"underlay selector update failed: {str(exc)[:180]}"
                rollback_verified = "previous selector path restored and verified" in str(exc)
                switch_failure = next_transport_switch_failure(
                    previous_state,
                    target,
                    failure_reason,
                    observed_at,
                )
                payload.update(
                    {
                        "state": "degraded" if rollback_verified else "failed",
                        "recommended": selected,
                        "would_switch": False,
                        "changed": False,
                        "switch_backoff": switch_failure,
                        "last_switch_failure": switch_failure,
                        "reason": failure_reason,
                    }
                )
            else:
                payload.update(
                    {
                        "changed": True,
                        "selected": target,
                        "would_switch": False,
                        "state": "degraded" if payload.get("hard_failure_evidence") else "healthy",
                        "reason": f"{payload.get('reason', '')}; underlay selector updated",
                    }
                )
        write_json_atomic(TRANSPORT_STATE_PATH, payload)
        return payload


def watch_interserver_transport() -> None:
    previous_signature: tuple[str, str, str] | None = None
    while True:
        started = time.monotonic()
        try:
            payload = reconcile_interserver_transport()
        except Exception as exc:  # noqa: BLE001
            payload = {
                "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
                "updated_at": utc_now(),
                "state": "failed",
                "selected": "",
                "recommended": "",
                "reason": str(exc)[:240],
            }
            write_json_atomic(TRANSPORT_STATE_PATH, payload)
        signature = (
            str(payload.get("state", "")),
            str(payload.get("selected", "")),
            str(payload.get("reason", "")),
        )
        if signature != previous_signature:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)
            previous_signature = signature
        time.sleep(max(0.1, TRANSPORT_PROBE_INTERVAL_SECONDS - (time.monotonic() - started)))


def transport_state_snapshot(path: Path = TRANSPORT_STATE_PATH) -> dict[str, Any]:
    state = read_json(path, {})
    if not isinstance(state, dict) or not state:
        return {}
    age_seconds = iso_age_seconds(str(state.get("updated_at", "")))
    return {
        **state,
        "age_seconds": round(age_seconds, 1) if age_seconds is not None else None,
        "fresh": age_seconds is not None and age_seconds <= TRANSPORT_PROBE_INTERVAL_SECONDS * 6,
    }


def interserver_transport_snapshot(contract: Mapping[str, Any], env: dict[str, str]) -> dict[str, Any]:
    config = read_json(SINGBOX_CONFIG_PATH, {})
    if not isinstance(config, dict):
        return {"configured": False, "reason": "sing-box config is unreadable"}
    if contract_has(contract, CAP_INTERSERVER_CLIENT):
        outbounds = {
            str(item.get("tag", "")): item
            for item in config.get("outbounds", [])
            if isinstance(item, dict) and item.get("tag")
        }
        hysteria = outbounds.get(TRANSPORT_HY2_TAG, {})
        server = str(hysteria.get("server", "")) if isinstance(hysteria, dict) else ""
        try:
            port = int(hysteria.get("server_port", 0)) if isinstance(hysteria, dict) else 0
        except (TypeError, ValueError):
            port = 0
        session_active = False
        if server and port:
            sockets = run(["ss", "-Huan"], timeout=5)
            for line in sockets.stdout.splitlines():
                fields = line.split()
                if len(fields) < 2:
                    continue
                host, remote_port = split_endpoint(fields[-1])
                if normalize_source(host) == normalize_source(server) and remote_port == port:
                    session_active = True
                    break
        configured = transport_topology_configured(config, env)
        controller = str(config.get("experimental", {}).get("clash_api", {}).get("external_controller", ""))
        selection = transport_selection_snapshot(config, env, controller)
        adaptive_state = transport_state_snapshot()
        if not adaptive_state:
            adaptive_state = {"state": "failed", "fresh": False, "reason": "transport watcher has not reported"}
        return {
            "configured": configured,
            "mode": "stable-wireguard-overlay",
            "candidates": list(TRANSPORT_CANDIDATE_TAGS),
            "server": server,
            "port": port,
            "relay_port": TRANSPORT_RELAY_PORT,
            "selector": TRANSPORT_SELECTOR_TAG,
            "hysteria_session_active": session_active,
            "selection": selection,
            "adaptive_state": adaptive_state,
        }
    if contract_has(contract, CAP_INTERSERVER_SERVER):
        inbound = next(
            (item for item in config.get("inbounds", []) if isinstance(item, dict) and item.get("tag") == "interserver-hy2-in"),
            {},
        )
        try:
            port = int(inbound.get("listen_port", 0))
        except (TypeError, ValueError):
            port = 0
        listeners = run(["ss", "-Huln"], timeout=5)
        listening = any(
            len(fields := line.split()) >= 2 and split_endpoint(fields[-2])[1] == port
            for line in listeners.stdout.splitlines()
        ) if port else False
        configured = (
            inbound.get("type") == "hysteria2"
            and inbound.get("obfs", {}).get("type") == "salamander"
            and bool(inbound.get("users"))
            and bool(inbound.get("tls", {}).get("certificate"))
            and bool(inbound.get("tls", {}).get("key"))
        )
        return {
            "configured": configured,
            "mode": "hysteria2-egress",
            "port": port,
            "listening": listening,
            "source_restricted_to": env.get("GATEWAY_PUBLIC_IP", ""),
        }
    return {"configured": False, "reason": "interserver transport is not required by node capabilities"}


def public_front_snapshot(minutes: int, source: str | None = None, *, live_probes: bool = False) -> dict[str, Any]:
    if not 5 <= minutes <= 1440:
        raise ValueError("since must be in range 5..1440 minutes")
    if source:
        try:
            source = normalize_source(source)
            ipaddress.ip_address(source)
        except ValueError as exc:
            raise ValueError("source must be an IP address") from exc
    env = parse_env()
    contract = installed_runtime_contract()
    if not contract_has(contract, CAP_PUBLIC_FRONT):
        raise RuntimeError("public front diagnostics are not applicable to this node")
    port = int(env.get("RU_LISTEN_PORT", "443") or 443)
    xray_lines = journal_filtered_lines("vpn-stack-xray.service", minutes, XRAY_FRONT_LOG_GREP)
    accepted_tcp = sum("accepted tcp:" in line for line in xray_lines)
    accepted_udp = sum("accepted udp:" in line for line in xray_lines)
    udp_443 = sum("accepted udp:" in line and (":443 " in line or ":443[" in line) for line in xray_lines)
    invalid_total = sum("REALITY: processed invalid connection" in line for line in xray_lines)
    disabled_total = sum("accepted tcp:disabled.invalid" in line for line in xray_lines)
    source_counts: Counter[str] = Counter()
    for line in xray_lines:
        if "accepted tcp:" in line or "accepted udp:" in line or "REALITY: processed invalid connection" in line:
            origin = source_from_line(line)
            if origin:
                source_counts[origin] += 1
    front = tcp_front_snapshot(port)
    services = {"xray": service_state("vpn-stack-xray.service"), "nftables": service_state(NFTABLES_SERVICE)}
    observation = front_observation(front)
    front_verdict = public_front_verdict(services["xray"], front)
    probes = run_probes(env, contract, "light") if live_probes else {"profile": "none", "ok": None, "requirements": {}}
    path_verdict = "verified" if probes.get("ok") is True else "failed" if probes.get("ok") is False else "inconclusive"
    overall = "failed" if "failed" in {front_verdict, path_verdict} else "degraded" if front_verdict == "degraded" else front_verdict
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "window_minutes": minutes,
        "services": services,
        "front": front,
        "events": {
            "accepted": accepted_tcp + accepted_udp,
            "accepted_tcp": accepted_tcp,
            "accepted_udp": accepted_udp,
            "udp_443": udp_443,
            "invalid_reality": invalid_total,
            "disabled_invalid": disabled_total,
        },
        "transport": {"udp_443_policy": udp_443_policy(), "public_client": public_hy2_snapshot(port)},
        "top_sources": dict(source_counts.most_common(20)),
        "observation": observation,
        "probes": probes,
        "verdicts": {"public_front": front_verdict, "server_path": path_verdict, "overall": overall},
        "verdict": overall,
    }
    if source is None:
        return payload
    source_events = {
        "accepted_tcp": sum("accepted tcp:" in line and source_in_log_line(line, source) for line in xray_lines),
        "accepted_udp": sum("accepted udp:" in line and source_in_log_line(line, source) for line in xray_lines),
        "udp_443": sum("accepted udp:" in line and source_in_log_line(line, source) and (":443 " in line or ":443[" in line) for line in xray_lines),
        "invalid_reality": sum("REALITY: processed invalid connection" in line and source_in_log_line(line, source) for line in xray_lines),
        "disabled_invalid": sum("accepted tcp:disabled.invalid" in line and source_in_log_line(line, source) for line in xray_lines),
    }
    source_events["accepted"] = source_events["accepted_tcp"] + source_events["accepted_udp"]
    client = front.get("clients", {}).get(source, {})
    active_flow_keys = {
        key
        for key, metrics in front.get("flows", {}).items()
        if metrics.get("source") == source and metrics.get("phase", "active") == "active"
    }
    flow_events: dict[str, Counter[str]] = {}
    tcp_flow_events: dict[str, Counter[str]] = {}
    for line in xray_lines:
        event_source, event_port = source_endpoint_from_line(line)
        destination = accepted_destination_from_line(line)
        if event_source != source or event_port is None or not destination:
            continue
        key = endpoint_key(event_source, event_port)
        if key in active_flow_keys:
            flow_events.setdefault(key, Counter())[destination] += 1
            if "accepted tcp:" in line:
                tcp_flow_events.setdefault(key, Counter())[destination] += 1
    client_transport = client_transport_observation(tcp_flow_events, active_outer_flows=len(active_flow_keys))
    source_flows = {
        key: {**metrics, "accepted_destinations": dict(flow_events.get(key, Counter()).most_common(10))}
        for key, metrics in front.get("flows", {}).items()
        if metrics.get("source") == source
    }
    recent_interval = recent_observation(
        read_json(HEALTH_STATE_PATH, {}).get("front_interval", {}),
        max_age_seconds=300,
    )
    interval_sources = recent_interval.get("sources", {}) if recent_interval else {}
    if not isinstance(interval_sources, dict):
        interval_sources = {}
    interval_degraded_sources = recent_interval.get("degraded_sources", []) if recent_interval else []
    if not isinstance(interval_degraded_sources, list):
        interval_degraded_sources = []
    source_interval = interval_sources.get(source, {})
    source_degraded = source in interval_degraded_sources or any(
        metrics.get("quality") == "degraded" for metrics in source_flows.values()
    )
    source_loss_observed = client.get("quality") == "loss_observed" or any(
        metrics.get("quality") == "loss_observed" for metrics in source_flows.values()
    )
    if source_events["accepted"] and source_degraded:
        source_verdict = "degraded"
    elif source_events["accepted"] and source_loss_observed:
        source_verdict = "loss_observed"
    elif source_events["accepted"]:
        source_verdict = "reached_xray"
    elif source_events["invalid_reality"] or source_events["disabled_invalid"]:
        source_verdict = "rejected_by_front"
    elif client or source in front.get("top_sources", {}):
        source_verdict = "tcp_reached_no_xray_accept"
    else:
        source_verdict = "not_seen_on_server"
    payload.update(
        {
            "source": source,
            "source_events": source_events,
            "source_client": client,
            "source_flows": source_flows,
            "source_interval": source_interval,
            "source_flow_events": {key: dict(counter.most_common(10)) for key, counter in flow_events.items()},
            "source_client_transport": client_transport,
            "source_verdict": source_verdict,
        }
    )
    return payload


def front_client_snapshot(source: str, minutes: int) -> dict[str, Any]:
    payload = public_front_snapshot(minutes, source)
    return {
        "schema_version": payload["schema_version"],
        "generated_at": payload["generated_at"],
        "source": source,
        "window_minutes": minutes,
        "services": payload["services"],
        "front": {
            "port": payload["front"].get("port", 0),
            "listening": payload["front"].get("listening", False),
            "client": payload["source_client"],
            "flows": payload["source_flows"],
            "recent_interval": payload["source_interval"],
        },
        "events": payload["source_events"],
        "flow_events": payload["source_flow_events"],
        "client_transport": payload["source_client_transport"],
        "transport": payload["transport"],
        "verdict": payload["source_verdict"],
    }


def percentile(values: list[float], percent: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percent / 100)))
    return ordered[index]


def kernel_conntrack_full_windows(*, full_logs: bool) -> dict[str, int]:
    windows = (5, 30, 1440) if full_logs else (5,)
    result = run(
        [
            "journalctl",
            "-k",
            "--since",
            f"{max(windows)} minutes ago",
            "--no-pager",
            "-o",
            "short-unix",
            f"--grep={CONNTRACK_FULL_GREP}",
        ],
        timeout=20,
    )
    timestamps: list[float] = []
    for raw_line in result.stdout.splitlines():
        timestamp, separator, message = raw_line.partition(" ")
        if not separator or "nf_conntrack" not in message or "table full" not in message:
            continue
        try:
            timestamps.append(float(timestamp))
        except ValueError:
            continue
    now = time.time()
    return {str(minutes): sum(timestamp >= now - minutes * 60 for timestamp in timestamps) for minutes in windows}


def xray_conntrack_bypass_snapshot(port: int) -> dict[str, bool]:
    result = run(["nft", "list", "table", "inet", "vpnstack"], timeout=5)
    lines = result.stdout.splitlines() if result.returncode == 0 else []
    ingress = any(f"tcp dport {port}" in line and "notrack" in line and "vpnstack-xray-in-notrack" in line for line in lines)
    egress = any(f"tcp sport {port}" in line and "notrack" in line and "vpnstack-xray-out-notrack" in line for line in lines)
    return {"active": ingress and egress, "ingress": ingress, "egress": egress}


def conntrack_snapshot(*, full_logs: bool = True) -> dict[str, Any]:
    def number(path: str) -> int:
        try:
            return int(Path(path).read_text().strip())
        except (OSError, ValueError):
            return 0

    count = number("/proc/sys/net/netfilter/nf_conntrack_count")
    maximum = number("/proc/sys/net/netfilter/nf_conntrack_max")
    return {
        "count": count,
        "max": maximum,
        "percent": round(count * 100 / maximum, 2) if maximum else 0.0,
        "table_full_events": kernel_conntrack_full_windows(full_logs=full_logs),
    }


def probe_url(
    url: str,
    *,
    interface: str = "",
    proxy: str = "",
    timeout: int = 8,
    ip_version: int = 4,
    insecure: bool = False,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    args = ["curl"]
    if not proxy:
        args.append(f"-{ip_version}")
    if follow_redirects:
        args.append("-L")
    args.extend(["--head", "-sS", "-o", "/dev/null", "-w", "%{http_code}|%{time_connect}|%{time_total}|%{remote_ip}", "--connect-timeout", "5", "--max-time", str(timeout)])
    if insecure:
        args.append("-k")
    if interface:
        args.extend(["--interface", interface])
    if proxy:
        args.extend(["--proxy", proxy])
    args.append(url)
    result = run(args, timeout=timeout + 2)
    fields = result.stdout.strip().split("|")
    return {
        "target": url,
        "ok": result.returncode == 0 and len(fields) == 4 and fields[0] != "000",
        "http_code": fields[0] if fields else "000",
        "connect_s": float(fields[1]) if len(fields) > 1 and fields[1] else None,
        "total_s": float(fields[2]) if len(fields) > 2 and fields[2] else None,
        "remote_ip": fields[3] if len(fields) > 3 else "",
        "error": result.stderr.strip()[:240],
    }


def probe_url_matrix(targets: list[tuple[str, dict[str, Any]]], paths: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any] | None]] = {name: [None] * len(targets) for name in paths}
    with ThreadPoolExecutor(max_workers=max(1, min(12, len(targets) * len(paths)))) as executor:
        futures = {
            executor.submit(probe_url, url, **target_options, **path_options): (path_name, index)
            for path_name, path_options in paths.items()
            for index, (url, target_options) in enumerate(targets)
        }
        for future, (path_name, index) in futures.items():
            results[path_name][index] = future.result()
    return {name: [item for item in values if item is not None] for name, values in results.items()}


def probe_identity(*, interface: str = "", proxy: str = "", timeout: int = 8) -> dict[str, Any]:
    args = ["curl"]
    if not proxy:
        args.append("-4")
    args.extend(["-k", "-fsS", "--connect-timeout", "5", "--max-time", str(timeout)])
    if interface:
        args.extend(["--interface", interface])
    if proxy:
        args.extend(["--proxy", proxy])
    args.append("https://1.1.1.1/cdn-cgi/trace")
    result = run(args, timeout=timeout + 2)
    value = next((line.partition("=")[2].strip() for line in result.stdout.splitlines() if line.startswith("ip=")), "")
    try:
        valid = ipaddress.ip_address(value).version == 4
    except ValueError:
        valid = False
    return {"ok": result.returncode == 0 and valid, "egress_ip": value if valid else "", "error": result.stderr.strip()[:240]}


def probe_private_reject(proxy: str) -> dict[str, Any]:
    """Verify that private and fake destinations fail at the local policy boundary."""

    targets = ("http://10.0.0.1:80/", "http://172.19.0.2:853/")
    results: list[dict[str, Any]] = []
    for target in targets:
        started = time.monotonic()
        result = run(
            ["curl", "-4", "-sS", "-o", "/dev/null", "--proxy", proxy, "--connect-timeout", "2", "--max-time", "4", target],
            timeout=6,
        )
        total_s = round(time.monotonic() - started, 3)
        results.append(
            {
                "target": target,
                "ok": result.returncode != 0 and total_s < 2,
                "total_s": total_s,
                "error": result.stderr.strip()[:240],
            }
        )
    return {"ok": all(item["ok"] for item in results), "targets": results}


def failed_requirements(probes: dict[str, Any]) -> list[str]:
    requirements = probes.get("requirements", {})
    if not isinstance(requirements, dict):
        return []
    return sorted(str(name) for name, passed in requirements.items() if passed is not True)


def release_gate_requirements(requirements: dict[str, bool]) -> dict[str, bool]:
    return {name: passed for name, passed in requirements.items() if name not in OPTIONAL_TRANSPORT_REQUIREMENTS}


def release_gate_ok(probes: dict[str, Any]) -> bool:
    if probes.get("profile") == "acceptance":
        return probes.get("release_gate_ok") is True
    return probes.get("ok") is True


def _configured_node_ip(env: Mapping[str, str], contract: Mapping[str, Any], node_id: str) -> str:
    if node_id == NODE_EXIT:
        return str(env.get("EXIT_PUBLIC_IP") or "")
    return str(env.get("GATEWAY_PUBLIC_IP") or "")


def run_probes(env: dict[str, str], contract: Mapping[str, Any], profile: str) -> dict[str, Any]:
    topology = str(contract.get("topology", TOPOLOGY_DUAL))
    node_id = str(contract.get("node_id", ""))
    has_router = contract_has(contract, CAP_ROUTER)
    has_interserver_client = contract_has(contract, CAP_INTERSERVER_CLIENT)
    wg_interface = env.get("WG_INTERFACE", "wg0")
    targets = ["https://www.google.com/generate_204"]
    required_targets = tuple(targets)
    observed_targets: tuple[str, ...] = ()
    if profile == "acceptance":
        required_targets = ACCEPTANCE_REQUIRED_TARGETS
        observed_targets = ACCEPTANCE_OBSERVED_TARGETS
        targets = [*required_targets, *observed_targets]
    paths = {"direct": {}}
    if has_router:
        paths["router"] = {"proxy": "socks5h://127.0.0.1:2080"}
        if profile == "acceptance" and has_interserver_client:
            paths["via_wg"] = {"interface": wg_interface}
    domain_matrix = probe_url_matrix([(url, {}) for url in targets], paths)
    direct = domain_matrix["direct"]
    via_wg = domain_matrix.get("via_wg", [])
    router = domain_matrix.get("router", [])
    by_target = lambda values: {str(item.get("target", "")): item for item in values}
    direct_by_target = by_target(direct)
    wg_by_target = by_target(via_wg)
    router_by_target = by_target(router)
    required_domain_results = lambda values: [item for item in values if item.get("target") in required_targets]
    observations = {
        target: {
            "direct": direct_by_target.get(target),
            "via_wg": wg_by_target.get(target),
            "router": router_by_target.get(target),
        }
        for target in observed_targets
    }
    result: dict[str, Any] = {
        "profile": profile,
        "required_targets": list(required_targets),
        "observed_targets": list(observed_targets),
        "observations": observations,
        "direct": direct,
        "via_wg": via_wg,
        "router": router,
    }
    if profile != "acceptance":
        if has_router:
            router_requirement = "foreign_domains_via_router" if has_interserver_client else "domains_via_router"
            required_paths = {router_requirement: router}
            if has_interserver_client and not all(item["ok"] for item in router):
                via_wg = probe_url_matrix(
                    [(url, {}) for url in required_targets],
                    {"via_wg": {"interface": wg_interface}},
                )["via_wg"]
                result["via_wg"] = via_wg
                required_paths["foreign_domains_via_wg"] = via_wg
        else:
            required_paths = {"egress_direct": direct}
        result["requirements"] = {name: all(item["ok"] for item in items) for name, items in required_paths.items()}
        required_names = {"egress_direct"} if not has_router else {router_requirement}
        result["ok"] = all(result["requirements"].get(name) is True for name in required_names)
        return result
    ipv4_literal_url = "https://1.1.1.1/cdn-cgi/trace"
    ipv6_literal_url = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
    literal_matrix = probe_url_matrix(
        [
            (ipv4_literal_url, {"insecure": True, "follow_redirects": False}),
            (ipv6_literal_url, {"ip_version": 6, "insecure": True, "follow_redirects": False}),
        ],
        paths,
    )
    literal_direct = literal_matrix["direct"]
    literal_wg = literal_matrix.get("via_wg", [])
    literal_router = literal_matrix.get("router", [])
    def expected_identity(probe: dict[str, Any], expected_ip: str) -> dict[str, Any]:
        observed_ip = str(probe.get("egress_ip", "")).strip()
        matches = bool(expected_ip) and observed_ip == expected_ip
        return {**probe, "expected_ip": expected_ip, "identity_match": matches, "ok": probe.get("ok") is True and matches}

    direct_expected = _configured_node_ip(env, contract, node_id)
    identities: dict[str, dict[str, Any]] = {"direct": expected_identity(probe_identity(), direct_expected)}
    if has_router:
        routed_egress_ip = (
            _configured_node_ip(env, contract, NODE_EXIT)
            if topology == TOPOLOGY_DUAL
            else _configured_node_ip(env, contract, NODE_GATEWAY)
        )
        identities["router"] = expected_identity(probe_identity(proxy="socks5h://127.0.0.1:2080"), routed_egress_ip)
        if has_interserver_client:
            identities["via_wg"] = expected_identity(probe_identity(interface=wg_interface), routed_egress_ip)
    private_reject = probe_private_reject("socks5h://127.0.0.1:2080") if has_router else {"ok": True, "not_applicable": True}
    if has_interserver_client:
        hysteria_candidate = transport_candidate_probe(TRANSPORT_HY2_TAG)
        required_paths: dict[str, list[dict[str, Any]]] = {
            "ru_direct_identity": [identities["direct"]],
            "foreign_domains_via_wg": required_domain_results(via_wg),
            "foreign_domains_via_router": required_domain_results(router),
            "ipv4_literal_via_foreign": [literal_router[0]],
            "ipv6_literal_via_router": [literal_router[1]],
            "egress_identities": [identities["router"]],
            "wireguard_candidate_ipv4": [literal_wg[0]],
            "wireguard_candidate_identity": [identities["via_wg"]],
            "hysteria_candidate_reachable": [hysteria_candidate],
            "private_fake_reject": [private_reject],
        }
    elif has_router:
        required_paths = {
            "gateway_direct_identity": [identities["direct"]],
            "domains_via_router": required_domain_results(router),
            "ipv4_literal_via_router": [literal_router[0]],
            "ipv6_literal_via_router": [literal_router[1]],
            "egress_identities": [identities["router"]],
            "private_fake_reject": [private_reject],
        }
    else:
        required_paths = {
            "egress_domains": required_domain_results(direct),
            "ipv4_literal": [literal_direct[0]],
            "ipv6_literal": [literal_direct[1]],
            "egress_identity": [identities["direct"]],
        }
    requirements = {name: all(item["ok"] for item in items) for name, items in required_paths.items()}
    gate_requirements = release_gate_requirements(requirements)
    failed_names = {name for name, passed in requirements.items() if passed is not True}
    result.update(
        {
            "identities": identities,
            "ipv4_literal": {"direct": literal_direct[0], "via_wg": literal_wg[0] if literal_wg else None, "router": literal_router[0] if literal_router else None},
            "ipv6_literal": {"direct": literal_direct[1], "via_wg": literal_wg[1] if literal_wg else None, "router": literal_router[1] if literal_router else None},
            "blocked_private_fake": private_reject,
            "requirements": requirements,
            "capability_failures": {
                "external": sorted(failed_names & EXTERNAL_CAPABILITY_REQUIREMENTS),
                "transport": sorted(failed_names & OPTIONAL_TRANSPORT_REQUIREMENTS),
            },
            "ok": all(requirements.values()),
            "release_gate_requirements": gate_requirements,
            "release_gate_ok": all(gate_requirements.values()),
        }
    )
    return result


def run_confirmed_probes(env: dict[str, str], contract: Mapping[str, Any], profile: str) -> dict[str, Any]:
    """Confirm an acceptance failure before it can reject or roll back a release."""

    first = run_probes(env, contract, profile)
    if profile != "acceptance" or release_gate_ok(first):
        first["confirmation"] = {"cycles": 1, "confirmed_failure": False, "recovered_on_retry": False}
        return first
    time.sleep(PROBE_CONFIRMATION_DELAY_SECONDS)
    retry = run_probes(env, contract, profile)
    retry_passed = release_gate_ok(retry)
    retry["confirmation"] = {
        "cycles": 2,
        "confirmed_failure": not retry_passed,
        "recovered_on_retry": retry_passed,
        "initial_failed_requirements": failed_requirements(first),
        "failed_requirements": failed_requirements(retry),
    }
    return retry


def maintenance_snapshot() -> dict[str, Any]:
    result = run(["apt", "list", "--upgradable"], timeout=20)
    if result.returncode != 0:
        return {"collector_error": (result.stderr.strip() or "apt list failed")[:240]}
    lines = [line for line in result.stdout.splitlines() if "/" in line and not line.startswith("Listing")]
    security = [line for line in lines if "security" in line.lower()]
    os_release = os_release_fields()
    return {
        "upgradable": len(lines),
        "security_upgradable": len(security),
        "reboot_required": Path("/var/run/reboot-required").exists(),
        "kernel": os.uname().release,
        "os": os_release.get("PRETTY_NAME", ""),
    }


def decode_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def root_fstab_passno(path: Path = FSTAB_PATH) -> int | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 6 or decode_mount_field(fields[1]) != "/":
            continue
        try:
            return int(fields[5])
        except ValueError:
            return None
    return None


def root_mount(path: Path = PROC_MOUNTS_PATH) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and decode_mount_field(fields[1]) == "/":
            return {
                "source": decode_mount_field(fields[0]),
                "filesystem": fields[2],
                "options": fields[3],
            }
    return {}


def read_counter(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def block_device_name(source: str, sys_dev_block_root: Path = SYS_DEV_BLOCK_ROOT) -> str:
    fallback = Path(os.path.realpath(source)).name
    try:
        device = os.stat(source).st_rdev
        uevent = sys_dev_block_root / f"{os.major(device)}:{os.minor(device)}" / "uevent"
        for line in uevent.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key == "DEVNAME" and value:
                return Path(value).name
    except (AttributeError, OSError, ValueError):
        pass
    return fallback


def root_filesystem_snapshot(
    mounts_path: Path = PROC_MOUNTS_PATH,
    fstab_path: Path = FSTAB_PATH,
    ext4_sysfs_root: Path = EXT4_SYSFS_ROOT,
    sys_dev_block_root: Path = SYS_DEV_BLOCK_ROOT,
) -> dict[str, Any]:
    mount = root_mount(mounts_path)
    source = mount.get("source", "")
    filesystem = mount.get("filesystem", "")
    passno = root_fstab_passno(fstab_path)
    result: dict[str, Any] = {
        **mount,
        "fstab_passno": passno,
        "boot_check_enabled": passno is not None and passno > 0,
        "state": "unknown",
        "errors_count": None,
        "first_error_time": None,
        "last_error_time": None,
        "last_checked": "",
        "verdict": "inconclusive",
        "reason": "root filesystem state is unavailable",
    }
    if filesystem != "ext4" or not source:
        result["reason"] = f"unsupported root filesystem: {filesystem or 'unknown'}"
        return result
    device = os.path.realpath(source)
    sysfs = ext4_sysfs_root / block_device_name(source, sys_dev_block_root)
    result["errors_count"] = read_counter(sysfs / "errors_count")
    result["first_error_time"] = read_counter(sysfs / "first_error_time")
    result["last_error_time"] = read_counter(sysfs / "last_error_time")
    tune = run(["tune2fs", "-l", device], timeout=8)
    metadata: dict[str, str] = {}
    if tune.returncode == 0:
        for line in tune.stdout.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                metadata[key.strip()] = value.strip()
    result["state"] = metadata.get("Filesystem state", "unknown")
    result["last_checked"] = metadata.get("Last checked", "")
    if result["errors_count"] is None:
        try:
            result["errors_count"] = int(metadata.get("FS Error count", ""))
        except ValueError:
            pass
    state = str(result["state"]).lower()
    error_count = result["errors_count"]
    if (isinstance(error_count, int) and error_count > 0) or "error" in state:
        result.update(verdict="failed", reason="ext4 metadata errors require offline fsck")
    elif state != "clean":
        result.update(verdict="inconclusive", reason=f"unexpected ext4 state: {result['state']}")
    elif error_count is None:
        result.update(verdict="inconclusive", reason="current ext4 error counter is unavailable")
    elif not result["boot_check_enabled"]:
        result.update(verdict="degraded", reason="root filesystem boot-time fsck is disabled in fstab")
    else:
        result.update(verdict="verified", reason="")
    return result


def os_release_fields() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
    except OSError:
        pass
    return values


def resolver_snapshot() -> dict[str, Any]:
    try:
        target = os.path.realpath(RESOLV_CONF_PATH)
    except OSError:
        target = ""
    try:
        lines = RESOLVED_DROPIN_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    dns_line = next((line.partition("=")[2].strip() for line in lines if line.startswith("DNS=")), "")
    stale_retention = next((line.partition("=")[2].strip() for line in lines if line.startswith("StaleRetentionSec=")), "")
    return {
        "resolv_conf_target": target,
        "managed_stub": target == RESOLVED_STUB_PATH,
        "upstreams": dns_line.split(),
        "cache_enabled": any(line.strip() == "Cache=yes" for line in lines),
        "stale_retention": stale_retention,
    }


def host_snapshot(default_iface: str) -> dict[str, Any]:
    is_root = bool(getattr(os, "geteuid", lambda: 1)() == 0)
    has_sudo = is_root or run(["sudo", "-n", "true"], timeout=2).returncode == 0
    os_release = os_release_fields()
    return {
        "hostname": socket.getfqdn() or socket.gethostname(),
        "login_user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
        "is_root": is_root,
        "has_sudo": has_sudo,
        "os_id": os_release.get("ID", ""),
        "os_version": os_release.get("VERSION_ID", ""),
        "default_interface": default_iface,
    }


def probe_requirement(probes: dict[str, Any], name: str) -> bool:
    requirements = probes.get("requirements", {})
    return isinstance(requirements, dict) and requirements.get(name) is True


def probe_path_ok(probes: dict[str, Any], *requirement_names: str) -> bool:
    return any(probe_requirement(probes, name) for name in requirement_names)


def collect_runtime_facts(*, live_probes: bool = False, profile: str = "light", full_logs: bool = True, include_maintenance: bool = True) -> dict[str, Any]:
    env = parse_env()
    manifest_data = manifest_snapshot()
    manifest = manifest_data.get("manifest", {})
    contract_error = ""
    try:
        contract = runtime_contract(manifest if isinstance(manifest, Mapping) else {}, env)
    except RuntimeError as exc:
        contract_error = str(exc)
        contract = {
            "topology": "",
            "node_id": "",
            "location": "",
            "capabilities": frozenset(),
            "required_services": (),
            "service_units": {},
            "role": "unknown",
            "migration": {"state": "invalid", "message": contract_error},
        }
    topology = str(contract.get("topology", ""))
    node_id = str(contract.get("node_id", ""))
    location = str(contract.get("location", ""))
    capabilities = frozenset(str(value) for value in contract.get("capabilities", ()))
    role = str(contract.get("role", "unknown"))
    has_interserver = bool(capabilities & INTERSERVER_CAPABILITIES)
    has_interserver_client = CAP_INTERSERVER_CLIENT in capabilities
    has_interserver_server = CAP_INTERSERVER_SERVER in capabilities
    has_public_front = CAP_PUBLIC_FRONT in capabilities
    wg_interface = env.get("WG_INTERFACE", "wg0")
    public_iface = default_interface()
    port = int(env.get("RU_LISTEN_PORT", "443") or 443)

    services = {name: "not-applicable" for name in SERVICE_UNIT_DEFAULTS}
    service_units = contract.get("service_units", {}) if isinstance(contract.get("service_units"), Mapping) else {}
    for name in contract.get("required_services", ()):
        unit = str(service_units.get(name, SERVICE_UNIT_DEFAULTS.get(name, ""))).format(wg_interface=wg_interface)
        services[str(name)] = service_state(unit) if unit else "unknown"

    fresh_since, fresh_window_minutes = fresh_log_since()
    if not full_logs and fresh_window_minutes > 5:
        fresh_since, fresh_window_minutes = "5 minutes ago", 5
    maintenance = maintenance_snapshot() if include_maintenance else {}
    logs, fresh_logs, logs_collector_error = summarize_problem_windows(full_logs=full_logs, fresh_since=fresh_since)
    front = tcp_front_snapshot(port) if has_public_front else {}
    probes = run_confirmed_probes(env, contract, profile) if live_probes and not contract_error else {"profile": "none", "ok": None}
    transport: dict[str, Any] = {}
    if has_interserver:
        transport["interserver"] = interserver_transport_snapshot(contract, env)
    if has_public_front:
        transport["udp_443_policy"] = udp_443_policy()
        transport["public_client"] = public_hy2_snapshot(port)
    tcp_adaptation = tcp_adaptation_snapshot(public_iface, wg_interface if has_interserver else "")
    resolver = resolver_snapshot()
    root_filesystem = root_filesystem_snapshot()
    conntrack = conntrack_snapshot(full_logs=full_logs)
    if has_public_front:
        conntrack["front_bypass"] = xray_conntrack_bypass_snapshot(port)
    expected_network_profile = managed_network_profile(include_overlay=has_interserver)
    actual_network_profile = {**tcp_adaptation, "conntrack_max": conntrack.get("max", 0)}
    profile_mismatches = network_profile_mismatches(actual_network_profile, expected_network_profile)
    wireguard_policy = (
        wireguard_policy_snapshot(env, managed=True)
        if has_interserver_client
        else {"managed": False, "ok": True, "not_applicable": True}
    )
    health_state = read_json(HEALTH_STATE_PATH, {})
    recent_front_interval = recent_observation(health_state.get("front_interval", {}), max_age_seconds=300)
    release_installed_at = installed_at_value()
    recent_front_interval = release_scoped_observation(recent_front_interval, release_installed_at)
    if front and recent_front_interval:
        front["recent_interval"] = recent_front_interval

    reasons = ([f"contract={contract_error}"] if contract_error else [])
    reasons.extend(
        f"{name}={services.get(name, 'unknown')}"
        for name in contract.get("required_services", ())
        if services.get(name) != "active"
    )
    if manifest_data.get("drift") != "none":
        reasons.append(f"drift={manifest_data.get('drift', 'unknown')}")
    if profile_mismatches:
        reasons.append(f"network_profile={','.join(profile_mismatches)}")
    if wireguard_policy.get("managed") and not wireguard_policy.get("ok"):
        reasons.append(f"wireguard_policy={','.join(wireguard_policy.get('missing', [])) or 'invalid'}")
    if not resolver.get("managed_stub"):
        reasons.append(f"resolver_stub={resolver.get('resolv_conf_target') or 'missing'}")
    if live_probes and not contract_error and not release_gate_ok(probes):
        failed = ",".join(failed_requirements(probes))
        reasons.append(f"live_probes_failed:{failed}" if failed else "live_probes_failed")
    if has_public_front and transport.get("udp_443_policy") != "routed":
        reasons.append(f"udp_443_policy={transport.get('udp_443_policy')}")
    public_client_transport = transport.get("public_client", {})
    if has_public_front:
        for requirement in ("configured", "listening", "firewall"):
            if public_client_transport.get(requirement) is not True:
                reasons.append(f"public_hy2_{requirement}=false")
        if not conntrack.get("front_bypass", {}).get("active"):
            reasons.append("xray_conntrack_bypass=inactive")
    interserver = transport.get("interserver", {})
    if has_interserver and not interserver.get("configured"):
        reasons.append("interserver_transport=not-configured")
    if has_interserver_server and not interserver.get("listening"):
        reasons.append("interserver_transport=not-listening")
    if has_interserver_client and not interserver.get("selection", {}).get("available"):
        reasons.append("interserver_overlay_endpoint=unavailable")
    adaptation_failure = adaptation_degradation = ""
    if has_interserver_client:
        adaptation_failure, adaptation_degradation = classify_interserver_adaptation(interserver.get("adaptive_state", {}))
        if adaptation_failure:
            reasons.append(adaptation_failure)

    capability_failures = [name for name in failed_requirements(probes) if name in EXTERNAL_CAPABILITY_REQUIREMENTS] if live_probes else []
    transport_failures = [name for name in failed_requirements(probes) if name in OPTIONAL_TRANSPORT_REQUIREMENTS] if live_probes else []
    server_path = "failed" if reasons else "verified" if live_probes else "inconclusive"
    host_integrity = str(root_filesystem.get("verdict", "inconclusive"))
    client_observation = front_observation(front, recent_front_interval) if front else "not-applicable"
    closing_churn = closing_churn_observation(front) if front else "not-applicable"
    public_front = public_front_verdict(services["xray"], front, recent_front_interval) if has_public_front else "not-applicable"
    public_quic = (
        "verified" if all(public_client_transport.get(name) is True for name in ("configured", "listening", "firewall")) else "failed"
    ) if has_public_front else "not-applicable"
    external_capabilities = "degraded" if capability_failures else "verified" if live_probes else "inconclusive"
    degradations = ([f"external_capabilities_failed:{','.join(capability_failures)}"] if capability_failures else [])
    if public_front == "degraded":
        degradations.append(f"public_front={client_observation}")
    if transport_failures:
        degradations.append(f"transport_capability_failed:{','.join(transport_failures)}")
    if adaptation_degradation:
        degradations.append(adaptation_degradation)
    if host_integrity in {"degraded", "inconclusive"}:
        degradations.append(f"host_integrity={host_integrity}:{root_filesystem.get('reason') or 'unknown'}")
    selected_transport = str(interserver.get("selection", {}).get("selected", ""))
    recent_conntrack_full = int(conntrack.get("table_full_events", {}).get("5", 0))
    if recent_conntrack_full:
        degradations.append(f"conntrack_table_full_5m={recent_conntrack_full}")
    overall = "failed" if "failed" in {server_path, public_front, public_quic, host_integrity} else "degraded" if degradations or client_observation in {"client_specific", "degraded"} else "verified" if server_path == "verified" else "inconclusive"
    healthy_exits = int(services.get("sing-box") == "active" and (not live_probes or release_gate_ok(probes)))
    interface_names = (public_iface, wg_interface) if has_interserver else (public_iface,)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "deployment": env.get("DEPLOY_NAME", ""),
        "topology": topology,
        "node_id": node_id,
        "location": location,
        "capabilities": sorted(capabilities),
        "role": role,
        "migration": dict(contract.get("migration", {})),
        "contract_error": contract_error,
        "required_services": list(contract.get("required_services", ())),
        "service_units": dict(service_units),
        "release": {
            "version": manifest.get("version", "") if isinstance(manifest, Mapping) else "",
            "release_id": manifest.get("release_id", "") if isinstance(manifest, Mapping) else "",
            "policy_version": manifest.get("policy_version", "") if isinstance(manifest, Mapping) else "",
            "manifest_schema": manifest.get("schema_version", 0) if isinstance(manifest, Mapping) else 0,
            "runtime": manifest.get("runtime", {}) if isinstance(manifest, Mapping) else {},
            "installed_at": release_installed_at,
        },
        "host": host_snapshot(public_iface),
        "storage": {"root_filesystem": root_filesystem},
        "services": services,
        "artifacts": manifest_data,
        "wireguard": wireguard_snapshot(wg_interface) if has_interserver else {},
        "network": {
            "interfaces": interface_counters(interface_names),
            "conntrack": conntrack,
            "tcp_adaptation": tcp_adaptation,
            "resolver": resolver,
            "managed_profile": expected_network_profile,
            "profile_mismatches": profile_mismatches,
            "wireguard_policy": wireguard_policy,
            "protocol_counters": protocol_counters_snapshot(),
            "softnet_counters": softnet_counters_snapshot(),
            "recent_health_deltas": health_state.get("network_deltas", {}),
            "health_state": health_state.get("state", "unknown"),
            "health_updated_at": health_state.get("updated_at", ""),
            "health_soft_reasons": health_state.get("soft_reasons", []),
            "last_front_degradation": health_state.get("last_front_degradation", {}),
            "recent_front_interval": recent_front_interval,
        },
        "front": front,
        "transport": transport,
        "probes": probes,
        "logs": {
            "collector_error": logs_collector_error,
            "fresh": {"since": fresh_since, "window_minutes": fresh_window_minutes, **fresh_logs},
            "windows_minutes": logs,
        },
        "maintenance": maintenance,
        "redundancy": {
            "egress": {"available": False, "healthy_exits": healthy_exits, "reason": "one egress node configured"},
            "transport": {
                "available": bool(interserver.get("configured")) if has_interserver else False,
                "selected": selected_transport or (TRANSPORT_HY2_TAG if interserver.get("listening") else ""),
                "not_applicable": not has_interserver,
            },
        },
        "verdicts": {
            "server_path": server_path,
            "public_front": public_front,
            "public_quic": public_quic,
            "client_observation": client_observation,
            "closing_churn": closing_churn,
            "host_integrity": host_integrity,
            "external_capabilities": external_capabilities,
            "overall": overall,
            "reasons": reasons + degradations + ([f"host_integrity=failed:{root_filesystem.get('reason') or 'unknown'}"] if host_integrity == "failed" else []),
        },
    }


def _diagnostics_log_window(raw: object, *, generated_at: str, since: str) -> LogWindowSnapshot:
    if not isinstance(raw, Mapping) or not isinstance(raw.get("counts"), Mapping):
        return LogWindowSnapshot.unavailable("log window was not collected")
    return LogWindowSnapshot.collected(
        raw["counts"],
        observed_at=generated_at,
        since=since,
        until=generated_at,
        top_destinations=raw.get("top_destinations") if isinstance(raw.get("top_destinations"), Mapping) else None,
        top_sources=raw.get("top_sources") if isinstance(raw.get("top_sources"), Mapping) else None,
        samples=raw.get("samples") if isinstance(raw.get("samples"), Mapping) else None,
    )


def _collector_state(condition: bool, generated_at: str, message: str) -> CollectorState:
    return CollectorState.ok(generated_at) if condition else CollectorState.error(message)


def diagnostics_snapshot(**snapshot_options: Any) -> dict[str, Any]:
    facts = collect_runtime_facts(**snapshot_options)
    generated_at = str(facts["generated_at"])
    role = str(facts.get("role", ""))
    topology = str(facts.get("topology", ""))
    node_id = str(facts.get("node_id", ""))
    location = str(facts.get("location", ""))
    raw_capabilities = facts.get("capabilities", ())
    capabilities = tuple(str(value) for value in raw_capabilities) if isinstance(raw_capabilities, (list, tuple, set, frozenset)) else ()
    migration = facts.get("migration", {}) if isinstance(facts.get("migration"), Mapping) else {}
    capability_set = frozenset(capabilities)
    has_interserver = bool(capability_set & INTERSERVER_CAPABILITIES)
    has_public_front = CAP_PUBLIC_FRONT in capability_set
    contract_error = str(facts.get("contract_error", ""))
    live_probes = bool(snapshot_options.get("live_probes", False))
    full_logs = bool(snapshot_options.get("full_logs", True))
    include_maintenance = bool(snapshot_options.get("include_maintenance", True))
    logs = facts.get("logs", {})
    minute_windows = logs.get("windows_minutes", {}) if isinstance(logs, Mapping) else {}
    fresh = logs.get("fresh", {}) if isinstance(logs, Mapping) else {}
    log_error = str(logs.get("collector_error", "")) if isinstance(logs, Mapping) else "invalid logs section"
    services = facts.get("services", {}) if isinstance(facts.get("services"), Mapping) else {}
    artifacts = facts.get("artifacts", {}) if isinstance(facts.get("artifacts"), Mapping) else {}
    wireguard = facts.get("wireguard", {}) if isinstance(facts.get("wireguard"), Mapping) else {}
    probes = facts.get("probes", {}) if isinstance(facts.get("probes"), Mapping) else {}
    storage = facts.get("storage", {}) if isinstance(facts.get("storage"), Mapping) else {}
    network = facts.get("network", {}) if isinstance(facts.get("network"), Mapping) else {}
    front = facts.get("front", {}) if isinstance(facts.get("front"), Mapping) else {}
    transport = facts.get("transport", {}) if isinstance(facts.get("transport"), Mapping) else {}
    maintenance = facts.get("maintenance", {}) if isinstance(facts.get("maintenance"), Mapping) else {}
    collectors = {
        "services": _collector_state(bool(services) and not contract_error and "unknown" not in services.values(), generated_at, contract_error or "service state is unavailable"),
        "artifacts": _collector_state(
            isinstance(artifacts.get("manifest"), Mapping) and bool(artifacts.get("manifest")),
            generated_at,
            "render manifest is unavailable",
        ),
        "wireguard": (
            _collector_state(bool(wireguard.get("interface")) and wireguard.get("state") in {"up", "down"}, generated_at, "WireGuard state is unavailable")
            if has_interserver
            else CollectorState.not_applicable("node plan has no interserver overlay")
        ),
        "route_probes": (
            _collector_state(probes.get("profile") not in {None, "none"}, generated_at, "live route probes were not collected")
            if live_probes
            else CollectorState.skipped("live route probes were not requested")
        ),
        "logs": _collector_state(not log_error, generated_at, log_error or "journal collection failed"),
        "storage": _collector_state(isinstance(storage.get("root_filesystem"), Mapping) and bool(storage.get("root_filesystem")), generated_at, "root filesystem state is unavailable"),
        "network": _collector_state(
            all(isinstance(network.get(key), Mapping) and bool(network.get(key)) for key in ("tcp_adaptation", "resolver", "conntrack")),
            generated_at,
            "network state is incomplete",
        ),
        "front": (
            _collector_state("listening" in front, generated_at, "public front state is unavailable")
            if has_public_front
            else CollectorState.not_applicable("node plan has no public front")
        ),
        "transport": (
            _collector_state(isinstance(transport.get("interserver"), Mapping) and bool(transport.get("interserver")), generated_at, "interserver transport state is unavailable")
            if has_interserver
            else CollectorState.not_applicable("node plan has no interserver transport")
        ),
        "maintenance": (
            _collector_state(bool(maintenance) and not maintenance.get("collector_error"), generated_at, str(maintenance.get("collector_error") or "maintenance state was not collected"))
            if include_maintenance
            else CollectorState.skipped("maintenance state was not requested")
        ),
    }
    if set(collectors) != set(COLLECTOR_NAMES):
        raise RuntimeError("diagnostics collectors do not match the schema")
    if log_error:
        log_windows = {
            name: LogWindowSnapshot.unavailable(log_error)
            for name in ("5m", "30m", "24h", "since_release")
        }
    else:
        release = facts.get("release", {}) if isinstance(facts.get("release"), Mapping) else {}
        release_installed_at = str(release.get("installed_at", ""))
        since_release = (
            _diagnostics_log_window(fresh, generated_at=generated_at, since=release_installed_at)
            if release_installed_at and str(fresh.get("since", "")) == release_installed_at
            else LogWindowSnapshot.skipped("complete since-release log window was not requested")
            if not full_logs
            else LogWindowSnapshot.unavailable("complete since-release log window is unavailable")
        )
        log_windows = {
            "5m": _diagnostics_log_window(minute_windows.get("5"), generated_at=generated_at, since="5 minutes ago"),
            "30m": _diagnostics_log_window(minute_windows.get("30"), generated_at=generated_at, since="30 minutes ago") if full_logs else LogWindowSnapshot.skipped("30m window was not requested"),
            "24h": _diagnostics_log_window(minute_windows.get("1440"), generated_at=generated_at, since="1440 minutes ago") if full_logs else LogWindowSnapshot.skipped("24h window was not requested"),
            "since_release": since_release,
        }
    artifact_files = artifacts.get("files", {}) if isinstance(artifacts, Mapping) else {}
    sing_box = artifact_files.get("sing-box.json", {}) if isinstance(artifact_files, Mapping) else {}
    verdicts = facts.get("verdicts", {}) if isinstance(facts.get("verdicts"), Mapping) else {}
    reasons = verdicts.get("reasons", []) if isinstance(verdicts, Mapping) else []
    payload = DiagnosticsSnapshot(
        generated_at=generated_at,
        deployment=str(facts.get("deployment", "")),
        topology=topology,
        node_id=node_id,
        location=location,
        capabilities=capabilities,
        role=role,
        host=dict(facts.get("host", {})),
        collectors=collectors,
        log_windows=log_windows,
        services={str(key): str(value) for key, value in services.items()},
        installed_env_hash=str(artifacts.get("installed_env_sha256", "")),
        installed_config_hash=str(sing_box.get("actual_sha256", "")),
        rendered_config_hash=str(sing_box.get("expected_sha256", "")),
        render_manifest=dict(artifacts.get("manifest", {})),
        drift=str(artifacts.get("drift", "unknown")),
        wg_state=dict(wireguard),
        route_probes=dict(probes),
        verdict=str(verdicts.get("overall", "inconclusive")),
        reasons=[str(reason) for reason in reasons],
        release=dict(facts.get("release", {})),
        artifacts=dict(artifacts),
        storage=dict(storage),
        network=dict(network),
        front=dict(front),
        transport=dict(transport),
        maintenance=dict(maintenance),
        redundancy=dict(facts.get("redundancy", {})),
        component_verdicts={str(key): str(value) for key, value in verdicts.items() if key not in {"overall", "reasons"}},
        migration=dict(migration),
    )
    return payload.to_dict()


def health() -> dict[str, Any]:
    install_lock = acquire_install_read_lock()
    if install_lock is None:
        previous = read_json(HEALTH_STATE_PATH, {})
        return {
            **(previous if isinstance(previous, dict) else {}),
            "schema_version": SCHEMA_VERSION,
            "updated_at": utc_now(),
            "state": "maintenance",
            "last_action": "none",
            "maintenance_reason": "install transaction is active",
        }
    try:
        return _health_unlocked()
    finally:
        release_install_read_lock(install_lock)


def _health_unlocked() -> dict[str, Any]:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = collect_runtime_facts(live_probes=True, profile="light", full_logs=False, include_maintenance=False)
        previous = read_json(HEALTH_STATE_PATH, {})
        observed_at = current.get("generated_at") or utc_now()
        front_interval, front_counters = front_interval_snapshot(
            current.get("front", {}),
            previous.get("front_counters", {}),
            observed_at,
        )
        interval_observation = str(front_interval.get("observation", "observed"))
        if interval_observation in {"client_specific", "degraded"}:
            verdicts = current["verdicts"]
            verdicts["client_observation"] = interval_observation
            verdicts["public_front"] = "degraded"
            if verdicts.get("overall") != "failed":
                verdicts["overall"] = "degraded"
            interval_reason = f"public_front_interval={interval_observation}"
            if interval_reason not in verdicts["reasons"]:
                verdicts["reasons"].append(interval_reason)
        now_epoch = int(time.time())
        server_path_failure = current["verdicts"]["server_path"] == "failed"
        host_integrity = current["verdicts"].get("host_integrity", "verified")
        host_integrity_failure = host_integrity == "failed"
        hard_failure = server_path_failure or host_integrity_failure
        hard_reasons = [
            reason
            for reason, failed in (
                ("server_path", server_path_failure),
                ("host_integrity", host_integrity_failure),
            )
            if failed
        ]
        previous_hard_reasons = previous.get("hard_reasons", [])
        same_failure = hard_failure and hard_reasons == previous_hard_reasons
        failures = (int(previous.get("consecutive_failures", 0)) + 1 if same_failure else 1) if hard_failure else 0
        network_counters = {
            "interfaces": current.get("network", {}).get("interfaces", {}),
            "protocol": current.get("network", {}).get("protocol_counters", {}),
            "softnet": current.get("network", {}).get("softnet_counters", {}),
            "qdisc": {
                "drops": int(current.get("network", {}).get("tcp_adaptation", {}).get("qdisc_drops", 0) or 0),
                "flow_limit_drops": int(current.get("network", {}).get("tcp_adaptation", {}).get("qdisc_flow_limit_drops", 0) or 0),
            },
        }
        network_deltas = positive_counter_deltas(network_counters, previous.get("network_counters", {}))
        soft_reasons = network_soft_reasons(network_deltas)
        conntrack_full = int(current.get("network", {}).get("conntrack", {}).get("table_full_events", {}).get("5", 0))
        if conntrack_full:
            soft_reasons.append(f"conntrack_table_full_5m={conntrack_full}")
        client_observation = current.get("verdicts", {}).get("client_observation")
        if client_observation in {"client_specific", "degraded"}:
            soft_reasons.append(f"public_front={client_observation}")
        closing_churn = current.get("verdicts", {}).get("closing_churn")
        if closing_churn in {"client_specific", "shared"}:
            soft_reasons.append(f"public_front_closing_churn={closing_churn}")
        if host_integrity in {"degraded", "inconclusive"}:
            soft_reasons.append(f"host_integrity={host_integrity}")
        front_evidence = front_degradation_evidence(
            current.get("front", {}),
            observed_at,
            front_interval,
        )
        last_front_degradation = front_evidence or previous.get("last_front_degradation", {})
        state = "degraded" if soft_reasons else "healthy"
        action = "none"
        recovery_succeeded = False
        postcheck: dict[str, Any] | None = None
        last_actions = previous.get("last_actions", {})
        if not isinstance(last_actions, dict):
            last_actions = {}
        if hard_failure and failures == 1:
            state = "suspect"
        elif hard_failure:
            state = "failed"
            failure_key = ",".join(hard_reasons)
            last_action = int((last_actions.get(failure_key, {}) or {}).get("epoch", previous.get("last_action_epoch", 0)) or 0)
            if server_path_failure and not host_integrity_failure and now_epoch - last_action >= 900:
                action = recover(current)
                recovery_succeeded = recovery_action_succeeded(action)
                if recovery_succeeded:
                    time.sleep(2)
                    postcheck = collect_runtime_facts(live_probes=True, profile="light", full_logs=False, include_maintenance=False)
                    postcheck_hard_reasons = hard_failure_reasons(postcheck)
                    if not postcheck_hard_reasons:
                        state = "healthy"
                        failures = 0
                    else:
                        state = "recovering"
                    last_actions = dict(last_actions)
                    last_actions[failure_key] = {"epoch": now_epoch, "action": action}
                elif action != "none":
                    state = "failed"
        if postcheck is not None:
            current["post_recovery"] = postcheck["verdicts"]
        payload = {
            "schema_version": SCHEMA_VERSION,
            "updated_at": utc_now(),
            "state": state,
            "consecutive_failures": failures,
            "last_action": action,
            "last_action_epoch": now_epoch if recovery_succeeded else int(previous.get("last_action_epoch", 0)),
            "last_actions": last_actions,
            "hard_reasons": hard_reasons,
            "probe_failures": failed_requirements((postcheck or current).get("probes", {})),
            "probes": (postcheck or current).get("probes", {}),
            "network_counters": network_counters,
            "network_deltas": network_deltas,
            "front_counters": front_counters,
            "front_interval": front_interval,
            "soft_reasons": soft_reasons,
            "last_front_degradation": last_front_degradation,
            "verdicts": (postcheck or current)["verdicts"],
        }
        if postcheck is not None:
            payload["post_recovery_verdicts"] = postcheck["verdicts"]
        write_json_atomic(HEALTH_STATE_PATH, payload)
        return payload


def health_log_summary(payload: dict[str, Any]) -> dict[str, Any]:
    interval = payload.get("front_interval", {})
    if not isinstance(interval, dict):
        interval = {}
    return {
        "schema_version": payload.get("schema_version"),
        "updated_at": payload.get("updated_at"),
        "state": payload.get("state"),
        "consecutive_failures": payload.get("consecutive_failures", 0),
        "last_action": payload.get("last_action", "none"),
        "maintenance_reason": payload.get("maintenance_reason", ""),
        "hard_reasons": payload.get("hard_reasons", []),
        "probe_failures": payload.get("probe_failures", []),
        "soft_reasons": payload.get("soft_reasons", []),
        "verdicts": payload.get("verdicts", {}),
        "front_interval": {
            "observation": interval.get("observation", "observed"),
            "degraded_sources": interval.get("degraded_sources", []),
            "aggregate": interval.get("aggregate", {}),
        },
    }


def positive_counter_deltas(current: Any, previous: Any) -> Any:
    if not isinstance(current, dict) or not isinstance(previous, dict):
        return {}
    deltas: dict[str, Any] = {}
    for key, value in current.items():
        old = previous.get(key)
        if isinstance(value, dict):
            nested = positive_counter_deltas(value, old)
            if nested:
                deltas[key] = nested
        elif isinstance(value, int) and isinstance(old, int) and value >= old and value > old:
            deltas[key] = value - old
    return deltas


def network_soft_reasons(deltas: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    protocol = deltas.get("protocol", {})
    softnet = deltas.get("softnet", {})
    receive_errors = int(protocol.get("UdpRcvbufErrors", 0)) + int(protocol.get("Udp6RcvbufErrors", 0))
    if receive_errors:
        reasons.append(f"udp_receive_buffer_drops={receive_errors}")
    qdisc = deltas.get("qdisc", {})
    qdisc_drops = int(qdisc.get("drops", 0))
    flow_limit_drops = int(qdisc.get("flow_limit_drops", 0))
    if qdisc_drops:
        reasons.append(f"qdisc_drops={qdisc_drops}")
    if flow_limit_drops:
        reasons.append(f"qdisc_flow_limit_drops={flow_limit_drops}")
    send_errors = int(protocol.get("UdpSndbufErrors", 0)) + int(protocol.get("Udp6SndbufErrors", 0))
    qdisc_explains_send_errors = send_errors > 0 and send_errors == qdisc_drops == flow_limit_drops
    if send_errors and not qdisc_explains_send_errors:
        reasons.append(f"udp_send_buffer_drops={send_errors}")
    if int(softnet.get("dropped", 0)):
        reasons.append(f"softnet_drops={softnet['dropped']}")
    missed = sum(int(values.get("rx_missed_errors", 0)) for values in deltas.get("interfaces", {}).values())
    if missed:
        reasons.append(f"interface_rx_missed={missed}")
    return reasons


def hard_failure_reasons(current: dict[str, Any]) -> list[str]:
    verdicts = current.get("verdicts", {})
    return [
        reason
        for reason, failed in (
            ("server_path", verdicts.get("server_path") == "failed"),
            ("host_integrity", verdicts.get("host_integrity") == "failed"),
        )
        if failed
    ]


def recovery_action_succeeded(action: str) -> bool:
    if not action or action == "none":
        return False
    results = action.split(";")
    return all(not result.endswith((":failed", ":invalid-config")) for result in results)


def recover(current: dict[str, Any]) -> str:
    services = current.get("services", {})
    interface = str(current.get("wireguard", {}).get("interface", "wg0"))
    raw_capabilities = current.get("capabilities", ())
    capabilities = frozenset(str(value) for value in raw_capabilities) if isinstance(raw_capabilities, (list, tuple, set, frozenset)) else frozenset()
    required_services = current.get("required_services")
    if not isinstance(required_services, list):
        required_services = []
    required = {str(name) for name in required_services}
    configured_units = current.get("service_units", {}) if isinstance(current.get("service_units"), Mapping) else {}
    actions: list[str] = []
    service_order = ("wireguard", "nftables", "resolver", "sing-box", "xray", "admin", "health_timer", "transport")
    for key in service_order:
        if key not in required or key not in services:
            continue
        unit = str(configured_units.get(key, SERVICE_UNIT_DEFAULTS[key])).format(wg_interface=interface)
        if services.get(key) != "active":
            result = run(["systemctl", "restart", unit], timeout=30)
            actions.append(f"restart:{unit}:{'ok' if result.returncode == 0 else 'failed'}")
    if actions:
        return ";".join(actions)
    artifacts_clean = current.get("artifacts", {}).get("drift") == "none"
    network = current.get("network", {})
    wireguard_policy = network.get("wireguard_policy", {})
    if (
        artifacts_clean
        and CAP_INTERSERVER_CLIENT in capabilities
        and wireguard_policy.get("managed") is True
        and wireguard_policy.get("ok") is not True
    ):
        try:
            applied = apply_wireguard_policy(parse_env())
            return f"apply:wireguard-policy:{'changed' if applied.get('changed') else 'ok'}"
        except (KeyError, RuntimeError, ValueError):
            return "apply:wireguard-policy:failed"
    profile_mismatches = set(network.get("profile_mismatches", []))
    qdisc_mismatches = profile_mismatches & {"qdisc", "qdisc_limit", "qdisc_flow_limit"}
    qdisc_mismatches.update(name for name in profile_mismatches if name.startswith("overlay_qdisc"))
    if artifacts_clean and qdisc_mismatches:
        try:
            applied = (
                apply_qdisc_profile()
                if capabilities & INTERSERVER_CAPABILITIES
                else apply_qdisc_profile(include_overlay=False)
            )
            return f"apply:qdisc:{'changed' if applied.get('changed') else 'ok'}"
        except RuntimeError:
            return "apply:qdisc:failed"
    if artifacts_clean and profile_mismatches:
        result = run(["sysctl", "--load", str(SYSCTL_PATH)], timeout=30)
        return f"reload:sysctl:{'ok' if result.returncode == 0 else 'failed'}"
    bypass = network.get("conntrack", {}).get("front_bypass", {})
    if artifacts_clean and CAP_PUBLIC_FRONT in capabilities and not bypass.get("active"):
        if not NFTABLES_CONFIG_PATH.is_file():
            return "reload:vpn-stack-nftables.service:invalid-config"
        result = run(["systemctl", "reload", NFTABLES_SERVICE], timeout=30)
        return f"reload:{NFTABLES_SERVICE}:{'ok' if result.returncode == 0 else 'failed'}"
    if CAP_ROUTER in capabilities:
        probes = current.get("probes", {})
        router_path_ok = probe_path_ok(probes, "foreign_domains_via_router", "domains_via_router")
        if CAP_INTERSERVER_CLIENT in capabilities:
            independent_path_ok = probe_path_ok(probes, "via_wg", "foreign_domains_via_wg")
        else:
            direct = probes.get("direct", [])
            independent_path_ok = bool(direct) and all(isinstance(item, Mapping) and item.get("ok") is True for item in direct)
        if independent_path_ok and not router_path_ok:
            result = run(["systemctl", "restart", "sing-box.service"], timeout=30)
            return f"restart:sing-box.service:{'ok' if result.returncode == 0 else 'failed'}"
    return "none"


def routes_command(args: argparse.Namespace) -> dict[str, Any]:
    try:
        from . import admin_apply
    except ImportError:
        import admin_apply  # type: ignore[no-redef]
    rules = admin_apply.load_rules()
    if args.routes_action == "list":
        return {"rules": rules}
    if args.routes_action == "add":
        rules.append(admin_apply.normalize_rule({"type": args.type, "value": args.value, "outbound": args.outbound, "include_subdomains": args.include_subdomains}))
    elif args.routes_action == "remove":
        before = len(rules)
        rules = [rule for rule in rules if rule["id"] != args.id]
        if len(rules) == before:
            raise ValueError(f"route id not found: {args.id}")
    applied = admin_apply.commit_rules(rules)
    return {"rules": applied, "applied": True}


def assets_snapshot() -> dict[str, Any]:
    """Expose manifest-bound assets without mutating a running release."""
    manifest = manifest_snapshot()
    return {"drift": manifest["drift"], "assets": manifest["assets"]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpn-stack-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--live-probes", action="store_true")
    snap.add_argument("--profile", choices=["light", "acceptance"], default="light")
    snap.add_argument("--compact", action="store_true")
    probe = sub.add_parser("probe")
    probe.add_argument("--profile", choices=["light", "acceptance"], default="light")
    client = sub.add_parser("client")
    client.add_argument("--source", required=True)
    client.add_argument("--since", type=int, default=15)
    front = sub.add_parser("front")
    front.add_argument("--since", type=int, default=30)
    front.add_argument("--live-probes", action="store_true")
    private_reject = sub.add_parser("private-reject-correlate")
    private_reject.add_argument("--since", required=True)
    private_reject.add_argument("--inbound", choices=PRIVATE_REJECT_INBOUND_TAGS, required=True)
    private_reject.add_argument("--target", action="append", required=True)
    sub.add_parser("health")
    sub.add_parser("transport-reconcile")
    sub.add_parser("transport-watch")
    transport_select = sub.add_parser("transport-select")
    transport_select.add_argument("--tag", choices=TRANSPORT_CANDIDATE_TAGS, required=True)
    sub.add_parser("network-apply")
    routes = sub.add_parser("routes")
    route_sub = routes.add_subparsers(dest="routes_action", required=True)
    route_sub.add_parser("list")
    add = route_sub.add_parser("add")
    add.add_argument("--type", choices=["domain", "cidr"], default="domain")
    add.add_argument("--value", required=True)
    add.add_argument("--outbound", required=True)
    add.add_argument("--include-subdomains", action="store_true")
    remove = route_sub.add_parser("remove")
    remove.add_argument("--id", required=True)
    sub.add_parser("assets")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "snapshot":
        payload = diagnostics_snapshot(
            live_probes=args.live_probes,
            profile=args.profile,
            full_logs=not args.compact,
            include_maintenance=not args.compact,
        )
    elif args.command == "probe":
        env = parse_env()
        manifest = read_json(MANIFEST_PATH, {})
        payload = run_confirmed_probes(env, runtime_contract(manifest if isinstance(manifest, Mapping) else {}, env), args.profile)
    elif args.command == "client":
        payload = front_client_snapshot(args.source, args.since)
    elif args.command == "front":
        payload = public_front_snapshot(args.since, live_probes=args.live_probes)
    elif args.command == "private-reject-correlate":
        payload = private_reject_correlations(args.since, args.inbound, args.target)
    elif args.command == "health":
        payload = health()
    elif args.command == "transport-reconcile":
        if not contract_has(installed_runtime_contract(), CAP_INTERSERVER_CLIENT):
            raise RuntimeError("interserver transport control is not applicable to this node")
        payload = reconcile_interserver_transport()
    elif args.command == "transport-watch":
        if not contract_has(installed_runtime_contract(), CAP_INTERSERVER_CLIENT):
            raise RuntimeError("interserver transport control is not applicable to this node")
        watch_interserver_transport()
        return 0
    elif args.command == "transport-select":
        if not contract_has(installed_runtime_contract(), CAP_INTERSERVER_CLIENT):
            raise RuntimeError("interserver transport control is not applicable to this node")
        env = parse_env()
        config = read_json(SINGBOX_CONFIG_PATH, {})
        controller = str(config.get("experimental", {}).get("clash_api", {}).get("external_controller", ""))
        if not controller:
            raise RuntimeError("transport controller is unavailable")
        select_transport(env, controller, args.tag)
        payload = {"selected": args.tag, "changed": True}
    elif args.command == "network-apply":
        payload = apply_network_profile()
    elif args.command == "routes":
        payload = routes_command(args)
    else:
        payload = assets_snapshot()
    output = health_log_summary(payload) if args.command == "health" else payload
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    if args.command == "health" and payload.get("state") in {"failed", "recovering"}:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)
