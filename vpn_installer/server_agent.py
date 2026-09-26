from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.dont_write_bytecode = True

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

if __package__:
    from . import server_lifecycle as lifecycle
    from . import server_runtime as runtime
    from . import journal_evidence as journal
else:
    import server_lifecycle as lifecycle
    import server_runtime as runtime
    import journal_evidence as journal

try:
    from .log_classifier import (
        BUCKETS,
        accepted_destination_from_line,
        classify_lines,
        event_id_from_line,
        inbound_destination_from_line,
        inbound_tag_from_line,
        normalize_source,
        source_endpoint_from_line,
        source_from_line,
        split_endpoint,
        summarize_classified_lines,
        summarize_lines,
    )
except ImportError:  # Installed agent runs as a standalone script.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from log_classifier import (  # type: ignore[no-redef]
        BUCKETS,
        accepted_destination_from_line,
        classify_lines,
        event_id_from_line,
        inbound_destination_from_line,
        inbound_tag_from_line,
        normalize_source,
        source_endpoint_from_line,
        source_from_line,
        split_endpoint,
        summarize_classified_lines,
        summarize_lines,
    )


try:
    from .network_profile import FQ_FLOW_LIMIT, FQ_KIND, FQ_PACKET_LIMIT, TCP_MTU_PROBE_FLOOR, wireguard_policy_spec
except ImportError:  # Installed agent runs as a standalone script.
    from network_profile import FQ_FLOW_LIMIT, FQ_KIND, FQ_PACKET_LIMIT, TCP_MTU_PROBE_FLOOR, wireguard_policy_spec  # type: ignore[no-redef]

try:
    from .diagnostics import SCHEMA_VERSION as DIAGNOSTICS_SCHEMA_VERSION, COLLECTOR_NAMES, INCOMPLETE_LOG_HISTORY_REASON, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot, classify_interserver_adaptation
except ImportError:  # Installed agent runs as a standalone script.
    from diagnostics import SCHEMA_VERSION as DIAGNOSTICS_SCHEMA_VERSION, COLLECTOR_NAMES, INCOMPLETE_LOG_HISTORY_REASON, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot, classify_interserver_adaptation  # type: ignore[no-redef]

try:
    from .release_integrity import release_tree_digest
except ImportError:  # Installed agent runs as a standalone script.
    from release_integrity import release_tree_digest  # type: ignore[no-redef]

try:
    from .resource_control import exec_router, prepare_memory_reserve, storage_maintenance, storage_snapshot
except ImportError:  # Installed agent runs as a standalone script.
    from resource_control import exec_router, prepare_memory_reserve, storage_maintenance, storage_snapshot  # type: ignore[no-redef]

try:
    from .platforms import PlatformSpec, apply_updates, current_platform, detect_host_facts, maintenance_snapshot as platform_maintenance_snapshot, resolve_platform
except ImportError:  # Installed agent runs as a standalone script.
    from platforms import PlatformSpec, apply_updates, current_platform, detect_host_facts, maintenance_snapshot as platform_maintenance_snapshot, resolve_platform  # type: ignore[no-redef]


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
FRONT_CURRENT_ACTIVITY_MAX_IDLE_MS = 30_000
REALITY_PENDING_HANDSHAKE_DEGRADED = 5
LOG_CONTEXT_MAX_EVENT_IDS = 500
PROBLEM_LOG_GREP = (
    "ERROR|FATAL|processed invalid connection|accepted tcp:disabled[.]invalid|"
    "connection rejected|mux connection closed|EOF|connection reset|using outbound/vless"
)
XRAY_FRONT_LOG_GREP = "accepted (tcp|udp):|REALITY: processed invalid connection"
CONNTRACK_FULL_GREP = "nf_conntrack.*table full"
RELEASES_PATH = runtime.ROOT / "releases"
CURRENT_RELEASE_PATH = runtime.ROOT / "current"
OPERATOR_MANIFEST_PATH = runtime.ROOT / "operator-state.json"
ADMIN_RULES_PATH = runtime.ROOT / "admin-routing-rules.json"
XRAY_CONFIG_PATH = Path("/etc/xray/config.json")
DNS_CACHE_CONFIG_PATH = runtime.ROOT / "dnsmasq.conf"
FSTAB_PATH = Path("/etc/fstab")
PROC_MOUNTS_PATH = Path("/proc/self/mounts")
EXT4_SYSFS_ROOT = Path("/sys/fs/ext4")
SYS_DEV_BLOCK_ROOT = Path("/sys/dev/block")


def load_transport():
    """Load the optional control owner only for an interserver-capable node."""
    if __package__:
        from . import server_transport
    else:
        import server_transport
    return server_transport


def _string_array(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise RuntimeError(f"manifest {field} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise RuntimeError(f"manifest {field} must not contain duplicates")
    return tuple(value)


def _expected_capabilities(
    topology: str,
    node_id: str,
) -> frozenset[str]:
    if node_id == runtime.NODE_GATEWAY:
        capabilities = {runtime.CAP_PUBLIC_FRONT, runtime.CAP_ROUTER, runtime.CAP_LOCAL_EGRESS}
        if topology == runtime.TOPOLOGY_DUAL:
            capabilities.update({runtime.CAP_RU_SPLIT_ROUTING, runtime.CAP_INTERSERVER_CLIENT, runtime.CAP_WEB_ADMIN})
        return frozenset(capabilities)
    if topology == runtime.TOPOLOGY_DUAL and node_id == runtime.NODE_EXIT:
        return frozenset({runtime.CAP_INTERSERVER_SERVER, runtime.CAP_NAT_EXIT})
    raise RuntimeError(f"node {node_id!r} is invalid for {topology!r} topology")


def _expected_required_services(capabilities: frozenset[str]) -> tuple[str, ...]:
    services = ["nftables", "sing-box", "resolver", "health_timer"]
    if runtime.CAP_PUBLIC_FRONT in capabilities:
        services.append("xray")
    if runtime.CAP_WEB_ADMIN in capabilities:
        services.append("admin")
    if capabilities & runtime.INTERSERVER_CAPABILITIES:
        services.append("wireguard")
    if runtime.CAP_INTERSERVER_CLIENT in capabilities:
        services.append("transport")
    return tuple(services)


def runtime_contract(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the installed node contract without importing installer code."""
    raw_schema = manifest.get("schema_version")
    try:
        schema = int(raw_schema)
    except (TypeError, ValueError):
        schema = 0
    if schema != runtime.MANIFEST_CAPABILITY_SCHEMA_VERSION:
        raise RuntimeError(f"unsupported render manifest schema: {raw_schema!r}")

    topology = str(manifest.get("topology", ""))
    node_id = str(manifest.get("node_id", ""))
    location = str(manifest.get("location", ""))
    if topology not in {runtime.TOPOLOGY_SINGLE, runtime.TOPOLOGY_DUAL}:
        raise RuntimeError(f"unsupported manifest topology: {topology!r}")
    if node_id not in {runtime.NODE_GATEWAY, runtime.NODE_EXIT}:
        raise RuntimeError(f"unsupported manifest node: {node_id!r}")
    if location not in {runtime.LOCATION_RU, runtime.LOCATION_FOREIGN}:
        raise RuntimeError(f"unsupported manifest location: {location!r}")
    if topology == runtime.TOPOLOGY_SINGLE and node_id != runtime.NODE_GATEWAY:
        raise RuntimeError("single topology cannot install an exit node")
    if topology == runtime.TOPOLOGY_DUAL and ((node_id == runtime.NODE_GATEWAY and location != runtime.LOCATION_RU) or (node_id == runtime.NODE_EXIT and location != runtime.LOCATION_FOREIGN)):
        raise RuntimeError("dual topology node location does not match the contract")

    capabilities = frozenset(_string_array(manifest.get("capabilities"), "capabilities"))
    expected_capabilities = _expected_capabilities(topology, node_id)
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
    if install_plan.get("schema_version") != runtime.MANIFEST_CAPABILITY_SCHEMA_VERSION:
        raise RuntimeError("manifest install plan schema is unsupported")
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
    if capabilities & runtime.INTERSERVER_CAPABILITIES:
        try:
            load_transport()
        except ImportError as exc:
            raise RuntimeError("interserver transport module is missing for an interserver-capable node") from exc
    try:
        platform = PlatformSpec.from_dict(manifest.get("platform"))
    except ValueError as exc:
        raise RuntimeError(f"manifest platform is invalid: {exc}") from exc
    if install_plan.get("platform") != platform.to_dict():
        raise RuntimeError("install plan platform conflicts with the manifest")

    return {
        "topology": topology,
        "node_id": node_id,
        "location": location,
        "capabilities": capabilities,
        "required_services": required_services,
        "service_units": service_units,
        "platform": platform.to_dict(),
    }


def installed_runtime_contract() -> dict[str, Any]:
    manifest = runtime.read_json(runtime.MANIFEST_PATH, {})
    return runtime_contract(manifest if isinstance(manifest, Mapping) else {})


def recent_observation(payload: Any, *, max_age_seconds: int) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    age = runtime._observation_age_seconds(str(payload.get("observed_at", "")))
    return payload if age is not None and 0 <= age <= max_age_seconds else {}


def release_scoped_observation(payload: dict[str, Any], installed_at: str) -> dict[str, Any]:
    """Exclude health evidence collected before the active release was installed."""

    if not payload or not installed_at:
        return payload
    observed = runtime.parse_iso_datetime(str(payload.get("observed_at", "")))
    release_started = runtime.parse_iso_datetime(installed_at)
    if release_started is None:
        return payload
    if observed is None or observed < release_started:
        return {}
    return payload


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


def service_state(name: str) -> str:
    result = runtime.run(["systemctl", "is-active", name], timeout=5)
    return result.stdout.strip() or "unknown"


def journal_filtered_events(unit: str, minutes: int, pattern: str) -> dict[str, Any]:
    cutoff = time.time()
    since = cutoff - minutes * 60
    return journal.journal_event_snapshot(
        runner=runtime.run, matches=("-u", unit), pattern=pattern,
        window_starts={"front": since}, query_since=since, cutoff=cutoff, timeout=30,
    )


def _journal_window_args(minutes: int, until: float | None) -> list[str]:
    if until is None:
        return ["--since", f"{minutes} minutes ago"]
    return ["--since", f"@{until - minutes * 60:.6f}", "--until", f"@{until:.6f}"]


def _journal_event_context(minutes: int, problem_events: list[tuple[float, str]], *, until: float | None = None) -> list[tuple[float, str]]:
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
    result = runtime.run(
        [
            "journalctl",
            "-u",
            "sing-box.service",
            *_journal_window_args(minutes, until),
            "--no-pager",
            "--output=json", "--all",
            rf"--grep=\[(?:\x1B\[[0-9;]*m)*(?:{event_pattern})\b",
        ],
        timeout=30,
    )
    if journal.journal_command_error(result):
        return []
    context, _malformed = journal.parse_journal_events(result)
    return [
        event
        for event in context
        if inbound_destination_from_line(event[1]) or "dns: lookup succeed for " in event[1]
    ]


def journal_problem_events(minutes: int, *, until: float | None = None) -> tuple[list[tuple[float, str]], str]:
    result = runtime.run(
        [
            "journalctl",
            "-u",
            "sing-box.service",
            "-u",
            "vpn-stack-xray.service",
            *_journal_window_args(minutes, until),
            "--no-pager",
            "--output=json", "--all",
            f"--grep={PROBLEM_LOG_GREP}",
        ],
        timeout=30,
    )
    command_error = journal.journal_command_error(result)
    events, malformed = journal.parse_journal_events(result)
    events.extend(_journal_event_context(minutes, events, until=until))
    if malformed:
        command_error = "; ".join(filter(None, (command_error, f"journalctl returned {malformed} malformed JSON record(s)")))
    return events, command_error


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
    has_router = runtime.contract_has(contract, runtime.CAP_ROUTER)
    verified = has_router and drift == "none" and ordered
    reason = ""
    if not has_router:
        reason = f"installed node is {contract.get('node_id') or 'unknown'}"
    elif drift != "none":
        reason = f"installed drift is {drift}"
    elif not ordered:
        reason = "private/fake reject guard is missing or ordered after the IPv4 catch-all"
    return {
        "verified": verified,
        "reason": reason,
        "drift": drift,
        "config_sha256": sha256_file(runtime.SINGBOX_CONFIG_PATH),
        "guard_indexes": guard_indexes,
        "ipv4_catchall_index": catchall_index if catchall_index < len(rules) else None,
    }


def private_reject_correlations(since: str, inbound: str, targets: Iterable[str]) -> dict[str, Any]:
    if inbound not in PRIVATE_REJECT_INBOUND_TAGS:
        raise ValueError(f"unsupported private reject inbound: {inbound}")
    marker = runtime.parse_iso_datetime(since)
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
        contract = runtime_contract(raw_manifest if isinstance(raw_manifest, Mapping) else {})
    except RuntimeError:
        contract = {}
    policy = _private_reject_policy(runtime.read_json(runtime.SINGBOX_CONFIG_PATH, {}), manifest, contract)
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

    journal_result = runtime.run(
        [
            "journalctl",
            "-u",
            "sing-box.service",
            "--since",
            marker.isoformat(),
            "--no-pager",
            "--output=json", "--all",
            "--grep=inbound connection to",
        ],
        timeout=20,
    )
    command_error = journal.journal_command_error(journal_result)
    if command_error:
        response["verdict"] = "failed"
        response["reason"] = command_error
        return response

    marker_epoch = marker.timestamp()
    latest: dict[str, tuple[float, str, str]] = {}
    for raw_line in journal_result.stdout.splitlines():
        try:
            record = json.loads(raw_line)
            timestamp = float(record["__REALTIME_TIMESTAMP"]) / 1_000_000
            message = journal.journal_record_message(record)
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
    fresh_age_minutes = max(0, math.ceil((now - fresh_epoch) / 60))
    query_minutes = max(windows)
    if fresh_age_minutes <= COMPLETE_LOG_RETENTION_MINUTES:
        query_minutes = max(query_minutes, fresh_age_minutes)
    query_since = now - query_minutes * 60
    events, collector_error = journal_problem_events(query_minutes, until=now)
    coverage = {
        **journal.journal_coverage(runner=runtime.run, since=query_since, until=now),
        "query_since_epoch": query_since,
        "query_until_epoch": now,
    }
    events = [(timestamp, line) for timestamp, line in events if timestamp <= now]
    # Resolve each failure once using the bounded query's context, then slice only its counts.
    classified = list(zip((timestamp for timestamp, _line in events), classify_lines(line for _timestamp, line in events)))
    observed_at = datetime.fromtimestamp(now, timezone.utc).isoformat()

    def window(since: float) -> dict[str, Any]:
        coverage_error = journal.journal_window_error(
            coverage, since=since, until=now, query_since=query_since, query_until=now,
            collector_error=collector_error,
        )
        return {
            **summarize_classified_lines(item for timestamp, item in classified if since <= timestamp),
            "observed_at": observed_at,
            "since": datetime.fromtimestamp(since, timezone.utc).isoformat(),
            "until": observed_at,
            "coverage": coverage,
            "coverage_error": coverage_error,
        }

    summaries = {
        str(minutes): window(now - minutes * 60)
        for minutes in windows
    }
    fresh = window(fresh_epoch)
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
    try:
        return (runtime.ROOT / "installed-at").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def service_exec_path(service: str) -> str:
    result = runtime.run(["systemctl", "show", service, "--property=MainPID", "--value"], timeout=5)
    if result.returncode != 0:
        return ""
    try:
        pid = int(result.stdout.strip())
    except ValueError:
        return ""
    if pid <= 0:
        return ""
    try:
        return os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")
    except OSError:
        return ""


def manifest_snapshot() -> dict[str, Any]:
    manifest = runtime.read_json(runtime.MANIFEST_PATH, {})
    manifest_mapping = manifest if isinstance(manifest, Mapping) else {}
    try:
        contract = runtime_contract(manifest_mapping)
    except RuntimeError:
        contract = {}
    entries = manifest_mapping.get("artifacts", {})
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
        if state == "ok" and service:
            try:
                runtime_matches = bool(runtime_exec_path) and Path(runtime_exec_path).samefile(actual_path)
            except OSError:
                runtime_matches = runtime_exec_path == str(actual_path)
            if not runtime_matches:
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
    installed_env_sha256 = sha256_file(runtime.ENV_PATH)
    expected_env_sha256 = str(manifest.get("env_sha256", "")) if isinstance(manifest, dict) else ""
    if not installed_env_sha256 or installed_env_sha256 != expected_env_sha256:
        mismatches.append("deployment.env")

    release_tree = release_tree_snapshot()
    if release_tree["state"] != "ok":
        mismatches.append("release-tree")

    manifest_capabilities = frozenset(str(value) for value in contract.get("capabilities", ()))
    has_operator_state = runtime.CAP_WEB_ADMIN in manifest_capabilities
    operator: dict[str, Any] = {"state": "not-applicable"}
    if has_operator_state:
        operator_manifest = runtime.read_json(OPERATOR_MANIFEST_PATH, {})
        actual_hashes = {
            "base_sha256": sha256_file(runtime.ROOT / "sing-box.base.json"),
            "rules_sha256": sha256_file(ADMIN_RULES_PATH),
            "effective_config_sha256": sha256_file(runtime.SINGBOX_CONFIG_PATH),
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
    elif contract.get("node_id") == runtime.NODE_EXIT:
        expected_config = str(manifest.get("config_sha256", ""))
        active_config = sha256_file(runtime.SINGBOX_CONFIG_PATH)
        operator = {
            "state": "ok" if expected_config and active_config == expected_config else "mutated",
            "effective_config_sha256": active_config,
        }
        if operator["state"] != "ok":
            mismatches.append("effective-config")
    manifest_valid = bool(contract)
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
    result = runtime.run(["wg", "show", interface, "dump"], timeout=5)
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
    link = runtime.run(["ip", "-j", "link", "show", "dev", interface], timeout=5)
    link_data = runtime.read_json_text(link.stdout, []) if link.returncode == 0 else []
    return {"interface": interface, "state": "up" if link_data and "UP" in link_data[0].get("flags", []) else "down", "peers": peers}


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


def tcp_adaptation_snapshot(interface: str, overlay_interface: str = "") -> dict[str, Any]:
    values: dict[str, Any] = {}
    for field, name in (
        ("congestion_control", "net.ipv4.tcp_congestion_control"),
        ("mtu_probing", "net.ipv4.tcp_mtu_probing"),
        ("mtu_probe_floor", "net.ipv4.tcp_mtu_probe_floor"),
        ("probe_interval_seconds", "net.ipv4.tcp_probe_interval"),
        ("metrics_save_disabled", "net.ipv4.tcp_no_metrics_save"),
        ("thin_linear_timeouts", "net.ipv4.tcp_thin_linear_timeouts"),
        ("udp_rmem_default", "net.core.rmem_default"),
        ("udp_rmem_max", "net.core.rmem_max"),
        ("udp_wmem_default", "net.core.wmem_default"),
        ("udp_wmem_max", "net.core.wmem_max"),
    ):
        result = runtime.run(["sysctl", "-n", name], timeout=3)
        value = result.stdout.strip()
        values[field] = int(value) if value.isdigit() else value
    values.update(runtime.qdisc_snapshot(interface))
    if overlay_interface:
        values.update({f"overlay_{name}": value for name, value in runtime.qdisc_snapshot(overlay_interface).items()})
    return values


def managed_network_profile(path: Path = runtime.SYSCTL_PATH, *, include_overlay: bool = True) -> dict[str, Any]:
    field_names = {
        "net.core.rmem_default": "udp_rmem_default",
        "net.core.rmem_max": "udp_rmem_max",
        "net.core.wmem_default": "udp_wmem_default",
        "net.core.wmem_max": "udp_wmem_max",
        "net.netfilter.nf_conntrack_max": "conntrack_max",
        "net.ipv4.tcp_mtu_probe_floor": "mtu_probe_floor",
        "net.ipv4.tcp_no_metrics_save": "metrics_save_disabled",
        "net.ipv4.tcp_thin_linear_timeouts": "thin_linear_timeouts",
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
    result = runtime.run(["nstat", "-az"], timeout=5)
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
    sockets = runtime.run(["ss", "-Htan", f"sport = :{port}"], timeout=8)
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
    for raw_line in runtime.run(["ss", "-Htoein", f"sport = :{port}"], timeout=8).stdout.splitlines():
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
    listener = runtime.run(["ss", "-Hltn", f"sport = :{port}"], timeout=5)
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
        and max_rto >= lifecycle.FRONT_RTO_DEGRADED_MS
    ):
        return "degraded"
    if (
        retransmissions >= FRONT_SMALL_FLOW_MIN_RETRANSMISSIONS
        and p95 >= FRONT_RTT_DEGRADED_MS
        and max_rto >= lifecycle.FRONT_RTO_DEGRADED_MS
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
FRONT_PATH_KEYS = ("pmtu", "mss", "rtt_ms", "rto_ms", "cwnd", "delivery_rate_bps", "reordering")


def front_path_snapshot(metrics: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: dict(value) if isinstance(value, Mapping) else value
        for key in FRONT_PATH_KEYS
        if (value := metrics.get(key)) is not None
    }


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
            **front_path_snapshot(metrics),
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
    previous_age = runtime.iso_age_seconds(
        str(previous_counters.get("observed_at", "")),
        now=runtime.parse_iso_datetime(observed_at),
    )
    baseline_reason = ""
    if not previous_flows:
        baseline_reason = "missing"
    elif previous_age is None or previous_age > lifecycle.FRONT_COUNTER_MAX_INTERVAL_SECONDS:
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
            **front_path_snapshot(current),
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
    sockets = runtime.run(["ss", "-Htanp", "state", "syn-sent"], timeout=5)
    if sockets.returncode != 0:
        return None
    return sum(
        '"xray"' in line.lower()
        and any(split_endpoint(field)[1] == target_port for field in line.split())
        for line in sockets.stdout.splitlines()
    )


def xray_front_socket_policy(port: int) -> dict[str, Any]:
    config = runtime.read_json(XRAY_CONFIG_PATH, {})
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
    config = runtime.read_json(runtime.SINGBOX_CONFIG_PATH, {})
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
    listener = runtime.run(["ss", "-Hlun", f"sport = :{port}"], timeout=5)
    ruleset = runtime.run(["nft", "list", "table", "inet", "vpnstack"], timeout=8)
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


def apply_front_interval_verdict(current: dict[str, Any], interval: dict[str, Any]) -> None:
    front = current.get("front")
    if not isinstance(front, dict) or not front:
        return
    verdicts = current.get("verdicts")
    if not isinstance(verdicts, dict):
        return
    services = current.get("services", {})
    xray_state = str(services.get("xray", "unknown")) if isinstance(services, Mapping) else "unknown"
    observation = front_observation(front, interval)
    public_front = public_front_verdict(xray_state, front, interval)
    reasons = [
        str(reason)
        for reason in verdicts.get("reasons", [])
        if not str(reason).startswith(("public_front=", "public_front_interval="))
    ]
    if public_front == "degraded":
        reasons.append(f"public_front={observation}")
    verdicts["client_observation"] = observation
    verdicts["public_front"] = public_front
    verdicts["reasons"] = reasons
    components = {
        verdicts.get("server_path"),
        public_front,
        verdicts.get("public_quic"),
        verdicts.get("host_integrity"),
    }
    if "failed" in components:
        verdicts["overall"] = "failed"
    elif reasons or observation in {"client_specific", "degraded"}:
        verdicts["overall"] = "degraded"
    elif verdicts.get("server_path") == "verified":
        verdicts["overall"] = "verified"
    else:
        verdicts["overall"] = "inconclusive"


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
    config = runtime.read_json(runtime.SINGBOX_CONFIG_PATH, {})
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


def public_front_snapshot(minutes: int, source: str | None = None, *, live_probes: bool = False) -> dict[str, Any]:
    if not 5 <= minutes <= 1440:
        raise ValueError("since must be in range 5..1440 minutes")
    if source:
        try:
            source = normalize_source(source)
            ipaddress.ip_address(source)
        except ValueError as exc:
            raise ValueError("source must be an IP address") from exc
    env = runtime.parse_env()
    contract = installed_runtime_contract()
    if not runtime.contract_has(contract, runtime.CAP_PUBLIC_FRONT):
        raise RuntimeError("public front diagnostics are not applicable to this node")
    port = int(env.get("RU_LISTEN_PORT", "443") or 443)
    evidence = journal_filtered_events("vpn-stack-xray.service", minutes, XRAY_FRONT_LOG_GREP)
    xray_lines = [event["message"] for event in evidence["events"]]
    journal_error = journal.journal_snapshot_error(evidence, window="front")
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
    services = {"xray": service_state("vpn-stack-xray.service"), "nftables": service_state(runtime.NFTABLES_SERVICE)}
    observation = front_observation(front)
    front_verdict = public_front_verdict(services["xray"], front)
    probes = run_probes(env, contract, "light") if live_probes else {"profile": "none", "ok": None, "requirements": {}}
    path_verdict = "verified" if probes.get("ok") is True else "failed" if probes.get("ok") is False else "inconclusive"
    overall = "failed" if "failed" in {front_verdict, path_verdict} else "degraded" if front_verdict == "degraded" else front_verdict
    if journal_error and overall != "failed":
        overall = "inconclusive"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": runtime.utc_now(),
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
    payload["journal_evidence"] = {key: value for key, value in evidence.items() if key != "events"}
    payload["observed_events"] = dict(payload["events"])
    if journal_error:
        payload["events"] = dict.fromkeys(payload["events"])
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
    if journal_error:
        client_transport["status"] = "inconclusive"
    source_flows = {
        key: {**metrics, "accepted_destinations": dict(flow_events.get(key, Counter()).most_common(10))}
        for key, metrics in front.get("flows", {}).items()
        if metrics.get("source") == source
    }
    recent_interval = recent_observation(
        runtime.read_json(runtime.HEALTH_STATE_PATH, {}).get("front_interval", {}),
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
    if front_verdict == "failed":
        source_verdict = "failed"
    elif journal_error:
        source_verdict = "inconclusive"
    elif source_events["accepted"] and source_degraded:
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
            "source_events": dict.fromkeys(source_events) if journal_error else source_events,
            "source_observed_events": source_events,
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
        "observed_events": payload["source_observed_events"],
        "journal_evidence": payload["journal_evidence"],
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


def kernel_conntrack_full_windows(
    *, full_logs: bool, coverage: Mapping[str, Any] | None = None, cutoff: float | None = None,
) -> dict[str, Any]:
    windows = (5, 30, 1440) if full_logs else (5,)
    now = time.time() if cutoff is None else cutoff
    return journal.kernel_event_snapshot(
        runner=runtime.run, pattern=CONNTRACK_FULL_GREP,
        window_starts={str(minutes): now - minutes * 60 for minutes in windows},
        query_since=now - max(windows) * 60, cutoff=now, coverage=coverage,
    )


def xray_conntrack_bypass_snapshot(port: int) -> dict[str, bool]:
    result = runtime.run(["nft", "list", "table", "inet", "vpnstack"], timeout=5)
    lines = result.stdout.splitlines() if result.returncode == 0 else []
    ingress = any(f"tcp dport {port}" in line and "notrack" in line and "vpnstack-xray-in-notrack" in line for line in lines)
    egress = any(f"tcp sport {port}" in line and "notrack" in line and "vpnstack-xray-out-notrack" in line for line in lines)
    return {"active": ingress and egress, "ingress": ingress, "egress": egress}


def conntrack_snapshot(
    *, full_logs: bool = True, coverage: Mapping[str, Any] | None = None, cutoff: float | None = None,
) -> dict[str, Any]:
    def number(path: str) -> int:
        try:
            return int(Path(path).read_text().strip())
        except (OSError, ValueError):
            return 0

    count = number("/proc/sys/net/netfilter/nf_conntrack_count")
    maximum = number("/proc/sys/net/netfilter/nf_conntrack_max")
    events = kernel_conntrack_full_windows(full_logs=full_logs, coverage=coverage, cutoff=cutoff)
    events.pop("events", None)
    return {
        "count": count,
        "max": maximum,
        "percent": round(count * 100 / maximum, 2) if maximum else 0.0,
        "table_full_events": events["counts"],
        "table_full_observed": events["observed_counts"],
        "journal_evidence": events,
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
    result = runtime.run(args, timeout=timeout + 2)
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
    result = runtime.run(args, timeout=timeout + 2)
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
        result = runtime.run(
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


def release_gate_requirements(requirements: dict[str, bool]) -> dict[str, bool]:
    return {name: passed for name, passed in requirements.items() if name not in OPTIONAL_TRANSPORT_REQUIREMENTS}


def release_gate_ok(probes: dict[str, Any]) -> bool:
    if probes.get("profile") == "acceptance":
        return probes.get("release_gate_ok") is True
    return probes.get("ok") is True


def _configured_node_ip(env: Mapping[str, str], contract: Mapping[str, Any], node_id: str) -> str:
    if node_id == runtime.NODE_EXIT:
        return str(env.get("EXIT_PUBLIC_IP") or "")
    return str(env.get("GATEWAY_PUBLIC_IP") or "")


def run_probes(env: dict[str, str], contract: Mapping[str, Any], profile: str) -> dict[str, Any]:
    topology = str(contract.get("topology", runtime.TOPOLOGY_DUAL))
    node_id = str(contract.get("node_id", ""))
    has_router = runtime.contract_has(contract, runtime.CAP_ROUTER)
    has_interserver_client = runtime.contract_has(contract, runtime.CAP_INTERSERVER_CLIENT)
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
            _configured_node_ip(env, contract, runtime.NODE_EXIT)
            if topology == runtime.TOPOLOGY_DUAL
            else _configured_node_ip(env, contract, runtime.NODE_GATEWAY)
        )
        identities["router"] = expected_identity(probe_identity(proxy="socks5h://127.0.0.1:2080"), routed_egress_ip)
        if has_interserver_client:
            identities["via_wg"] = expected_identity(probe_identity(interface=wg_interface), routed_egress_ip)
    private_reject = probe_private_reject("socks5h://127.0.0.1:2080") if has_router else {"ok": True, "not_applicable": True}
    if has_interserver_client:
        hysteria_candidate = load_transport().policy.transport_candidate_probe(load_transport().policy.TRANSPORT_HY2_TAG)
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
        "initial_failed_requirements": runtime.failed_requirements(first),
        "failed_requirements": runtime.failed_requirements(retry),
    }
    return retry


def maintenance_snapshot(platform: PlatformSpec | None = None) -> dict[str, Any]:
    try:
        result = platform_maintenance_snapshot(platform or current_platform())
    except (OSError, RuntimeError, ValueError) as exc:
        return {"collector_error": str(exc)[:240]}
    result.update(kernel=os.uname().release, os=os_release_fields().get("PRETTY_NAME", ""))
    return result


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
    if not source:
        return result
    mount_options = {item for item in mount.get("options", "").split(",") if item}
    if "ro" in mount_options:
        result.update(state="read-only", verdict="failed", reason="root filesystem is mounted read-only")
        return result
    if filesystem in {"xfs", "btrfs"}:
        result.update(
            state="mounted",
            boot_check_enabled=None,
            verdict="verified",
            reason="",
        )
        return result
    if filesystem != "ext4":
        result["reason"] = f"unsupported root filesystem: {filesystem or 'unknown'}"
        return result
    device = os.path.realpath(source)
    sysfs = ext4_sysfs_root / block_device_name(source, sys_dev_block_root)
    result["errors_count"] = read_counter(sysfs / "errors_count")
    result["first_error_time"] = read_counter(sysfs / "first_error_time")
    result["last_error_time"] = read_counter(sysfs / "last_error_time")
    tune = runtime.run(["tune2fs", "-l", device], timeout=8)
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
        lines = DNS_CACHE_CONFIG_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    settings: dict[str, list[str]] = {}
    flags: set[str] = set()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator:
            settings.setdefault(key, []).append(value)
        else:
            flags.add(key)
    address = settings.get("listen-address", [""])[-1]
    port = settings.get("port", [""])[-1]
    cache_capacity = settings.get("cache-size", [""])[-1]
    upstreams = settings.get("server", [])
    managed = (
        address == "127.0.0.1"
        and port == "1054"
        and bool(upstreams)
        and "no-resolv" in flags
        and "all-servers" in flags
    )
    return {
        "provider": "dnsmasq",
        "listen_address": address,
        "listen_port": int(port) if port.isdigit() else 0,
        "upstreams": upstreams,
        "cache_capacity": int(cache_capacity) if cache_capacity.isdigit() else 0,
        "concurrent_upstreams": "all-servers" in flags,
        "managed_config": managed,
    }


def host_snapshot(default_iface: str) -> dict[str, Any]:
    is_root = bool(getattr(os, "geteuid", lambda: 1)() == 0)
    has_sudo = is_root or runtime.run(["sudo", "-n", "true"], timeout=2).returncode == 0
    os_release = os_release_fields()
    facts = detect_host_facts()
    try:
        platform = resolve_platform(facts).to_dict()
    except ValueError:
        platform = {}
    return {
        "hostname": socket.getfqdn() or socket.gethostname(),
        "login_user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
        "is_root": is_root,
        "has_sudo": has_sudo,
        "os_id": os_release.get("ID", ""),
        "os_version": os_release.get("VERSION_ID", ""),
        "os_id_like": list(facts.id_like),
        "architecture": facts.architecture,
        "init_system": facts.init_system,
        "security_mode": facts.security_mode,
        "host_firewall": facts.host_firewall,
        "platform": platform,
        "default_interface": default_iface,
    }


def collect_runtime_facts(*, live_probes: bool = False, profile: str = "light", full_logs: bool = True, include_maintenance: bool = True) -> dict[str, Any]:
    # A composite collector keeps its earliest acquisition time, not the later envelope time.
    observed_at = {"artifacts": runtime.utc_now()}
    env = runtime.parse_env()
    manifest_data = manifest_snapshot()
    manifest = manifest_data.get("manifest", {})
    contract_error = ""
    try:
        contract = runtime_contract(manifest if isinstance(manifest, Mapping) else {})
    except RuntimeError as exc:
        contract_error = str(exc)
        contract = {
            "topology": "",
            "node_id": "",
            "location": "",
            "capabilities": frozenset(),
            "required_services": (),
            "service_units": {},
        }
    topology = str(contract.get("topology", ""))
    node_id = str(contract.get("node_id", ""))
    location = str(contract.get("location", ""))
    capabilities = frozenset(str(value) for value in contract.get("capabilities", ()))
    has_interserver = bool(capabilities & runtime.INTERSERVER_CAPABILITIES)
    has_interserver_client = runtime.CAP_INTERSERVER_CLIENT in capabilities
    has_interserver_server = runtime.CAP_INTERSERVER_SERVER in capabilities
    has_public_front = runtime.CAP_PUBLIC_FRONT in capabilities
    wg_interface = env.get("WG_INTERFACE", "wg0")
    public_iface = runtime.default_interface()
    port = int(env.get("RU_LISTEN_PORT", "443") or 443)

    services = {name: "not-applicable" for name in runtime.SERVICE_UNIT_DEFAULTS}
    service_units = contract.get("service_units", {}) if isinstance(contract.get("service_units"), Mapping) else {}
    observed_at["services"] = runtime.utc_now()
    for name in contract.get("required_services", ()):
        unit = str(service_units.get(name, runtime.SERVICE_UNIT_DEFAULTS.get(name, ""))).format(wg_interface=wg_interface)
        services[str(name)] = service_state(unit) if unit else "unknown"

    fresh_since, fresh_window_minutes = fresh_log_since()
    if not full_logs and fresh_window_minutes > 5:
        fresh_since, fresh_window_minutes = "5 minutes ago", 5
    if include_maintenance:
        observed_at["maintenance"] = runtime.utc_now()
    maintenance = maintenance_snapshot() if include_maintenance else {}
    release_installed_at = installed_at_value()
    observed_at["logs"] = runtime.utc_now()
    logs, fresh_logs, logs_collector_error = summarize_problem_windows(full_logs=full_logs, fresh_since=fresh_since)
    if has_public_front:
        observed_at["front"] = runtime.utc_now()
    front = tcp_front_snapshot(port) if has_public_front else {}
    if live_probes and not contract_error:
        observed_at["route_probes"] = runtime.utc_now()
    probes = run_confirmed_probes(env, contract, profile) if live_probes and not contract_error else {"profile": "none", "ok": None}
    transport: dict[str, Any] = {}
    if has_interserver:
        observed_at["transport"] = runtime.utc_now()
        transport["interserver"] = load_transport().interserver_transport_snapshot(contract, env)
    if has_public_front:
        transport["udp_443_policy"] = udp_443_policy()
        transport["public_client"] = public_hy2_snapshot(port)
    observed_at["network"] = runtime.utc_now()
    tcp_adaptation = tcp_adaptation_snapshot(public_iface, wg_interface if has_interserver else "")
    resolver = resolver_snapshot()
    observed_at["storage"] = runtime.utc_now()
    root_filesystem = root_filesystem_snapshot()
    coverage = fresh_logs.get("coverage", {})
    cutoff = coverage.get("query_until_epoch")
    storage = storage_snapshot(root_filesystem, release_installed_at, coverage=coverage, cutoff=cutoff)
    conntrack = conntrack_snapshot(full_logs=full_logs, coverage=coverage, cutoff=cutoff)
    if has_public_front:
        conntrack["front_bypass"] = xray_conntrack_bypass_snapshot(port)
    expected_network_profile = managed_network_profile(include_overlay=has_interserver)
    actual_network_profile = {**tcp_adaptation, "conntrack_max": conntrack.get("max", 0)}
    profile_mismatches = network_profile_mismatches(actual_network_profile, expected_network_profile)
    wireguard_policy = (
        runtime.wireguard_policy_snapshot(env, managed=True)
        if has_interserver_client
        else {"managed": False, "ok": True, "not_applicable": True}
    )
    health_state = runtime.read_json(runtime.HEALTH_STATE_PATH, {})
    recent_front_interval = recent_observation(health_state.get("front_interval", {}), max_age_seconds=300)
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
    if not resolver.get("managed_config"):
        reasons.append("resolver_config=missing")
    capacity = storage.get("capacity", {})
    memory = storage.get("memory", {})
    if capacity.get("verdict") == "failed":
        reasons.append(f"root_disk_full={capacity.get('used_percent', 'unknown')}%")
    if memory.get("reserve_ready") is False:
        reasons.append("low_memory_swap_reserve=missing")
    router_memory = memory.get("router", {}) if isinstance(memory.get("router"), Mapping) else {}
    if services.get("sing-box") == "active" and router_memory.get("go_memory_limit_active") is not True:
        reasons.append("sing_box_memory_budget=missing")
    if live_probes and not contract_error and not release_gate_ok(probes):
        failed = ",".join(runtime.failed_requirements(probes))
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

    capability_failures = [name for name in runtime.failed_requirements(probes) if name in EXTERNAL_CAPABILITY_REQUIREMENTS] if live_probes else []
    transport_failures = [name for name in runtime.failed_requirements(probes) if name in OPTIONAL_TRANSPORT_REQUIREMENTS] if live_probes else []
    server_path = "failed" if reasons else "verified" if live_probes else "inconclusive"
    host_integrity = str(root_filesystem.get("verdict", "inconclusive"))
    host_integrity_detail = str(root_filesystem.get("reason", ""))
    if capacity.get("verdict") == "failed":
        host_integrity_detail = host_integrity_detail or "root_disk_full"
        host_integrity = "failed"
    elif memory.get("reserve_ready") is False:
        host_integrity_detail = host_integrity_detail or "low_memory_swap_reserve_missing"
        host_integrity = "failed"
    elif services.get("sing-box") == "active" and router_memory.get("go_memory_limit_active") is not True:
        host_integrity_detail = host_integrity_detail or "sing_box_memory_budget_missing"
        host_integrity = "failed"
    elif capacity.get("verdict") == "degraded" and host_integrity == "verified":
        host_integrity_detail = "root_disk_near_capacity"
        host_integrity = "degraded"
    oom = storage.get("runtime_events", {}).get("oom_kills", {})
    recent_oom = oom.get("observed_counts", {}).get("30m") or oom.get("counts", {}).get("30m")
    if int(recent_oom or 0) > 0 and host_integrity == "verified":
        host_integrity_detail = "kernel_oom_kill_30m"
        host_integrity = "degraded"
    elif oom.get("collector_error") and host_integrity == "verified":
        host_integrity_detail = "kernel_journal_unavailable"
        host_integrity = "inconclusive"
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
        degradations.append(f"host_integrity={host_integrity}:{host_integrity_detail or 'unknown'}")
    selected_transport = str(interserver.get("selection", {}).get("selected", ""))
    recent_conntrack_full = int(conntrack.get("table_full_observed", {}).get("5") or conntrack.get("table_full_events", {}).get("5") or 0)
    if recent_conntrack_full:
        degradations.append(f"conntrack_table_full_5m={recent_conntrack_full}")
    overall = "failed" if "failed" in {server_path, public_front, public_quic, host_integrity} else "degraded" if degradations or client_observation in {"client_specific", "degraded"} else "verified" if server_path == "verified" else "inconclusive"
    healthy_exits = int(services.get("sing-box") == "active" and (not live_probes or release_gate_ok(probes)))
    interface_names = (public_iface, wg_interface) if has_interserver else (public_iface,)
    host = host_snapshot(public_iface)
    if has_interserver:
        observed_at["wireguard"] = runtime.utc_now()
    wireguard = wireguard_snapshot(wg_interface) if has_interserver else {}
    interfaces = interface_counters(interface_names)
    protocol_counters = protocol_counters_snapshot()
    softnet_counters = softnet_counters_snapshot()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": runtime.utc_now(),
        "collector_observed_at": observed_at,
        "deployment": env.get("DEPLOY_NAME", ""),
        "topology": topology,
        "node_id": node_id,
        "location": location,
        "capabilities": sorted(capabilities),
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
        "host": host,
        "storage": storage,
        "services": services,
        "artifacts": manifest_data,
        "wireguard": wireguard,
        "network": {
            "interfaces": interfaces,
            "conntrack": conntrack,
            "tcp_adaptation": tcp_adaptation,
            "resolver": resolver,
            "managed_profile": expected_network_profile,
            "profile_mismatches": profile_mismatches,
            "wireguard_policy": wireguard_policy,
            "protocol_counters": protocol_counters,
            "softnet_counters": softnet_counters,
            "recent_health_deltas": health_state.get("network_deltas", {}),
            "health_state": health_state.get("state", "unknown"),
            "health_updated_at": health_state.get("updated_at", ""),
            "health_soft_reasons": health_state.get("soft_reasons", []),
            "last_front_degradation": health_state.get("last_front_degradation", {}),
            "front_cache_recovery": health_state.get("front_cache_recovery", {}),
            "last_runtime_degradation": health_state.get("last_runtime_degradation", {}),
            "recent_front_interval": recent_front_interval,
        },
        "front": front,
        "transport": transport,
        "probes": probes,
        "logs": {
            "collector_error": logs_collector_error,
            "fresh": {**fresh_logs, "since": fresh_since, "window_minutes": fresh_window_minutes},
            "windows_minutes": logs,
        },
        "maintenance": maintenance,
        "redundancy": {
            "egress": {"available": False, "healthy_exits": healthy_exits, "reason": "one egress node configured"},
            "transport": {
                "available": bool(interserver.get("configured")) if has_interserver else False,
                "selected": selected_transport or (load_transport().policy.TRANSPORT_HY2_TAG if interserver.get("listening") else ""),
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


def _diagnostics_log_window(raw: object, *, since: str) -> LogWindowSnapshot:
    if not isinstance(raw, Mapping) or not isinstance(raw.get("counts"), Mapping):
        return LogWindowSnapshot.unavailable("log window was not collected")
    if not all(isinstance(raw.get(key), str) and raw[key] for key in ("observed_at", "until")):
        return LogWindowSnapshot.unavailable("log window acquisition timestamps are unavailable")
    if "coverage_error" not in raw or not isinstance(raw.get("coverage"), Mapping):
        return LogWindowSnapshot.unavailable("journal retention evidence was not collected")
    if raw.get("coverage_error"):
        return LogWindowSnapshot.unavailable(str(raw["coverage_error"]))
    try:
        return LogWindowSnapshot.collected(
            raw["counts"],
            observed_at=raw["observed_at"],
            since=raw.get("since", since),
            until=raw["until"],
            top_destinations=raw.get("top_destinations") if isinstance(raw.get("top_destinations"), Mapping) else None,
            top_sources=raw.get("top_sources") if isinstance(raw.get("top_sources"), Mapping) else None,
            samples=raw.get("samples") if isinstance(raw.get("samples"), Mapping) else None,
        )
    except (TypeError, ValueError) as exc:
        return LogWindowSnapshot.unavailable(str(exc))


def _collector_state(condition: bool, observed_at: object, message: str) -> CollectorState:
    if not condition:
        return CollectorState.error(message)
    if not isinstance(observed_at, str) or not observed_at:
        return CollectorState.error("collector acquisition timestamp is unavailable")
    return CollectorState.ok(observed_at)


def diagnostics_snapshot(**snapshot_options: Any) -> dict[str, Any]:
    facts = collect_runtime_facts(**snapshot_options)
    generated_at = str(facts["generated_at"])
    observed_at = facts.get("collector_observed_at", {})
    if not isinstance(observed_at, Mapping):
        observed_at = {}
    topology = str(facts.get("topology", ""))
    node_id = str(facts.get("node_id", ""))
    location = str(facts.get("location", ""))
    raw_capabilities = facts.get("capabilities", ())
    capabilities = tuple(str(value) for value in raw_capabilities) if isinstance(raw_capabilities, (list, tuple, set, frozenset)) else ()
    capability_set = frozenset(capabilities)
    has_interserver = bool(capability_set & runtime.INTERSERVER_CAPABILITIES)
    has_public_front = runtime.CAP_PUBLIC_FRONT in capability_set
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
    oom_evidence = storage.get("runtime_events", {}).get("oom_kills", {})
    conntrack_evidence = network.get("conntrack", {}).get("journal_evidence", {})
    storage_error = str(oom_evidence.get("collector_error") or "")
    network_error = str(conntrack_evidence.get("collector_error") or "")
    if not isinstance(oom_evidence.get("counts"), Mapping) or "5m" not in oom_evidence["counts"]:
        storage_error = "kernel OOM evidence is missing"
    if not isinstance(conntrack_evidence.get("counts"), Mapping) or "5" not in conntrack_evidence["counts"]:
        network_error = "kernel conntrack evidence is missing"
    collectors = {
        "services": _collector_state(bool(services) and not contract_error and "unknown" not in services.values(), observed_at.get("services"), contract_error or "service state is unavailable"),
        "artifacts": _collector_state(
            isinstance(artifacts.get("manifest"), Mapping) and bool(artifacts.get("manifest")),
            observed_at.get("artifacts"),
            "render manifest is unavailable",
        ),
        "wireguard": (
            _collector_state(bool(wireguard.get("interface")) and wireguard.get("state") in {"up", "down"}, observed_at.get("wireguard"), "WireGuard state is unavailable")
            if has_interserver
            else CollectorState.not_applicable("node plan has no interserver overlay")
        ),
        "route_probes": (
            _collector_state(probes.get("profile") not in {None, "none"}, observed_at.get("route_probes"), "live route probes were not collected")
            if live_probes
            else CollectorState.skipped("live route probes were not requested")
        ),
        "logs": _collector_state(not log_error, observed_at.get("logs"), log_error or "journal collection failed"),
        "storage": _collector_state(isinstance(storage.get("root_filesystem"), Mapping) and bool(storage.get("root_filesystem")) and not storage_error, observed_at.get("storage"), storage_error or "root filesystem state is unavailable"),
        "network": _collector_state(
            not network_error and all(isinstance(network.get(key), Mapping) and bool(network.get(key)) for key in ("tcp_adaptation", "resolver", "conntrack")),
            observed_at.get("network"),
            network_error or "network state is incomplete",
        ),
        "front": (
            _collector_state("listening" in front, observed_at.get("front"), "public front state is unavailable")
            if has_public_front
            else CollectorState.not_applicable("node plan has no public front")
        ),
        "transport": (
            _collector_state(isinstance(transport.get("interserver"), Mapping) and bool(transport.get("interserver")), observed_at.get("transport"), "interserver transport state is unavailable")
            if has_interserver
            else CollectorState.not_applicable("node plan has no interserver transport")
        ),
        "maintenance": (
            _collector_state(bool(maintenance) and not maintenance.get("collector_error"), observed_at.get("maintenance"), str(maintenance.get("collector_error") or "maintenance state was not collected"))
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
            _diagnostics_log_window(fresh, since=release_installed_at)
            if release_installed_at and str(fresh.get("since", "")) == release_installed_at
            else LogWindowSnapshot.skipped("complete since-release log window was not requested")
            if not full_logs
            else LogWindowSnapshot.unavailable("complete since-release log window is unavailable")
        )
        log_windows = {
            "5m": _diagnostics_log_window(minute_windows.get("5"), since="5 minutes ago"),
            "30m": _diagnostics_log_window(minute_windows.get("30"), since="30 minutes ago") if full_logs else LogWindowSnapshot.skipped("30m window was not requested"),
            "24h": _diagnostics_log_window(minute_windows.get("1440"), since="1440 minutes ago") if full_logs else LogWindowSnapshot.skipped("24h window was not requested"),
            "since_release": since_release,
        }
    raw_windows = {"5m": minute_windows.get("5"), "30m": minute_windows.get("30"), "24h": minute_windows.get("1440"), "since_release": fresh}
    partial_windows = {
        name: {**raw, "error": log_windows[name].collector.message}
        for name, raw in raw_windows.items()
        if isinstance(raw, Mapping) and log_windows[name].collector.status == "error"
    }
    storage = dict(storage)
    storage["journal_coverage"] = {
        "partial_windows": partial_windows,
        "retained_sequence": dict(fresh.get("coverage", {})) if isinstance(fresh, Mapping) else {},
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
    )
    if any(window.collector.status == "error" for window in log_windows.values()):
        payload.component_verdicts["log_history"] = "inconclusive"
        payload.reasons.append(INCOMPLETE_LOG_HISTORY_REASON)
        if payload.verdict == "verified":
            payload.verdict = "inconclusive"
    for name in ("storage", "network"):
        if collectors[name].status == "error":
            payload.reasons.append(f"collector {name}: {collectors[name].message}")
            if payload.verdict == "verified":
                payload.verdict = "inconclusive"
    return payload.to_dict()


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
    transport_select.add_argument("--tag", choices=("interserver-underlay-wg", "interserver-underlay-hy2"), required=True)
    sub.add_parser("network-apply")
    sub.add_parser("memory-prepare")
    exec_router_parser = sub.add_parser("exec-router")
    exec_router_parser.add_argument("router_command", nargs=argparse.REMAINDER)
    storage = sub.add_parser("storage-maintain")
    storage.add_argument("--deep", action="store_true")
    maintain = sub.add_parser("maintain")
    maintain.add_argument("--apply", action="store_true")
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
        env = runtime.parse_env()
        manifest = runtime.read_json(runtime.MANIFEST_PATH, {})
        payload = run_confirmed_probes(env, runtime_contract(manifest if isinstance(manifest, Mapping) else {}), args.profile)
    elif args.command == "client":
        payload = front_client_snapshot(args.source, args.since)
    elif args.command == "front":
        payload = public_front_snapshot(args.since, live_probes=args.live_probes)
    elif args.command == "private-reject-correlate":
        payload = private_reject_correlations(args.since, args.inbound, args.target)
    elif args.command == "health":
        payload = lifecycle.health(
            collect_runtime_facts=collect_runtime_facts,
            front_interval_snapshot=front_interval_snapshot,
            apply_front_interval_verdict=apply_front_interval_verdict,
            front_degradation_evidence=front_degradation_evidence,
        )
    elif args.command == "transport-reconcile":
        if not runtime.contract_has(installed_runtime_contract(), runtime.CAP_INTERSERVER_CLIENT):
            raise RuntimeError("interserver transport control is not applicable to this node")
        payload = load_transport().reconcile_interserver_transport()
    elif args.command == "transport-watch":
        if not runtime.contract_has(installed_runtime_contract(), runtime.CAP_INTERSERVER_CLIENT):
            raise RuntimeError("interserver transport control is not applicable to this node")
        load_transport().watch_interserver_transport()
        return 0
    elif args.command == "transport-select":
        if not runtime.contract_has(installed_runtime_contract(), runtime.CAP_INTERSERVER_CLIENT):
            raise RuntimeError("interserver transport control is not applicable to this node")
        env = runtime.parse_env()
        config = runtime.read_json(runtime.SINGBOX_CONFIG_PATH, {})
        controller = str(config.get("experimental", {}).get("clash_api", {}).get("external_controller", ""))
        if not controller:
            raise RuntimeError("transport controller is unavailable")
        load_transport().select_transport(env, controller, args.tag)
        payload = {"selected": args.tag, "changed": True}
    elif args.command == "network-apply":
        payload = lifecycle.apply_network_profile(installed_runtime_contract())
    elif args.command == "memory-prepare":
        payload = prepare_memory_reserve()
    elif args.command == "exec-router":
        exec_router(args.router_command)
        return 0
    elif args.command == "storage-maintain":
        payload = storage_maintenance(runtime.parse_env(), deep=args.deep)
    elif args.command == "maintain":
        platform = current_platform()
        if args.apply:
            apply_updates(platform)
        payload = maintenance_snapshot(platform)
    elif args.command == "routes":
        payload = routes_command(args)
    else:
        payload = assets_snapshot()
    output = lifecycle.health_log_summary(payload) if args.command == "health" else payload
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
