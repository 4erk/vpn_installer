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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    from .log_classifier import BUCKETS, accepted_destination_from_line, normalize_source, source_endpoint_from_line, source_from_line, split_endpoint, summarize_lines
except ImportError:  # Installed agent runs as a standalone script.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from log_classifier import BUCKETS, accepted_destination_from_line, normalize_source, source_endpoint_from_line, source_from_line, split_endpoint, summarize_lines

try:
    import fcntl
except ImportError:  # pragma: no cover - local Windows tests only
    class _NoopFcntl:
        LOCK_EX = 0

        @staticmethod
        def flock(_handle: Any, _operation: int) -> None:
            return None

    fcntl = _NoopFcntl()  # type: ignore[assignment]

SCHEMA_VERSION = 2
ACCEPTANCE_REQUIRED_TARGETS = ("https://github.com/", "https://www.google.com/generate_204")
ACCEPTANCE_OBSERVED_TARGETS = ("https://telegram.org/",)
PROBE_CONFIRMATION_DELAY_SECONDS = 2
EXTERNAL_CAPABILITY_REQUIREMENTS = frozenset({"ipv6_literal", "ipv6_literal_via_router"})
FRONT_LOSS_MIN_BYTES = 1_000_000
FRONT_LOSS_DEGRADED_PERCENT = 2.0
FRONT_SMALL_FLOW_MIN_BYTES = 8_192
FRONT_SMALL_FLOW_MIN_RETRANSMISSIONS = 3
FRONT_SMALL_FLOW_DEGRADED_PERCENT = 10.0
FRONT_RTT_MIN_SAMPLES = 3
FRONT_RTT_DEGRADED_MS = 250
FRONT_RTT_INFLATION_FACTOR = 3
FRONT_RTO_DEGRADED_MS = 1_000
PROBLEM_LOG_GREP = (
    "ERROR|FATAL|processed invalid connection|accepted tcp:disabled[.]invalid|"
    "connection rejected|mux connection closed|EOF|connection reset|using outbound/vless"
)
XRAY_FRONT_LOG_GREP = "accepted (tcp|udp):|REALITY: processed invalid connection"
CONNTRACK_FULL_GREP = "nf_conntrack.*table full"
ROOT = Path("/etc/vpn-stack")
MANIFEST_PATH = ROOT / "render-manifest.json"
ENV_PATH = ROOT / "deployment.env"
STATE_DIR = Path("/var/lib/vpn-stack")
HEALTH_STATE_PATH = STATE_DIR / "health-state.json"
LOCK_PATH = Path("/run/vpn-stack-agent.lock")
SINGBOX_CONFIG_PATH = Path("/etc/sing-box/config.json")
SYSCTL_PATH = Path("/etc/sysctl.d/90-vpn-stack.conf")

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def journal_problem_events(minutes: int) -> list[tuple[float, str]]:
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
            "-o",
            "short-unix",
            f"--grep={PROBLEM_LOG_GREP}",
        ],
        timeout=30,
    )
    events: list[tuple[float, str]] = []
    for raw_line in result.stdout.splitlines():
        timestamp, separator, message = raw_line.partition(" ")
        if not separator:
            continue
        try:
            events.append((float(timestamp), message))
        except ValueError:
            continue
    return events


def summarize_problem_windows(*, full_logs: bool, fresh_since: str) -> tuple[dict[str, Any], dict[str, Any]]:
    windows = (5, 30, 1440) if full_logs else (5,)
    now = time.time()
    events = journal_problem_events(max(windows))
    summaries = {
        str(minutes): summarize_lines(line for timestamp, line in events if timestamp >= now - minutes * 60)
        for minutes in windows
    }
    try:
        fresh_epoch = datetime.fromisoformat(fresh_since.replace("Z", "+00:00")).timestamp()
    except ValueError:
        fresh_epoch = now - 300
    fresh = summarize_lines(line for timestamp, line in events if timestamp >= fresh_epoch)
    return summaries, fresh


def fresh_log_since() -> tuple[str, int]:
    value = installed_at_value()
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        age_minutes = max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds() / 60))
        if age_minutes <= 24 * 60:
            return value, age_minutes
    except (OSError, TypeError, ValueError):
        pass
    return "5 minutes ago", 5


def installed_at_value() -> str:
    try:
        return (ROOT / "installed_at").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def manifest_snapshot() -> dict[str, Any]:
    manifest = read_json(MANIFEST_PATH, {})
    entries = manifest.get("artifacts", {}) if isinstance(manifest, dict) else {}
    if not entries and isinstance(manifest, dict):
        legacy = manifest.get("artifact_sha256", {})
        entries = {name: {"sha256": digest, "install_path": ""} for name, digest in legacy.items()}
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
        if state != "ok":
            mismatches.append(f"binary:{name}")
        checked_binaries[name] = {"expected_sha256": expected, "actual_sha256": actual, "path": str(actual_path), "state": state}
    manifest_valid = bool(manifest) and int(manifest.get("schema_version", 0)) >= 2
    return {
        "manifest": manifest,
        "files": checked,
        "assets": checked_assets,
        "binaries": checked_binaries,
        "mismatches": mismatches,
        "drift": "none" if manifest_valid and not mismatches else "server-mutated" if mismatches else "unknown",
        "installed_env_sha256": sha256_file(ENV_PATH),
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


def tcp_adaptation_snapshot(interface: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for field, name in (
        ("congestion_control", "net.ipv4.tcp_congestion_control"),
        ("mtu_probing", "net.ipv4.tcp_mtu_probing"),
        ("probe_interval_seconds", "net.ipv4.tcp_probe_interval"),
        ("udp_rmem_default", "net.core.rmem_default"),
        ("udp_rmem_max", "net.core.rmem_max"),
    ):
        result = run(["sysctl", "-n", name], timeout=3)
        value = result.stdout.strip()
        values[field] = int(value) if value.isdigit() else value
    qdisc = run(["tc", "qdisc", "show", "dev", interface], timeout=3) if interface else None
    fields = qdisc.stdout.split() if qdisc and qdisc.returncode == 0 else []
    values["qdisc"] = fields[1] if len(fields) > 1 else ""
    return values


def managed_network_profile(path: Path = SYSCTL_PATH) -> dict[str, int]:
    field_names = {
        "net.core.rmem_default": "udp_rmem_default",
        "net.core.rmem_max": "udp_rmem_max",
        "net.netfilter.nf_conntrack_max": "conntrack_max",
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
    return values


def network_profile_mismatches(actual: dict[str, Any], expected: dict[str, int]) -> list[str]:
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


def endpoint_key(source: str, port: int | None) -> str:
    host = f"[{source}]" if ":" in source else source
    return f"{host}:{port}" if port is not None else host


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
        "idle_ms": [],
    }


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
    for key in ("retransmissions", "bytes_sent", "bytes_retrans", "data_segs_out", "reord_seen", "dsack_dups", "rcv_ooopack", "unacked"):
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
        "idle_ms_p95": percentile(values["idle_ms"], 95),
    }
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
        host, _source_port = socket_endpoint(fields[-1])
        if host:
            clients[host] += 1
    per_flow: dict[str, dict[str, Any]] = {}
    current_flow: dict[str, Any] | None = None
    for raw_line in run(["ss", "-Htin", f"sport = :{port}"], timeout=8).stdout.splitlines():
        line = raw_line.strip()
        fields = line.split()
        if len(fields) >= 5 and fields[0] in {"ESTAB", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "TIME-WAIT"}:
            source, source_port = socket_endpoint(fields[-1])
            if not source:
                current_flow = None
                continue
            current_flow = empty_tcp_metrics()
            current_flow.update({"source": source, "source_port": source_port})
            current_flow["connections"] = 1
            current_flow["states"][fields[0]] = 1
            per_flow[endpoint_key(source, source_port)] = current_flow
            continue
        if current_flow is None:
            continue
        add_tcp_info(current_flow, line)
    per_client: dict[str, dict[str, Any]] = {}
    for values in per_flow.values():
        merge_tcp_metrics(per_client.setdefault(values["source"], empty_tcp_metrics()), values)
    all_client_metrics = {source: render_tcp_metrics(values) for source, values in per_client.items()}
    all_flow_metrics = {
        key: {"source": values["source"], "source_port": values["source_port"], **render_tcp_metrics(values)}
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
    rtts = [rtt for values in per_flow.values() for rtt in values["rtts"]]
    retrans = sum(int(value["retransmissions"]) for value in all_client_metrics.values())
    bytes_sent = sum(int(value["bytes_sent"]) for value in all_client_metrics.values())
    bytes_retrans = sum(int(value["bytes_retrans"]) for value in all_client_metrics.values())
    unacked = sum(int(value["unacked"]) for value in all_client_metrics.values())
    fin_wait_sources = sorted(
        source
        for source, values in all_client_metrics.items()
        if int(values["states"].get("FIN-WAIT-1", 0)) >= 25
    )
    degraded_sources = {source for source, metrics in all_client_metrics.items() if metrics["quality"] == "degraded"}
    degraded_sources.update(
        str(metrics["source"])
        for metrics in all_flow_metrics.values()
        if metrics["quality"] == "degraded"
    )
    listener = run(["ss", "-Hln", f"sport = :{port}"], timeout=5)
    return {
        "port": port,
        "listening": bool(listener.stdout.strip()),
        "state_counts": dict(states),
        "connections": sum(states.values()),
        "top_sources": dict(clients.most_common(20)),
        "clients": client_metrics,
        "flows": flow_metrics,
        "rtt_ms": {"min": min(rtts) if rtts else None, "median": percentile(rtts, 50), "p95": percentile(rtts, 95), "max": max(rtts) if rtts else None},
        "socket_retransmissions": retrans,
        "socket_retransmissions_scope": "lifetime counters of currently open sockets",
        "bytes_sent": bytes_sent,
        "bytes_retrans": bytes_retrans,
        "retransmit_ratio_pct": round(bytes_retrans * 100 / bytes_sent, 3) if bytes_sent else 0.0,
        "degraded_sources": sorted(degraded_sources),
        "unacked": unacked,
        "fin_wait_1_sources": fin_wait_sources,
    }


def client_front_quality(metrics: dict[str, Any]) -> str:
    bytes_sent = int(metrics.get("bytes_sent", 0))
    retransmissions = int(metrics.get("retransmissions", 0))
    retransmit_ratio_pct = float(metrics.get("retransmit_ratio_pct", 0.0))
    if bytes_sent >= FRONT_LOSS_MIN_BYTES and retransmit_ratio_pct >= FRONT_LOSS_DEGRADED_PERCENT:
        return "degraded"
    if (
        bytes_sent >= FRONT_SMALL_FLOW_MIN_BYTES
        and retransmissions >= FRONT_SMALL_FLOW_MIN_RETRANSMISSIONS
        and retransmit_ratio_pct >= FRONT_SMALL_FLOW_DEGRADED_PERCENT
    ):
        return "degraded"
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
    return "observed"


def front_observation(front: dict[str, Any]) -> str:
    """Separate one lossy source from degradation shared by several clients."""
    fin_wait_sources = front.get("fin_wait_1_sources")
    if not isinstance(fin_wait_sources, list):
        clients = front.get("clients", {})
        fin_wait_sources = [
            source
            for source, metrics in clients.items()
            if int(metrics.get("states", {}).get("FIN-WAIT-1", 0)) >= 25
        ]
    clients = front.get("clients", {})
    degraded_sources = set(front.get("degraded_sources", []))
    degraded_sources.update(source for source, metrics in clients.items() if metrics.get("quality") == "degraded")
    noisy_sources = degraded_sources | set(fin_wait_sources)
    if len(noisy_sources) >= 3:
        return "degraded"
    if noisy_sources:
        return "client_specific"
    return "observed"


def front_degradation_evidence(front: dict[str, Any], observed_at: str) -> dict[str, Any]:
    degraded_flows = dict(
        sorted(
            (
                (key, metrics)
                for key, metrics in front.get("flows", {}).items()
                if metrics.get("quality") == "degraded"
            ),
            key=lambda item: -int(item[1].get("bytes_retrans", 0)),
        )[:20]
    )
    degraded_sources = sorted(set(front.get("degraded_sources", [])) | set(front.get("fin_wait_1_sources", [])))
    if not degraded_sources and not degraded_flows:
        return {}
    return {
        "observed_at": observed_at,
        "observation": front_observation(front),
        "degraded_sources": degraded_sources,
        "aggregate": {
            "connections": front.get("connections", 0),
            "bytes_sent": front.get("bytes_sent", 0),
            "bytes_retrans": front.get("bytes_retrans", 0),
            "retransmit_ratio_pct": front.get("retransmit_ratio_pct", 0.0),
            "rtt_ms": front.get("rtt_ms", {}),
        },
        "flows": degraded_flows,
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
    services = {"xray": service_state("vpn-stack-xray.service"), "nftables": service_state("nftables.service")}
    observation = front_observation(front)
    front_verdict = "failed" if services["xray"] != "active" or not front["listening"] else "degraded" if observation in {"client_specific", "degraded"} else "verified"
    probes = run_probes(env, "ru-gateway", "light") if live_probes else {"profile": "none", "ok": None, "requirements": {}}
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
        "transport": {"udp_443_policy": udp_443_policy()},
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
        if metrics.get("source") == source
    }
    flow_events: dict[str, Counter[str]] = {}
    for line in xray_lines:
        event_source, event_port = source_endpoint_from_line(line)
        destination = accepted_destination_from_line(line)
        if event_source != source or event_port is None or not destination:
            continue
        key = endpoint_key(event_source, event_port)
        if key in active_flow_keys:
            flow_events.setdefault(key, Counter())[destination] += 1
    source_flows = {
        key: {**metrics, "accepted_destinations": dict(flow_events.get(key, Counter()).most_common(10))}
        for key, metrics in front.get("flows", {}).items()
        if metrics.get("source") == source
    }
    source_degraded = client.get("quality") == "degraded" or any(
        metrics.get("quality") == "degraded" for metrics in source_flows.values()
    )
    if source_events["accepted"] and source_degraded:
        source_verdict = "degraded"
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
            "source_flow_events": {key: dict(counter.most_common(10)) for key, counter in flow_events.items()},
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
        },
        "events": payload["source_events"],
        "flow_events": payload["source_flow_events"],
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


def probe_url(url: str, *, interface: str = "", proxy: str = "", timeout: int = 6, ip_version: int = 4, insecure: bool = False) -> dict[str, Any]:
    args = ["curl"]
    if not proxy:
        args.append(f"-{ip_version}")
    args.extend(["-L", "--head", "-sS", "-o", "/dev/null", "-w", "%{http_code}|%{time_connect}|%{time_total}|%{remote_ip}", "--connect-timeout", "2", "--max-time", str(timeout)])
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
    args = ["curl", "-4", "-fsS", "--connect-timeout", "3", "--max-time", str(timeout)]
    if interface:
        args.extend(["--interface", interface])
    if proxy:
        args.extend(["--proxy", proxy])
    args.append("https://api.ipify.org")
    result = run(args, timeout=timeout + 2)
    value = result.stdout.strip()
    try:
        ipaddress.ip_address(value)
        valid = True
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
    return {name: passed for name, passed in requirements.items() if name not in EXTERNAL_CAPABILITY_REQUIREMENTS}


def release_gate_ok(probes: dict[str, Any]) -> bool:
    if probes.get("profile") == "acceptance":
        return probes.get("release_gate_ok") is True
    return probes.get("ok") is True


def run_probes(env: dict[str, str], role: str, profile: str) -> dict[str, Any]:
    wg_interface = env.get("WG_INTERFACE", "wg0")
    targets = ["https://www.google.com/generate_204"]
    required_targets = tuple(targets)
    observed_targets: tuple[str, ...] = ()
    if profile == "acceptance":
        required_targets = ACCEPTANCE_REQUIRED_TARGETS
        observed_targets = ACCEPTANCE_OBSERVED_TARGETS
        targets = [*required_targets, *observed_targets]
    paths = {"direct": {}}
    if role == "ru-gateway":
        paths.update({"via_wg": {"interface": wg_interface}, "router": {"proxy": "socks5h://127.0.0.1:2080"}})
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
        required_paths = {"foreign_direct": direct} if role != "ru-gateway" else {"ru_direct": direct, "via_wg": via_wg, "router": router}
        result["requirements"] = {name: all(item["ok"] for item in items) for name, items in required_paths.items()}
        result["ok"] = all(result["requirements"].values())
        return result
    ipv4_literal_url = "https://1.1.1.1/cdn-cgi/trace"
    ipv6_literal_url = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
    literal_matrix = probe_url_matrix(
        [(ipv4_literal_url, {"insecure": True}), (ipv6_literal_url, {"ip_version": 6, "insecure": True})],
        paths,
    )
    literal_direct = literal_matrix["direct"]
    literal_wg = literal_matrix.get("via_wg", [])
    literal_router = literal_matrix.get("router", [])
    identities: dict[str, dict[str, Any]] = {"direct": probe_identity()}
    if role == "ru-gateway":
        identities["via_wg"] = probe_identity(interface=wg_interface)
        identities["router"] = probe_identity(proxy="socks5h://127.0.0.1:2080")
    private_reject = probe_private_reject("socks5h://127.0.0.1:2080") if role == "ru-gateway" else {"ok": True, "not_applicable": True}
    if role == "ru-gateway":
        required_paths: dict[str, list[dict[str, Any]]] = {
            "ru_direct_identity": [identities["direct"]],
            "foreign_domains_via_wg": required_domain_results(via_wg),
            "foreign_domains_via_router": required_domain_results(router),
            "ipv4_literal_via_foreign": [literal_wg[0], literal_router[0]],
            "ipv6_literal_via_router": [literal_router[1]],
            "egress_identities": [identities["via_wg"], identities["router"]],
            "private_fake_reject": [private_reject],
        }
    else:
        required_paths = {
            "foreign_domains": required_domain_results(direct),
            "ipv4_literal": [literal_direct[0]],
            "ipv6_literal": [literal_direct[1]],
            "foreign_identity": [identities["direct"]],
        }
    requirements = {name: all(item["ok"] for item in items) for name, items in required_paths.items()}
    gate_requirements = release_gate_requirements(requirements)
    result.update(
        {
            "identities": identities,
            "ipv4_literal": {"direct": literal_direct[0], "via_wg": literal_wg[0] if literal_wg else None, "router": literal_router[0] if literal_router else None},
            "ipv6_literal": {"direct": literal_direct[1], "via_wg": literal_wg[1] if literal_wg else None, "router": literal_router[1] if literal_router else None},
            "blocked_private_fake": private_reject,
            "requirements": requirements,
            "ok": all(requirements.values()),
            "release_gate_requirements": gate_requirements,
            "release_gate_ok": all(gate_requirements.values()),
        }
    )
    return result


def run_confirmed_probes(env: dict[str, str], role: str, profile: str) -> dict[str, Any]:
    """Confirm an acceptance failure before it can reject or roll back a release."""

    first = run_probes(env, role, profile)
    if profile != "acceptance" or first.get("ok") is True:
        first["confirmation"] = {"cycles": 1, "confirmed_failure": False, "recovered_on_retry": False}
        return first
    time.sleep(PROBE_CONFIRMATION_DELAY_SECONDS)
    retry = run_probes(env, role, profile)
    retry["confirmation"] = {
        "cycles": 2,
        "confirmed_failure": retry.get("ok") is not True,
        "recovered_on_retry": retry.get("ok") is True,
        "initial_failed_requirements": failed_requirements(first),
        "failed_requirements": failed_requirements(retry),
    }
    return retry


def maintenance_snapshot() -> dict[str, Any]:
    result = run(["apt", "list", "--upgradable"], timeout=20)
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


def snapshot(*, live_probes: bool = False, profile: str = "light", full_logs: bool = True, include_maintenance: bool = True) -> dict[str, Any]:
    env = parse_env()
    manifest_data = manifest_snapshot()
    manifest = manifest_data.get("manifest", {})
    role = str(manifest.get("role") or env.get("ROLE") or "unknown")
    wg_interface = env.get("WG_INTERFACE", "wg0")
    public_iface = default_interface()
    port = int(env.get("RU_LISTEN_PORT", "443") or 443)
    services = {
        "wireguard": service_state(f"wg-quick@{wg_interface}.service"),
        "nftables": service_state("nftables.service"),
        "sing-box": service_state("sing-box.service"),
        "xray": service_state("vpn-stack-xray.service"),
        "admin": service_state("vpn-stack-admin.service"),
        "health_timer": service_state("vpn-stack-health.timer"),
    }
    fresh_since, fresh_window_minutes = fresh_log_since()
    if not full_logs:
        fresh_since, fresh_window_minutes = "5 minutes ago", 5
    maintenance = maintenance_snapshot() if include_maintenance else {}
    logs, fresh_logs = summarize_problem_windows(full_logs=full_logs, fresh_since=fresh_since)
    front = tcp_front_snapshot(port) if role == "ru-gateway" else {}
    transport = {"udp_443_policy": udp_443_policy()} if role == "ru-gateway" else {}
    probes = run_confirmed_probes(env, role, profile) if live_probes else {"profile": "none", "ok": None}
    tcp_adaptation = tcp_adaptation_snapshot(public_iface)
    conntrack = conntrack_snapshot(full_logs=full_logs)
    if role == "ru-gateway":
        conntrack["front_bypass"] = xray_conntrack_bypass_snapshot(port)
    expected_network_profile = managed_network_profile()
    actual_network_profile = {**tcp_adaptation, "conntrack_max": conntrack.get("max", 0)}
    profile_mismatches = network_profile_mismatches(actual_network_profile, expected_network_profile)
    health_state = read_json(HEALTH_STATE_PATH, {})
    required = ["wireguard", "nftables"] + (["sing-box", "xray"] if role == "ru-gateway" else [])
    reasons = [f"{name}={services[name]}" for name in required if services.get(name) != "active"]
    if manifest_data["drift"] != "none":
        reasons.append(f"drift={manifest_data['drift']}")
    if profile_mismatches:
        reasons.append(f"network_profile={','.join(profile_mismatches)}")
    if live_probes and not release_gate_ok(probes):
        failed = ",".join(failed_requirements(probes))
        reasons.append(f"live_probes_failed:{failed}" if failed else "live_probes_failed")
    if role == "ru-gateway" and transport.get("udp_443_policy") != "routed":
        reasons.append(f"udp_443_policy={transport.get('udp_443_policy')}")
    if role == "ru-gateway" and not conntrack.get("front_bypass", {}).get("active"):
        reasons.append("xray_conntrack_bypass=inactive")
    capability_failures = [name for name in failed_requirements(probes) if name in EXTERNAL_CAPABILITY_REQUIREMENTS] if live_probes else []
    server_path = "failed" if reasons else "verified" if live_probes else "inconclusive"
    public_front = "not-applicable"
    if role == "ru-gateway":
        public_front = "verified" if services["xray"] == "active" and front.get("listening") else "failed"
    client_observation = front_observation(front) if front else "not-applicable"
    external_capabilities = "degraded" if capability_failures else "verified" if live_probes else "inconclusive"
    degradations = ([f"external_capabilities_failed:{','.join(capability_failures)}"] if capability_failures else [])
    recent_conntrack_full = int(conntrack.get("table_full_events", {}).get("5", 0))
    if recent_conntrack_full:
        degradations.append(f"conntrack_table_full_5m={recent_conntrack_full}")
    overall = "failed" if "failed" in {server_path, public_front} else "degraded" if degradations or client_observation in {"client_specific", "degraded"} else "verified" if server_path == "verified" else "inconclusive"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "deployment": env.get("DEPLOY_NAME", ""),
        "role": role,
        "release": {
            "version": manifest.get("version", ""),
            "release_id": manifest.get("release_id", ""),
            "policy_version": manifest.get("policy_version", ""),
            "manifest_schema": manifest.get("schema_version", 0),
            "runtime": manifest.get("runtime", {}),
            "installed_at": installed_at_value(),
        },
        "host": host_snapshot(public_iface),
        "services": services,
        "artifacts": manifest_data,
        "wireguard": wireguard_snapshot(wg_interface),
        "network": {
            "interfaces": interface_counters((public_iface, wg_interface)),
            "conntrack": conntrack,
            "tcp_adaptation": tcp_adaptation,
            "managed_profile": expected_network_profile,
            "profile_mismatches": profile_mismatches,
            "protocol_counters": protocol_counters_snapshot(),
            "softnet_counters": softnet_counters_snapshot(),
            "recent_health_deltas": health_state.get("network_deltas", {}),
            "health_state": health_state.get("state", "unknown"),
            "health_updated_at": health_state.get("updated_at", ""),
            "health_soft_reasons": health_state.get("soft_reasons", []),
            "last_front_degradation": health_state.get("last_front_degradation", {}),
        },
        "front": front,
        "transport": transport,
        "probes": probes,
        "logs": {"fresh": {"since": fresh_since, "window_minutes": fresh_window_minutes, **fresh_logs}, "windows_minutes": logs},
        "maintenance": maintenance,
        "redundancy": {"available": False, "healthy_exits": 1 if services["wireguard"] == "active" else 0, "reason": "single foreign egress configured"},
        "verdicts": {"server_path": server_path, "public_front": public_front, "client_observation": client_observation, "external_capabilities": external_capabilities, "overall": overall, "reasons": reasons + degradations},
    }


def health() -> dict[str, Any]:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = snapshot(live_probes=True, profile="light", full_logs=False, include_maintenance=False)
        previous = read_json(HEALTH_STATE_PATH, {})
        hard_failure = current["verdicts"]["server_path"] == "failed"
        failures = int(previous.get("consecutive_failures", 0)) + 1 if hard_failure else 0
        network_counters = {
            "interfaces": current.get("network", {}).get("interfaces", {}),
            "protocol": current.get("network", {}).get("protocol_counters", {}),
            "softnet": current.get("network", {}).get("softnet_counters", {}),
        }
        network_deltas = positive_counter_deltas(network_counters, previous.get("network_counters", {}))
        soft_reasons = network_soft_reasons(network_deltas)
        conntrack_full = int(current.get("network", {}).get("conntrack", {}).get("table_full_events", {}).get("5", 0))
        if conntrack_full:
            soft_reasons.append(f"conntrack_table_full_5m={conntrack_full}")
        client_observation = current.get("verdicts", {}).get("client_observation")
        if client_observation in {"client_specific", "degraded"}:
            soft_reasons.append(f"public_front={client_observation}")
        front_evidence = front_degradation_evidence(current.get("front", {}), current.get("generated_at") or utc_now())
        last_front_degradation = front_evidence or previous.get("last_front_degradation", {})
        state = "degraded" if soft_reasons else "healthy"
        action = "none"
        postcheck: dict[str, Any] | None = None
        if hard_failure and failures == 1:
            state = "suspect"
        elif hard_failure:
            state = "failed"
            last_action = int(previous.get("last_action_epoch", 0))
            if int(time.time()) - last_action >= 900:
                action = recover(current)
                if action != "none":
                    time.sleep(2)
                    postcheck = snapshot(live_probes=True, profile="light", full_logs=False, include_maintenance=False)
                    if postcheck["verdicts"]["server_path"] == "verified":
                        state = "healthy"
                        failures = 0
                    else:
                        state = "recovering"
        if postcheck is not None:
            current["post_recovery"] = postcheck["verdicts"]
        payload = {
            "schema_version": SCHEMA_VERSION,
            "updated_at": utc_now(),
            "state": state,
            "consecutive_failures": failures,
            "last_action": action,
            "last_action_epoch": int(time.time()) if action != "none" else int(previous.get("last_action_epoch", 0)),
            "probe_failures": failed_requirements((postcheck or current).get("probes", {})),
            "probes": (postcheck or current).get("probes", {}),
            "network_counters": network_counters,
            "network_deltas": network_deltas,
            "soft_reasons": soft_reasons,
            "last_front_degradation": last_front_degradation,
            "verdicts": (postcheck or current)["verdicts"],
        }
        if postcheck is not None:
            payload["post_recovery_verdicts"] = postcheck["verdicts"]
        write_json_atomic(HEALTH_STATE_PATH, payload)
        return payload


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
    if int(softnet.get("dropped", 0)):
        reasons.append(f"softnet_drops={softnet['dropped']}")
    missed = sum(int(values.get("rx_missed_errors", 0)) for values in deltas.get("interfaces", {}).values())
    if missed:
        reasons.append(f"interface_rx_missed={missed}")
    return reasons


def recover(current: dict[str, Any]) -> str:
    services = current.get("services", {})
    interface = str(current.get("wireguard", {}).get("interface", "wg0"))
    for key, unit in (("wireguard", f"wg-quick@{interface}.service"), ("nftables", "nftables.service"), ("sing-box", "sing-box.service"), ("xray", "vpn-stack-xray.service")):
        if services.get(key) not in {None, "active", "inactive" if key in {"sing-box", "xray"} and current.get("role") == "foreign-exit" else "active"}:
            result = run(["systemctl", "restart", unit], timeout=30)
            return f"restart:{unit}:{'ok' if result.returncode == 0 else 'failed'}"
    artifacts_clean = current.get("artifacts", {}).get("drift") == "none"
    network = current.get("network", {})
    if artifacts_clean and network.get("profile_mismatches"):
        result = run(["sysctl", "--load", str(SYSCTL_PATH)], timeout=30)
        return f"reload:sysctl:{'ok' if result.returncode == 0 else 'failed'}"
    bypass = network.get("conntrack", {}).get("front_bypass", {})
    if artifacts_clean and current.get("role") == "ru-gateway" and not bypass.get("active"):
        check = run(["nft", "--check", "--file", "/etc/nftables.conf"], timeout=15)
        if check.returncode != 0:
            return "reload:nftables:invalid-config"
        result = run(["nft", "--file", "/etc/nftables.conf"], timeout=30)
        return f"reload:nftables:{'ok' if result.returncode == 0 else 'failed'}"
    if current.get("role") == "ru-gateway":
        probes = current.get("probes", {})
        if probe_requirement(probes, "via_wg") and not probe_requirement(probes, "router"):
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
    admin_apply.write_json_atomic(admin_apply.RULES_PATH, {"schema_version": 1, "rules": rules})
    admin_apply.apply_rules()
    return {"rules": rules, "applied": True}


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
    sub.add_parser("health")
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
        payload = snapshot(
            live_probes=args.live_probes,
            profile=args.profile,
            full_logs=not args.compact,
            include_maintenance=not args.compact,
        )
    elif args.command == "probe":
        env = parse_env()
        manifest = read_json(MANIFEST_PATH, {})
        payload = run_confirmed_probes(env, str(manifest.get("role", "unknown")), args.profile)
    elif args.command == "client":
        payload = front_client_snapshot(args.source, args.since)
    elif args.command == "front":
        payload = public_front_snapshot(args.since, live_probes=args.live_probes)
    elif args.command == "health":
        payload = health()
    elif args.command == "routes":
        payload = routes_command(args)
    else:
        payload = assets_snapshot()
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    if args.command == "health" and payload.get("state") in {"failed", "recovering"}:
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)
