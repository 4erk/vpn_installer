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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    from .log_classifier import BUCKETS, normalize_source, source_from_line, summarize_lines
except ImportError:  # Installed agent runs as a standalone script.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from log_classifier import BUCKETS, normalize_source, source_from_line, summarize_lines

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
ROOT = Path("/etc/vpn-stack")
MANIFEST_PATH = ROOT / "render-manifest.json"
ENV_PATH = ROOT / "deployment.env"
STATE_DIR = Path("/var/lib/vpn-stack")
HEALTH_STATE_PATH = STATE_DIR / "health-state.json"
LOCK_PATH = Path("/run/vpn-stack-agent.lock")
SINGBOX_CONFIG_PATH = Path("/etc/sing-box/config.json")

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
    fields = ("rx_bytes", "rx_packets", "rx_dropped", "rx_errors", "tx_bytes", "tx_packets", "tx_dropped", "tx_errors")
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


def socket_source(peer: str) -> str:
    if peer.startswith("["):
        return normalize_source(peer[1 : peer.find("]")])
    return normalize_source(peer.rsplit(":", 1)[0] if ":" in peer else peer)


def tcp_front_snapshot(port: int) -> dict[str, Any]:
    states = Counter()
    clients = Counter()
    sockets = run(["ss", "-Htan", f"sport = :{port}"], timeout=8)
    for line in sockets.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        states[fields[0]] += 1
        host = socket_source(fields[-1])
        if host:
            clients[host] += 1
    per_client: dict[str, dict[str, Any]] = {}
    current_client: dict[str, Any] | None = None
    for raw_line in run(["ss", "-Htin", f"sport = :{port}"], timeout=8).stdout.splitlines():
        line = raw_line.strip()
        fields = line.split()
        if len(fields) >= 5 and fields[0] in {"ESTAB", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "TIME-WAIT"}:
            source = socket_source(fields[-1])
            current_client = per_client.setdefault(source, {"connections": 0, "states": Counter(), "rtts": [], "retransmissions": 0, "unacked": 0, "idle_ms": []})
            current_client["connections"] += 1
            current_client["states"][fields[0]] += 1
            continue
        if current_client is None:
            continue
        rtt = re.search(r"\brtt:([0-9.]+)", line)
        retrans = re.search(r"\bretrans:\d+/(\d+)", line)
        unacked = re.search(r"\bunacked:(\d+)", line)
        idle = [int(value) for value in re.findall(r"\b(?:lastsnd|lastrcv|lastack):(\d+)", line)]
        if rtt:
            current_client["rtts"].append(float(rtt.group(1)))
        if retrans:
            current_client["retransmissions"] += int(retrans.group(1))
        if unacked:
            current_client["unacked"] += int(unacked.group(1))
        current_client["idle_ms"].extend(idle)
    all_client_metrics: dict[str, dict[str, Any]] = {}
    for source, values in per_client.items():
        rtts = values["rtts"]
        idle = values["idle_ms"]
        all_client_metrics[source] = {
            "connections": values["connections"],
            "states": dict(values["states"]),
            "rtt_ms": {"median": percentile(rtts, 50), "p95": percentile(rtts, 95)},
            "retransmissions": values["retransmissions"],
            "unacked": values["unacked"],
            "idle_ms_p95": percentile(idle, 95),
        }
    client_metrics = {
        source: all_client_metrics[source]
        for source, _metrics in sorted(all_client_metrics.items(), key=lambda item: (-item[1]["connections"], item[0]))[:20]
    }
    rtts = [rtt for values in per_client.values() for rtt in values["rtts"]]
    retrans = sum(int(value["retransmissions"]) for value in all_client_metrics.values())
    unacked = sum(int(value["unacked"]) for value in all_client_metrics.values())
    fin_wait_sources = sorted(
        source
        for source, values in all_client_metrics.items()
        if int(values["states"].get("FIN-WAIT-1", 0)) >= 25
    )
    listener = run(["ss", "-Hln", f"sport = :{port}"], timeout=5)
    return {
        "port": port,
        "listening": bool(listener.stdout.strip()),
        "state_counts": dict(states),
        "connections": sum(states.values()),
        "top_sources": dict(clients.most_common(20)),
        "clients": client_metrics,
        "rtt_ms": {"min": min(rtts) if rtts else None, "median": percentile(rtts, 50), "p95": percentile(rtts, 95), "max": max(rtts) if rtts else None},
        "socket_retransmissions": retrans,
        "socket_retransmissions_scope": "lifetime counters of currently open sockets",
        "unacked": unacked,
        "fin_wait_1_sources": fin_wait_sources,
    }


def front_observation(front: dict[str, Any]) -> str:
    """Report only present socket churn; ss retransmission values are lifetime counters."""
    fin_wait_sources = front.get("fin_wait_1_sources")
    if not isinstance(fin_wait_sources, list):
        clients = front.get("clients", {})
        fin_wait_sources = [
            source
            for source, metrics in clients.items()
            if int(metrics.get("states", {}).get("FIN-WAIT-1", 0)) >= 25
        ]
    if len(fin_wait_sources) >= 3:
        return "degraded"
    if fin_wait_sources:
        return "client_specific"
    return "observed"


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


def public_front_snapshot(minutes: int, source: str | None = None) -> dict[str, Any]:
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
    xray_lines = journal_lines("vpn-stack-xray.service", minutes)
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
        "verdict": "verified" if services["xray"] == "active" and front["listening"] else "failed",
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
    if source_events["accepted"]:
        source_verdict = "reached_xray"
    elif source_events["invalid_reality"] or source_events["disabled_invalid"]:
        source_verdict = "rejected_by_front"
    elif client or source in front.get("top_sources", {}):
        source_verdict = "tcp_reached_no_xray_accept"
    else:
        source_verdict = "not_seen_on_server"
    payload.update({"source": source, "source_events": source_events, "source_client": client, "source_verdict": source_verdict})
    return payload


def front_client_snapshot(source: str, minutes: int) -> dict[str, Any]:
    payload = public_front_snapshot(minutes, source)
    return {
        "schema_version": payload["schema_version"],
        "generated_at": payload["generated_at"],
        "source": source,
        "window_minutes": minutes,
        "services": payload["services"],
        "front": {"port": payload["front"].get("port", 0), "listening": payload["front"].get("listening", False), "client": payload["source_client"]},
        "events": payload["source_events"],
        "transport": payload["transport"],
        "verdict": payload["source_verdict"],
    }


def percentile(values: list[float], percent: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percent / 100)))
    return ordered[index]


def conntrack_snapshot() -> dict[str, int | float]:
    def number(path: str) -> int:
        try:
            return int(Path(path).read_text().strip())
        except (OSError, ValueError):
            return 0

    count = number("/proc/sys/net/netfilter/nf_conntrack_count")
    maximum = number("/proc/sys/net/netfilter/nf_conntrack_max")
    return {"count": count, "max": maximum, "percent": round(count * 100 / maximum, 2) if maximum else 0.0}


def probe_url(url: str, *, interface: str = "", proxy: str = "", timeout: int = 6, ip_version: int = 4, insecure: bool = False) -> dict[str, Any]:
    args = ["curl", f"-{ip_version}", "-L", "-sS", "-o", "/dev/null", "-w", "%{http_code}|%{time_connect}|%{time_total}|%{remote_ip}", "--connect-timeout", "2", "--max-time", str(timeout)]
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


def run_probes(env: dict[str, str], role: str, profile: str) -> dict[str, Any]:
    wg_interface = env.get("WG_INTERFACE", "wg0")
    targets = ["https://www.google.com/generate_204"]
    required_targets = tuple(targets)
    observed_targets: tuple[str, ...] = ()
    if profile == "acceptance":
        required_targets = ACCEPTANCE_REQUIRED_TARGETS
        observed_targets = ACCEPTANCE_OBSERVED_TARGETS
        targets = [*required_targets, *observed_targets]
    direct = [probe_url(url) for url in targets]
    via_wg = [probe_url(url, interface=wg_interface) for url in targets] if role == "ru-gateway" else []
    router = [probe_url(url, proxy="socks5h://127.0.0.1:2080") for url in targets] if role == "ru-gateway" else []
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
        required_paths = {"foreign_direct": direct} if role != "ru-gateway" else {"via_wg": via_wg, "router": router}
        result["requirements"] = {name: all(item["ok"] for item in items) for name, items in required_paths.items()}
        result["ok"] = all(result["requirements"].values())
        return result
    ipv4_literal_url = "https://1.1.1.1/cdn-cgi/trace"
    ipv6_literal_url = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
    literal_direct = [probe_url(ipv4_literal_url, insecure=True), probe_url(ipv6_literal_url, ip_version=6, insecure=True)]
    literal_wg = [probe_url(ipv4_literal_url, interface=wg_interface, insecure=True), probe_url(ipv6_literal_url, interface=wg_interface, ip_version=6, insecure=True)] if role == "ru-gateway" else []
    literal_router = [probe_url(ipv4_literal_url, proxy="socks5h://127.0.0.1:2080", insecure=True), probe_url(ipv6_literal_url, proxy="socks5h://127.0.0.1:2080", insecure=True)] if role == "ru-gateway" else []
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
    result.update(
        {
            "identities": identities,
            "ipv4_literal": {"direct": literal_direct[0], "via_wg": literal_wg[0] if literal_wg else None, "router": literal_router[0] if literal_router else None},
            "ipv6_literal": {"direct": literal_direct[1], "via_wg": literal_wg[1] if literal_wg else None, "router": literal_router[1] if literal_router else None},
            "blocked_private_fake": private_reject,
            "requirements": requirements,
            "ok": all(requirements.values()),
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
    maintenance = maintenance_snapshot() if include_maintenance else {}
    log_windows = (5, 30, 1440) if full_logs else (5,)
    logs = {str(minutes): summarize_lines(journal_lines("sing-box.service", minutes) + journal_lines("vpn-stack-xray.service", minutes)) for minutes in log_windows}
    fresh_logs = summarize_lines(journal_lines_since("sing-box.service", fresh_since) + journal_lines_since("vpn-stack-xray.service", fresh_since))
    front = tcp_front_snapshot(port) if role == "ru-gateway" else {}
    transport = {"udp_443_policy": udp_443_policy()} if role == "ru-gateway" else {}
    probes = run_confirmed_probes(env, role, profile) if live_probes else {"profile": "none", "ok": None}
    required = ["wireguard", "nftables"] + (["sing-box", "xray"] if role == "ru-gateway" else [])
    reasons = [f"{name}={services[name]}" for name in required if services.get(name) != "active"]
    if manifest_data["drift"] != "none":
        reasons.append(f"drift={manifest_data['drift']}")
    if live_probes and not probes.get("ok"):
        reasons.append("live_probes_failed")
    if role == "ru-gateway" and transport.get("udp_443_policy") != "routed":
        reasons.append(f"udp_443_policy={transport.get('udp_443_policy')}")
    server_path = "failed" if reasons else "verified" if live_probes else "inconclusive"
    public_front = "not-applicable"
    if role == "ru-gateway":
        public_front = "verified" if services["xray"] == "active" and front.get("listening") else "failed"
    client_observation = front_observation(front) if front else "not-applicable"
    overall = "failed" if "failed" in {server_path, public_front} else "degraded" if client_observation == "degraded" else "verified" if server_path == "verified" else "inconclusive"
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
        "network": {"interfaces": interface_counters((public_iface, wg_interface)), "conntrack": conntrack_snapshot()},
        "front": front,
        "transport": transport,
        "probes": probes,
        "logs": {"fresh": {"since": fresh_since, "window_minutes": fresh_window_minutes, **fresh_logs}, "windows_minutes": logs},
        "maintenance": maintenance,
        "redundancy": {"available": False, "healthy_exits": 1 if services["wireguard"] == "active" else 0, "reason": "single foreign egress configured"},
        "verdicts": {"server_path": server_path, "public_front": public_front, "client_observation": client_observation, "overall": overall, "reasons": reasons},
    }


def health() -> dict[str, Any]:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = snapshot(live_probes=True, profile="light", full_logs=False, include_maintenance=False)
        previous = read_json(HEALTH_STATE_PATH, {})
        hard_failure = current["verdicts"]["server_path"] == "failed"
        failures = int(previous.get("consecutive_failures", 0)) + 1 if hard_failure else 0
        state = "healthy"
        action = "none"
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
                    if postcheck["verdicts"]["server_path"] != "failed":
                        state = "healthy"
                        failures = 0
                    else:
                        state = "recovering"
                    current["post_recovery"] = postcheck["verdicts"]
        payload = {
            "schema_version": SCHEMA_VERSION,
            "updated_at": utc_now(),
            "state": state,
            "consecutive_failures": failures,
            "last_action": action,
            "last_action_epoch": int(time.time()) if action != "none" else int(previous.get("last_action_epoch", 0)),
            "verdicts": current["verdicts"],
        }
        write_json_atomic(HEALTH_STATE_PATH, payload)
        return payload


def recover(current: dict[str, Any]) -> str:
    services = current.get("services", {})
    interface = str(current.get("wireguard", {}).get("interface", "wg0"))
    for key, unit in (("wireguard", f"wg-quick@{interface}.service"), ("nftables", "nftables.service"), ("sing-box", "sing-box.service"), ("xray", "vpn-stack-xray.service")):
        if services.get(key) not in {None, "active", "inactive" if key in {"sing-box", "xray"} and current.get("role") == "foreign-exit" else "active"}:
            result = run(["systemctl", "restart", unit], timeout=30)
            return f"restart:{unit}:{'ok' if result.returncode == 0 else 'failed'}"
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
    probe = sub.add_parser("probe")
    probe.add_argument("--profile", choices=["light", "acceptance"], default="light")
    client = sub.add_parser("client")
    client.add_argument("--source", required=True)
    client.add_argument("--since", type=int, default=15)
    front = sub.add_parser("front")
    front.add_argument("--since", type=int, default=30)
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
        payload = snapshot(live_probes=args.live_probes, profile=args.profile)
    elif args.command == "probe":
        env = parse_env()
        manifest = read_json(MANIFEST_PATH, {})
        payload = run_confirmed_probes(env, str(manifest.get("role", "unknown")), args.profile)
    elif args.command == "client":
        payload = front_client_snapshot(args.source, args.since)
    elif args.command == "front":
        payload = public_front_snapshot(args.since)
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
