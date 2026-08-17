from __future__ import annotations

import json
import shlex
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from . import workflows
from .common import OUT_DIR, print_header
from .client_artifacts import render_vless_uri
from .diagnostics import DiagnosticsSnapshot, classify_interserver_adaptation
from .network_profile import (
    FQ_FLOW_LIMIT,
    FQ_KIND,
    FQ_PACKET_LIMIT,
    TCP_MTU_PROBE_FLOOR,
    TCP_NO_METRICS_SAVE,
    UDP_RMEM_DEFAULT,
    UDP_RMEM_MAX,
    UDP_WMEM_DEFAULT,
    UDP_WMEM_MAX,
)
from .public_transport import PUBLIC_HY2_OUTBOUND_TAG, render_public_hy2_outbound
from .remote import remote_agent_snapshot, scp_upload, ssh_capture
from .topology import (
    CAP_INTERSERVER_CLIENT,
    CAP_INTERSERVER_SERVER,
    CAP_PUBLIC_FRONT,
    CAP_WEB_ADMIN,
    NODE_EXIT,
    NODE_GATEWAY,
    NodePlan,
    TOPOLOGY_DUAL,
    TopologySpec,
)
from .vless_verify import (
    RUNNER_HTTP_PROBE_COUNT,
    RUNNER_HTTP_TIMEOUT_SECONDS,
    RUNNER_CURL_WATCHDOG_KILL_SECONDS,
    RUNNER_RELIABILITY_ATTEMPTS,
    RUNNER_RELIABILITY_MAX_TOTAL_SECONDS,
    RUNNER_RELIABILITY_TIMEOUT_SECONDS,
    RUNNER_REPORT_SECONDS,
    RUNNER_SHUTDOWN_SECONDS,
    RUNNER_STARTUP_SECONDS,
    RUNNER_THROUGHPUT_CLOCK_SKEW_SECONDS,
    RUNNER_TRANSPORT_DRAIN_SECONDS,
    RUNNER_ROUTE_PROBE_TIMEOUT_SECONDS,
    THROUGHPUT_MAX_GAP_SECONDS,
    THROUGHPUT_SUSTAINED_FLOOR_BYTES_PER_SECOND,
    parse_vless_uri,
    render_ephemeral_singbox_client,
    render_live_route_probe,
    render_vless_runner,
)


VLESS_RUNNER_POLL_INTERVAL_SECONDS = 5
PRIMARY_CAPACITY_REFERENCE_BYTES_PER_SECOND = 6_250_000
FALLBACK_CAPACITY_REFERENCE_BYTES_PER_SECOND = 1_250_000
VLESS_RUNNER_LOCK_PATH = "/run/lock/vpn-stack-vless-verify.lock"
SNAPSHOT_MAX_AGE_SECONDS = 180
COMPLETE_LOG_RETENTION_SECONDS = 14 * 24 * 60 * 60
INTERSERVER_CAPABILITIES = frozenset({CAP_INTERSERVER_CLIENT, CAP_INTERSERVER_SERVER})


def _required_snapshot_collectors(capabilities: frozenset[str]) -> frozenset[str]:
    required = {"services", "artifacts", "route_probes", "logs", "storage", "network", "maintenance"}
    if CAP_PUBLIC_FRONT in capabilities:
        required.add("front")
    if capabilities & INTERSERVER_CAPABILITIES:
        required.update({"wireguard", "transport"})
    return frozenset(required)


def _required_snapshot_services(capabilities: frozenset[str]) -> frozenset[str]:
    required = {"nftables", "sing-box", "resolver", "health_timer"}
    if CAP_PUBLIC_FRONT in capabilities:
        required.add("xray")
    if CAP_WEB_ADMIN in capabilities:
        required.add("admin")
    if capabilities & INTERSERVER_CAPABILITIES:
        required.add("wireguard")
    if CAP_INTERSERVER_CLIENT in capabilities:
        required.add("transport")
    return frozenset(required)


def _release_within_complete_log_retention(snapshot: DiagnosticsSnapshot) -> bool:
    installed_at = str(snapshot.release.get("installed_at", ""))
    try:
        timestamp = datetime.fromisoformat(installed_at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)).total_seconds()
    except (TypeError, ValueError):
        return True
    return -30 <= age_seconds <= COMPLETE_LOG_RETENTION_SECONDS


def _verify_snapshot(snapshot: DiagnosticsSnapshot, *, expected_plan: NodePlan | None = None) -> DiagnosticsSnapshot:
    if not snapshot.has_capability_contract:
        snapshot.verdict = "inconclusive"
        snapshot.reasons = ["canonical topology/node/location/capabilities evidence is missing"]
        return snapshot
    try:
        observed_at = datetime.fromisoformat(snapshot.generated_at.replace("Z", "+00:00"))
        age_seconds = (datetime.now(timezone.utc) - observed_at.astimezone(timezone.utc)).total_seconds()
    except (TypeError, ValueError):
        snapshot.verdict = "inconclusive"
        snapshot.reasons = ["diagnostics snapshot timestamp is invalid"]
        return snapshot
    if age_seconds < -30 or age_seconds > SNAPSHOT_MAX_AGE_SECONDS:
        snapshot.verdict = "inconclusive"
        snapshot.reasons = [f"diagnostics snapshot is stale or from the future: age={age_seconds:.1f}s"]
        return snapshot

    hard_failures: list[str] = []
    degradations: list[str] = []
    capabilities = frozenset(snapshot.capabilities)
    if expected_plan is not None:
        expected_contract = (
            expected_plan.topology,
            expected_plan.node_id,
            expected_plan.location,
            expected_plan.capabilities,
        )
        observed_contract = (
            snapshot.topology,
            snapshot.node_id,
            snapshot.location,
            capabilities,
        )
        if observed_contract != expected_contract:
            hard_failures.append("agent canonical node contract differs from deployment topology")
    required_collectors = _required_snapshot_collectors(capabilities)
    for name in sorted(required_collectors):
        state = snapshot.collectors[name]
        if state.status == "error":
            hard_failures.append(f"collector {name} failed: {state.message}")
        elif state.status == "skipped":
            hard_failures.append(f"collector {name} was skipped: {state.message}")
        elif state.status == "not_applicable":
            hard_failures.append(f"collector {name} is required by node capabilities")
        elif state.status == "stale":
            degradations.append(f"collector {name} is stale")
    for name in sorted({"front", "wireguard", "transport"} - required_collectors):
        state = snapshot.collectors[name]
        if state.status != "not_applicable":
            hard_failures.append(f"collector {name} must be not_applicable for this node")
    for name, window in snapshot.log_windows.items():
        if window.collector.status == "error":
            if name == "since_release" and not _release_within_complete_log_retention(snapshot):
                continue
            hard_failures.append(f"log window {name} unavailable: {window.collector.message}")
        elif window.collector.status == "skipped":
            hard_failures.append(f"log window {name} was skipped: {window.collector.message}")
        elif window.collector.status == "not_applicable":
            hard_failures.append(f"log window {name} is unexpectedly not_applicable")
        elif window.collector.status == "stale":
            degradations.append(f"log window {name} is stale")
    required_services = _required_snapshot_services(capabilities)
    for service_name in sorted(required_services):
        state = snapshot.services.get(service_name)
        if state != "active":
            hard_failures.append(f"{service_name}={state or 'missing'}")
    has_public_front = CAP_PUBLIC_FRONT in capabilities
    has_interserver_client = CAP_INTERSERVER_CLIENT in capabilities
    requires_public_quic = has_public_front and snapshot.topology == TOPOLOGY_DUAL
    if has_public_front and (
        snapshot.front.get("tcp_keepalive_idle_seconds") != 90
        or snapshot.front.get("tcp_keepalive_interval_seconds") != 15
    ):
        hard_failures.append("public TCP front keepalive policy is missing")
    if has_interserver_client:
        adaptation = snapshot.transport.get("interserver", {}).get("adaptive_state", {})
        adaptation_failure, adaptation_degradation = classify_interserver_adaptation(adaptation)
        if adaptation_failure:
            hard_failures.append(adaptation_failure)
        elif adaptation_degradation:
            degradations.append(adaptation_degradation)
    if snapshot.drift == "server-mutated":
        hard_failures.append("installed config hash differs from render manifest")
    elif snapshot.drift == "unknown":
        degradations.append("render manifest is missing or incomplete")
    tcp_adaptation = snapshot.network.get("tcp_adaptation", {})
    if not tcp_adaptation:
        hard_failures.append("network adaptation fields are missing")
    elif str(tcp_adaptation.get("mtu_probing", "")).strip() != "1":
        degradations.append("TCP PLPMTUD adaptation is disabled")
    if tcp_adaptation and tcp_adaptation.get("mtu_probe_floor") != TCP_MTU_PROBE_FLOOR:
        degradations.append("TCP PLPMTUD floor is not active")
    if tcp_adaptation and tcp_adaptation.get("metrics_save_disabled") != TCP_NO_METRICS_SAVE:
        degradations.append("TCP destination metrics cache is not active")
    try:
        rmem_default = int(tcp_adaptation.get("udp_rmem_default", 0))
        rmem_max = int(tcp_adaptation.get("udp_rmem_max", 0))
        wmem_default = int(tcp_adaptation.get("udp_wmem_default", 0))
        wmem_max = int(tcp_adaptation.get("udp_wmem_max", 0))
    except (TypeError, ValueError):
        rmem_default = rmem_max = wmem_default = wmem_max = 0
    if tcp_adaptation and (
        rmem_default < UDP_RMEM_DEFAULT
        or rmem_max < UDP_RMEM_MAX
        or wmem_default < UDP_WMEM_DEFAULT
        or wmem_max < UDP_WMEM_MAX
    ):
        degradations.append("UDP socket buffer profile is not active")
    try:
        qdisc_limit = int(tcp_adaptation.get("qdisc_limit", 0))
        qdisc_flow_limit = int(tcp_adaptation.get("qdisc_flow_limit", 0))
    except (TypeError, ValueError):
        qdisc_limit = qdisc_flow_limit = 0
    if tcp_adaptation and (
        tcp_adaptation.get("qdisc") != FQ_KIND
        or qdisc_limit != FQ_PACKET_LIMIT
        or qdisc_flow_limit != FQ_FLOW_LIMIT
    ):
        hard_failures.append("managed fq profile is not active")
    required_verdicts = {"server_path", "host_integrity"}
    if has_public_front:
        required_verdicts.update({"public_front", "client_observation"})
    if requires_public_quic:
        required_verdicts.add("public_quic")
    if not required_verdicts.issubset(snapshot.component_verdicts):
        hard_failures.append("agent verdict fields are incomplete")
    if not snapshot.storage.get("root_filesystem"):
        hard_failures.append("root filesystem integrity fields are missing")
    server_path = snapshot.component_verdicts.get("server_path", "inconclusive")
    public_front = snapshot.component_verdicts.get("public_front", "not-applicable")
    public_quic = snapshot.component_verdicts.get("public_quic", "not-applicable")
    client_observation = snapshot.component_verdicts.get("client_observation", "not-applicable")
    host_integrity = snapshot.component_verdicts.get("host_integrity", "inconclusive")
    if server_path == "failed":
        hard_failures.append("agent server_path failed")
    elif server_path != "verified":
        degradations.append(f"agent server_path={server_path}")
    if has_public_front:
        if public_front == "failed":
            hard_failures.append("agent public_front failed")
        elif public_front != "verified":
            degradations.append(f"agent public_front={public_front}")
    if requires_public_quic and public_quic != "verified":
        hard_failures.append(f"agent public_quic={public_quic}")
    if has_public_front and client_observation in {"client_specific", "degraded"}:
        degradations.append("public TCP front shows active data-path degradation")
    if host_integrity == "failed":
        hard_failures.append("agent host_integrity failed")
    elif host_integrity != "verified":
        degradations.append(f"agent host_integrity={host_integrity}")
    if snapshot.route_probes.get("profile") != "acceptance":
        hard_failures.append("acceptance probes did not run")
    elif "release_gate_ok" in snapshot.route_probes:
        if snapshot.route_probes.get("release_gate_ok") is not True:
            hard_failures.append("acceptance release gate failed")
        elif snapshot.route_probes.get("ok") is not True:
            capability_failures = snapshot.route_probes.get("capability_failures", {})
            transport_failures = capability_failures.get("transport", []) if isinstance(capability_failures, dict) else []
            external_failures = capability_failures.get("external", []) if isinstance(capability_failures, dict) else []
            if transport_failures:
                degradations.append("transport capability probe failed: " + ",".join(map(str, transport_failures)))
            if external_failures or not transport_failures:
                degradations.append("external capability probe failed")
    elif snapshot.route_probes.get("ok") is not True:
        hard_failures.append("acceptance probes failed")
    if hard_failures:
        snapshot.verdict = "failed"
        snapshot.reasons = hard_failures + degradations
    elif degradations:
        snapshot.verdict = "degraded"
        snapshot.reasons = degradations
    else:
        snapshot.verdict = "verified"
        snapshot.reasons = []
    return snapshot


def _collect_agent_snapshot(target) -> DiagnosticsSnapshot:
    try:
        payload = remote_agent_snapshot(target, live_probes=True, profile="acceptance")
        return DiagnosticsSnapshot.from_agent(payload)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid vpn-stack-agent snapshot from {target.label}") from exc


def _reconcile_public_capabilities(snapshot: DiagnosticsSnapshot, public_vless: dict[str, object]) -> DiagnosticsSnapshot:
    if snapshot.collector_status != "ok":
        return snapshot
    functional = public_vless.get("functional", {})
    functional_verdict = functional.get("verdict") if isinstance(functional, dict) else None
    if functional_verdict is None:
        functional_verdict = public_vless.get("verdict")
    if functional_verdict != "verified":
        return snapshot
    snapshot.reasons = [reason for reason in snapshot.reasons if reason != "external capability probe failed"]
    if snapshot.verdict == "degraded" and not snapshot.reasons:
        snapshot.verdict = "verified"
    return snapshot


def _probe_component(verdict: str, reason: str = "", *, measured: bool = True) -> dict[str, object]:
    component: dict[str, object] = {"verdict": verdict, "measured": measured}
    if reason:
        component["reason"] = reason
    return component


def _private_reject_component(private_reject: object, *, label: str) -> dict[str, object]:
    if not isinstance(private_reject, dict):
        return _probe_component("failed", f"{label} private/fake reject result is missing")
    targets = private_reject.get("targets")
    if not isinstance(targets, list) or not targets:
        return _probe_component("inconclusive", f"{label} private/fake reject has no correlated evidence")
    target_verdicts: list[str] = []
    for target in targets:
        if not isinstance(target, dict):
            return _probe_component("failed", f"{label} private/fake reject target result is malformed")
        explicit_reject = (
            target.get("evidence") == "socks-reply-reject"
            and isinstance(target.get("socks_reply_status"), int)
            and int(target["socks_reply_status"]) == 2
        )
        correlated_reject = target.get("correlated") is True and bool(str(target.get("correlation_id", "")).strip())
        if target.get("verdict") == "verified" and (explicit_reject or correlated_reject):
            target_verdicts.append("verified")
        elif target.get("verdict") == "failed":
            target_verdicts.append("failed")
        else:
            target_verdicts.append("inconclusive")
    computed = "failed" if "failed" in target_verdicts else "inconclusive" if "inconclusive" in target_verdicts else "verified"
    if private_reject.get("verdict") != computed or private_reject.get("ok") is not (computed == "verified"):
        return _probe_component("failed", f"{label} private/fake reject aggregate is inconsistent")
    if computed == "failed":
        return _probe_component("failed", f"{label} private/fake route accepted or probe failed")
    if computed == "inconclusive":
        return _probe_component("inconclusive", f"{label} private/fake reject lacks SOCKS or log correlation")
    return _probe_component("verified")


def _validate_functional_transport_result(
    result: dict[str, object],
    topology: TopologySpec,
    *,
    label: str,
    require_private_reject: bool = True,
) -> dict[str, object]:
    statuses = {str(result.get("github_status", "")), str(result.get("google_status", ""))}
    failures: list[str] = []
    inconclusive: list[str] = []
    expected_gateway_ip = topology.gateway.public_ip
    expected_routed_ip = topology.exit.public_ip if topology.exit is not None else expected_gateway_ip
    observed_gateway_ip = str(result.get("ru_egress_ip", ""))
    observed_routed_ip = str(result.get("foreign_egress_ip", ""))
    gateway_identity_ok = observed_gateway_ip == expected_gateway_ip
    routed_identity_ok = observed_routed_ip == expected_routed_ip
    if not gateway_identity_ok:
        failures.append(
            f"{label} gateway-local identity mismatch: expected {expected_gateway_ip}, got {observed_gateway_ip}"
        )
    if not routed_identity_ok:
        route_label = "exit" if topology.is_dual else "gateway-local"
        failures.append(
            f"{label} {route_label} routed identity mismatch: expected {expected_routed_ip}, got {observed_routed_ip}"
        )
    local_egress_ok = gateway_identity_ok and (routed_identity_ok if not topology.is_dual else True)
    paths: dict[str, dict[str, object]] = {
        "gateway_local_egress": {
            "state": "verified" if local_egress_ok else "failed",
            "checked": True,
            "expected_ip": expected_gateway_ip,
            "observed_ips": [
                observed_gateway_ip,
                *([observed_routed_ip] if not topology.is_dual else []),
            ],
        },
        "interserver_exit": (
            {
                "state": "verified" if routed_identity_ok else "failed",
                "checked": True,
                "expected_ip": expected_routed_ip,
                "observed_ip": observed_routed_ip,
            }
            if topology.is_dual
            else {
                "state": "not_applicable",
                "checked": False,
                "reason": "single topology has no exit or interserver path",
            }
        ),
    }
    if not statuses.issubset({"200", "204", "301", "302", "403"}):
        failures.append(f"{label} returned invalid HTTP probes")

    udp_dns = result.get("udp_dns")
    if not isinstance(udp_dns, dict) or udp_dns.get("ok") is not True:
        failures.append(f"{label} UDP DNS probe failed")
    else:
        dns = udp_dns.get("dns")
        queries = dns.get("queries") if isinstance(dns, dict) else None

        def valid_dns_query(query: object, expected_type: int) -> bool:
            if not isinstance(query, dict):
                return False
            question = query.get("question")
            return (
                query.get("verdict") == "verified"
                and query.get("qr") is True
                and query.get("rcode") == 0
                and isinstance(question, dict)
                and question.get("name") == "example.com"
                and question.get("type") == expected_type
                and question.get("class") == 1
                and isinstance(query.get("answer_count"), int)
                and int(query["answer_count"]) > 0
                and isinstance(query.get("matching_answers"), int)
                and int(query["matching_answers"]) > 0
            )

        dns_valid = (
            isinstance(dns, dict)
            and dns.get("verdict") == "verified"
            and isinstance(queries, dict)
            and valid_dns_query(dns, 1)
            and valid_dns_query(queries.get("A"), 1)
            and valid_dns_query(queries.get("AAAA"), 28)
        )
        if not dns_valid:
            failures.append(f"{label} UDP DNS A/AAAA response semantics are invalid")
        private_component = _private_reject_component(udp_dns.get("private_reject"), label=label)
        if private_component["verdict"] == "failed":
            failures.append(str(private_component.get("reason", "private/fake reject failed")))
        elif private_component["verdict"] == "inconclusive" and require_private_reject:
            inconclusive.append(str(private_component.get("reason", "private/fake reject is inconclusive")))

    if str(result.get("ipv6_literal_status", "")) != "200":
        failures.append(f"{label} IPv6 literal probe failed")
    reliability = result.get("first_load_reliability")
    if not isinstance(reliability, dict):
        failures.append(f"{label} first-load reliability result is missing")
    else:
        try:
            attempts = int(reliability.get("attempts", 0) or 0)
            successes = int(reliability.get("successes", 0) or 0)
            failure_count = int(reliability.get("failures", 0) or 0)
            max_total = float(reliability.get("max_total_seconds", 0) or 0)
        except (TypeError, ValueError):
            failures.append(f"{label} first-load reliability result is malformed")
        else:
            if attempts != RUNNER_RELIABILITY_ATTEMPTS or successes != attempts or failure_count:
                failures.append(f"{label} first-load reliability failed")
            elif max_total <= 0 or max_total > RUNNER_RELIABILITY_MAX_TOTAL_SECONDS:
                failures.append(f"{label} first-load latency exceeded {RUNNER_RELIABILITY_MAX_TOTAL_SECONDS:.1f}s")
    if failures:
        component = _probe_component("failed", "; ".join(failures))
    elif inconclusive:
        component = _probe_component("inconclusive", "; ".join(inconclusive))
    else:
        component = _probe_component("verified")
    component.update({"topology": topology.mode, "paths": paths})
    return component


def _validate_performance_result(
    result: dict[str, object],
    *,
    label: str,
    throughput_seconds: int,
    capacity_reference_bytes_per_second: int,
) -> dict[str, object]:
    if throughput_seconds == 0:
        return _probe_component("inconclusive", f"{label} performance was not measured", measured=False)
    measurement = result.get("throughput")
    if not isinstance(measurement, dict):
        return _probe_component("failed", f"{label} throughput measurement is missing")
    required_fields = {
        "sustained_bytes_per_second",
        "capacity_bytes_per_second",
        "max_gap_seconds",
        "duration_seconds",
        "failures",
        "source_failures",
        "successful_sources",
        "required_successful_sources",
        "source_metrics",
    }
    if not required_fields.issubset(measurement):
        return _probe_component("failed", f"{label} throughput measurement is incomplete")
    try:
        sustained_bps = float(measurement.get("sustained_bytes_per_second", 0) or 0)
        capacity_bps = float(measurement.get("capacity_bytes_per_second", 0) or 0)
        max_gap = float(measurement.get("max_gap_seconds", -1))
        duration = float(measurement.get("duration_seconds", 0) or 0)
        failures = int(measurement.get("failures", 0) or 0)
        source_failures = int(measurement.get("source_failures", 0) or 0)
        source_metrics = measurement.get("source_metrics")
        successful_sources = int(measurement.get("successful_sources", 0) or 0)
        required_successful_sources = int(measurement.get("required_successful_sources", 0) or 0)
    except (TypeError, ValueError):
        return _probe_component("failed", f"{label} throughput measurement is malformed")
    if (
        not isinstance(source_metrics, list)
        or not source_metrics
        or not all(isinstance(item, dict) for item in source_metrics)
        or required_successful_sources < 1
    ):
        return _probe_component("failed", f"{label} throughput source metrics are incomplete")
    try:
        computed_source_failures = sum(int(item["failures"]) for item in source_metrics if isinstance(item, dict))
        computed_successful_sources = sum(
            float(item["bytes_downloaded"]) > 0 and float(item["duration_seconds"]) > 0
            for item in source_metrics
            if isinstance(item, dict)
        )
    except (KeyError, TypeError, ValueError):
        return _probe_component("failed", f"{label} throughput source metrics are malformed")
    if computed_source_failures != source_failures or computed_successful_sources != successful_sources:
        return _probe_component("failed", f"{label} throughput source aggregates are inconsistent")
    if failures:
        return _probe_component("failed", f"{label} throughput had {failures} transfer failures")
    if successful_sources < required_successful_sources:
        return _probe_component(
            "failed",
            f"{label} throughput source coverage is insufficient: {successful_sources}/{required_successful_sources} successful",
        )
    if duration + 0.5 < throughput_seconds:
        return _probe_component("failed", f"{label} throughput window too short: {duration:.1f}s of {throughput_seconds}s")
    if sustained_bps < THROUGHPUT_SUSTAINED_FLOOR_BYTES_PER_SECOND:
        return _probe_component(
            "failed",
            f"{label} sustained goodput below 10 Mbit/s: {sustained_bps * 8 / 1_000_000:.2f} Mbit/s",
        )
    if max_gap < 0 or max_gap > THROUGHPUT_MAX_GAP_SECONDS:
        return _probe_component(
            "failed",
            f"{label} transfer stalled for {max_gap:.2f}s (limit {THROUGHPUT_MAX_GAP_SECONDS:.1f}s)",
        )
    performance = _probe_component("verified")
    performance.update(
        {
            "sustained_bytes_per_second": sustained_bps,
            "max_gap_seconds": max_gap,
            "peak_capacity_bytes_per_second": capacity_bps,
            "peak_capacity_reference_bytes_per_second": capacity_reference_bytes_per_second,
            "peak_capacity_reference_met": capacity_bps >= capacity_reference_bytes_per_second,
        }
    )
    if capacity_bps < capacity_reference_bytes_per_second:
        performance["observation"] = (
            f"{label} peak capacity {capacity_bps * 8 / 1_000_000:.2f} Mbit/s is below "
            f"the {capacity_reference_bytes_per_second * 8 / 1_000_000:.2f} Mbit/s reference"
        )
    return performance


def _validate_public_transport_result(
    result: dict[str, object],
    topology: TopologySpec,
    *,
    label: str,
    throughput_seconds: int = 0,
    capacity_reference_bytes_per_second: int = PRIMARY_CAPACITY_REFERENCE_BYTES_PER_SECOND,
    require_private_reject: bool = True,
) -> dict[str, object]:
    functional = _validate_functional_transport_result(
        result,
        topology,
        label=label,
        require_private_reject=require_private_reject,
    )
    performance = _validate_performance_result(
        result,
        label=label,
        throughput_seconds=throughput_seconds,
        capacity_reference_bytes_per_second=capacity_reference_bytes_per_second,
    )
    component_verdicts = {str(functional["verdict"])}
    if performance.get("measured") is not False:
        component_verdicts.add(str(performance["verdict"]))
    verdict = "failed" if "failed" in component_verdicts else "inconclusive" if "inconclusive" in component_verdicts else "verified"
    reasons = [str(component["reason"]) for component in (functional, performance) if component.get("reason")]
    response: dict[str, object] = {
        "verdict": verdict,
        "topology": topology.mode,
        "paths": dict(functional.get("paths", {})),
        "functional": functional,
        "performance": performance,
        "result": result,
    }
    if reasons:
        response["reason"] = "; ".join(reasons)
    return response


def _validate_public_vless_result(
    result: dict[str, object],
    uri,
    topology: TopologySpec,
    *,
    throughput_seconds: int = 0,
    require_private_reject: bool = True,
) -> dict[str, object]:
    response = _validate_public_transport_result(
        result,
        topology,
        label="public VLESS",
        throughput_seconds=throughput_seconds,
        require_private_reject=require_private_reject,
    )
    if uri.host != topology.gateway.public_ip:
        reason = (
            f"public VLESS gateway mismatch: expected {topology.gateway.public_ip}, got {uri.host}"
        )
        response["verdict"] = "failed"
        response["reason"] = "; ".join(
            value for value in (str(response.get("reason", "")), reason) if value
        )
    return response


def _annotate_public_vless_evidence(
    topology: TopologySpec,
    payload: dict[str, object],
) -> dict[str, object]:
    verdict = str(payload.get("verdict", "inconclusive"))
    raw_paths = payload.get("paths")
    paths = dict(raw_paths) if isinstance(raw_paths, dict) else {}
    correlation = payload.get("front_correlation")
    functional = payload.get("functional")
    functional_paths = functional.get("paths") if isinstance(functional, dict) else None
    gateway_evidence = (
        functional_paths.get("gateway_local_egress")
        if isinstance(functional_paths, dict)
        else None
    )
    interserver_evidence = (
        functional_paths.get("interserver_exit")
        if isinstance(functional_paths, dict)
        else None
    )
    complete_path_evidence = (
        isinstance(correlation, dict)
        and isinstance(gateway_evidence, dict)
        and gateway_evidence.get("checked") is True
        and isinstance(interserver_evidence, dict)
        and (
            interserver_evidence.get("checked") is True
            if topology.is_dual
            else interserver_evidence.get("state") == "not_applicable"
        )
    )
    if verdict == "verified" and not complete_path_evidence:
        verdict = "inconclusive"
        payload["verdict"] = verdict
        missing_reason = "required VLESS/Xray/egress evidence is incomplete"
        payload["reason"] = "; ".join(
            value for value in (str(payload.get("reason", "")), missing_reason) if value
        )
    front_state = str(correlation.get("verdict", verdict)) if isinstance(correlation, dict) else verdict
    paths.setdefault(
        "gateway_local_egress",
        {
            "state": verdict,
            "checked": False,
            "reason": "public VLESS probe did not produce validated egress evidence",
        },
    )
    paths.setdefault(
        "interserver_exit",
        (
            {
                "state": verdict,
                "checked": False,
                "reason": "public VLESS probe did not produce validated exit evidence",
            }
            if topology.is_dual
            else {
                "state": "not_applicable",
                "checked": False,
                "reason": "single topology has no exit or interserver path",
            }
        ),
    )
    paths["gateway_public_front"] = {
        "state": front_state,
        "checked": isinstance(correlation, dict),
        "chain": ["gateway-public-vless", "xray", "local-router"],
    }
    runner_scope = "independent-node" if topology.is_dual else "same-node"
    chain = ["probe-runner", "gateway-public-vless", "xray", "local-router"]
    chain.extend(["interserver", "exit-egress"] if topology.is_dual else ["gateway-local-egress"])
    paths["public_vless"] = {
        "state": verdict,
        "checked": complete_path_evidence,
        "required": True,
        "runner_node": NODE_EXIT if topology.is_dual else NODE_GATEWAY,
        "runner_scope": runner_scope,
        "external_ingress_observed": topology.is_dual and complete_path_evidence,
        "chain": chain,
    }
    payload.update({"topology": topology.mode, "paths": paths})
    return payload


def _public_vless_failure(topology: TopologySpec, verdict: str, reason: str) -> dict[str, object]:
    return _annotate_public_vless_evidence(
        topology,
        {"verdict": verdict, "reason": reason},
    )


def _not_applicable_profile(topology: TopologySpec, profile: str, reason: str) -> dict[str, object]:
    return {
        "verdict": "not_applicable",
        "topology": topology.mode,
        "reason": reason,
        "paths": {
            profile: {
                "state": "not_applicable",
                "checked": False,
                "required": False,
                "reason": reason,
            }
        },
    }


def _vless_runner_timeout(throughput_seconds: int) -> int:
    """Return the runner's explicit network/process upper bound plus SSH drain."""

    return (
        RUNNER_STARTUP_SECONDS
        + RUNNER_HTTP_PROBE_COUNT * RUNNER_HTTP_TIMEOUT_SECONDS
        + RUNNER_RELIABILITY_ATTEMPTS * RUNNER_RELIABILITY_TIMEOUT_SECONDS
        + RUNNER_ROUTE_PROBE_TIMEOUT_SECONDS
        + throughput_seconds
        + RUNNER_THROUGHPUT_CLOCK_SKEW_SECONDS
        + (RUNNER_CURL_WATCHDOG_KILL_SECONDS if throughput_seconds else 0)
        + RUNNER_SHUTDOWN_SECONDS
        + RUNNER_REPORT_SECONDS
        + RUNNER_TRANSPORT_DRAIN_SECONDS
    )


def _start_vless_runner(
    target,
    remote_runner: str,
    remote_config: str,
    remote_udp_probe: str,
    *,
    throughput_seconds: int,
    result_path: str,
    error_path: str,
    lease_path: str,
) -> str:
    runtime_limit = _vless_runner_timeout(throughput_seconds)
    command = (
        f"touch {shlex.quote(lease_path)}; "
        f"setsid timeout --foreground --signal=TERM --kill-after={RUNNER_CURL_WATCHDOG_KILL_SECONDS}s {runtime_limit}s "
        f"bash {shlex.quote(remote_runner)} {shlex.quote(remote_config)} {shlex.quote(remote_udp_probe)} {throughput_seconds} "
        f"{shlex.quote(lease_path)} {shlex.quote(VLESS_RUNNER_LOCK_PATH)} "
        f"> {shlex.quote(result_path)} 2> {shlex.quote(error_path)} < /dev/null & printf '%s\\n' \"$!\""
    )
    pid = ssh_capture(target, command, command_timeout=20).strip()
    if not pid.isdecimal():
        raise RuntimeError(f"VLESS probe runner did not return a PID: {pid!r}")
    return pid


def _vless_runner_state_command(pid: str, result_path: str, error_path: str, lease_path: str) -> str:
    return (
        f"if kill -0 {shlex.quote(pid)} 2>/dev/null; then touch {shlex.quote(lease_path)}; printf '%s\\n' running; "
        f"elif test -s {shlex.quote(result_path)}; then printf '%s\\n' completed; cat {shlex.quote(result_path)}; "
        f"else printf '%s\\n' exited; tail -n 40 {shlex.quote(error_path)} 2>/dev/null || true; fi"
    )


def _stop_vless_runner(target, pid: str, error_path: str) -> str:
    command = (
        f"if kill -0 {shlex.quote(pid)} 2>/dev/null; then "
        f"kill -TERM -- -{shlex.quote(pid)} 2>/dev/null || kill -TERM {shlex.quote(pid)} 2>/dev/null || true; "
        f"sleep 2; kill -KILL -- -{shlex.quote(pid)} 2>/dev/null || kill -KILL {shlex.quote(pid)} 2>/dev/null || true; fi; "
        f"tail -n 40 {shlex.quote(error_path)} 2>/dev/null || true"
    )
    try:
        return ssh_capture(target, command, command_timeout=15).strip()
    except Exception:  # noqa: BLE001
        return ""


def _wait_for_vless_runner(
    target,
    pid: str,
    result_path: str,
    error_path: str,
    lease_path: str,
    *,
    throughput_seconds: int,
) -> dict[str, object]:
    deadline = time.monotonic() + _vless_runner_timeout(throughput_seconds)
    while True:
        response = ssh_capture(target, _vless_runner_state_command(pid, result_path, error_path, lease_path), command_timeout=20)
        state, separator, payload = response.partition("\n")
        if state == "completed":
            if not separator:
                raise RuntimeError("VLESS probe runner completed without a result payload")
            return json.loads(payload)
        if state == "exited":
            detail = payload.strip()
            raise RuntimeError(f"VLESS probe runner exited before result{f': {detail}' if detail else ''}")
        if state != "running":
            raise RuntimeError(f"VLESS probe runner returned an invalid state: {state!r}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            detail = _stop_vless_runner(target, pid, error_path)
            raise RuntimeError(f"VLESS probe runner exceeded its {_vless_runner_timeout(throughput_seconds)}s budget{f': {detail}' if detail else ''}")
        time.sleep(min(VLESS_RUNNER_POLL_INTERVAL_SECONDS, remaining))


def _run_public_profile(
    config_text: str,
    foreign_target,
    *,
    label: str,
    throughput_seconds: int = 0,
    on_running: Callable[[], dict[str, object]] | None = None,
) -> dict[str, object]:
    if throughput_seconds < 0 or 0 < throughput_seconds < 30:
        return {"verdict": "failed", "reason": "throughput-seconds must be 0 or at least 30"}
    try:
        remote_dir = ssh_capture(
            foreign_target,
            "find /tmp -maxdepth 1 -type d -name 'vpn-stack-vless-verify.*' -mmin +60 -exec rm -rf -- {} +; "
            "mktemp -d /tmp/vpn-stack-vless-verify.XXXXXX",
            command_timeout=15,
        ).strip()
    except Exception as exc:  # noqa: BLE001
        return {"verdict": "failed", "reason": f"could not start {label} runner: {exc}"}
    if not remote_dir.startswith("/tmp/"):
        return {"verdict": "failed", "reason": f"could not allocate {label} runner"}
    listen_port = 18080
    with tempfile.TemporaryDirectory(prefix="vpn-stack-public-") as temp_dir:
        local_config = Path(temp_dir) / "sing-box.json"
        local_udp_probe = Path(temp_dir) / "udp-probe.py"
        local_runner = Path(temp_dir) / "runner.sh"
        local_config.write_text(config_text, encoding="utf-8")
        local_udp_probe.write_text(
            render_live_route_probe(listen_port=listen_port, dns_listen_port=listen_port + 1),
            encoding="utf-8",
        )
        # Bash must retain LF on a Windows control host; write bytes deliberately.
        local_runner.write_bytes(render_vless_runner(listen_port=listen_port).encode("utf-8"))
        remote_config = f"{remote_dir}/sing-box.json"
        remote_udp_probe = f"{remote_dir}/udp-probe.py"
        remote_runner = f"{remote_dir}/runner.sh"
        remote_result = f"{remote_dir}/result.json"
        remote_error = f"{remote_dir}/runner.stderr"
        remote_lease = f"{remote_dir}/controller.lease"
        runner_pid = ""
        runner_completed = False
        try:
            scp_upload(foreign_target, local_config, remote_config)
            scp_upload(foreign_target, local_udp_probe, remote_udp_probe)
            scp_upload(foreign_target, local_runner, remote_runner)
            runner_pid = _start_vless_runner(
                foreign_target,
                remote_runner,
                remote_config,
                remote_udp_probe,
                throughput_seconds=throughput_seconds,
                result_path=remote_result,
                error_path=remote_error,
                lease_path=remote_lease,
            )
            running_observations: list[dict[str, object]] = []
            if on_running is not None:
                for _sample in range(3):
                    time.sleep(1)
                    running_observations.append(on_running())
            result = _wait_for_vless_runner(
                foreign_target,
                runner_pid,
                remote_result,
                remote_error,
                remote_lease,
                throughput_seconds=throughput_seconds,
            )
            if running_observations:
                result["running_observations"] = running_observations
            try:
                result["runner_log"] = ssh_capture(
                    foreign_target,
                    f"tail -n 200 {shlex.quote(remote_error)} 2>/dev/null || true",
                    command_timeout=15,
                )
            except Exception:  # noqa: BLE001
                result["runner_log"] = "unavailable"
            runner_completed = True
        except (ValueError, OSError, RuntimeError) as exc:
            return {"verdict": "failed", "reason": f"{label} path failed: {exc}"}
        finally:
            if runner_pid and not runner_completed:
                _stop_vless_runner(foreign_target, runner_pid, remote_error)
            try:
                ssh_capture(foreign_target, f"rm -rf {shlex.quote(remote_dir)}", command_timeout=15)
            except Exception:  # noqa: BLE001
                pass
    return {"verdict": "completed", "result": result}


def _capture_private_reject_marker(target) -> str:
    try:
        return ssh_capture(target, "date -u +%Y-%m-%dT%H:%M:%S.%6NZ", command_timeout=10).strip()
    except Exception:  # noqa: BLE001
        return ""


def _apply_private_reject_correlation(result: dict[str, object], correlation: dict[str, object]) -> dict[str, object]:
    udp_dns = result.get("udp_dns")
    private_reject = udp_dns.get("private_reject") if isinstance(udp_dns, dict) else None
    targets = private_reject.get("targets") if isinstance(private_reject, dict) else None
    correlation_targets = correlation.get("targets")
    if not isinstance(udp_dns, dict) or not isinstance(private_reject, dict) or not isinstance(targets, list):
        return result
    policy = correlation.get("policy")
    correlation_verified = (
        correlation.get("verdict") == "verified"
        and isinstance(policy, dict)
        and policy.get("verified") is True
        and policy.get("drift") == "none"
        and bool(str(policy.get("config_sha256", "")).strip())
    )
    correlated_by_target = {
        str(item.get("target", "")): item
        for item in correlation_targets
        if isinstance(item, dict)
        and item.get("correlated") is True
        and bool(str(item.get("correlation_id", "")).strip())
    } if isinstance(correlation_targets, list) and correlation_verified else {}
    merged_targets: list[object] = []
    for raw_target in targets:
        if not isinstance(raw_target, dict):
            merged_targets.append(raw_target)
            continue
        target = dict(raw_target)
        evidence = correlated_by_target.get(str(target.get("target", "")))
        if (
            evidence
            and target.get("verdict") == "inconclusive"
            and target.get("evidence") == "socks-success-eof"
            and target.get("correlation_required") is True
        ):
            target.update(
                {
                    "verdict": "verified",
                    "ok": True,
                    "correlated": True,
                    "correlation_required": False,
                    "correlation_id": evidence["correlation_id"],
                    "event_id": evidence.get("event_id", ""),
                }
            )
        merged_targets.append(target)
    target_verdicts = [
        str(target.get("verdict", "inconclusive"))
        for target in merged_targets
        if isinstance(target, dict)
    ]
    aggregate = (
        "failed"
        if "failed" in target_verdicts
        else "inconclusive"
        if any(verdict != "verified" for verdict in target_verdicts)
        else "verified"
    )
    merged_private = {
        **private_reject,
        "verdict": aggregate,
        "ok": aggregate == "verified",
        "targets": merged_targets,
        "correlation": correlation,
    }
    return {**result, "udp_dns": {**udp_dns, "private_reject": merged_private}}


def _correlate_private_reject(target, result: dict[str, object], *, since: str, inbound: str) -> dict[str, object]:
    udp_dns = result.get("udp_dns")
    private_reject = udp_dns.get("private_reject") if isinstance(udp_dns, dict) else None
    raw_targets = private_reject.get("targets") if isinstance(private_reject, dict) else None
    targets = [
        str(item.get("target", ""))
        for item in raw_targets
        if isinstance(item, dict)
        and item.get("verdict") == "inconclusive"
        and item.get("evidence") == "socks-success-eof"
        and item.get("correlation_required") is True
        and str(item.get("target", "")).strip()
    ] if isinstance(raw_targets, list) else []
    if not targets:
        return result
    if not since:
        return _apply_private_reject_correlation(
            result,
            {"verdict": "failed", "reason": "RU correlation marker is unavailable", "targets": []},
        )
    command = (
        "python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py private-reject-correlate "
        f"--since {shlex.quote(since)} --inbound {shlex.quote(inbound)} "
        + " ".join(f"--target {shlex.quote(item)}" for item in targets)
    )
    try:
        payload = ssh_capture(target, command, as_root=True, command_timeout=30)
        correlation = json.loads(payload)
        if not isinstance(correlation, dict):
            raise ValueError("correlation payload is not an object")
    except Exception as exc:  # noqa: BLE001
        correlation = {"verdict": "failed", "reason": str(exc)[:240], "targets": []}
    return _apply_private_reject_correlation(result, correlation)


def _verify_public_vless_uri(
    uri_path: Path,
    env: dict[str, str],
    runner_target,
    *,
    throughput_seconds: int = 0,
    on_running: Callable[[], dict[str, object]] | None = None,
    reject_target=None,
    require_private_reject: bool = True,
) -> dict[str, object]:
    try:
        topology = TopologySpec.from_env(env)
    except ValueError as exc:
        return {
            "verdict": "failed",
            "topology": str(env.get("TOPOLOGY", "") or "invalid"),
            "reason": f"canonical topology is invalid: {exc}",
            "paths": {
                "public_vless": {
                    "state": "failed",
                    "checked": False,
                    "required": True,
                }
            },
        }
    if not uri_path.is_file():
        return _public_vless_failure(topology, "failed", f"primary VLESS URI is missing: {uri_path}")
    try:
        raw_uri = uri_path.read_bytes()
        expected_uri = render_vless_uri(env).encode("utf-8")
        if raw_uri != expected_uri:
            return _public_vless_failure(
                topology,
                "failed",
                "primary VLESS URI differs from the canonical deployment contract",
            )
        uri = parse_vless_uri(raw_uri.decode("utf-8").strip())
    except (OSError, ValueError) as exc:
        return _public_vless_failure(topology, "failed", f"primary VLESS URI is invalid: {exc}")
    reject_marker = _capture_private_reject_marker(reject_target) if reject_target is not None else ""
    run_result = _run_public_profile(
        render_ephemeral_singbox_client(uri, listen_port=18080),
        runner_target,
        label="public VLESS",
        throughput_seconds=throughput_seconds,
        on_running=on_running,
    )
    if run_result.get("verdict") != "completed":
        return _annotate_public_vless_evidence(topology, run_result)
    if reject_target is not None:
        run_result["result"] = _correlate_private_reject(
            reject_target,
            run_result["result"],
            since=reject_marker,
            inbound="router-in",
        )
    validated = _validate_public_vless_result(
        run_result["result"],
        uri,
        topology,
        throughput_seconds=throughput_seconds,
        require_private_reject=require_private_reject,
    )
    correlation = _validate_front_correlation(run_result["result"].get("running_observations"))
    validated["front_correlation"] = correlation
    if correlation["verdict"] != "verified":
        current = str(validated.get("verdict", "failed"))
        if correlation["verdict"] == "failed" or current == "failed":
            validated["verdict"] = "failed"
        elif correlation["verdict"] == "degraded" or current == "degraded":
            validated["verdict"] = "degraded"
        else:
            validated["verdict"] = "inconclusive"
    return _annotate_public_vless_evidence(topology, validated)


def _capture_client_front(target, source: str) -> dict[str, object]:
    try:
        payload = ssh_capture(
            target,
            f"python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py client --source {shlex.quote(source)} --since 5",
            command_timeout=20,
        )
        parsed = json.loads(payload)
        return parsed if isinstance(parsed, dict) else {"error": "client-front payload is not an object"}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:240]}


def _validate_front_correlation(observation: object) -> dict[str, object]:
    if isinstance(observation, dict):
        observations = [observation]
    elif isinstance(observation, list) and observation:
        observations = observation
    else:
        return _probe_component("inconclusive", "public VLESS front was not observed while the runner was active")
    best: tuple[int, dict[str, object]] | None = None
    errors: list[str] = []
    for item in observations:
        if not isinstance(item, dict):
            continue
        baseline = item.get("baseline")
        during = item.get("during")
        if not isinstance(baseline, dict) or not isinstance(during, dict):
            continue
        if baseline.get("error") or during.get("error"):
            errors.append(str(during.get("error") or baseline.get("error")))
            continue
        baseline_events = baseline.get("events", {})
        during_events = during.get("events", {})
        try:
            accepted_delta = int(during_events.get("accepted_tcp", 0)) - int(baseline_events.get("accepted_tcp", 0))
        except (AttributeError, TypeError, ValueError):
            return _probe_component("failed", "public VLESS front correlation counters are malformed")
        flows = during.get("front", {}).get("flows", {}) if isinstance(during.get("front"), dict) else {}
        if not isinstance(flows, dict):
            flows = {}
        candidate = (accepted_delta, flows)
        if best is None or (accepted_delta, len(flows)) > (best[0], len(best[1])):
            best = candidate
    if best is None:
        detail = f": {errors[-1]}" if errors else ""
        return _probe_component("inconclusive", f"public VLESS front correlation snapshots are incomplete{detail}")
    accepted_delta, flows = best
    if accepted_delta < 1:
        return _probe_component("inconclusive", "public VLESS runner produced no correlated Xray TCP accept event")
    qualities = {str(metrics.get("quality", "")) for metrics in flows.values() if isinstance(metrics, dict)}
    verdict = "degraded" if "degraded" in qualities else "verified"
    result = _probe_component(verdict)
    result.update({"accepted_delta": accepted_delta, "flow_count": len(flows), "qualities": sorted(qualities)})
    return result


def _verify_public_hysteria2(env: dict[str, str], runner_target, *, throughput_seconds: int = 0, reject_target=None) -> dict[str, object]:
    topology = TopologySpec.from_env(env)
    if not topology.is_dual:
        return _not_applicable_profile(
            topology,
            "public_hysteria2",
            "single topology release acceptance is defined by the primary public VLESS path",
        )
    payload = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {"type": "mixed", "listen": "127.0.0.1", "listen_port": 18080, "tag": "verify-in"},
            {
                "type": "direct",
                "tag": "verify-dns-in",
                "listen": "127.0.0.1",
                "listen_port": 18081,
                "network": "udp",
                "override_address": "1.1.1.1",
                "override_port": 53,
            },
        ],
        "outbounds": [render_public_hy2_outbound(env)],
        "route": {"final": PUBLIC_HY2_OUTBOUND_TAG},
    }
    reject_marker = _capture_private_reject_marker(reject_target) if reject_target is not None else ""
    run_result = _run_public_profile(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        runner_target,
        label="public Hysteria2",
        throughput_seconds=throughput_seconds,
    )
    if run_result.get("verdict") != "completed":
        return run_result
    if reject_target is not None:
        run_result["result"] = _correlate_private_reject(
            reject_target,
            run_result["result"],
            since=reject_marker,
            inbound="public-hy2-in",
        )
    return _validate_public_transport_result(
        run_result["result"],
        topology,
        label="public Hysteria2",
        throughput_seconds=throughput_seconds,
        capacity_reference_bytes_per_second=FALLBACK_CAPACITY_REFERENCE_BYTES_PER_SECOND,
    )


def _verification_path_evidence(
    topology: TopologySpec,
    public_vless: dict[str, object],
    snapshots: list[DiagnosticsSnapshot],
    *,
    require_native_agent: bool,
) -> dict[str, object]:
    raw_paths = public_vless.get("paths")
    paths: dict[str, object] = dict(raw_paths) if isinstance(raw_paths, dict) else {}
    snapshots_by_node = {snapshot.node_id: snapshot for snapshot in snapshots if snapshot.node_id}
    for node in topology.nodes:
        snapshot = snapshots_by_node.get(node.node_id)
        key = f"{node.node_id}_agent_acceptance"
        if not require_native_agent:
            paths[key] = {
                "state": "not_applicable",
                "checked": False,
                "reason": "rollback scope requires only external public VLESS evidence",
            }
        elif snapshot is None:
            paths[key] = {
                "state": "failed",
                "checked": False,
                "reason": "required native agent evidence is missing",
            }
        else:
            paths[key] = {
                "state": snapshot.verdict,
                "checked": True,
                "topology": snapshot.topology,
                "capabilities": list(snapshot.capabilities),
            }
    if topology.exit is None:
        paths["exit_agent_acceptance"] = {
            "state": "not_applicable",
            "checked": False,
            "reason": "single topology has no exit node",
        }
    return paths


def verify_live_workflow(
    deployment: str | None,
    *,
    non_interactive: bool = False,
    throughput_seconds: int = 30,
    require_native_agent: bool = True,
    accept_same_node_for_install: bool = False,
) -> int:
    print_header("Live verification")
    deployment_name, env_path, env, _state, targets, _preflights_by_node = workflows.prepare_remote_session(
        deployment,
        nodes=None,
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
        run_live_probes=False,
    )
    topology = TopologySpec.from_env(env)
    workflows.print_summary(deployment_name, env, targets)
    worst = "verified"
    rank = {"verified": 0, "degraded": 1, "inconclusive": 2, "failed": 3}
    targets_by_node = {target.node_id: target for target in targets}
    gateway_target = targets_by_node.get(NODE_GATEWAY)
    runner_node = NODE_EXIT if topology.is_dual else NODE_GATEWAY
    runner_target = targets_by_node.get(runner_node)
    public_vless = _public_vless_failure(
        topology,
        "inconclusive",
        f"VLESS probe runner node {runner_node} is unavailable",
    )
    public_hysteria2 = (
        {"verdict": "inconclusive", "topology": topology.mode, "reason": "exit verifier is unavailable"}
        if topology.is_dual
        else _not_applicable_profile(
            topology,
            "public_hysteria2",
            "single topology release acceptance is defined by the primary public VLESS path",
        )
    )
    if runner_target is not None and gateway_target is not None:
        runner_spec = topology.node(runner_node)
        verifier_source = runner_spec.public_ip or runner_target.public_ip or runner_target.ssh_host
        if not verifier_source:
            baseline_front = {"error": "external verifier source address is unavailable"}
        else:
            baseline_front = _capture_client_front(gateway_target, verifier_source)
        public_vless = _verify_public_vless_uri(
            OUT_DIR / deployment_name / "client" / "vless-uri.txt",
            env,
            runner_target,
            throughput_seconds=throughput_seconds,
            on_running=lambda: {
                "baseline": baseline_front,
                "during": _capture_client_front(gateway_target, verifier_source)
                if verifier_source
                else {"error": "gateway target or verifier source is unavailable"},
            },
            reject_target=gateway_target if require_native_agent else None,
            require_private_reject=require_native_agent,
        )
        if require_native_agent and topology.is_dual:
            public_hysteria2 = _verify_public_hysteria2(
                env,
                runner_target,
                throughput_seconds=0,
                reject_target=gateway_target,
            )
    public_vless = _annotate_public_vless_evidence(topology, public_vless)
    same_node_functional = public_vless.get("functional", {})
    same_node_functional_verified = (
        not topology.is_dual
        and isinstance(same_node_functional, dict)
        and same_node_functional.get("verdict") == "verified"
        and public_vless.get("verdict") == "verified"
    )
    if same_node_functional_verified:
        public_vless["verdict"] = "inconclusive"
        public_vless["reason"] = (
            "same-node VLESS path passed, but no independent runner observed the public gateway ingress"
        )
        public_path = public_vless.get("paths", {}).get("public_vless", {})
        if isinstance(public_path, dict):
            public_path["state"] = "inconclusive"
    snapshots: list[DiagnosticsSnapshot] = []
    if require_native_agent:
        for target in targets:
            plan = topology.plan(target.node_id)
            try:
                snapshot = _collect_agent_snapshot(target)
                snapshot.deployment = deployment_name
                snapshot = _verify_snapshot(snapshot, expected_plan=plan)
            except Exception as exc:  # noqa: BLE001
                snapshot = DiagnosticsSnapshot(
                    deployment=deployment_name,
                    topology=plan.topology,
                    node_id=plan.node_id,
                    location=plan.location,
                    capabilities=tuple(plan.capabilities),
                    verdict="failed",
                    reasons=[f"agent snapshot failed: {exc}"],
                )
            snapshots.append(snapshot)
        snapshots = [_reconcile_public_capabilities(snapshot, public_vless) for snapshot in snapshots]
    verdicts = [str(public_vless["verdict"])]
    if require_native_agent:
        verdicts = [*(snapshot.verdict for snapshot in snapshots), *verdicts]
    for verdict in verdicts:
        if verdict not in rank:
            worst = "failed"
        elif rank[verdict] > rank[worst]:
            worst = verdict
    same_node_install_accepted = bool(
        accept_same_node_for_install
        and same_node_functional_verified
        and require_native_agent
        and snapshots
        and all(snapshot.verdict == "verified" for snapshot in snapshots)
    )
    if (
        require_native_agent
        and topology.is_dual
        and public_hysteria2.get("verdict") != "verified"
        and rank[worst] < rank["degraded"]
    ):
        worst = "degraded"
    paths = _verification_path_evidence(
        topology,
        public_vless,
        snapshots,
        require_native_agent=require_native_agent,
    )
    report_dir = OUT_DIR / "diagnostics" / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{deployment_name}"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "live-verify.json"
    report_path.write_text(
        json.dumps(
            {
                "deployment": deployment_name,
                "topology": topology.mode,
                "nodes": [
                    {
                        "node_id": node.node_id,
                        "location": node.location,
                        "capabilities": sorted(topology.plan(node.node_id).capabilities),
                    }
                    for node in topology.nodes
                ],
                "verdict": worst,
                "paths": paths,
                "throughput_seconds": throughput_seconds,
                "verification_scope": "release" if require_native_agent else "rollback-public-vless",
                "runner_scope": "independent-node" if topology.is_dual else "same-node",
                "same_node_install_accepted": same_node_install_accepted,
                "public_vless": public_vless,
                "public_hysteria2": public_hysteria2,
                "snapshots": [snapshot.to_dict() for snapshot in snapshots],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print_header("Live verification result")
    print(f"topology: {topology.mode}")
    print(f"verification scope: {'release' if require_native_agent else 'rollback-public-vless'}")
    print(f"verify verdict: {worst}")
    for snapshot in snapshots:
        reason_text = "; ".join(snapshot.reasons) if snapshot.reasons else "fresh probes and installed manifest are consistent"
        print(f"{snapshot.node_id or 'unknown'}: {snapshot.verdict} - {reason_text}")
    for path_name, evidence in paths.items():
        if isinstance(evidence, dict):
            print(f"path {path_name}: {evidence.get('state', 'inconclusive')}")
    profiles = [("public-vless-uri", public_vless)]
    if require_native_agent:
        profiles.append(("public-hysteria2", public_hysteria2))
    for profile_name, profile in profiles:
        print(f"{profile_name}: {profile['verdict']} - {profile.get('reason', profile.get('result', ''))}")
        for component_name in ("functional", "performance"):
            component = profile.get(component_name)
            if isinstance(component, dict):
                print(f"{profile_name}-{component_name}: {component['verdict']} - {component.get('reason', 'passed')}")
    print(f"report: {report_path}")
    print(f"Deployment env: {Path(env_path)}")
    return 0 if worst == "verified" or same_node_install_accepted else 1
