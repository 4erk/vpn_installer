from __future__ import annotations

import ipaddress
import re
import time
from pathlib import Path
from typing import Any, Callable, Mapping

if __package__:
    from . import diagnostics
    from . import server_runtime as runtime
    from .network_profile import FQ_FLOW_LIMIT, FQ_KIND, FQ_PACKET_LIMIT, TCP_MTU_PROBE_FLOOR, wireguard_policy_spec
else:
    import diagnostics
    import server_runtime as runtime
    from network_profile import FQ_FLOW_LIMIT, FQ_KIND, FQ_PACKET_LIMIT, TCP_MTU_PROBE_FLOOR, wireguard_policy_spec


FRONT_RTO_DEGRADED_MS = 1_000
FRONT_COUNTER_MAX_INTERVAL_SECONDS = 300
HEALTH_CONFIRMATION_MAX_GAP_SECONDS = 300
FRONT_CACHE_REORDERING_THRESHOLD = 64
FRONT_CACHE_STALLED_RTO_MS = 8_000
FRONT_CACHE_RECOVERY_COOLDOWN_SECONDS = 1_800
FRONT_CACHE_RECOVERY_MAX_ACTIONS = 2
FRONT_CACHE_RECOVERY_HISTORY_LIMIT = 20


def apply_wireguard_policy(env: Mapping[str, str]) -> dict[str, Any]:
    spec = wireguard_policy_spec(env)
    before = runtime.wireguard_policy_snapshot(env, managed=True)
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
        result = runtime.run(command, timeout=10)
        if result.returncode != 0:
            raise RuntimeError(f"unable to apply WireGuard policy {name}: {result.stderr.strip()[:240]}")
    after = runtime.wireguard_policy_snapshot(env, managed=True)
    if not after.get("ok"):
        raise RuntimeError(f"WireGuard policy did not converge: {','.join(after.get('missing', []))}")
    return {**after, "changed": bool(before.get("missing"))}


def apply_interface_qdisc(interface: str) -> dict[str, Any]:
    before = runtime.qdisc_snapshot(interface)
    expected = {"qdisc": FQ_KIND, "qdisc_limit": FQ_PACKET_LIMIT, "qdisc_flow_limit": FQ_FLOW_LIMIT}
    if all(before.get(name) == value for name, value in expected.items()):
        return {"changed": False, **before}
    result = runtime.run(
        ["tc", "qdisc", "replace", "dev", interface, "root", FQ_KIND, "limit", str(FQ_PACKET_LIMIT), "flow_limit", str(FQ_FLOW_LIMIT)],
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"unable to apply managed qdisc profile: {result.stderr.strip()[:240]}")
    after = runtime.qdisc_snapshot(interface)
    mismatches = [name for name, value in expected.items() if after.get(name) != value]
    if mismatches:
        raise RuntimeError(f"managed qdisc profile did not converge: {','.join(mismatches)}")
    return {"changed": True, **after}


def apply_qdisc_profile(*, include_overlay: bool = True) -> dict[str, Any]:
    interface = runtime.default_interface()
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
    overlay_interface = runtime.parse_env().get("WG_INTERFACE", "").strip() or "wg0"
    if overlay_interface == interface:
        overlay = public
    elif (Path("/sys/class/net") / overlay_interface).exists():
        overlay = apply_interface_qdisc(overlay_interface)
    else:
        overlay = {"changed": False, **runtime.qdisc_snapshot("")}
    result.update(
        {
            "changed": public["changed"] or overlay["changed"],
            "overlay_interface": overlay_interface,
            **{f"overlay_{name}": value for name, value in overlay.items() if name != "changed"},
        }
    )
    return result


def apply_network_profile(contract: Mapping[str, Any]) -> dict[str, Any]:
    env = runtime.parse_env()
    has_interserver = bool(contract.get("capabilities", frozenset()) & runtime.INTERSERVER_CAPABILITIES)
    qdisc = apply_qdisc_profile(include_overlay=has_interserver)
    if runtime.contract_has(contract, runtime.CAP_INTERSERVER_CLIENT):
        policy = apply_wireguard_policy(env)
    else:
        policy = {"managed": False, "ok": True, "not_applicable": True}
    return {
        "changed": bool(qdisc.get("changed") or policy.get("changed")),
        "qdisc": qdisc,
        "wireguard_policy": policy,
    }


def parse_tcp_destination_metrics(source: str, output: str) -> dict[str, Any]:
    line = next((raw.strip() for raw in output.splitlines() if raw.strip()), "")
    metrics: dict[str, Any] = {"source": source, "cached": bool(line)}
    if match := re.search(r"\breordering\s+(\d+)", line):
        metrics["reordering"] = int(match.group(1))
    return metrics


def tcp_destination_metrics(source: str) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return {"source": source, "available": False, "error": "invalid source address"}
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        return {"source": str(address), "available": False, "error": "source address is not recoverable"}
    canonical = str(address)
    result = runtime.run(["ip", "tcp_metrics", "show", canonical], timeout=5)
    if result.returncode != 0:
        detail = " ".join((result.stderr.strip() or result.stdout.strip() or "ip tcp_metrics failed").split())
        return {"source": canonical, "available": False, "error": detail[:160]}
    return {"available": True, **parse_tcp_destination_metrics(canonical, result.stdout)}


def front_source_stall(front: Mapping[str, Any], source: str) -> dict[str, Any]:
    max_rto_ms = 0
    min_mss: int | None = None
    active_flows = 0
    stalled = False
    for metrics in front.get("flows", {}).values():
        if not isinstance(metrics, Mapping) or metrics.get("source") != source or metrics.get("phase") != "active":
            continue
        active_flows += 1
        rto = metrics.get("rto_ms", {})
        flow_rto_ms = int(rto.get("max", 0) or 0) if isinstance(rto, Mapping) else 0
        max_rto_ms = max(max_rto_ms, flow_rto_ms)
        raw_mss = metrics.get("mss")
        if isinstance(raw_mss, int):
            min_mss = raw_mss if min_mss is None else min(min_mss, raw_mss)
        floor_collapse = isinstance(raw_mss, int) and raw_mss <= TCP_MTU_PROBE_FLOOR
        stalled |= flow_rto_ms >= FRONT_CACHE_STALLED_RTO_MS or (floor_collapse and flow_rto_ms >= FRONT_RTO_DEGRADED_MS)
    return {
        "active_flows": active_flows,
        "max_rto_ms": max_rto_ms,
        "min_mss": min_mss,
        "stalled": stalled,
    }


def previous_front_interval_degraded(previous: Mapping[str, Any], source: str, observed_at: str) -> bool:
    now = runtime.parse_iso_datetime(observed_at)
    prior_interval = previous.get("front_interval", {})
    if not isinstance(prior_interval, Mapping) or source not in prior_interval.get("degraded_sources", []):
        return False
    age = runtime.iso_age_seconds(str(prior_interval.get("observed_at", "")), now=now) if now else None
    return age is not None and 0 <= age <= FRONT_COUNTER_MAX_INTERVAL_SECONDS


def reconcile_front_tcp_metrics_cache(
    front: Mapping[str, Any],
    interval: Mapping[str, Any],
    previous: Mapping[str, Any],
    observed_at: str,
    now_epoch: int,
) -> dict[str, Any]:
    prior_recovery = previous.get("front_cache_recovery", {})
    prior_actions = prior_recovery.get("last_actions", {}) if isinstance(prior_recovery, Mapping) else {}
    last_actions = dict(prior_actions) if isinstance(prior_actions, Mapping) else {}
    actions: list[dict[str, Any]] = []
    degraded_sources = interval.get("degraded_sources", []) if interval.get("baseline") is not True else []
    for source in sorted({str(value) for value in degraded_sources})[:FRONT_CACHE_RECOVERY_HISTORY_LIMIT]:
        stall = front_source_stall(front, source)
        if not stall["stalled"] or not previous_front_interval_degraded(previous, source, observed_at):
            continue
        last = last_actions.get(source, {})
        last_epoch = int(last.get("epoch", 0) or 0) if isinstance(last, Mapping) and last.get("status") == "ok" else 0
        if now_epoch - last_epoch < FRONT_CACHE_RECOVERY_COOLDOWN_SECONDS:
            continue
        cached = tcp_destination_metrics(source)
        reordering = int(cached.get("reordering", 0) or 0)
        if cached.get("available") is not True or cached.get("cached") is not True or reordering < FRONT_CACHE_REORDERING_THRESHOLD:
            continue
        if len(actions) >= FRONT_CACHE_RECOVERY_MAX_ACTIONS:
            break
        source = str(cached["source"])
        result = runtime.run(["ip", "tcp_metrics", "delete", source], timeout=5)
        status = "ok" if result.returncode == 0 else "failed"
        action = {
            "source": source,
            "status": status,
            "observed_at": observed_at,
            "epoch": now_epoch,
            "cached_reordering": reordering,
            "max_rto_ms": stall["max_rto_ms"],
            "min_mss": stall["min_mss"],
        }
        if status == "failed":
            action["error"] = " ".join((result.stderr.strip() or result.stdout.strip() or "delete failed").split())[:160]
        actions.append(action)
        last_actions[source] = action
    bounded_actions = dict(
        sorted(
            ((str(source), dict(value)) for source, value in last_actions.items() if isinstance(value, Mapping)),
            key=lambda item: int(item[1].get("epoch", 0) or 0),
            reverse=True,
        )[:FRONT_CACHE_RECOVERY_HISTORY_LIMIT]
    )
    return {
        "policy": "exact-destination-metrics-v1",
        "observed_at": observed_at,
        "actions": actions,
        "last_actions": bounded_actions,
    }


def health(
    *,
    collect_runtime_facts: Callable[..., dict[str, Any]],
    front_interval_snapshot: Callable[..., tuple[dict[str, Any], dict[str, Any]]],
    apply_front_interval_verdict: Callable[[dict[str, Any], dict[str, Any]], None],
    front_degradation_evidence: Callable[..., dict[str, Any]],

) -> dict[str, Any]:
    install_lock = runtime.acquire_install_read_lock()
    if install_lock is None:
        previous = runtime.read_json(runtime.HEALTH_STATE_PATH, {})
        return {
            **(previous if isinstance(previous, dict) else {}),
            "schema_version": diagnostics.SCHEMA_VERSION,
            "updated_at": runtime.utc_now(),
            "state": "maintenance",
            "last_action": "none",
            "maintenance_reason": "install transaction is active",
        }
    try:
        return _health_unlocked(
            collect_runtime_facts=collect_runtime_facts,
            front_interval_snapshot=front_interval_snapshot,
            apply_front_interval_verdict=apply_front_interval_verdict,
            front_degradation_evidence=front_degradation_evidence,
        )
    finally:
        runtime.release_install_read_lock(install_lock)


def _health_unlocked(
    *,
    collect_runtime_facts: Callable[..., dict[str, Any]],
    front_interval_snapshot: Callable[..., tuple[dict[str, Any], dict[str, Any]]],
    apply_front_interval_verdict: Callable[[dict[str, Any], dict[str, Any]], None],
    front_degradation_evidence: Callable[..., dict[str, Any]],

) -> dict[str, Any]:
    runtime.LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with runtime.LOCK_PATH.open("w", encoding="utf-8") as lock:
        runtime.fcntl.flock(lock, runtime.fcntl.LOCK_EX)
        current = collect_runtime_facts(live_probes=True, profile="light", full_logs=False, include_maintenance=False)
        previous = runtime.read_json(runtime.HEALTH_STATE_PATH, {})
        observed_at = current.get("generated_at") or runtime.utc_now()
        front_interval, front_counters = front_interval_snapshot(
            current.get("front", {}),
            previous.get("front_counters", {}),
            observed_at,
        )
        apply_front_interval_verdict(current, front_interval)
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
        recovery_actions = planned_recovery_actions(current)
        failure_evidence = {
            "actions": recovery_actions,
            "requirements": runtime.failed_requirements(current.get("probes", {})),
            "profile_mismatches": sorted(current.get("network", {}).get("profile_mismatches", [])),
            "wireguard_policy_missing": sorted(current.get("network", {}).get("wireguard_policy", {}).get("missing", [])),
        }
        observed_time = runtime.parse_iso_datetime(observed_at)
        previous_time = runtime.parse_iso_datetime(str(previous.get("observed_at", "")))
        confirmation_gap = (observed_time - previous_time).total_seconds() if observed_time and previous_time else None
        same_failure = (
            hard_failure and hard_reasons == previous.get("hard_reasons", [])
            and failure_evidence == previous.get("failure_evidence")
            and confirmation_gap is not None and 0 < confirmation_gap <= HEALTH_CONFIRMATION_MAX_GAP_SECONDS
        )
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
        router_resources = current.get("storage", {}).get("memory", {}).get("router", {})
        resource_counters = {
            "sing_box_automatic_restarts": int(router_resources.get("automatic_restarts", 0) or 0),
        }
        resource_deltas = positive_counter_deltas(resource_counters, previous.get("resource_counters", {}))
        restart_delta = int(resource_deltas.get("sing_box_automatic_restarts", 0) or 0)
        if restart_delta:
            soft_reasons.append(f"sing_box_automatic_restarts={restart_delta}")
        oom_latest = current.get("storage", {}).get("runtime_events", {}).get("oom_kills", {}).get("latest_since_release", {})
        oom_timestamp = str(oom_latest.get("timestamp", "")) if isinstance(oom_latest, Mapping) else ""
        previous_oom_timestamp = str(previous.get("last_seen_oom_timestamp", ""))
        if oom_timestamp and oom_timestamp != previous_oom_timestamp:
            soft_reasons.append("kernel_oom_kill=observed")
        runtime_evidence = (
            {
                "observed_at": observed_at,
                "automatic_restart_delta": restart_delta,
                "oom": dict(oom_latest) if isinstance(oom_latest, Mapping) else {},
            }
            if restart_delta or (oom_timestamp and oom_timestamp != previous_oom_timestamp)
            else previous.get("last_runtime_degradation", {})
        )
        conntrack = current.get("network", {}).get("conntrack", {})
        conntrack_full = int(conntrack.get("table_full_observed", {}).get("5") or conntrack.get("table_full_events", {}).get("5") or 0)
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
        front_cache_recovery = reconcile_front_tcp_metrics_cache(
            current.get("front", {}),
            front_interval,
            previous,
            observed_at,
            now_epoch,
        )
        failed_cache_actions = [
            action for action in front_cache_recovery["actions"] if action.get("status") != "ok"
        ]
        if failed_cache_actions:
            soft_reasons.append(f"front_tcp_metrics_cache_recovery_failed={len(failed_cache_actions)}")
        state = "degraded" if soft_reasons else "healthy"
        last_actions = previous.get("last_actions", {})
        if not isinstance(last_actions, dict):
            last_actions = {}
        if hard_failure and failures == 1:
            state = "suspect"
        elif hard_failure:
            state = "failed"
        payload = {
            "schema_version": diagnostics.SCHEMA_VERSION,
            "updated_at": runtime.utc_now(),
            "observed_at": observed_at,
            "state": state,
            "consecutive_failures": failures,
            "last_action": "none",
            "last_action_epoch": int(previous.get("last_action_epoch", 0)),
            "last_actions": last_actions,
            "hard_reasons": hard_reasons,
            "failure_evidence": failure_evidence,
            "probe_failures": runtime.failed_requirements(current.get("probes", {})),
            "probes": current.get("probes", {}),
            "network_counters": network_counters,
            "network_deltas": network_deltas,
            "resource_counters": resource_counters,
            "resource_deltas": resource_deltas,
            "last_seen_oom_timestamp": oom_timestamp or previous_oom_timestamp,
            "last_runtime_degradation": runtime_evidence,
            "front_counters": front_counters,
            "front_interval": front_interval,
            "soft_reasons": soft_reasons,
            "last_front_degradation": last_front_degradation,
            "front_cache_recovery": front_cache_recovery,
            "verdicts": current["verdicts"],
        }
        eligible_actions = [
            action
            for action in recovery_actions
            if now_epoch - int((last_actions.get(action, {}) or {}).get("epoch", 0)) >= 900
        ]
        if server_path_failure and not host_integrity_failure and failures >= 2 and eligible_actions:
            action = recover(
                current,
                actions=eligible_actions,
                on_result=lambda result: _record_recovery_action(payload, current, result),
            )
            payload["last_action"] = action
            if successful_recovery_actions(action):
                _post_recovery_check(payload, collect_runtime_facts)
        payload["updated_at"] = runtime.utc_now()
        runtime.write_json_atomic(runtime.HEALTH_STATE_PATH, payload)
        return payload


def _record_recovery_action(
    payload: dict[str, Any], current: dict[str, Any], result: str,
) -> None:
    prior_results = payload["last_action"]
    payload["last_action"] = result if prior_results == "none" else f"{prior_results};{result}"
    successful_actions = successful_recovery_actions(result)
    if successful_actions:
        completed_epoch = int(time.time())
        payload.update({
            "state": "recovering",
            "last_action_epoch": completed_epoch,
            "last_actions": {
                **payload["last_actions"],
                **{key: {"epoch": completed_epoch, "action": value} for key, value in successful_actions.items()},
            },
        })
        payload["pre_recovery"] = {
            "observed_at": payload["observed_at"],
            "hard_reasons": payload["hard_reasons"],
            "probe_failures": payload["probe_failures"],
            "probes": payload["probes"],
            "verdicts": current["verdicts"],
        }
        payload["post_recovery_verdicts"] = {"server_path": "inconclusive", "host_integrity": "inconclusive", "overall": "inconclusive"}
        payload["verdicts"] = {**current["verdicts"], **payload["post_recovery_verdicts"]}
    payload["updated_at"] = runtime.utc_now()
    # A failed receipt write must abort recovery before the next mutation.
    runtime.write_json_atomic(runtime.HEALTH_STATE_PATH, payload)


def _post_recovery_check(
    payload: dict[str, Any], collect_runtime_facts: Callable[..., dict[str, Any]],
) -> None:
    time.sleep(2)
    try:
        postcheck = collect_runtime_facts(live_probes=True, profile="light", full_logs=False, include_maintenance=False)
        observed_time = runtime.parse_iso_datetime(str(payload["observed_at"]))
        postcheck_time = runtime.parse_iso_datetime(str(postcheck.get("generated_at", "")))
        postcheck_fresh = (
            observed_time is not None and postcheck_time is not None
            and 0 < (postcheck_time - observed_time).total_seconds() <= HEALTH_CONFIRMATION_MAX_GAP_SECONDS
        )
        verdicts = postcheck.get("verdicts", {})
        soft_reasons = [
            f"post_recovery.{name}={value}"
            for name, value in verdicts.items()
            if isinstance(value, str) and value in {"degraded", "client_specific", "shared", "inconclusive", "failed"}
        ]
        probe_failures = runtime.failed_requirements(postcheck.get("probes", {}))
    except Exception as exc:
        payload["post_recovery_error"] = f"{type(exc).__name__}: {' '.join(str(exc).split())}"[:240]
        payload["soft_reasons"].append("post_recovery.collection=inconclusive")
        return
    payload.update({
        "post_recovery_at": postcheck.get("generated_at"),
        "post_recovery_verdicts": verdicts,
        "probes": postcheck.get("probes", {}),
        "probe_failures": probe_failures,
        "verdicts": verdicts,
    })
    payload["soft_reasons"].extend(soft_reasons)
    if postcheck_fresh and all(verdicts.get(name) == "verified" for name in ("server_path", "host_integrity")):
        payload["state"] = "degraded" if payload["soft_reasons"] else "healthy"
        payload["consecutive_failures"] = 0


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
        "failure_evidence": payload.get("failure_evidence", {}),
        "probe_failures": payload.get("probe_failures", []),
        "pre_recovery": payload.get("pre_recovery", {}),
        "post_recovery_error": payload.get("post_recovery_error", ""),
        "soft_reasons": payload.get("soft_reasons", []),
        "verdicts": payload.get("verdicts", {}),
        "front_interval": {
            "observation": interval.get("observation", "observed"),
            "degraded_sources": interval.get("degraded_sources", []),
            "aggregate": interval.get("aggregate", {}),
        },
        "front_cache_recovery": {
            "actions": payload.get("front_cache_recovery", {}).get("actions", []),
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


def successful_recovery_actions(results: str) -> dict[str, str]:
    successful = {}
    for result in results.split(";"):
        action, _, status = result.rpartition(":")
        if action and status in {"ok", "changed"}:
            successful[action] = result
    return successful


def planned_recovery_actions(current: dict[str, Any]) -> list[str]:
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
        unit = str(configured_units.get(key, runtime.SERVICE_UNIT_DEFAULTS[key])).format(wg_interface=interface)
        if services.get(key) != "active":
            actions.append(f"restart:{unit}")
    if actions:
        return actions
    artifacts_clean = current.get("artifacts", {}).get("drift") == "none"
    network = current.get("network", {})
    wireguard_policy = network.get("wireguard_policy", {})
    if (
        artifacts_clean
        and runtime.CAP_INTERSERVER_CLIENT in capabilities
        and wireguard_policy.get("managed") is True
        and wireguard_policy.get("ok") is not True
    ):
        return ["apply:wireguard-policy"]
    profile_mismatches = set(network.get("profile_mismatches", []))
    qdisc_mismatches = profile_mismatches & {"qdisc", "qdisc_limit", "qdisc_flow_limit"}
    qdisc_mismatches.update(name for name in profile_mismatches if name.startswith("overlay_qdisc"))
    if artifacts_clean and qdisc_mismatches:
        return ["apply:qdisc"]
    if artifacts_clean and profile_mismatches:
        return ["reload:sysctl"]
    bypass = network.get("conntrack", {}).get("front_bypass", {})
    if artifacts_clean and runtime.CAP_PUBLIC_FRONT in capabilities and not bypass.get("active"):
        return [f"reload:{runtime.NFTABLES_SERVICE}"]
    if runtime.CAP_ROUTER in capabilities:
        probes = current.get("probes", {})
        router_path_ok = runtime.probe_path_ok(probes, "foreign_domains_via_router", "domains_via_router")
        if runtime.CAP_INTERSERVER_CLIENT in capabilities:
            independent_path_ok = runtime.probe_path_ok(probes, "via_wg", "foreign_domains_via_wg")
        else:
            direct = probes.get("direct", [])
            independent_path_ok = bool(direct) and all(isinstance(item, Mapping) and item.get("ok") is True for item in direct)
        if independent_path_ok and not router_path_ok:
            return ["restart:sing-box.service"]
    return []


def recover(
    current: dict[str, Any], *, actions: list[str] | None = None,
    on_result: Callable[[str], None] | None = None,
) -> str:
    results: list[str] = []
    for action in planned_recovery_actions(current) if actions is None else actions:
        if action == "apply:wireguard-policy":
            try:
                applied = apply_wireguard_policy(runtime.parse_env())
                status = "changed" if applied.get("changed") else "ok"
            except (KeyError, RuntimeError, ValueError):
                status = "failed"
        elif action == "apply:qdisc":
            try:
                applied = (
                    apply_qdisc_profile()
                    if set(current.get("capabilities", ())) & runtime.INTERSERVER_CAPABILITIES
                    else apply_qdisc_profile(include_overlay=False)
                )
                status = "changed" if applied.get("changed") else "ok"
            except RuntimeError:
                status = "failed"
        elif action == f"reload:{runtime.NFTABLES_SERVICE}" and not runtime.NFTABLES_CONFIG_PATH.is_file():
            status = "invalid-config"
        else:
            command = (
                ["sysctl", "--load", str(runtime.SYSCTL_PATH)]
                if action == "reload:sysctl" else ["systemctl", *action.split(":", 1)]
            )
            result = runtime.run(command, timeout=30)
            status = "ok" if result.returncode == 0 else "failed"
        results.append(f"{action}:{status}")
        if on_result is not None:
            on_result(results[-1])
    return ";".join(results) or "none"
