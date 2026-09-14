from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

if __package__:
    from . import interserver_transport as policy
    from . import server_runtime as runtime
    from .log_classifier import normalize_source, split_endpoint
else:
    import interserver_transport as policy
    import server_runtime as runtime
    from log_classifier import normalize_source, split_endpoint


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
    result = runtime.run(["wg", "show", interface, "endpoints"], timeout=3)
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
    available = normalize_source(host) in {"127.0.0.1", "::1"} and port == policy.TRANSPORT_RELAY_PORT
    return {
        "available": available,
        "endpoint": endpoint,
        "reason": "" if available else "WireGuard overlay endpoint is not the fixed managed relay",
    }


def transport_selector_selection(controller: str) -> dict[str, Any]:
    try:
        selector = clash_api_json(
            controller,
            f"/proxies/{urllib.parse.quote(policy.TRANSPORT_SELECTOR_TAG, safe='')}",
            timeout=2,
        )
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return {"available": False, "selected": "", "reason": f"selector state is unavailable: {exc}"[:240]}
    selected = str(selector.get("now", ""))
    available = selected in policy.TRANSPORT_CANDIDATE_TAGS
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
        policy.TRANSPORT_WG_TAG: {"configured": policy.TRANSPORT_WG_TAG in endpoint_tags},
        policy.TRANSPORT_HY2_TAG: {"configured": policy.TRANSPORT_HY2_TAG in outbound_tags},
    }
    relay = wireguard_overlay_relay(env)
    selector = transport_selector_selection(controller)
    selected = str(selector.get("selected", ""))
    topology_configured = policy.transport_topology_configured(config, env)
    available = relay.get("available") is True and selector.get("available") is True and topology_configured
    return {
        "available": available,
        "selected": selected,
        "endpoint": relay.get("endpoint", ""),
        "selector": policy.TRANSPORT_SELECTOR_TAG,
        "candidates": candidates,
        "reason": "" if available else str(
            relay.get("reason") or selector.get("reason") or "transport topology is incomplete"
        ),
    }


def preferred_transport_probe_due(previous: dict[str, Any], observed_at: str) -> bool:
    now = runtime.parse_iso_datetime(observed_at)
    retry = previous.get("preferred_retry", {})
    retry_at = runtime.parse_iso_datetime(str(retry.get("retry_at", ""))) if isinstance(retry, dict) else None
    if now is not None and retry_at is not None and now < retry_at:
        return False
    age = runtime.iso_age_seconds(str(previous.get("preferred_probe_at", "")), now=now) if now else None
    return age is None or age >= policy.TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS


def overlay_quality_probe_due(previous: dict[str, Any], observed_at: str) -> bool:
    if previous.get("state") == "suspect":
        return False
    now = runtime.parse_iso_datetime(observed_at)
    age = runtime.iso_age_seconds(str(previous.get("quality_probe_at", "")), now=now) if now else None
    return age is None or age >= policy.TRANSPORT_QUALITY_PROBE_INTERVAL_SECONDS


def ping_failure_reason(result: subprocess.CompletedProcess[str], fallback: str) -> str:
    detail = " ".join((result.stderr.strip() or result.stdout.strip() or fallback).split())
    lowered = detail.lower()
    if "100% packet loss" in lowered or "0 received" in lowered:
        return f"{fallback} timed out"
    return detail[:240]


def transport_overlay_path_probe(env: dict[str, str], *, quality: bool = False) -> dict[str, Any]:
    """Probe the managed overlay; quality sampling never decides liveness."""

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
    if not quality:
        return policy.transport_overlay_dns_probe(interface, target)

    packet_count = policy.TRANSPORT_QUALITY_PROBE_PACKETS
    payload_bytes = policy.TRANSPORT_QUALITY_PROBE_PAYLOAD_BYTES
    command = ["ping", "-n", "-I", interface, "-c", str(packet_count)]
    command.extend(["-i", "0.05", "-w", "2"])
    command.extend(["-W", "1", "-s", str(payload_bytes), target])
    result = runtime.run(command, timeout=3)
    elapsed_ms = max(1, round((time.monotonic() - started) * 1000))
    error = ""
    packet_loss_pct: float | None = None
    rtt_avg_ms: float | None = None
    loss_match = re.search(r"([0-9]+(?:[.,][0-9]+)?)%\s+packet loss", result.stdout)
    if loss_match:
        packet_loss_pct = float(loss_match.group(1).replace(",", "."))
    rtt_match = re.search(r"=\s*[0-9.]+/([0-9.]+)/[0-9.]+/[0-9.]+\s+ms", result.stdout)
    if rtt_match:
        rtt_avg_ms = float(rtt_match.group(1))
    if packet_loss_pct is not None and packet_loss_pct > 0:
        error = f"WireGuard overlay packet loss {packet_loss_pct:g}%"
    if not error and result.returncode != 0:
        error = ping_failure_reason(result, "WireGuard overlay liveness probe")
    payload: dict[str, Any] = {
        "checked": True,
        "ok": not error,
        "attempts": packet_count,
        "delay_ms": 0 if error else round(rtt_avg_ms or elapsed_ms),
        "elapsed_ms": elapsed_ms,
        "scope": "overlay-quality",
        "target": target,
        "error": error,
        "quality_checked": packet_loss_pct is not None,
        "payload_bytes": payload_bytes,
    }
    if packet_loss_pct is not None:
        payload["packet_loss_pct"] = packet_loss_pct
    if rtt_avg_ms is not None:
        payload["rtt_avg_ms"] = rtt_avg_ms
    return payload


def collect_transport_probes(
    selected: str,
    previous: dict[str, Any],
    *,
    env: dict[str, str],
    observed_at: str,
) -> dict[str, dict[str, Any]]:
    probes = {tag: {"checked": False, "ok": False, "attempts": 0} for tag in policy.TRANSPORT_CANDIDATE_TAGS}
    if selected not in probes:
        return probes
    probes[selected] = transport_overlay_path_probe(env)
    if probes[selected].get("ok") is True and overlay_quality_probe_due(previous, observed_at):
        quality = transport_overlay_path_probe(env, quality=True)
        probes[selected] = {
            **probes[selected],
            "quality_checked": quality.get("quality_checked") is True,
            "quality_sampled": True,
            "quality_ok": quality.get("ok") is True,
            "quality_error": str(quality.get("error", ""))[:240],
            **{
                key: quality[key]
                for key in ("packet_loss_pct", "rtt_avg_ms", "payload_bytes")
                if key in quality
            },
        }
    elif probes[selected].get("ok") is True and isinstance(previous.get("last_quality_probe"), dict):
        prior_quality = previous["last_quality_probe"]
        probes[selected].update(
            {
                key: prior_quality[key]
                for key in (
                    "quality_checked",
                    "quality_ok",
                    "quality_error",
                    "packet_loss_pct",
                    "rtt_avg_ms",
                    "payload_bytes",
                )
                if key in prior_quality
            }
        )
        probes[selected]["quality_sampled"] = False
    fresh_selected_quality_failure = (
        probes[selected].get("quality_sampled") is True
        and probes[selected].get("quality_checked") is True
        and probes[selected].get("quality_ok") is False
    )
    if probes[selected].get("ok") is not True or fresh_selected_quality_failure:
        alternate = next(tag for tag in policy.TRANSPORT_CANDIDATE_TAGS if tag != selected)
        if transport_switch_backoff_active(previous, alternate, observed_at) is None:
            if fresh_selected_quality_failure:
                probes[alternate] = policy.transport_candidate_probe(
                    alternate,
                    timeout_ms=policy.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
                    attempts=policy.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
                )
            else:
                probes[alternate] = policy.transport_candidate_probe(alternate)
    elif (
        selected != policy.TRANSPORT_PREFERRED_TAG
        and preferred_transport_probe_due(previous, observed_at)
        and transport_switch_backoff_active(previous, policy.TRANSPORT_PREFERRED_TAG, observed_at) is None
    ):
        probes[policy.TRANSPORT_PREFERRED_TAG] = policy.transport_candidate_probe(
            policy.TRANSPORT_PREFERRED_TAG,
            timeout_ms=policy.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
            attempts=policy.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
        )
    return probes


class TransportSwitchError(RuntimeError):
    def __init__(self, message: str, evidence: dict[str, Any]):
        super().__init__(message[:240])
        self.evidence = evidence


def prove_wireguard_overlay(env: dict[str, str]) -> dict[str, Any]:
    interface = env.get("WG_INTERFACE", "wg0")
    target = str(env.get("WG_FOREIGN_ADDRESS", "")).split("/", 1)[0]
    if not interface or not target:
        raise RuntimeError("foreign WireGuard overlay proof identity is missing")

    started = time.monotonic()
    budget = (
        policy.TRANSPORT_SWITCH_PROOF_ATTEMPTS * policy.TRANSPORT_SWITCH_PROOF_TIMEOUT_MS / 1000
        + (policy.TRANSPORT_SWITCH_PROOF_ATTEMPTS - 1) * policy.TRANSPORT_SWITCH_PROOF_RETRY_DELAY_SECONDS
    )
    deadline = started + budget
    report: dict[str, Any] = {
        "ok": False, "checked": True, "budget_ms": round(budget * 1000),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "rounds_limit": policy.TRANSPORT_SWITCH_PROOF_ATTEMPTS, "rounds": [],
        "probe": {"checked": False, "ok": False},
    }
    last_error = "overlay DNS convergence deadline expired"
    for attempt in range(1, policy.TRANSPORT_SWITCH_PROOF_ATTEMPTS + 1):
        if time.monotonic() >= deadline:
            break
        proof = policy.transport_overlay_dns_probe(interface, target, deadline=deadline)
        report["rounds"].append(proof)
        report["probe"] = proof
        if proof.get("ok") is True and proof.get("health_confirmed") is True and time.monotonic() < deadline:
            report["ok"] = True
            break
        last_error = str(proof.get("error", "") or last_error)[:240]
        if attempt < policy.TRANSPORT_SWITCH_PROOF_ATTEMPTS:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(policy.TRANSPORT_SWITCH_PROOF_RETRY_DELAY_SECONDS, remaining))
    report.update(
        elapsed_ms=max(0, round((time.monotonic() - started) * 1000)),
        finished_at=datetime.now(timezone.utc).isoformat(),
        error="" if report["ok"] else last_error,
    )
    if not report["ok"]:
        raise TransportSwitchError(
            f"WireGuard overlay DNS convergence proof failed after {len(report['rounds'])} rounds: {last_error[:160]}",
            report,
        )
    return report


def reset_transport_relay(controller: str) -> int:
    """Close only the inner-WireGuard relay association so it follows the new selector."""

    payload = clash_api_json(controller, "/connections", timeout=2)
    connections = payload.get("connections", [])
    expected_type = f"direct/{policy.TRANSPORT_RELAY_INBOUND_TAG}"
    closed = 0
    for connection in connections if isinstance(connections, list) else []:
        if not isinstance(connection, dict):
            continue
        chains = connection.get("chains", [])
        metadata = connection.get("metadata", {})
        connection_id = str(connection.get("id", ""))
        if (
            not isinstance(chains, list)
            or policy.TRANSPORT_SELECTOR_TAG not in chains
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


def select_transport(
    env: dict[str, str], controller: str, tag: str, *, cycle_id: str = "",
) -> dict[str, Any]:
    if tag not in policy.TRANSPORT_CANDIDATE_TAGS:
        raise ValueError(f"unknown transport candidate: {tag}")
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    current = transport_selector_selection(controller)
    old_tag = str(current.get("selected", ""))
    if current.get("available") is not True or old_tag not in policy.TRANSPORT_CANDIDATE_TAGS:
        raise RuntimeError("current underlay selector state is not recoverable")
    report: dict[str, Any] = {
        "cycle_id": cycle_id or f"{started_at}:{time.monotonic_ns()}",
        "phase": "after", "started_at": started_at,
        "selector_before": old_tag, "selector_requested": tag, "selector_after": old_tag,
        "changed": False, "ok": False, "rollback_verified": False,
        "relay_resets": [], "activation_proof": {}, "rollback_proof": {},
    }
    stage = "selector_apply"

    def observe_selector() -> str:
        selected = transport_selector_selection(controller)
        value = str(selected.get("selected", "")) if selected.get("available") is True else ""
        report["selector_after"] = value
        return value

    def set_selector(value: str, phase: str) -> None:
        nonlocal stage
        stage = f"{phase}_selector"
        clash_api_json(
            controller,
            f"/proxies/{urllib.parse.quote(policy.TRANSPORT_SELECTOR_TAG, safe='')}",
            method="PUT",
            payload={"name": value},
            timeout=2,
        )
        if observe_selector() != value:
            raise RuntimeError("underlay selector did not apply the requested path")
        stage = f"{phase}_relay_reset"
        closed = reset_transport_relay(controller)
        report["relay_resets"].append({"phase": phase, "path": value, "closed": closed})

    def prove(phase: str, path: str) -> None:
        nonlocal stage
        stage = phase
        proof: dict[str, Any] = {"checked": False, "ok": False}
        try:
            proof = prove_wireguard_overlay(env)
        except TransportSwitchError as exc:
            proof = exc.evidence
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            proof["error"] = str(exc)[:240]
            raise
        finally:
            after = observe_selector()
            evidence = {
                **proof, "phase": phase, "path": path, "cycle_id": report["cycle_id"],
                "selector_after": after,
            }
            evidence["probe"] = {
                **proof.get("probe", {"checked": False, "ok": False}),
                "phase": phase, "path": path, "cycle_id": report["cycle_id"],
            }
            if after != path:
                evidence["ok"] = False
                evidence["probe"] = {
                    "checked": False, "ok": False, "phase": phase, "path": after,
                    "cycle_id": report["cycle_id"], "error": "selector changed during overlay proof",
                }
            report[f"{phase}_proof"] = evidence
        if proof.get("ok") is not True or after != path:
            raise RuntimeError("selected path has no matching overlay proof")

    def finish() -> None:
        report.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            elapsed_ms=max(0, round((time.monotonic() - started) * 1000)),
        )

    try:
        if old_tag != tag:
            set_selector(tag, "activation")
        prove("activation", tag)
    except (OSError, RuntimeError, ValueError, urllib.error.URLError) as exc:
        report.update(error=str(exc)[:180], failure_stage=stage)
        if old_tag != tag:
            try:
                set_selector(old_tag, "rollback")
                prove("rollback", old_tag)
            except (OSError, RuntimeError, ValueError, urllib.error.URLError) as rollback_exc:
                report.update(rollback_error=str(rollback_exc)[:240], rollback_failure_stage=stage)
            else:
                report["rollback_verified"] = True
        # A failed PUT may have applied remotely even when no acknowledgement arrived.
        observe_selector()
        report["rollback_verified"] = report["rollback_verified"] and report["selector_after"] == old_tag
        finish()
        suffix = "previous selector path restored and verified" if report["rollback_verified"] else "rollback not verified"
        raise TransportSwitchError(f"{report['error']}; {suffix}", report) from exc
    report.update(ok=True, changed=old_tag != tag, error="")
    finish()
    return report


def transport_switch_backoff_active(
    previous: dict[str, Any],
    target: str,
    observed_at: str,
) -> dict[str, Any] | None:
    backoff = previous.get("switch_backoff", {})
    if not isinstance(backoff, dict) or backoff.get("target") != target:
        return None
    retry_at = runtime.parse_iso_datetime(str(backoff.get("retry_at", "")))
    observed = runtime.parse_iso_datetime(observed_at)
    if retry_at is None or observed is None or observed >= retry_at:
        return None
    return backoff


def next_transport_switch_failure(
    previous: dict[str, Any],
    target: str,
    reason: str,
    observed_at: str,
) -> dict[str, Any]:
    prior = transport_switch_failure_history(previous, target, observed_at)
    attempts = max(0, int(prior.get("attempts", 0) or 0)) + 1 if prior else 1
    delay = min(
        policy.TRANSPORT_SWITCH_RETRY_MAX_SECONDS,
        policy.TRANSPORT_SWITCH_RETRY_BASE_SECONDS * (2 ** min(attempts - 1, 8)),
    )
    observed = runtime.parse_iso_datetime(observed_at) or datetime.now(timezone.utc)
    return {
        "target": target,
        "attempts": attempts,
        "failed_at": observed_at,
        "retry_at": (observed + timedelta(seconds=delay)).isoformat(),
        "reason": reason[:240],
    }


def transport_switch_failure_history(
    previous: dict[str, Any], target: str, observed_at: str,
) -> dict[str, Any] | None:
    now = runtime.parse_iso_datetime(observed_at)
    if now is None or target not in policy.TRANSPORT_CANDIDATE_TAGS:
        return None
    for key in ("switch_backoff", "last_switch_failure"):
        failure = previous.get(key, {})
        if not isinstance(failure, dict) or failure.get("target") != target:
            continue
        age = runtime.iso_age_seconds(str(failure.get("failed_at", "")), now=now)
        if age is not None and 0 <= age < policy.TRANSPORT_PREFERRED_STABLE_RESET_SECONDS:
            return failure
    return None


def current_transport_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != policy.TRANSPORT_STATE_SCHEMA_VERSION:
        return {}
    return value


def reconcile_interserver_transport() -> dict[str, Any]:
    install_lock = runtime.acquire_install_read_lock()
    if install_lock is None:
        previous = current_transport_state(runtime.read_json(runtime.TRANSPORT_STATE_PATH, {}))
        payload = {
            **(previous if isinstance(previous, dict) else {}),
            "schema_version": policy.TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": runtime.utc_now(),
            "state": "maintenance",
            "changed": False,
            "would_switch": False,
            "reason": "install transaction is active",
        }
        runtime.write_json_atomic(runtime.TRANSPORT_STATE_PATH, payload)
        return payload
    try:
        return _reconcile_interserver_transport_unlocked()
    finally:
        runtime.release_install_read_lock(install_lock)


def _reconcile_interserver_transport_unlocked() -> dict[str, Any]:
    runtime.TRANSPORT_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with runtime.TRANSPORT_LOCK_PATH.open("w", encoding="utf-8") as lock:
        runtime.fcntl.flock(lock, runtime.fcntl.LOCK_EX)
        config = runtime.read_json(runtime.SINGBOX_CONFIG_PATH, {})
        env = runtime.parse_env()
        controller = str(config.get("experimental", {}).get("clash_api", {}).get("external_controller", "")) if isinstance(config, dict) else ""
        previous_state = current_transport_state(runtime.read_json(runtime.TRANSPORT_STATE_PATH, {}))
        if not isinstance(config, dict) or not policy.transport_topology_configured(config, env) or not controller:
            payload = {
                "schema_version": policy.TRANSPORT_STATE_SCHEMA_VERSION,
                "updated_at": runtime.utc_now(),
                "state": "failed",
                "selected": "",
                "recommended": "",
                "would_switch": False,
                "reason": "stable WireGuard overlay relays are not configured",
            }
            runtime.write_json_atomic(runtime.TRANSPORT_STATE_PATH, payload)
            return payload

        selection = transport_selection_snapshot(config, env, controller)
        selected = str(selection.get("selected", ""))
        if not selection.get("available"):
            payload = {
                "schema_version": policy.TRANSPORT_STATE_SCHEMA_VERSION,
                "updated_at": runtime.utc_now(),
                "state": "failed",
                "selected": selected,
                "recommended": selected,
                "would_switch": False,
                "reason": str(selection.get("reason", "transport endpoint state is unavailable")),
            }
            runtime.write_json_atomic(runtime.TRANSPORT_STATE_PATH, payload)
            return payload

        observed_at = runtime.utc_now()
        probes = collect_transport_probes(
            selected,
            previous_state,
            env=env,
            observed_at=observed_at,
        )
        cycle_id = f"{observed_at}:{time.monotonic_ns()}"
        probes = {
            path: {**probe, "cycle_id": cycle_id, "phase": "before", "path": path}
            for path, probe in probes.items()
        }
        payload = policy.evaluate_transport_policy(
            selected=selected,
            probes=probes,
            previous=previous_state,
            observed_at=observed_at,
        )
        payload.update(cycle_id=cycle_id, selector_before=selected, selector_after=selected)
        if isinstance(previous_state.get("last_transition"), dict):
            payload["last_transition"] = previous_state["last_transition"]
        payload["overlay_probe"] = probes.get(selected, {})
        if probes.get(selected, {}).get("quality_sampled") is True:
            payload["quality_probe_at"] = observed_at
            payload["last_quality_probe"] = probes[selected]
        elif previous_state.get("quality_probe_at"):
            payload["quality_probe_at"] = previous_state["quality_probe_at"]
            if isinstance(previous_state.get("last_quality_probe"), dict):
                payload["last_quality_probe"] = previous_state["last_quality_probe"]
        alternate = next((tag for tag in policy.TRANSPORT_CANDIDATE_TAGS if tag != selected), "")
        last_switch_failure = transport_switch_failure_history(previous_state, alternate, observed_at)
        if last_switch_failure is not None:
            payload["last_switch_failure"] = last_switch_failure
        switch_backoff = transport_switch_backoff_active(previous_state, alternate, observed_at)
        if switch_backoff is not None:
            payload["switch_backoff"] = switch_backoff
            if payload.get("would_switch"):
                payload.update(
                    {
                        "state": "degraded" if probes.get(selected, {}).get("ok") is True else "failed",
                        "recommended": selected,
                        "would_switch": False,
                        "changed": False,
                        "reason": (
                            f"{payload.get('reason', '')}; underlay activation is paused until "
                            f"{switch_backoff.get('retry_at', 'the next retry window')}"
                        ),
                    }
                )
        if payload.get("would_switch"):
            target = str(payload.get("recommended", ""))
            transition: dict[str, Any] = {}
            try:
                transition = select_transport(env, controller, target, cycle_id=cycle_id)
            except (OSError, RuntimeError, ValueError) as exc:
                failure_reason = f"underlay selector update failed: {str(exc)[:180]}"
                if isinstance(exc, TransportSwitchError):
                    transition = exc.evidence
                rollback_verified = transition.get("rollback_verified") is True
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
                        "changed": transition["changed"],
                        "selected": target,
                        "would_switch": False,
                        "state": "degraded" if payload.get("hard_failure_evidence") else "healthy",
                        "reason": f"{payload.get('reason', '')}; underlay selector updated",
                    }
                )
                payload.pop("switch_backoff", None)
                payload.pop("last_switch_failure", None)
                payload.pop("quality_failure", None)
                payload.pop("last_quality_probe", None)
            if transition:
                payload["last_transition"] = transition
                payload["selector_after"] = transition["selector_after"]
                payload["selected"] = transition["selector_after"]
                phase = "rollback" if transition.get("rollback_proof") else "activation"
                proof = transition.get(f"{phase}_proof", {})
                current_probe = proof.get("probe", {})
                payload["overlay_probe"] = current_probe if current_probe.get("path") == transition["selector_after"] else {
                    "checked": False, "ok": False, "phase": phase,
                    "path": transition["selector_after"], "cycle_id": cycle_id,
                }
            else:
                payload["selector_after"] = ""
                payload["selected"] = ""
                payload["overlay_probe"] = {
                    "checked": False, "ok": False, "phase": "after", "path": "", "cycle_id": cycle_id,
                }
        runtime.write_json_atomic(runtime.TRANSPORT_STATE_PATH, payload)
        return payload


def watch_interserver_transport() -> None:
    previous_signature: tuple[str, str, str] | None = None
    while True:
        started = time.monotonic()
        try:
            payload = reconcile_interserver_transport()
        except Exception as exc:  # noqa: BLE001
            payload = {
                "schema_version": policy.TRANSPORT_STATE_SCHEMA_VERSION,
                "updated_at": runtime.utc_now(),
                "state": "failed",
                "selected": "",
                "recommended": "",
                "reason": str(exc)[:240],
            }
            runtime.write_json_atomic(runtime.TRANSPORT_STATE_PATH, payload)
        signature = (
            str(payload.get("state", "")),
            str(payload.get("selected", "")),
            str(payload.get("reason", "")),
        )
        transition = payload.get("last_transition", {})
        new_transition = isinstance(transition, dict) and bool(payload.get("cycle_id")) and transition.get("cycle_id") == payload["cycle_id"]
        if signature != previous_signature or new_transition:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)
            previous_signature = signature
        time.sleep(max(0.1, policy.TRANSPORT_PROBE_INTERVAL_SECONDS - (time.monotonic() - started)))


def transport_state_snapshot(path: Path = runtime.TRANSPORT_STATE_PATH) -> dict[str, Any]:
    state = runtime.read_json(path, {})
    if not isinstance(state, dict) or not state:
        return {}
    age_seconds = runtime._observation_age_seconds(str(state.get("updated_at", "")))
    return {
        **state,
        "age_seconds": round(age_seconds, 1) if age_seconds is not None else None,
        "fresh": age_seconds is not None and 0 <= age_seconds <= policy.TRANSPORT_PROBE_INTERVAL_SECONDS * 6,
    }


def interserver_transport_snapshot(contract: Mapping[str, Any], env: dict[str, str]) -> dict[str, Any]:
    config = runtime.read_json(runtime.SINGBOX_CONFIG_PATH, {})
    if not isinstance(config, dict):
        return {"configured": False, "reason": "sing-box config is unreadable"}
    if runtime.contract_has(contract, runtime.CAP_INTERSERVER_CLIENT):
        outbounds = {
            str(item.get("tag", "")): item
            for item in config.get("outbounds", [])
            if isinstance(item, dict) and item.get("tag")
        }
        hysteria = outbounds.get(policy.TRANSPORT_HY2_TAG, {})
        server = str(hysteria.get("server", "")) if isinstance(hysteria, dict) else ""
        try:
            port = int(hysteria.get("server_port", 0)) if isinstance(hysteria, dict) else 0
        except (TypeError, ValueError):
            port = 0
        session_active = False
        if server and port:
            sockets = runtime.run(["ss", "-Huan"], timeout=5)
            for line in sockets.stdout.splitlines():
                fields = line.split()
                if len(fields) < 2:
                    continue
                host, remote_port = split_endpoint(fields[-1])
                if normalize_source(host) == normalize_source(server) and remote_port == port:
                    session_active = True
                    break
        configured = policy.transport_topology_configured(config, env)
        controller = str(config.get("experimental", {}).get("clash_api", {}).get("external_controller", ""))
        selection = transport_selection_snapshot(config, env, controller)
        adaptive_state = transport_state_snapshot()
        if not adaptive_state:
            adaptive_state = {"state": "failed", "fresh": False, "reason": "transport watcher has not reported"}
        return {
            "configured": configured,
            "mode": "stable-wireguard-overlay",
            "candidates": list(policy.TRANSPORT_CANDIDATE_TAGS),
            "server": server,
            "port": port,
            "relay_port": policy.TRANSPORT_RELAY_PORT,
            "selector": policy.TRANSPORT_SELECTOR_TAG,
            "hysteria_session_active": session_active,
            "selection": selection,
            "adaptive_state": adaptive_state,
        }
    if runtime.contract_has(contract, runtime.CAP_INTERSERVER_SERVER):
        inbound = next(
            (item for item in config.get("inbounds", []) if isinstance(item, dict) and item.get("tag") == "interserver-hy2-in"),
            {},
        )
        try:
            port = int(inbound.get("listen_port", 0))
        except (TypeError, ValueError):
            port = 0
        listeners = runtime.run(["ss", "-Huln"], timeout=5)
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
