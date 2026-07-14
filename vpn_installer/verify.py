from __future__ import annotations

import time
from pathlib import Path
from . import health, workflows
from .common import print_header
from .diagnostics import DiagnosticsSnapshot
from .models import ROLE_FOREIGN, ROLE_RU
from .roles import requested_roles


def _probe_has_broken_result(raw_value: str) -> bool:
    if not raw_value:
        return False
    for part in raw_value.replace(",", ";").split(";"):
        part = part.strip()
        if not part:
            continue
        if part.split("|", 1)[0].endswith("broken") or "|broken|" in part:
            return True
        fields = part.split(":")
        if len(fields) > 1 and fields[1] == "broken":
            return True
    return False


def _probe_has_any_reachable_result(raw_value: str) -> bool:
    if not raw_value:
        return False
    for part in raw_value.replace(",", ";").split(";"):
        part = part.strip()
        if not part:
            continue
        fields = part.split(":")
        if len(fields) > 1 and fields[1] in {"reachable", "http_400", "http_403", "http_404"}:
            return True
    return False


def _verify_snapshot(snapshot: DiagnosticsSnapshot) -> DiagnosticsSnapshot:
    hard_failures: list[str] = []
    degradations: list[str] = []
    for service_name, state in snapshot.services.items():
        required_services = {"wireguard", "nftables"}
        if snapshot.role == ROLE_RU:
            required_services.add("sing-box")
        if service_name in required_services and state and state != "active":
            hard_failures.append(f"{service_name}={state}")
    if snapshot.role == ROLE_RU and snapshot.services.get("xray") not in {"", "active"}:
        hard_failures.append(f"xray={snapshot.services.get('xray')}")
    if snapshot.drift == "server-mutated":
        hard_failures.append("installed config hash differs from render manifest")
    elif snapshot.drift == "unknown":
        degradations.append("render manifest is missing or incomplete")
    direct_probe = snapshot.route_probes.get("direct", "")
    if not _probe_has_any_reachable_result(direct_probe):
        degradations.append("direct route probe did not produce a reachable target")
    elif _probe_has_broken_result(direct_probe):
        degradations.append("direct route probe has broken targets")
    if snapshot.role == ROLE_RU:
        wg_probe = snapshot.route_probes.get("wg", "")
        if not _probe_has_any_reachable_result(wg_probe):
            degradations.append("wg route probe did not produce a reachable target")
        elif _probe_has_broken_result(wg_probe):
            degradations.append("wg route probe has broken targets")
        ipv6_probe = snapshot.route_probes.get("ipv6_literal_tcp", "")
        if not ipv6_probe:
            degradations.append("IPv6 literal TCP route probe did not run")
        elif _probe_has_broken_result(ipv6_probe) and not _probe_has_any_reachable_result(ipv6_probe):
            degradations.append("IPv6 literal TCP route probe has broken targets")
    if hard_failures:
        snapshot.verdict = "failed"
        snapshot.reasons = hard_failures + degradations
    elif degradations:
        snapshot.verdict = "degraded"
        snapshot.reasons = degradations
    elif snapshot.services:
        snapshot.verdict = "verified"
        snapshot.reasons = []
    else:
        snapshot.verdict = "inconclusive"
        snapshot.reasons = ["no service data collected"]
    return snapshot


def verify_live_workflow(deployment: str | None, *, non_interactive: bool = False) -> int:
    print_header("Live verification")
    roles = requested_roles("all")
    verify_started_epoch = int(time.time())
    deployment_name, env_path, env, _state, targets, preflights_by_role = workflows.prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
        fresh_since_epoch=verify_started_epoch,
        run_live_probes=True,
    )
    workflows.print_summary(deployment_name, env, targets)
    snapshots: list[DiagnosticsSnapshot] = []
    worst = "verified"
    rank = {"verified": 0, "degraded": 1, "inconclusive": 2, "failed": 3}
    for target in targets:
        preflight = preflights_by_role[target.role]
        snapshot = _verify_snapshot(DiagnosticsSnapshot.from_preflight(preflight, deployment=deployment_name))
        snapshots.append(snapshot)
        if rank[snapshot.verdict] > rank[worst]:
            worst = snapshot.verdict
    health_reason = ""
    if {ROLE_RU, ROLE_FOREIGN}.issubset(preflights_by_role):
        deployment_health = health.deployment_health_snapshot(env, preflights_by_role)
        health.print_deployment_health(deployment_health)
        if deployment_health["health_verdict"] != "ok":
            health_verdict = "failed" if health.is_hard_health_verdict(deployment_health["health_verdict"]) else "degraded"
            health_reason = health.health_failure_message(deployment_health)
            if rank[health_verdict] > rank[worst]:
                worst = health_verdict
    print_header("Live verification result")
    print(f"verify verdict: {worst}")
    for snapshot in snapshots:
        reason_text = "; ".join(snapshot.reasons) if snapshot.reasons else "fresh probes and installed manifest are consistent"
        print(f"{snapshot.role or 'unknown'}: {snapshot.verdict} - {reason_text}")
    if health_reason:
        print(f"deployment-health: {health_reason}")
    print(f"Deployment env: {Path(env_path)}")
    return 0 if worst == "verified" else 1
