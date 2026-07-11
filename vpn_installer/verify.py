from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from . import remote, workflows
from .common import print_header
from .diagnostics import DiagnosticsSnapshot
from .models import ROLE_FOREIGN, ROLE_RU


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


def _positive_int(raw_value: Any) -> int:
    try:
        return int(str(raw_value or "0"))
    except ValueError:
        return 0


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
    if _probe_has_broken_result(snapshot.route_probes.get("direct", "")):
        degradations.append("direct route probe has broken targets")
    if snapshot.role == ROLE_RU and _probe_has_broken_result(snapshot.route_probes.get("wg", "")):
        degradations.append("wg route probe has broken targets")
    if snapshot.role == ROLE_RU:
        ipv6_probe = snapshot.route_probes.get("ipv6_literal_tcp", "")
        if not ipv6_probe:
            degradations.append("IPv6 literal TCP route probe did not run")
        elif _probe_has_broken_result(ipv6_probe) and not _probe_has_any_reachable_result(ipv6_probe):
            degradations.append("IPv6 literal TCP route probe has broken targets")
    for bucket in ("dns_failed", "domain_to_foreign_timeout", "ipv4_literal_timeout", "ipv6_literal_timeout", "invalid_reality", "private_dns_leak"):
        count = _positive_int(snapshot.log_buckets.get(bucket, 0))
        if count > 0:
            degradations.append(f"fresh {bucket}={count}")
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
    roles = workflows.requested_roles("all")
    deployment_name, env_path, env, _state, targets, _preflights = workflows.prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
    )
    workflows.print_summary(deployment_name, env, targets)
    snapshots: list[DiagnosticsSnapshot] = []
    preflights_by_role: dict[str, dict[str, str]] = {}
    worst = "verified"
    rank = {"verified": 0, "degraded": 1, "inconclusive": 2, "failed": 3}
    verify_started_epoch = int(time.time())
    for target in targets:
        preflight = remote.remote_preflight(target, workflows.current_wg_interface(env), fresh_since_epoch=verify_started_epoch)
        preflights_by_role[target.role] = preflight
        remote.print_preflight(target, preflight)
        snapshot = _verify_snapshot(DiagnosticsSnapshot.from_preflight(preflight, deployment=deployment_name))
        snapshots.append(snapshot)
        if rank[snapshot.verdict] > rank[worst]:
            worst = snapshot.verdict
    health_reason = ""
    if {ROLE_RU, ROLE_FOREIGN}.issubset(preflights_by_role):
        health = workflows.deployment_health_snapshot(env, preflights_by_role)
        workflows.print_deployment_health(health)
        if health["health_verdict"] != "ok":
            health_verdict = "failed" if workflows.is_hard_health_verdict(health["health_verdict"]) else "degraded"
            health_reason = workflows.health_failure_message(health)
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
