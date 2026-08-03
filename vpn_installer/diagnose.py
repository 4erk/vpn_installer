from __future__ import annotations

import json
import shlex
import time
from pathlib import Path
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from .common import OUT_DIR, print_header, warn, write_text
from .config import load_existing_deployment_env
from .log_classifier import BUCKETS, summarize_lines
from .localnet import local_route_to_server, route_uses_self_tunnel
from .models import ROLE_FOREIGN, ROLE_RU, AppError, RemoteTarget
from .prompts import select_existing_deployment
from .remote import ssh_capture
from .state import load_state
from .client_artifacts import client_artifact_paths
from .roles import requested_roles
from .targets import build_target
from .workflows import prepare_remote_session

_SOURCE_IP_RE = re.compile(r"^[0-9A-Fa-f:.]+$")
PATH_DIAGNOSE_COMMAND_TIMEOUT = 180


def _diagnostic_run_dir(deployment_name: str) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return OUT_DIR / "diagnostics" / f"{stamp}-{deployment_name}"


def _decode_agent_snapshot(report: str, name: str) -> dict[str, object]:
    try:
        payload = json.loads(report)
    except json.JSONDecodeError as exc:
        raise AppError(f"Агент вернул некорректный {name} snapshot: {report[:240]}") from exc
    if not isinstance(payload, dict):
        raise AppError(f"Агент вернул некорректный {name} snapshot type.")
    return payload


def diagnose_front_workflow(deployment: str | None, *, source_ip: str | None = None, minutes: int = 120, non_interactive: bool = False) -> int:
    if source_ip:
        return diagnose_server_client_workflow(deployment, source_ip=source_ip, minutes=minutes, non_interactive=non_interactive)
    if not 5 <= minutes <= 1440:
        raise AppError("--minutes должен быть в диапазоне 5..1440")
    deployment_name, _env_path, _env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=[ROLE_RU],
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
    )
    report = ssh_capture(
        targets[0],
        f"/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py front --since {minutes} --live-probes",
        as_root=True,
    )
    payload = _decode_agent_snapshot(report, "front")
    output_dir = _diagnostic_run_dir(deployment_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "front-ru-gateway.json"
    write_text(report_path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    front = payload.get("front", {})
    events = payload.get("events", {})
    print_header("Front diagnostics")
    print(f"deployment: {deployment_name}")
    print(f"window: {payload.get('window_minutes', minutes)}m")
    print(f"xray/nftables: {payload.get('services', {}).get('xray', '-')}/{payload.get('services', {}).get('nftables', '-')}")
    print(
        "events: "
        f"accepted={events.get('accepted', 0)}, udp={events.get('accepted_udp', 0)}, udp443={events.get('udp_443', 0)}, invalid_reality={events.get('invalid_reality', 0)}, "
        f"disabled_invalid={events.get('disabled_invalid', 0)}"
    )
    print(
        "front: "
        f"listening={front.get('listening', False)}, active={front.get('active_connections', 0)}, closing={front.get('closing_connections', 0)}, "
        f"rtt_p95_ms={front.get('rtt_ms', {}).get('p95', '-')}, retransmissions_lifetime={front.get('socket_retransmissions', 0)}, "
        f"retransmitted_bytes={front.get('bytes_retrans', 0)}, retransmit_ratio_pct={front.get('retransmit_ratio_pct', 0)}"
    )
    print(f"front retransmission scope: {front.get('socket_retransmissions_scope', 'unknown')}")
    print(
        f"front observation: {payload.get('observation', 'unknown')}; "
        f"degraded_sources={len(front.get('degraded_sources', []))}; "
        f"lifetime_loss_sources={len(front.get('loss_observed_sources', []))}; "
        f"closing_churn_sources={len(front.get('closing_churn_sources', []))}"
    )
    requirements = payload.get("probes", {}).get("requirements", {})
    failed_requirements = ",".join(name for name, passed in requirements.items() if passed is not True) or "-"
    print(
        "path: "
        f"{payload.get('verdicts', {}).get('server_path', 'inconclusive')}; "
        f"failed_requirements={failed_requirements}"
    )
    print(f"verdict: {payload.get('verdict', 'inconclusive')}")
    print(f"udp/443 policy: {payload.get('transport', {}).get('udp_443_policy', '-')}")
    public_client = payload.get("transport", {}).get("public_client", {})
    if public_client:
        print(
            "public QUIC: "
            f"configured={public_client.get('configured', False)}, listener={public_client.get('listening', False)}, "
            f"firewall={public_client.get('firewall', False)}"
        )
    print(f"report: {report_path}")
    return 1 if payload.get("verdict") == "failed" else 0


def diagnose_server_client_workflow(deployment: str | None, *, source_ip: str, minutes: int = 15, non_interactive: bool = False) -> int:
    """Collect structured public-front evidence for one source without touching a client."""
    if not _SOURCE_IP_RE.fullmatch(source_ip):
        raise AppError(f"Некорректный source IP: {source_ip}")
    if not 5 <= minutes <= 1440:
        raise AppError("--since должен быть в диапазоне 5..1440")
    deployment_name, _env_path, _env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=[ROLE_RU],
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
    )
    report = ssh_capture(
        targets[0],
        "/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py client "
        f"--source {shlex.quote(source_ip)} --since {minutes}",
        as_root=True,
    )
    payload = _decode_agent_snapshot(report, "client")
    output_dir = _diagnostic_run_dir(deployment_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "client-front-ru-gateway.json"
    write_text(report_path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    events = payload.get("events", {})
    client = payload.get("front", {}).get("client", {})
    print_header("Client front diagnostics")
    print(f"deployment: {deployment_name}")
    print(f"source: {source_ip}; window: {payload.get('window_minutes', minutes)}m")
    print(f"xray/nftables: {payload.get('services', {}).get('xray', '-')}/{payload.get('services', {}).get('nftables', '-')}")
    print(
        "events: "
        f"accepted={events.get('accepted', 0)}, udp={events.get('accepted_udp', 0)}, udp443={events.get('udp_443', 0)}, invalid_reality={events.get('invalid_reality', 0)}, "
        f"disabled_invalid={events.get('disabled_invalid', 0)}"
    )
    if client:
        print(
            "active sockets: "
            f"connections={client.get('connections', 0)}, quality={client.get('quality', 'unknown')}, "
            f"rtt_p95_ms={client.get('rtt_ms', {}).get('p95', '-')}, "
            f"rto_max_ms={client.get('rto_ms', {}).get('max', '-')}, "
            f"retransmissions_lifetime={client.get('retransmissions', 0)}, retransmitted_bytes={client.get('bytes_retrans', 0)}, "
            f"retransmit_ratio_pct={client.get('retransmit_ratio_pct', 0)}, pmtu={client.get('pmtu', '-')}, "
            f"reordering={client.get('reordering', '-')}, reord_seen={client.get('reord_seen', 0)}, "
            f"dsack_dups={client.get('dsack_dups', 0)}, rcv_ooopack={client.get('rcv_ooopack', 0)}, unacked={client.get('unacked', 0)}"
        )
    flows = payload.get("front", {}).get("flows", {})
    if flows:
        degraded_flows = sum(flow.get("quality") == "degraded" for flow in flows.values())
        loss_observed_flows = sum(flow.get("quality") == "loss_observed" for flow in flows.values())
        print(f"active flows: total={len(flows)}, degraded={degraded_flows}, lifetime_loss={loss_observed_flows}")
    recent_interval = payload.get("front", {}).get("recent_interval", {})
    if recent_interval:
        print(
            "fresh source interval: "
            f"quality={recent_interval.get('quality', 'unknown')}, "
            f"retrans={recent_interval.get('bytes_retrans', 0)}/{recent_interval.get('activity_bytes', 0)} "
            f"({recent_interval.get('retransmit_ratio_pct', 0)}%)"
        )
    verdict = payload.get("verdict", "inconclusive")
    verdict_basis = {
        "degraded": "Xray accepted the client; aggregate outer TCP quality is degraded",
        "loss_observed": "Xray accepted the client; open-socket lifetime counters contain loss, but no fresh degraded interval is available",
        "reached_xray": "Xray accepted the client; no active aggregate degradation was measured",
        "rejected_by_front": "the public front rejected the connection",
        "tcp_reached_no_xray_accept": "TCP reached port 443 without a matching Xray accept event",
        "not_seen_on_server": "no matching TCP/Xray evidence was observed",
    }.get(verdict, "")
    print(f"verdict: {verdict}{f'; basis: {verdict_basis}' if verdict_basis else ''}")
    print(f"udp/443 policy: {payload.get('transport', {}).get('udp_443_policy', '-')}")
    print(f"report: {report_path}")
    return 1 if payload.get("verdict") in {"degraded", "loss_observed", "rejected_by_front", "tcp_reached_no_xray_accept", "not_seen_on_server"} else 0

def _cleanup_iperf_rules(foreign: RemoteTarget) -> None:
    ssh_capture(
        foreign,
        "nft -a list chain inet vpnstack input 2>/dev/null | "
        "awk '/vpnstack-diag-iperf/ {print $NF}' | "
        "while read -r handle; do nft delete rule inet vpnstack input handle \"$handle\" 2>/dev/null || true; done; "
        "systemctl stop vpnstack-iperf3.service >/dev/null 2>&1 || true; "
        "systemctl reset-failed vpnstack-iperf3.service >/dev/null 2>&1 || true",
        as_root=True,
    )


def _run_iperf_smoke(output_dir: Path, targets: list[RemoteTarget]) -> None:
    target_map = {target.role: target for target in targets}
    if ROLE_RU not in target_map or ROLE_FOREIGN not in target_map:
        warn("iperf-проба требует обе роли, пропускаю.")
        return
    ru = target_map[ROLE_RU]
    foreign = target_map[ROLE_FOREIGN]
    tests = [
        ("tcp-ru-to-foreign-p1", "-t 8 -P 1"),
        ("tcp-foreign-to-ru-p1", "-t 8 -P 1 -R"),
        ("tcp-ru-to-foreign-p4", "-t 8 -P 4"),
        ("tcp-foreign-to-ru-p4", "-t 8 -P 4 -R"),
        ("udp-ru-to-foreign-25m", "-u -b 25M -l 1200 -t 8"),
        ("udp-foreign-to-ru-25m", "-u -b 25M -l 1200 -t 8 -R"),
        ("udp-ru-to-foreign-100m", "-u -b 100M -l 1200 -t 8"),
        ("udp-foreign-to-ru-100m", "-u -b 100M -l 1200 -t 8 -R"),
    ]
    try:
        _cleanup_iperf_rules(foreign)
        ssh_capture(
            foreign,
            "nft add rule inet vpnstack input iifname wg0 tcp dport 5201 counter accept comment vpnstack-diag-iperf; "
            "nft add rule inet vpnstack input iifname wg0 udp dport 5201 counter accept comment vpnstack-diag-iperf",
            as_root=True,
        )
        for name, args in tests:
            ssh_capture(
                foreign,
                "systemctl stop vpnstack-iperf3.service >/dev/null 2>&1 || true; "
                "systemctl reset-failed vpnstack-iperf3.service >/dev/null 2>&1 || true; "
                "rm -f /tmp/vpnstack-iperf3.log; "
                "systemd-run --unit=vpnstack-iperf3 --property=RuntimeMaxSec=35 "
                "--property=StandardOutput=append:/tmp/vpnstack-iperf3.log "
                "--property=StandardError=append:/tmp/vpnstack-iperf3.log "
                "/usr/bin/iperf3 -s -B 10.74.0.2 -p 5201 --one-off >/dev/null",
                as_root=True,
            )
            time.sleep(1.0)
            client = ssh_capture(
                ru,
                f"timeout 35 iperf3 -c 10.74.0.2 -B 10.74.0.1 -p 5201 {args} 2>&1 || true",
                as_root=True,
            )
            server = ssh_capture(foreign, "cat /tmp/vpnstack-iperf3.log 2>/dev/null || true", as_root=True)
            write_text(output_dir / f"iperf-{name}.txt", f"## client\n{client}\n## server\n{server}\n")
    finally:
        _cleanup_iperf_rules(foreign)


def diagnose_path_workflow(deployment: str | None, role: str, *, iperf: bool = False, non_interactive: bool = False) -> int:
    roles = requested_roles(role)
    deployment_name, _env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
    )
    output_dir = _diagnostic_run_dir(deployment_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    print_header("Path diagnostics")
    with ThreadPoolExecutor(max_workers=max(1, len(targets))) as executor:
        future_to_target = {}
        for target in targets:
            print(f"{target.label}: собираю диагностику")
            future_to_target[
                executor.submit(
                    ssh_capture,
                    target,
                    "/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py "
                    "snapshot --live-probes --profile acceptance",
                    as_root=True,
                    command_timeout=PATH_DIAGNOSE_COMMAND_TIMEOUT,
                )
            ] = target
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                report = future.result()
            except AppError as exc:
                report = f"diagnose_error={exc}\n"
                warn(f"{target.label}: диагностика завершилась неполно: {exc}")
            try:
                snapshot = _decode_agent_snapshot(report, f"{target.role} path")
                rendered = json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            except AppError:
                rendered = report
            write_text(output_dir / f"{target.role}.json", rendered)

    if iperf:
        print("Запускаю bounded iperf smoke через wg0.")
        _run_iperf_smoke(output_dir, targets)

    if not any(output_dir.iterdir()):
        raise AppError("Диагностика не собрала ни одного файла.")
    print(f"Диагностика сохранена: {output_dir}")
    return 0


def _print_nonzero_bucket_summary(summary: dict[str, object]) -> None:
    counts = summary["counts"]
    top_destinations = summary["top_destinations"]
    samples = summary["samples"]
    assert isinstance(counts, dict)
    assert isinstance(top_destinations, dict)
    assert isinstance(samples, dict)
    for bucket in BUCKETS:
        count = int(counts.get(bucket, 0))
        if count <= 0:
            continue
        print(f"{bucket}: {count}")
        destinations = top_destinations.get(bucket)
        if destinations:
            rendered = ", ".join(f"{destination}={value}" for destination, value in dict(destinations).items())
            print(f"  top: {rendered}")
        sample = samples.get(bucket)
        if sample:
            print(f"  sample: {sample}")


def diagnose_client_log_workflow(log_path: str, deployment: str | None = None, role: str = "all") -> int:
    path = Path(log_path)
    if not path.is_file():
        raise AppError(f"Файл лога не найден: {path}")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    summary = summarize_lines(lines)
    print_header("Client log diagnostics")
    print(f"log: {path}")
    print(f"lines: {len(lines)}")
    _print_nonzero_bucket_summary(summary)

    counts = summary["counts"]
    assert isinstance(counts, dict)
    if int(counts.get("client_front_connect_failed", 0)) > 0:
        print(
            "diagnosis: клиент не смог подключиться к public VPN endpoint до входа в Xray; "
            "DNS и сайты после этого могут падать вторично."
        )

    if deployment is None:
        return 0

    deployment_name = select_existing_deployment(deployment)
    env_path, env = load_existing_deployment_env(deployment_name)
    state = load_state(deployment_name)
    route_failed = False
    print_header("Client route diagnostics")
    for selected_role in requested_roles(role):
        target = build_target(selected_role, env, state)
        route_info = local_route_to_server(target)
        public_ip = target.public_ip or target.ssh_host or "-"
        if route_info is None:
            print(f"{target.label}: route check unavailable; ip={public_ip}")
            continue
        self_tunnel = route_uses_self_tunnel(route_info, client_tun_name=env.get("CLIENT_TUN_NAME", ""))
        verdict = "BAD: self-tunnel" if self_tunnel else "OK"
        print(
            f"{target.label}: {verdict}; ip={route_info.target_ip}; "
            f"iface={route_info.interface_alias or '-'}; source={route_info.source_address or '-'}; next-hop={route_info.next_hop or '-'}"
        )
        route_failed = route_failed or self_tunnel
    if route_failed:
        paths = client_artifact_paths(env)
        print("diagnosis: IP сервера уходит через VPN-интерфейс; это ломает Reality/VLESS connect до входа на сервер.")
        print(f"Windows bypass helper: {paths['windows_route_bypass']}")
        print(f"Route-safe JSON: {paths['hiddify_json']}")
    print(f"Deployment env: {env_path}")
    return 1 if route_failed or int(counts.get("client_front_connect_failed", 0)) > 0 else 0
