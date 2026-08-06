from __future__ import annotations

import json
import shlex
import tempfile
import time
from pathlib import Path
from . import workflows
from .common import OUT_DIR, print_header
from .diagnostics import DiagnosticsSnapshot
from .models import (
    ROLE_FOREIGN,
    ROLE_RU,
)
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
from .roles import requested_roles
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
    THROUGHPUT_CAPACITY_SECONDS,
    THROUGHPUT_STABILITY_FLOOR_BYTES_PER_SECOND,
    parse_vless_uri,
    render_ephemeral_singbox_client,
    render_socks5_udp_dns_probe,
    render_vless_runner,
)


VLESS_RUNNER_POLL_INTERVAL_SECONDS = 5
PRIMARY_CAPACITY_FLOOR_BYTES_PER_SECOND = 6_250_000
FALLBACK_CAPACITY_FLOOR_BYTES_PER_SECOND = 1_250_000
VLESS_RUNNER_LOCK_PATH = "/run/lock/vpn-stack-vless-verify.lock"


def _verify_snapshot(snapshot: DiagnosticsSnapshot) -> DiagnosticsSnapshot:
    hard_failures: list[str] = []
    degradations: list[str] = []
    required_services = {"wireguard", "nftables", "sing-box", "resolver"}
    for service_name in sorted(required_services):
        state = snapshot.services.get(service_name)
        if state != "active":
            hard_failures.append(f"{service_name}={state or 'missing'}")
    if snapshot.role == ROLE_RU and snapshot.services.get("xray") != "active":
        hard_failures.append(f"xray={snapshot.services.get('xray')}")
    if snapshot.role == ROLE_RU and (
        snapshot.front.get("tcp_keepalive_idle_seconds") != 90
        or snapshot.front.get("tcp_keepalive_interval_seconds") != 15
    ):
        hard_failures.append("public TCP front keepalive policy is missing")
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
    required_verdicts = {"server_path", "public_front", "client_observation", "host_integrity"}
    if snapshot.role == ROLE_RU:
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
    if public_front == "failed":
        hard_failures.append("agent public_front failed")
    elif snapshot.role == ROLE_RU and public_front != "verified":
        degradations.append(f"agent public_front={public_front}")
    if snapshot.role == ROLE_RU and public_quic != "verified":
        hard_failures.append(f"agent public_quic={public_quic}")
    if client_observation in {"client_specific", "degraded"}:
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
    if public_vless.get("verdict") != "verified":
        return snapshot
    snapshot.reasons = [reason for reason in snapshot.reasons if reason != "external capability probe failed"]
    if snapshot.verdict == "degraded" and not snapshot.reasons:
        snapshot.verdict = "verified"
    return snapshot


def _validate_public_transport_result(
    result: dict[str, object],
    expected_ru_ip: str,
    foreign_target,
    *,
    label: str,
    throughput_seconds: int = 0,
    capacity_floor_bytes_per_second: int = PRIMARY_CAPACITY_FLOOR_BYTES_PER_SECOND,
) -> dict[str, object]:
    statuses = {str(result.get("github_status", "")), str(result.get("google_status", ""))}
    expected_foreign_ip = foreign_target.public_ip or foreign_target.ssh_host
    if result.get("ru_egress_ip") != expected_ru_ip:
        return {"verdict": "failed", "reason": f"{label} direct identity mismatch: expected {expected_ru_ip}, got {result.get('ru_egress_ip', '')}", "result": result}
    if result.get("foreign_egress_ip") != expected_foreign_ip:
        return {"verdict": "failed", "reason": f"{label} foreign identity mismatch: expected {expected_foreign_ip}, got {result.get('foreign_egress_ip', '')}", "result": result}
    if not statuses.issubset({"200", "204", "301", "302", "403"}):
        return {"verdict": "failed", "reason": f"{label} returned invalid probes: {result}", "result": result}
    udp_dns = result.get("udp_dns", {})
    if not isinstance(udp_dns, dict) or udp_dns.get("ok") is not True:
        return {"verdict": "failed", "reason": f"{label} UDP probe failed: {result}", "result": result}
    private_reject = udp_dns.get("private_reject", {})
    if not isinstance(private_reject, dict) or private_reject.get("ok") is not True:
        return {"verdict": "failed", "reason": f"{label} private/fake reject probe failed: {result}", "result": result}
    if str(result.get("ipv6_literal_status", "")) != "200":
        return {"verdict": "failed", "reason": f"{label} IPv6 literal probe failed: {result}", "result": result}
    reliability = result.get("first_load_reliability", {})
    if not isinstance(reliability, dict):
        return {"verdict": "failed", "reason": f"{label} first-load reliability result is missing", "result": result}
    try:
        attempts = int(reliability.get("attempts", 0) or 0)
        successes = int(reliability.get("successes", 0) or 0)
        failures = int(reliability.get("failures", 0) or 0)
        max_total = float(reliability.get("max_total_seconds", 0) or 0)
    except (TypeError, ValueError):
        return {"verdict": "failed", "reason": f"{label} first-load reliability result is malformed: {reliability}", "result": result}
    if attempts != RUNNER_RELIABILITY_ATTEMPTS or successes != attempts or failures:
        return {"verdict": "failed", "reason": f"{label} first-load reliability failed: {reliability}", "result": result}
    if max_total <= 0 or max_total > RUNNER_RELIABILITY_MAX_TOTAL_SECONDS:
        return {
            "verdict": "failed",
            "reason": f"{label} first-load latency exceeded {RUNNER_RELIABILITY_MAX_TOTAL_SECONDS:.1f}s: {reliability}",
            "result": result,
        }
    if throughput_seconds:
        measurement = result.get("throughput", {})
        if not isinstance(measurement, dict):
            return {"verdict": "failed", "reason": f"{label} throughput measurement is missing", "result": result}
        try:
            speed_bps = float(measurement.get("capacity_bytes_per_second", measurement.get("bytes_per_second", 0)) or 0)
            duration = float(measurement.get("duration_seconds", 0) or 0)
            failures = int(measurement.get("failures", 0) or 0)
            source_failures = int(measurement.get("source_failures", 0) or 0)
            source_metrics = measurement.get("source_metrics", [])
            if not isinstance(source_metrics, list):
                source_metrics = []
            successful_sources = int(
                measurement.get("successful_sources", int(speed_bps > 0 and source_failures == 0)) or 0
            )
            required_successful_sources = int(measurement.get("required_successful_sources", 1) or 1)
            stability_bps = float(measurement.get("stability_bytes_per_second", 0) or 0)
            stability_duration = float(measurement.get("stability_duration_seconds", 0) or 0)
        except (TypeError, ValueError):
            return {"verdict": "failed", "reason": f"{label} throughput measurement is malformed: {measurement}", "result": result}
        if failures:
            return {"verdict": "failed", "reason": f"{label} throughput had {failures} transfer failures", "result": result}
        if successful_sources < required_successful_sources:
            return {
                "verdict": "failed",
                "reason": (
                    f"{label} throughput source coverage is insufficient: "
                    f"{successful_sources}/{required_successful_sources} successful, "
                    f"failures={source_failures}, metrics={source_metrics}"
                ),
                "result": result,
            }
        if speed_bps < capacity_floor_bytes_per_second:
            floor_mbps = capacity_floor_bytes_per_second * 8 / 1_000_000
            return {"verdict": "failed", "reason": f"{label} capacity below {floor_mbps:g} Mbit/s: {speed_bps * 8 / 1_000_000:.2f} Mbit/s", "result": result}
        expected_stability_seconds = max(0, throughput_seconds - THROUGHPUT_CAPACITY_SECONDS)
        if expected_stability_seconds and stability_bps < THROUGHPUT_STABILITY_FLOOR_BYTES_PER_SECOND:
            return {"verdict": "failed", "reason": f"{label} sustained rate below 10 Mbit/s: {stability_bps * 8 / 1_000_000:.2f} Mbit/s", "result": result}
        if stability_duration + 0.5 < expected_stability_seconds:
            return {"verdict": "failed", "reason": f"{label} stability window too short: {stability_duration:.1f}s of {expected_stability_seconds}s", "result": result}
        if duration + 0.5 < throughput_seconds:
            return {"verdict": "failed", "reason": f"{label} throughput window too short: {duration:.1f}s of {throughput_seconds}s", "result": result}
    return {"verdict": "verified", "result": result}


def _validate_public_vless_result(result: dict[str, object], uri, foreign_target, *, throughput_seconds: int = 0) -> dict[str, object]:
    return _validate_public_transport_result(
        result,
        uri.host,
        foreign_target,
        label="public VLESS",
        throughput_seconds=throughput_seconds,
    )


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
        raise RuntimeError(f"external VLESS runner did not return a PID: {pid!r}")
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
                raise RuntimeError("external VLESS runner completed without a result payload")
            return json.loads(payload)
        if state == "exited":
            detail = payload.strip()
            raise RuntimeError(f"external VLESS runner exited before result{f': {detail}' if detail else ''}")
        if state != "running":
            raise RuntimeError(f"external VLESS runner returned an invalid state: {state!r}")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            detail = _stop_vless_runner(target, pid, error_path)
            raise RuntimeError(f"external VLESS runner exceeded its {_vless_runner_timeout(throughput_seconds)}s budget{f': {detail}' if detail else ''}")
        time.sleep(min(VLESS_RUNNER_POLL_INTERVAL_SECONDS, remaining))


def _run_external_public_profile(
    config_text: str,
    foreign_target,
    *,
    label: str,
    throughput_seconds: int = 0,
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
        local_udp_probe.write_text(render_socks5_udp_dns_probe(listen_port=listen_port), encoding="utf-8")
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
            result = _wait_for_vless_runner(
                foreign_target,
                runner_pid,
                remote_result,
                remote_error,
                remote_lease,
                throughput_seconds=throughput_seconds,
            )
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


def _verify_public_vless_uri(uri_path: Path, foreign_target, *, throughput_seconds: int = 0) -> dict[str, object]:
    if not uri_path.is_file():
        return {"verdict": "failed", "reason": f"primary VLESS URI is missing: {uri_path}"}
    try:
        uri = parse_vless_uri(uri_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        return {"verdict": "failed", "reason": f"primary VLESS URI is invalid: {exc}"}
    run_result = _run_external_public_profile(
        render_ephemeral_singbox_client(uri, listen_port=18080),
        foreign_target,
        label="public VLESS",
        throughput_seconds=throughput_seconds,
    )
    if run_result.get("verdict") != "completed":
        return run_result
    return _validate_public_vless_result(
        run_result["result"],
        uri,
        foreign_target,
        throughput_seconds=throughput_seconds,
    )


def _verify_public_hysteria2(env: dict[str, str], foreign_target, *, throughput_seconds: int = 0) -> dict[str, object]:
    payload = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 18080, "tag": "verify-in"}],
        "outbounds": [render_public_hy2_outbound(env)],
        "route": {"final": PUBLIC_HY2_OUTBOUND_TAG},
    }
    run_result = _run_external_public_profile(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        foreign_target,
        label="public Hysteria2",
        throughput_seconds=throughput_seconds,
    )
    if run_result.get("verdict") != "completed":
        return run_result
    return _validate_public_transport_result(
        run_result["result"],
        env["RU_PUBLIC_IP"],
        foreign_target,
        label="public Hysteria2",
        throughput_seconds=throughput_seconds,
        capacity_floor_bytes_per_second=FALLBACK_CAPACITY_FLOOR_BYTES_PER_SECOND,
    )


def verify_live_workflow(deployment: str | None, *, non_interactive: bool = False, throughput_seconds: int = 0) -> int:
    print_header("Live verification")
    roles = requested_roles("all")
    deployment_name, env_path, env, _state, targets, _preflights_by_role = workflows.prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
        run_live_probes=False,
    )
    workflows.print_summary(deployment_name, env, targets)
    worst = "verified"
    rank = {"verified": 0, "degraded": 1, "inconclusive": 2, "failed": 3}
    foreign_target = next((target for target in targets if target.role == ROLE_FOREIGN), None)
    public_vless: dict[str, object] = {"verdict": "inconclusive", "reason": "foreign verifier is unavailable"}
    public_hysteria2: dict[str, object] = {"verdict": "inconclusive", "reason": "foreign verifier is unavailable"}
    if foreign_target is not None:
        public_vless = _verify_public_vless_uri(OUT_DIR / deployment_name / "client" / "vless-uri.txt", foreign_target, throughput_seconds=throughput_seconds)
        public_hysteria2 = _verify_public_hysteria2(env, foreign_target, throughput_seconds=throughput_seconds)
    snapshots: list[DiagnosticsSnapshot] = []
    for target in targets:
        try:
            snapshot = _collect_agent_snapshot(target)
            snapshot.deployment = deployment_name
            snapshot = _verify_snapshot(snapshot)
        except Exception as exc:  # noqa: BLE001
            snapshot = DiagnosticsSnapshot(deployment=deployment_name, role=target.role, verdict="failed", reasons=[f"agent snapshot failed: {exc}"])
        snapshots.append(snapshot)
    snapshots = [_reconcile_public_capabilities(snapshot, public_vless) for snapshot in snapshots]
    report_dir = OUT_DIR / "diagnostics" / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{deployment_name}"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "live-verify.json"
    report_path.write_text(
        json.dumps(
            {
                "deployment": deployment_name,
                "throughput_seconds": throughput_seconds,
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
    for verdict in [*(snapshot.verdict for snapshot in snapshots), str(public_vless["verdict"]), str(public_hysteria2["verdict"])]:
        if rank[verdict] > rank[worst]:
            worst = verdict
    print_header("Live verification result")
    print(f"verify verdict: {worst}")
    for snapshot in snapshots:
        reason_text = "; ".join(snapshot.reasons) if snapshot.reasons else "fresh probes and installed manifest are consistent"
        print(f"{snapshot.role or 'unknown'}: {snapshot.verdict} - {reason_text}")
    print(f"public-vless-uri: {public_vless['verdict']} - {public_vless.get('reason', public_vless.get('result', ''))}")
    print(f"public-hysteria2: {public_hysteria2['verdict']} - {public_hysteria2.get('reason', public_hysteria2.get('result', ''))}")
    print(f"report: {report_path}")
    print(f"Deployment env: {Path(env_path)}")
    return 0 if worst == "verified" else 1
