from __future__ import annotations

import json
import shlex
import tempfile
import time
from pathlib import Path
from . import workflows
from .common import OUT_DIR, print_header
from .diagnostics import DiagnosticsSnapshot
from .models import ROLE_FOREIGN, ROLE_RU, UDP_RMEM_DEFAULT, UDP_RMEM_MAX
from .remote import remote_agent_snapshot, scp_upload, ssh_capture
from .roles import requested_roles
from .vless_verify import (
    RUNNER_HTTP_PROBE_COUNT,
    RUNNER_HTTP_TIMEOUT_SECONDS,
    RUNNER_CURL_WATCHDOG_KILL_SECONDS,
    RUNNER_REPORT_SECONDS,
    RUNNER_SHUTDOWN_SECONDS,
    RUNNER_STARTUP_SECONDS,
    RUNNER_THROUGHPUT_CLOCK_SKEW_SECONDS,
    RUNNER_TRANSPORT_DRAIN_SECONDS,
    RUNNER_ROUTE_PROBE_TIMEOUT_SECONDS,
    parse_vless_uri,
    render_ephemeral_singbox_client,
    render_socks5_udp_dns_probe,
    render_vless_runner,
)


VLESS_RUNNER_POLL_INTERVAL_SECONDS = 15
VLESS_CAPACITY_FLOOR_BYTES_PER_SECOND = 6_250_000


def _verify_snapshot(snapshot: DiagnosticsSnapshot) -> DiagnosticsSnapshot:
    hard_failures: list[str] = []
    degradations: list[str] = []
    for service_name, state in snapshot.services.items():
        required_services = {"wireguard", "nftables"}
        if snapshot.role == ROLE_RU:
            required_services.add("sing-box")
        if service_name in required_services and state and state != "active":
            hard_failures.append(f"{service_name}={state}")
    if snapshot.role == ROLE_RU and snapshot.services.get("xray") != "active":
        hard_failures.append(f"xray={snapshot.services.get('xray')}")
    if snapshot.drift == "server-mutated":
        hard_failures.append("installed config hash differs from render manifest")
    elif snapshot.drift == "unknown":
        degradations.append("render manifest is missing or incomplete")
    tcp_adaptation = snapshot.network.get("tcp_adaptation", {})
    if not tcp_adaptation:
        hard_failures.append("network adaptation fields are missing")
    elif str(tcp_adaptation.get("mtu_probing", "")).strip() != "1":
        degradations.append("TCP PLPMTUD adaptation is disabled")
    try:
        rmem_default = int(tcp_adaptation.get("udp_rmem_default", 0))
        rmem_max = int(tcp_adaptation.get("udp_rmem_max", 0))
    except (TypeError, ValueError):
        rmem_default = rmem_max = 0
    if tcp_adaptation and (rmem_default < UDP_RMEM_DEFAULT or rmem_max < UDP_RMEM_MAX):
        degradations.append("UDP receive buffer profile is not active")
    required_verdicts = {"server_path", "public_front", "client_observation"}
    if not required_verdicts.issubset(snapshot.component_verdicts):
        hard_failures.append("agent verdict fields are incomplete")
    server_path = snapshot.component_verdicts.get("server_path", "inconclusive")
    public_front = snapshot.component_verdicts.get("public_front", "not-applicable")
    client_observation = snapshot.component_verdicts.get("client_observation", "not-applicable")
    if server_path == "failed":
        hard_failures.append("agent server_path failed")
    elif server_path != "verified":
        degradations.append(f"agent server_path={server_path}")
    if public_front == "failed":
        hard_failures.append("agent public_front failed")
    elif snapshot.role == ROLE_RU and public_front != "verified":
        degradations.append(f"agent public_front={public_front}")
    if client_observation in {"client_specific", "degraded"}:
        degradations.append("public TCP front shows retransmission or socket churn")
    if snapshot.route_probes.get("profile") != "acceptance":
        hard_failures.append("acceptance probes did not run")
    elif "release_gate_ok" in snapshot.route_probes:
        if snapshot.route_probes.get("release_gate_ok") is not True:
            hard_failures.append("acceptance release gate failed")
        elif snapshot.route_probes.get("ok") is not True:
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


def _validate_public_vless_result(result: dict[str, object], uri, foreign_target, *, throughput_seconds: int = 0) -> dict[str, object]:
    statuses = {str(result.get("github_status", "")), str(result.get("google_status", ""))}
    expected_foreign_ip = foreign_target.public_ip or foreign_target.ssh_host
    if result.get("ru_egress_ip") != uri.host:
        return {"verdict": "failed", "reason": f"public VLESS direct identity mismatch: expected {uri.host}, got {result.get('ru_egress_ip', '')}", "result": result}
    if result.get("foreign_egress_ip") != expected_foreign_ip:
        return {"verdict": "failed", "reason": f"public VLESS foreign identity mismatch: expected {expected_foreign_ip}, got {result.get('foreign_egress_ip', '')}", "result": result}
    if not statuses.issubset({"200", "204", "301", "302", "403"}):
        return {"verdict": "failed", "reason": f"public VLESS path returned invalid probes: {result}", "result": result}
    udp_dns = result.get("udp_dns", {})
    if not isinstance(udp_dns, dict) or udp_dns.get("ok") is not True:
        return {"verdict": "failed", "reason": f"public VLESS UDP probe failed: {result}", "result": result}
    private_reject = udp_dns.get("private_reject", {})
    if not isinstance(private_reject, dict) or private_reject.get("ok") is not True:
        return {"verdict": "failed", "reason": f"public VLESS private/fake reject probe failed: {result}", "result": result}
    if str(result.get("ipv6_literal_status", "")) != "200":
        return {"verdict": "failed", "reason": f"public VLESS IPv6 literal probe failed: {result}", "result": result}
    if throughput_seconds:
        measurement = result.get("throughput", {})
        if not isinstance(measurement, dict):
            return {"verdict": "failed", "reason": "public VLESS throughput measurement is missing", "result": result}
        try:
            speed_bps = float(measurement.get("bytes_per_second", 0) or 0)
            duration = float(measurement.get("duration_seconds", 0) or 0)
            failures = int(measurement.get("failures", 0) or 0)
        except (TypeError, ValueError):
            return {"verdict": "failed", "reason": f"public VLESS throughput measurement is malformed: {measurement}", "result": result}
        if failures:
            return {"verdict": "failed", "reason": f"public VLESS throughput had {failures} transfer failures", "result": result}
        if speed_bps < VLESS_CAPACITY_FLOOR_BYTES_PER_SECOND:
            return {"verdict": "failed", "reason": f"public VLESS throughput below 50 Mbit/s: {speed_bps * 8 / 1_000_000:.2f} Mbit/s", "result": result}
        if duration < throughput_seconds:
            return {"verdict": "failed", "reason": f"public VLESS throughput window too short: {duration:.1f}s of {throughput_seconds}s", "result": result}
    return {"verdict": "verified", "result": result}


def _vless_runner_timeout(throughput_seconds: int) -> int:
    """Return the runner's explicit network/process upper bound plus SSH drain."""

    return (
        RUNNER_STARTUP_SECONDS
        + RUNNER_HTTP_PROBE_COUNT * RUNNER_HTTP_TIMEOUT_SECONDS
        + RUNNER_ROUTE_PROBE_TIMEOUT_SECONDS
        + throughput_seconds
        + RUNNER_THROUGHPUT_CLOCK_SKEW_SECONDS
        + (RUNNER_CURL_WATCHDOG_KILL_SECONDS if throughput_seconds else 0)
        + RUNNER_SHUTDOWN_SECONDS
        + RUNNER_REPORT_SECONDS
        + RUNNER_TRANSPORT_DRAIN_SECONDS
    )


def _start_vless_runner(target, remote_runner: str, remote_config: str, remote_udp_probe: str, *, throughput_seconds: int, result_path: str, error_path: str) -> str:
    command = (
        f"setsid bash {shlex.quote(remote_runner)} {shlex.quote(remote_config)} {shlex.quote(remote_udp_probe)} {throughput_seconds} "
        f"> {shlex.quote(result_path)} 2> {shlex.quote(error_path)} < /dev/null & printf '%s\\n' \"$!\""
    )
    pid = ssh_capture(target, command, command_timeout=20).strip()
    if not pid.isdecimal():
        raise RuntimeError(f"external VLESS runner did not return a PID: {pid!r}")
    return pid


def _vless_runner_state_command(pid: str, result_path: str, error_path: str) -> str:
    return (
        f"if test -s {shlex.quote(result_path)}; then printf '%s\\n' completed; cat {shlex.quote(result_path)}; "
        f"elif kill -0 {shlex.quote(pid)} 2>/dev/null; then printf '%s\\n' running; "
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


def _wait_for_vless_runner(target, pid: str, result_path: str, error_path: str, *, throughput_seconds: int) -> dict[str, object]:
    deadline = time.monotonic() + _vless_runner_timeout(throughput_seconds)
    while True:
        response = ssh_capture(target, _vless_runner_state_command(pid, result_path, error_path), command_timeout=20)
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


def _verify_public_vless_uri(uri_path: Path, foreign_target, *, throughput_seconds: int = 0) -> dict[str, object]:
    if not uri_path.is_file():
        return {"verdict": "failed", "reason": f"primary VLESS URI is missing: {uri_path}"}
    try:
        uri = parse_vless_uri(uri_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as exc:
        return {"verdict": "failed", "reason": f"primary VLESS URI is invalid: {exc}"}
    if throughput_seconds < 0 or 0 < throughput_seconds < 30:
        return {"verdict": "failed", "reason": "throughput-seconds must be 0 or at least 30"}
    try:
        remote_dir = ssh_capture(foreign_target, "mktemp -d /tmp/vpn-stack-vless-verify.XXXXXX", command_timeout=15).strip()
    except Exception as exc:  # noqa: BLE001
        return {"verdict": "failed", "reason": f"could not start external VLESS runner: {exc}"}
    if not remote_dir.startswith("/tmp/"):
        return {"verdict": "failed", "reason": "could not allocate external VLESS runner"}
    listen_port = 18080
    with tempfile.TemporaryDirectory(prefix="vpn-stack-vless-") as temp_dir:
        local_config = Path(temp_dir) / "sing-box.json"
        local_udp_probe = Path(temp_dir) / "udp-probe.py"
        local_runner = Path(temp_dir) / "runner.sh"
        local_config.write_text(render_ephemeral_singbox_client(uri, listen_port=listen_port), encoding="utf-8")
        local_udp_probe.write_text(render_socks5_udp_dns_probe(listen_port=listen_port), encoding="utf-8")
        # Bash must retain LF on a Windows control host; write bytes deliberately.
        local_runner.write_bytes(render_vless_runner(listen_port=listen_port).encode("utf-8"))
        remote_config = f"{remote_dir}/sing-box.json"
        remote_udp_probe = f"{remote_dir}/udp-probe.py"
        remote_runner = f"{remote_dir}/runner.sh"
        remote_result = f"{remote_dir}/result.json"
        remote_error = f"{remote_dir}/runner.stderr"
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
            )
            result = _wait_for_vless_runner(
                foreign_target,
                runner_pid,
                remote_result,
                remote_error,
                throughput_seconds=throughput_seconds,
            )
            runner_completed = True
        except (ValueError, OSError, RuntimeError) as exc:
            return {"verdict": "failed", "reason": f"public VLESS path failed: {exc}"}
        finally:
            if runner_pid and not runner_completed:
                _stop_vless_runner(foreign_target, runner_pid, remote_error)
            try:
                ssh_capture(foreign_target, f"rm -rf {shlex.quote(remote_dir)}", command_timeout=15)
            except Exception:  # noqa: BLE001
                pass
    return _validate_public_vless_result(result, uri, foreign_target, throughput_seconds=throughput_seconds)


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
    snapshots: list[DiagnosticsSnapshot] = []
    worst = "verified"
    rank = {"verified": 0, "degraded": 1, "inconclusive": 2, "failed": 3}
    for target in targets:
        try:
            snapshot = _collect_agent_snapshot(target)
            snapshot.deployment = deployment_name
            snapshot = _verify_snapshot(snapshot)
        except Exception as exc:  # noqa: BLE001
            snapshot = DiagnosticsSnapshot(deployment=deployment_name, role=target.role, verdict="failed", reasons=[f"agent snapshot failed: {exc}"])
        snapshots.append(snapshot)
    foreign_target = next((target for target in targets if target.role == ROLE_FOREIGN), None)
    public_vless: dict[str, object] = {"verdict": "inconclusive", "reason": "foreign verifier is unavailable"}
    if foreign_target is not None:
        public_vless = _verify_public_vless_uri(OUT_DIR / deployment_name / "client" / "vless-uri.txt", foreign_target, throughput_seconds=throughput_seconds)
    snapshots = [_reconcile_public_capabilities(snapshot, public_vless) for snapshot in snapshots]
    for verdict in [*(snapshot.verdict for snapshot in snapshots), str(public_vless["verdict"])]:
        if rank[verdict] > rank[worst]:
            worst = verdict
    print_header("Live verification result")
    print(f"verify verdict: {worst}")
    for snapshot in snapshots:
        reason_text = "; ".join(snapshot.reasons) if snapshot.reasons else "fresh probes and installed manifest are consistent"
        print(f"{snapshot.role or 'unknown'}: {snapshot.verdict} - {reason_text}")
    print(f"public-vless-uri: {public_vless['verdict']} - {public_vless.get('reason', public_vless.get('result', ''))}")
    print(f"Deployment env: {Path(env_path)}")
    return 0 if worst == "verified" else 1
