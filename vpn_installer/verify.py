from __future__ import annotations

import json
import shlex
import tempfile
from pathlib import Path
from . import workflows
from .common import OUT_DIR, print_header
from .diagnostics import DiagnosticsSnapshot
from .models import ROLE_FOREIGN, ROLE_RU
from .remote import remote_agent_snapshot, scp_upload, ssh_capture
from .roles import requested_roles
from .vless_verify import parse_vless_uri, render_ephemeral_singbox_client


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
    if client_observation == "degraded":
        degradations.append("public TCP front shows retransmission or socket churn")
    if snapshot.route_probes.get("profile") != "acceptance":
        hard_failures.append("acceptance probes did not run")
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


def _validate_public_vless_result(result: dict[str, object], uri, foreign_target, *, throughput_seconds: int = 0) -> dict[str, object]:
    statuses = {str(result.get("github_status", "")), str(result.get("google_status", ""))}
    expected_foreign_ip = foreign_target.public_ip or foreign_target.ssh_host
    if result.get("ru_egress_ip") != uri.host:
        return {"verdict": "failed", "reason": f"public VLESS direct identity mismatch: expected {uri.host}, got {result.get('ru_egress_ip', '')}", "result": result}
    if result.get("foreign_egress_ip") != expected_foreign_ip:
        return {"verdict": "failed", "reason": f"public VLESS foreign identity mismatch: expected {expected_foreign_ip}, got {result.get('foreign_egress_ip', '')}", "result": result}
    if not statuses.issubset({"200", "204", "301", "302", "403"}):
        return {"verdict": "failed", "reason": f"public VLESS path returned invalid probes: {result}", "result": result}
    if throughput_seconds:
        measurement = result.get("throughput", {})
        if not isinstance(measurement, dict):
            return {"verdict": "failed", "reason": "public VLESS throughput measurement is missing", "result": result}
        speed_bps = float(measurement.get("bytes_per_second", 0) or 0)
        duration = float(measurement.get("duration_seconds", 0) or 0)
        if speed_bps < 1_250_000:
            return {"verdict": "failed", "reason": f"public VLESS throughput below 10 Mbit/s: {speed_bps * 8 / 1_000_000:.2f} Mbit/s", "result": result}
        if duration < throughput_seconds * 0.9:
            return {"verdict": "failed", "reason": f"public VLESS throughput window too short: {duration:.1f}s of {throughput_seconds}s", "result": result}
    return {"verdict": "verified", "result": result}


def _vless_runner_timeout(throughput_seconds: int) -> int:
    return max(60, throughput_seconds + 60)


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
        local_config.write_text(render_ephemeral_singbox_client(uri, listen_port=listen_port), encoding="utf-8")
        remote_config = f"{remote_dir}/sing-box.json"
        try:
            scp_upload(foreign_target, local_config, remote_config)
            commands = [
                    "set -euo pipefail",
                    f"cd {shlex.quote(remote_dir)}",
                    "sing-box check -c sing-box.json",
                    "sing-box run -c sing-box.json >sing-box.log 2>&1 &",
                    "pid=$!",
                    "cleanup() { kill \"$pid\" >/dev/null 2>&1 || true; wait \"$pid\" >/dev/null 2>&1 || true; }",
                    "trap cleanup EXIT",
                    "sleep 1",
                    "kill -0 \"$pid\"",
                    f"ru_ip=$(curl -4fsS --proxy socks5h://127.0.0.1:{listen_port} --connect-timeout 5 --max-time 15 https://api.ipify.org)",
                    f"foreign_ip=$(curl -4fsS --proxy socks5h://127.0.0.1:{listen_port} --connect-timeout 5 --max-time 15 https://www.cloudflare.com/cdn-cgi/trace | awk -F= '/^ip=/{{print $2; exit}}')",
                    f"github=$(curl -4sS -o /dev/null -w '%{{http_code}}' --proxy socks5h://127.0.0.1:{listen_port} --connect-timeout 5 --max-time 15 https://github.com/)",
                    f"google=$(curl -4sS -o /dev/null -w '%{{http_code}}' --proxy socks5h://127.0.0.1:{listen_port} --connect-timeout 5 --max-time 15 https://www.google.com/generate_204)",
            ]
            if throughput_seconds:
                throughput_bytes = throughput_seconds * 1_500_000
                commands.extend(
                    [
                        f"throughput=$(curl -4fsS --proxy socks5h://127.0.0.1:{listen_port} --connect-timeout 5 --max-time {throughput_seconds + 20} --limit-rate 1500k --range 0-{throughput_bytes - 1} -o /dev/null -w '%{{speed_download}}|%{{time_total}}' https://download.thinkbroadband.com/1GB.zip)",
                        "throughput_speed=${throughput%%|*}",
                        "throughput_duration=${throughput#*|}",
                    ]
                )
            else:
                commands.extend(["throughput_speed=", "throughput_duration="])
            commands.extend(
                [
                    "python3 - \"$ru_ip\" \"$foreign_ip\" \"$github\" \"$google\" \"$throughput_speed\" \"$throughput_duration\" <<'PY'",
                    "import json, sys",
                    "def number(value):",
                    "    try: return float(value)",
                    "    except ValueError: return 0.0",
                    "print(json.dumps({'ru_egress_ip': sys.argv[1], 'foreign_egress_ip': sys.argv[2], 'github_status': sys.argv[3], 'google_status': sys.argv[4], 'throughput': {'bytes_per_second': number(sys.argv[5]), 'duration_seconds': number(sys.argv[6])}}))",
                    "PY",
                ]
            )
            command = "\n".join(commands)
            result = json.loads(ssh_capture(foreign_target, command, command_timeout=_vless_runner_timeout(throughput_seconds)))
        except (ValueError, OSError, RuntimeError) as exc:
            return {"verdict": "failed", "reason": f"public VLESS path failed: {exc}"}
        finally:
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
        if rank[snapshot.verdict] > rank[worst]:
            worst = snapshot.verdict
    foreign_target = next((target for target in targets if target.role == ROLE_FOREIGN), None)
    public_vless: dict[str, object] = {"verdict": "inconclusive", "reason": "foreign verifier is unavailable"}
    if foreign_target is not None:
        public_vless = _verify_public_vless_uri(OUT_DIR / deployment_name / "client" / "vless-uri.txt", foreign_target, throughput_seconds=throughput_seconds)
        if rank[str(public_vless["verdict"])] > rank[worst]:
            worst = str(public_vless["verdict"])
    print_header("Live verification result")
    print(f"verify verdict: {worst}")
    for snapshot in snapshots:
        reason_text = "; ".join(snapshot.reasons) if snapshot.reasons else "fresh probes and installed manifest are consistent"
        print(f"{snapshot.role or 'unknown'}: {snapshot.verdict} - {reason_text}")
    print(f"public-vless-uri: {public_vless['verdict']} - {public_vless.get('reason', public_vless.get('result', ''))}")
    print(f"Deployment env: {Path(env_path)}")
    return 0 if worst == "verified" else 1
