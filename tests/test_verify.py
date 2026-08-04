from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.verify import (
    FALLBACK_CAPACITY_FLOOR_BYTES_PER_SECOND,
    _reconcile_public_capabilities,
    _validate_public_transport_result,
    _validate_public_vless_result,
    _verify_public_hysteria2,
    _verify_public_vless_uri,
    _verify_snapshot,
    _vless_runner_timeout,
    _wait_for_vless_runner,
    verify_live_workflow,
)
from vpn_installer.vless_verify import parse_vless_uri


FIRST_LOAD_OK = {"attempts": 9, "successes": 9, "failures": 0, "average_total_seconds": 0.2, "max_total_seconds": 0.4}


def acceptance_snapshot(role: str, **overrides: object) -> DiagnosticsSnapshot:
    services = {"wireguard": "active", "nftables": "active", "sing-box": "active", "resolver": "active"}
    verdicts = {
        "server_path": "verified",
        "public_front": "not-applicable",
        "client_observation": "not-applicable",
        "host_integrity": "verified",
    }
    if role == ROLE_RU:
        services.update({"sing-box": "active", "xray": "active", "transport": "active"})
        verdicts.update({"public_front": "verified", "public_quic": "verified", "client_observation": "observed"})
    payload: dict[str, object] = {
        "role": role,
        "services": services,
        "drift": "none",
        "network": {
            "tcp_adaptation": {
                "congestion_control": "bbr",
                "qdisc": "fq",
                "mtu_probing": 1,
                "mtu_probe_floor": 536,
                "metrics_save_disabled": 0,
                "udp_rmem_default": 8_388_608,
                "udp_rmem_max": 16_777_216,
                "udp_wmem_max": 16_777_216,
            }
        },
        "front": {"tcp_keepalive_idle_seconds": 90, "tcp_keepalive_interval_seconds": 15} if role == ROLE_RU else {},
        "storage": {
            "root_filesystem": {
                "filesystem": "ext4",
                "state": "clean",
                "errors_count": 0,
                "boot_check_enabled": True,
                "verdict": "verified",
            }
        },
        "route_probes": {"profile": "acceptance", "ok": True},
        "component_verdicts": verdicts,
    }
    payload.update(overrides)
    return DiagnosticsSnapshot(**payload)


class VerifyTests(unittest.TestCase):
    def test_verify_snapshot_requires_drift_free_manifest(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_RU, drift="server-mutated"))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("installed config hash differs from render manifest", verified.reasons)

    def test_verify_snapshot_requires_complete_agent_verdicts(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_RU, component_verdicts={"server_path": "verified"}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("agent verdict fields are incomplete", verified.reasons)

    def test_verify_snapshot_requires_public_front_keepalive_policy(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_RU, front={}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("public TCP front keepalive policy is missing", verified.reasons)

    def test_verify_snapshot_requires_root_filesystem_integrity_fields(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_FOREIGN, storage={}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("root filesystem integrity fields are missing", verified.reasons)

    def test_verify_snapshot_fails_for_filesystem_corruption(self) -> None:
        verdicts = {
            "server_path": "verified",
            "public_front": "not-applicable",
            "client_observation": "not-applicable",
            "host_integrity": "failed",
        }
        verified = _verify_snapshot(acceptance_snapshot(ROLE_FOREIGN, component_verdicts=verdicts))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("agent host_integrity failed", verified.reasons)

    def test_verify_snapshot_degrades_for_front_socket_churn(self) -> None:
        verdicts = {"server_path": "verified", "public_front": "verified", "public_quic": "verified", "client_observation": "degraded", "host_integrity": "verified"}
        verified = _verify_snapshot(acceptance_snapshot(ROLE_RU, component_verdicts=verdicts))
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("public TCP front shows active data-path degradation", verified.reasons)

    def test_verify_snapshot_degrades_for_one_measured_lossy_client(self) -> None:
        verdicts = {"server_path": "verified", "public_front": "verified", "public_quic": "verified", "client_observation": "client_specific", "host_integrity": "verified"}
        verified = _verify_snapshot(acceptance_snapshot(ROLE_RU, component_verdicts=verdicts))
        self.assertEqual(verified.verdict, "degraded")

    def test_verify_snapshot_degrades_when_plpmtud_is_disabled(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                ROLE_RU,
                network={
                    "tcp_adaptation": {
                        "mtu_probing": 0,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "udp_rmem_default": 8_388_608,
                        "udp_rmem_max": 16_777_216,
                    }
                },
            )
        )
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("TCP PLPMTUD adaptation is disabled", verified.reasons)

    def test_verify_snapshot_degrades_when_udp_receive_profile_is_inactive(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                ROLE_FOREIGN,
                network={
                    "tcp_adaptation": {
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "udp_rmem_default": 212_992,
                        "udp_rmem_max": 212_992,
                    }
                },
            )
        )
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("UDP socket buffer profile is not active", verified.reasons)

    def test_verify_snapshot_requires_acceptance_probes(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_FOREIGN, route_probes={"profile": "light", "ok": True}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("acceptance probes did not run", verified.reasons)

    def test_verify_snapshot_degrades_external_capability_without_failing_release_gate(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                ROLE_RU,
                route_probes={"profile": "acceptance", "ok": False, "release_gate_ok": True},
            )
        )
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("external capability probe failed", verified.reasons)

    def test_verify_snapshot_fails_when_release_gate_fails(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                ROLE_RU,
                route_probes={"profile": "acceptance", "ok": False, "release_gate_ok": False},
            )
        )
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("acceptance release gate failed", verified.reasons)

    def test_public_vless_supersedes_only_matching_external_capability_degradation(self) -> None:
        snapshot = acceptance_snapshot(ROLE_RU)
        snapshot.verdict = "degraded"
        snapshot.reasons = ["external capability probe failed"]
        reconciled = _reconcile_public_capabilities(snapshot, {"verdict": "verified"})
        self.assertEqual(reconciled.verdict, "verified")
        self.assertEqual(reconciled.reasons, [])

        snapshot.verdict = "degraded"
        snapshot.reasons = ["external capability probe failed", "public TCP front shows active data-path degradation"]
        reconciled = _reconcile_public_capabilities(snapshot, {"verdict": "verified"})
        self.assertEqual(reconciled.verdict, "degraded")
        self.assertEqual(reconciled.reasons, ["public TCP front shows active data-path degradation"])

    def test_public_vless_does_not_hide_a_failed_transport_fallback(self) -> None:
        snapshot = acceptance_snapshot(
            ROLE_RU,
            route_probes={
                "profile": "acceptance",
                "ok": False,
                "release_gate_ok": True,
                "capability_failures": {"external": [], "transport": ["hysteria_fallback_reachable"]},
            },
        )
        verified = _verify_snapshot(snapshot)
        reconciled = _reconcile_public_capabilities(verified, {"verdict": "verified"})

        self.assertEqual(reconciled.verdict, "degraded")
        self.assertEqual(reconciled.reasons, ["transport capability probe failed: hysteria_fallback_reachable"])

    def test_verify_snapshot_requires_foreign_transport_service(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                ROLE_FOREIGN,
                services={"sing-box": "inactive", "wireguard": "active", "nftables": "active", "resolver": "active"},
            )
        )
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("sing-box=inactive", verified.reasons)

    def test_verify_snapshot_requires_managed_resolver(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_FOREIGN, services={"sing-box": "active", "wireguard": "active", "nftables": "active"}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("resolver=missing", verified.reasons)

    def test_verify_live_workflow_returns_nonzero_on_server_mutated_drift(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[acceptance_snapshot(ROLE_RU, drift="server-mutated"), acceptance_snapshot(ROLE_FOREIGN)]),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified", "result": {}}),
            patch("vpn_installer.verify._verify_public_hysteria2", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_returns_nonzero_when_agent_acceptance_fails(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        broken = acceptance_snapshot(ROLE_RU, route_probes={"profile": "acceptance", "ok": False}, component_verdicts={"server_path": "failed", "public_front": "verified", "public_quic": "verified", "client_observation": "observed", "host_integrity": "verified"})
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[broken, acceptance_snapshot(ROLE_FOREIGN)]),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified", "result": {}}),
            patch("vpn_installer.verify._verify_public_hysteria2", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_requests_post_vless_agent_acceptance_per_role(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        sequence: list[str] = []

        def public_vless(*_args, **_kwargs) -> dict[str, object]:
            sequence.append("public-vless")
            return {"verdict": "verified", "result": {}}

        def public_hysteria2(*_args, **_kwargs) -> dict[str, object]:
            sequence.append("public-hysteria2")
            return {"verdict": "verified", "result": {}}

        def collect(target: RemoteTarget) -> DiagnosticsSnapshot:
            sequence.append(f"snapshot:{target.role}")
            return acceptance_snapshot(target.role)

        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, targets, {})) as prepare,
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=collect) as collect_mock,
            patch("vpn_installer.verify._verify_public_vless_uri", side_effect=public_vless),
            patch("vpn_installer.verify._verify_public_hysteria2", side_effect=public_hysteria2),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 0)
        self.assertEqual(collect_mock.call_count, 2)
        self.assertEqual(sequence, ["public-vless", "public-hysteria2", f"snapshot:{ROLE_RU}", f"snapshot:{ROLE_FOREIGN}"])
        self.assertFalse(prepare.call_args.kwargs["run_live_probes"])
        self.assertFalse(prepare.call_args.kwargs["enforce_safe_route"])

    def test_public_vless_verifier_requires_both_egress_identities(self) -> None:
        uri = parse_vless_uri("vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision")
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        valid = {"ru_egress_ip": "203.0.113.10", "foreign_egress_ip": "198.51.100.20", "github_status": "200", "google_status": "204", "udp_dns": {"ok": True, "private_reject": {"ok": True}}, "ipv6_literal_status": "200", "first_load_reliability": FIRST_LOAD_OK}
        self.assertEqual(_validate_public_vless_result(valid, uri, foreign)["verdict"], "verified")
        invalid = {**valid, "foreign_egress_ip": "203.0.113.99"}
        self.assertEqual(_validate_public_vless_result(invalid, uri, foreign)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**valid, "udp_dns": {"ok": True, "private_reject": {"ok": False}}}, uri, foreign)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**valid, "first_load_reliability": {**FIRST_LOAD_OK, "failures": 1}}, uri, foreign)["verdict"], "failed")

    def test_public_vless_throughput_requires_rate_and_duration(self) -> None:
        uri = parse_vless_uri("vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision")
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {"ru_egress_ip": "203.0.113.10", "foreign_egress_ip": "198.51.100.20", "github_status": "200", "google_status": "204", "udp_dns": {"ok": True, "private_reject": {"ok": True}}, "ipv6_literal_status": "200", "first_load_reliability": FIRST_LOAD_OK, "throughput": {"bytes_per_second": 7_000_000, "capacity_bytes_per_second": 7_000_000, "stability_bytes_per_second": 1_400_000, "stability_duration_seconds": 30, "duration_seconds": 60, "failures": 0, "source_failures": 0}}
        self.assertEqual(_validate_public_vless_result(result, uri, foreign, throughput_seconds=60)["verdict"], "verified")
        source_limited = {**result, "throughput": {"bytes_per_second": 1_400_000, "capacity_bytes_per_second": 7_000_000, "stability_bytes_per_second": 1_400_000, "stability_duration_seconds": 30, "duration_seconds": 60, "failures": 0, "source_failures": 0}}
        self.assertEqual(_validate_public_vless_result(source_limited, uri, foreign, throughput_seconds=60)["verdict"], "verified")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {"bytes_per_second": 5_000_000, "duration_seconds": 60, "failures": 0}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {"bytes_per_second": 7_000_000, "duration_seconds": 60, "failures": 1}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {**result["throughput"], "source_failures": 1}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {**result["throughput"], "stability_bytes_per_second": 1_000_000}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_vless_runner_timeout(0), 189)
        self.assertEqual(_vless_runner_timeout(600), 794)

    def test_public_fallback_uses_availability_floor_without_weakening_primary(self) -> None:
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {
            "ru_egress_ip": "203.0.113.10",
            "foreign_egress_ip": "198.51.100.20",
            "github_status": "200",
            "google_status": "204",
            "udp_dns": {"ok": True, "private_reject": {"ok": True}},
            "ipv6_literal_status": "200",
            "first_load_reliability": FIRST_LOAD_OK,
            "throughput": {
                "capacity_bytes_per_second": 2_000_000,
                "duration_seconds": 30,
                "failures": 0,
                "source_failures": 0,
            },
        }
        fallback = _validate_public_transport_result(
            result,
            "203.0.113.10",
            foreign,
            label="public Hysteria2",
            throughput_seconds=30,
            capacity_floor_bytes_per_second=FALLBACK_CAPACITY_FLOOR_BYTES_PER_SECOND,
        )
        primary = _validate_public_transport_result(
            result,
            "203.0.113.10",
            foreign,
            label="public VLESS",
            throughput_seconds=30,
        )
        self.assertEqual(fallback["verdict"], "verified")
        self.assertEqual(primary["verdict"], "failed")

    def test_public_hysteria_runner_and_validator_keep_separate_contracts(self) -> None:
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {
            "ru_egress_ip": "203.0.113.10",
            "foreign_egress_ip": "198.51.100.20",
            "github_status": "200",
            "google_status": "204",
            "udp_dns": {"ok": True, "private_reject": {"ok": True}},
            "ipv6_literal_status": "200",
            "first_load_reliability": FIRST_LOAD_OK,
            "throughput": {
                "capacity_bytes_per_second": 2_000_000,
                "duration_seconds": 30,
                "failures": 0,
                "source_failures": 0,
            },
        }

        def run_profile(_config, _target, *, label: str, throughput_seconds: int) -> dict[str, object]:
            self.assertEqual(label, "public Hysteria2")
            self.assertEqual(throughput_seconds, 30)
            return {"verdict": "completed", "result": result}

        with (
            patch("vpn_installer.verify.render_public_hy2_outbound", return_value={"type": "direct", "tag": "ru-gateway"}),
            patch("vpn_installer.verify._run_external_public_profile", side_effect=run_profile),
        ):
            verified = _verify_public_hysteria2({"RU_PUBLIC_IP": "203.0.113.10"}, foreign, throughput_seconds=30)
        self.assertEqual(verified["verdict"], "verified")

    def test_public_vless_runner_uploads_lf_script_and_executes_it(self) -> None:
        uri_text = "vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision"
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {
            "ru_egress_ip": "203.0.113.10",
            "foreign_egress_ip": "198.51.100.20",
            "github_status": "200",
            "google_status": "204",
            "udp_dns": {"ok": True, "private_reject": {"ok": True}},
            "ipv6_literal_status": "200",
            "first_load_reliability": FIRST_LOAD_OK,
            "throughput": {},
        }
        uploads: dict[str, bytes] = {}

        def capture_upload(_target, local_path, remote_path) -> None:
            uploads[remote_path] = local_path.read_bytes()

        with tempfile.TemporaryDirectory() as temp_dir:
            uri_path = Path(temp_dir) / "vless-uri.txt"
            uri_path.write_text(uri_text, encoding="utf-8")
            with (
                patch("vpn_installer.verify.scp_upload", side_effect=capture_upload),
                patch("vpn_installer.verify.ssh_capture", side_effect=["/tmp/vpn-stack-vless-verify.test\n", "4242\n", f"completed\n{json.dumps(result)}", ""]) as capture,
            ):
                verified = _verify_public_vless_uri(uri_path, foreign)

        self.assertEqual(verified["verdict"], "verified")
        runner = uploads["/tmp/vpn-stack-vless-verify.test/runner.sh"]
        self.assertTrue(runner.startswith(b"#!/usr/bin/env bash\n"))
        self.assertNotIn(b"\r", runner)
        command = capture.call_args_list[1].args[1]
        self.assertIn("setsid timeout --foreground", command)
        self.assertIn("controller.lease", command)
        self.assertIn("result.json", capture.call_args_list[2].args[1])
        self.assertIn("touch /tmp/vpn-stack-vless-verify.test/controller.lease", capture.call_args_list[2].args[1])

    def test_detached_runner_reports_its_stderr_when_it_exits_without_result(self) -> None:
        target = RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")
        with patch("vpn_installer.verify.ssh_capture", return_value="exited\nvpn-vless-runner phase=throughput-curl-exit-56\n"):
            with self.assertRaisesRegex(RuntimeError, "throughput-curl-exit-56"):
                _wait_for_vless_runner(target, "4242", "/tmp/result.json", "/tmp/runner.stderr", "/tmp/controller.lease", throughput_seconds=30)


if __name__ == "__main__":
    unittest.main()
