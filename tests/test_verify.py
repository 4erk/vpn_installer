from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.verify import _validate_public_vless_result, _verify_public_vless_uri, _verify_snapshot, _vless_runner_timeout, _wait_for_vless_runner, verify_live_workflow
from vpn_installer.vless_verify import parse_vless_uri


def acceptance_snapshot(role: str, **overrides: object) -> DiagnosticsSnapshot:
    services = {"wireguard": "active", "nftables": "active"}
    verdicts = {"server_path": "verified", "public_front": "not-applicable", "client_observation": "not-applicable"}
    if role == ROLE_RU:
        services.update({"sing-box": "active", "xray": "active"})
        verdicts.update({"public_front": "verified", "client_observation": "observed"})
    payload: dict[str, object] = {
        "role": role,
        "services": services,
        "drift": "none",
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

    def test_verify_snapshot_degrades_for_front_socket_churn(self) -> None:
        verdicts = {"server_path": "verified", "public_front": "verified", "client_observation": "degraded"}
        verified = _verify_snapshot(acceptance_snapshot(ROLE_RU, component_verdicts=verdicts))
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("public TCP front shows retransmission or socket churn", verified.reasons)

    def test_verify_snapshot_requires_acceptance_probes(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_FOREIGN, route_probes={"profile": "light", "ok": True}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("acceptance probes did not run", verified.reasons)

    def test_verify_snapshot_allows_inactive_foreign_singbox(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_FOREIGN, services={"sing-box": "inactive", "wireguard": "active", "nftables": "active"}))
        self.assertEqual(verified.verdict, "verified")

    def test_verify_live_workflow_returns_nonzero_on_server_mutated_drift(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[acceptance_snapshot(ROLE_RU, drift="server-mutated"), acceptance_snapshot(ROLE_FOREIGN)]),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_returns_nonzero_when_agent_acceptance_fails(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        broken = acceptance_snapshot(ROLE_RU, route_probes={"profile": "acceptance", "ok": False}, component_verdicts={"server_path": "failed", "public_front": "verified", "client_observation": "observed"})
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[broken, acceptance_snapshot(ROLE_FOREIGN)]),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_requests_one_agent_acceptance_per_role(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, targets, {})) as prepare,
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[acceptance_snapshot(ROLE_RU), acceptance_snapshot(ROLE_FOREIGN)]) as collect,
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 0)
        self.assertEqual(collect.call_count, 2)
        self.assertFalse(prepare.call_args.kwargs["run_live_probes"])
        self.assertFalse(prepare.call_args.kwargs["enforce_safe_route"])

    def test_public_vless_verifier_requires_both_egress_identities(self) -> None:
        uri = parse_vless_uri("vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision")
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        valid = {"ru_egress_ip": "203.0.113.10", "foreign_egress_ip": "198.51.100.20", "github_status": "200", "google_status": "204", "udp_dns": {"ok": True}, "ipv6_literal_status": "200"}
        self.assertEqual(_validate_public_vless_result(valid, uri, foreign)["verdict"], "verified")
        invalid = {**valid, "foreign_egress_ip": "203.0.113.99"}
        self.assertEqual(_validate_public_vless_result(invalid, uri, foreign)["verdict"], "failed")

    def test_public_vless_throughput_requires_rate_and_duration(self) -> None:
        uri = parse_vless_uri("vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision")
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {"ru_egress_ip": "203.0.113.10", "foreign_egress_ip": "198.51.100.20", "github_status": "200", "google_status": "204", "udp_dns": {"ok": True}, "ipv6_literal_status": "200", "throughput": {"bytes_per_second": 1_500_000, "duration_seconds": 60, "failures": 0}}
        self.assertEqual(_validate_public_vless_result(result, uri, foreign, throughput_seconds=60)["verdict"], "verified")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {"bytes_per_second": 1_000_000, "duration_seconds": 60, "failures": 0}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {"bytes_per_second": 1_500_000, "duration_seconds": 60, "failures": 1}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_vless_runner_timeout(0), 111)
        self.assertEqual(_vless_runner_timeout(600), 716)

    def test_public_vless_runner_uploads_lf_script_and_executes_it(self) -> None:
        uri_text = "vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision"
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {
            "ru_egress_ip": "203.0.113.10",
            "foreign_egress_ip": "198.51.100.20",
            "github_status": "200",
            "google_status": "204",
            "udp_dns": {"ok": True},
            "ipv6_literal_status": "200",
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
        self.assertTrue(command.startswith("setsid bash /tmp/vpn-stack-vless-verify.test/runner.sh "))
        self.assertIn("result.json", capture.call_args_list[2].args[1])

    def test_detached_runner_reports_its_stderr_when_it_exits_without_result(self) -> None:
        target = RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")
        with patch("vpn_installer.verify.ssh_capture", return_value="exited\nvpn-vless-runner phase=throughput-curl-exit-56\n"):
            with self.assertRaisesRegex(RuntimeError, "throughput-curl-exit-56"):
                _wait_for_vless_runner(target, "4242", "/tmp/result.json", "/tmp/runner.stderr", throughput_seconds=30)


if __name__ == "__main__":
    unittest.main()
