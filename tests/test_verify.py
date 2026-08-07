from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from vpn_installer.diagnostics import COLLECTOR_NAMES, LOG_WINDOW_KEYS, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot
from vpn_installer.log_classifier import BUCKETS
from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.verify import (
    FALLBACK_CAPACITY_FLOOR_BYTES_PER_SECOND,
    _apply_private_reject_correlation,
    _reconcile_public_capabilities,
    _validate_front_correlation,
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
UDP_DNS_OK = {
    "ok": True,
    "dns": {
        "verdict": "verified",
        "qr": True,
        "rcode": 0,
        "question": {"name": "example.com", "type": 1, "class": 1},
        "answer_count": 1,
        "matching_answers": 1,
        "queries": {
            "A": {
                "verdict": "verified",
                "qr": True,
                "rcode": 0,
                "question": {"name": "example.com", "type": 1, "class": 1},
                "answer_count": 1,
                "matching_answers": 1,
            },
            "AAAA": {
                "verdict": "verified",
                "qr": True,
                "rcode": 0,
                "question": {"name": "example.com", "type": 28, "class": 1},
                "answer_count": 1,
                "matching_answers": 1,
            },
        },
    },
    "private_reject": {
        "verdict": "verified",
        "ok": True,
        "targets": [
            {"target": "10.0.0.1:80", "verdict": "verified", "evidence": "socks-reply-reject", "socks_reply_status": 2},
            {"target": "172.19.0.2:853", "verdict": "verified", "evidence": "socks-reply-reject", "socks_reply_status": 2},
        ],
    },
}


def throughput_result(*, sustained: float, capacity: float, max_gap: float, duration: float = 60) -> dict[str, object]:
    return {
        "bytes_per_second": sustained,
        "sustained_bytes_per_second": sustained,
        "capacity_bytes_per_second": capacity,
        "max_gap_seconds": max_gap,
        "duration_seconds": duration,
        "failures": 0,
        "source_failures": 0,
        "successful_sources": 2,
        "required_successful_sources": 2,
        "source_metrics": [
            {"url": "https://a.example", "bytes_downloaded": 1, "duration_seconds": 1, "failures": 0},
            {"url": "https://b.example", "bytes_downloaded": 1, "duration_seconds": 1, "failures": 0},
        ],
    }


def acceptance_snapshot(role: str, **overrides: object) -> DiagnosticsSnapshot:
    observed_at = datetime.now(timezone.utc).isoformat()
    services = {"wireguard": "active", "nftables": "active", "sing-box": "active", "resolver": "active"}
    verdicts = {
        "server_path": "verified",
        "public_front": "not-applicable",
        "client_observation": "not-applicable",
        "host_integrity": "verified",
    }
    if role == ROLE_RU:
        services.update({"sing-box": "active", "xray": "active"})
        verdicts.update({"public_front": "verified", "public_quic": "verified", "client_observation": "observed"})
    payload: dict[str, object] = {
        "role": role,
        "generated_at": observed_at,
        "collectors": {name: CollectorState.ok(observed_at) for name in COLLECTOR_NAMES},
        "log_windows": {
            name: LogWindowSnapshot.collected({bucket: 0 for bucket in BUCKETS}, observed_at=observed_at)
            for name in LOG_WINDOW_KEYS
        },
        "services": services,
        "drift": "none",
        "network": {
            "tcp_adaptation": {
                "congestion_control": "bbr",
                "qdisc": "fq",
                "qdisc_limit": 10_000,
                "qdisc_flow_limit": 512,
                "mtu_probing": 1,
                "mtu_probe_floor": 536,
                "metrics_save_disabled": 0,
                "udp_rmem_default": 8_388_608,
                "udp_rmem_max": 16_777_216,
                "udp_wmem_default": 8_388_608,
                "udp_wmem_max": 16_777_216,
            }
        },
        "front": {"tcp_keepalive_idle_seconds": 90, "tcp_keepalive_interval_seconds": 15} if role == ROLE_RU else {},
        "transport": {"interserver": {"adaptive_state": {"state": "healthy", "fresh": True}}} if role == ROLE_RU else {},
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
    def setUp(self) -> None:
        self.temp_out = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_out.cleanup)
        out_patch = patch("vpn_installer.verify.OUT_DIR", Path(self.temp_out.name))
        out_patch.start()
        self.addCleanup(out_patch.stop)

    def test_verify_snapshot_requires_drift_free_manifest(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(ROLE_RU, drift="server-mutated"))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("installed config hash differs from render manifest", verified.reasons)

    def test_verify_snapshot_treats_stale_transport_observer_as_degraded(self) -> None:
        snapshot = acceptance_snapshot(
            ROLE_RU,
            transport={"interserver": {"adaptive_state": {"state": "healthy", "fresh": False, "reason": "selected underlay is healthy"}}},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "degraded")
        self.assertEqual(verified.reasons, ["interserver_adaptation=stale"])

    def test_verify_snapshot_rejects_stale_or_migrated_evidence(self) -> None:
        stale = acceptance_snapshot(ROLE_FOREIGN, generated_at="2026-01-01T00:00:00+00:00")
        self.assertEqual(_verify_snapshot(stale).verdict, "inconclusive")
        migrated = DiagnosticsSnapshot.migrate_agent_v2(
            {"schema_version": 2, "generated_at": datetime.now(timezone.utc).isoformat(), "verdicts": {"overall": "verified"}}
        )
        self.assertEqual(_verify_snapshot(migrated).verdict, "inconclusive")

    def test_verify_snapshot_requires_recent_since_release_window_only_within_retention(self) -> None:
        windows = {
            name: LogWindowSnapshot.collected(
                {bucket: 0 for bucket in BUCKETS},
                observed_at=datetime.now(timezone.utc).isoformat(),
            )
            for name in LOG_WINDOW_KEYS
        }
        windows["since_release"] = LogWindowSnapshot.unavailable("retention expired")
        old_release = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        snapshot = acceptance_snapshot(
            ROLE_FOREIGN,
            release={"installed_at": old_release},
            log_windows=windows,
        )
        self.assertEqual(_verify_snapshot(snapshot).verdict, "verified")

        recent_release = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        snapshot = acceptance_snapshot(
            ROLE_FOREIGN,
            release={"installed_at": recent_release},
            log_windows=windows,
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "failed")
        self.assertTrue(any(reason.startswith("log window since_release unavailable") for reason in verified.reasons))

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
                        "qdisc": "fq",
                        "qdisc_limit": 10_000,
                        "qdisc_flow_limit": 512,
                        "mtu_probing": 0,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "udp_rmem_default": 8_388_608,
                        "udp_rmem_max": 16_777_216,
                        "udp_wmem_default": 8_388_608,
                        "udp_wmem_max": 16_777_216,
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
                        "qdisc": "fq",
                        "qdisc_limit": 10_000,
                        "qdisc_flow_limit": 512,
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "udp_rmem_default": 212_992,
                        "udp_rmem_max": 212_992,
                        "udp_wmem_default": 8_388_608,
                        "udp_wmem_max": 16_777_216,
                    }
                },
            )
        )
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("UDP socket buffer profile is not active", verified.reasons)

    def test_verify_snapshot_degrades_when_udp_send_default_is_inactive(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                ROLE_FOREIGN,
                network={
                    "tcp_adaptation": {
                        "qdisc": "fq",
                        "qdisc_limit": 10_000,
                        "qdisc_flow_limit": 512,
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "udp_rmem_default": 8_388_608,
                        "udp_rmem_max": 16_777_216,
                        "udp_wmem_default": 212_992,
                        "udp_wmem_max": 16_777_216,
                    }
                },
            )
        )
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("UDP socket buffer profile is not active", verified.reasons)

    def test_verify_snapshot_fails_when_fq_flow_limit_is_not_managed(self) -> None:
        snapshot = acceptance_snapshot(ROLE_FOREIGN)
        snapshot.network["tcp_adaptation"]["qdisc_flow_limit"] = 100
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("managed fq profile is not active", verified.reasons)

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
                "capability_failures": {"external": [], "transport": ["hysteria_candidate_reachable"]},
            },
        )
        verified = _verify_snapshot(snapshot)
        reconciled = _reconcile_public_capabilities(verified, {"verdict": "verified"})

        self.assertEqual(reconciled.verdict, "degraded")
        self.assertEqual(reconciled.reasons, ["transport capability probe failed: hysteria_candidate_reachable"])

    def test_verify_snapshot_requires_foreign_singbox_service(self) -> None:
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

    def test_verify_snapshot_rejects_skipped_required_collector(self) -> None:
        snapshot = acceptance_snapshot(ROLE_RU)
        snapshot.collectors["route_probes"] = CollectorState.skipped("not requested")

        verified = _verify_snapshot(snapshot)

        self.assertEqual(verified.verdict, "failed")
        self.assertIn("collector route_probes was skipped: not requested", verified.reasons)

    def test_verify_live_workflow_returns_nonzero_on_server_mutated_drift(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        env = {"RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"}
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 0}, "front": {"flows": {}}}),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[acceptance_snapshot(ROLE_RU, drift="server-mutated"), acceptance_snapshot(ROLE_FOREIGN)]),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified", "result": {}}),
            patch("vpn_installer.verify._verify_public_hysteria2", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_returns_nonzero_when_agent_acceptance_fails(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        env = {"RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"}
        broken = acceptance_snapshot(ROLE_RU, route_probes={"profile": "acceptance", "ok": False}, component_verdicts={"server_path": "failed", "public_front": "verified", "public_quic": "verified", "client_observation": "observed", "host_integrity": "verified"})
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 0}, "front": {"flows": {}}}),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[broken, acceptance_snapshot(ROLE_FOREIGN)]),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified", "result": {}}),
            patch("vpn_installer.verify._verify_public_hysteria2", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_rollback_scope_checks_primary_vless_only(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        env = {"RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"}
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 1}, "front": {"flows": {}}}),
            patch("vpn_installer.verify._collect_agent_snapshot") as collect_snapshot,
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified", "result": {}}),
            patch("vpn_installer.verify._verify_public_hysteria2") as verify_hysteria2,
        ):
            self.assertEqual(
                verify_live_workflow("demo", non_interactive=True, throughput_seconds=0, require_native_agent=False),
                0,
            )
        collect_snapshot.assert_not_called()
        verify_hysteria2.assert_not_called()

    def test_verify_live_workflow_requests_post_vless_agent_acceptance_per_role(self) -> None:
        targets = [RemoteTarget(role=ROLE_RU, ssh_host="ru.example"), RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")]
        env = {"RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"}
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
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})) as prepare,
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 0}, "front": {"flows": {}}}),
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
        valid = {"ru_egress_ip": "203.0.113.10", "foreign_egress_ip": "198.51.100.20", "github_status": "200", "google_status": "204", "udp_dns": UDP_DNS_OK, "ipv6_literal_status": "200", "first_load_reliability": FIRST_LOAD_OK}
        unmeasured = _validate_public_vless_result(valid, uri, foreign)
        self.assertEqual(unmeasured["verdict"], "verified")
        self.assertEqual(unmeasured["functional"]["verdict"], "verified")
        self.assertEqual(unmeasured["performance"], {"verdict": "inconclusive", "measured": False, "reason": "public VLESS performance was not measured"})
        invalid = {**valid, "foreign_egress_ip": "203.0.113.99"}
        self.assertEqual(_validate_public_vless_result(invalid, uri, foreign)["verdict"], "failed")
        uncorrelated = {
            **UDP_DNS_OK,
            "private_reject": {
                "verdict": "inconclusive",
                "ok": False,
                "targets": [
                    {"target": "10.0.0.1:80", "verdict": "inconclusive", "evidence": "socks-success-eof"}
                ],
            },
        }
        private_result = _validate_public_vless_result({**valid, "udp_dns": uncorrelated}, uri, foreign)
        self.assertEqual(private_result["verdict"], "inconclusive")
        self.assertEqual(private_result["functional"]["verdict"], "inconclusive")
        correlated = {
            **UDP_DNS_OK,
            "private_reject": {
                "verdict": "verified",
                "ok": True,
                "targets": [
                    {
                        "target": "10.0.0.1:80",
                        "verdict": "verified",
                        "evidence": "socks-success-eof",
                        "correlated": True,
                        "correlation_id": "route-event-1",
                    }
                ],
            },
        }
        self.assertEqual(
            _validate_public_vless_result({**valid, "udp_dns": correlated}, uri, foreign)["functional"]["verdict"],
            "verified",
        )
        invalid_dns = {**UDP_DNS_OK, "dns": {**UDP_DNS_OK["dns"], "rcode": 2}}
        self.assertEqual(_validate_public_vless_result({**valid, "udp_dns": invalid_dns}, uri, foreign)["functional"]["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**valid, "first_load_reliability": {**FIRST_LOAD_OK, "failures": 1}}, uri, foreign)["verdict"], "failed")

    def test_private_reject_log_correlation_upgrades_only_matching_eof_evidence(self) -> None:
        raw = {
            "udp_dns": {
                "private_reject": {
                    "verdict": "inconclusive",
                    "ok": False,
                    "targets": [
                        {
                            "target": "10.0.0.1:80",
                            "verdict": "inconclusive",
                            "ok": False,
                            "evidence": "socks-success-eof",
                            "correlation_required": True,
                        },
                        {
                            "target": "172.19.0.2:853",
                            "verdict": "inconclusive",
                            "ok": False,
                            "evidence": "socks-success-eof",
                            "correlation_required": True,
                        },
                    ],
                }
            }
        }
        correlation = {
            "verdict": "verified",
            "policy": {"verified": True, "drift": "none", "config_sha256": "known"},
            "targets": [
                {"target": "10.0.0.1:80", "correlated": True, "correlation_id": "event-1", "event_id": "1"},
                {"target": "172.19.0.2:853", "correlated": True, "correlation_id": "event-2", "event_id": "2"},
            ],
        }

        merged = _apply_private_reject_correlation(raw, correlation)

        private_reject = merged["udp_dns"]["private_reject"]
        self.assertEqual(private_reject["verdict"], "verified")
        self.assertTrue(private_reject["ok"])
        self.assertEqual([target["correlation_id"] for target in private_reject["targets"]], ["event-1", "event-2"])

        partial = _apply_private_reject_correlation(raw, {**correlation, "verdict": "inconclusive", "targets": correlation["targets"][:1]})
        self.assertEqual(partial["udp_dns"]["private_reject"]["verdict"], "inconclusive")

    def test_public_vless_throughput_requires_rate_and_duration(self) -> None:
        uri = parse_vless_uri("vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision")
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {"ru_egress_ip": "203.0.113.10", "foreign_egress_ip": "198.51.100.20", "github_status": "200", "google_status": "204", "udp_dns": UDP_DNS_OK, "ipv6_literal_status": "200", "first_load_reliability": FIRST_LOAD_OK, "throughput": throughput_result(sustained=7_000_000, capacity=7_000_000, max_gap=0.4)}
        self.assertEqual(_validate_public_vless_result(result, uri, foreign, throughput_seconds=60)["verdict"], "verified")
        source_limited = {**result, "throughput": throughput_result(sustained=1_000_000, capacity=7_000_000, max_gap=0.4)}
        self.assertEqual(_validate_public_vless_result(source_limited, uri, foreign, throughput_seconds=60)["performance"]["verdict"], "failed")
        stalled = {**result, "throughput": throughput_result(sustained=7_000_000, capacity=7_000_000, max_gap=3.0)}
        self.assertEqual(_validate_public_vless_result(stalled, uri, foreign, throughput_seconds=60)["performance"]["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {"bytes_per_second": 5_000_000, "duration_seconds": 60, "failures": 0}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {"bytes_per_second": 7_000_000, "duration_seconds": 60, "failures": 1}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {**result["throughput"], "source_failures": 1}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        source_redundant = {
            **result,
            "throughput": {
                **result["throughput"],
                "source_failures": 1,
                "successful_sources": 2,
                "required_successful_sources": 2,
                "source_metrics": [
                    {"url": "https://a.example", "bytes_downloaded": 1, "duration_seconds": 1, "failures": 0},
                    {"url": "https://b.example", "bytes_downloaded": 1, "duration_seconds": 1, "failures": 0},
                    {"url": "https://c.example", "bytes_downloaded": 0, "duration_seconds": 0, "failures": 1},
                ],
            },
        }
        self.assertEqual(_validate_public_vless_result(source_redundant, uri, foreign, throughput_seconds=60)["verdict"], "verified")
        insufficient_sources = {
            **source_redundant,
            "throughput": {**source_redundant["throughput"], "successful_sources": 1},
        }
        self.assertEqual(_validate_public_vless_result(insufficient_sources, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {**result["throughput"], "sustained_bytes_per_second": 1_000_000}}, uri, foreign, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_vless_runner_timeout(0), 189)
        self.assertEqual(_vless_runner_timeout(600), 794)

    def test_peak_capacity_is_an_acceptance_gate(self) -> None:
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {
            "ru_egress_ip": "203.0.113.10",
            "foreign_egress_ip": "198.51.100.20",
            "github_status": "200",
            "google_status": "204",
            "udp_dns": UDP_DNS_OK,
            "ipv6_literal_status": "200",
            "first_load_reliability": FIRST_LOAD_OK,
            "throughput": throughput_result(sustained=2_000_000, capacity=2_000_000, max_gap=0.3, duration=30),
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
        self.assertTrue(fallback["performance"]["peak_capacity_target_met"])
        self.assertFalse(primary["performance"]["peak_capacity_target_met"])

    def test_front_correlation_uses_accept_event_after_short_flow_closes(self) -> None:
        baseline = {"events": {"accepted_tcp": 4}, "front": {"flows": {}}}
        correlation = _validate_front_correlation(
            [
                {"baseline": baseline, "during": {"events": {"accepted_tcp": 4}, "front": {"flows": {}}}},
                {"baseline": baseline, "during": {"events": {"accepted_tcp": 5}, "front": {"flows": {}}}},
            ]
        )

        self.assertEqual(correlation["verdict"], "verified")
        self.assertEqual(correlation["accepted_delta"], 1)
        self.assertEqual(correlation["flow_count"], 0)

    def test_public_hysteria_runner_and_validator_keep_separate_contracts(self) -> None:
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {
            "ru_egress_ip": "203.0.113.10",
            "foreign_egress_ip": "198.51.100.20",
            "github_status": "200",
            "google_status": "204",
            "udp_dns": UDP_DNS_OK,
            "ipv6_literal_status": "200",
            "first_load_reliability": FIRST_LOAD_OK,
            "throughput": throughput_result(sustained=2_000_000, capacity=2_000_000, max_gap=0.3, duration=30),
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
        env = {
            "CLIENT_UUID": "00000000-0000-0000-0000-000000000000",
            "RU_PUBLIC_IP": "203.0.113.10",
            "RU_LISTEN_PORT": "443",
            "RU_REALITY_SERVER_NAME": "www.bing.com",
            "RU_REALITY_PUBLIC_KEY": "public-key",
            "RU_REALITY_SHORT_ID": "0123456789abcdef",
            "UTLS_FINGERPRINT": "chrome",
            "CLIENT_FLOW": "xtls-rprx-vision",
            "DEPLOY_NAME": "demo",
        }
        from vpn_installer.client_artifacts import render_vless_uri

        uri_text = render_vless_uri(env)
        foreign = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20")
        result = {
            "ru_egress_ip": "203.0.113.10",
            "foreign_egress_ip": "198.51.100.20",
            "github_status": "200",
            "google_status": "204",
            "udp_dns": UDP_DNS_OK,
            "ipv6_literal_status": "200",
            "first_load_reliability": FIRST_LOAD_OK,
            "throughput": {},
        }
        uploads: dict[str, bytes] = {}

        def capture_upload(_target, local_path, remote_path) -> None:
            uploads[remote_path] = local_path.read_bytes()

        with tempfile.TemporaryDirectory() as temp_dir:
            uri_path = Path(temp_dir) / "vless-uri.txt"
            uri_path.write_bytes(uri_text.encode("utf-8"))
            with (
                patch("vpn_installer.verify.scp_upload", side_effect=capture_upload),
                patch("vpn_installer.verify.ssh_capture", side_effect=["/tmp/vpn-stack-vless-verify.test\n", "4242\n", f"completed\n{json.dumps(result)}", "", ""]) as capture,
            ):
                verified = _verify_public_vless_uri(
                    uri_path,
                    env,
                    foreign,
                    on_running=lambda: {
                        "baseline": {"events": {"accepted_tcp": 0}, "front": {"flows": {}}},
                        "during": {
                            "events": {"accepted_tcp": 1},
                            "front": {"flows": {"198.51.100.20:50000": {"quality": "observed"}}},
                        },
                    },
                )

        self.assertEqual(verified["verdict"], "verified")
        self.assertEqual(verified["functional"]["verdict"], "verified")
        self.assertEqual(verified["performance"]["measured"], False)
        runner = uploads["/tmp/vpn-stack-vless-verify.test/runner.sh"]
        self.assertTrue(runner.startswith(b"#!/usr/bin/env bash\n"))
        self.assertNotIn(b"\r", runner)
        command = capture.call_args_list[1].args[1]
        self.assertIn("setsid timeout --foreground", command)
        self.assertIn("controller.lease", command)
        self.assertIn("result.json", capture.call_args_list[2].args[1])
        self.assertIn("touch /tmp/vpn-stack-vless-verify.test/controller.lease", capture.call_args_list[2].args[1])
        self.assertEqual(capture.call_args_list[-1].args[1], "rm -rf /tmp/vpn-stack-vless-verify.test")

    def test_public_vless_rejects_noncanonical_contract_before_network(self) -> None:
        env = {
            "CLIENT_UUID": "00000000-0000-0000-0000-000000000000", "RU_PUBLIC_IP": "203.0.113.10",
            "RU_LISTEN_PORT": "443", "RU_REALITY_SERVER_NAME": "www.bing.com", "RU_REALITY_PUBLIC_KEY": "public-key",
            "RU_REALITY_SHORT_ID": "0123456789abcdef", "UTLS_FINGERPRINT": "chrome", "CLIENT_FLOW": "xtls-rprx-vision",
            "DEPLOY_NAME": "demo",
        }
        foreign = RemoteTarget(role=ROLE_FOREIGN, ssh_host="198.51.100.20")
        with tempfile.TemporaryDirectory() as temp_dir:
            uri_path = Path(temp_dir) / "vless-uri.txt"
            uri_path.write_text("vless://stale", encoding="utf-8")
            with patch("vpn_installer.verify._run_external_public_profile") as runner:
                result = _verify_public_vless_uri(uri_path, env, foreign)
        self.assertEqual(result["verdict"], "failed")
        runner.assert_not_called()

    def test_detached_runner_reports_its_stderr_when_it_exits_without_result(self) -> None:
        target = RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example")
        with patch("vpn_installer.verify.ssh_capture", return_value="exited\nvpn-vless-runner phase=throughput-curl-exit-56\n"):
            with self.assertRaisesRegex(RuntimeError, "throughput-curl-exit-56"):
                _wait_for_vless_runner(target, "4242", "/tmp/result.json", "/tmp/runner.stderr", "/tmp/controller.lease", throughput_seconds=30)


if __name__ == "__main__":
    unittest.main()
