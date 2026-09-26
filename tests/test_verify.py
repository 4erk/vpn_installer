from __future__ import annotations

import copy
import json
import tempfile
import subprocess
import unittest
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from vpn_installer import server_agent, server_runtime, verify
from vpn_installer.diagnostics import COLLECTOR_NAMES, LOG_WINDOW_KEYS, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot
from vpn_installer.log_classifier import BUCKETS
from vpn_installer.models import RemoteTarget
from vpn_installer.topology import (
    CAP_INTERSERVER_CLIENT,
    CAP_INTERSERVER_SERVER,
    CAP_PUBLIC_FRONT,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
    TopologySpec,
)
from vpn_installer.verify import (
    FALLBACK_CAPACITY_REFERENCE_BYTES_PER_SECOND,
    _apply_private_reject_correlation,
    _install_release_gate,
    _private_reject_component,
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
from vpn_installer.vless_verify import RELIABILITY_PROBE_URLS, parse_vless_uri
from tests.test_journal_evidence import front_evidence
from tests.test_server_agent import front_snapshot


FIRST_LOAD_OK = {
    "attempts": 9,
    "successes": 9,
    "failures": 0,
    "average_total_seconds": 0.2,
    "max_total_seconds": 0.4,
    "required_targets": list(RELIABILITY_PROBE_URLS),
    "probes": [
        {"url": url, "ok": True, "curl_status": 0, "http_status": "200", "total_seconds": 0.2}
        for _cycle in range(3)
        for url in RELIABILITY_PROBE_URLS
    ],
}
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


def deployment_env(
    topology: str = TOPOLOGY_DUAL,
    *,
    gateway_location: str = "ru",
) -> dict[str, str]:
    return {
        "TOPOLOGY": topology,
        "GATEWAY_LOCATION": gateway_location,
        "GATEWAY_PUBLIC_IP": "203.0.113.10",
        "EXIT_PUBLIC_IP": "198.51.100.20" if topology == TOPOLOGY_DUAL else "",
    }


def client_env(
    topology: str = TOPOLOGY_DUAL,
    *,
    gateway_location: str = "ru",
) -> dict[str, str]:
    return {
        **deployment_env(topology, gateway_location=gateway_location),
        "CLIENT_UUID": "00000000-0000-0000-0000-000000000000",
        "RU_LISTEN_PORT": "443",
        "RU_REALITY_SERVER_NAME": "www.bing.com",
        "RU_REALITY_PUBLIC_KEY": "public-key",
        "RU_REALITY_SHORT_ID": "0123456789abcdef",
        "UTLS_FINGERPRINT": "chrome",
        "CLIENT_FLOW": "xtls-rprx-vision",
        "DEPLOY_NAME": "demo",
    }


def remote_target(topology: TopologySpec, node_id: str, *, ssh_host: str | None = None) -> RemoteTarget:
    node = topology.node(node_id)
    return RemoteTarget(
        node_id=node_id,
        location=node.location,
        public_ip=node.public_ip,
        ssh_host=ssh_host or node.public_ip,
    )


def verified_public_vless_evidence(topology: TopologySpec) -> dict[str, object]:
    paths: dict[str, dict[str, object]] = {
        "gateway_local_egress": {
            "state": "verified",
            "checked": True,
            "expected_ip": topology.gateway.public_ip,
            "observed_ips": [topology.gateway.public_ip],
        },
        "interserver_exit": (
            {
                "state": "verified",
                "checked": True,
                "expected_ip": topology.exit.public_ip,
                "observed_ip": topology.exit.public_ip,
            }
            if topology.exit is not None
            else {
                "state": "not_applicable",
                "checked": False,
                "reason": "single topology has no exit or interserver path",
            }
        ),
    }
    return {
        "verdict": "verified",
        "topology": topology.mode,
        "functional": {"verdict": "verified", "paths": paths},
        "front_correlation": {"verdict": "verified", "accepted_delta": 1},
        "paths": paths,
        "result": {},
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


def acceptance_snapshot(
    node_id: str,
    *,
    topology_mode: str = TOPOLOGY_DUAL,
    gateway_location: str = "ru",
    **overrides: object,
) -> DiagnosticsSnapshot:
    topology = TopologySpec.from_env(
        deployment_env(topology_mode, gateway_location=gateway_location)
    )
    plan = topology.plan(node_id)
    observed_at = datetime.now(timezone.utc).isoformat()
    services = {name: "active" for name in plan.required_services}
    verdicts = {
        "server_path": "verified",
        "public_front": "not-applicable",
        "client_observation": "not-applicable",
        "host_integrity": "verified",
    }
    if CAP_PUBLIC_FRONT in plan.capabilities:
        verdicts.update({"public_front": "verified", "public_quic": "verified", "client_observation": "observed"})
    collectors = {name: CollectorState.ok(observed_at) for name in COLLECTOR_NAMES}
    if CAP_PUBLIC_FRONT not in plan.capabilities:
        collectors["front"] = CollectorState.not_applicable("node plan has no public front")
    if not plan.capabilities & {CAP_INTERSERVER_CLIENT, CAP_INTERSERVER_SERVER}:
        collectors["wireguard"] = CollectorState.not_applicable("node plan has no interserver overlay")
        collectors["transport"] = CollectorState.not_applicable("node plan has no interserver transport")
    payload: dict[str, object] = {
        "topology": topology.mode,
        "node_id": plan.node_id,
        "location": plan.location,
        "capabilities": tuple(plan.capabilities),
        "generated_at": observed_at,
        "release": {"installed_at": observed_at},
        "collectors": collectors,
        "log_windows": {
            name: LogWindowSnapshot.collected({bucket: 0 for bucket in BUCKETS}, observed_at=observed_at, since=observed_at, until=observed_at)
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
                "thin_linear_timeouts": 1,
                "udp_rmem_default": 8_388_608,
                "udp_rmem_max": 16_777_216,
                "udp_wmem_default": 8_388_608,
                "udp_wmem_max": 16_777_216,
            }
        },
        "front": {"tcp_keepalive_idle_seconds": 90, "tcp_keepalive_interval_seconds": 15}
        if CAP_PUBLIC_FRONT in plan.capabilities
        else {},
        "transport": {"interserver": {"adaptive_state": {"state": "healthy", "fresh": True}}}
        if CAP_INTERSERVER_CLIENT in plan.capabilities
        else {},
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
        verified = _verify_snapshot(acceptance_snapshot(NODE_GATEWAY, drift="server-mutated"))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("installed config hash differs from render manifest", verified.reasons)

    def test_verify_snapshot_treats_stale_transport_observer_as_degraded(self) -> None:
        snapshot = acceptance_snapshot(
            NODE_GATEWAY,
            transport={"interserver": {"adaptive_state": {"state": "healthy", "fresh": False, "reason": "selected underlay is healthy"}}},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "degraded")
        self.assertEqual(verified.reasons, ["interserver_adaptation=stale"])

    def test_verify_snapshot_rejects_stale_evidence(self) -> None:
        stale = acceptance_snapshot(NODE_EXIT, generated_at="2026-01-01T00:00:00+00:00")
        self.assertEqual(_verify_snapshot(stale).verdict, "inconclusive")

    def test_fresh_envelope_does_not_refresh_old_collectors_or_log_window(self) -> None:
        old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        snapshot = acceptance_snapshot(NODE_EXIT)
        snapshot.collectors["services"] = CollectorState.ok(old)
        self.assertEqual(_verify_snapshot(snapshot).verdict, "inconclusive")
        snapshot.services["sing-box"] = "inactive"
        self.assertEqual(_verify_snapshot(snapshot).verdict, "failed")
        snapshot = acceptance_snapshot(NODE_EXIT)
        snapshot.log_windows["5m"] = LogWindowSnapshot.collected({bucket: 0 for bucket in BUCKETS}, observed_at=snapshot.generated_at, until=old)
        self.assertEqual(_verify_snapshot(snapshot).verdict, "inconclusive")

    def test_verify_snapshot_accepts_native_v5_contract_metadata(self) -> None:
        snapshot = acceptance_snapshot(NODE_GATEWAY)

        verified = _verify_snapshot(snapshot)

        self.assertEqual(verified.verdict, "verified")

    def test_verify_snapshot_single_gateway_does_not_require_interserver(self) -> None:
        snapshot = acceptance_snapshot(NODE_GATEWAY, topology_mode=TOPOLOGY_SINGLE)
        snapshot.component_verdicts.pop("public_quic")

        verified = _verify_snapshot(snapshot)

        self.assertEqual(verified.verdict, "verified")
        self.assertEqual(verified.collectors["wireguard"].status, "not_applicable")
        self.assertEqual(verified.collectors["transport"].status, "not_applicable")
        self.assertNotIn("wireguard", verified.services)

        snapshot.collectors["wireguard"] = CollectorState.ok(datetime.now(timezone.utc).isoformat())
        invalid = _verify_snapshot(snapshot)
        self.assertEqual(invalid.verdict, "failed")
        self.assertIn("collector wireguard must be not_applicable for this node", invalid.reasons)

    def test_verify_snapshot_requires_recent_since_release_window_only_within_retention(self) -> None:
        windows = {
            name: LogWindowSnapshot.collected(
                {bucket: 0 for bucket in BUCKETS},
                observed_at=datetime.now(timezone.utc).isoformat(),
                until=datetime.now(timezone.utc).isoformat(),
            )
            for name in LOG_WINDOW_KEYS
        }
        windows["since_release"] = LogWindowSnapshot.unavailable("retention expired")
        old_release = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        snapshot = acceptance_snapshot(
            NODE_EXIT,
            release={"installed_at": old_release},
            log_windows=windows,
        )
        self.assertEqual(_verify_snapshot(snapshot).verdict, "verified")

        recent_release = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        snapshot = acceptance_snapshot(
            NODE_EXIT,
            release={"installed_at": recent_release},
            log_windows=windows,
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "failed")
        self.assertTrue(any(reason.startswith("log window since_release unavailable") for reason in verified.reasons))

    def test_verify_snapshot_requires_complete_agent_verdicts(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(NODE_GATEWAY, component_verdicts={"server_path": "verified"}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("agent verdict fields are incomplete", verified.reasons)

    def test_retained_partial_observations_do_not_satisfy_required_log_window(self) -> None:
        snapshot = acceptance_snapshot(NODE_EXIT)
        snapshot.log_windows["24h"] = LogWindowSnapshot.unavailable("requested start precedes retained journal sequence")
        snapshot.storage["journal_coverage"] = {"partial_windows": {"24h": {"counts": {bucket: 0 for bucket in BUCKETS}}}}
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "failed")
        self.assertTrue(any("log window 24h unavailable" in reason for reason in verified.reasons))

    def test_verify_snapshot_requires_public_front_keepalive_policy(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(NODE_GATEWAY, front={}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("public TCP front keepalive policy is missing", verified.reasons)

    def test_verify_snapshot_requires_root_filesystem_integrity_fields(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(NODE_EXIT, storage={}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("root filesystem integrity fields are missing", verified.reasons)

    def test_verify_snapshot_fails_for_filesystem_corruption(self) -> None:
        verdicts = {
            "server_path": "verified",
            "public_front": "not-applicable",
            "client_observation": "not-applicable",
            "host_integrity": "failed",
        }
        verified = _verify_snapshot(acceptance_snapshot(NODE_EXIT, component_verdicts=verdicts))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("agent host_integrity failed", verified.reasons)

    def test_verify_snapshot_degrades_for_front_socket_churn(self) -> None:
        verdicts = {"server_path": "verified", "public_front": "verified", "public_quic": "verified", "client_observation": "degraded", "host_integrity": "verified"}
        verified = _verify_snapshot(acceptance_snapshot(NODE_GATEWAY, component_verdicts=verdicts))
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("public TCP front shows active data-path degradation", verified.reasons)

    def test_verify_snapshot_degrades_for_one_measured_lossy_client(self) -> None:
        verdicts = {"server_path": "verified", "public_front": "verified", "public_quic": "verified", "client_observation": "client_specific", "host_integrity": "verified"}
        verified = _verify_snapshot(acceptance_snapshot(NODE_GATEWAY, component_verdicts=verdicts))
        self.assertEqual(verified.verdict, "degraded")

    def test_verify_snapshot_degrades_when_plpmtud_is_disabled(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                NODE_GATEWAY,
                network={
                    "tcp_adaptation": {
                        "qdisc": "fq",
                        "qdisc_limit": 10_000,
                        "qdisc_flow_limit": 512,
                        "mtu_probing": 0,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "thin_linear_timeouts": 1,
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
                NODE_EXIT,
                network={
                    "tcp_adaptation": {
                        "qdisc": "fq",
                        "qdisc_limit": 10_000,
                        "qdisc_flow_limit": 512,
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "thin_linear_timeouts": 1,
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
                NODE_EXIT,
                network={
                    "tcp_adaptation": {
                        "qdisc": "fq",
                        "qdisc_limit": 10_000,
                        "qdisc_flow_limit": 512,
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "thin_linear_timeouts": 1,
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
        snapshot = acceptance_snapshot(NODE_EXIT)
        snapshot.network["tcp_adaptation"]["qdisc_flow_limit"] = 100
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("managed fq profile is not active", verified.reasons)

    def test_verify_snapshot_requires_acceptance_probes(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(NODE_EXIT, route_probes={"profile": "light", "ok": True}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("acceptance probes did not run", verified.reasons)

    def test_verify_snapshot_degrades_external_capability_without_failing_release_gate(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                NODE_GATEWAY,
                route_probes={"profile": "acceptance", "ok": False, "release_gate_ok": True},
            )
        )
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("external capability probe failed", verified.reasons)

    def test_verify_snapshot_fails_when_release_gate_fails(self) -> None:
        verified = _verify_snapshot(
            acceptance_snapshot(
                NODE_GATEWAY,
                route_probes={"profile": "acceptance", "ok": False, "release_gate_ok": False},
            )
        )
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("acceptance release gate failed", verified.reasons)

    def test_public_vless_supersedes_only_matching_external_capability_degradation(self) -> None:
        snapshot = acceptance_snapshot(NODE_GATEWAY)
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
            NODE_GATEWAY,
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
                NODE_EXIT,
                services={"sing-box": "inactive", "wireguard": "active", "nftables": "active", "resolver": "active"},
            )
        )
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("sing-box=inactive", verified.reasons)

    def test_verify_snapshot_requires_managed_resolver(self) -> None:
        verified = _verify_snapshot(acceptance_snapshot(NODE_EXIT, services={"sing-box": "active", "wireguard": "active", "nftables": "active"}))
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("resolver=missing", verified.reasons)

    def test_verify_snapshot_rejects_skipped_required_collector(self) -> None:
        snapshot = acceptance_snapshot(NODE_GATEWAY)
        snapshot.collectors["route_probes"] = CollectorState.skipped("not requested")

        verified = _verify_snapshot(snapshot)

        self.assertEqual(verified.verdict, "failed")
        self.assertIn("collector route_probes was skipped: not requested", verified.reasons)

    def test_verify_live_workflow_returns_nonzero_on_server_mutated_drift(self) -> None:
        env = deployment_env()
        topology = TopologySpec.from_env(env)
        targets = [
            remote_target(topology, NODE_GATEWAY, ssh_host="gateway.example"),
            remote_target(topology, NODE_EXIT, ssh_host="exit.example"),
        ]
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 0}, "front": {"flows": {}}}),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[acceptance_snapshot(NODE_GATEWAY, drift="server-mutated"), acceptance_snapshot(NODE_EXIT)]),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value=verified_public_vless_evidence(topology)),
            patch("vpn_installer.verify._verify_public_hysteria2", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_returns_nonzero_when_agent_acceptance_fails(self) -> None:
        env = deployment_env()
        topology = TopologySpec.from_env(env)
        targets = [
            remote_target(topology, NODE_GATEWAY, ssh_host="gateway.example"),
            remote_target(topology, NODE_EXIT, ssh_host="exit.example"),
        ]
        broken = acceptance_snapshot(NODE_GATEWAY, route_probes={"profile": "acceptance", "ok": False}, component_verdicts={"server_path": "failed", "public_front": "verified", "public_quic": "verified", "client_observation": "observed", "host_integrity": "verified"})
        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 0}, "front": {"flows": {}}}),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=[broken, acceptance_snapshot(NODE_EXIT)]),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value=verified_public_vless_evidence(topology)),
            patch("vpn_installer.verify._verify_public_hysteria2", return_value={"verdict": "verified", "result": {}}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_install_gate_accepts_only_unrelated_client_specific_front_loss(self) -> None:
        topology = TopologySpec.from_env(deployment_env())
        public_vless = verified_public_vless_evidence(topology)
        public_vless["paths"]["public_vless"] = {"checked": True}
        degraded_gateway = _verify_snapshot(
            acceptance_snapshot(
                NODE_GATEWAY,
                component_verdicts={
                    "server_path": "verified",
                    "public_front": "degraded",
                    "public_quic": "verified",
                    "client_observation": "client_specific",
                    "host_integrity": "verified",
                },
            )
        )
        decision = _install_release_gate(
            topology,
            public_vless,
            {"verdict": "verified"},
            [degraded_gateway, _verify_snapshot(acceptance_snapshot(NODE_EXIT))],
            same_node_functional_verified=False,
        )

        self.assertTrue(decision["eligible"])
        self.assertEqual(decision["accepted_degradations"], [f"{NODE_GATEWAY}:client_specific_public_front"])

        server_wide = copy.deepcopy(degraded_gateway)
        server_wide.component_verdicts["client_observation"] = "degraded"
        self.assertFalse(
            _install_release_gate(
                topology,
                public_vless,
                {"verdict": "verified"},
                [server_wide, _verify_snapshot(acceptance_snapshot(NODE_EXIT))],
                same_node_functional_verified=False,
            )["eligible"]
        )
        self.assertFalse(
            _install_release_gate(
                topology,
                {**public_vless, "verdict": "failed"},
                {"verdict": "verified"},
                [degraded_gateway, _verify_snapshot(acceptance_snapshot(NODE_EXIT))],
                same_node_functional_verified=False,
            )["eligible"]
        )
        self.assertFalse(
            _install_release_gate(
                topology,
                public_vless,
                {"verdict": "failed"},
                [degraded_gateway, _verify_snapshot(acceptance_snapshot(NODE_EXIT))],
                same_node_functional_verified=False,
            )["eligible"]
        )

    def test_install_gate_uses_complete_post_install_logs_without_claiming_complete_history(self) -> None:
        topology = TopologySpec.from_env(deployment_env())
        public = verified_public_vless_evidence(topology)
        public["paths"]["public_vless"] = {"checked": True}
        gateway = acceptance_snapshot(NODE_GATEWAY)
        for name in ("5m", "30m", "24h"):
            gateway.log_windows[name] = LogWindowSnapshot.unavailable("journal starts after requested window")
        _verify_snapshot(gateway)
        before = copy.deepcopy(gateway.to_dict())

        def gate(candidate: DiagnosticsSnapshot) -> dict:
            return _install_release_gate(topology, public, {"verdict": "verified"},
                [candidate, acceptance_snapshot(NODE_EXIT)], same_node_functional_verified=False)

        decision = gate(gateway)
        self.assertTrue(decision["eligible"])
        self.assertEqual(decision["accepted_degradations"], [f"{NODE_GATEWAY}:incomplete_historical_logs"])
        self.assertEqual(gateway.to_dict(), before)
        self.assertEqual(gateway.verdict, "failed")
        for damage in ("missing", "partial", "stale", "late_start", "missing_installed_at", "xray", "drift", "routes"):
            with self.subTest(damage=damage):
                broken = copy.deepcopy(gateway)
                if damage == "missing":
                    broken.log_windows.pop("since_release")
                elif damage == "partial":
                    broken.log_windows["since_release"] = LogWindowSnapshot.unavailable("discarded messages")
                elif damage == "stale":
                    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
                    broken.log_windows["since_release"] = LogWindowSnapshot.collected(
                        {bucket: 0 for bucket in BUCKETS}, observed_at=old, since=old, until=old)
                    broken.release["installed_at"] = old
                elif damage == "late_start":
                    broken.release["installed_at"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
                elif damage == "missing_installed_at":
                    broken.release = {}
                elif damage == "xray":
                    broken.services["xray"] = "inactive"
                elif damage == "drift":
                    broken.drift = "server-mutated"
                else:
                    broken.route_probes["ok"] = False
                self.assertFalse(gate(broken)["eligible"])

    def test_install_gate_does_not_make_operational_client_loss_green(self) -> None:
        env = deployment_env()
        topology = TopologySpec.from_env(env)
        targets = [remote_target(topology, NODE_GATEWAY), remote_target(topology, NODE_EXIT)]

        def snapshots() -> list[DiagnosticsSnapshot]:
            return [
                acceptance_snapshot(
                    NODE_GATEWAY,
                    component_verdicts={
                        "server_path": "verified",
                        "public_front": "degraded",
                        "public_quic": "verified",
                        "client_observation": "client_specific",
                        "host_integrity": "verified",
                    },
                ),
                acceptance_snapshot(NODE_EXIT),
            ]

        def run(*, install_gate: bool) -> int:
            with (
                patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
                patch("vpn_installer.verify.workflows.print_summary"),
                patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 0}, "front": {"flows": {}}}),
                patch("vpn_installer.verify._collect_agent_snapshot", side_effect=snapshots()),
                patch("vpn_installer.verify._verify_public_vless_uri", return_value=verified_public_vless_evidence(topology)),
                patch("vpn_installer.verify._verify_public_hysteria2", return_value={"verdict": "verified", "result": {}}),
            ):
                return verify_live_workflow("demo", non_interactive=True, accept_install_gate=install_gate)

        self.assertEqual(run(install_gate=False), 1)
        self.assertEqual(run(install_gate=True), 0)
        reports = sorted((Path(self.temp_out.name) / "diagnostics").glob("*/live-verify.json"))
        report = json.loads(reports[-1].read_text(encoding="utf-8"))
        self.assertEqual(report["verdict"], "degraded")
        self.assertTrue(report["install_release_gate"]["applied"])

    def test_verify_live_workflow_rollback_scope_checks_primary_vless_only(self) -> None:
        env = deployment_env()
        observations, source, ownership = self._front_pair()
        env["EXIT_PUBLIC_IP"] = source
        topology = TopologySpec.from_env(env)
        targets = [
            remote_target(topology, NODE_GATEWAY, ssh_host="gateway.example"),
            remote_target(topology, NODE_EXIT, ssh_host="exit.example"),
        ]
        remote_dir = "/tmp/vpn-stack-front-verify.aBc123"

        def public_vless(*args, **kwargs):
            correlation = _validate_front_correlation(kwargs["on_running"](), source=source, runner_sockets=ownership)
            self.assertEqual(correlation["verdict"], "verified")
            return {**verified_public_vless_evidence(topology), "front_correlation": correlation}

        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify.ssh_capture", side_effect=[remote_dir, "", json.dumps(observations["baseline"]), json.dumps(observations["during"]), ""]) as ssh,
            patch("vpn_installer.verify.scp_upload") as upload,
            patch("vpn_installer.verify._collect_agent_snapshot") as collect_snapshot,
            patch("vpn_installer.verify._verify_public_vless_uri", side_effect=public_vless),
            patch("vpn_installer.verify._verify_public_hysteria2") as verify_hysteria2,
        ):
            self.assertEqual(
                verify_live_workflow("demo", non_interactive=True, throughput_seconds=0, require_native_agent=False),
                0,
            )
        collect_snapshot.assert_not_called()
        verify_hysteria2.assert_not_called()
        upload.assert_called_once()
        commands = [call.args[1] for call in ssh.call_args_list]
        self.assertEqual(sum(f"{remote_dir}/vpn-stack-agent.py client" in command for command in commands), 2)
        self.assertEqual(commands[-1], f"rm -rf -- {remote_dir}")
        self.assertFalse(any("/usr/local/lib/vpn-stack/vpn-stack-agent.py" in command for command in commands))

    def test_transient_collector_cleans_up_setup_collection_and_cleanup_failures(self) -> None:
        remote_dir = "/tmp/vpn-stack-front-verify.aBc123"
        sources = {"vpn-stack-agent.py": "# canonical collector\n" * 10000, "journal_evidence.py": "# canonical parser\n"}
        for failure in (None, "upload", "extract", "collect", "cleanup"):
            with self.subTest(failure=failure):
                commands = []
                archives = []

                def capture(target, command, **kwargs):
                    commands.append(command)
                    self.assertLess(len(command), 1024)
                    self.assertLessEqual(kwargs["command_timeout"], 20)
                    if command.startswith("mktemp"):
                        return remote_dir
                    if (failure == "extract" and "zipfile -e" in command) or (failure == "cleanup" and command.startswith("rm")):
                        raise RuntimeError(failure)
                    return ""

                def upload(target, local, remote):
                    archives.append(local)
                    with zipfile.ZipFile(local) as bundle:
                        self.assertEqual({name: bundle.read(name).decode() for name in bundle.namelist()}, sources)
                    self.assertEqual(remote, f"{remote_dir}/collector.zip")
                    if failure == "upload":
                        raise RuntimeError(failure)

                with (
                    patch.object(verify, "server_agent_artifacts", return_value=sources),
                    patch.object(verify, "ssh_capture", side_effect=capture),
                    patch.object(verify, "scp_upload", side_effect=upload),
                ):
                    def run():
                        with verify._transient_front_collector(object()) as script:
                            self.assertEqual(script, f"{remote_dir}/vpn-stack-agent.py")
                            if failure == "collect":
                                raise RuntimeError(failure)
                    if failure:
                        with self.assertRaisesRegex(RuntimeError, failure):
                            run()
                    else:
                        run()
                self.assertEqual(commands[-1], f"rm -rf -- {remote_dir}")
                self.assertTrue(archives)
                self.assertFalse(any(path.exists() for path in archives))

    def test_transient_collector_rejects_unowned_directory_without_removal(self) -> None:
        with patch.object(verify, "ssh_capture", return_value="/tmp/unrelated") as ssh, patch.object(verify, "scp_upload") as upload:
            with self.assertRaisesRegex(Exception, "allocate"):
                with verify._transient_front_collector(object()):
                    self.fail("unowned path was accepted")
        ssh.assert_called_once()
        upload.assert_not_called()

    def test_rollback_verification_cannot_hide_collector_setup_or_cleanup_error(self) -> None:
        env = deployment_env()
        topology = TopologySpec.from_env(env)
        targets = [remote_target(topology, node) for node in (NODE_GATEWAY, NODE_EXIT)]
        for stage in ("setup", "cleanup"):
            @contextmanager
            def collector(_target):
                if stage == "setup":
                    raise RuntimeError(stage)
                yield "/tmp/vpn-stack-front-verify.aBc123/vpn-stack-agent.py"
                raise RuntimeError(stage)

            with (
                self.subTest(stage=stage),
                patch.object(verify.workflows, "prepare_remote_session", return_value=("demo", Path("demo.env"), env, {}, targets, {})),
                patch.object(verify.workflows, "print_summary"),
                patch.object(verify, "_transient_front_collector", collector),
                patch.object(verify, "_capture_client_front", return_value={}),
                patch.object(verify, "_verify_public_vless_uri", return_value=verified_public_vless_evidence(topology)),
            ):
                self.assertEqual(verify_live_workflow("demo", non_interactive=True, throughput_seconds=0, require_native_agent=False), 1)
                report = sorted((Path(self.temp_out.name) / "diagnostics").glob("*/live-verify.json"))[-1]
                payload = json.loads(report.read_text(encoding="utf-8"))
                self.assertEqual(payload["verdict"], "inconclusive")
                self.assertEqual(payload["public_vless"]["collector_error"], stage)

    def test_verify_live_workflow_requests_post_vless_agent_acceptance_per_node(self) -> None:
        env = deployment_env()
        topology = TopologySpec.from_env(env)
        targets = [
            remote_target(topology, NODE_GATEWAY, ssh_host="gateway.example"),
            remote_target(topology, NODE_EXIT, ssh_host="exit.example"),
        ]
        sequence: list[str] = []

        def public_vless(*_args, **_kwargs) -> dict[str, object]:
            sequence.append("public-vless")
            return verified_public_vless_evidence(topology)

        def public_hysteria2(*_args, **_kwargs) -> dict[str, object]:
            sequence.append("public-hysteria2")
            return {"verdict": "verified", "result": {}}

        def collect(target: RemoteTarget) -> DiagnosticsSnapshot:
            sequence.append(f"snapshot:{target.node_id}")
            return acceptance_snapshot(target.node_id)

        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})) as prepare,
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 0}, "front": {"flows": {}}}),
            patch("vpn_installer.verify._collect_agent_snapshot", side_effect=collect) as collect_mock,
            patch("vpn_installer.verify._verify_public_vless_uri", side_effect=public_vless),
            patch("vpn_installer.verify._verify_public_hysteria2", side_effect=public_hysteria2),
            patch("vpn_installer.verify._transient_front_collector", side_effect=AssertionError("native verification must use installed agent")),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 0)
        self.assertEqual(collect_mock.call_count, 2)
        self.assertEqual(sequence, ["public-vless", "public-hysteria2", f"snapshot:{NODE_GATEWAY}", f"snapshot:{NODE_EXIT}"])
        self.assertFalse(prepare.call_args.kwargs["run_live_probes"])
        self.assertFalse(prepare.call_args.kwargs["enforce_safe_route"])
        self.assertIsNone(prepare.call_args.kwargs["nodes"])

    def test_verify_live_workflow_single_uses_gateway_runner_and_marks_exit_not_applicable(self) -> None:
        env = client_env(TOPOLOGY_SINGLE, gateway_location="foreign")
        topology = TopologySpec.from_env(env)
        gateway = remote_target(topology, NODE_GATEWAY, ssh_host="gateway.example")
        observed_runner_nodes: list[str] = []

        def public_vless(_path, _env, runner, **_kwargs) -> dict[str, object]:
            observed_runner_nodes.append(runner.node_id)
            return verified_public_vless_evidence(topology)

        with (
            patch(
                "vpn_installer.verify.workflows.prepare_remote_session",
                return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {}),
            ) as prepare,
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 1}, "front": {"flows": {}}}),
            patch("vpn_installer.verify._collect_agent_snapshot", return_value=acceptance_snapshot(NODE_GATEWAY, topology_mode=TOPOLOGY_SINGLE, gateway_location="foreign")) as collect,
            patch("vpn_installer.verify._verify_public_vless_uri", side_effect=public_vless),
            patch("vpn_installer.verify._verify_public_hysteria2") as verify_hysteria2,
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

        self.assertEqual(observed_runner_nodes, [NODE_GATEWAY])
        self.assertEqual(collect.call_count, 1)
        verify_hysteria2.assert_not_called()
        self.assertIsNone(prepare.call_args.kwargs["nodes"])
        report_path = next((Path(self.temp_out.name) / "diagnostics").glob("*/live-verify.json"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["topology"], TOPOLOGY_SINGLE)
        self.assertEqual(report["verdict"], "inconclusive")
        self.assertEqual([node["node_id"] for node in report["nodes"]], [NODE_GATEWAY])
        self.assertEqual(report["paths"]["interserver_exit"]["state"], "not_applicable")
        self.assertEqual(report["paths"]["exit_agent_acceptance"]["state"], "not_applicable")
        self.assertEqual(report["paths"]["public_vless"]["runner_scope"], "same-node")
        self.assertFalse(report["paths"]["public_vless"]["external_ingress_observed"])
        self.assertEqual(report["runner_scope"], "same-node")
        self.assertEqual(report["public_hysteria2"]["verdict"], "not_applicable")
        self.assertFalse(report["same_node_install_accepted"])

    def test_verify_live_workflow_can_accept_same_node_only_for_internal_install_gate(self) -> None:
        env = client_env(TOPOLOGY_SINGLE, gateway_location="foreign")
        topology = TopologySpec.from_env(env)
        gateway = remote_target(topology, NODE_GATEWAY, ssh_host="gateway.example")
        with (
            patch(
                "vpn_installer.verify.workflows.prepare_remote_session",
                return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {}),
            ),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch(
                "vpn_installer.verify._capture_client_front",
                return_value={"events": {"accepted_tcp": 1}, "front": {"flows": {}}},
            ),
            patch(
                "vpn_installer.verify._collect_agent_snapshot",
                return_value=acceptance_snapshot(
                    NODE_GATEWAY,
                    topology_mode=TOPOLOGY_SINGLE,
                    gateway_location="foreign",
                ),
            ),
            patch(
                "vpn_installer.verify._verify_public_vless_uri",
                return_value=verified_public_vless_evidence(topology),
            ),
        ):
            self.assertEqual(
                verify_live_workflow(
                    "demo",
                    non_interactive=True,
                    accept_install_gate=True,
                ),
                0,
            )

        report_path = next((Path(self.temp_out.name) / "diagnostics").glob("*/live-verify.json"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["verdict"], "inconclusive")
        self.assertTrue(report["same_node_install_accepted"])

    def test_verified_agent_or_direct_probes_cannot_replace_public_vless_evidence(self) -> None:
        env = client_env(TOPOLOGY_SINGLE)
        topology = TopologySpec.from_env(env)
        gateway = remote_target(topology, NODE_GATEWAY)
        with (
            patch(
                "vpn_installer.verify.workflows.prepare_remote_session",
                return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {}),
            ),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify._capture_client_front", return_value={"events": {"accepted_tcp": 1}, "front": {"flows": {}}}),
            patch("vpn_installer.verify._collect_agent_snapshot", return_value=acceptance_snapshot(NODE_GATEWAY, topology_mode=TOPOLOGY_SINGLE)),
            patch("vpn_installer.verify._verify_public_vless_uri", return_value={"verdict": "verified"}),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

        report_path = next((Path(self.temp_out.name) / "diagnostics").glob("*/live-verify.json"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["public_vless"]["verdict"], "inconclusive")
        self.assertFalse(report["paths"]["public_vless"]["checked"])

    def test_public_vless_verifier_requires_both_egress_identities(self) -> None:
        uri = parse_vless_uri("vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision")
        topology = TopologySpec.from_env(deployment_env())
        valid = {"ru_egress_ip": "203.0.113.10", "foreign_egress_ip": "198.51.100.20", "github_status": "200", "google_status": "204", "udp_dns": UDP_DNS_OK, "ipv6_literal_status": "200", "first_load_reliability": FIRST_LOAD_OK}
        unmeasured = _validate_public_vless_result(valid, uri, topology)
        self.assertEqual(unmeasured["verdict"], "verified")
        self.assertEqual(unmeasured["functional"]["verdict"], "verified")
        self.assertEqual(unmeasured["topology"], TOPOLOGY_DUAL)
        self.assertEqual(unmeasured["paths"]["gateway_local_egress"]["state"], "verified")
        self.assertEqual(unmeasured["paths"]["interserver_exit"]["state"], "verified")
        self.assertEqual(unmeasured["performance"], {"verdict": "inconclusive", "measured": False, "reason": "public VLESS performance was not measured"})
        invalid = {**valid, "foreign_egress_ip": "203.0.113.99"}
        self.assertEqual(_validate_public_vless_result(invalid, uri, topology)["verdict"], "failed")
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
        private_result = _validate_public_vless_result({**valid, "udp_dns": uncorrelated}, uri, topology)
        self.assertEqual(private_result["verdict"], "inconclusive")
        self.assertEqual(private_result["functional"]["verdict"], "inconclusive")
        rollback_result = _validate_public_vless_result(
            {**valid, "udp_dns": uncorrelated},
            uri,
            topology,
            require_private_reject=False,
        )
        self.assertEqual(rollback_result["verdict"], "verified")
        rejected = {
            **uncorrelated,
            "private_reject": {
                "verdict": "failed",
                "ok": False,
                "targets": [{"target": "10.0.0.1:80", "verdict": "failed", "evidence": "accepted"}],
            },
        }
        self.assertEqual(
            _validate_public_vless_result(
                {**valid, "udp_dns": rejected},
                uri,
                topology,
                require_private_reject=False,
            )["verdict"],
            "failed",
        )
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
            _validate_public_vless_result({**valid, "udp_dns": correlated}, uri, topology)["functional"]["verdict"],
            "verified",
        )
        invalid_dns = {**UDP_DNS_OK, "dns": {**UDP_DNS_OK["dns"], "rcode": 2}}
        self.assertEqual(_validate_public_vless_result({**valid, "udp_dns": invalid_dns}, uri, topology)["functional"]["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**valid, "first_load_reliability": {**FIRST_LOAD_OK, "failures": 1}}, uri, topology)["verdict"], "failed")
        incomplete_targets = {
            **FIRST_LOAD_OK,
            "probes": [{**probe, "url": RELIABILITY_PROBE_URLS[0]} for probe in FIRST_LOAD_OK["probes"]],
        }
        self.assertEqual(
            _validate_public_vless_result({**valid, "first_load_reliability": incomplete_targets}, uri, topology)["verdict"],
            "failed",
        )

    def test_public_vless_identity_paths_are_topology_aware(self) -> None:
        uri = parse_vless_uri("vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision")
        single = TopologySpec.from_env(deployment_env(TOPOLOGY_SINGLE))
        result = {
            "ru_egress_ip": single.gateway.public_ip,
            "foreign_egress_ip": single.gateway.public_ip,
            "github_status": "200",
            "google_status": "204",
            "udp_dns": UDP_DNS_OK,
            "ipv6_literal_status": "200",
            "first_load_reliability": FIRST_LOAD_OK,
        }

        verified = _validate_public_vless_result(result, uri, single)

        self.assertEqual(verified["verdict"], "verified")
        self.assertEqual(verified["topology"], TOPOLOGY_SINGLE)
        self.assertEqual(verified["paths"]["gateway_local_egress"]["state"], "verified")
        self.assertEqual(verified["paths"]["interserver_exit"]["state"], "not_applicable")

        leaked_exit = _validate_public_vless_result(
            {**result, "foreign_egress_ip": "198.51.100.20"},
            uri,
            single,
        )
        self.assertEqual(leaked_exit["verdict"], "failed")

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
                            "elapsed_seconds": 0.012,
                        },
                        {
                            "target": "172.19.0.2:853",
                            "verdict": "inconclusive",
                            "ok": False,
                            "evidence": "socks-success-eof",
                            "correlation_required": True,
                            "elapsed_seconds": 0.018,
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

        policy_only = _apply_private_reject_correlation(
            raw,
            {**correlation, "verdict": "inconclusive", "targets": correlation["targets"]},
        )
        policy_targets = policy_only["udp_dns"]["private_reject"]["targets"]
        self.assertEqual(policy_only["udp_dns"]["private_reject"]["verdict"], "verified")
        self.assertTrue(all(target["verification_basis"] == "installed-policy-fast-eof" for target in policy_targets))
        self.assertEqual(
            _private_reject_component(policy_only["udp_dns"]["private_reject"], label="public VLESS")["verdict"],
            "verified",
        )

        slow = copy.deepcopy(raw)
        slow["udp_dns"]["private_reject"]["targets"][0]["elapsed_seconds"] = 2.0
        self.assertEqual(
            _apply_private_reject_correlation(slow, {**correlation, "verdict": "inconclusive"})["udp_dns"]["private_reject"]["verdict"],
            "inconclusive",
        )

    def test_public_vless_throughput_requires_rate_and_duration(self) -> None:
        uri = parse_vless_uri("vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision")
        topology = TopologySpec.from_env(deployment_env())
        result = {"ru_egress_ip": "203.0.113.10", "foreign_egress_ip": "198.51.100.20", "github_status": "200", "google_status": "204", "udp_dns": UDP_DNS_OK, "ipv6_literal_status": "200", "first_load_reliability": FIRST_LOAD_OK, "throughput": throughput_result(sustained=7_000_000, capacity=7_000_000, max_gap=0.4)}
        self.assertEqual(_validate_public_vless_result(result, uri, topology, throughput_seconds=60)["verdict"], "verified")
        source_limited = {**result, "throughput": throughput_result(sustained=1_000_000, capacity=7_000_000, max_gap=0.4)}
        self.assertEqual(_validate_public_vless_result(source_limited, uri, topology, throughput_seconds=60)["performance"]["verdict"], "failed")
        stalled = {**result, "throughput": throughput_result(sustained=7_000_000, capacity=7_000_000, max_gap=3.0)}
        self.assertEqual(_validate_public_vless_result(stalled, uri, topology, throughput_seconds=60)["performance"]["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {"bytes_per_second": 5_000_000, "duration_seconds": 60, "failures": 0}}, uri, topology, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {"bytes_per_second": 7_000_000, "duration_seconds": 60, "failures": 1}}, uri, topology, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {**result["throughput"], "source_failures": 1}}, uri, topology, throughput_seconds=60)["verdict"], "failed")
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
        self.assertEqual(_validate_public_vless_result(source_redundant, uri, topology, throughput_seconds=60)["verdict"], "verified")
        insufficient_sources = {
            **source_redundant,
            "throughput": {**source_redundant["throughput"], "successful_sources": 1},
        }
        self.assertEqual(_validate_public_vless_result(insufficient_sources, uri, topology, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_validate_public_vless_result({**result, "throughput": {**result["throughput"], "sustained_bytes_per_second": 1_000_000}}, uri, topology, throughput_seconds=60)["verdict"], "failed")
        self.assertEqual(_vless_runner_timeout(0), 194)
        self.assertEqual(_vless_runner_timeout(600), 799)

    def test_peak_capacity_is_diagnostic_after_sustained_gate_passes(self) -> None:
        topology = TopologySpec.from_env(deployment_env())
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
            topology,
            label="public Hysteria2",
            throughput_seconds=30,
            capacity_reference_bytes_per_second=FALLBACK_CAPACITY_REFERENCE_BYTES_PER_SECOND,
        )
        primary = _validate_public_transport_result(
            result,
            topology,
            label="public VLESS",
            throughput_seconds=30,
        )
        self.assertEqual(fallback["verdict"], "verified")
        self.assertEqual(primary["verdict"], "verified")
        self.assertTrue(fallback["performance"]["peak_capacity_reference_met"])
        self.assertFalse(primary["performance"]["peak_capacity_reference_met"])
        self.assertIn("below the 50.00 Mbit/s reference", primary["performance"]["observation"])

    def test_front_correlation_requires_active_flow_for_accept_event(self) -> None:
        source = "198.51.100.20"
        now = datetime.now(timezone.utc)
        baseline = {"generated_at": (now - timedelta(seconds=2)).isoformat(), "source": source, "events": {"accepted_tcp": 4}, "front": {"flows": {}}}
        baseline["journal_evidence"] = front_evidence()
        baseline["flow_events"] = {}
        correlation = _validate_front_correlation(
            [
                {"baseline": baseline, "during": {**baseline, "generated_at": now.isoformat(), "events": {"accepted_tcp": 4}}},
                {"baseline": baseline, "during": {**baseline, "generated_at": now.isoformat(), "events": {"accepted_tcp": 5}, "flow_events": {f"{source}:37166": {"example.com:443": 1}}}},
            ],
            source=source,
            runner_sockets={"status": "ok", "flows": [f"{source}:37166"]},
        )

        self.assertEqual(correlation["verdict"], "inconclusive")

    def _front_pair(self, *, failed_baseline=False, new_accept=True):
        source = "203.0.113.20"
        now = datetime.now(timezone.utc)
        message = f"from {source}:50123 accepted tcp:example.org:443"
        record = json.dumps({"__REALTIME_TIMESTAMP": str(int((now.timestamp() - 20) * 1e6)), "MESSAGE": message})
        replies = (
            subprocess.CompletedProcess([], 2 if failed_baseline else 0, record, "partial baseline" if failed_baseline else ""),
            subprocess.CompletedProcess([], 0, record + ("\n" + record if new_accept else ""), ""),
        )
        snapshots = []
        for index, reply in enumerate(replies):
            acquired = now - timedelta(seconds=2 - index)
            snapshot = front_snapshot(reply, source=source, cutoff=acquired.timestamp())
            snapshot["generated_at"] = acquired.isoformat()
            snapshots.append(snapshot)
        return {"baseline": snapshots[0], "during": snapshots[1]}, source, {"status": "ok", "flows": [f"{source}:50123"]}

    def test_front_correlation_cannot_turn_failed_baseline_into_new_accept(self) -> None:
        observations, source, ownership = self._front_pair(failed_baseline=True, new_accept=False)
        result = _validate_front_correlation(observations, source=source, runner_sockets=ownership)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("partial baseline", result["reason"])
        self.assertEqual(observations["baseline"]["observed_events"]["accepted_tcp"], 1)
        self.assertEqual(observations["during"]["events"]["accepted_tcp"], 1)

    def test_front_correlation_requires_complete_evidence_and_counters_in_both_snapshots(self) -> None:
        observations, source, ownership = self._front_pair()
        self.assertEqual(_validate_front_correlation(observations, source=source, runner_sockets=ownership)["verdict"], "verified")
        for side in ("baseline", "during"):
            for field, value in (("journal_evidence", None), ("journal_evidence", {}),
                                 ("journal_evidence", {**observations[side]["journal_evidence"], "collector_error": "partial"}),
                                 ("events", {}), ("events", {"accepted_tcp": None}), ("events", {"accepted_tcp": True}),
                                 ("flow_events", None), ("flow_events", {f"{source}:50123": {"example.org:443": -1}})):
                with self.subTest(side=side, field=field, value=value):
                    incomplete = copy.deepcopy(observations)
                    incomplete[side][field] = value
                    result = _validate_front_correlation(incomplete, source=source, runner_sockets=ownership)
                    self.assertEqual(result["verdict"], "inconclusive")
            missing = copy.deepcopy(observations)
            del missing[side]["journal_evidence"]
            self.assertEqual(_validate_front_correlation(missing, source=source, runner_sockets=ownership)["verdict"], "inconclusive")

    def test_fresh_front_envelope_does_not_refresh_journal_acquisition(self) -> None:
        observations, source, ownership = self._front_pair()
        now = datetime.now(timezone.utc).timestamp()
        for side in ("baseline", "during"):
            for cutoff in (now - 600, now + 600, datetime.fromisoformat(observations[side]["generated_at"]).timestamp() + 0.5):
                with self.subTest(side=side, cutoff=cutoff):
                    stale = copy.deepcopy(observations)
                    stale[side]["journal_evidence"] = front_evidence(cutoff=cutoff)
                    result = _validate_front_correlation(stale, source=source, runner_sockets=ownership)
                    self.assertEqual(result["verdict"], "inconclusive")
                    self.assertIn("journal", result["reason"])
        for delta in (0, -1):
            unordered = copy.deepcopy(observations)
            unordered["during"]["journal_evidence"] = front_evidence(cutoff=observations["baseline"]["journal_evidence"]["query_until_epoch"] + delta)
            self.assertEqual(_validate_front_correlation(unordered, source=source, runner_sockets=ownership)["verdict"], "inconclusive")

    def test_front_correlation_matches_agent_active_and_closed_flow_output(self) -> None:
        source = "198.51.100.20"
        flow = f"{source}:37166"
        now = datetime.now(timezone.utc)
        snapshots = []
        with (
            patch.object(server_runtime, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "installed_runtime_contract", return_value={"capabilities": [CAP_PUBLIC_FRONT]}),
            patch.object(server_agent, "journal_filtered_events") as logs,
            patch.object(server_agent, "tcp_front_snapshot") as front,
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "udp_443_policy", return_value="routed"),
            patch.object(server_agent, "public_hy2_snapshot", return_value={}),
            patch.object(server_runtime, "read_json", return_value={}),
            patch.object(server_runtime, "utc_now") as clock,
        ):
            for index, phase in enumerate((None, "active", "closing", None)):
                logs.return_value = front_evidence([] if index == 0 else [f"from {flow} accepted tcp:example.com:443"])
                front.return_value = {"listening": True, "flows": {flow: {"source": source, "source_port": 37166, "phase": phase, "quality": "observed"}} if phase else {}}
                clock.return_value = (now - timedelta(seconds=4 - index)).isoformat()
                snapshots.append(server_agent.front_client_snapshot(source, 5))
        self.assertEqual(snapshots[1]["flow_events"], {flow: {"example.com:443": 1}})
        for during in snapshots[2:]:
            self.assertEqual(during["events"]["accepted_tcp"], 1)
            self.assertEqual(during["flow_events"], {})
        ownership = {"status": "ok", "flows": [flow]}
        for during in snapshots[1:]:
            result = _validate_front_correlation({"baseline": snapshots[0], "during": during}, source=source, runner_sockets=ownership)
            self.assertEqual(result["verdict"], "verified" if during is snapshots[1] else "inconclusive")
        result = _validate_front_correlation([{"baseline": snapshots[0], "during": during} for during in snapshots[1:]], source=source, runner_sockets=ownership)
        self.assertEqual(result["verdict"], "verified")

    def test_front_correlation_rejects_historical_future_or_invalid_timestamps(self) -> None:
        source = "198.51.100.20"
        flow = f"{source}:37166"
        now = datetime.now(timezone.utc)
        baseline = {"generated_at": (now - timedelta(seconds=2)).isoformat(), "source": source, "events": {"accepted_tcp": 0}, "flow_events": {}}
        during = {"generated_at": (now - timedelta(seconds=1)).isoformat(), "source": source, "events": {"accepted_tcp": 1}, "flow_events": {flow: {"example.com:443": 1}}, "front": {"flows": {flow: {"quality": "observed", "phase": "active"}}}}
        baseline["journal_evidence"] = front_evidence()
        during["journal_evidence"] = front_evidence()
        for name in ("baseline", "during"):
            for value in (None, "", "invalid", 123, now.replace(tzinfo=None).isoformat(), (now - timedelta(minutes=10)).isoformat(), (now + timedelta(minutes=10)).isoformat()):
                with self.subTest(snapshot=name, timestamp=value):
                    observation = {"baseline": dict(baseline), "during": dict(during)}
                    observation[name]["generated_at"] = value
                    result = _validate_front_correlation(observation, source=source, runner_sockets={"status": "ok", "flows": [flow]})
                    self.assertEqual(result["verdict"], "inconclusive")
        for stamp in (baseline["generated_at"], (now - timedelta(seconds=3)).isoformat()):
            with self.subTest(order=stamp):
                result = _validate_front_correlation({"baseline": baseline, "during": {**during, "generated_at": stamp}}, source=source, runner_sockets={"status": "ok", "flows": [flow]})
                self.assertEqual(result["verdict"], "inconclusive")

    def test_front_correlation_uses_flow_event_when_rolling_counter_decreases(self) -> None:
        now = datetime.now(timezone.utc)
        correlation = _validate_front_correlation(
            {
                "baseline": {"generated_at": (now - timedelta(seconds=2)).isoformat(), "source": "198.51.100.20", "events": {"accepted_tcp": 40}, "front": {"flows": {}}, "flow_events": {}, "journal_evidence": front_evidence()},
                "during": {
                    "generated_at": now.isoformat(),
                    "journal_evidence": front_evidence(),
                    "source": "198.51.100.20",
                    "events": {"accepted_tcp": 37},
                    "flow_events": {"198.51.100.20:37166": {"1.1.1.1:53": 1}},
                    "front": {
                        "flows": {
                            "198.51.100.20:37166": {
                                "accepted_destinations": {"1.1.1.1:53": 1},
                                "quality": "observed",
                            }
                        }
                    },
                },
            },
            source="198.51.100.20",
            runner_sockets={"status": "ok", "flows": ["198.51.100.20:37166"]},
        )

        self.assertEqual(correlation["verdict"], "verified")
        self.assertEqual(correlation["accepted_delta"], -3)
        self.assertEqual(correlation["correlated_events"], 1)
        self.assertEqual(correlation["flow_count"], 1)

    def test_front_correlation_rejects_unchanged_flow_events_with_no_accept_delta(self) -> None:
        now = datetime.now(timezone.utc)
        baseline = {
            "journal_evidence": front_evidence(),
            "generated_at": (now - timedelta(seconds=2)).isoformat(),
            "source": "198.51.100.20",
            "events": {"accepted_tcp": 4},
            "flow_events": {"198.51.100.20:37166": {"example.com:443": 1}},
            "front": {"flows": {"198.51.100.20:37166": {"quality": "observed"}}},
        }
        for accepted in (4, 3):
            with self.subTest(accepted=accepted):
                during = copy.deepcopy(baseline)
                during["generated_at"] = now.isoformat()
                during["events"]["accepted_tcp"] = accepted
                correlation = _validate_front_correlation({"baseline": baseline, "during": during}, source=baseline["source"], runner_sockets={"status": "ok", "flows": ["198.51.100.20:37166"]})
                self.assertEqual(correlation["verdict"], "inconclusive")

    def test_front_correlation_counts_only_new_events_for_runner_source(self) -> None:
        source = "198.51.100.20"
        now = datetime.now(timezone.utc)
        baseline = {
            "journal_evidence": front_evidence(),
            "generated_at": (now - timedelta(seconds=2)).isoformat(),
            "source": source,
            "events": {"accepted_tcp": 4},
            "flow_events": {f"{source}:37166": {"example.com:443": 2, "old.example:443": 10}},
        }
        during = {
            "journal_evidence": front_evidence(),
            "generated_at": now.isoformat(),
            "source": source,
            "events": {"accepted_tcp": 4},
            "flow_events": {
                f"{source}:37166": {"example.com:443": 3, "old.example:443": 10},
                "192.0.2.99:50000": {"unrelated.example:443": 5},
            },
            "front": {"flows": {
                f"{source}:37166": {"quality": "observed"},
                "192.0.2.99:50000": {"quality": "degraded"},
            }},
        }
        correlation = _validate_front_correlation({"baseline": baseline, "during": during}, source=source, runner_sockets={"status": "ok", "flows": [f"{source}:37166"]})
        self.assertEqual(correlation["verdict"], "verified")
        self.assertEqual(correlation["accepted_delta"], 0)
        self.assertEqual(correlation["correlated_events"], 1)
        self.assertEqual(correlation["flow_count"], 1)
        self.assertEqual(correlation["qualities"], ["observed"])

    def test_front_correlation_rejects_unrelated_source_evidence(self) -> None:
        source = "198.51.100.20"
        unrelated = "192.0.2.99"
        now = datetime.now(timezone.utc)
        baseline = {"generated_at": (now - timedelta(seconds=2)).isoformat(), "source": source, "events": {"accepted_tcp": 4}}
        baseline["journal_evidence"] = front_evidence()
        during = {
            "journal_evidence": front_evidence(),
            "generated_at": now.isoformat(),
            "source": source,
            "events": {"accepted_tcp": 4},
            "flow_events": {f"{unrelated}:50000": {"example.com:443": 1}},
            "front": {"flows": {f"{unrelated}:50000": {"quality": "observed"}}},
        }
        correlation = _validate_front_correlation({"baseline": baseline, "during": during}, source=source, runner_sockets={"status": "ok", "flows": [f"{source}:37166"]})
        self.assertEqual(correlation["verdict"], "inconclusive")
        for baseline_source, during_source in ((source, unrelated), (unrelated, unrelated), ("", source)):
            with self.subTest(baseline_source=baseline_source, during_source=during_source):
                correlation = _validate_front_correlation(
                    {
                        "baseline": {**baseline, "source": baseline_source},
                        "during": {**during, "source": during_source, "events": {"accepted_tcp": 5}},
                    },
                    source=source,
                    runner_sockets={"status": "ok", "flows": [f"{source}:37166"]},
                )
                self.assertEqual(correlation["verdict"], "inconclusive")

    def test_front_correlation_rejects_other_process_on_same_source(self) -> None:
        source = "198.51.100.20"
        now = datetime.now(timezone.utc)
        observation = {
            "baseline": {"generated_at": (now - timedelta(seconds=2)).isoformat(), "source": source, "events": {"accepted_tcp": 0}, "journal_evidence": front_evidence()},
            "during": {"generated_at": now.isoformat(), "source": source, "events": {"accepted_tcp": 10},
                       "journal_evidence": front_evidence(),
                       "front": {"flows": {f"{source}:50000": {"quality": "observed"}}},
                       "flow_events": {f"{source}:50000": {"example.com:443": 10}}},
        }
        result = _validate_front_correlation(observation, source=source, runner_sockets={"status": "ok", "flows": [f"{source}:37166"]})
        self.assertEqual(result["verdict"], "inconclusive")
        for ownership in (None, {"status": "error"}, {"status": "ok", "flows": []}):
            self.assertEqual(_validate_front_correlation(observation, source=source, runner_sockets=ownership)["verdict"], "inconclusive")

    def test_public_hysteria_runner_and_validator_keep_separate_contracts(self) -> None:
        env = deployment_env()
        topology = TopologySpec.from_env(env)
        runner = remote_target(topology, NODE_EXIT)
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
            patch("vpn_installer.verify._run_public_profile", side_effect=run_profile),
        ):
            verified = _verify_public_hysteria2(env, runner, throughput_seconds=30)
        self.assertEqual(verified["verdict"], "verified")

    def test_public_vless_runner_uploads_lf_script_and_executes_it(self) -> None:
        env = client_env()
        from vpn_installer.client_artifacts import render_vless_uri

        uri_text = render_vless_uri(env)
        topology = TopologySpec.from_env(env)
        runner = remote_target(topology, NODE_EXIT)
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
        result["runner_sockets"] = {"status": "ok", "flows": ["198.51.100.20:50000"]}
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
                    runner,
                    on_running=lambda: {
                        "baseline": {"generated_at": (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat(), "source": "198.51.100.20", "events": {"accepted_tcp": 0}, "front": {"flows": {}}, "flow_events": {}, "journal_evidence": front_evidence()},
                        "during": {
                            "journal_evidence": front_evidence(),
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "source": "198.51.100.20",
                            "events": {"accepted_tcp": 1},
                            "flow_events": {"198.51.100.20:50000": {"example.com:443": 1}},
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
        env = client_env()
        topology = TopologySpec.from_env(env)
        runner = remote_target(topology, NODE_EXIT)
        with tempfile.TemporaryDirectory() as temp_dir:
            uri_path = Path(temp_dir) / "vless-uri.txt"
            uri_path.write_text("vless://stale", encoding="utf-8")
        with patch("vpn_installer.verify._run_public_profile") as run_profile:
                result = _verify_public_vless_uri(uri_path, env, runner)
        self.assertEqual(result["verdict"], "failed")
        run_profile.assert_not_called()

    def test_detached_runner_reports_its_stderr_when_it_exits_without_result(self) -> None:
        target = RemoteTarget(node_id=NODE_EXIT, ssh_host="foreign.example")
        with patch("vpn_installer.verify.ssh_capture", return_value="exited\nvpn-vless-runner phase=throughput-curl-exit-56\n"):
            with self.assertRaisesRegex(RuntimeError, "throughput-curl-exit-56"):
                _wait_for_vless_runner(target, "4242", "/tmp/result.json", "/tmp/runner.stderr", "/tmp/controller.lease", throughput_seconds=30)


if __name__ == "__main__":
    unittest.main()
