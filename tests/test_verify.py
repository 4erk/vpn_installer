from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.verify import _verify_snapshot, verify_live_workflow


class VerifyTests(unittest.TestCase):
    def test_verify_snapshot_requires_drift_free_manifest(self) -> None:
        snapshot = DiagnosticsSnapshot(role="ru-gateway", services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"}, drift="server-mutated")
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("installed config hash differs from render manifest", verified.reasons)

    def test_verify_snapshot_keeps_ambient_literal_timeout_out_of_probe_verdict(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role="ru-gateway",
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={
                "direct": "api.ipify.org:reachable:200:0:127.0.0.1:0.1",
                "wg": "github.com:reachable:200:0:127.0.0.1:0.2",
                "ipv6_literal_tcp": "cloudflare_v6:reachable:200:0:127.0.0.1:0.1",
            },
            log_buckets={"ipv4_literal_timeout": 5},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "verified")
        self.assertEqual(verified.log_buckets["ipv4_literal_timeout"], 5)

    def test_verify_snapshot_allows_inactive_foreign_singbox(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_FOREIGN,
            services={"sing-box": "inactive", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"direct": "github.com:reachable:200:0:20.0.0.1:0.2"},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "verified")

    def test_verify_snapshot_degrades_on_ipv6_literal_tcp_probe_failure(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_RU,
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"direct": "api.ipify.org:reachable:200:0:127.0.0.1:0.1", "wg": "github.com:reachable:200:0:127.0.0.1:0.2", "ipv6_literal_tcp": "cloudflare_v6:broken:000:28::6.0"},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("IPv6 literal TCP route probe has broken targets", verified.reasons)

    def test_verify_snapshot_allows_partial_ipv6_literal_probe_failure(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_RU,
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"direct": "api.ipify.org:reachable:200:0:127.0.0.1:0.1", "wg": "github.com:reachable:200:0:127.0.0.1:0.2", "ipv6_literal_tcp": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08;meta_v6:broken:000:28:-:2.0"},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "verified")

    def test_verify_snapshot_ignores_deep_probe_verdict_without_fresh_failure(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_FOREIGN,
            services={"wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"direct": "github.com:reachable:200:0:20.0.0.1:0.2", "deep_probe_verdict": "degraded", "deep_probe_reasons": "foreign_ru_ping_loss=10"},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "verified")

    def test_verify_snapshot_degrades_when_ipv6_literal_probe_is_missing(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_RU,
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"direct": "api.ipify.org:reachable:200:0:127.0.0.1:0.1", "wg": "github.com:reachable:200:0:127.0.0.1:0.2"},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("IPv6 literal TCP route probe did not run", verified.reasons)

    def test_verify_snapshot_keeps_ambient_dns_timeout_out_of_probe_verdict(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_RU,
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"direct": "api.ipify.org:reachable:200:0:127.0.0.1:0.1", "wg": "github.com:reachable:200:0:127.0.0.1:0.2", "ipv6_literal_tcp": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08"},
            log_buckets={"dns_timeout": 2},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "verified")
        self.assertEqual(verified.log_buckets["dns_timeout"], 2)

    def test_verify_snapshot_keeps_ambient_private_dns_event_out_of_probe_verdict(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_RU,
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"direct": "api.ipify.org:reachable:200:0:127.0.0.1:0.1", "wg": "github.com:reachable:200:0:127.0.0.1:0.2", "ipv6_literal_tcp": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08"},
            log_buckets={"private_dns_leak": 7},
            top_destinations={"private_dns_leak": "172.19.0.2:853=7"},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "verified")
        self.assertEqual(verified.top_destinations["private_dns_leak"], "172.19.0.2:853=7")

    def test_verify_live_workflow_returns_nonzero_on_server_mutated_drift(self) -> None:
        targets = [
            RemoteTarget(role=ROLE_RU, ssh_host="ru.example"),
            RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example"),
        ]
        env = {"WG_INTERFACE": "wg-test"}
        preflights = {
            ROLE_RU: {
                "role": ROLE_RU,
                "sing_box": "active",
                "xray": "active",
                "wireguard": "active",
                "nftables": "active",
                "drift": "server-mutated",
                "observed_ipv4": "198.51.100.1",
                "wg_observed_ipv4": "198.51.100.2",
                "target_probe_direct": "api.ipify.org:reachable:200:0:127.0.0.1:0.1",
                "target_probe_wg": "github.com:reachable:200:0:127.0.0.1:0.2",
                "ipv6_literal_tcp_probe": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08",
            },
            ROLE_FOREIGN: {
                "role": ROLE_FOREIGN,
                "sing_box": "active",
                "wireguard": "active",
                "nftables": "active",
                "drift": "none",
                "observed_ipv4": "198.51.100.2",
                "target_probe_direct": "github.com:reachable:200:0:20.0.0.1:0.2",
            },
        }

        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, preflights)),
            patch("vpn_installer.verify.workflows.print_summary"),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_returns_nonzero_on_soft_health_degradation(self) -> None:
        targets = [
            RemoteTarget(role=ROLE_RU, ssh_host="ru.example"),
            RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example"),
        ]
        env = {"WG_INTERFACE": "wg-test", "HEALTH_MIN_RU_WG_DOWNLOAD_BPS": "500000"}
        preflights = {
            ROLE_RU: {
                "role": ROLE_RU,
                "sing_box": "active",
                "xray": "active",
                "wireguard": "active",
                "nftables": "active",
                "drift": "none",
                "observed_ipv4": "198.51.100.20",
                "wg_observed_ipv4": "198.51.100.10",
                "wg_download_bps": "100000",
                "ipv6_literal_tcp_probe": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08",
            },
            ROLE_FOREIGN: {
                "role": ROLE_FOREIGN,
                "wireguard": "active",
                "nftables": "active",
                "drift": "none",
                "observed_ipv4": "198.51.100.10",
                "direct_download_bps": "800000",
            },
        }

        with (
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, preflights)),
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify.health.print_deployment_health"),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)

    def test_verify_live_workflow_anchors_preflight_log_window_at_verify_start(self) -> None:
        targets = [
            RemoteTarget(role=ROLE_RU, ssh_host="ru.example"),
            RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example"),
        ]
        env = {"WG_INTERFACE": "wg-test"}
        preflights = {
            ROLE_RU: {
                "role": ROLE_RU,
                "sing_box": "active",
                "xray": "active",
                "wireguard": "active",
                "nftables": "active",
                "drift": "none",
                "observed_ipv4": "198.51.100.1",
                "wg_observed_ipv4": "198.51.100.2",
                "target_probe_direct": "api.ipify.org:reachable:200:0:127.0.0.1:0.1",
                "target_probe_wg": "github.com:reachable:200:0:127.0.0.1:0.2",
                "ipv6_literal_tcp_probe": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08",
            },
            ROLE_FOREIGN: {
                "role": ROLE_FOREIGN,
                "wireguard": "active",
                "nftables": "active",
                "drift": "none",
                "observed_ipv4": "198.51.100.2",
                "target_probe_direct": "github.com:reachable:200:0:20.0.0.1:0.2",
            },
        }

        with (
            patch("vpn_installer.verify.time.time", return_value=1783733002),
            patch("vpn_installer.verify.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, preflights)) as prepare,
            patch("vpn_installer.verify.workflows.print_summary"),
            patch("vpn_installer.verify.health.print_deployment_health"),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 0)
        self.assertEqual(prepare.call_args.kwargs["fresh_since_epoch"], 1783733002)
        self.assertFalse(prepare.call_args.kwargs["enforce_safe_route"])
        self.assertTrue(prepare.call_args.kwargs["run_live_probes"])


if __name__ == "__main__":
    unittest.main()
