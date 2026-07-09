from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.workflows import _verify_snapshot, verify_live_workflow


class VerifyTests(unittest.TestCase):
    def test_verify_snapshot_requires_drift_free_manifest(self) -> None:
        snapshot = DiagnosticsSnapshot(role="ru-gateway", services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"}, drift="server-mutated")
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "failed")
        self.assertIn("installed config hash differs from render manifest", verified.reasons)

    def test_verify_snapshot_allows_literal_timeout_noise_as_degraded_not_failed(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role="ru-gateway",
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            log_buckets={"ipv4_literal_timeout": 5},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("fresh ipv4_literal_timeout=5", verified.reasons)

    def test_verify_snapshot_allows_inactive_foreign_singbox(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_FOREIGN,
            services={"sing-box": "inactive", "wireguard": "active", "nftables": "active"},
            drift="none",
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "verified")

    def test_verify_snapshot_degrades_on_ipv6_literal_tcp_probe_failure(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_RU,
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"ipv6_literal_tcp": "cloudflare_v6:broken:000:28::6.0"},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("IPv6 literal TCP route probe has broken targets", verified.reasons)

    def test_verify_snapshot_degrades_when_ipv6_literal_probe_is_missing(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_RU,
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("IPv6 literal TCP route probe did not run", verified.reasons)

    def test_verify_snapshot_degrades_on_fresh_dns_timeout(self) -> None:
        snapshot = DiagnosticsSnapshot(
            role=ROLE_RU,
            services={"sing-box": "active", "xray": "active", "wireguard": "active", "nftables": "active"},
            drift="none",
            route_probes={"ipv6_literal_tcp": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08"},
            log_buckets={"dns_failed": 2},
        )
        verified = _verify_snapshot(snapshot)
        self.assertEqual(verified.verdict, "degraded")
        self.assertIn("fresh dns_failed=2", verified.reasons)

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
                "ipv6_literal_tcp_probe": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08",
            },
            ROLE_FOREIGN: {
                "role": ROLE_FOREIGN,
                "sing_box": "active",
                "wireguard": "active",
                "nftables": "active",
                "drift": "none",
                "observed_ipv4": "198.51.100.2",
            },
        }

        def fake_remote_preflight(target: RemoteTarget, _wg_interface: str) -> dict[str, str]:
            return preflights[target.role]

        with (
            patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
            patch("vpn_installer.workflows.print_summary"),
            patch("vpn_installer.workflows.print_preflight"),
            patch("vpn_installer.workflows.remote_preflight", side_effect=fake_remote_preflight),
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

        def fake_remote_preflight(target: RemoteTarget, _wg_interface: str) -> dict[str, str]:
            return preflights[target.role]

        with (
            patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {})),
            patch("vpn_installer.workflows.print_summary"),
            patch("vpn_installer.workflows.print_preflight"),
            patch("vpn_installer.workflows.print_deployment_health"),
            patch("vpn_installer.workflows.remote_preflight", side_effect=fake_remote_preflight),
        ):
            self.assertEqual(verify_live_workflow("demo", non_interactive=True), 1)


if __name__ == "__main__":
    unittest.main()
