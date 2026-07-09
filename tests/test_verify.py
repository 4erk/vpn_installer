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
        self.assertEqual(verified.verdict, "verified")

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
            },
            ROLE_FOREIGN: {
                "role": ROLE_FOREIGN,
                "sing_box": "active",
                "wireguard": "active",
                "nftables": "active",
                "drift": "none",
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


if __name__ == "__main__":
    unittest.main()
