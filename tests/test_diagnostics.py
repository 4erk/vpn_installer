from __future__ import annotations

import unittest

from vpn_installer.diagnostics import DiagnosticsSnapshot


class DiagnosticsTests(unittest.TestCase):
    def test_snapshot_roundtrips_json_without_shell_parsing(self) -> None:
        snapshot = DiagnosticsSnapshot(
            deployment="demo",
            role="ru-gateway",
            services={"sing-box": "active"},
            drift="none",
            log_buckets={"ipv4_literal_timeout": 2},
            top_destinations={"ipv4_literal_timeout": "91.108.56.103:443=2"},
            verdict="verified",
        )
        restored = DiagnosticsSnapshot.from_json(snapshot.to_json())
        self.assertEqual(restored.deployment, "demo")
        self.assertEqual(restored.log_buckets["ipv4_literal_timeout"], 2)
        self.assertEqual(restored.drift, "none")

    def test_snapshot_from_preflight_separates_fresh_and_historical_windows(self) -> None:
        snapshot = DiagnosticsSnapshot.from_preflight(
            {
                "deployment_name": "demo",
                "role": "ru-gateway",
                "sing_box": "active",
                "xray": "active",
                "wireguard": "active",
                "nftables": "active",
                "singbox_log_window_minutes": "30",
                "singbox_recent_to_foreign_ip_literal_timeout_count": "2",
                "singbox_to_foreign_ip_literal_timeout_count": "4",
                "singbox_fresh_ipv6_literal_timeout_destinations": "[2606:4700:4700::1111]:443=1",
                "ipv6_literal_tcp_probe": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08",
                "xray_recent_disabled_invalid_count": "3",
                "drift": "none",
            }
        )
        self.assertEqual(snapshot.fresh_window_minutes, 30)
        self.assertEqual(snapshot.historical_window_hours, 4)
        self.assertEqual(snapshot.log_buckets["ipv4_literal_timeout"], 2)
        self.assertEqual(snapshot.historical_log_buckets["ipv4_literal_timeout"], 4)
        self.assertEqual(snapshot.log_buckets["disabled_invalid"], 3)
        self.assertEqual(snapshot.top_destinations["ipv6_literal_timeout"], "[2606:4700:4700::1111]:443=1")
        self.assertEqual(snapshot.route_probes["ipv6_literal_tcp"], "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08")


if __name__ == "__main__":
    unittest.main()
