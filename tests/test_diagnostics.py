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
                "singbox_to_foreign_ip_literal_timeout_count": "4",
                "xray_recent_disabled_invalid_count": "3",
                "drift": "none",
            }
        )
        self.assertEqual(snapshot.fresh_window_minutes, 30)
        self.assertEqual(snapshot.historical_window_hours, 4)
        self.assertEqual(snapshot.log_buckets["ipv4_literal_timeout"], 4)
        self.assertEqual(snapshot.log_buckets["disabled_invalid"], 3)


if __name__ == "__main__":
    unittest.main()
