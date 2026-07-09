from __future__ import annotations

import unittest

from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.status_output import format_snapshot_summary


class StatusOutputTests(unittest.TestCase):
    def test_formats_snapshot_windows_buckets_destinations_and_reasons(self) -> None:
        lines = format_snapshot_summary(
            DiagnosticsSnapshot(
                role="ru-gateway",
                drift="none",
                verdict="degraded",
                fresh_window_minutes=30,
                historical_window_hours=4,
                log_buckets={"ipv4_literal_timeout": 2},
                historical_log_buckets={"ipv4_literal_timeout": 9},
                top_destinations={"ipv4_literal_timeout": "91.108.56.103:443=2"},
                dataplane_cache={"good_wg_path_age_s": "45", "route_fail_ipv4_literal_count": "2"},
                reasons=["domain_to_foreign_timeout present"],
            )
        )
        rendered = "\n".join(lines)
        self.assertIn("role: ru-gateway", rendered)
        self.assertIn("drift: none", rendered)
        self.assertIn("fresh window: 30m", rendered)
        self.assertIn("historical window: 4h", rendered)
        self.assertIn("ipv4_literal_timeout=2", rendered)
        self.assertIn("historical log buckets: ipv4_literal_timeout=9", rendered)
        self.assertIn("91.108.56.103:443=2", rendered)
        self.assertIn("dataplane cache:", rendered)
        self.assertIn("good_wg_path_age_s=45", rendered)
        self.assertIn("domain_to_foreign_timeout present", rendered)


if __name__ == "__main__":
    unittest.main()
