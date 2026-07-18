from __future__ import annotations

import unittest

from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.status_output import format_snapshot_summary


class StatusOutputTests(unittest.TestCase):
    def test_explains_when_read_only_status_skips_live_probes(self) -> None:
        lines = format_snapshot_summary(
            DiagnosticsSnapshot(
                verdict="inconclusive",
                route_probes={"profile": "none", "ok": None},
            )
        )
        self.assertIn("live probes: not run by read-only status; use vpn verify live for route acceptance", lines)

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
                runtime_overrides={"admin_routing_rules_count": "2"},
                network={
                    "tcp_adaptation": {
                        "congestion_control": "bbr",
                        "qdisc": "fq",
                        "mtu_probing": 1,
                        "probe_interval_seconds": 600,
                        "udp_rmem_default": 4194304,
                        "udp_rmem_max": 16777216,
                    },
                    "protocol_counters": {"UdpRcvbufErrors": 816},
                    "recent_health_deltas": {"protocol": {"UdpRcvbufErrors": 3}},
                },
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
        self.assertIn("runtime overrides:", rendered)
        self.assertIn("admin_routing_rules_count=2", rendered)
        self.assertIn("domain_to_foreign_timeout present", rendered)
        self.assertIn("tcp adaptation: cc=bbr, qdisc=fq, mtu_probing=1, probe_interval_s=600", rendered)
        self.assertIn("udp_rmem=4194304/16777216", rendered)
        self.assertIn("protocol counters (lifetime): UdpRcvbufErrors=816", rendered)
        self.assertIn("protocol deltas (last health cycle): UdpRcvbufErrors=+3", rendered)


if __name__ == "__main__":
    unittest.main()
