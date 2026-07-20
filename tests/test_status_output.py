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
                    "conntrack": {
                        "count": 95,
                        "max": 32768,
                        "percent": 0.29,
                        "front_bypass": {"active": True, "ingress": True, "egress": True},
                        "table_full_events": {"5": 0, "30": 2, "1440": 23},
                    },
                    "health_state": "degraded",
                    "health_updated_at": "2026-07-20T08:00:00+00:00",
                    "health_soft_reasons": ["conntrack_table_full_5m=2"],
                    "protocol_counters": {"UdpRcvbufErrors": 816},
                    "recent_health_deltas": {
                        "protocol": {
                            "UdpRcvbufErrors": 3,
                            "TcpOutSegs": 10_000,
                            "TcpRetransSegs": 125,
                            "TcpExtTCPSACKReorder": 20,
                            "TcpExtTCPDSACKRecv": 7,
                            "TcpExtTCPTimeouts": 2,
                        }
                    },
                    "last_front_degradation": {
                        "observed_at": "2026-07-20T07:58:00+00:00",
                        "degraded_sources": ["203.0.113.20"],
                        "aggregate": {"bytes_sent": 12_251, "bytes_retrans": 2_829, "retransmit_ratio_pct": 23.092},
                    },
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
        self.assertIn("conntrack: 95/32768 (0.29%)", rendered)
        self.assertIn("xray_front_bypass=active", rendered)
        self.assertIn("table_full=5m:0,30m:2,24h:23", rendered)
        self.assertIn("health: degraded", rendered)
        self.assertIn("soft=conntrack_table_full_5m=2", rendered)
        self.assertIn("protocol counters (lifetime): UdpRcvbufErrors=816", rendered)
        self.assertIn("protocol deltas (last health cycle): UdpRcvbufErrors=+3", rendered)
        self.assertIn("tcp deltas (last health cycle): out=10000, retrans=125 (1.250%)", rendered)
        self.assertIn("tcp recovery deltas: TcpExtTCPSACKReorder=+20, TcpExtTCPDSACKRecv=+7, TcpExtTCPTimeouts=+2", rendered)
        self.assertIn("last front degradation: at=2026-07-20T07:58:00+00:00, sources=203.0.113.20", rendered)

    def test_does_not_invent_retransmit_ratio_without_out_segments(self) -> None:
        lines = format_snapshot_summary(
            DiagnosticsSnapshot(network={"recent_health_deltas": {"protocol": {"TcpRetransSegs": 229}}})
        )
        self.assertIn("tcp deltas (last health cycle): out=unavailable, retrans=229", lines)


if __name__ == "__main__":
    unittest.main()
