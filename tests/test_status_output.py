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
                fresh_since="2026-07-20T08:00:00Z",
                runtime_overrides={"admin_routing_rules_count": "2"},
                storage={
                    "root_filesystem": {
                        "source": "/dev/vda1",
                        "filesystem": "ext4",
                        "state": "clean",
                        "errors_count": 0,
                        "boot_check_enabled": True,
                        "verdict": "verified",
                    }
                },
                front={"loss_observed_sources": ["203.0.113.20"]},
                network={
                    "tcp_adaptation": {
                        "congestion_control": "bbr",
                        "qdisc": "fq",
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "probe_interval_seconds": 600,
                        "udp_rmem_default": 8388608,
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
                        "interfaces": {"eth0": {"rx_dropped": 64, "rx_errors": 0}},
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
                transport={
                    "interserver": {
                        "mode": "priority-wireguard-hysteria2",
                        "hysteria_session_active": True,
                        "adaptive_state": {"state": "healthy", "reason": "primary transport is healthy"},
                        "selection": {
                            "selected": "to-foreign-wg",
                            "selection_pending": False,
                            "candidates": {
                                "to-foreign-hy2": {"delay_ms": 23},
                                "to-foreign-wg": {"delay_ms": 74},
                            },
                        },
                    }
                },
                reasons=["domain_to_foreign_timeout present"],
            )
        )
        rendered = "\n".join(lines)
        self.assertIn("role: ru-gateway", rendered)
        self.assertIn("drift: none", rendered)
        self.assertIn("current log window: since=2026-07-20T08:00:00Z, duration=30m", rendered)
        self.assertIn("historical window: 4h", rendered)
        self.assertIn("ipv4_literal_timeout=2", rendered)
        self.assertIn("historical log buckets: ipv4_literal_timeout=9", rendered)
        self.assertIn("91.108.56.103:443=2", rendered)
        self.assertIn("runtime overrides:", rendered)
        self.assertIn("admin_routing_rules_count=2", rendered)
        self.assertIn("root filesystem: source=/dev/vda1, fs=ext4, state=clean, errors=0, boot_fsck=enabled, verdict=verified", rendered)
        self.assertIn("public front lifetime loss sources: 203.0.113.20", rendered)
        self.assertIn("domain_to_foreign_timeout present", rendered)
        self.assertIn("tcp adaptation: cc=bbr, qdisc=fq, mtu_probing=1, mtu_floor=536, metrics_cache=enabled, probe_interval_s=600", rendered)
        self.assertIn("udp_rmem=8388608/16777216", rendered)
        self.assertIn("conntrack: 95/32768 (0.29%)", rendered)
        self.assertIn("xray_front_bypass=active", rendered)
        self.assertIn("table_full=5m:0,30m:2,24h:23", rendered)
        self.assertIn("health: degraded", rendered)
        self.assertIn("soft=conntrack_table_full_5m=2", rendered)
        self.assertIn("protocol counters (lifetime): UdpRcvbufErrors=816", rendered)
        self.assertIn("protocol deltas (last health cycle): UdpRcvbufErrors=+3", rendered)
        self.assertIn("interface deltas (last health cycle): eth0.rx_dropped=+64", rendered)
        self.assertIn("host-wide tcp deltas (last health cycle): out=10000, retrans=125 (1.250%)", rendered)
        self.assertIn("tcp recovery deltas: TcpExtTCPSACKReorder=+20, TcpExtTCPDSACKRecv=+7, TcpExtTCPTimeouts=+2", rendered)
        self.assertIn("last front degradation: at=2026-07-20T07:58:00+00:00, sources=203.0.113.20", rendered)
        self.assertIn(
            "interserver transport: mode=priority-wireguard-hysteria2, selected=to-foreign-wg, "
            "candidates=to-foreign-hy2=23ms,to-foreign-wg=74ms, adaptation=healthy, hy2_session=active, "
            "reason=primary transport is healthy",
            rendered,
        )

    def test_formats_foreign_interserver_listener(self) -> None:
        rendered = "\n".join(
            format_snapshot_summary(
                DiagnosticsSnapshot(
                    role="foreign-exit",
                    transport={
                        "interserver": {
                            "mode": "hysteria2-egress",
                            "listening": True,
                            "source_restricted_to": "94.232.248.35",
                        }
                    },
                )
            )
        )
        self.assertIn(
            "interserver transport: mode=hysteria2-egress, selected=-, candidates=-, "
            "listener=active, source=94.232.248.35",
            rendered,
        )

    def test_formats_unmeasured_transport_without_none_milliseconds(self) -> None:
        rendered = "\n".join(
            format_snapshot_summary(
                DiagnosticsSnapshot(
                    role="ru-gateway",
                    transport={
                        "interserver": {
                            "mode": "priority-wireguard-hysteria2",
                            "selection": {"selected": "to-foreign-wg", "candidates": {"to-foreign-hy2": {"delay_ms": None}}},
                        }
                    },
                )
            )
        )
        self.assertIn("to-foreign-hy2=not-probed", rendered)
        self.assertNotIn("Nonems", rendered)

    def test_formats_stale_transport_shadow_and_fresh_front_interval(self) -> None:
        rendered = "\n".join(
            format_snapshot_summary(
                DiagnosticsSnapshot(
                    role="ru-gateway",
                    network={
                        "recent_front_interval": {
                            "observed_at": "2026-07-30T20:02:00+00:00",
                            "observation": "client_specific",
                            "sampled_flows": 2,
                            "degraded_sources": ["203.0.113.20"],
                            "aggregate": {
                                "activity_bytes": 2_000_000,
                                "bytes_retrans": 80_000,
                                "retransmit_ratio_pct": 4.0,
                            },
                        }
                    },
                    transport={
                        "interserver": {
                            "mode": "priority-wireguard-hysteria2",
                            "adaptive_state": {
                                "state": "healthy",
                                "fresh": False,
                                "age_seconds": 120.0,
                            },
                            "selection": {
                                "selected": "to-foreign-hy2",
                                "candidates": {
                                    "to-foreign-hy2": {
                                        "delay_ms": 62,
                                        "fresh": False,
                                        "age_seconds": 120.0,
                                    }
                                },
                            },
                        }
                    },
                )
            )
        )
        self.assertIn("to-foreign-hy2=stale(62ms,age=120.0s)", rendered)
        self.assertIn("adaptation=stale(healthy,age=120.0s)", rendered)
        self.assertIn(
            "front interval: at=2026-07-30T20:02:00+00:00, observation=client_specific, "
            "flows=2, sources=203.0.113.20, retrans=80000/2000000 (4.0%)",
            rendered,
        )

    def test_does_not_invent_retransmit_ratio_without_out_segments(self) -> None:
        lines = format_snapshot_summary(
            DiagnosticsSnapshot(network={"recent_health_deltas": {"protocol": {"TcpRetransSegs": 229}}})
        )
        self.assertIn("host-wide tcp deltas (last health cycle): out=unavailable, retrans=229", lines)


if __name__ == "__main__":
    unittest.main()
