from __future__ import annotations

import unittest

from vpn_installer.diagnostics import (
    COLLECTOR_NAMES,
    LOG_WINDOW_KEYS,
    CollectorState,
    DiagnosticsSnapshot,
    LogWindowSnapshot,
)
from vpn_installer.log_classifier import BUCKETS
from vpn_installer.status_output import format_snapshot_summary


OBSERVED_AT = "2026-07-20T08:00:00Z"


def ok_collectors() -> dict[str, CollectorState]:
    return {name: CollectorState.ok(OBSERVED_AT) for name in COLLECTOR_NAMES}


def collected_windows() -> dict[str, LogWindowSnapshot]:
    return {
        name: LogWindowSnapshot.empty(observed_at=OBSERVED_AT, since=name, until=OBSERVED_AT)
        for name in LOG_WINDOW_KEYS
    }


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
        windows = collected_windows()
        windows["5m"] = LogWindowSnapshot.collected(
            {bucket: 2 if bucket == "ipv4_literal_timeout" else 0 for bucket in BUCKETS},
            observed_at=OBSERVED_AT,
            since="2026-07-20T07:55:00Z",
            until=OBSERVED_AT,
            top_destinations={"ipv4_literal_timeout": {"91.108.56.103:443": 2}},
        )
        windows["24h"] = LogWindowSnapshot.collected(
            {bucket: 9 if bucket == "ipv4_literal_timeout" else 0 for bucket in BUCKETS},
            observed_at=OBSERVED_AT,
            since="2026-07-19T08:00:00Z",
            until=OBSERVED_AT,
        )
        lines = format_snapshot_summary(
            DiagnosticsSnapshot(
                role="ru-gateway",
                drift="none",
                verdict="degraded",
                collectors=ok_collectors(),
                log_windows=windows,
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
                front={
                    "loss_observed_sources": ["203.0.113.20"],
                    "reality_target": "r.bing.com:443",
                    "reality_target_config_key": "target",
                    "reality_server_names": ["www.bing.com"],
                    "reality_pending_handshakes": 0,
                },
                network={
                    "tcp_adaptation": {
                        "congestion_control": "bbr",
                        "qdisc": "fq",
                        "qdisc_limit": 10000,
                        "qdisc_flow_limit": 512,
                        "qdisc_drops": 7,
                        "qdisc_flow_limit_drops": 7,
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "probe_interval_seconds": 600,
                        "udp_rmem_default": 8388608,
                        "udp_rmem_max": 16777216,
                        "udp_wmem_default": 8388608,
                        "udp_wmem_max": 16777216,
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
                        "mode": "stable-wireguard-overlay",
                        "hysteria_session_active": True,
                        "adaptive_state": {
                            "state": "healthy",
                            "reason": "selected underlay is healthy",
                            "overlay_probe": {
                                "checked": True,
                                "ok": True,
                                "delay_ms": 18,
                                "target": "10.74.0.2:1053",
                            },
                            "probes": {
                                "interserver-underlay-hy2": {
                                    "checked": True,
                                    "ok": True,
                                    "delay_ms": 23,
                                    "scope": "raw-underlay-udp",
                                }
                            },
                        },
                        "selection": {
                            "selected": "interserver-underlay-wg",
                            "candidates": {
                                "interserver-underlay-hy2": {"configured": True},
                                "interserver-underlay-wg": {"configured": True},
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
        self.assertIn("snapshot schema: 3", rendered)
        self.assertIn("collector status: ok", rendered)
        self.assertIn(
            "log window 5m: status=ok (observed=2026-07-20T08:00:00Z), "
            "since=2026-07-20T07:55:00Z, until=2026-07-20T08:00:00Z, counts=ipv4_literal_timeout=2",
            rendered,
        )
        self.assertIn("log window 24h:", rendered)
        self.assertIn("counts=ipv4_literal_timeout=9", rendered)
        self.assertIn("top destinations [5m]: ipv4_literal_timeout:91.108.56.103:443=2", rendered)
        self.assertIn("runtime overrides:", rendered)
        self.assertIn("admin_routing_rules_count=2", rendered)
        self.assertIn("root filesystem: source=/dev/vda1, fs=ext4, state=clean, errors=0, boot_fsck=enabled, verdict=verified", rendered)
        self.assertIn("public front lifetime loss sources: 203.0.113.20", rendered)
        self.assertIn(
            "Reality target: target=r.bing.com:443, config_key=target, "
            "server_names=www.bing.com, pending_handshakes=0",
            rendered,
        )
        self.assertIn("domain_to_foreign_timeout present", rendered)
        self.assertIn(
            "tcp adaptation: cc=bbr, qdisc=fq(limit=10000,flow_limit=512,drops=7,flow_limit_drops=7), "
            "mtu_probing=1, mtu_floor=536, metrics_cache=enabled, probe_interval_s=600",
            rendered,
        )
        self.assertIn("udp_rmem=8388608/16777216", rendered)
        self.assertIn("udp_wmem=8388608/16777216", rendered)
        self.assertIn("conntrack: 95/32768 (0.29%)", rendered)
        self.assertIn("xray_front_bypass=active", rendered)
        self.assertIn("table_full=5m:0,30m:2,24h:23", rendered)
        self.assertIn("health: degraded", rendered)
        self.assertIn("soft=conntrack_table_full_5m=2", rendered)
        self.assertIn("protocol counters (lifetime): UdpRcvbufErrors=816", rendered)
        self.assertIn("protocol deltas (last health cycle): UdpRcvbufErrors=+3", rendered)
        self.assertIn("interface counters (unscoped, informational; last health cycle): eth0.rx_dropped=+64", rendered)
        self.assertIn("host-wide tcp counters (informational; last health cycle): out=10000, retrans=125 (1.250%)", rendered)
        self.assertIn("tcp recovery deltas: TcpExtTCPSACKReorder=+20, TcpExtTCPDSACKRecv=+7, TcpExtTCPTimeouts=+2", rendered)
        self.assertIn("last front degradation: at=2026-07-20T07:58:00+00:00, sources=203.0.113.20", rendered)
        self.assertIn(
            "interserver transport: mode=stable-wireguard-overlay, selected=interserver-underlay-wg, "
            "configured_candidates=interserver-underlay-hy2,interserver-underlay-wg, "
            "overlay_probe=ok(18ms,target=10.74.0.2:1053), "
            "cold_probe=interserver-underlay-hy2:ok(23ms), adaptation=healthy, "
            "hy2_session=active, reason=selected underlay is healthy",
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
            "interserver transport: mode=hysteria2-egress, listener=active, source=94.232.248.35",
            rendered,
        )

    def test_omits_a_probe_that_was_not_executed(self) -> None:
        rendered = "\n".join(
            format_snapshot_summary(
                DiagnosticsSnapshot(
                    role="ru-gateway",
                    transport={
                        "interserver": {
                            "mode": "stable-wireguard-overlay",
                            "adaptive_state": {"state": "healthy"},
                            "selection": {
                                "selected": "interserver-underlay-wg",
                                "candidates": {"interserver-underlay-hy2": {"configured": True}},
                            },
                        }
                    },
                )
            )
        )
        self.assertIn("configured_candidates=interserver-underlay-hy2", rendered)
        self.assertNotIn("probe=", rendered)
        self.assertNotIn("not-probed", rendered)
        self.assertNotIn("Nonems", rendered)

    def test_formats_stale_adaptation_and_fresh_front_interval(self) -> None:
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
                            "mode": "stable-wireguard-overlay",
                            "adaptive_state": {
                                "state": "healthy",
                                "fresh": False,
                                "age_seconds": 120.0,
                                "overlay_probe": {
                                    "checked": True,
                                    "ok": True,
                                    "delay_ms": 62,
                                    "target": "10.74.0.2:1053",
                                },
                            },
                            "selection": {
                                "selected": "interserver-underlay-hy2",
                                "candidates": {
                                    "interserver-underlay-hy2": {
                                        "configured": True,
                                    }
                                },
                            },
                        }
                    },
                )
            )
        )
        self.assertIn("overlay_probe=ok(62ms,target=10.74.0.2:1053)", rendered)
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
        self.assertIn(
            "host-wide tcp counters (informational; last health cycle): out=unavailable, retrans=229",
            lines,
        )

    def test_distinguishes_unavailable_log_data_from_collected_zero(self) -> None:
        windows = collected_windows()
        windows["5m"] = LogWindowSnapshot.unavailable("journalctl timed out")
        rendered = "\n".join(
            format_snapshot_summary(
                DiagnosticsSnapshot(
                    collectors={
                        **ok_collectors(),
                        "logs": CollectorState.error("journalctl timed out"),
                    },
                    log_windows=windows,
                )
            )
        )
        self.assertIn("collector status: error", rendered)
        self.assertIn("log window 5m: status=error (journalctl timed out), counts=unavailable", rendered)
        self.assertIn("log window 30m:", rendered)
        self.assertIn("counts=no classified events", rendered)


if __name__ == "__main__":
    unittest.main()
