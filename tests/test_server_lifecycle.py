from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import server_agent, server_lifecycle, server_runtime
from vpn_installer.config import generate_default_env


from tests.server_agent_fixtures import AgentFixtures


class ServerLifecycleTests(AgentFixtures, unittest.TestCase):
    def test_network_apply_uses_the_supplied_contract_without_interserver_on_single(self) -> None:
        env = {"WG_INTERFACE": "wg0"}
        with (
            patch.object(server_runtime, "parse_env", return_value=env),
            patch.object(server_lifecycle, "apply_qdisc_profile", return_value={"changed": False}) as qdisc,
            patch.object(server_lifecycle, "apply_wireguard_policy", return_value={"changed": True}) as wireguard,
        ):
            single = server_lifecycle.apply_network_profile(self.gateway_contract(topology="single"))
            qdisc.assert_called_once_with(include_overlay=False)
            wireguard.assert_not_called()
            self.assertFalse(single["changed"])
            self.assertTrue(single["wireguard_policy"]["not_applicable"])
            dual = server_lifecycle.apply_network_profile(self.gateway_contract())
            qdisc.assert_called_with(include_overlay=True)
            wireguard.assert_called_once_with(env)
            self.assertTrue(dual["changed"])

    @staticmethod
    def health_collectors():
        return {
            "collect_runtime_facts": server_agent.collect_runtime_facts,
            "front_interval_snapshot": server_agent.front_interval_snapshot,
            "apply_front_interval_verdict": server_agent.apply_front_interval_verdict,
            "front_degradation_evidence": server_agent.front_degradation_evidence,
        }

    def test_single_recovery_never_touches_interserver_services(self) -> None:
        current = {
            **self.gateway_contract(topology="single"),
            "services": {
                "nftables": "active",
                "sing-box": "active",
                "resolver": "active",
                "health_timer": "active",
                "xray": "active",
                "wireguard": "failed",
                "transport": "failed",
            },
            "artifacts": {"drift": "server-mutated"},
        }
        with patch.object(server_runtime, "run") as run_mock:
            action = server_lifecycle.recover(current)

        self.assertEqual(action, "none")
        run_mock.assert_not_called()

    def test_health_requires_two_failed_cycles_before_recovery(self) -> None:
        failed = {**self.gateway_contract(), "verdicts": {"server_path": "failed"}, "services": {}}
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "health.json"
            lock = Path(tmp) / "lock"
            with patch.object(server_runtime, "HEALTH_STATE_PATH", state), patch.object(server_runtime, "LOCK_PATH", lock), patch.object(server_agent, "collect_runtime_facts", return_value=failed) as snapshot_mock, patch.object(server_lifecycle, "recover", return_value="restart:sing-box.service:ok") as recover, patch.object(server_lifecycle.time, "sleep"):
                first = server_lifecycle.health(**self.health_collectors())
                second = server_lifecycle.health(**self.health_collectors())
        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["last_action"], "restart:sing-box.service:ok")
        recover.assert_called_once()
        self.assertFalse(snapshot_mock.call_args_list[0].kwargs["full_logs"])
        self.assertFalse(snapshot_mock.call_args_list[0].kwargs["include_maintenance"])

    def test_health_does_not_probe_or_recover_during_install_transaction(self) -> None:
        previous = {"consecutive_failures": 1, "hard_reasons": ["server_path"]}
        with (
            patch.object(server_runtime, "acquire_install_read_lock", return_value=None),
            patch.object(server_runtime, "read_json", return_value=previous),
            patch.object(server_agent, "collect_runtime_facts") as collect,
            patch.object(server_lifecycle, "recover") as recover,
        ):
            result = server_lifecycle.health(**self.health_collectors())

        self.assertEqual(result["state"], "maintenance")
        self.assertEqual(result["consecutive_failures"], 1)
        collect.assert_not_called()
        recover.assert_not_called()

    def test_health_does_not_combine_different_hard_failures(self) -> None:
        server_failed = {**self.gateway_contract(), "verdicts": {"server_path": "failed", "host_integrity": "verified"}, "services": {}}
        host_failed = {**self.gateway_contract(), "verdicts": {"server_path": "verified", "host_integrity": "failed"}, "services": {}}
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_runtime, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_runtime, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", side_effect=[server_failed, host_failed]),
                patch.object(server_lifecycle, "recover") as recover,
            ):
                first = server_lifecycle.health(**self.health_collectors())
                second = server_lifecycle.health(**self.health_collectors())

        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["state"], "suspect")
        self.assertEqual(second["consecutive_failures"], 1)
        recover.assert_not_called()

    def test_failed_recovery_does_not_start_cooldown(self) -> None:
        failed = {**self.gateway_contract(), "verdicts": {"server_path": "failed", "host_integrity": "verified"}, "services": {}}
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_runtime, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_runtime, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", return_value=failed),
                patch.object(server_lifecycle, "recover", return_value="restart:sing-box.service:failed") as recover,
            ):
                server_lifecycle.health(**self.health_collectors())
                second = server_lifecycle.health(**self.health_collectors())
                third = server_lifecycle.health(**self.health_collectors())

        self.assertEqual(second["state"], "failed")
        self.assertEqual(second["last_action_epoch"], 0)
        self.assertEqual(third["last_action_epoch"], 0)
        self.assertEqual(recover.call_count, 2)

    def test_health_never_restarts_services_for_filesystem_corruption(self) -> None:
        failed = {
            **self.exit_contract(),
            "generated_at": "2026-08-01T20:00:00+00:00",
            "verdicts": {
                "server_path": "verified",
                "host_integrity": "failed",
                "client_observation": "not-applicable",
            },
            "services": {},
            "probes": {"requirements": {"foreign_direct": True}},
            "network": {"interfaces": {}, "protocol_counters": {}, "softnet_counters": {}, "conntrack": {}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_runtime, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_runtime, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", return_value=failed),
                patch.object(server_lifecycle, "recover") as recover,
            ):
                first = server_lifecycle.health(**self.health_collectors())
                second = server_lifecycle.health(**self.health_collectors())

        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["state"], "failed")
        self.assertEqual(second["hard_reasons"], ["host_integrity"])
        self.assertEqual(second["last_action"], "none")
        recover.assert_not_called()

    def test_health_reports_udp_buffer_drops_as_degraded_without_recovery(self) -> None:
        def healthy(udp_drops: int) -> dict[str, object]:
            return {
                **self.exit_contract(),
                "verdicts": {"server_path": "verified"},
                "services": {},
                "probes": {"requirements": {"foreign_direct": True}},
                "network": {
                    "interfaces": {"eth0": {"rx_missed_errors": 0}},
                    "protocol_counters": {"UdpRcvbufErrors": udp_drops, "Udp6RcvbufErrors": 0},
                    "softnet_counters": {"dropped": 0},
                },
            }

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "health.json"
            lock = Path(tmp) / "lock"
            with (
                patch.object(server_runtime, "HEALTH_STATE_PATH", state),
                patch.object(server_runtime, "LOCK_PATH", lock),
                patch.object(server_agent, "collect_runtime_facts", side_effect=[healthy(10), healthy(13)]),
                patch.object(server_lifecycle, "recover") as recover,
            ):
                first = server_lifecycle.health(**self.health_collectors())
                second = server_lifecycle.health(**self.health_collectors())

        self.assertEqual(first["state"], "healthy")
        self.assertEqual(second["state"], "degraded")
        self.assertEqual(second["soft_reasons"], ["udp_receive_buffer_drops=3"])
        recover.assert_not_called()

    def test_health_reports_recent_conntrack_exhaustion_without_recovery(self) -> None:
        current = {
            **self.gateway_contract(),
            "verdicts": {"server_path": "verified"},
            "services": {},
            "probes": {"requirements": {"ru_direct": True, "via_wg": True, "router": True}},
            "network": {
                "interfaces": {},
                "protocol_counters": {},
                "softnet_counters": {},
                "conntrack": {"table_full_events": {"5": 2}},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "health.json"
            lock = Path(tmp) / "lock"
            with (
                patch.object(server_runtime, "HEALTH_STATE_PATH", state),
                patch.object(server_runtime, "LOCK_PATH", lock),
                patch.object(server_agent, "collect_runtime_facts", return_value=current),
                patch.object(server_lifecycle, "recover") as recover,
            ):
                result = server_lifecycle.health(**self.health_collectors())

        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["soft_reasons"], ["conntrack_table_full_5m=2"])
        recover.assert_not_called()

    def test_health_handles_unknown_conntrack_counts_and_retains_observed_loss(self) -> None:
        for observed, state, reasons in (
            (None, "healthy", []),
            (2, "degraded", ["conntrack_table_full_5m=2"]),
        ):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as tmp:
                current = {
                    **self.gateway_contract(),
                    "verdicts": {"server_path": "verified"},
                    "network": {"conntrack": {
                        "table_full_events": {"5": None},
                        "table_full_observed": {"5": observed},
                    }},
                }
                with (
                    patch.object(server_runtime, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                    patch.object(server_runtime, "LOCK_PATH", Path(tmp) / "lock"),
                    patch.object(server_agent, "collect_runtime_facts", return_value=current),
                    patch.object(server_lifecycle, "recover") as recover,
                ):
                    result = server_lifecycle.health(**self.health_collectors())
                self.assertEqual(result["state"], state)
                self.assertEqual(result["soft_reasons"], reasons)
                recover.assert_not_called()

    def test_health_does_not_replay_oom_from_before_current_release(self) -> None:
        current = {
            **self.gateway_contract(),
            "generated_at": "2026-08-21T10:00:00+00:00",
            "verdicts": {"server_path": "verified", "host_integrity": "verified"},
            "services": {},
            "probes": {"requirements": {"ru_direct": True, "via_wg": True, "router": True}},
            "network": {"interfaces": {}, "protocol_counters": {}, "softnet_counters": {}, "conntrack": {}},
            "storage": {
                "memory": {"router": {"automatic_restarts": 0}},
                "runtime_events": {
                    "oom_kills": {
                        "latest": {"timestamp": "2026-08-21T05:32:46+00:00", "message": "old OOM"},
                        "latest_since_release": {},
                    }
                },
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_runtime, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_runtime, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", return_value=current),
                patch.object(server_lifecycle, "recover") as recover,
            ):
                result = server_lifecycle.health(**self.health_collectors())

        self.assertEqual(result["state"], "healthy")
        self.assertEqual(result["soft_reasons"], [])
        self.assertEqual(result["last_seen_oom_timestamp"], "")
        recover.assert_not_called()

    def test_network_soft_reasons_do_not_promote_unscoped_host_tcp_or_generic_rx_drops(self) -> None:
        reasons = server_lifecycle.network_soft_reasons(
            {
                "interfaces": {
                    "eth0": {
                        "rx_packets": 24_693,
                        "rx_dropped": 67,
                        "rx_missed_errors": 0,
                    }
                },
                "protocol": {
                    "TcpOutSegs": 171,
                    "TcpRetransSegs": 26,
                    "TcpExtTCPTimeouts": 20,
                },
                "softnet": {"dropped": 0},
            }
        )

        self.assertEqual(reasons, [])

    def test_network_soft_reasons_require_specific_interface_loss_evidence(self) -> None:
        reasons = server_lifecycle.network_soft_reasons(
            {
                "interfaces": {"eth0": {"rx_packets": 20_000, "rx_dropped": 200, "rx_missed_errors": 0}},
                "protocol": {},
                "softnet": {"dropped": 0},
            }
        )
        self.assertEqual(reasons, [])

    def test_network_soft_reasons_ignore_low_volume_counter_noise(self) -> None:
        reasons = server_lifecycle.network_soft_reasons(
            {
                "interfaces": {"eth0": {"rx_packets": 1_000, "rx_dropped": 9}},
                "protocol": {
                    "TcpOutSegs": 99,
                    "TcpRetransSegs": 9,
                    "TcpExtTCPTimeouts": 2,
                },
            }
        )

        self.assertEqual(reasons, [])

    def test_network_soft_reasons_attribute_udp_send_errors_to_fq_flow_limit_once(self) -> None:
        reasons = server_lifecycle.network_soft_reasons(
            {
                "protocol": {"UdpSndbufErrors": 252, "Udp6SndbufErrors": 0},
                "qdisc": {"drops": 252, "flow_limit_drops": 252},
            }
        )
        self.assertEqual(reasons, ["qdisc_drops=252", "qdisc_flow_limit_drops=252"])

    def test_network_soft_reasons_keep_independent_udp_send_errors(self) -> None:
        reasons = server_lifecycle.network_soft_reasons(
            {
                "protocol": {"UdpSndbufErrors": 10},
                "qdisc": {"drops": 252, "flow_limit_drops": 252},
            }
        )
        self.assertEqual(reasons, ["qdisc_drops=252", "qdisc_flow_limit_drops=252", "udp_send_buffer_drops=10"])

    def test_health_log_summary_omits_persistent_flow_counters(self) -> None:
        payload = {
            "schema_version": 5,
            "updated_at": "2026-08-03T20:12:26+00:00",
            "state": "degraded",
            "consecutive_failures": 0,
            "last_action": "none",
            "hard_reasons": [],
            "probe_failures": [],
            "soft_reasons": ["public_front=client_specific"],
            "verdicts": {"overall": "degraded"},
            "front_counters": {"flows": {"socket": {"bytes_sent": 1000}}},
            "front_interval": {
                "observation": "client_specific",
                "degraded_sources": ["203.0.113.20"],
                "aggregate": {"bytes_sent": 1000, "bytes_retrans": 100},
                "flows": {"203.0.113.20:50000": {"bytes_sent": 1000}},
            },
        }

        summary = server_lifecycle.health_log_summary(payload)

        self.assertNotIn("front_counters", summary)
        self.assertNotIn("flows", summary["front_interval"])
        self.assertEqual(summary["front_interval"]["aggregate"]["bytes_retrans"], 100)

    def test_health_reports_client_specific_front_loss_without_recovery(self) -> None:
        current = {
            **self.gateway_contract(),
            "generated_at": "2026-07-20T08:00:00+00:00",
            "verdicts": {
                "server_path": "verified",
                "public_front": "degraded",
                "client_observation": "client_specific",
                "overall": "degraded",
                "reasons": ["public_front=client_specific"],
            },
            "services": {"xray": "active"},
            "probes": {"requirements": {"ru_direct": True, "via_wg": True, "router": True}},
            "network": {"interfaces": {}, "protocol_counters": {}, "softnet_counters": {}, "conntrack": {}},
            "front": {
                "listening": True,
                "connections": 1,
                "bytes_sent": 12_251,
                "bytes_retrans": 2_829,
                "retransmit_ratio_pct": 23.092,
                "degraded_sources": ["203.0.113.20"],
                "recent_degraded_sources": ["203.0.113.20"],
                "flows": {
                    "203.0.113.20:50123": {
                        "source": "203.0.113.20",
                        "quality": "degraded",
                        "bytes_retrans": 2_829,
                    }
                },
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_runtime, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_runtime, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", return_value=current),
                patch.object(server_lifecycle, "recover") as recover,
            ):
                result = server_lifecycle.health(**self.health_collectors())

        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["soft_reasons"], ["public_front=client_specific"])
        self.assertEqual(result["last_front_degradation"]["observed_at"], current["generated_at"])
        self.assertEqual(result["last_front_degradation"]["degraded_sources"], ["203.0.113.20"])
        recover.assert_not_called()

    def test_tcp_destination_metrics_parser_keeps_only_recovery_fields(self) -> None:
        metrics = server_lifecycle.parse_tcp_destination_metrics(
            "5.166.130.228",
            "5.166.130.228 age 425.952sec cwnd 2150 reordering 185 rtt 104073us rttvar 142185us source 94.232.248.35\n",
        )

        self.assertEqual(
            metrics,
            {
                "source": "5.166.130.228",
                "cached": True,
                "reordering": 185,
            },
        )

    def test_front_cache_recovery_deletes_only_confirmed_poisoned_destination(self) -> None:
        source = "5.166.130.228"
        front = {
            "flows": {
                f"{source}:50123": {
                    "source": source,
                    "phase": "active",
                    "rto_ms": {"max": 120_000},
                    "mss": 536,
                    "reordering": 185,
                }
            }
        }
        interval = {
            "observed_at": "2026-09-04T12:00:00+00:00",
            "baseline": False,
            "degraded_sources": [source],
        }
        previous = {
            "front_interval": {
                "observed_at": "2026-09-04T11:58:00+00:00",
                "degraded_sources": [source],
            }
        }

        def command(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if args[:3] == ["ip", "tcp_metrics", "show"]:
                return subprocess.CompletedProcess(args, 0, f"{source} age 300sec cwnd 2150 reordering 185 rtt 104073us\n", "")
            if args[:3] == ["ip", "tcp_metrics", "delete"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            raise AssertionError(args)

        with patch.object(server_runtime, "run", side_effect=command) as run_mock:
            result = server_lifecycle.reconcile_front_tcp_metrics_cache(
                front,
                interval,
                previous,
                interval["observed_at"],
                10_000,
            )

        self.assertEqual(result["actions"][0]["status"], "ok")
        self.assertEqual(
            [call.args[0] for call in run_mock.call_args_list],
            [["ip", "tcp_metrics", "show", source], ["ip", "tcp_metrics", "delete", source]],
        )

    def test_front_cache_recovery_preserves_cache_without_stall_or_confirmation(self) -> None:
        source = "5.166.130.228"
        interval = {
            "observed_at": "2026-09-04T12:00:00+00:00",
            "baseline": False,
            "degraded_sources": [source],
        }
        healthy_front = {
            "flows": {
                f"{source}:50123": {
                    "source": source,
                    "phase": "active",
                    "rto_ms": {"max": 500},
                    "mss": 1428,
                    "reordering": 185,
                }
            }
        }
        with patch.object(server_runtime, "run") as run_mock:
            healthy = server_lifecycle.reconcile_front_tcp_metrics_cache(
                healthy_front,
                interval,
                {},
                interval["observed_at"],
                10_000,
            )
        self.assertEqual(healthy["actions"], [])
        run_mock.assert_not_called()

        stalled_front = {
            "flows": {
                f"{source}:50123": {
                    "source": source,
                    "phase": "active",
                    "rto_ms": {"max": 120_000},
                    "mss": 536,
                    "reordering": 185,
                }
            }
        }
        with patch.object(server_runtime, "run") as run_mock:
            first = server_lifecycle.reconcile_front_tcp_metrics_cache(
                stalled_front,
                interval,
                {},
                interval["observed_at"],
                10_000,
            )
        self.assertEqual(first["actions"], [])
        run_mock.assert_not_called()

    def test_front_cache_recovery_honors_per_destination_cooldown(self) -> None:
        source = "5.166.130.228"
        observed_at = "2026-09-04T12:00:00+00:00"
        front = {
            "flows": {
                f"{source}:50123": {
                    "source": source,
                    "phase": "active",
                    "rto_ms": {"max": 120_000},
                    "mss": 536,
                }
            }
        }
        previous = {
            "front_interval": {
                "observed_at": "2026-09-04T11:58:00+00:00",
                "degraded_sources": [source],
            },
            "front_cache_recovery": {
                "last_actions": {
                    source: {
                        "source": source,
                        "status": "ok",
                        "epoch": 9_500,
                    }
                }
            },
        }
        with patch.object(server_runtime, "run") as run_mock:
            result = server_lifecycle.reconcile_front_tcp_metrics_cache(
                front,
                {"observed_at": observed_at, "baseline": False, "degraded_sources": [source]},
                previous,
                observed_at,
                10_000,
            )

        self.assertEqual(result["actions"], [])
        self.assertEqual(result["last_actions"][source]["epoch"], 9_500)
        run_mock.assert_not_called()

    def test_recovery_never_routes_foreign_traffic_through_ru(self) -> None:
        current = {
            **self.gateway_contract(),
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "probes": {"requirements": {"ru_direct": True, "via_wg": False, "router": False}},
        }
        with patch.object(server_runtime, "run") as run_mock:
            action = server_lifecycle.recover(current)
        self.assertEqual(action, "none")
        run_mock.assert_not_called()

    def test_recovery_restarts_router_when_acceptance_wg_fallback_is_healthy(self) -> None:
        current = {
            **self.gateway_contract(),
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "none"},
            "network": {"profile_mismatches": [], "conntrack": {"front_bypass": {"active": True}}},
            "probes": {
                "requirements": {
                    "foreign_domains_via_wg": True,
                    "foreign_domains_via_router": False,
                }
            },
        }
        completed = subprocess.CompletedProcess(["systemctl"], 0, "", "")
        with patch.object(server_runtime, "run", return_value=completed) as run_mock:
            action = server_lifecycle.recover(current)

        self.assertEqual(action, "restart:sing-box.service:ok")
        run_mock.assert_called_once_with(["systemctl", "restart", "sing-box.service"], timeout=30)

    def test_recovery_restarts_all_failed_required_services_including_transport(self) -> None:
        current = {
            **self.gateway_contract(),
            "services": {
                "wireguard": "inactive",
                "nftables": "inactive",
                "resolver": "active",
                "sing-box": "active",
                "xray": "active",
                "transport": "failed",
            },
            "wireguard": {"interface": "wg0"},
        }
        completed = subprocess.CompletedProcess(["systemctl"], 0, "", "")
        with patch.object(server_runtime, "run", return_value=completed) as run_mock:
            action = server_lifecycle.recover(current)

        self.assertEqual(
            action,
            "restart:wg-quick@wg0.service:ok;restart:vpn-stack-nftables.service:ok;restart:vpn-stack-transport.service:ok",
        )
        self.assertEqual(run_mock.call_count, 3)

    def test_recovery_reapplies_clean_managed_network_profile(self) -> None:
        current = {
            **self.gateway_contract(),
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "none"},
            "network": {"profile_mismatches": ["conntrack_max"]},
        }
        with patch.object(server_runtime, "run", return_value=subprocess.CompletedProcess(["sysctl"], 0, "", "")) as run_mock:
            action = server_lifecycle.recover(current)
        self.assertEqual(action, "reload:sysctl:ok")
        run_mock.assert_called_once_with(["sysctl", "--load", str(server_runtime.SYSCTL_PATH)], timeout=30)

    def test_recovery_reapplies_clean_managed_qdisc_profile(self) -> None:
        current = {
            **self.exit_contract(),
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "none"},
            "network": {"profile_mismatches": ["overlay_qdisc_flow_limit"]},
        }
        with patch.object(server_lifecycle, "apply_qdisc_profile", return_value={"changed": True}) as apply_mock:
            action = server_lifecycle.recover(current)
        self.assertEqual(action, "apply:qdisc:changed")
        apply_mock.assert_called_once_with()

    def test_recovery_repairs_clean_wireguard_policy_without_restart(self) -> None:
        current = {
            **self.gateway_contract(),
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active", "transport": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "none"},
            "network": {
                "wireguard_policy": {"managed": True, "ok": False, "missing": ["ipv6_rule"]},
                "profile_mismatches": [],
            },
        }
        with (
            patch.object(server_runtime, "parse_env", return_value=generate_default_env("demo")),
            patch.object(server_lifecycle, "apply_wireguard_policy", return_value={"changed": True}) as apply_mock,
        ):
            action = server_lifecycle.recover(current)
        self.assertEqual(action, "apply:wireguard-policy:changed")
        apply_mock.assert_called_once()

    def test_recovery_reloads_clean_nftables_when_bypass_is_missing(self) -> None:
        current = {
            **self.gateway_contract(),
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "none"},
            "network": {"profile_mismatches": [], "conntrack": {"front_bypass": {"active": False}}},
        }
        completed = subprocess.CompletedProcess(["systemctl"], 0, "", "")
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "nftables.conf"
            config_path.write_text("table inet vpnstack {}\n", encoding="utf-8")
            with (
                patch.object(server_runtime, "NFTABLES_CONFIG_PATH", config_path),
                patch.object(server_runtime, "run", return_value=completed) as run_mock,
            ):
                action = server_lifecycle.recover(current)
        self.assertEqual(action, "reload:vpn-stack-nftables.service:ok")
        run_mock.assert_called_once_with(["systemctl", "reload", "vpn-stack-nftables.service"], timeout=30)

    def test_recovery_never_applies_mutated_managed_artifacts(self) -> None:
        current = {
            **self.gateway_contract(),
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "server-mutated"},
            "network": {"profile_mismatches": ["conntrack_max"], "conntrack": {"front_bypass": {"active": False}}},
            "probes": {"requirements": {}},
        }
        with patch.object(server_runtime, "run") as run_mock:
            action = server_lifecycle.recover(current)
        self.assertEqual(action, "none")
        run_mock.assert_not_called()

    def test_positive_counter_deltas_ignore_first_sample_and_counter_reset(self) -> None:
        self.assertEqual(server_lifecycle.positive_counter_deltas({"UdpRcvbufErrors": 10}, {}), {})
        self.assertEqual(server_lifecycle.positive_counter_deltas({"UdpRcvbufErrors": 10}, {"UdpRcvbufErrors": 7}), {"UdpRcvbufErrors": 3})
        self.assertEqual(server_lifecycle.positive_counter_deltas({"UdpRcvbufErrors": 1}, {"UdpRcvbufErrors": 7}), {})

    def test_apply_qdisc_profile_manages_public_and_wireguard_interfaces(self) -> None:
        before = {"qdisc": "fq", "qdisc_limit": 10_000, "qdisc_flow_limit": 100, "qdisc_drops": 7, "qdisc_flow_limit_drops": 7}
        overlay_before = {"qdisc": "noqueue", "qdisc_limit": 0, "qdisc_flow_limit": 0, "qdisc_drops": 0, "qdisc_flow_limit_drops": 0}
        after = {**before, "qdisc_flow_limit": 512, "qdisc_drops": 0, "qdisc_flow_limit_drops": 0}
        completed = subprocess.CompletedProcess(["tc"], 0, "", "")
        with (
            patch.object(server_runtime, "default_interface", return_value="eth0"),
            patch.object(server_runtime, "parse_env", return_value={"WG_INTERFACE": "wg0"}),
            patch.object(Path, "exists", return_value=True),
            patch.object(server_runtime, "qdisc_snapshot", side_effect=[before, after, overlay_before, after]),
            patch.object(server_runtime, "run", return_value=completed) as run_mock,
        ):
            result = server_lifecycle.apply_qdisc_profile()
        self.assertTrue(result["changed"])
        self.assertEqual(result["overlay_qdisc"], "fq")
        self.assertEqual(
            [call.args[0][4] for call in run_mock.call_args_list],
            ["eth0", "wg0"],
        )

        with (
            patch.object(server_runtime, "default_interface", return_value="eth0"),
            patch.object(server_runtime, "parse_env", return_value={"WG_INTERFACE": "wg0"}),
            patch.object(Path, "exists", return_value=True),
            patch.object(server_runtime, "qdisc_snapshot", return_value=after),
            patch.object(server_runtime, "run") as unchanged_run,
        ):
            unchanged = server_lifecycle.apply_qdisc_profile()
        self.assertFalse(unchanged["changed"])
        unchanged_run.assert_not_called()

    def test_apply_wireguard_policy_repairs_only_missing_state(self) -> None:
        env = generate_default_env("demo")
        missing = {"managed": True, "ok": False, "missing": ["ipv6_rule"]}
        healthy = {"managed": True, "ok": True, "missing": []}
        completed = subprocess.CompletedProcess(["ip"], 0, "", "")
        with (
            patch.object(server_runtime, "wireguard_policy_snapshot", side_effect=[missing, healthy]),
            patch.object(server_runtime, "run", return_value=completed) as run_mock,
        ):
            result = server_lifecycle.apply_wireguard_policy(env)

        self.assertTrue(result["changed"])
        run_mock.assert_called_once_with(
            ["ip", "-6", "rule", "add", "fwmark", "48", "table", "51820", "priority", "10000"],
            timeout=10,
        )
