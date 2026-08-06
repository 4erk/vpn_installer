from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vpn_installer import server_agent
from vpn_installer.log_classifier import classify_line


class ServerAgentTests(unittest.TestCase):
    def test_classifier_assigns_timeout_to_one_bucket(self) -> None:
        line = "ERROR dns: exchange failed for www.msftconnecttest.com. IN A: context deadline exceeded"
        classified = classify_line(line)
        self.assertIsNotNone(classified)
        self.assertEqual(classified.bucket, "dns_timeout")

    def test_classifier_separates_ipv6_literal_from_domain_timeout(self) -> None:
        line = "ERROR open connection to [2a0a:f280:203:a:5000::100]:443 using outbound/direct[to-foreign]: i/o timeout"
        classified = classify_line(line)
        self.assertIsNotNone(classified)
        self.assertEqual(classified.bucket, "ipv6_literal_timeout")

    def test_private_reject_requires_fast_rejection_for_each_target(self) -> None:
        failed = subprocess.CompletedProcess(["curl"], 7, "", "blocked")
        with (
            patch.object(server_agent, "run", return_value=failed),
            patch.object(server_agent.time, "monotonic", side_effect=[1.0, 1.01, 2.0, 2.01]),
        ):
            result = server_agent.probe_private_reject("socks5h://127.0.0.1:2080")

        self.assertTrue(result["ok"])
        self.assertEqual([item["target"] for item in result["targets"]], ["http://10.0.0.1:80/", "http://172.19.0.2:853/"])

    def test_private_reject_rejects_a_slow_failure(self) -> None:
        failed = subprocess.CompletedProcess(["curl"], 28, "", "timeout")
        with (
            patch.object(server_agent, "run", return_value=failed),
            patch.object(server_agent.time, "monotonic", side_effect=[1.0, 3.1, 4.0, 4.01]),
        ):
            result = server_agent.probe_private_reject("socks5h://127.0.0.1:2080")

        self.assertFalse(result["ok"])

    def test_manifest_snapshot_detects_asset_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset = root / "geosite-ru.srs"
            asset.write_bytes(b"good")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"schema_version": 2, "assets": {"geosite-ru.srs": {"sha256": server_agent.sha256_file(asset), "install_path": str(asset)}}}), encoding="utf-8")
            with patch.object(server_agent, "MANIFEST_PATH", manifest), patch.object(server_agent, "ENV_PATH", root / "env"):
                self.assertEqual(server_agent.manifest_snapshot()["drift"], "none")
                asset.write_bytes(b"changed")
                self.assertEqual(server_agent.manifest_snapshot()["drift"], "server-mutated")

    def test_manifest_snapshot_detects_binary_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "sing-box"
            binary.write_bytes(b"known-binary")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "binaries": {"sing-box": {"version": "1.13.12", "path": str(binary), "sha256": server_agent.sha256_file(binary)}},
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_agent, "MANIFEST_PATH", manifest), patch.object(server_agent, "ENV_PATH", root / "env"):
                self.assertEqual(server_agent.manifest_snapshot()["binaries"]["sing-box"]["state"], "ok")
                binary.write_bytes(b"mutated-binary")
                snapshot = server_agent.manifest_snapshot()
        self.assertEqual(snapshot["drift"], "server-mutated")
        self.assertEqual(snapshot["binaries"]["sing-box"]["state"], "mutated")

    def test_assets_command_only_reports_manifest_bound_state(self) -> None:
        with patch.object(server_agent, "manifest_snapshot", return_value={"drift": "none", "assets": {"geoip-ru.srs": {"state": "ok"}}}):
            payload = server_agent.assets_snapshot()
        self.assertEqual(payload, {"drift": "none", "assets": {"geoip-ru.srs": {"state": "ok"}}})

    def test_root_filesystem_snapshot_verifies_clean_ext4_and_boot_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounts = root / "mounts"
            fstab = root / "fstab"
            sysfs = root / "sysfs" / "vda1"
            sysfs.mkdir(parents=True)
            mounts.write_text("/dev/vda1 / ext4 rw,relatime 0 0\n", encoding="utf-8")
            fstab.write_text("LABEL=root / ext4 defaults 0 1\n", encoding="utf-8")
            for name, value in (("errors_count", "0"), ("first_error_time", "0"), ("last_error_time", "0")):
                (sysfs / name).write_text(value, encoding="utf-8")
            tune = subprocess.CompletedProcess(
                ["tune2fs"],
                0,
                "Filesystem state:         clean\nFS Error count:          0\nLast checked:             Sat Aug  1 19:56:37 2026\n",
                "",
            )
            with patch.object(server_agent, "run", return_value=tune):
                result = server_agent.root_filesystem_snapshot(mounts, fstab, root / "sysfs")

        self.assertEqual(result["verdict"], "verified")
        self.assertTrue(result["boot_check_enabled"])
        self.assertEqual(result["errors_count"], 0)
        self.assertEqual(result["state"], "clean")

    def test_block_device_name_resolves_dev_root_alias_through_sysfs_device_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            metadata = Mock(st_rdev=123)
            with (
                patch.object(server_agent.os, "stat", return_value=metadata),
                patch.object(server_agent.os, "major", return_value=253, create=True),
                patch.object(server_agent.os, "minor", return_value=1, create=True),
                patch.object(server_agent.Path, "read_text", autospec=True, return_value="MAJOR=253\nMINOR=1\nDEVNAME=vda1\n") as read_text,
            ):
                name = server_agent.block_device_name("/dev/root", Path(tmp))

        self.assertEqual(name, "vda1")
        self.assertEqual(read_text.call_args.args[0], Path(tmp) / "253:1" / "uevent")
        self.assertEqual(read_text.call_args.kwargs, {"encoding": "utf-8"})

    def test_root_filesystem_snapshot_fails_on_ext4_metadata_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounts = root / "mounts"
            fstab = root / "fstab"
            sysfs = root / "sysfs" / "vda1"
            sysfs.mkdir(parents=True)
            mounts.write_text("/dev/vda1 / ext4 rw,relatime 0 0\n", encoding="utf-8")
            fstab.write_text("LABEL=root / ext4 defaults 0 1\n", encoding="utf-8")
            (sysfs / "errors_count").write_text("3", encoding="utf-8")
            tune = subprocess.CompletedProcess(["tune2fs"], 0, "Filesystem state:         clean with errors\n", "")
            with patch.object(server_agent, "run", return_value=tune):
                result = server_agent.root_filesystem_snapshot(mounts, fstab, root / "sysfs")

        self.assertEqual(result["verdict"], "failed")
        self.assertIn("offline fsck", result["reason"])

    def test_root_filesystem_snapshot_degrades_when_boot_check_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounts = root / "mounts"
            fstab = root / "fstab"
            sysfs = root / "sysfs" / "vda1"
            sysfs.mkdir(parents=True)
            mounts.write_text("/dev/vda1 / ext4 rw,relatime 0 0\n", encoding="utf-8")
            fstab.write_text("LABEL=root / ext4 defaults 0 0\n", encoding="utf-8")
            (sysfs / "errors_count").write_text("0", encoding="utf-8")
            tune = subprocess.CompletedProcess(["tune2fs"], 0, "Filesystem state:         clean\n", "")
            with patch.object(server_agent, "run", return_value=tune):
                result = server_agent.root_filesystem_snapshot(mounts, fstab, root / "sysfs")

        self.assertEqual(result["verdict"], "degraded")
        self.assertFalse(result["boot_check_enabled"])

    def test_root_filesystem_snapshot_is_inconclusive_without_runtime_error_counter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounts = root / "mounts"
            fstab = root / "fstab"
            mounts.write_text("/dev/vda1 / ext4 rw,relatime 0 0\n", encoding="utf-8")
            fstab.write_text("LABEL=root / ext4 defaults 0 1\n", encoding="utf-8")
            tune = subprocess.CompletedProcess(["tune2fs"], 0, "Filesystem state:         clean\n", "")
            with patch.object(server_agent, "run", return_value=tune):
                result = server_agent.root_filesystem_snapshot(mounts, fstab, root / "missing-sysfs")

        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("error counter is unavailable", result["reason"])

    def test_health_requires_two_failed_cycles_before_recovery(self) -> None:
        failed = {"verdicts": {"server_path": "failed"}, "services": {}, "role": "ru-gateway"}
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "health.json"
            lock = Path(tmp) / "lock"
            with patch.object(server_agent, "HEALTH_STATE_PATH", state), patch.object(server_agent, "LOCK_PATH", lock), patch.object(server_agent, "snapshot", return_value=failed) as snapshot_mock, patch.object(server_agent, "recover", return_value="restart:sing-box.service:ok") as recover, patch.object(server_agent.time, "sleep"):
                first = server_agent.health()
                second = server_agent.health()
        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["last_action"], "restart:sing-box.service:ok")
        recover.assert_called_once()
        self.assertFalse(snapshot_mock.call_args_list[0].kwargs["full_logs"])
        self.assertFalse(snapshot_mock.call_args_list[0].kwargs["include_maintenance"])

    def test_health_never_restarts_services_for_filesystem_corruption(self) -> None:
        failed = {
            "generated_at": "2026-08-01T20:00:00+00:00",
            "verdicts": {
                "server_path": "verified",
                "host_integrity": "failed",
                "client_observation": "not-applicable",
            },
            "services": {},
            "role": "foreign-exit",
            "probes": {"requirements": {"foreign_direct": True}},
            "network": {"interfaces": {}, "protocol_counters": {}, "softnet_counters": {}, "conntrack": {}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_agent, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_agent, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "snapshot", return_value=failed),
                patch.object(server_agent, "recover") as recover,
            ):
                first = server_agent.health()
                second = server_agent.health()

        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["state"], "failed")
        self.assertEqual(second["hard_reasons"], ["host_integrity"])
        self.assertEqual(second["last_action"], "none")
        recover.assert_not_called()

    def test_health_reports_udp_buffer_drops_as_degraded_without_recovery(self) -> None:
        def healthy(udp_drops: int) -> dict[str, object]:
            return {
                "verdicts": {"server_path": "verified"},
                "services": {},
                "role": "foreign-exit",
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
                patch.object(server_agent, "HEALTH_STATE_PATH", state),
                patch.object(server_agent, "LOCK_PATH", lock),
                patch.object(server_agent, "snapshot", side_effect=[healthy(10), healthy(13)]),
                patch.object(server_agent, "recover") as recover,
            ):
                first = server_agent.health()
                second = server_agent.health()

        self.assertEqual(first["state"], "healthy")
        self.assertEqual(second["state"], "degraded")
        self.assertEqual(second["soft_reasons"], ["udp_receive_buffer_drops=3"])
        recover.assert_not_called()

    def test_health_reports_recent_conntrack_exhaustion_without_recovery(self) -> None:
        current = {
            "verdicts": {"server_path": "verified"},
            "services": {},
            "role": "ru-gateway",
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
                patch.object(server_agent, "HEALTH_STATE_PATH", state),
                patch.object(server_agent, "LOCK_PATH", lock),
                patch.object(server_agent, "snapshot", return_value=current),
                patch.object(server_agent, "recover") as recover,
            ):
                result = server_agent.health()

        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["soft_reasons"], ["conntrack_table_full_5m=2"])
        recover.assert_not_called()

    def test_network_soft_reasons_do_not_promote_unscoped_host_tcp_or_generic_rx_drops(self) -> None:
        reasons = server_agent.network_soft_reasons(
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
        reasons = server_agent.network_soft_reasons(
            {
                "interfaces": {"eth0": {"rx_packets": 20_000, "rx_dropped": 200, "rx_missed_errors": 0}},
                "protocol": {},
                "softnet": {"dropped": 0},
            }
        )
        self.assertEqual(reasons, [])

    def test_network_soft_reasons_ignore_low_volume_counter_noise(self) -> None:
        reasons = server_agent.network_soft_reasons(
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

    def test_health_log_summary_omits_persistent_flow_counters(self) -> None:
        payload = {
            "schema_version": 2,
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

        summary = server_agent.health_log_summary(payload)

        self.assertNotIn("front_counters", summary)
        self.assertNotIn("flows", summary["front_interval"])
        self.assertEqual(summary["front_interval"]["aggregate"]["bytes_retrans"], 100)

    def test_health_reports_client_specific_front_loss_without_recovery(self) -> None:
        current = {
            "generated_at": "2026-07-20T08:00:00+00:00",
            "verdicts": {"server_path": "verified", "client_observation": "client_specific"},
            "services": {},
            "role": "ru-gateway",
            "probes": {"requirements": {"ru_direct": True, "via_wg": True, "router": True}},
            "network": {"interfaces": {}, "protocol_counters": {}, "softnet_counters": {}, "conntrack": {}},
            "front": {
                "connections": 1,
                "bytes_sent": 12_251,
                "bytes_retrans": 2_829,
                "retransmit_ratio_pct": 23.092,
                "degraded_sources": ["203.0.113.20"],
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
                patch.object(server_agent, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_agent, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "snapshot", return_value=current),
                patch.object(server_agent, "recover") as recover,
            ):
                result = server_agent.health()

        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["soft_reasons"], ["public_front=client_specific"])
        self.assertEqual(result["last_front_degradation"]["observed_at"], current["generated_at"])
        self.assertEqual(result["last_front_degradation"]["degraded_sources"], ["203.0.113.20"])
        recover.assert_not_called()

    def test_front_degradation_evidence_is_bounded(self) -> None:
        flows = {
            f"203.0.113.20:{port}": {"quality": "degraded", "bytes_retrans": port}
            for port in range(100, 125)
        }
        evidence = server_agent.front_degradation_evidence(
            {
                "flows": flows,
                "degraded_sources": ["203.0.113.20"],
                "connections": len(flows),
                "bytes_sent": 1_000_000,
                "bytes_retrans": 20_000,
                "retransmit_ratio_pct": 2.0,
            },
            "2026-07-20T08:00:00+00:00",
        )
        self.assertEqual(len(evidence["flows"]), 20)
        self.assertIn("203.0.113.20:124", evidence["flows"])
        self.assertNotIn("203.0.113.20:100", evidence["flows"])

    def test_recovery_never_routes_foreign_traffic_through_ru(self) -> None:
        current = {
            "role": "ru-gateway",
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "probes": {"requirements": {"ru_direct": True, "via_wg": False, "router": False}},
        }
        with patch.object(server_agent, "run") as run_mock:
            action = server_agent.recover(current)
        self.assertEqual(action, "none")
        run_mock.assert_not_called()

    def test_recovery_restarts_router_when_acceptance_wg_fallback_is_healthy(self) -> None:
        current = {
            "role": "ru-gateway",
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
        with patch.object(server_agent, "run", return_value=completed) as run_mock:
            action = server_agent.recover(current)

        self.assertEqual(action, "restart:sing-box.service:ok")
        run_mock.assert_called_once_with(["systemctl", "restart", "sing-box.service"], timeout=30)

    def test_recovery_reapplies_clean_managed_network_profile(self) -> None:
        current = {
            "role": "ru-gateway",
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "none"},
            "network": {"profile_mismatches": ["conntrack_max"]},
        }
        with patch.object(server_agent, "run", return_value=subprocess.CompletedProcess(["sysctl"], 0, "", "")) as run_mock:
            action = server_agent.recover(current)
        self.assertEqual(action, "reload:sysctl:ok")
        run_mock.assert_called_once_with(["sysctl", "--load", str(server_agent.SYSCTL_PATH)], timeout=30)

    def test_recovery_reloads_clean_nftables_when_bypass_is_missing(self) -> None:
        current = {
            "role": "ru-gateway",
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "none"},
            "network": {"profile_mismatches": [], "conntrack": {"front_bypass": {"active": False}}},
        }
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with patch.object(server_agent, "run", side_effect=[completed, completed]) as run_mock:
            action = server_agent.recover(current)
        self.assertEqual(action, "reload:nftables:ok")
        self.assertEqual(run_mock.call_args_list[0].args[0], ["nft", "--check", "--file", "/etc/nftables.conf"])
        self.assertEqual(run_mock.call_args_list[1].args[0], ["nft", "--file", "/etc/nftables.conf"])

    def test_recovery_never_applies_mutated_managed_artifacts(self) -> None:
        current = {
            "role": "ru-gateway",
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "server-mutated"},
            "network": {"profile_mismatches": ["conntrack_max"], "conntrack": {"front_bypass": {"active": False}}},
            "probes": {"requirements": {}},
        }
        with patch.object(server_agent, "run") as run_mock:
            action = server_agent.recover(current)
        self.assertEqual(action, "none")
        run_mock.assert_not_called()

    def test_positive_counter_deltas_ignore_first_sample_and_counter_reset(self) -> None:
        self.assertEqual(server_agent.positive_counter_deltas({"UdpRcvbufErrors": 10}, {}), {})
        self.assertEqual(server_agent.positive_counter_deltas({"UdpRcvbufErrors": 10}, {"UdpRcvbufErrors": 7}), {"UdpRcvbufErrors": 3})
        self.assertEqual(server_agent.positive_counter_deltas({"UdpRcvbufErrors": 1}, {"UdpRcvbufErrors": 7}), {})

    def test_protocol_snapshot_collects_tcp_out_and_retrans_segments(self) -> None:
        completed = subprocess.CompletedProcess(
            ["nstat"],
            0,
            "TcpOutSegs 10000 0.0\nTcpRetransSegs 125 0.0\nTcpExtTCPSACKReorder 20 0.0\nTcpExtTCPDSACKRecv 7 0.0\nUdpRcvbufErrors 3 0.0\n",
            "",
        )
        with patch.object(server_agent, "run", return_value=completed):
            counters = server_agent.protocol_counters_snapshot()
        self.assertEqual(counters["TcpOutSegs"], 10_000)
        self.assertEqual(counters["TcpRetransSegs"], 125)
        self.assertEqual(counters["TcpExtTCPSACKReorder"], 20)
        self.assertEqual(counters["TcpExtTCPDSACKRecv"], 7)

    def test_snapshot_includes_bootstrap_identity_for_lifecycle_preflight(self) -> None:
        manifest = {"role": "ru-gateway", "version": "0.11.0", "release_id": "release-1", "policy_version": "0.11.0", "schema_version": 2}
        with (
            patch.object(server_agent, "parse_env", return_value={"DEPLOY_NAME": "demo", "WAN_INTERFACE": "eth0", "WG_INTERFACE": "wg0", "RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "manifest_snapshot", return_value={"manifest": manifest, "drift": "none", "files": {}}),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "fresh_log_since", return_value=("5 minutes ago", 5)),
            patch.object(server_agent, "maintenance_snapshot", return_value={"upgradable": 0}),
            patch.object(server_agent, "journal_lines", return_value=[]),
            patch.object(server_agent, "journal_lines_since", return_value=[]),
            patch.object(server_agent, "tcp_front_snapshot", return_value={"listening": True, "state_counts": {}, "socket_retransmissions": 0}),
            patch.object(server_agent, "public_hy2_snapshot", return_value={"configured": True, "listening": True, "firewall": True}),
            patch.object(server_agent, "wireguard_snapshot", return_value={"peers": []}),
            patch.object(server_agent, "default_interface", return_value="ens3"),
            patch.object(server_agent, "interface_counters", return_value={"ens3": {}}),
            patch.object(server_agent, "tcp_adaptation_snapshot", return_value={"congestion_control": "bbr", "qdisc": "fq", "mtu_probing": 1}),
            patch.object(server_agent, "conntrack_snapshot", return_value={}),
            patch.object(server_agent, "xray_conntrack_bypass_snapshot", return_value={"active": True, "ingress": True, "egress": True}),
            patch.object(server_agent, "host_snapshot", return_value={"hostname": "ru-host", "login_user": "root", "is_root": True, "has_sudo": True, "os_id": "ubuntu", "os_version": "24.04", "default_interface": "ens3"}) as host_snapshot,
            patch.object(server_agent, "installed_at_value", return_value="2026-07-15T00:00:00Z"),
        ):
            snapshot = server_agent.snapshot()
        self.assertEqual(snapshot["host"]["login_user"], "root")
        self.assertTrue(snapshot["host"]["is_root"])
        host_snapshot.assert_called_once_with("ens3")
        self.assertEqual(snapshot["release"]["installed_at"], "2026-07-15T00:00:00Z")
        self.assertEqual(snapshot["network"]["tcp_adaptation"]["mtu_probing"], 1)

    def test_tcp_adaptation_snapshot_reads_runtime_kernel_state(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            values = {
                "net.ipv4.tcp_congestion_control": "bbr\n",
                "net.ipv4.tcp_mtu_probing": "1\n",
                "net.ipv4.tcp_mtu_probe_floor": "536\n",
                "net.ipv4.tcp_probe_interval": "600\n",
                "net.ipv4.tcp_no_metrics_save": "0\n",
                "net.core.rmem_default": "8388608\n",
                "net.core.rmem_max": "16777216\n",
                "net.core.wmem_max": "16777216\n",
            }
            if args[0] == "sysctl":
                return subprocess.CompletedProcess(args, 0, values[args[-1]], "")
            return subprocess.CompletedProcess(args, 0, "qdisc fq 0: root\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            snapshot = server_agent.tcp_adaptation_snapshot("ens3")
        self.assertEqual(
            snapshot,
            {
                "congestion_control": "bbr",
                "mtu_probing": 1,
                "mtu_probe_floor": 536,
                "probe_interval_seconds": 600,
                "metrics_save_disabled": 0,
                "udp_rmem_default": 8388608,
                "udp_rmem_max": 16777216,
                "udp_wmem_max": 16777216,
                "qdisc": "fq",
            },
        )

    def test_conntrack_snapshot_reports_capacity_and_fresh_kernel_events(self) -> None:
        def read_text(path: Path, *_args: object, **_kwargs: object) -> str:
            values = {
                "/proc/sys/net/netfilter/nf_conntrack_count": "6144",
                "/proc/sys/net/netfilter/nf_conntrack_max": "6144",
            }
            return values[str(path).replace("\\", "/")]

        with (
            patch.object(Path, "read_text", autospec=True, side_effect=read_text),
            patch.object(server_agent, "kernel_conntrack_full_windows", return_value={"5": 2}) as events,
        ):
            snapshot = server_agent.conntrack_snapshot(full_logs=False)

        self.assertEqual(snapshot, {"count": 6144, "max": 6144, "percent": 100.0, "table_full_events": {"5": 2}})
        events.assert_called_once_with(full_logs=False)

    def test_kernel_conntrack_events_are_bucketed_from_one_journal_read(self) -> None:
        journal = "900.0 host kernel: nf_conntrack: table full, dropping packet\n500.0 host kernel: nf_conntrack: table full, dropping packet\n"
        completed = subprocess.CompletedProcess(["journalctl"], 0, journal, "")
        with patch.object(server_agent, "run", return_value=completed) as run_mock, patch.object(server_agent.time, "time", return_value=1_000.0):
            windows = server_agent.kernel_conntrack_full_windows(full_logs=True)

        self.assertEqual(windows, {"5": 1, "30": 2, "1440": 2})
        run_mock.assert_called_once()

    def test_xray_conntrack_bypass_requires_both_runtime_rules(self) -> None:
        rules = (
            'tcp dport 443 counter packets 1 bytes 60 notrack comment "vpnstack-xray-in-notrack"\n'
            'tcp sport 443 counter packets 1 bytes 60 notrack comment "vpnstack-xray-out-notrack"\n'
        )
        with patch.object(server_agent, "run", return_value=subprocess.CompletedProcess(["nft"], 0, rules, "")):
            active = server_agent.xray_conntrack_bypass_snapshot(443)
        with patch.object(server_agent, "run", return_value=subprocess.CompletedProcess(["nft"], 0, rules.splitlines()[0], "")):
            incomplete = server_agent.xray_conntrack_bypass_snapshot(443)

        self.assertEqual(active, {"active": True, "ingress": True, "egress": True})
        self.assertEqual(incomplete, {"active": False, "ingress": True, "egress": False})

    def test_managed_network_profile_detects_runtime_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sysctl.conf"
            path.write_text(
                "net.core.rmem_max=16777216\n"
                "net.core.rmem_default=8388608\n"
                "net.core.wmem_max=16777216\n"
                "net.ipv4.tcp_mtu_probe_floor=536\n"
                "net.ipv4.tcp_no_metrics_save=0\n",
                encoding="utf-8",
            )
            expected = server_agent.managed_network_profile(path)
        self.assertEqual(
            expected,
            {
                "udp_rmem_default": 8_388_608,
                "udp_rmem_max": 16_777_216,
                "udp_wmem_max": 16_777_216,
                "mtu_probe_floor": 536,
                "metrics_save_disabled": 0,
            },
        )
        self.assertEqual(
            server_agent.network_profile_mismatches(
                {
                    "udp_rmem_default": 212_992,
                    "udp_rmem_max": 16_777_216,
                    "udp_wmem_max": 16_777_216,
                    "mtu_probe_floor": 536,
                    "metrics_save_disabled": 0,
                },
                expected,
            ),
            ["udp_rmem_default"],
        )

    def test_managed_network_profile_includes_conntrack_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sysctl.conf"
            path.write_text("net.netfilter.nf_conntrack_max=32768\n", encoding="utf-8")
            expected = server_agent.managed_network_profile(path)
        self.assertEqual(expected, {"conntrack_max": 32768})
        self.assertEqual(server_agent.network_profile_mismatches({"conntrack_max": 6144}, expected), ["conntrack_max"])

    def test_front_snapshot_groups_tcp_metrics_by_client_source(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123 sk:2D43A0\n\t cubic rtt:45.2/3.1 mss:1428 pmtu:1500 cwnd:12 bytes_sent:2000000 bytes_retrans:80000 data_segs_out:1400 delivery_rate 12000000bps retrans:0/3 reord_seen:7 dsack_dups:4 reordering:300 rcv_ooopack:5 unacked:2 lastsnd:100 lastrcv:200\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertTrue(front["listening"])
        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        client = front["clients"]["203.0.113.20"]
        self.assertEqual(client["retransmissions"], 3)
        self.assertEqual(client["bytes_retrans"], 80000)
        self.assertEqual(client["retransmit_ratio_pct"], 4.0)
        self.assertEqual(client["quality"], "loss_observed")
        self.assertEqual(client["pmtu"], 1500)
        self.assertEqual(client["reord_seen"], 7)
        self.assertEqual(client["dsack_dups"], 4)
        self.assertEqual(client["rcv_ooopack"], 5)
        self.assertEqual(client["reordering"], 300)
        self.assertEqual(client["unacked"], 2)
        self.assertEqual(client["rtt_ms"]["p95"], 45.2)
        self.assertEqual(client["rtt_ms"]["samples"], 1)
        flow = front["flows"]["203.0.113.20:50123"]
        self.assertEqual(flow["source_port"], 50123)
        self.assertEqual(flow["socket_id"], "2d43a0")
        self.assertEqual(flow["retransmit_ratio_pct"], 4.0)
        self.assertEqual(front["degraded_sources"], [])
        self.assertEqual(front["loss_observed_sources"], ["203.0.113.20"])

    def test_front_snapshot_does_not_classify_fin_retransmits_as_active_loss(self) -> None:
        sockets = "".join(
            f"FIN-WAIT-1 0 0 192.0.2.10:443 203.0.113.20:{port}\n"
            for port in range(50100, 50125)
        )
        details = "".join(
            f"FIN-WAIT-1 0 0 192.0.2.10:443 203.0.113.20:{port}\n"
            "\t cubic rtt:900/100 rto:76000 bytes_sent:0 bytes_retrans:64000 retrans:0/20\n"
            for port in range(50100, 50125)
        )

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, sockets, "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(args, 0, details, "")
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 192.0.2.10:443 0.0.0.0:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["active_connections"], 0)
        self.assertEqual(front["closing_connections"], 25)
        self.assertEqual(front["bytes_retrans"], 0)
        self.assertEqual(front["degraded_sources"], [])
        self.assertEqual(front["closing_churn_sources"], ["203.0.113.20"])
        self.assertEqual(server_agent.front_observation(front), "observed")
        self.assertEqual(server_agent.closing_churn_observation(front), "client_specific")

    def test_front_client_metrics_exclude_closing_socket_counters(self) -> None:
        sockets = (
            "ESTAB 0 0 192.0.2.10:443 203.0.113.20:50000\n"
            + "".join(
                f"FIN-WAIT-1 0 0 192.0.2.10:443 203.0.113.20:{port}\n"
                for port in range(50100, 50125)
            )
        )
        details = (
            "ESTAB 0 0 192.0.2.10:443 203.0.113.20:50000\n"
            "\t cubic rtt:65/5 rto:220 bytes_sent:1000000 bytes_retrans:1000 retrans:0/1\n"
            + "".join(
                f"FIN-WAIT-1 0 0 192.0.2.10:443 203.0.113.20:{port}\n"
                "\t cubic rtt:900/100 rto:76000 bytes_sent:0 bytes_retrans:64000 retrans:0/20\n"
                for port in range(50100, 50125)
            )
        )

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, sockets, "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(args, 0, details, "")
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 192.0.2.10:443 0.0.0.0:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        client = front["clients"]["203.0.113.20"]
        self.assertEqual(client["phase"], "active")
        self.assertEqual(client["states"], {"ESTAB": 1})
        self.assertEqual(client["bytes_retrans"], 1000)
        self.assertEqual(front["closing_churn_sources"], ["203.0.113.20"])

    def test_front_interval_uses_monotonic_counters_from_the_same_socket(self) -> None:
        first = {
            "flows": {
                "203.0.113.20:50123": {
                    "socket_id": "2d43a0",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 100_000,
                    "bytes_retrans": 1_000,
                    "retransmissions": 1,
                    "data_segs_out": 80,
                }
            }
        }
        second = {
            "flows": {
                "203.0.113.20:50123": {
                    "socket_id": "2d43a0",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 2_100_000,
                    "bytes_retrans": 81_000,
                    "retransmissions": 7,
                    "data_segs_out": 1_480,
                }
            }
        }

        baseline, counters = server_agent.front_interval_snapshot(first, {}, "2026-07-30T20:00:00+00:00")
        interval, _counters = server_agent.front_interval_snapshot(second, counters, "2026-07-30T20:02:00+00:00")

        self.assertTrue(baseline["baseline"])
        self.assertEqual(baseline["sampled_flows"], 0)
        self.assertEqual(interval["degraded_sources"], ["203.0.113.20"])
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["bytes_retrans"], 80_000)
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["quality"], "degraded")

    def test_front_interval_aggregates_loss_across_one_clients_flows(self) -> None:
        first = {
            "flows": {
                f"203.0.113.20:{port}": {
                    "socket_id": f"socket-{port}",
                    "source": "203.0.113.20",
                    "source_port": port,
                    "bytes_sent": 100_000,
                    "bytes_retrans": 1_000,
                    "retransmissions": 1,
                    "data_segs_out": 80,
                }
                for port in (50123, 50124)
            }
        }
        second = {
            "flows": {
                f"203.0.113.20:{port}": {
                    "socket_id": f"socket-{port}",
                    "source": "203.0.113.20",
                    "source_port": port,
                    "bytes_sent": 700_000,
                    "bytes_retrans": 13_000,
                    "retransmissions": 3,
                    "data_segs_out": 500,
                }
                for port in (50123, 50124)
            }
        }

        _baseline, counters = server_agent.front_interval_snapshot(first, {}, "2026-08-01T20:00:00+00:00")
        interval, _counters = server_agent.front_interval_snapshot(second, counters, "2026-08-01T20:02:00+00:00")

        self.assertEqual({flow["quality"] for flow in interval["flows"].values()}, {"observed"})
        self.assertEqual(interval["sources"]["203.0.113.20"]["activity_bytes"], 1_200_000)
        self.assertEqual(interval["sources"]["203.0.113.20"]["retransmit_ratio_pct"], 2.0)
        self.assertEqual(interval["sources"]["203.0.113.20"]["quality"], "degraded")
        self.assertEqual(interval["degraded_sources"], ["203.0.113.20"])
        self.assertEqual(interval["observation"], "client_specific")

    def test_front_interval_detects_fresh_loss_before_lifetime_threshold(self) -> None:
        metrics = server_agent.front_interval_metrics(
            {
                "bytes_sent": 300_000,
                "bytes_retrans": 3_600,
                "retransmissions": 3,
                "data_segs_out": 200,
            }
        )

        self.assertEqual(metrics["retransmit_ratio_pct"], 1.2)
        self.assertEqual(metrics["quality"], "degraded")

    def test_front_interval_marks_tiny_samples_insufficient(self) -> None:
        metrics = server_agent.front_interval_metrics(
            {
                "bytes_sent": 183,
                "bytes_retrans": 122,
                "retransmissions": 2,
                "data_segs_out": 3,
            }
        )

        self.assertEqual(metrics["retransmit_ratio_pct"], 66.667)
        self.assertEqual(metrics["quality"], "insufficient")

    def test_front_interval_does_not_join_replaced_or_reset_sockets(self) -> None:
        previous = {
            "observed_at": "2026-07-30T20:00:00+00:00",
            "flows": {
                "old": {
                    "endpoint": "203.0.113.20:50123",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 2_000_000,
                    "bytes_retrans": 80_000,
                    "retransmissions": 8,
                    "data_segs_out": 1_400,
                },
                "reset": {
                    "endpoint": "203.0.113.21:50124",
                    "source": "203.0.113.21",
                    "source_port": 50124,
                    "bytes_sent": 2_000_000,
                    "bytes_retrans": 80_000,
                    "retransmissions": 8,
                    "data_segs_out": 1_400,
                },
                "reused": {
                    "endpoint": "203.0.113.22:50125",
                    "source": "203.0.113.22",
                    "source_port": 50125,
                    "bytes_sent": 1_000,
                    "bytes_retrans": 0,
                    "retransmissions": 0,
                    "data_segs_out": 10,
                },
            },
        }
        current = {
            "flows": {
                "203.0.113.20:50123": {
                    "socket_id": "new",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 100_000,
                    "bytes_retrans": 20_000,
                    "retransmissions": 4,
                    "data_segs_out": 70,
                },
                "203.0.113.21:50124": {
                    "socket_id": "reset",
                    "source": "203.0.113.21",
                    "source_port": 50124,
                    "bytes_sent": 100,
                    "bytes_retrans": 0,
                    "retransmissions": 0,
                    "data_segs_out": 1,
                },
                "203.0.113.23:50126": {
                    "socket_id": "reused",
                    "source": "203.0.113.23",
                    "source_port": 50126,
                    "bytes_sent": 2_000_000,
                    "bytes_retrans": 100_000,
                    "retransmissions": 10,
                    "data_segs_out": 1_400,
                },
            }
        }

        interval, _counters = server_agent.front_interval_snapshot(
            current,
            previous,
            "2026-07-30T20:02:00+00:00",
        )

        self.assertEqual(interval["sampled_flows"], 0)
        self.assertEqual(interval["degraded_sources"], [])

    def test_front_interval_resets_a_stale_baseline(self) -> None:
        current = {
            "flows": {
                "203.0.113.20:50123": {
                    "socket_id": "2d43a0",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 2_000_000,
                    "bytes_retrans": 100_000,
                    "retransmissions": 10,
                    "data_segs_out": 1_400,
                }
            }
        }
        previous = {
            "observed_at": "2026-07-30T20:00:00+00:00",
            "flows": {
                "2d43a0": {
                    "endpoint": "203.0.113.20:50123",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 1_000,
                    "bytes_retrans": 0,
                    "retransmissions": 0,
                    "data_segs_out": 10,
                }
            },
        }

        interval, _counters = server_agent.front_interval_snapshot(
            current,
            previous,
            "2026-07-30T20:10:00+00:00",
        )

        self.assertTrue(interval["baseline"])
        self.assertEqual(interval["baseline_reason"], "stale")
        self.assertEqual(interval["sampled_flows"], 0)
        self.assertEqual(interval["degraded_sources"], [])

    def test_front_snapshot_normalizes_ipv4_mapped_socket_source(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 [::ffff:94.232.248.35]:443 [::ffff:203.0.113.20]:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 [::ffff:94.232.248.35]:443 [::ffff:203.0.113.20]:50123\n\t cubic rtt:45.2/3.1 retrans:0/3 unacked:2\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 [::]:443 [::]:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        self.assertEqual(front["clients"]["203.0.113.20"]["retransmissions"], 3)
        self.assertIn("203.0.113.20:50123", front["flows"])

    def test_front_snapshot_keeps_flows_separate_behind_one_nat(self) -> None:
        sockets = (
            "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n"
            "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50124\n"
        )
        details = (
            "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n\t cubic rtt:30/2 bytes_sent:2000000 bytes_retrans:0 retrans:0/0\n"
            "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50124\n\t cubic rtt:400/20 rto:1200 bytes_sent:2000000 bytes_retrans:100000 retrans:0/8\n"
        )

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, sockets, "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(args, 0, details, "")
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["clients"]["203.0.113.20"]["connections"], 2)
        self.assertEqual(front["flows"]["203.0.113.20:50123"]["quality"], "observed")
        self.assertEqual(front["flows"]["203.0.113.20:50124"]["quality"], "degraded")
        self.assertEqual(front["degraded_sources"], ["203.0.113.20"])

    def test_front_snapshot_reports_keepalive_and_stale_socket_lifecycle(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123 timer:(keepalive,12sec,0)\n"
                    "\t cubic rtt:45/3 lastsnd:3600001 lastrcv:3600001\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["keepalive_timer_connections"], 1)
        self.assertEqual(front["stale_connections_5m"], 1)
        self.assertEqual(front["stale_connections_1h"], 1)
        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        self.assertIn("203.0.113.20", front["clients"])
        self.assertIn("203.0.113.20:50123", front["flows"])
        self.assertNotIn("timer", front["clients"])
        self.assertEqual(server_agent.front_observation(front), "observed")

    def test_front_snapshot_ignores_optional_ss_fields_before_endpoints(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 timer:(keepalive,12sec,0) 94.232.248.35:443 203.0.113.20:50123\n"
                    "\t cubic rtt:45/3\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        self.assertEqual(front["keepalive_timer_connections"], 1)
        self.assertIn("203.0.113.20:50123", front["flows"])

    def test_client_snapshot_matches_ipv4_mapped_xray_source(self) -> None:
        front = {"listening": True, "clients": {"203.0.113.20": {"connections": 1}}, "top_sources": {"203.0.113.20": 1}}
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with (
            patch.object(server_agent, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "journal_filtered_lines", return_value=["from [::ffff:203.0.113.20]:50123 accepted tcp:example.org:443"]),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "run", return_value=completed),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["events"]["accepted"], 1)
        self.assertEqual(payload["front"]["client"], {"connections": 1})

    def test_front_observation_separates_closing_churn_from_active_loss(self) -> None:
        isolated = {"closing_churn_sources": ["203.0.113.20"]}
        shared = {"closing_churn_sources": [f"203.0.113.{index}" for index in range(1, 4)]}
        self.assertEqual(server_agent.front_observation(isolated), "observed")
        self.assertEqual(server_agent.front_observation(shared), "observed")
        self.assertEqual(server_agent.closing_churn_observation(isolated), "client_specific")
        self.assertEqual(server_agent.closing_churn_observation(shared), "shared")

    def test_front_observation_does_not_treat_lifetime_retransmissions_as_fresh_failure(self) -> None:
        front = {"clients": {"203.0.113.20": {"states": {"ESTAB": 1}, "retransmissions": 200}}}
        self.assertEqual(server_agent.front_observation(front), "observed")

    def test_front_observation_does_not_promote_client_lifetime_loss(self) -> None:
        front = {"clients": {"203.0.113.20": {"states": {"ESTAB": 1}, "bytes_sent": 5_000_000, "retransmit_ratio_pct": 4.5, "quality": "degraded"}}}
        self.assertEqual(server_agent.front_observation(front), "observed")

    def test_public_front_verdict_uses_socket_quality_not_only_listener_state(self) -> None:
        degraded = {
            "listening": True,
            "degraded_sources": ["203.0.113.20"],
            "fin_wait_1_sources": [],
        }
        self.assertEqual(server_agent.public_front_verdict("active", degraded), "degraded")
        self.assertEqual(server_agent.public_front_verdict("inactive", degraded), "failed")

    def test_public_front_verdict_uses_fresh_interval_loss(self) -> None:
        front = {"listening": True, "degraded_sources": [], "fin_wait_1_sources": []}
        interval = {"degraded_sources": ["203.0.113.20"], "observation": "client_specific"}
        self.assertEqual(server_agent.public_front_verdict("active", front, interval), "degraded")

    def test_xray_front_socket_policy_reads_inbound_liveness_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "xray.json"
            config.write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "port": 443,
                                "streamSettings": {
                                    "sockopt": {
                                        "tcpKeepAliveIdle": 90,
                                        "tcpKeepAliveInterval": 15,
                                    }
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_agent, "XRAY_CONFIG_PATH", config):
                policy = server_agent.xray_front_socket_policy(443)

        self.assertEqual(
            policy,
            {
                "tcp_keepalive_idle_seconds": 90,
                "tcp_keepalive_interval_seconds": 15,
            },
        )

    def test_public_hysteria_snapshot_requires_config_listener_and_firewall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "sing-box.json"
            config.write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "type": "hysteria2",
                                "tag": "public-hy2-in",
                                "listen_port": 443,
                                "users": [{"password": "secret"}],
                                "tls": {"enabled": True},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                if args[0] == "ss":
                    return subprocess.CompletedProcess(args, 0, "UNCONN 0 0 0.0:443 0.0.0.0:*\n", "")
                return subprocess.CompletedProcess(
                    args,
                    0,
                    'udp dport 443 notrack comment "vpnstack-hy2-in-notrack"\n'
                    'udp sport 443 notrack comment "vpnstack-hy2-out-notrack"\n'
                    "udp dport 443 counter accept\n",
                    "",
                )

            with patch.object(server_agent, "SINGBOX_CONFIG_PATH", config), patch.object(server_agent, "run", side_effect=fake_run):
                result = server_agent.public_hy2_snapshot(443)

        self.assertEqual(result, {"port": 443, "protocol": "hysteria2", "configured": True, "listening": True, "firewall": True})

    def test_front_live_diagnostics_fail_when_downstream_path_fails(self) -> None:
        with (
            patch.object(server_agent, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "journal_filtered_lines", return_value=[]),
            patch.object(server_agent, "tcp_front_snapshot", return_value={"listening": True, "clients": {}, "flows": {}}),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "udp_443_policy", return_value="routed"),
            patch.object(server_agent, "public_hy2_snapshot", return_value={"configured": True, "listening": True, "firewall": True}),
            patch.object(
                server_agent,
                "run_probes",
                return_value={"profile": "light", "ok": False, "requirements": {"ru_direct": True, "via_wg": False, "router": False}},
            ),
        ):
            payload = server_agent.public_front_snapshot(30, live_probes=True)

        self.assertEqual(payload["verdicts"]["public_front"], "verified")
        self.assertEqual(payload["verdicts"]["server_path"], "failed")
        self.assertEqual(payload["verdict"], "failed")

    def test_client_quality_detects_rto_backed_rtt_inflation(self) -> None:
        metrics = {
            "bytes_sent": 200_000,
            "retransmit_ratio_pct": 0.5,
            "rtt_ms": {"samples": 4, "min": 24.0, "median": 70.0, "p95": 385.0},
            "rto_ms": {"max": 1_183},
        }
        self.assertEqual(server_agent.client_front_quality(metrics), "degraded")

    def test_client_quality_keeps_lifetime_loss_separate_from_current_stall(self) -> None:
        metrics = {
            "bytes_sent": 12_251,
            "bytes_retrans": 2_829,
            "retransmissions": 3,
            "retransmit_ratio_pct": 23.092,
            "rtt_ms": {"samples": 1, "min": 70.0, "p95": 70.0},
            "rto_ms": {"max": 391},
        }
        self.assertEqual(server_agent.client_front_quality(metrics), "loss_observed")

    def test_client_quality_detects_one_stalled_flow_without_mixing_connections(self) -> None:
        metrics = {
            "bytes_sent": 96_410,
            "bytes_retrans": 5_237,
            "retransmissions": 16,
            "retransmit_ratio_pct": 5.465,
            "rtt_ms": {"samples": 1, "min": 1_232.49, "p95": 1_232.49},
            "rto_ms": {"max": 3_429},
        }
        self.assertEqual(server_agent.client_front_quality(metrics), "degraded")

    def test_client_quality_keeps_stable_high_rtt_as_observation(self) -> None:
        metrics = {
            "bytes_sent": 5_000_000,
            "retransmit_ratio_pct": 0.5,
            "rtt_ms": {"samples": 4, "min": 280.0, "median": 310.0, "p95": 350.0},
            "rto_ms": {"max": 1_200},
        }
        self.assertEqual(server_agent.client_front_quality(metrics), "observed")

    def test_client_snapshot_reports_lifetime_loss_separately_from_current_degradation(self) -> None:
        front = {"listening": True, "clients": {"203.0.113.20": {"connections": 1, "quality": "loss_observed"}}, "top_sources": {"203.0.113.20": 1}}
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with (
            patch.object(server_agent, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "journal_filtered_lines", return_value=["from 203.0.113.20:50123 accepted tcp:example.org:443"]),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "run", return_value=completed),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)
        self.assertEqual(payload["verdict"], "loss_observed")

    def test_client_snapshot_uses_degraded_active_flow_and_omits_stale_ports(self) -> None:
        front = {
            "listening": True,
            "clients": {"203.0.113.20": {"connections": 1, "quality": "observed"}},
            "flows": {
                "203.0.113.20:50123": {
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "quality": "degraded",
                }
            },
            "top_sources": {"203.0.113.20": 1},
        }
        lines = [
            "from 203.0.113.20:50123 accepted tcp:current.example:443",
            "from 203.0.113.20:59999 accepted tcp:stale.example:443",
        ]
        with (
            patch.object(server_agent, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "journal_filtered_lines", return_value=lines),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "udp_443_policy", return_value="routed"),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["verdict"], "degraded")
        self.assertEqual(payload["flow_events"], {"203.0.113.20:50123": {"current.example:443": 1}})

    def test_udp_443_policy_rejects_only_global_transport_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"
            config_path.write_text(json.dumps({"route": {"rules": [{"network": ["udp"], "port": [443], "action": "reject"}]}}), encoding="utf-8")
            with patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path):
                self.assertEqual(server_agent.udp_443_policy(), "rejected")
            config_path.write_text(json.dumps({"route": {"rules": [{"network": "udp", "port": 443, "domain": ["private.example"], "action": "reject"}]}}), encoding="utf-8")
            with patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path):
                self.assertEqual(server_agent.udp_443_policy(), "routed")
            config_path.write_text(json.dumps({"route": {"rules": [{"action": "resolve", "server": "dns-global", "strategy": "ipv4_only"}]}}), encoding="utf-8")
            with patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path):
                self.assertEqual(server_agent.udp_443_policy(), "routed")

    def test_interserver_transport_snapshot_reports_ru_hysteria_fallback_session(self) -> None:
        config = {
            "outbounds": [
                {"type": "direct", "tag": "to-foreign-wg"},
                {"type": "hysteria2", "tag": "to-foreign-hy2", "server": "132.243.21.108", "server_port": 18443, "obfs": {"type": "salamander", "password": "secret"}, "tls": {"certificate_public_key_sha256": ["pin"]}},
                {"type": "selector", "tag": "to-foreign", "outbounds": ["to-foreign-wg", "to-foreign-hy2"], "default": "to-foreign-wg", "interrupt_exist_connections": False},
            ]
        }
        sockets = subprocess.CompletedProcess(
            ["ss"],
            0,
            "ESTAB 0 0 94.232.248.35:45678 132.243.21.108:18443\n",
            "",
        )
        selection = {"available": True, "selected": "to-foreign-wg", "candidates": {"to-foreign-wg": {"delay_ms": 42}}}
        with (
            patch.object(server_agent, "read_json", return_value=config),
            patch.object(server_agent, "run", return_value=sockets),
            patch.object(server_agent, "selector_selection_snapshot", return_value=selection),
        ):
            transport = server_agent.interserver_transport_snapshot("ru-gateway", {})

        self.assertTrue(transport["configured"])
        self.assertTrue(transport["hysteria_session_active"])
        self.assertEqual(transport["selection"]["selected"], "to-foreign-wg")

    def test_selector_selection_snapshot_reads_selected_transport_and_delays(self) -> None:
        payload = {
            "proxies": {
                "to-foreign": {"now": "to-foreign-hy2", "all": ["to-foreign-hy2", "to-foreign-wg"]},
                "to-foreign-hy2": {"history": [{"delay": 42, "time": "2026-07-22T12:00:00Z"}]},
                "to-foreign-wg": {"history": [{"delay": 310, "time": "2026-07-22T12:00:00Z"}]},
            }
        }

        config = {"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}}
        with patch.object(server_agent, "clash_api_json", return_value=payload):
            selection = server_agent.selector_selection_snapshot(config)

        self.assertTrue(selection["available"])
        self.assertEqual(selection["selected"], "to-foreign-hy2")
        self.assertEqual(selection["candidates"]["to-foreign-wg"]["delay_ms"], 310)
        self.assertFalse(selection["candidates"]["to-foreign-wg"]["fresh"])

    def test_transport_probe_leaves_fallback_dormant_while_primary_is_healthy(self) -> None:
        with (
            patch.object(
                server_agent,
                "transport_candidate_probe",
                return_value={"checked": True, "ok": True, "attempts": 1, "delay_ms": 55, "error": ""},
            ) as primary_probe,
            patch.object(server_agent, "probe_transport_candidates") as parallel_probe,
        ):
            probes = server_agent.collect_transport_probes("127.0.0.1:19090", "to-foreign-wg")

        primary_probe.assert_called_once_with("127.0.0.1:19090", "to-foreign-wg")
        parallel_probe.assert_not_called()
        self.assertTrue(probes["to-foreign-wg"]["ok"])
        self.assertFalse(probes["to-foreign-hy2"]["checked"])

    def test_transport_probe_confirms_primary_failure_before_checking_fallback(self) -> None:
        first = {"checked": True, "ok": False, "attempts": 1, "delay_ms": 0, "error": "timeout"}
        confirmation = {
            "to-foreign-wg": dict(first),
            "to-foreign-hy2": {"checked": True, "ok": True, "attempts": 1, "delay_ms": 70, "error": ""},
        }
        with (
            patch.object(server_agent, "transport_candidate_probe", return_value=first),
            patch.object(server_agent, "probe_transport_candidates", return_value=confirmation) as parallel_probe,
        ):
            probes = server_agent.collect_transport_probes("127.0.0.1:19090", "to-foreign-wg")

        parallel_probe.assert_called_once_with(
            "127.0.0.1:19090",
            ("to-foreign-wg", "to-foreign-hy2"),
        )
        self.assertEqual(probes["to-foreign-wg"]["attempts"], 2)
        self.assertFalse(probes["to-foreign-wg"]["ok"])
        self.assertTrue(probes["to-foreign-hy2"]["ok"])

    def test_transport_state_snapshot_marks_old_state_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "transport-state.json"
            state_path.write_text(
                json.dumps({"updated_at": "2000-01-01T00:00:00+00:00", "state": "healthy"}),
                encoding="utf-8",
            )

            state = server_agent.transport_state_snapshot(state_path)

        self.assertFalse(state["fresh"])
        self.assertGreater(state["age_seconds"], 30)

    def test_transport_reconciler_applies_a_confirmed_failover(self) -> None:
        config = {
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}},
            "outbounds": [
                {"type": "selector", "tag": "to-foreign", "outbounds": ["to-foreign-wg", "to-foreign-hy2"], "default": "to-foreign-wg"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "sing-box.json"
            state_path = root / "transport-state.json"
            lock_path = root / "transport.lock"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(server_agent, "TRANSPORT_STATE_PATH", state_path),
                patch.object(server_agent, "TRANSPORT_LOCK_PATH", lock_path),
                patch.object(server_agent, "selector_selection_snapshot", return_value={"available": True, "selected": "to-foreign-wg"}),
                patch.object(
                    server_agent,
                    "collect_transport_probes",
                    return_value={
                        "to-foreign-wg": {"ok": False, "attempts": 2, "delay_ms": 0, "error": "timeout"},
                        "to-foreign-hy2": {"ok": True, "delay_ms": 70, "error": ""},
                    },
                ),
                patch.object(server_agent, "select_transport") as select_transport,
            ):
                result = server_agent.reconcile_interserver_transport()

        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["selected"], "to-foreign-hy2")
        select_transport.assert_called_once_with("127.0.0.1:19090", "to-foreign-hy2")

    def test_transport_reconciler_discards_one_transient_probe_failure(self) -> None:
        config = {
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}},
            "outbounds": [
                {"type": "selector", "tag": "to-foreign", "outbounds": ["to-foreign-wg", "to-foreign-hy2"], "default": "to-foreign-wg"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "sing-box.json"
            state_path = root / "transport-state.json"
            lock_path = root / "transport.lock"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(server_agent, "TRANSPORT_STATE_PATH", state_path),
                patch.object(server_agent, "TRANSPORT_LOCK_PATH", lock_path),
                patch.object(server_agent, "selector_selection_snapshot", return_value={"available": True, "selected": "to-foreign-wg"}),
                patch.object(
                    server_agent,
                    "collect_transport_probes",
                    return_value={
                        "to-foreign-wg": {"ok": True, "attempts": 2, "delay_ms": 50, "error": ""},
                        "to-foreign-hy2": {"ok": True, "delay_ms": 70, "error": ""},
                    },
                ),
                patch.object(server_agent, "select_transport") as select_transport,
            ):
                result = server_agent.reconcile_interserver_transport()

        self.assertEqual(result["state"], "healthy")
        self.assertTrue(result["probes"]["to-foreign-wg"]["ok"])
        select_transport.assert_not_called()

    def test_transport_reconciler_returns_to_primary_after_two_successes(self) -> None:
        config = {
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}},
            "outbounds": [
                {"type": "selector", "tag": "to-foreign", "outbounds": ["to-foreign-wg", "to-foreign-hy2"], "default": "to-foreign-wg"},
            ],
        }
        healthy = {
            "to-foreign-wg": {"ok": True, "delay_ms": 50, "error": ""},
            "to-foreign-hy2": {"ok": True, "delay_ms": 70, "error": ""},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "sing-box.json"
            state_path = root / "transport-state.json"
            lock_path = root / "transport.lock"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(server_agent, "TRANSPORT_STATE_PATH", state_path),
                patch.object(server_agent, "TRANSPORT_LOCK_PATH", lock_path),
                patch.object(server_agent, "selector_selection_snapshot", return_value={"available": True, "selected": "to-foreign-hy2"}),
                patch.object(server_agent, "collect_transport_probes", return_value=healthy),
                patch.object(server_agent, "select_transport") as select_transport,
            ):
                first = server_agent.reconcile_interserver_transport()
                second = server_agent.reconcile_interserver_transport()

        self.assertEqual(first["state"], "recovering")
        self.assertEqual(second["state"], "healthy")
        self.assertEqual(second["selected"], "to-foreign-wg")
        select_transport.assert_called_once_with("127.0.0.1:19090", "to-foreign-wg")

    def test_interserver_transport_snapshot_reports_foreign_listener(self) -> None:
        config = {
            "inbounds": [
                {
                    "type": "hysteria2",
                    "tag": "interserver-hy2-in",
                    "listen_port": 18443,
                    "obfs": {"type": "salamander", "password": "obfs-secret"},
                    "users": [{"password": "secret"}],
                    "tls": {"certificate": ["cert"], "key": ["key"]},
                }
            ]
        }
        sockets = subprocess.CompletedProcess(["ss"], 0, "UNCONN 0 0 0.0.0.0:18443 0.0.0.0:*\n", "")
        with patch.object(server_agent, "read_json", return_value=config), patch.object(server_agent, "run", return_value=sockets):
            transport = server_agent.interserver_transport_snapshot("foreign-exit", {"RU_PUBLIC_IP": "94.232.248.35"})

        self.assertTrue(transport["configured"])
        self.assertTrue(transport["listening"])
        self.assertEqual(transport["source_restricted_to"], "94.232.248.35")

    def test_standalone_agent_loads_bundled_log_classifier(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "vpn_installer"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            agent = target / "vpn-stack-agent.py"
            shutil.copy2(source_root / "server_agent.py", agent)
            shutil.copy2(source_root / "log_classifier.py", target / "log_classifier.py")
            shutil.copy2(source_root / "interserver_transport.py", target / "interserver_transport.py")
            result = subprocess.run([sys.executable, str(agent), "--help"], text=True, capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vpn-stack-agent", result.stdout)

    def test_client_snapshot_prefers_accepted_xray_event_over_socket_state(self) -> None:
        front = {
            "listening": True,
            "clients": {"203.0.113.20": {"connections": 1}},
            "flows": {"203.0.113.20:50123": {"source": "203.0.113.20", "source_port": 50123, "quality": "observed"}},
            "top_sources": {"203.0.113.20": 1},
        }
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with (
            patch.object(server_agent, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "journal_filtered_lines", return_value=["from 203.0.113.20:50123 accepted tcp:example.org:443"]),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "run", return_value=completed),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["events"]["accepted"], 1)
        self.assertEqual(payload["events"]["accepted_tcp"], 1)
        self.assertEqual(payload["events"]["accepted_udp"], 0)
        self.assertEqual(payload["verdict"], "reached_xray")
        self.assertEqual(payload["flow_events"], {"203.0.113.20:50123": {"example.org:443": 1}})
        self.assertEqual(payload["front"]["flows"]["203.0.113.20:50123"]["accepted_destinations"], {"example.org:443": 1})

    def test_ru_acceptance_requires_router_paths_not_direct_foreign_access(self) -> None:
        def probe(url: str, *, interface: str = "", proxy: str = "", **_kwargs: object) -> dict[str, object]:
            blocked_telegram = url == "https://telegram.org/"
            unavailable_wg_ipv6 = "2606:4700:4700::1111" in url and interface == "wg0"
            return {"target": url, "ok": not (blocked_telegram or unavailable_wg_ipv6)}

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", return_value={"ok": True}),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(server_agent, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0"}, "ru-gateway", "acceptance")

        telegram = next(item for item in result["direct"] if item["target"] == "https://telegram.org/")
        self.assertFalse(telegram["ok"])
        self.assertEqual(result["required_targets"], ["https://github.com/", "https://www.google.com/generate_204"])
        self.assertEqual(result["observations"]["https://telegram.org/"]["direct"], telegram)
        self.assertFalse(result["observations"]["https://telegram.org/"]["via_wg"]["ok"])
        self.assertFalse(result["observations"]["https://telegram.org/"]["router"]["ok"])
        self.assertFalse(result["ipv6_literal"]["via_wg"]["ok"])
        self.assertTrue(result["requirements"]["foreign_domains_via_wg"])
        self.assertTrue(result["requirements"]["ipv6_literal_via_router"])
        self.assertTrue(result["ok"])
        self.assertTrue(result["release_gate_ok"])

    def test_light_health_profile_does_not_duplicate_the_selected_transport_probe(self) -> None:
        calls: list[dict[str, object]] = []

        def probe(url: str, **kwargs: object) -> dict[str, object]:
            calls.append(kwargs)
            return {"target": url, "ok": True}

        with patch.object(server_agent, "probe_url", side_effect=probe):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0"}, "ru-gateway", "light")

        self.assertTrue(result["ok"])
        self.assertEqual(result["via_wg"], [])
        self.assertNotIn("via_wg", result["requirements"])
        self.assertFalse(any(call.get("interface") == "wg0" for call in calls))

    def test_external_ipv6_failure_degrades_acceptance_without_rejecting_release(self) -> None:
        def probe(url: str, **_kwargs: object) -> dict[str, object]:
            return {"target": url, "ok": "2606:4700:4700::1111" not in url}

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", return_value={"ok": True}),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(server_agent, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0"}, "ru-gateway", "acceptance")

        self.assertFalse(result["requirements"]["ipv6_literal_via_router"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["release_gate_ok"])
        self.assertNotIn("ipv6_literal_via_router", result["release_gate_requirements"])
        self.assertTrue(server_agent.release_gate_ok(result))

    def test_wireguard_primary_failure_is_degraded_when_hysteria_router_path_is_healthy(self) -> None:
        def probe(url: str, *, interface: str = "", proxy: str = "", **_kwargs: object) -> dict[str, object]:
            return {"target": url, "ok": not bool(interface)}

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", side_effect=lambda **kwargs: {"ok": not bool(kwargs.get("interface"))}),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(server_agent, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0"}, "ru-gateway", "acceptance")

        self.assertFalse(result["requirements"]["foreign_domains_via_wg"])
        self.assertFalse(result["requirements"]["wireguard_primary_identity"])
        self.assertTrue(result["requirements"]["foreign_domains_via_router"])
        self.assertTrue(result["release_gate_ok"])

    def test_hysteria_fallback_failure_is_reported_without_rejecting_a_healthy_primary(self) -> None:
        with (
            patch.object(server_agent, "probe_url", return_value={"ok": True}),
            patch.object(server_agent, "probe_identity", return_value={"ok": True}),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(server_agent, "transport_candidate_probe", return_value={"ok": False, "error": "timeout"}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0"}, "ru-gateway", "acceptance")

        self.assertFalse(result["requirements"]["hysteria_fallback_reachable"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["release_gate_ok"])
        self.assertEqual(result["capability_failures"]["transport"], ["hysteria_fallback_reachable"])

    def test_release_gate_still_rejects_core_foreign_path_failure(self) -> None:
        probes = {
            "profile": "acceptance",
            "ok": False,
            "release_gate_ok": False,
            "requirements": {"foreign_domains_via_router": False, "ipv6_literal_via_router": False},
        }
        self.assertFalse(server_agent.release_gate_ok(probes))

    def test_route_probe_uses_headers_instead_of_downloading_unbounded_body(self) -> None:
        completed = subprocess.CompletedProcess(["curl"], 0, "200|0.010|0.020|203.0.113.10", "")
        with patch.object(server_agent, "run", return_value=completed) as run_mock:
            result = server_agent.probe_url("https://github.com/")

        self.assertTrue(result["ok"])
        self.assertIn("--head", run_mock.call_args.args[0])
        self.assertIn("-L", run_mock.call_args.args[0])
        self.assertEqual(run_mock.call_args.args[0][run_mock.call_args.args[0].index("--connect-timeout") + 1], "5")

    def test_literal_probe_does_not_follow_a_domain_redirect(self) -> None:
        completed = subprocess.CompletedProcess(["curl"], 0, "302|0.010|0.020|1.1.1.1", "")
        with patch.object(server_agent, "run", return_value=completed) as run_mock:
            result = server_agent.probe_url(
                "https://1.1.1.1/cdn-cgi/trace",
                insecure=True,
                follow_redirects=False,
            )

        self.assertTrue(result["ok"])
        self.assertNotIn("-L", run_mock.call_args.args[0])

    def test_identity_probe_uses_dns_independent_trace_endpoint(self) -> None:
        completed = subprocess.CompletedProcess(["curl"], 0, "fl=1\nip=203.0.113.9\nwarp=off\n", "")
        with patch.object(server_agent, "run", return_value=completed) as run_mock:
            result = server_agent.probe_identity()

        self.assertEqual(result, {"ok": True, "egress_ip": "203.0.113.9", "error": ""})
        self.assertIn("https://1.1.1.1/cdn-cgi/trace", run_mock.call_args.args[0])
        self.assertNotIn("api.ipify.org", run_mock.call_args.args[0])

    def test_resolver_snapshot_reports_managed_cache_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dropin = Path(tmp) / "resolved.conf"
            dropin.write_text(
                "[Resolve]\nDNS=1.1.1.1 9.9.9.9 8.8.8.8\nCache=yes\nStaleRetentionSec=1h\n",
                encoding="utf-8",
            )
            with (
                patch.object(server_agent, "RESOLVED_DROPIN_PATH", dropin),
                patch.object(server_agent.os.path, "realpath", return_value=server_agent.RESOLVED_STUB_PATH),
            ):
                resolver = server_agent.resolver_snapshot()

        self.assertTrue(resolver["managed_stub"])
        self.assertTrue(resolver["cache_enabled"])
        self.assertEqual(resolver["stale_retention"], "1h")
        self.assertEqual(resolver["upstreams"], ["1.1.1.1", "9.9.9.9", "8.8.8.8"])

    def test_proxy_probe_does_not_force_ip_family_on_ipv4_loopback_proxy(self) -> None:
        completed = subprocess.CompletedProcess(["curl"], 0, "200|0.001|0.100|127.0.0.1", "")
        with patch.object(server_agent, "run", return_value=completed) as run_mock:
            result = server_agent.probe_url(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace",
                proxy="socks5h://127.0.0.1:2080",
                ip_version=6,
            )

        self.assertTrue(result["ok"])
        self.assertNotIn("-6", run_mock.call_args.args[0])

    def test_acceptance_retries_one_failed_cycle_without_declaring_hard_failure(self) -> None:
        failed = {
            "profile": "acceptance",
            "ok": False,
            "release_gate_ok": False,
            "requirements": {"foreign_domains_via_router": False, "foreign_domains_via_wg": False},
        }
        recovered = {
            "profile": "acceptance",
            "ok": False,
            "release_gate_ok": True,
            "requirements": {"foreign_domains_via_router": True, "foreign_domains_via_wg": False},
        }
        with patch.object(server_agent, "run_probes", side_effect=[failed, recovered]), patch.object(server_agent.time, "sleep") as sleep:
            result = server_agent.run_confirmed_probes({}, "ru-gateway", "acceptance")

        self.assertFalse(result["ok"])
        self.assertTrue(result["release_gate_ok"])
        self.assertEqual(result["confirmation"]["cycles"], 2)
        self.assertTrue(result["confirmation"]["recovered_on_retry"])
        self.assertFalse(result["confirmation"]["confirmed_failure"])
        self.assertEqual(
            result["confirmation"]["initial_failed_requirements"],
            ["foreign_domains_via_router", "foreign_domains_via_wg"],
        )
        sleep.assert_called_once_with(server_agent.PROBE_CONFIRMATION_DELAY_SECONDS)

    def test_acceptance_reports_confirmed_failure_after_two_cycles(self) -> None:
        failed = {
            "profile": "acceptance",
            "ok": False,
            "release_gate_ok": False,
            "requirements": {"foreign_domains_via_router": False},
        }
        with patch.object(server_agent, "run_probes", side_effect=[failed, failed]), patch.object(server_agent.time, "sleep"):
            result = server_agent.run_confirmed_probes({}, "ru-gateway", "acceptance")

        self.assertFalse(result["ok"])
        self.assertEqual(result["confirmation"]["cycles"], 2)
        self.assertTrue(result["confirmation"]["confirmed_failure"])
        self.assertFalse(result["confirmation"]["recovered_on_retry"])


if __name__ == "__main__":
    unittest.main()
