from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from vpn_installer import interserver_transport, server_agent
from vpn_installer.config import generate_default_env
from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.log_classifier import classify_line
from vpn_installer.platforms import default_build_platform
from vpn_installer.render import render_gateway_singbox


class ServerAgentTests(unittest.TestCase):
    def test_agent_main_dispatches_every_managed_command(self) -> None:
        payload = {"state": "healthy"}
        targets = (
            "diagnostics_snapshot",
            "run_confirmed_probes",
            "front_client_snapshot",
            "public_front_snapshot",
            "private_reject_correlations",
            "health",
            "health_log_summary",
            "reconcile_interserver_transport",
            "watch_interserver_transport",
            "select_transport",
            "apply_network_profile",
            "prepare_memory_reserve",
            "exec_router",
            "storage_maintenance",
            "routes_command",
            "assets_snapshot",
        )
        commands = (
            ["snapshot", "--compact"],
            ["probe", "--profile", "acceptance"],
            ["client", "--source", "203.0.113.5", "--since", "10"],
            ["front", "--since", "10", "--live-probes"],
            [
                "private-reject-correlate",
                "--since",
                "2026-08-30T00:00:00Z",
                "--inbound",
                "router-in",
                "--target",
                "10.0.0.1:80",
            ],
            ["health"],
            ["transport-reconcile"],
            ["transport-watch"],
            ["transport-select", "--tag", "interserver-underlay-hy2"],
            ["network-apply"],
            ["memory-prepare"],
            ["exec-router", "/bin/true"],
            ["storage-maintain", "--deep"],
            ["routes", "list"],
            ["assets"],
        )
        with ExitStack() as stack:
            mocks = {
                name: stack.enter_context(patch.object(server_agent, name, return_value=payload))
                for name in targets
            }
            stack.enter_context(patch.object(server_agent, "parse_env", return_value={"WG_INTERFACE": "wg0"}))
            stack.enter_context(
                patch.object(
                    server_agent,
                    "read_json",
                    return_value={"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}},
                )
            )
            stack.enter_context(patch.object(server_agent, "runtime_contract", return_value={}))
            stack.enter_context(patch.object(server_agent, "installed_runtime_contract", return_value={}))
            stack.enter_context(patch.object(server_agent, "contract_has", return_value=True))
            stack.enter_context(patch("builtins.print"))

            for command in commands:
                with self.subTest(command=command):
                    self.assertEqual(server_agent.main(command), 0)

        for name, mocked in mocks.items():
            with self.subTest(dispatched=name):
                mocked.assert_called()

    def test_agent_main_health_returns_failure_status(self) -> None:
        with patch.object(server_agent, "health", return_value={"state": "failed"}), patch.object(
            server_agent, "health_log_summary", return_value={"state": "failed"}
        ), patch("builtins.print"):
            self.assertEqual(server_agent.main(["health"]), 1)

    def test_installed_at_uses_only_canonical_hyphenated_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "installed-at").write_text("2026-08-16T12:00:00Z\n", encoding="utf-8")
            (root / "installed_at").write_text("ignored\n", encoding="utf-8")
            with patch.object(server_agent, "ROOT", root):
                self.assertEqual(server_agent.installed_at_value(), "2026-08-16T12:00:00Z")
                (root / "installed-at").unlink()
                self.assertEqual(server_agent.installed_at_value(), "")

    @staticmethod
    def gateway_contract(*, topology: str = "dual") -> dict[str, object]:
        capabilities = {"public-front", "router", "local-egress"}
        required_services = ["nftables", "sing-box", "resolver", "health_timer", "xray"]
        if topology == "dual":
            capabilities.update({"ru-split-routing", "interserver-client", "web-admin"})
            required_services.extend(["admin", "wireguard", "transport"])
        return {
            "topology": topology,
            "node_id": "gateway",
            "location": "ru" if topology == "dual" else "foreign",
            "capabilities": frozenset(capabilities),
            "required_services": required_services,
            "service_units": {
                name: server_agent.SERVICE_UNIT_DEFAULTS[name].format(wg_interface="wg0")
                for name in required_services
            },
        }

    @staticmethod
    def exit_contract() -> dict[str, object]:
        required_services = ["nftables", "sing-box", "resolver", "health_timer", "wireguard"]
        return {
            "topology": "dual",
            "node_id": "exit",
            "location": "foreign",
            "capabilities": frozenset({"interserver-server", "nat-exit"}),
            "required_services": required_services,
            "service_units": {
                name: server_agent.SERVICE_UNIT_DEFAULTS[name].format(wg_interface="wg0")
                for name in required_services
            },
        }

    @staticmethod
    def single_manifest() -> dict[str, object]:
        capabilities = ["local-egress", "public-front", "router"]
        required = ["nftables", "sing-box", "resolver", "health_timer", "xray"]
        services = [
            {"name": name, "unit": server_agent.SERVICE_UNIT_DEFAULTS[name].format(wg_interface="wg0")}
            for name in required
        ]
        node = {
            "id": "gateway",
            "location": "foreign",
            "capabilities": capabilities,
            "required_services": required,
        }
        platform = default_build_platform().to_dict()
        return {
            "schema_version": 5,
            "topology": "single",
            "node_id": "gateway",
            "location": "foreign",
            "capabilities": capabilities,
            "required_services": required,
            "node": node,
            "platform": platform,
            "install_plan": {
                "schema_version": 5,
                "topology": "single",
                "node_id": "gateway",
                "location": "foreign",
                "capabilities": capabilities,
                "required_services": required,
                "services": services,
                "platform": platform,
            },
        }

    def test_runtime_contract_is_fail_closed_and_accepts_native_single_gateway(self) -> None:
        contract = server_agent.runtime_contract(self.single_manifest())

        self.assertEqual(contract["topology"], "single")
        self.assertEqual(contract["node_id"], "gateway")
        self.assertNotIn("interserver-client", contract["capabilities"])
        self.assertEqual(contract["capabilities"], frozenset({"local-egress", "public-front", "router"}))
        with self.assertRaisesRegex(RuntimeError, "unsupported render manifest schema"):
            server_agent.runtime_contract({"schema_version": 99})

    def test_runtime_contract_single_excludes_web_admin(self) -> None:
        contract = server_agent.runtime_contract(self.single_manifest())

        self.assertNotIn("web-admin", contract["capabilities"])
        self.assertNotIn("admin", contract["required_services"])

    def test_runtime_contract_rejects_capability_and_install_plan_drift(self) -> None:
        manifest = self.single_manifest()
        manifest["install_plan"] = {**manifest["install_plan"], "capabilities": ["local-egress"]}  # type: ignore[index]

        with self.assertRaisesRegex(RuntimeError, "install plan capabilities conflict"):
            server_agent.runtime_contract(manifest)

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
        with patch.object(server_agent, "run") as run_mock:
            action = server_agent.recover(current)

        self.assertEqual(action, "none")
        run_mock.assert_not_called()

    def test_agent_emits_native_diagnostics_v6_end_to_end(self) -> None:
        generated_at = "2026-08-06T18:00:00+00:00"
        installed_at = "2026-08-06T17:59:00+00:00"
        empty_logs = server_agent.summarize_lines([])
        facts = {
            **self.gateway_contract(),
            "generated_at": generated_at,
            "deployment": "demo",
            "host": {"hostname": "ru", "login_user": "root", "is_root": True},
            "release": {"release_id": "release-1", "installed_at": installed_at},
            "services": {name: "active" for name in ("wireguard", "nftables", "sing-box", "resolver", "xray", "admin", "health_timer", "transport")},
            "artifacts": {"manifest": {"schema_version": 5, "release_id": "release-1"}, "drift": "none", "files": {"sing-box.json": {"actual_sha256": "a", "expected_sha256": "a"}}},
            "wireguard": {"interface": "wg0", "state": "up", "peers": []},
            "probes": {"profile": "acceptance", "ok": True},
            "storage": {"root_filesystem": {"source": "/dev/vda1", "verdict": "verified"}},
            "network": {"tcp_adaptation": {"qdisc": "fq"}, "resolver": {"managed_config": True}, "conntrack": {"count": 1}},
            "front": {"listening": True},
            "transport": {"interserver": {"configured": True}},
            "maintenance": {"upgradable": 0, "security_upgradable": 0, "reboot_required": False},
            "redundancy": {"egress": {"available": False}},
            "logs": {
                "collector_error": "",
                "windows_minutes": {key: dict(empty_logs) for key in ("5", "30", "1440")},
                "fresh": {"since": installed_at, "window_minutes": 1, **empty_logs},
            },
            "verdicts": {"overall": "verified", "server_path": "verified", "reasons": []},
        }
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            payload = server_agent.diagnostics_snapshot(live_probes=True, full_logs=True, include_maintenance=True)

        snapshot = DiagnosticsSnapshot.from_agent(payload)
        self.assertEqual(snapshot.schema_version, 6)
        self.assertEqual(snapshot.collector_status, "ok")
        self.assertEqual(snapshot.host["login_user"], "root")
        self.assertEqual(snapshot.log_windows["since_release"].counts["dns_timeout"], 0)

    def test_compact_snapshot_marks_intentional_omissions_as_skipped(self) -> None:
        generated_at = "2026-08-06T18:00:00+00:00"
        empty_logs = server_agent.summarize_lines([])
        facts = {
            **self.gateway_contract(),
            "generated_at": generated_at,
            "deployment": "demo",
            "host": {},
            "release": {"installed_at": generated_at},
            "services": {name: "active" for name in ("wireguard", "nftables", "sing-box", "resolver", "xray")},
            "artifacts": {"manifest": {"schema_version": 5}, "drift": "none", "files": {}},
            "wireguard": {"interface": "wg0", "state": "up"},
            "probes": {"profile": "none", "ok": None},
            "storage": {"root_filesystem": {"verdict": "verified"}},
            "network": {"tcp_adaptation": {"qdisc": "fq"}, "resolver": {"managed_config": True}, "conntrack": {"count": 1}},
            "front": {"listening": True},
            "transport": {"interserver": {"configured": True}},
            "maintenance": {},
            "redundancy": {},
            "logs": {
                "collector_error": "",
                "windows_minutes": {"5": dict(empty_logs)},
                "fresh": {"since": generated_at, **empty_logs},
            },
            "verdicts": {"overall": "inconclusive", "reasons": []},
        }
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            snapshot = DiagnosticsSnapshot.from_agent(
                server_agent.diagnostics_snapshot(
                    live_probes=False,
                    full_logs=False,
                    include_maintenance=False,
                )
            )

        self.assertEqual(snapshot.collector_status, "skipped")
        self.assertEqual(snapshot.collectors["route_probes"].status, "skipped")
        self.assertEqual(snapshot.collectors["maintenance"].status, "skipped")
        self.assertEqual(snapshot.log_windows["30m"].collector.status, "skipped")
        self.assertEqual(snapshot.log_windows["24h"].collector.status, "skipped")

    def test_journal_failure_is_not_reported_as_zero_events(self) -> None:
        failure = subprocess.CompletedProcess(["journalctl"], 1, "", "journal unavailable")
        with patch.object(server_agent, "run", return_value=failure):
            windows, fresh, error = server_agent.summarize_problem_windows(full_logs=True, fresh_since="5 minutes ago")
        self.assertEqual(error, "journal unavailable")
        self.assertEqual(windows["5"]["counts"]["dns_timeout"], 0)
        self.assertEqual(fresh["counts"]["dns_timeout"], 0)

        facts = {
            **self.exit_contract(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "release": {},
            "logs": {"collector_error": error, "windows_minutes": windows, "fresh": fresh},
        }
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot())
        self.assertEqual(snapshot.collectors["logs"].status, "error")
        self.assertTrue(all(window.counts is None for window in snapshot.log_windows.values()))

    def test_journal_no_matches_is_a_collected_zero_window(self) -> None:
        no_matches = subprocess.CompletedProcess(["journalctl"], 1, "", "")
        with patch.object(server_agent, "run", return_value=no_matches):
            windows, fresh, error = server_agent.summarize_problem_windows(
                full_logs=True,
                fresh_since="5 minutes ago",
            )

        self.assertEqual(error, "")
        self.assertTrue(all(count == 0 for count in windows["5"]["counts"].values()))
        self.assertTrue(all(count == 0 for count in fresh["counts"].values()))

    def test_log_collection_covers_release_within_journal_retention(self) -> None:
        now = 1_786_040_000.0
        installed_at = datetime.fromtimestamp(now - 7 * 24 * 60 * 60, timezone.utc).isoformat()
        with patch.object(server_agent.time, "time", return_value=now), patch.object(
            server_agent, "journal_problem_events", return_value=([], "")
        ) as journal:
            server_agent.summarize_problem_windows(full_logs=True, fresh_since=installed_at)
        journal.assert_called_once_with(7 * 24 * 60)

    def test_journal_json_preserves_unit_identity(self) -> None:
        records = [
            {"__REALTIME_TIMESTAMP": "1786040000000000", "_SYSTEMD_UNIT": "sing-box.service", "MESSAGE": "ERROR [42 1s] dns: exchange failed for a.example. IN A: context deadline exceeded"},
            {"__REALTIME_TIMESTAMP": "1786040001000000", "_SYSTEMD_UNIT": "vpn-stack-xray.service", "MESSAGE": "ERROR [42 1s] connection reset"},
        ]
        completed = subprocess.CompletedProcess(["journalctl"], 0, "\n".join(json.dumps(item) for item in records), "")
        with patch.object(server_agent, "run", return_value=completed):
            events, error = server_agent.journal_problem_events(5)
        self.assertEqual(error, "")
        self.assertIn("[unit=sing-box.service]", events[0][1])
        summary = server_agent.summarize_lines(message for _timestamp, message in events)
        self.assertEqual(summary["counts"]["dns_timeout"], 1)
        self.assertEqual(summary["counts"]["client_reset_eof"], 1)

    def test_journal_json_decodes_binary_ansi_messages(self) -> None:
        message = (
            "+0000 2026-08-07 04:13:07 \x1b[36mERROR\x1b[0m "
            "[\x1b[38;5;51m4252783395\x1b[0m 10s] dns: exchange failed for example.com. IN A: context deadline exceeded"
        )
        record = {
            "__REALTIME_TIMESTAMP": "1786075987103741",
            "_SYSTEMD_UNIT": "sing-box.service",
            "MESSAGE": list(message.encode("utf-8")),
        }
        completed = subprocess.CompletedProcess(["journalctl"], 0, json.dumps(record), "")
        with patch.object(server_agent, "run", return_value=completed):
            events, error = server_agent.journal_problem_events(5)

        self.assertEqual(error, "")
        self.assertNotIn("\x1b", events[0][1])
        self.assertEqual(server_agent.summarize_lines(line for _timestamp, line in events)["counts"]["dns_timeout"], 1)

    def test_journal_problem_events_adds_matching_inbound_context(self) -> None:
        problem = {
            "__REALTIME_TIMESTAMP": "1786075987103741",
            "_SYSTEMD_UNIT": "sing-box.service",
            "MESSAGE": "ERROR [4252783395 10s] open connection to 185.178.210.193:443 using outbound/direct[direct-ru]: i/o timeout",
        }
        context = {
            "__REALTIME_TIMESTAMP": "1786075977103741",
            "_SYSTEMD_UNIT": "sing-box.service",
            "MESSAGE": "INFO [4252783395 0ms] inbound/mixed[router-in]: inbound connection to cs.pikabu.ru:443",
        }
        results = [
            subprocess.CompletedProcess(["journalctl"], 0, json.dumps(problem), ""),
            subprocess.CompletedProcess(["journalctl"], 0, json.dumps(context), ""),
        ]
        with patch.object(server_agent, "run", side_effect=results) as command:
            events, error = server_agent.journal_problem_events(30)

        self.assertEqual(error, "")
        self.assertEqual(len(events), 2)
        self.assertIn("4252783395", command.call_args_list[1].args[0][-1])
        summary = server_agent.summarize_lines(line for _timestamp, line in events)
        self.assertEqual(summary["top_destinations"]["direct_ru_timeout"], {"cs.pikabu.ru:443": 1})

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

    def test_private_reject_correlation_requires_clean_ordered_policy_and_exact_events(self) -> None:
        marker = datetime.now(timezone.utc) - timedelta(seconds=1)
        event_time = datetime.now(timezone.utc)
        records = [
            {
                "__REALTIME_TIMESTAMP": str(int(event_time.timestamp() * 1_000_000)),
                "__CURSOR": "cursor-1",
                "MESSAGE": list(
                    (
                        "+0000 2026-08-07 03:54:45 \x1b[36mINFO\x1b[0m "
                        "[\x1b[38;5;218m3039373591\x1b[0m 0ms] inbound/mixed[router-in]: inbound connection to 10.0.0.1:80"
                    ).encode("utf-8")
                ),
            },
            {
                "__REALTIME_TIMESTAMP": str(int(event_time.timestamp() * 1_000_000)),
                "__CURSOR": "cursor-2",
                "MESSAGE": list(
                    (
                        "+0000 2026-08-07 03:54:46 \x1b[36mINFO\x1b[0m "
                        "[\x1b[38;5;71m3886298263\x1b[0m 0ms] inbound/mixed[router-in]: inbound connection to 172.19.0.2:853"
                    ).encode("utf-8")
                ),
            },
            {
                "__REALTIME_TIMESTAMP": str(int(event_time.timestamp() * 1_000_000)),
                "__CURSOR": "wrong-inbound",
                "MESSAGE": "+0000 2026-08-07 03:54:47 INFO [999999999 0ms] inbound/hysteria2[public-hy2-in]: inbound connection to 10.0.0.1:80",
            },
        ]
        journal = subprocess.CompletedProcess(
            ["journalctl"],
            0,
            "\n".join(json.dumps(record) for record in records),
            "",
        )
        config = {
            "route": {
                "rules": [
                    {"ip_is_private": True, "action": "reject", "method": "default", "no_drop": True},
                    {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"},
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(
                    server_agent,
                    "manifest_snapshot",
                    return_value={"drift": "none", "manifest": self.single_manifest()},
                ),
                patch.object(server_agent, "run", return_value=journal) as run,
            ):
                result = server_agent.private_reject_correlations(
                    marker.isoformat(),
                    "router-in",
                    ["10.0.0.1:80", "172.19.0.2:853"],
                )

        self.assertEqual(result["verdict"], "verified")
        self.assertTrue(result["policy"]["verified"])
        self.assertEqual([item["event_id"] for item in result["targets"]], ["3039373591", "3886298263"])
        self.assertIn(marker.isoformat(), run.call_args.args[0])

    def test_private_reject_correlation_refuses_dirty_or_unordered_config(self) -> None:
        marker = datetime.now(timezone.utc).isoformat()
        config = {
            "route": {
                "rules": [
                    {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"},
                    {"ip_is_private": True, "action": "reject", "method": "default", "no_drop": True},
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(
                    server_agent,
                    "manifest_snapshot",
                    return_value={"drift": "none", "manifest": self.single_manifest()},
                ),
                patch.object(server_agent, "run") as run,
            ):
                result = server_agent.private_reject_correlations(marker, "router-in", ["10.0.0.1:80"])

        self.assertEqual(result["verdict"], "failed")
        self.assertFalse(result["policy"]["verified"])
        run.assert_not_called()

    def test_private_reject_correlation_treats_empty_journal_as_inconclusive(self) -> None:
        config = {
            "route": {
                "rules": [
                    {"ip_is_private": True, "action": "reject", "method": "default", "no_drop": True},
                    {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"},
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_agent, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(
                    server_agent,
                    "manifest_snapshot",
                    return_value={"drift": "none", "manifest": self.single_manifest()},
                ),
                patch.object(
                    server_agent,
                    "run",
                    return_value=subprocess.CompletedProcess(["journalctl"], 1, "", ""),
                ),
            ):
                result = server_agent.private_reject_correlations(
                    datetime.now(timezone.utc).isoformat(),
                    "router-in",
                    ["10.0.0.1:80"],
                )

        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("not observed", result["reason"])

    def test_manifest_snapshot_detects_asset_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset = root / "geosite-ru.srs"
            asset.write_bytes(b"good")
            env_path = root / "env"
            env_path.write_text("DEPLOY_NAME=demo\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        **self.single_manifest(),
                        "env_sha256": server_agent.sha256_file(env_path),
                        "assets": {
                            "geosite-ru.srs": {
                                "sha256": server_agent.sha256_file(asset),
                                "install_path": str(asset),
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_agent, "MANIFEST_PATH", manifest), patch.object(
                server_agent, "ENV_PATH", env_path
            ), patch.object(server_agent, "release_tree_snapshot", return_value={"state": "ok"}):
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
                        **self.single_manifest(),
                        "binaries": {"sing-box": {"version": "1.13.12", "path": str(binary), "sha256": server_agent.sha256_file(binary)}},
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_agent, "MANIFEST_PATH", manifest), patch.object(
                server_agent, "ENV_PATH", root / "env"
            ), patch.object(server_agent, "release_tree_snapshot", return_value={"state": "ok"}):
                self.assertEqual(server_agent.manifest_snapshot()["binaries"]["sing-box"]["state"], "ok")
                binary.write_bytes(b"mutated-binary")
                snapshot = server_agent.manifest_snapshot()
        self.assertEqual(snapshot["drift"], "server-mutated")
        self.assertEqual(snapshot["binaries"]["sing-box"]["state"], "mutated")

    def test_manifest_snapshot_rejects_binary_not_used_by_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "sing-box"
            binary.write_bytes(b"known-binary")
            env = root / "env"
            env.write_text("DEPLOY_NAME=test\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        **self.single_manifest(),
                        "env_sha256": server_agent.sha256_file(env),
                        "binaries": {
                            "sing-box": {
                                "path": str(binary),
                                "sha256": server_agent.sha256_file(binary),
                                "service": "sing-box.service",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_agent, "MANIFEST_PATH", manifest), patch.object(
                server_agent, "ENV_PATH", env
            ), patch.object(server_agent, "service_exec_path", return_value="/usr/bin/sing-box"), patch.object(
                server_agent, "release_tree_snapshot", return_value={"state": "ok"}
            ):
                snapshot = server_agent.manifest_snapshot()
        self.assertEqual(snapshot["drift"], "server-mutated")
        self.assertEqual(snapshot["binaries"]["sing-box"]["state"], "wrong-exec")

    def test_manifest_snapshot_accepts_exec_launcher_actual_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "sing-box"
            binary.write_bytes(b"known-binary")
            env = root / "env"
            env.write_text("DEPLOY_NAME=test\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        **self.single_manifest(),
                        "env_sha256": server_agent.sha256_file(env),
                        "binaries": {
                            "sing-box": {
                                "path": str(binary),
                                "sha256": server_agent.sha256_file(binary),
                                "service": "sing-box.service",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_agent, "MANIFEST_PATH", manifest), patch.object(
                server_agent, "ENV_PATH", env
            ), patch.object(server_agent, "service_exec_path", return_value=str(binary)), patch.object(
                server_agent, "release_tree_snapshot", return_value={"state": "ok"}
            ):
                snapshot = server_agent.manifest_snapshot()
        self.assertEqual(snapshot["drift"], "none")
        self.assertEqual(snapshot["binaries"]["sing-box"]["state"], "ok")

    def test_service_exec_path_reads_the_actual_main_process(self) -> None:
        service = subprocess.CompletedProcess(["systemctl"], 0, "42\n", "")
        with patch.object(server_agent, "run", return_value=service), patch.object(
            server_agent.os, "readlink", return_value="/opt/sing-box"
        ):
            self.assertEqual(server_agent.service_exec_path("sing-box.service"), "/opt/sing-box")

    def test_release_tree_snapshot_detects_content_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            releases = root / "releases"
            candidate = releases / "candidate"
            candidate.mkdir(parents=True)
            (candidate / "render-manifest.json").write_text(
                json.dumps(self.single_manifest()) + "\n",
                encoding="utf-8",
            )
            (candidate / "agent.py").write_text("print('ok')\n", encoding="utf-8")
            digest = server_agent.release_tree_digest(candidate)
            release = releases / f"0.18.0-test-{digest[:12]}"
            candidate.rename(release)

            clean = server_agent.release_tree_snapshot(release, releases, require_symlink=False)
            cache = release / "__pycache__"
            cache.mkdir()
            (cache / "agent.cpython-312.pyc").write_bytes(b"derived-bytecode")
            cached = server_agent.release_tree_snapshot(release, releases, require_symlink=False)
            (release / "agent.py").write_text("print('mutated')\n", encoding="utf-8")
            mutated = server_agent.release_tree_snapshot(release, releases, require_symlink=False)

        self.assertEqual(clean["state"], "ok")
        self.assertEqual(cached["state"], "ok")
        self.assertEqual(mutated["state"], "mutated")

    def test_manifest_snapshot_rejects_release_tree_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_path = root / "env"
            env_path.write_text("DEPLOY_NAME=demo\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({**self.single_manifest(), "env_sha256": server_agent.sha256_file(env_path)}),
                encoding="utf-8",
            )
            with patch.object(server_agent, "MANIFEST_PATH", manifest), patch.object(
                server_agent, "ENV_PATH", env_path
            ), patch.object(server_agent, "release_tree_snapshot", return_value={"state": "mutated"}):
                snapshot = server_agent.manifest_snapshot()

        self.assertEqual(snapshot["drift"], "server-mutated")
        self.assertIn("release-tree", snapshot["mismatches"])

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
        failed = {**self.gateway_contract(), "verdicts": {"server_path": "failed"}, "services": {}}
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "health.json"
            lock = Path(tmp) / "lock"
            with patch.object(server_agent, "HEALTH_STATE_PATH", state), patch.object(server_agent, "LOCK_PATH", lock), patch.object(server_agent, "collect_runtime_facts", return_value=failed) as snapshot_mock, patch.object(server_agent, "recover", return_value="restart:sing-box.service:ok") as recover, patch.object(server_agent.time, "sleep"):
                first = server_agent.health()
                second = server_agent.health()
        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["last_action"], "restart:sing-box.service:ok")
        recover.assert_called_once()
        self.assertFalse(snapshot_mock.call_args_list[0].kwargs["full_logs"])
        self.assertFalse(snapshot_mock.call_args_list[0].kwargs["include_maintenance"])

    def test_health_does_not_probe_or_recover_during_install_transaction(self) -> None:
        previous = {"consecutive_failures": 1, "hard_reasons": ["server_path"]}
        with (
            patch.object(server_agent, "acquire_install_read_lock", return_value=None),
            patch.object(server_agent, "read_json", return_value=previous),
            patch.object(server_agent, "collect_runtime_facts") as collect,
            patch.object(server_agent, "recover") as recover,
        ):
            result = server_agent.health()

        self.assertEqual(result["state"], "maintenance")
        self.assertEqual(result["consecutive_failures"], 1)
        collect.assert_not_called()
        recover.assert_not_called()

    def test_health_does_not_combine_different_hard_failures(self) -> None:
        server_failed = {**self.gateway_contract(), "verdicts": {"server_path": "failed", "host_integrity": "verified"}, "services": {}}
        host_failed = {**self.gateway_contract(), "verdicts": {"server_path": "verified", "host_integrity": "failed"}, "services": {}}
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_agent, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_agent, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", side_effect=[server_failed, host_failed]),
                patch.object(server_agent, "recover") as recover,
            ):
                first = server_agent.health()
                second = server_agent.health()

        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["state"], "suspect")
        self.assertEqual(second["consecutive_failures"], 1)
        recover.assert_not_called()

    def test_failed_recovery_does_not_start_cooldown(self) -> None:
        failed = {**self.gateway_contract(), "verdicts": {"server_path": "failed", "host_integrity": "verified"}, "services": {}}
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_agent, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_agent, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", return_value=failed),
                patch.object(server_agent, "recover", return_value="restart:sing-box.service:failed") as recover,
            ):
                server_agent.health()
                second = server_agent.health()
                third = server_agent.health()

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
                patch.object(server_agent, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_agent, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", return_value=failed),
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
                patch.object(server_agent, "HEALTH_STATE_PATH", state),
                patch.object(server_agent, "LOCK_PATH", lock),
                patch.object(server_agent, "collect_runtime_facts", side_effect=[healthy(10), healthy(13)]),
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
                patch.object(server_agent, "HEALTH_STATE_PATH", state),
                patch.object(server_agent, "LOCK_PATH", lock),
                patch.object(server_agent, "collect_runtime_facts", return_value=current),
                patch.object(server_agent, "recover") as recover,
            ):
                result = server_agent.health()

        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["soft_reasons"], ["conntrack_table_full_5m=2"])
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
                patch.object(server_agent, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_agent, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", return_value=current),
                patch.object(server_agent, "recover") as recover,
            ):
                result = server_agent.health()

        self.assertEqual(result["state"], "healthy")
        self.assertEqual(result["soft_reasons"], [])
        self.assertEqual(result["last_seen_oom_timestamp"], "")
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

    def test_network_soft_reasons_attribute_udp_send_errors_to_fq_flow_limit_once(self) -> None:
        reasons = server_agent.network_soft_reasons(
            {
                "protocol": {"UdpSndbufErrors": 252, "Udp6SndbufErrors": 0},
                "qdisc": {"drops": 252, "flow_limit_drops": 252},
            }
        )
        self.assertEqual(reasons, ["qdisc_drops=252", "qdisc_flow_limit_drops=252"])

    def test_network_soft_reasons_keep_independent_udp_send_errors(self) -> None:
        reasons = server_agent.network_soft_reasons(
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

        summary = server_agent.health_log_summary(payload)

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
                patch.object(server_agent, "HEALTH_STATE_PATH", Path(tmp) / "health.json"),
                patch.object(server_agent, "LOCK_PATH", Path(tmp) / "lock"),
                patch.object(server_agent, "collect_runtime_facts", return_value=current),
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
            f"203.0.113.20:{port}": {"source": "203.0.113.20", "quality": "degraded", "bytes_retrans": port}
            for port in range(100, 125)
        }
        evidence = server_agent.front_degradation_evidence(
            {
                "flows": flows,
                "degraded_sources": ["203.0.113.20"],
                "recent_degraded_sources": ["203.0.113.20"],
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

    def test_tcp_destination_metrics_parser_keeps_only_recovery_fields(self) -> None:
        metrics = server_agent.parse_tcp_destination_metrics(
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

        with patch.object(server_agent, "run", side_effect=command) as run_mock:
            result = server_agent.reconcile_front_tcp_metrics_cache(
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
        with patch.object(server_agent, "run") as run_mock:
            healthy = server_agent.reconcile_front_tcp_metrics_cache(
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
        with patch.object(server_agent, "run") as run_mock:
            first = server_agent.reconcile_front_tcp_metrics_cache(
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
        with patch.object(server_agent, "run") as run_mock:
            result = server_agent.reconcile_front_tcp_metrics_cache(
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
        with patch.object(server_agent, "run") as run_mock:
            action = server_agent.recover(current)
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
        with patch.object(server_agent, "run", return_value=completed) as run_mock:
            action = server_agent.recover(current)

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
        with patch.object(server_agent, "run", return_value=completed) as run_mock:
            action = server_agent.recover(current)

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
        with patch.object(server_agent, "run", return_value=subprocess.CompletedProcess(["sysctl"], 0, "", "")) as run_mock:
            action = server_agent.recover(current)
        self.assertEqual(action, "reload:sysctl:ok")
        run_mock.assert_called_once_with(["sysctl", "--load", str(server_agent.SYSCTL_PATH)], timeout=30)

    def test_recovery_reapplies_clean_managed_qdisc_profile(self) -> None:
        current = {
            **self.exit_contract(),
            "services": {"wireguard": "active", "nftables": "active", "sing-box": "active"},
            "wireguard": {"interface": "wg0"},
            "artifacts": {"drift": "none"},
            "network": {"profile_mismatches": ["overlay_qdisc_flow_limit"]},
        }
        with patch.object(server_agent, "apply_qdisc_profile", return_value={"changed": True}) as apply_mock:
            action = server_agent.recover(current)
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
            patch.object(server_agent, "parse_env", return_value=generate_default_env("demo")),
            patch.object(server_agent, "apply_wireguard_policy", return_value={"changed": True}) as apply_mock,
        ):
            action = server_agent.recover(current)
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
                patch.object(server_agent, "NFTABLES_CONFIG_PATH", config_path),
                patch.object(server_agent, "run", return_value=completed) as run_mock,
            ):
                action = server_agent.recover(current)
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
        manifest = {
            **self.single_manifest(),
            "version": "0.21.0",
            "release_id": "release-1",
            "policy_version": "0.21.0",
        }
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
            patch.object(
                server_agent,
                "tcp_adaptation_snapshot",
                return_value={"congestion_control": "bbr", "qdisc": "fq", "qdisc_limit": 10_000, "qdisc_flow_limit": 512, "mtu_probing": 1},
            ),
            patch.object(server_agent, "wireguard_policy_snapshot", return_value={"managed": True, "ok": True, "checks": {}, "missing": []}),
            patch.object(server_agent, "conntrack_snapshot", return_value={}),
            patch.object(server_agent, "xray_conntrack_bypass_snapshot", return_value={"active": True, "ingress": True, "egress": True}),
            patch.object(server_agent, "host_snapshot", return_value={"hostname": "ru-host", "login_user": "root", "is_root": True, "has_sudo": True, "os_id": "ubuntu", "os_version": "24.04", "default_interface": "ens3"}) as host_snapshot,
            patch.object(server_agent, "installed_at_value", return_value="2026-07-15T00:00:00Z"),
        ):
            snapshot = server_agent.collect_runtime_facts()
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
                "net.ipv4.tcp_thin_linear_timeouts": "1\n",
                "net.core.rmem_default": "8388608\n",
                "net.core.rmem_max": "16777216\n",
                "net.core.wmem_default": "8388608\n",
                "net.core.wmem_max": "16777216\n",
            }
            if args[0] == "sysctl":
                return subprocess.CompletedProcess(args, 0, values[args[-1]], "")
            return subprocess.CompletedProcess(
                args,
                0,
                '[{"kind":"fq","root":true,"options":{"limit":10000,"flow_limit":512},"drops":3,"flows_plimit":2}]\n',
                "",
            )

        with patch.object(server_agent, "run", side_effect=fake_run):
            snapshot = server_agent.tcp_adaptation_snapshot("ens3", "wg0")
        self.assertEqual(
            snapshot,
            {
                "congestion_control": "bbr",
                "mtu_probing": 1,
                "mtu_probe_floor": 536,
                "probe_interval_seconds": 600,
                "metrics_save_disabled": 0,
                "thin_linear_timeouts": 1,
                "udp_rmem_default": 8388608,
                "udp_rmem_max": 16777216,
                "udp_wmem_default": 8388608,
                "udp_wmem_max": 16777216,
                "qdisc": "fq",
                "qdisc_limit": 10000,
                "qdisc_flow_limit": 512,
                "qdisc_drops": 3,
                "qdisc_flow_limit_drops": 2,
                "overlay_qdisc": "fq",
                "overlay_qdisc_limit": 10000,
                "overlay_qdisc_flow_limit": 512,
                "overlay_qdisc_drops": 3,
                "overlay_qdisc_flow_limit_drops": 2,
            },
        )

    def test_apply_qdisc_profile_manages_public_and_wireguard_interfaces(self) -> None:
        before = {"qdisc": "fq", "qdisc_limit": 10_000, "qdisc_flow_limit": 100, "qdisc_drops": 7, "qdisc_flow_limit_drops": 7}
        overlay_before = {"qdisc": "noqueue", "qdisc_limit": 0, "qdisc_flow_limit": 0, "qdisc_drops": 0, "qdisc_flow_limit_drops": 0}
        after = {**before, "qdisc_flow_limit": 512, "qdisc_drops": 0, "qdisc_flow_limit_drops": 0}
        completed = subprocess.CompletedProcess(["tc"], 0, "", "")
        with (
            patch.object(server_agent, "default_interface", return_value="eth0"),
            patch.object(server_agent, "parse_env", return_value={"WG_INTERFACE": "wg0"}),
            patch.object(Path, "exists", return_value=True),
            patch.object(server_agent, "qdisc_snapshot", side_effect=[before, after, overlay_before, after]),
            patch.object(server_agent, "run", return_value=completed) as run_mock,
        ):
            result = server_agent.apply_qdisc_profile()
        self.assertTrue(result["changed"])
        self.assertEqual(result["overlay_qdisc"], "fq")
        self.assertEqual(
            [call.args[0][4] for call in run_mock.call_args_list],
            ["eth0", "wg0"],
        )

        with (
            patch.object(server_agent, "default_interface", return_value="eth0"),
            patch.object(server_agent, "parse_env", return_value={"WG_INTERFACE": "wg0"}),
            patch.object(Path, "exists", return_value=True),
            patch.object(server_agent, "qdisc_snapshot", return_value=after),
            patch.object(server_agent, "run") as unchanged_run,
        ):
            unchanged = server_agent.apply_qdisc_profile()
        self.assertFalse(unchanged["changed"])
        unchanged_run.assert_not_called()

    def test_wireguard_policy_snapshot_detects_a_missing_ipv6_rule(self) -> None:
        env = generate_default_env("demo")

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if args[2:4] == ["rule", "show"]:
                output = "" if args[1] == "-6" else "10000: from all fwmark 0x30 lookup 51820\n"
                return subprocess.CompletedProcess(args, 0, output, "")
            destination = args[-1]
            return subprocess.CompletedProcess(args, 0, f"{destination} dev wg0\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            snapshot = server_agent.wireguard_policy_snapshot(env, managed=True)

        self.assertFalse(snapshot["ok"])
        self.assertEqual(snapshot["missing"], ["ipv6_rule"])

    def test_apply_wireguard_policy_repairs_only_missing_state(self) -> None:
        env = generate_default_env("demo")
        missing = {"managed": True, "ok": False, "missing": ["ipv6_rule"]}
        healthy = {"managed": True, "ok": True, "missing": []}
        completed = subprocess.CompletedProcess(["ip"], 0, "", "")
        with (
            patch.object(server_agent, "wireguard_policy_snapshot", side_effect=[missing, healthy]),
            patch.object(server_agent, "run", return_value=completed) as run_mock,
        ):
            result = server_agent.apply_wireguard_policy(env)

        self.assertTrue(result["changed"])
        run_mock.assert_called_once_with(
            ["ip", "-6", "rule", "add", "fwmark", "48", "table", "51820", "priority", "10000"],
            timeout=10,
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
                "net.core.wmem_default=8388608\n"
                "net.core.wmem_max=16777216\n"
                "net.ipv4.tcp_mtu_probe_floor=536\n"
                "net.ipv4.tcp_no_metrics_save=0\n"
                "net.ipv4.tcp_thin_linear_timeouts=1\n",
                encoding="utf-8",
            )
            expected = server_agent.managed_network_profile(path)
        self.assertEqual(
            expected,
            {
                "udp_rmem_default": 8_388_608,
                "udp_rmem_max": 16_777_216,
                "udp_wmem_default": 8_388_608,
                "udp_wmem_max": 16_777_216,
                "mtu_probe_floor": 536,
                "metrics_save_disabled": 0,
                "thin_linear_timeouts": 1,
                "qdisc": "fq",
                "qdisc_limit": 10_000,
                "qdisc_flow_limit": 512,
                "overlay_qdisc": "fq",
                "overlay_qdisc_limit": 10_000,
                "overlay_qdisc_flow_limit": 512,
            },
        )
        self.assertEqual(
            server_agent.network_profile_mismatches(
                {
                    "udp_rmem_default": 212_992,
                    "udp_rmem_max": 16_777_216,
                    "udp_wmem_default": 8_388_608,
                    "udp_wmem_max": 16_777_216,
                    "mtu_probe_floor": 536,
                    "metrics_save_disabled": 0,
                    "thin_linear_timeouts": 1,
                    "qdisc": "fq",
                    "qdisc_limit": 10_000,
                    "qdisc_flow_limit": 512,
                    "overlay_qdisc": "fq",
                    "overlay_qdisc_limit": 10_000,
                    "overlay_qdisc_flow_limit": 512,
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
        self.assertEqual(
            expected,
            {
                "conntrack_max": 32768,
                "qdisc": "fq",
                "qdisc_limit": 10_000,
                "qdisc_flow_limit": 512,
                "overlay_qdisc": "fq",
                "overlay_qdisc_limit": 10_000,
                "overlay_qdisc_flow_limit": 512,
            },
        )
        self.assertEqual(
            server_agent.network_profile_mismatches(
                {
                    "conntrack_max": 6144,
                    "qdisc": "fq",
                    "qdisc_limit": 10_000,
                    "qdisc_flow_limit": 512,
                    "overlay_qdisc": "fq",
                    "overlay_qdisc_limit": 10_000,
                    "overlay_qdisc_flow_limit": 512,
                },
                expected,
            ),
            ["conntrack_max"],
        )

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
                    "pmtu": 1480,
                    "mss": 1408,
                    "rtt_ms": {"median": 28.0, "p95": 35.0},
                    "rto_ms": {"p95": 210, "max": 220},
                    "cwnd": {"median": 18, "max": 24},
                    "delivery_rate_bps": {"median": 42_000_000, "max": 55_000_000},
                    "reordering": 3,
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
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["pmtu"], 1480)
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["mss"], 1408)
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["rtt_ms"]["p95"], 35.0)
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["rto_ms"]["max"], 220)

    def test_front_interval_replaces_stale_client_specific_verdict(self) -> None:
        current = {
            "front": {"listening": True, "recent_degraded_sources": ["203.0.113.20"]},
            "services": {"xray": "active"},
            "verdicts": {
                "server_path": "verified",
                "public_front": "degraded",
                "public_quic": "verified",
                "client_observation": "client_specific",
                "host_integrity": "verified",
                "overall": "degraded",
                "reasons": ["public_front=client_specific"],
            },
        }
        interval = {
            "baseline": False,
            "observation": "observed",
            "degraded_sources": [],
        }

        server_agent.apply_front_interval_verdict(current, interval)

        self.assertEqual(current["verdicts"]["client_observation"], "observed")
        self.assertEqual(current["verdicts"]["public_front"], "verified")
        self.assertEqual(current["verdicts"]["overall"], "verified")
        self.assertEqual(current["verdicts"]["reasons"], [])

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

    def test_front_snapshot_keeps_idle_lifetime_loss_out_of_current_sources(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n"
                    "\t cubic rtt:400/20 rto:1200 lastsnd:60001 lastrcv:60001 bytes_sent:2000000 bytes_retrans:100000 retrans:0/8\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["degraded_sources"], ["203.0.113.20"])
        self.assertEqual(front["recent_degraded_sources"], [])
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
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
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
            "recent_degraded_sources": ["203.0.113.20"],
            "fin_wait_1_sources": [],
        }
        self.assertEqual(server_agent.public_front_verdict("active", degraded), "degraded")
        self.assertEqual(server_agent.public_front_verdict("inactive", degraded), "failed")

    def test_public_front_verdict_uses_fresh_interval_loss(self) -> None:
        front = {"listening": True, "degraded_sources": [], "fin_wait_1_sources": []}
        interval = {"degraded_sources": ["203.0.113.20"], "observation": "client_specific"}
        self.assertEqual(server_agent.public_front_verdict("active", front, interval), "degraded")

    def test_release_scoped_observation_excludes_previous_release_interval(self) -> None:
        previous = {
            "observed_at": "2026-08-16T22:22:43+00:00",
            "degraded_sources": ["203.0.113.20"],
        }
        current = {
            "observed_at": "2026-08-16T22:23:43+00:00",
            "degraded_sources": ["203.0.113.20"],
        }
        installed_at = "2026-08-16T22:23:00+00:00"
        self.assertEqual(server_agent.release_scoped_observation(previous, installed_at), {})
        self.assertIs(server_agent.release_scoped_observation(current, installed_at), current)
        self.assertIs(server_agent.release_scoped_observation(current, ""), current)

    def test_public_front_ignores_degraded_lifetime_metrics_after_flow_is_idle(self) -> None:
        front = {
            "listening": True,
            "degraded_sources": ["203.0.113.20"],
            "recent_degraded_sources": [],
            "stale_connections_5m": 1,
            "keepalive_timer_connections": 1,
        }
        self.assertEqual(server_agent.front_observation(front), "observed")
        self.assertEqual(server_agent.public_front_verdict("active", front), "verified")

    def test_public_front_reports_accumulated_reality_handshakes_as_degraded(self) -> None:
        front = {
            "listening": True,
            "recent_degraded_sources": [],
            "reality_pending_handshakes": server_agent.REALITY_PENDING_HANDSHAKE_DEGRADED,
        }
        self.assertEqual(server_agent.front_observation(front), "degraded")
        self.assertEqual(server_agent.public_front_verdict("active", front), "degraded")

    def test_reality_pending_handshakes_count_only_xray_target_sockets(self) -> None:
        output = (
            '0 1 10.0.0.1:50001 13.107.21.200:443 users:(("xray",pid=1,fd=1))\n'
            '0 1 10.0.0.1:50002 13.107.21.200:443 users:(("curl",pid=2,fd=2))\n'
            '0 1 10.0.0.1:50003 13.107.21.200:80 users:(("xray",pid=1,fd=3))\n'
        )
        completed = subprocess.CompletedProcess(["ss"], 0, output, "")
        with patch.object(server_agent, "run", return_value=completed):
            self.assertEqual(server_agent.xray_reality_pending_handshakes("r.bing.com:443"), 1)

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
                                    "realitySettings": {
                                        "target": "r.bing.com:443",
                                        "serverNames": ["www.bing.com"],
                                    },
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
            with (
                patch.object(server_agent, "XRAY_CONFIG_PATH", config),
                patch.object(server_agent, "xray_reality_pending_handshakes", return_value=0),
            ):
                policy = server_agent.xray_front_socket_policy(443)

        self.assertEqual(
            policy,
            {
                "tcp_keepalive_idle_seconds": 90,
                "tcp_keepalive_interval_seconds": 15,
                "reality_target": "r.bing.com:443",
                "reality_target_config_key": "target",
                "reality_server_names": ["www.bing.com"],
                "reality_pending_handshakes": 0,
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
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
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
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
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
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
            patch.object(server_agent, "journal_filtered_lines", return_value=lines),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "udp_443_policy", return_value="routed"),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["verdict"], "degraded")
        self.assertEqual(payload["flow_events"], {"203.0.113.20:50123": {"current.example:443": 1}})
        self.assertFalse(payload["client_transport"]["multiplex_detected"])
        self.assertEqual(payload["client_transport"]["status"], "not_observed")

    def test_client_snapshot_detects_tcp_multiplex_on_active_outer_flow(self) -> None:
        front = {
            "listening": True,
            "clients": {"203.0.113.20": {"connections": 1, "quality": "observed"}},
            "flows": {
                "203.0.113.20:50123": {
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "phase": "active",
                    "quality": "observed",
                }
            },
            "top_sources": {"203.0.113.20": 1},
        }
        lines = [
            "from 203.0.113.20:50123 accepted tcp:first.example:443",
            "from 203.0.113.20:50123 accepted udp:1.1.1.1:53",
            "from 203.0.113.20:50123 accepted tcp:second.example:443",
        ]
        with (
            patch.object(server_agent, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
            patch.object(server_agent, "journal_filtered_lines", return_value=lines),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "udp_443_policy", return_value="routed"),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        transport = payload["client_transport"]
        self.assertTrue(transport["multiplex_detected"])
        self.assertEqual(transport["status"], "detected")
        self.assertEqual(transport["multiplexed_flow_count"], 1)
        self.assertEqual(transport["risk"], "tcp_head_of_line")
        self.assertEqual(
            transport["flows"]["203.0.113.20:50123"],
            {
                "accepted_tcp_requests": 2,
                "destinations": {"first.example:443": 1, "second.example:443": 1},
            },
        )

    def test_client_transport_is_inconclusive_without_active_outer_flow(self) -> None:
        observation = server_agent.client_transport_observation({}, active_outer_flows=0)

        self.assertEqual(observation["status"], "inconclusive")
        self.assertFalse(observation["multiplex_detected"])
        self.assertEqual(observation["risk"], "unknown")

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

    def test_interserver_transport_snapshot_reports_stable_wireguard_overlay(self) -> None:
        env = generate_default_env("demo")
        env.update({"GATEWAY_PUBLIC_IP": "94.232.248.35", "EXIT_PUBLIC_IP": "132.243.21.108"})
        config = json.loads(render_gateway_singbox(env))
        sockets = subprocess.CompletedProcess(
            ["ss"],
            0,
            "ESTAB 0 0 94.232.248.35:45678 132.243.21.108:18443\n",
            "",
        )
        selection = {
            "available": True,
            "selected": "interserver-underlay-wg",
            "endpoint": "127.0.0.1:19091",
            "candidates": {"interserver-underlay-wg": {"delay_ms": 42}},
        }
        with (
            patch.object(server_agent, "read_json", return_value=config),
            patch.object(server_agent, "run", return_value=sockets),
            patch.object(server_agent, "transport_selection_snapshot", return_value=selection),
            patch.object(server_agent, "transport_state_snapshot", return_value={"state": "healthy", "fresh": True}),
        ):
            transport = server_agent.interserver_transport_snapshot(self.gateway_contract(), env)

        self.assertTrue(transport["configured"])
        self.assertTrue(transport["hysteria_session_active"])
        self.assertEqual(transport["selection"]["selected"], "interserver-underlay-wg")
        self.assertEqual(transport["adaptive_state"]["state"], "healthy")

    def test_transport_selection_snapshot_reports_configured_topology_without_urltest_history(self) -> None:
        env = generate_default_env("demo")
        env.update({"GATEWAY_PUBLIC_IP": "94.232.248.35", "EXIT_PUBLIC_IP": "132.243.21.108"})
        config = json.loads(render_gateway_singbox(env))
        relay = {"available": True, "endpoint": "127.0.0.1:19091", "reason": ""}
        selector = {"available": True, "selected": "interserver-underlay-hy2", "reason": ""}
        with (
            patch.object(server_agent, "wireguard_overlay_relay", return_value=relay),
            patch.object(server_agent, "transport_selector_selection", return_value=selector),
        ):
            selection = server_agent.transport_selection_snapshot(config, env, "127.0.0.1:19090")

        self.assertTrue(selection["available"])
        self.assertEqual(selection["selected"], "interserver-underlay-hy2")
        self.assertEqual(selection["endpoint"], "127.0.0.1:19091")
        self.assertTrue(selection["candidates"]["interserver-underlay-wg"]["configured"])
        self.assertTrue(selection["candidates"]["interserver-underlay-hy2"]["configured"])

    def test_transport_selection_rejects_an_incomplete_topology(self) -> None:
        env = generate_default_env("demo")
        env.update({"GATEWAY_PUBLIC_IP": "94.232.248.35", "EXIT_PUBLIC_IP": "132.243.21.108"})
        config = json.loads(render_gateway_singbox(env))
        config["outbounds"] = [
            outbound
            for outbound in config["outbounds"]
            if outbound.get("tag") != "interserver-underlay-hy2"
        ]
        relay = {"available": True, "endpoint": "127.0.0.1:19091", "reason": ""}
        selector = {"available": True, "selected": "interserver-underlay-wg", "reason": ""}
        with (
            patch.object(server_agent, "wireguard_overlay_relay", return_value=relay),
            patch.object(server_agent, "transport_selector_selection", return_value=selector),
        ):
            selection = server_agent.transport_selection_snapshot(config, env, "127.0.0.1:19090")

        self.assertFalse(selection["available"])
        self.assertFalse(selection["candidates"]["interserver-underlay-hy2"]["configured"])
        self.assertEqual(selection["reason"], "transport topology is incomplete")

    def test_transport_cycle_probes_alternate_only_after_overlay_failure(self) -> None:
        failed = {"checked": True, "ok": False, "attempts": 1, "error": "timeout"}
        healthy = {"checked": True, "ok": True, "attempts": 1, "delay_ms": 50}
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with (
            patch.object(server_agent, "transport_overlay_path_probe", return_value=failed) as overlay_probe,
            patch.object(server_agent, "transport_candidate_probe", return_value=healthy) as probe,
        ):
            result = server_agent.collect_transport_probes(
                "interserver-underlay-wg",
                {},
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        probe.assert_called_once_with("interserver-underlay-hy2")
        overlay_probe.assert_called_once_with(env)
        self.assertEqual(result["interserver-underlay-wg"], failed)
        self.assertEqual(result["interserver-underlay-hy2"], healthy)

        with (
            patch.object(server_agent, "transport_overlay_path_probe", return_value=failed),
            patch.object(server_agent, "transport_candidate_probe", return_value=healthy) as probe,
        ):
            result = server_agent.collect_transport_probes(
                "interserver-underlay-wg",
                {
                    "switch_backoff": {
                        "target": "interserver-underlay-hy2",
                        "retry_at": "2026-08-07T12:00:30+00:00",
                    }
                },
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        probe.assert_not_called()
        self.assertFalse(result["interserver-underlay-hy2"]["checked"])

        with (
            patch.object(server_agent, "transport_overlay_path_probe", return_value=healthy),
            patch.object(server_agent, "transport_candidate_probe", return_value=healthy) as probe,
        ):
            result = server_agent.collect_transport_probes(
                "interserver-underlay-wg",
                {"preferred_probe_at": "2026-08-07T11:59:55+00:00"},
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        probe.assert_not_called()
        self.assertFalse(result["interserver-underlay-hy2"]["checked"])

        with (
            patch.object(server_agent, "transport_overlay_path_probe", return_value=healthy),
            patch.object(server_agent, "transport_candidate_probe", return_value=healthy) as probe,
        ):
            server_agent.collect_transport_probes(
                "interserver-underlay-hy2",
                {"preferred_probe_at": "2026-08-07T11:59:29+00:00"},
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        probe.assert_called_once_with(
            "interserver-underlay-wg",
            timeout_ms=server_agent.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
            attempts=server_agent.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
        )

    def test_transport_reconcile_does_not_switch_during_install_transaction(self) -> None:
        previous = {
            "schema_version": server_agent.TRANSPORT_STATE_SCHEMA_VERSION,
            "selected": "interserver-underlay-wg",
            "state": "healthy",
        }
        with (
            patch.object(server_agent, "acquire_install_read_lock", return_value=None),
            patch.object(server_agent, "read_json", return_value=previous),
            patch.object(server_agent, "collect_transport_probes") as probes,
            patch.object(server_agent, "select_transport") as select,
            patch.object(server_agent, "write_json_atomic"),
        ):
            result = server_agent.reconcile_interserver_transport()

        self.assertEqual(result["state"], "maintenance")
        self.assertEqual(result["selected"], "interserver-underlay-wg")
        probes.assert_not_called()
        select.assert_not_called()

    def test_transport_candidate_probe_uses_path_specific_local_proxy(self) -> None:
        with patch.object(interserver_transport, "_socks_udp_dns_probe") as probe:
            result = server_agent.transport_candidate_probe("interserver-underlay-hy2")

        self.assertTrue(result["ok"])
        self.assertEqual(result["scope"], "raw-underlay-udp")
        self.assertEqual(result["target"], "10.75.0.2:1053")
        self.assertTrue(result["health_confirmed"])
        probe.assert_called_once_with(19094, "10.75.0.2", 1053, 1.2)

    def test_transport_candidate_quality_probe_reports_partial_loss(self) -> None:
        with patch.object(
            interserver_transport,
            "_socks_udp_dns_probe",
            side_effect=[None, TimeoutError("timed out"), None, None],
        ) as probe:
            result = server_agent.transport_candidate_probe(
                "interserver-underlay-wg",
                timeout_ms=1200,
                attempts=4,
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["health_confirmed"])
        self.assertFalse(result["quality_ok"])
        self.assertEqual(result["packet_loss_pct"], 25.0)
        self.assertEqual(probe.call_count, 4)
        probe.assert_called_with(19093, "10.75.0.2", 1053, 0.3)

    def test_overlay_dns_probe_retries_one_lost_exchange_without_failing_the_path(self) -> None:
        with patch.object(
            interserver_transport,
            "_bound_tcp_dns_probe",
            side_effect=[TimeoutError("timed out"), None],
        ) as probe:
            result = interserver_transport.transport_overlay_dns_probe("wg0", "10.74.0.2")

        self.assertTrue(result["ok"])
        self.assertTrue(result["health_confirmed"])
        self.assertFalse(result["failure_confirmed"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(probe.call_args.args, ("wg0", "10.74.0.2", 1053, 0.6))

    def test_overlay_dns_probe_confirms_failure_only_after_two_exchanges(self) -> None:
        with patch.object(
            interserver_transport,
            "_bound_tcp_dns_probe",
            side_effect=TimeoutError("timed out"),
        ) as probe:
            result = interserver_transport.transport_overlay_dns_probe("wg0", "10.74.0.2")

        self.assertFalse(result["ok"])
        self.assertTrue(result["failure_confirmed"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(probe.call_count, 2)

    def test_overlay_dns_probe_rejects_incomplete_and_non_ipv4_identity(self) -> None:
        cases = (
            (("", "10.74.0.2"), {}, "identity is incomplete"),
            (("wg0", ""), {}, "identity is incomplete"),
            (("wg0", "not-an-ip"), {}, "not an IP literal"),
            (("wg0", "2001:db8::1"), {}, "not IPv4"),
            (("wg0", "10.74.0.2"), {"attempts": 0}, "identity is incomplete"),
        )
        with patch.object(interserver_transport, "_bound_tcp_dns_probe") as probe:
            for args, kwargs, expected in cases:
                with self.subTest(args=args, kwargs=kwargs):
                    result = interserver_transport.transport_overlay_dns_probe(*args, **kwargs)
                    self.assertFalse(result["ok"])
                    self.assertIn(expected, result["error"])
        probe.assert_not_called()

    def test_transport_candidate_probe_rejects_an_unknown_tag(self) -> None:
        result = interserver_transport.transport_candidate_probe("unknown")
        self.assertFalse(result["ok"])
        self.assertIn("unknown transport candidate", result["error"])

    def test_transport_candidate_probe_rejects_a_local_accept_without_remote_dns(self) -> None:
        with patch.object(
            interserver_transport,
            "_socks_udp_dns_probe",
            side_effect=OSError("DNS probe returned no answers"),
        ):
            result = server_agent.transport_candidate_probe("interserver-underlay-hy2")

        self.assertFalse(result["ok"])
        self.assertIn("no answers", result["error"])

    def test_socks_udp_probe_validates_the_remote_dns_response(self) -> None:
        control = MagicMock()
        control.__enter__.return_value = control
        control.recv.side_effect = [
            b"\x05\x00",
            b"\x05\x00\x00\x01",
            b"\x7f\x00\x00\x01",
            (9999).to_bytes(2, "big"),
        ]
        datagram = MagicMock()
        datagram.__enter__.return_value = datagram
        datagram.getsockname.return_value = ("127.0.0.1", 54321)
        _query_id, dns_query = interserver_transport._dns_probe_query()
        dns_response = (
            bytes.fromhex("565081800001000100000000")
            + dns_query[12:]
            + bytes.fromhex("c00c000100010000003c00047f000001")
        )
        datagram.recvfrom.return_value = (
            b"\x00\x00\x00\x01\x0a\x4b\x00\x02" + (1053).to_bytes(2, "big") + dns_response,
            ("127.0.0.1", 9999),
        )
        with (
            patch.object(interserver_transport.socket, "socket", return_value=datagram),
            patch.object(interserver_transport.socket, "create_connection", return_value=control),
        ):
            interserver_transport._socks_udp_dns_probe(19094, "10.75.0.2", 1053, 1.2)

        self.assertEqual(control.sendall.call_args_list[0].args[0], b"\x05\x01\x00")
        self.assertTrue(control.sendall.call_args_list[1].args[0].startswith(b"\x05\x03\x00\x01"))
        self.assertEqual(datagram.sendto.call_args.args[1], ("127.0.0.1", 9999))
        self.assertIn(b"\x09localhost\x00", datagram.sendto.call_args.args[0])

    def test_bound_tcp_probe_validates_the_framed_dns_response(self) -> None:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        _query_id, dns_query = interserver_transport._dns_probe_query()
        dns_response = (
            bytes.fromhex("565081800001000100000000")
            + dns_query[12:]
            + bytes.fromhex("c00c000100010000003c00047f000001")
        )
        connection.recv.side_effect = [len(dns_response).to_bytes(2, "big"), dns_response]
        with patch.object(interserver_transport.socket, "socket", return_value=connection):
            interserver_transport._bound_tcp_dns_probe("wg0", "10.74.0.2", 1053, 0.6)

        connection.connect.assert_called_once_with(("10.74.0.2", 1053))
        framed_query = connection.sendall.call_args.args[0]
        self.assertEqual(int.from_bytes(framed_query[:2], "big"), len(dns_query))
        self.assertEqual(framed_query[2:], dns_query)

    def test_dns_probe_rejects_an_answer_count_without_record_data(self) -> None:
        _query_id, dns_query = interserver_transport._dns_probe_query()
        forged_response = bytes.fromhex("565081800001000100000000") + dns_query[12:]

        with self.assertRaisesRegex(OSError, "truncated name"):
            interserver_transport._dns_probe_response(forged_response, 0x5650)

    def test_transport_overlay_path_probe_uses_the_managed_dns_dataplane(self) -> None:
        healthy = {
            "checked": True,
            "ok": True,
            "attempts": 1,
            "scope": "overlay-dns",
            "target": "10.74.0.2:1053",
        }
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with patch.object(server_agent, "transport_overlay_dns_probe", return_value=healthy) as probe:
            result = server_agent.transport_overlay_path_probe(env)

        self.assertTrue(result["ok"])
        self.assertEqual(result["scope"], "overlay-dns")
        probe.assert_called_once_with("wg0", "10.74.0.2")

    def test_transport_overlay_path_probe_preserves_confirmed_failure(self) -> None:
        failed = {
            "checked": True,
            "ok": False,
            "attempts": 2,
            "scope": "overlay-dns",
            "target": "10.74.0.2:1053",
            "error": "timed out",
            "failure_confirmed": True,
        }
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with patch.object(server_agent, "transport_overlay_dns_probe", return_value=failed):
            result = server_agent.transport_overlay_path_probe(env)

        self.assertFalse(result["ok"])
        self.assertTrue(result["failure_confirmed"])

    def test_transport_overlay_quality_probe_reports_partial_loss_and_rtt(self) -> None:
        completed = subprocess.CompletedProcess(
            ["ping"],
            0,
            (
                "20 packets transmitted, 15 received, 25% packet loss, time 955ms\n"
                "rtt min/avg/max/mdev = 24.100/31.250/48.500/8.200 ms\n"
            ),
            "",
        )
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with patch.object(server_agent, "run", return_value=completed) as command:
            result = server_agent.transport_overlay_path_probe(env, quality=True)

        self.assertFalse(result["ok"])
        self.assertTrue(result["quality_checked"])
        self.assertEqual(result["packet_loss_pct"], 25.0)
        self.assertEqual(result["rtt_avg_ms"], 31.25)
        self.assertEqual(result["scope"], "overlay-quality")
        self.assertIn("packet loss 25%", result["error"])
        self.assertEqual(
            command.call_args.args[0],
            [
                "ping",
                "-n",
                "-I",
                "wg0",
                "-c",
                "20",
                "-i",
                "0.05",
                "-w",
                "2",
                "-W",
                "1",
                "-s",
                "1200",
                "10.74.0.2",
            ],
        )

    def test_transport_probe_schedules_quality_and_honors_preferred_retry(self) -> None:
        self.assertTrue(server_agent.overlay_quality_probe_due({}, "2026-08-07T12:00:00+00:00"))
        self.assertFalse(
            server_agent.overlay_quality_probe_due(
                {"quality_probe_at": "2026-08-07T11:59:55+00:00", "state": "healthy"},
                "2026-08-07T12:00:00+00:00",
            )
        )
        self.assertFalse(
            server_agent.overlay_quality_probe_due(
                {"quality_probe_at": "2026-08-07T11:59:59+00:00", "state": "suspect"},
                "2026-08-07T12:00:00+00:00",
            )
        )
        retry = {
            "preferred_retry": {
                "path": "interserver-underlay-wg",
                "retry_at": "2026-08-07T12:01:00+00:00",
            }
        }
        self.assertFalse(server_agent.preferred_transport_probe_due(retry, "2026-08-07T12:00:59+00:00"))
        self.assertTrue(server_agent.preferred_transport_probe_due(retry, "2026-08-07T12:01:00+00:00"))

    def test_transport_cycle_runs_quality_only_after_fast_liveness_succeeds(self) -> None:
        liveness = {"checked": True, "ok": True, "attempts": 1, "scope": "overlay-dns", "health_confirmed": True}
        quality = {
            "checked": True,
            "ok": True,
            "attempts": 20,
            "scope": "overlay-quality",
            "quality_checked": True,
            "packet_loss_pct": 0.0,
        }
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with patch.object(
            server_agent,
            "transport_overlay_path_probe",
            side_effect=(liveness, quality),
        ) as probe:
            result = server_agent.collect_transport_probes(
                "interserver-underlay-wg",
                {},
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        selected = result["interserver-underlay-wg"]
        self.assertTrue(selected["ok"])
        self.assertEqual(selected["scope"], "overlay-dns")
        self.assertTrue(selected["quality_sampled"])
        self.assertTrue(selected["quality_ok"])
        self.assertEqual(selected["packet_loss_pct"], 0.0)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(probe.call_args_list[0].args, (env,))
        self.assertEqual(probe.call_args_list[0].kwargs, {})
        self.assertEqual(probe.call_args_list[1].args, (env,))
        self.assertEqual(probe.call_args_list[1].kwargs, {"quality": True})

    def test_transport_cycle_keeps_a_live_path_when_quality_sample_has_loss(self) -> None:
        liveness = {"checked": True, "ok": True, "attempts": 1, "scope": "overlay-dns", "health_confirmed": True}
        quality = {
            "checked": True,
            "ok": False,
            "attempts": 4,
            "scope": "overlay-quality",
            "quality_checked": True,
            "packet_loss_pct": 25.0,
            "error": "WireGuard overlay packet loss 25%",
        }
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        alternate_probe = {
            "checked": True,
            "ok": True,
            "health_confirmed": True,
            "quality_checked": True,
            "quality_ok": True,
            "packet_loss_pct": 0.0,
        }
        with patch.object(server_agent, "transport_overlay_path_probe", side_effect=(liveness, quality)), patch.object(
            server_agent, "transport_candidate_probe", return_value=alternate_probe
        ) as alternate:
            result = server_agent.collect_transport_probes(
                "interserver-underlay-wg",
                {},
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        self.assertTrue(result["interserver-underlay-wg"]["ok"])
        self.assertFalse(result["interserver-underlay-wg"]["quality_ok"])
        self.assertTrue(result["interserver-underlay-wg"]["quality_sampled"])
        self.assertEqual(result["interserver-underlay-wg"]["packet_loss_pct"], 25.0)
        self.assertEqual(result["interserver-underlay-hy2"], alternate_probe)
        alternate.assert_called_once_with(
            "interserver-underlay-hy2",
            timeout_ms=server_agent.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
            attempts=server_agent.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
        )

    def test_transport_cycle_bypasses_preferred_retry_when_selected_fallback_degrades(self) -> None:
        liveness = {"checked": True, "ok": True, "attempts": 1, "scope": "overlay-dns", "health_confirmed": True}
        quality = {
            "checked": True,
            "ok": False,
            "attempts": 20,
            "scope": "overlay-quality",
            "quality_checked": True,
            "packet_loss_pct": 15.0,
            "error": "Hysteria overlay packet loss 15%",
        }
        alternate_probe = {
            "checked": True,
            "ok": True,
            "health_confirmed": True,
            "quality_checked": True,
            "quality_ok": True,
        }
        previous = {
            "preferred_retry": {
                "path": "interserver-underlay-wg",
                "retry_at": "2026-08-07T13:00:00+00:00",
            }
        }
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with patch.object(server_agent, "transport_overlay_path_probe", side_effect=(liveness, quality)), patch.object(
            server_agent, "transport_candidate_probe", return_value=alternate_probe
        ) as alternate:
            result = server_agent.collect_transport_probes(
                "interserver-underlay-hy2",
                previous,
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        self.assertFalse(result["interserver-underlay-hy2"]["quality_ok"])
        self.assertEqual(result["interserver-underlay-wg"], alternate_probe)
        alternate.assert_called_once_with(
            "interserver-underlay-wg",
            timeout_ms=server_agent.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
            attempts=server_agent.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
        )

    def test_transport_cycle_reuses_the_last_quality_sample_until_refresh(self) -> None:
        liveness = {"checked": True, "ok": True, "attempts": 1, "scope": "overlay-dns"}
        previous = {
            "state": "degraded",
            "quality_probe_at": "2026-08-07T11:59:59+00:00",
            "last_quality_probe": {
                "quality_checked": True,
                "quality_ok": False,
                "quality_error": "packet loss 25%",
                "packet_loss_pct": 25.0,
            },
        }
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with patch.object(server_agent, "transport_overlay_path_probe", return_value=liveness) as probe:
            result = server_agent.collect_transport_probes(
                "interserver-underlay-wg",
                previous,
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        self.assertFalse(result["interserver-underlay-wg"]["quality_ok"])
        self.assertFalse(result["interserver-underlay-wg"]["quality_sampled"])
        self.assertEqual(result["interserver-underlay-wg"]["packet_loss_pct"], 25.0)
        probe.assert_called_once_with(env)

    def test_transport_relay_reset_does_not_touch_application_flows(self) -> None:
        payload = {
            "connections": [
                {
                    "id": "relay-id",
                    "chains": ["interserver-underlay-wg", "interserver-underlay-select"],
                    "metadata": {"network": "udp", "type": "direct/interserver-overlay-in"},
                },
                {
                    "id": "app-id",
                    "chains": ["to-foreign"],
                    "metadata": {"network": "tcp", "type": "mixed/router-in"},
                },
            ]
        }
        with patch.object(server_agent, "clash_api_json", side_effect=[payload, {}]) as api:
            closed = server_agent.reset_transport_relay("127.0.0.1:19090")

        self.assertEqual(closed, 1)
        self.assertEqual(api.call_args_list[1].args[1], "/connections/relay-id")
        self.assertEqual(api.call_args_list[1].kwargs["method"], "DELETE")

    def test_select_transport_changes_only_the_underlay_selector(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_PUBLIC_KEY": "peer-key", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        selections = [
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-hy2"},
        ]
        with (
            patch.object(server_agent, "transport_selector_selection", side_effect=selections),
            patch.object(server_agent, "clash_api_json") as api,
            patch.object(server_agent, "reset_transport_relay", return_value=1) as reset,
            patch.object(server_agent, "prove_wireguard_overlay") as proof,
        ):
            result = server_agent.select_transport(env, "127.0.0.1:19090", "interserver-underlay-hy2")

        self.assertIsNone(result)
        reset.assert_called_once_with("127.0.0.1:19090")
        proof.assert_called_once_with(env)
        self.assertEqual(api.call_args.args[1], "/proxies/interserver-underlay-select")
        self.assertEqual(api.call_args.kwargs["method"], "PUT")
        self.assertEqual(api.call_args.kwargs["payload"], {"name": "interserver-underlay-hy2"})

    def test_select_transport_restores_previous_selector_on_failed_activation(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_PUBLIC_KEY": "peer-key", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        selections = [
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-wg"},
        ]
        with (
            patch.object(server_agent, "transport_selector_selection", side_effect=selections),
            patch.object(server_agent, "clash_api_json") as api,
            patch.object(server_agent, "reset_transport_relay", return_value=1) as reset,
            patch.object(server_agent, "prove_wireguard_overlay") as proof,
        ):
            with self.assertRaisesRegex(RuntimeError, "previous selector path restored and verified"):
                server_agent.select_transport(env, "127.0.0.1:19090", "interserver-underlay-hy2")

        self.assertEqual([call.kwargs["payload"] for call in api.call_args_list], [
            {"name": "interserver-underlay-hy2"},
            {"name": "interserver-underlay-wg"},
        ])
        reset.assert_called_once_with("127.0.0.1:19090")
        proof.assert_called_once_with(env)

    def test_transport_switch_failure_uses_bounded_backoff(self) -> None:
        first = server_agent.next_transport_switch_failure(
            {},
            "interserver-underlay-hy2",
            "activation failed",
            "2026-08-09T12:00:00+00:00",
        )
        self.assertEqual(first["attempts"], 1)
        self.assertEqual(first["retry_at"], "2026-08-09T12:00:30+00:00")
        self.assertIsNotNone(
            server_agent.transport_switch_backoff_active(
                {"switch_backoff": first},
                "interserver-underlay-hy2",
                "2026-08-09T12:00:29+00:00",
            )
        )
        self.assertIsNone(
            server_agent.transport_switch_backoff_active(
                {"switch_backoff": first},
                "interserver-underlay-hy2",
                "2026-08-09T12:00:30+00:00",
            )
        )
        second = server_agent.next_transport_switch_failure(
            {"switch_backoff": first},
            "interserver-underlay-hy2",
            "activation still failed",
            "2026-08-09T12:00:30+00:00",
        )
        self.assertEqual(second["attempts"], 2)
        self.assertEqual(second["retry_at"], "2026-08-09T12:01:30+00:00")

    def test_transport_reconcile_does_not_repeat_a_failed_switch_inside_backoff(self) -> None:
        config = {"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}}
        env = {"SSH_PORT": "22"}
        state: dict[str, object] = {}
        probes = {
            "interserver-underlay-wg": {"checked": True, "ok": False, "error": "timed out"},
            "interserver-underlay-hy2": {"checked": True, "ok": True, "delay_ms": 70},
        }

        def read(path: Path, _default: object) -> dict[str, object]:
            return config if path == server_agent.SINGBOX_CONFIG_PATH else dict(state)

        def write(_path: Path, payload: dict[str, object]) -> None:
            state.clear()
            state.update(payload)

        selection = {
            "available": True,
            "selected": "interserver-underlay-wg",
            "endpoint": "127.0.0.1:19091",
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_agent, "TRANSPORT_LOCK_PATH", Path(tmp) / "transport.lock"),
                patch.object(server_agent, "read_json", side_effect=read),
                patch.object(server_agent, "write_json_atomic", side_effect=write),
                patch.object(server_agent, "parse_env", return_value=env),
                patch.object(server_agent, "transport_topology_configured", return_value=True),
                patch.object(server_agent, "transport_selection_snapshot", return_value=selection),
                patch.object(server_agent, "collect_transport_probes", return_value=probes),
                patch.object(
                    server_agent,
                    "utc_now",
                    side_effect=[
                        "2026-08-09T12:00:00+00:00",
                        "2026-08-09T12:00:02+00:00",
                        "2026-08-09T12:00:04+00:00",
                    ],
                ),
                patch.object(
                    server_agent,
                    "select_transport",
                    side_effect=RuntimeError("activation failed; previous selector path restored and verified"),
                ) as select,
            ):
                first = server_agent._reconcile_interserver_transport_unlocked()
                second = server_agent._reconcile_interserver_transport_unlocked()
                third = server_agent._reconcile_interserver_transport_unlocked()

        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["state"], "degraded")
        self.assertIn("switch_backoff", second)
        self.assertEqual(third["state"], "failed")
        self.assertFalse(third["would_switch"])
        self.assertIn("paused until", third["reason"])
        select.assert_called_once()

    def test_select_transport_restores_previous_selector_when_overlay_proof_fails(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_PUBLIC_KEY": "peer-key", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        selections = [
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-hy2"},
            {"available": True, "selected": "interserver-underlay-wg"},
        ]
        with patch.object(server_agent, "transport_selector_selection", side_effect=selections), patch.object(
            server_agent, "prove_wireguard_overlay", side_effect=[RuntimeError("proof failed"), None]
        ), patch.object(server_agent, "clash_api_json") as api, patch.object(
            server_agent, "reset_transport_relay", return_value=1
        ) as reset:
            with self.assertRaisesRegex(RuntimeError, "previous selector path restored and verified"):
                server_agent.select_transport(env, "127.0.0.1:19090", "interserver-underlay-hy2")
        self.assertEqual(
            [call.kwargs["payload"] for call in api.call_args_list],
            [{"name": "interserver-underlay-hy2"}, {"name": "interserver-underlay-wg"}],
        )
        self.assertEqual(reset.call_count, 2)

    def test_transport_reconcile_persists_maintenance_during_install(self) -> None:
        previous = {
            "schema_version": server_agent.TRANSPORT_STATE_SCHEMA_VERSION,
            "state": "failed",
            "selected": "interserver-underlay-hy2",
            "reason": "old transient failure",
        }
        with (
            patch.object(server_agent, "acquire_install_read_lock", return_value=None),
            patch.object(server_agent, "read_json", return_value=previous),
            patch.object(server_agent, "write_json_atomic") as write,
        ):
            payload = server_agent.reconcile_interserver_transport()

        self.assertEqual(payload["state"], "maintenance")
        self.assertFalse(payload["would_switch"])
        write.assert_called_once_with(server_agent.TRANSPORT_STATE_PATH, payload)

    def test_transport_reconcile_drops_state_from_an_old_schema(self) -> None:
        previous = {
            "schema_version": server_agent.TRANSPORT_STATE_SCHEMA_VERSION - 1,
            "state": "failed",
            "last_switch_failure": {"reason": "obsolete endpoint mutation failure"},
        }
        with (
            patch.object(server_agent, "acquire_install_read_lock", return_value=None),
            patch.object(server_agent, "read_json", return_value=previous),
            patch.object(server_agent, "write_json_atomic"),
        ):
            payload = server_agent.reconcile_interserver_transport()

        self.assertEqual(payload["schema_version"], server_agent.TRANSPORT_STATE_SCHEMA_VERSION)
        self.assertNotIn("last_switch_failure", payload)

    def test_transport_reconcile_drops_an_expired_switch_failure(self) -> None:
        config = {"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}}
        expired_failure = {
            "target": "interserver-underlay-hy2",
            "attempts": 1,
            "failed_at": "2026-08-09T11:59:00+00:00",
            "retry_at": "2026-08-09T11:59:30+00:00",
            "reason": "transient activation failure",
        }
        previous = {
            "schema_version": server_agent.TRANSPORT_STATE_SCHEMA_VERSION,
            "state": "healthy",
            "selected": "interserver-underlay-wg",
            "switch_backoff": expired_failure,
            "last_switch_failure": expired_failure,
        }
        selection = {"available": True, "selected": "interserver-underlay-wg"}
        probes = {"interserver-underlay-wg": {"checked": True, "ok": True}}
        evaluated = {
            "schema_version": server_agent.TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": "2026-08-09T12:00:00+00:00",
            "state": "healthy",
            "selected": "interserver-underlay-wg",
            "recommended": "interserver-underlay-wg",
            "would_switch": False,
            "changed": False,
            "reason": "selected overlay is healthy",
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(server_agent, "TRANSPORT_LOCK_PATH", Path(tmp) / "transport.lock"),
                patch.object(server_agent, "read_json", side_effect=[config, previous]),
                patch.object(server_agent, "write_json_atomic") as write,
                patch.object(server_agent, "parse_env", return_value={}),
                patch.object(server_agent, "transport_topology_configured", return_value=True),
                patch.object(server_agent, "transport_selection_snapshot", return_value=selection),
                patch.object(server_agent, "collect_transport_probes", return_value=probes),
                patch.object(server_agent, "evaluate_transport_policy", return_value=evaluated),
                patch.object(server_agent, "utc_now", return_value="2026-08-09T12:00:00+00:00"),
            ):
                payload = server_agent._reconcile_interserver_transport_unlocked()

        self.assertNotIn("switch_backoff", payload)
        self.assertNotIn("last_switch_failure", payload)
        write.assert_called_once_with(server_agent.TRANSPORT_STATE_PATH, payload)

    def test_overlay_proof_waits_for_exact_dns_dataplane_convergence(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        failed = {"ok": False, "health_confirmed": False, "error": "timed out"}
        healthy = {"ok": True, "health_confirmed": True, "error": ""}
        with patch.object(
            server_agent,
            "transport_overlay_dns_probe",
            side_effect=[failed, failed, healthy],
        ) as probe, patch.object(server_agent.time, "sleep") as sleep:
            server_agent.prove_wireguard_overlay(env)

        self.assertEqual(probe.call_count, 3)
        probe.assert_called_with(
            "wg0",
            "10.74.0.2",
            timeout_ms=server_agent.TRANSPORT_SWITCH_PROOF_TIMEOUT_MS,
            attempts=1,
        )
        self.assertEqual(sleep.call_count, 2)
        sleep.assert_called_with(server_agent.TRANSPORT_SWITCH_PROOF_RETRY_DELAY_SECONDS)

    def test_overlay_proof_fails_after_bounded_dns_attempts(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        failed = {"ok": False, "health_confirmed": False, "error": "timed out"}
        with patch.object(
            server_agent,
            "transport_overlay_dns_probe",
            return_value=failed,
        ) as probe, patch.object(server_agent.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "DNS convergence proof failed after 5 attempts"):
                server_agent.prove_wireguard_overlay(env)

        self.assertEqual(probe.call_count, server_agent.TRANSPORT_SWITCH_PROOF_ATTEMPTS)

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
            transport = server_agent.interserver_transport_snapshot(self.exit_contract(), {"GATEWAY_PUBLIC_IP": "94.232.248.35"})

        self.assertTrue(transport["configured"])
        self.assertTrue(transport["listening"])
        self.assertEqual(transport["source_restricted_to"], "94.232.248.35")

    def test_standalone_agent_loads_bundled_log_classifier(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "vpn_installer"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            agent = target / "vpn-stack-agent.py"
            shutil.copy2(source_root / "server_agent.py", agent)
            shutil.copy2(source_root / "diagnostics.py", target / "diagnostics.py")
            shutil.copy2(source_root / "log_classifier.py", target / "log_classifier.py")
            shutil.copy2(source_root / "interserver_transport.py", target / "interserver_transport.py")
            shutil.copy2(source_root / "network_profile.py", target / "network_profile.py")
            shutil.copy2(source_root / "release_integrity.py", target / "release_integrity.py")
            shutil.copy2(source_root / "resource_control.py", target / "resource_control.py")
            shutil.copy2(source_root / "platforms.py", target / "platforms.py")
            result = subprocess.run([sys.executable, str(agent), "--help"], text=True, capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vpn-stack-agent", result.stdout)

    def test_standalone_single_agent_does_not_require_interserver_module(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "vpn_installer"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            agent = target / "vpn-stack-agent.py"
            shutil.copy2(source_root / "server_agent.py", agent)
            shutil.copy2(source_root / "diagnostics.py", target / "diagnostics.py")
            shutil.copy2(source_root / "log_classifier.py", target / "log_classifier.py")
            shutil.copy2(source_root / "network_profile.py", target / "network_profile.py")
            shutil.copy2(source_root / "release_integrity.py", target / "release_integrity.py")
            shutil.copy2(source_root / "resource_control.py", target / "resource_control.py")
            shutil.copy2(source_root / "platforms.py", target / "platforms.py")
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
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
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

        def identity(*, interface: str = "", proxy: str = "") -> dict[str, object]:
            return {"ok": True, "egress_ip": "198.51.100.20" if interface or proxy else "203.0.113.10"}

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", side_effect=identity),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(server_agent, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0", "GATEWAY_PUBLIC_IP": "203.0.113.10", "EXIT_PUBLIC_IP": "198.51.100.20"}, self.gateway_contract(), "acceptance")

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
            result = server_agent.run_probes({"WG_INTERFACE": "wg0"}, self.gateway_contract(), "light")

        self.assertTrue(result["ok"])
        self.assertEqual(result["via_wg"], [])
        self.assertNotIn("via_wg", result["requirements"])
        self.assertFalse(any(call.get("interface") == "wg0" for call in calls))

    def test_external_ipv6_failure_rejects_release_acceptance(self) -> None:
        def probe(url: str, **_kwargs: object) -> dict[str, object]:
            return {"target": url, "ok": "2606:4700:4700::1111" not in url}

        def identity(*, interface: str = "", proxy: str = "") -> dict[str, object]:
            return {"ok": True, "egress_ip": "198.51.100.20" if interface or proxy else "203.0.113.10"}

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", side_effect=identity),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(server_agent, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0", "GATEWAY_PUBLIC_IP": "203.0.113.10", "EXIT_PUBLIC_IP": "198.51.100.20"}, self.gateway_contract(), "acceptance")

        self.assertFalse(result["requirements"]["ipv6_literal_via_router"])
        self.assertFalse(result["ok"])
        self.assertFalse(result["release_gate_ok"])
        self.assertFalse(result["release_gate_requirements"]["ipv6_literal_via_router"])
        self.assertFalse(server_agent.release_gate_ok(result))

    def test_wireguard_candidate_failure_is_degraded_when_router_path_is_healthy(self) -> None:
        def probe(url: str, *, interface: str = "", proxy: str = "", **_kwargs: object) -> dict[str, object]:
            return {"target": url, "ok": not bool(interface)}

        def identity(*, interface: str = "", proxy: str = "") -> dict[str, object]:
            return {
                "ok": not bool(interface),
                "egress_ip": "198.51.100.20" if interface or proxy else "203.0.113.10",
            }

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", side_effect=identity),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(server_agent, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0", "GATEWAY_PUBLIC_IP": "203.0.113.10", "EXIT_PUBLIC_IP": "198.51.100.20"}, self.gateway_contract(), "acceptance")

        self.assertFalse(result["requirements"]["foreign_domains_via_wg"])
        self.assertFalse(result["requirements"]["wireguard_candidate_identity"])
        self.assertTrue(result["requirements"]["foreign_domains_via_router"])
        self.assertTrue(result["release_gate_ok"])

    def test_hysteria_candidate_failure_is_reported_without_rejecting_a_healthy_router(self) -> None:
        def identity(*, interface: str = "", proxy: str = "") -> dict[str, object]:
            return {"ok": True, "egress_ip": "198.51.100.20" if interface or proxy else "203.0.113.10"}

        with (
            patch.object(server_agent, "probe_url", return_value={"ok": True}),
            patch.object(server_agent, "probe_identity", side_effect=identity),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(
                server_agent,
                "transport_candidate_probe",
                return_value={"ok": False, "error": "timeout"},
            ) as candidate_probe,
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0", "GATEWAY_PUBLIC_IP": "203.0.113.10", "EXIT_PUBLIC_IP": "198.51.100.20"}, self.gateway_contract(), "acceptance")

        candidate_probe.assert_called_once_with("interserver-underlay-hy2")
        self.assertFalse(result["requirements"]["hysteria_candidate_reachable"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["release_gate_ok"])
        self.assertEqual(result["capability_failures"]["transport"], ["hysteria_candidate_reachable"])

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
            config = Path(tmp) / "dnsmasq.conf"
            config.write_text(
                "listen-address=127.0.0.1\nport=1054\nno-resolv\nall-servers\n"
                "cache-size=4096\nserver=1.1.1.1\nserver=9.9.9.9\nserver=8.8.8.8\n",
                encoding="utf-8",
            )
            with patch.object(server_agent, "DNS_CACHE_CONFIG_PATH", config):
                resolver = server_agent.resolver_snapshot()

        self.assertTrue(resolver["managed_config"])
        self.assertTrue(resolver["concurrent_upstreams"])
        self.assertEqual(resolver["listen_port"], 1054)
        self.assertEqual(resolver["cache_capacity"], 4096)
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
            result = server_agent.run_confirmed_probes({}, self.gateway_contract(), "acceptance")

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
            result = server_agent.run_confirmed_probes({}, self.gateway_contract(), "acceptance")

        self.assertFalse(result["ok"])
        self.assertEqual(result["confirmation"]["cycles"], 2)
        self.assertTrue(result["confirmation"]["confirmed_failure"])
        self.assertFalse(result["confirmation"]["recovered_on_retry"])


if __name__ == "__main__":
    unittest.main()
