from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
            patch.object(server_agent, "wireguard_snapshot", return_value={"peers": []}),
            patch.object(server_agent, "default_interface", return_value="ens3"),
            patch.object(server_agent, "interface_counters", return_value={"ens3": {}}),
            patch.object(server_agent, "conntrack_snapshot", return_value={}),
            patch.object(server_agent, "host_snapshot", return_value={"hostname": "ru-host", "login_user": "root", "is_root": True, "has_sudo": True, "os_id": "ubuntu", "os_version": "24.04", "default_interface": "ens3"}) as host_snapshot,
            patch.object(server_agent, "installed_at_value", return_value="2026-07-15T00:00:00Z"),
        ):
            snapshot = server_agent.snapshot()
        self.assertEqual(snapshot["host"]["login_user"], "root")
        self.assertTrue(snapshot["host"]["is_root"])
        host_snapshot.assert_called_once_with("ens3")
        self.assertEqual(snapshot["release"]["installed_at"], "2026-07-15T00:00:00Z")

    def test_front_snapshot_groups_tcp_metrics_by_client_source(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htin" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n\t cubic rtt:45.2/3.1 retrans:0/3 unacked:2 lastsnd:100 lastrcv:200\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_agent, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertTrue(front["listening"])
        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        client = front["clients"]["203.0.113.20"]
        self.assertEqual(client["retransmissions"], 3)
        self.assertEqual(client["unacked"], 2)
        self.assertEqual(client["rtt_ms"]["p95"], 45.2)

    def test_front_snapshot_normalizes_ipv4_mapped_socket_source(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 [::ffff:94.232.248.35]:443 [::ffff:203.0.113.20]:50123\n", "")
            if "-Htin" in args:
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

    def test_client_snapshot_matches_ipv4_mapped_xray_source(self) -> None:
        front = {"listening": True, "clients": {"203.0.113.20": {"connections": 1}}, "top_sources": {"203.0.113.20": 1}}
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with (
            patch.object(server_agent, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "journal_lines", side_effect=[["from [::ffff:203.0.113.20]:50123 accepted tcp:example.org:443"], []]),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "run", return_value=completed),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["events"]["accepted"], 1)
        self.assertEqual(payload["front"]["client"], {"connections": 1})

    def test_front_observation_keeps_one_noisy_client_separate_from_shared_degradation(self) -> None:
        isolated = {"clients": {"203.0.113.20": {"states": {"FIN-WAIT-1": 200}, "retransmissions": 5}}}
        shared = {"clients": {f"203.0.113.{index}": {"states": {"FIN-WAIT-1": 30}, "retransmissions": 0} for index in range(1, 4)}}
        self.assertEqual(server_agent.front_observation(isolated), "client_specific")
        self.assertEqual(server_agent.front_observation(shared), "degraded")

    def test_front_observation_does_not_treat_lifetime_retransmissions_as_fresh_failure(self) -> None:
        front = {"clients": {"203.0.113.20": {"states": {"ESTAB": 1}, "retransmissions": 200}}}
        self.assertEqual(server_agent.front_observation(front), "observed")

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

    def test_standalone_agent_loads_bundled_log_classifier(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "vpn_installer"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            agent = target / "vpn-stack-agent.py"
            shutil.copy2(source_root / "server_agent.py", agent)
            shutil.copy2(source_root / "log_classifier.py", target / "log_classifier.py")
            result = subprocess.run([sys.executable, str(agent), "--help"], text=True, capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vpn-stack-agent", result.stdout)

    def test_client_snapshot_prefers_accepted_xray_event_over_socket_state(self) -> None:
        front = {"listening": True, "clients": {"203.0.113.20": {"connections": 1}}, "top_sources": {"203.0.113.20": 1}}
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with (
            patch.object(server_agent, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "journal_lines", side_effect=[["from 203.0.113.20:50123 accepted tcp:example.org:443"], []]),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "run", return_value=completed),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["events"]["accepted"], 1)
        self.assertEqual(payload["events"]["accepted_tcp"], 1)
        self.assertEqual(payload["events"]["accepted_udp"], 0)
        self.assertEqual(payload["verdict"], "reached_xray")

    def test_ru_acceptance_requires_router_paths_not_direct_foreign_access(self) -> None:
        def probe(url: str, *, interface: str = "", proxy: str = "", **_kwargs: object) -> dict[str, object]:
            blocked_telegram = url == "https://telegram.org/"
            unavailable_wg_ipv6 = "2606:4700:4700::1111" in url and interface == "wg0"
            return {"target": url, "ok": not (blocked_telegram or unavailable_wg_ipv6)}

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", return_value={"ok": True}),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
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

    def test_acceptance_retries_one_failed_cycle_without_declaring_hard_failure(self) -> None:
        failed = {"profile": "acceptance", "ok": False, "requirements": {"foreign_domains_via_wg": False}}
        recovered = {"profile": "acceptance", "ok": True, "requirements": {"foreign_domains_via_wg": True}}
        with patch.object(server_agent, "run_probes", side_effect=[failed, recovered]), patch.object(server_agent.time, "sleep") as sleep:
            result = server_agent.run_confirmed_probes({}, "ru-gateway", "acceptance")

        self.assertTrue(result["ok"])
        self.assertEqual(result["confirmation"]["cycles"], 2)
        self.assertTrue(result["confirmation"]["recovered_on_retry"])
        self.assertFalse(result["confirmation"]["confirmed_failure"])
        self.assertEqual(result["confirmation"]["initial_failed_requirements"], ["foreign_domains_via_wg"])
        sleep.assert_called_once_with(server_agent.PROBE_CONFIRMATION_DELAY_SECONDS)

    def test_acceptance_reports_confirmed_failure_after_two_cycles(self) -> None:
        failed = {"profile": "acceptance", "ok": False, "requirements": {"foreign_domains_via_wg": False}}
        with patch.object(server_agent, "run_probes", side_effect=[failed, failed]), patch.object(server_agent.time, "sleep"):
            result = server_agent.run_confirmed_probes({}, "ru-gateway", "acceptance")

        self.assertFalse(result["ok"])
        self.assertEqual(result["confirmation"]["cycles"], 2)
        self.assertTrue(result["confirmation"]["confirmed_failure"])
        self.assertFalse(result["confirmation"]["recovered_on_retry"])


if __name__ == "__main__":
    unittest.main()
