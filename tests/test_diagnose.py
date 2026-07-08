from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import diagnose
from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.localnet import LocalRoute


class DiagnoseTests(unittest.TestCase):
    def test_path_script_collects_route_and_loss_diagnostics(self) -> None:
        script = diagnose._path_script(ROLE_RU, "wg0")
        self.assertIn("tc -s qdisc show dev", script)
        self.assertIn("mtr -rwzc 20", script)
        self.assertIn("curl -4kLsS", script)
        self.assertIn("peer_wg", script)
        self.assertIn("10.74.0.2", script)
        self.assertIn("section recent_xray_grouped", script)
        self.assertIn("vpn-stack-xray.service", script)
        self.assertIn("accepted_destinations=", script)
        self.assertIn("disabled_invalid=", script)
        self.assertIn("to_foreign_ip_literal=", script)
        self.assertIn("to_foreign_ipv6_literal=", script)
        self.assertIn("timeout_destinations=", script)
        self.assertIn("ip_literal_timeout_destinations=", script)

    def test_diagnose_path_writes_reports_for_targets(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        foreign = RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example", ssh_user="root")
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(
                    diagnose,
                    "prepare_remote_session",
                    return_value=("demo", Path("deployments/demo.env"), {"WG_INTERFACE": "wgx"}, {}, [ru, foreign], {}),
                ) as prepare_mock,
                patch.object(diagnose, "ssh_capture", side_effect=["ru-report", "foreign-report"]) as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_path_workflow("demo", "all"), 0)
                reports = sorted(out_dir.glob("diagnostics/*/*.txt"))
                self.assertEqual([path.name for path in reports], ["foreign-exit.txt", "ru-gateway.txt"])
                self.assertEqual(reports[0].read_text(encoding="utf-8"), "foreign-report")
                self.assertEqual(reports[1].read_text(encoding="utf-8"), "ru-report")

        prepare_mock.assert_called_once()
        self.assertEqual(ssh_mock.call_count, 2)

    def test_diagnose_client_log_reports_front_failure_and_self_tunnel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "client.log"
            log_path.write_text(
                "\n".join(
                    [
                        "connection: open connection to 149.154.175.100:443 using outbound/vless[proxy]: dial tcp 94.232.248.35:443: i/o timeout",
                        "dns: exchange failed for plugins.jetbrains.com. IN A: context deadline exceeded",
                    ]
                ),
                encoding="utf-8",
            )
            env = {"DEPLOY_NAME": "demo", "RU_PUBLIC_IP": "94.232.248.35", "FOREIGN_PUBLIC_IP": "132.243.21.108", "SSH_PORT": "22", "CLIENT_TUN_NAME": "singbox_tun"}
            with (
                patch.object(diagnose, "select_existing_deployment", return_value="demo"),
                patch.object(diagnose, "load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)),
                patch.object(diagnose, "load_state", return_value={}),
                patch.object(diagnose, "local_route_to_server", return_value=LocalRoute("94.232.248.35", "singbox_tun", "172.18.0.2", "172.18.0.1")),
                patch("sys.stdout", new_callable=__import__("io").StringIO) as stream,
            ):
                self.assertEqual(diagnose.diagnose_client_log_workflow(str(log_path), deployment="demo", role=ROLE_RU), 1)
        output = stream.getvalue()
        self.assertIn("client_front_connect_failed: 1", output)
        self.assertIn("dns_failed: 1", output)
        self.assertIn("BAD: self-tunnel", output)
        self.assertIn("Windows bypass helper", output)

    def test_front_script_collects_source_gate_counters(self) -> None:
        script = diagnose._front_script("203.0.113.44", 120)
        self.assertIn("accepted_from_source=", script)
        self.assertIn("invalid_from_source=", script)
        self.assertIn("abuse_set_contains_source=", script)
        self.assertIn("nft_vless_accept_packets=", script)
        self.assertIn("front_socket_states=", script)

    def test_front_verdicts_are_source_specific(self) -> None:
        self.assertEqual(diagnose._front_verdict({"source_ip": "203.0.113.44", "accepted_from_source": "2"}), "reached_xray")
        self.assertEqual(diagnose._front_verdict({"source_ip": "203.0.113.44", "invalid_from_source": "1"}), "rejected_by_front")
        self.assertEqual(diagnose._front_verdict({"source_ip": "203.0.113.44", "abuse_set_contains_source": "1"}), "blocked_by_guard")
        self.assertEqual(diagnose._front_verdict({"source_ip": "203.0.113.44", "socket_rows_from_source": "1"}), "tcp_reached_no_xray_accept")
        self.assertEqual(diagnose._front_verdict({"source_ip": "203.0.113.44"}), "not_seen_on_server")

    def test_diagnose_front_writes_report_and_returns_not_seen(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        report = "\n".join(
            [
                "window_minutes=120",
                "listen_port=443",
                "xray_active=active",
                "nftables_active=active",
                "accepted_total=10",
                "invalid_reality_total=0",
                "disabled_invalid_total=0",
                "sources=198.51.100.1=10",
                "source_ip=203.0.113.44",
                "accepted_from_source=0",
                "invalid_from_source=0",
                "disabled_invalid_from_source=0",
                "guard_blocks_from_source=0",
                "abuse_set_contains_source=0",
                "socket_rows_from_source=0",
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, [ru], {})),
                patch.object(diagnose, "ssh_capture", return_value=report),
                patch("sys.stdout", new_callable=__import__("io").StringIO) as stream,
            ):
                self.assertEqual(diagnose.diagnose_front_workflow("demo", source_ip="203.0.113.44", non_interactive=True), 1)
            output = stream.getvalue()
            self.assertIn("verdict: not_seen_on_server", output)
            self.assertTrue(list(out_dir.glob("diagnostics/*/front-ru-gateway.txt")))

    def test_iperf_smoke_requires_both_roles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(diagnose, "warn") as warn_mock:
            diagnose._run_iperf_smoke(Path(tmp), [RemoteTarget(role=ROLE_RU)])
        warn_mock.assert_called_once()

    def test_iperf_smoke_opens_and_cleans_temporary_wg_rules(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        foreign = RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example", ssh_user="root")
        with tempfile.TemporaryDirectory() as tmp, patch.object(diagnose.time, "sleep"), patch.object(diagnose, "ssh_capture", return_value="ok") as ssh_mock:
            diagnose._run_iperf_smoke(Path(tmp), [ru, foreign])
            outputs = sorted(Path(tmp).glob("iperf-*.txt"))

        self.assertEqual(len(outputs), 4)
        commands = "\n".join(call.args[1] for call in ssh_mock.call_args_list)
        self.assertIn("vpnstack-diag-iperf", commands)
        self.assertIn("systemd-run --unit=vpnstack-iperf3", commands)
        self.assertIn("iperf3 -c 10.74.0.2", commands)
        self.assertIn("nft delete rule inet vpnstack input handle", commands)


if __name__ == "__main__":
    unittest.main()
