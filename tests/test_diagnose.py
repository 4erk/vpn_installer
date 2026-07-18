from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import diagnose
from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.localnet import LocalRoute


class DiagnoseTests(unittest.TestCase):
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
                reports = sorted(out_dir.glob("diagnostics/*/*.json"))
                self.assertEqual([path.name for path in reports], ["foreign-exit.json", "ru-gateway.json"])
                self.assertEqual(reports[0].read_text(encoding="utf-8"), "foreign-report")
                self.assertEqual(reports[1].read_text(encoding="utf-8"), "ru-report")

        prepare_mock.assert_called_once()
        self.assertEqual(ssh_mock.call_count, 2)
        for call in ssh_mock.call_args_list:
            self.assertEqual(call.kwargs["command_timeout"], diagnose.PATH_DIAGNOSE_COMMAND_TIMEOUT)

    def test_diagnose_path_writes_partial_report_when_target_times_out(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(
                    diagnose,
                    "prepare_remote_session",
                    return_value=("demo", Path("deployments/demo.env"), {"WG_INTERFACE": "wgx"}, {}, [ru], {}),
                ),
                patch.object(diagnose, "ssh_capture", side_effect=diagnose.AppError("timeout")),
            ):
                self.assertEqual(diagnose.diagnose_path_workflow("demo", "ru"), 0)
                report = next(out_dir.glob("diagnostics/*/ru-gateway.json"))
                self.assertIn("diagnose_error=timeout", report.read_text(encoding="utf-8"))

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
        self.assertIn("dns_timeout: 1", output)
        self.assertIn("BAD: self-tunnel", output)
        self.assertIn("Windows bypass helper", output)

    def test_diagnose_client_uses_structured_agent_snapshot(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        payload = {
            "source": "203.0.113.44",
            "window_minutes": 15,
            "services": {"xray": "active", "nftables": "active"},
            "events": {"accepted": 0, "invalid_reality": 0, "disabled_invalid": 0},
            "front": {"client": {}},
            "verdict": "not_seen_on_server",
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, [ru], {})),
                patch.object(diagnose, "ssh_capture", return_value=json.dumps(payload)) as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_server_client_workflow("demo", source_ip="203.0.113.44", non_interactive=True), 1)
            self.assertTrue(list(out_dir.glob("diagnostics/*/client-front-ru-gateway.json")))
        self.assertIn("vpn-stack-agent.py client --source 203.0.113.44 --since 15", ssh_mock.call_args.args[1])

    def test_diagnose_front_uses_structured_agent_snapshot(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        payload = {
            "window_minutes": 120,
            "services": {"xray": "active", "nftables": "active"},
            "events": {"accepted": 10, "invalid_reality": 0, "disabled_invalid": 0},
            "front": {"listening": True, "connections": 2, "rtt_ms": {"p95": 40}, "socket_retransmissions": 0},
            "verdict": "verified",
        }
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), {}, {}, [ru], {})),
                patch.object(diagnose, "ssh_capture", return_value=json.dumps(payload)) as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_front_workflow("demo", non_interactive=True), 0)
            self.assertTrue(list(out_dir.glob("diagnostics/*/front-ru-gateway.json")))
        self.assertIn("vpn-stack-agent.py front --since 120 --live-probes", ssh_mock.call_args.args[1])
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

        self.assertEqual(len(outputs), 8)
        commands = "\n".join(call.args[1] for call in ssh_mock.call_args_list)
        self.assertIn("vpnstack-diag-iperf", commands)
        self.assertIn("systemd-run --unit=vpnstack-iperf3", commands)
        self.assertIn("iperf3 -c 10.74.0.2", commands)
        self.assertIn("-P 1", commands)
        self.assertIn("-P 4", commands)
        self.assertIn("-b 100M", commands)
        self.assertIn("nft delete rule inet vpnstack input handle", commands)


if __name__ == "__main__":
    unittest.main()
