from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import diagnose
from vpn_installer.models import RemoteTarget
from vpn_installer.localnet import LocalRoute
from vpn_installer.topology import (
    CONFIG_SCHEMA_VERSION,
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
    TopologySpec,
)


def topology_env(mode: str, gateway_location: str) -> dict[str, str]:
    return {
        "CONFIG_SCHEMA": str(CONFIG_SCHEMA_VERSION),
        "DEPLOY_NAME": "demo",
        "TOPOLOGY": mode,
        "GATEWAY_LOCATION": gateway_location,
        "GATEWAY_PUBLIC_IP": "94.232.248.35" if gateway_location == LOCATION_RU else "132.243.21.108",
        "EXIT_PUBLIC_IP": "132.243.21.108" if mode == TOPOLOGY_DUAL else "",
        "SSH_PORT": "22",
        "CLIENT_TUN_NAME": "singbox_tun",
    }


def target(node_id: str, location: str) -> RemoteTarget:
    host = "94.232.248.35" if location == LOCATION_RU else "132.243.21.108"
    return RemoteTarget(node_id=node_id, location=location, public_ip=host, ssh_host=host, ssh_user="root")


class DiagnoseTests(unittest.TestCase):
    def test_diagnose_path_dual_writes_gateway_and_exit_reports(self) -> None:
        gateway = target(NODE_GATEWAY, LOCATION_RU)
        exit_target = target(NODE_EXIT, LOCATION_FOREIGN)
        env = topology_env(TOPOLOGY_DUAL, LOCATION_RU)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(
                    diagnose,
                    "prepare_remote_session",
                    return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway, exit_target], {}),
                ) as prepare_mock,
                patch.object(
                    diagnose,
                    "ssh_capture",
                    side_effect=lambda remote, *_args, **_kwargs: f"{remote.node_id}-report",
                ) as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_path_workflow("demo", "all"), 0)
                reports = sorted(out_dir.glob("diagnostics/*/*.json"))
                self.assertEqual([path.name for path in reports], ["exit.json", "gateway.json"])
                self.assertEqual(reports[0].read_text(encoding="utf-8"), "exit-report")
                self.assertEqual(reports[1].read_text(encoding="utf-8"), "gateway-report")

        prepare_mock.assert_called_once()
        self.assertEqual(ssh_mock.call_count, 2)
        for call in ssh_mock.call_args_list:
            self.assertEqual(call.kwargs["command_timeout"], diagnose.PATH_DIAGNOSE_COMMAND_TIMEOUT)

    def test_diagnose_path_single_ru_writes_only_gateway_without_interserver_probe(self) -> None:
        gateway = target(NODE_GATEWAY, LOCATION_RU)
        env = topology_env(TOPOLOGY_SINGLE, LOCATION_RU)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(
                    diagnose,
                    "prepare_remote_session",
                    return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {}),
                ),
                patch.object(diagnose, "ssh_capture", return_value="gateway-report") as ssh_mock,
                patch.object(diagnose, "warn") as warn_mock,
            ):
                self.assertEqual(diagnose.diagnose_path_workflow("demo", NODE_GATEWAY, iperf=True), 0)
                reports = list(out_dir.glob("diagnostics/*/*.json"))
                self.assertEqual([path.name for path in reports], ["gateway.json"])
                self.assertEqual(ssh_mock.call_count, 1)
                self.assertNotIn("iperf", ssh_mock.call_args.args[1])
                warn_mock.assert_called_once_with("Interserver iperf неприменим для single topology, пропускаю.")

    def test_diagnose_path_single_foreign_writes_only_gateway(self) -> None:
        gateway = target(NODE_GATEWAY, LOCATION_FOREIGN)
        env = topology_env(TOPOLOGY_SINGLE, LOCATION_FOREIGN)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(
                    diagnose,
                    "prepare_remote_session",
                    return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {}),
                ),
                patch.object(diagnose, "ssh_capture", return_value="gateway-report") as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_path_workflow("demo", "all"), 0)
                reports = list(out_dir.glob("diagnostics/*/*.json"))
                self.assertEqual([path.name for path in reports], ["gateway.json"])
                self.assertEqual(ssh_mock.call_count, 1)

    def test_diagnose_path_writes_partial_report_when_gateway_times_out(self) -> None:
        gateway = target(NODE_GATEWAY, LOCATION_RU)
        env = topology_env(TOPOLOGY_SINGLE, LOCATION_RU)
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(
                    diagnose,
                    "prepare_remote_session",
                    return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {}),
                ),
                patch.object(diagnose, "ssh_capture", side_effect=diagnose.AppError("timeout")),
            ):
                self.assertEqual(diagnose.diagnose_path_workflow("demo", NODE_GATEWAY), 0)
                report = next(out_dir.glob("diagnostics/*/gateway.json"))
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
            env = topology_env(TOPOLOGY_SINGLE, LOCATION_RU)
            with (
                patch.object(diagnose, "select_existing_deployment", return_value="demo"),
                patch.object(diagnose, "load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)),
                patch.object(diagnose, "load_state", return_value={}),
                patch.object(diagnose, "local_route_to_server", return_value=LocalRoute("94.232.248.35", "singbox_tun", "172.18.0.2", "172.18.0.1")),
                patch("sys.stdout", new_callable=__import__("io").StringIO) as stream,
            ):
                self.assertEqual(diagnose.diagnose_client_log_workflow(str(log_path), deployment="demo", node=NODE_GATEWAY), 1)
        output = stream.getvalue()
        self.assertIn("client_front_connect_failed: 1", output)
        self.assertIn("dns_timeout: 1", output)
        self.assertIn("BAD: self-tunnel", output)
        self.assertIn("Windows bypass helper", output)

    def test_diagnose_client_uses_structured_agent_snapshot(self) -> None:
        gateway = target(NODE_GATEWAY, LOCATION_RU)
        env = topology_env(TOPOLOGY_SINGLE, LOCATION_RU)
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
                patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {})),
                patch.object(diagnose, "ssh_capture", return_value=json.dumps(payload)) as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_server_client_workflow("demo", source_ip="203.0.113.44", non_interactive=True), 1)
            self.assertTrue(list(out_dir.glob("diagnostics/*/client-front-gateway.json")))
        self.assertIn("vpn-stack-agent.py client --source 203.0.113.44 --since 15", ssh_mock.call_args.args[1])

    def test_diagnose_client_reports_lifetime_loss_without_claiming_current_failure(self) -> None:
        gateway = target(NODE_GATEWAY, LOCATION_RU)
        env = topology_env(TOPOLOGY_SINGLE, LOCATION_RU)
        payload = {
            "source": "203.0.113.44",
            "window_minutes": 15,
            "services": {"xray": "active", "nftables": "active"},
            "events": {"accepted": 2, "invalid_reality": 0, "disabled_invalid": 0},
            "front": {"client": {"quality": "loss_observed", "pmtu": 1480, "mss": 1408}, "flows": {}},
            "client_transport": {"status": "detected", "multiplex_detected": True, "active_outer_flows": 1, "multiplexed_flow_count": 1, "risk": "tcp_head_of_line"},
            "verdict": "loss_observed",
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(diagnose, "OUT_DIR", Path(tmp) / "out"),
                patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {})),
                patch.object(diagnose, "ssh_capture", return_value=json.dumps(payload)),
                patch("sys.stdout", new_callable=__import__("io").StringIO) as stream,
            ):
                result = diagnose.diagnose_server_client_workflow("demo", source_ip="203.0.113.44", non_interactive=True)

        self.assertEqual(result, 0)
        self.assertIn("verdict: loss_observed", stream.getvalue())
        self.assertIn("pmtu=1480, mss=1408", stream.getvalue())
        self.assertIn("client transport: multiplex=detected, active_outer_flows=1, multiplexed_flows=1, risk=tcp_head_of_line", stream.getvalue())
        self.assertIn("no fresh degraded interval is available", stream.getvalue())

    def test_diagnose_front_uses_structured_agent_snapshot(self) -> None:
        gateway = target(NODE_GATEWAY, LOCATION_FOREIGN)
        env = topology_env(TOPOLOGY_SINGLE, LOCATION_FOREIGN)
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
                patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {})),
                patch.object(diagnose, "ssh_capture", return_value=json.dumps(payload)) as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_front_workflow("demo", non_interactive=True), 0)
            self.assertTrue(list(out_dir.glob("diagnostics/*/front-gateway.json")))
        self.assertIn("vpn-stack-agent.py front --since 120 --live-probes", ssh_mock.call_args.args[1])
    def test_iperf_smoke_single_does_not_require_exit_or_touch_remote(self) -> None:
        topology = TopologySpec.from_env(topology_env(TOPOLOGY_SINGLE, LOCATION_RU))
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(diagnose, "warn") as warn_mock,
            patch.object(diagnose, "ssh_capture") as ssh_mock,
        ):
            diagnose._run_iperf_smoke(Path(tmp), topology, [target(NODE_GATEWAY, LOCATION_RU)])
        warn_mock.assert_called_once()
        ssh_mock.assert_not_called()

    def test_iperf_smoke_opens_and_cleans_temporary_wg_rules(self) -> None:
        topology = TopologySpec.from_env(topology_env(TOPOLOGY_DUAL, LOCATION_RU))
        gateway = target(NODE_GATEWAY, LOCATION_RU)
        exit_target = target(NODE_EXIT, LOCATION_FOREIGN)
        with tempfile.TemporaryDirectory() as tmp, patch.object(diagnose.time, "sleep"), patch.object(diagnose, "ssh_capture", return_value="ok") as ssh_mock:
            diagnose._run_iperf_smoke(Path(tmp), topology, [gateway, exit_target])
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
