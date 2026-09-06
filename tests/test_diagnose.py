from __future__ import annotations

import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

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


def telegram_probe(*, router: bool, success: bool = True, address: str = "149.154.167.50") -> dict:
    probe = {
        "address": address, "port": 443,
        "path": {"kind": "socks5" if router else "direct",
                 "proxy": "127.0.0.1:2080" if router else None, "interface": None},
        "phase": "mtproto", "tcp_connected": True,
        "proxy_accepted": True if router else None,
        "protocol_response": success, "error": None if success else "timeout", "elapsed": 0.1,
    }
    if success:
        probe["res_pq"] = {
            "server_nonce": "63248f6748214eab8a2f4cc876e11974",
            "pq": "2e9cdb98c80cda4b", "fingerprints": ["d09d1d85de64fd85"],
        }
    return probe


def telegram_report(*probes: dict) -> dict:
    successes = sum(probe.get("protocol_response") is True for probe in probes)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": "telegram", "scope": "unauthenticated_req_pq_multi",
        "verdict": "responsive" if successes == len(probes) else "degraded" if successes else "failed",
        "probes": list(probes),
    }


class DiagnoseTests(unittest.TestCase):
    def _run_telegram_report(self, reply: dict, *, router: bool = True, destinations=None):
        env = topology_env(TOPOLOGY_DUAL, LOCATION_RU)
        targets = [target(NODE_GATEWAY, LOCATION_RU), target(NODE_EXIT, LOCATION_FOREIGN)]
        node = NODE_GATEWAY if router else NODE_EXIT
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(diagnose, "OUT_DIR", Path(tmp)),
            patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("unused"), env, {}, targets, {})),
            patch.object(diagnose, "ssh_capture", return_value=json.dumps(reply)),
            patch("sys.stdout", io.StringIO()),
        ):
            code = diagnose.diagnose_telegram_workflow("demo", node, destinations or ["149.154.167.50"])
            report = json.loads(next(Path(tmp).glob("diagnostics/*/telegram.json")).read_text(encoding="utf-8"))
        return code, report["nodes"][node]

    def test_telegram_checks_router_and_exit_and_preserves_negative_results(self) -> None:
        env = topology_env(TOPOLOGY_DUAL, LOCATION_RU)
        targets = [target(NODE_GATEWAY, LOCATION_RU), target(NODE_EXIT, LOCATION_FOREIGN)]

        def reply(remote, command, **kwargs):
            self.assertIn("VPN_APPLICATION_PROBE", command)
            self.assertEqual("--proxy 127.0.0.1:2080" in command, remote.node_id == NODE_GATEWAY)
            self.assertTrue(kwargs["as_root"])
            return json.dumps(telegram_report(telegram_probe(router=remote.node_id == NODE_GATEWAY, success=False)))

        with tempfile.TemporaryDirectory() as tmp, patch.object(diagnose, "OUT_DIR", Path(tmp)), patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("unused"), env, {}, targets, {})), patch.object(diagnose, "ssh_capture", side_effect=reply):
            self.assertEqual(diagnose.diagnose_telegram_workflow("demo", "all", ["149.154.167.50"]), 1)
            report = json.loads(next(Path(tmp).glob("diagnostics/*/telegram.json")).read_text(encoding="utf-8"))
            self.assertEqual(set(report["nodes"]), {NODE_GATEWAY, NODE_EXIT})
            self.assertEqual(report["nodes"][NODE_GATEWAY]["path"], "router")
            self.assertEqual(report["nodes"][NODE_EXIT]["probes"][0]["error"], "timeout")
            self.assertEqual(len(report["probe_sha256"]), 64)

    def test_telegram_requires_complete_success_evidence(self) -> None:
        for router in (True, False):
            for missing in telegram_probe(router=router):
                with self.subTest(router=router, missing=missing):
                    probe = telegram_probe(router=router)
                    del probe[missing]
                    reply = telegram_report(probe)
                    reply["verdict"] = "responsive"
                    code, report = self._run_telegram_report(reply, router=router)
                    self.assertEqual(code, 2)
                    self.assertEqual(report["verdict"], "inconclusive")
                    self.assertTrue(report["error"])

    def test_telegram_rejects_contradictory_success_evidence(self) -> None:
        for router in (True, False):
            cases = [
                ("tcp_connected", value) for value in (False, None, 1, "true")
            ] + [
                ("proxy_accepted", value) for value in ((False, None, 1, "true") if router else (False, True, 0, "null"))
            ] + [
                ("phase", "tcp"), ("phase", "proxy"), ("phase", "unknown"),
                ("error", "timeout"), ("error", ""), ("error", False),
                ("elapsed", -1), ("elapsed", True), ("elapsed", "0.1"),
                ("elapsed", float("nan")), ("elapsed", float("inf")),
                ("path", None), ("path", {}),
                ("path", telegram_probe(router=not router)["path"]),
                ("path", {"kind": "socks5", "proxy": "127.0.0.1:1080", "interface": None}),
                ("path", {**telegram_probe(router=router)["path"], "interface": "wg0"}),
                ("path", {"kind": "socks5" if router else "direct"}),
                ("res_pq", None), ("res_pq", {}),
            ]
            valid_pq = telegram_probe(router=router)["res_pq"]
            for field, value in (("server_nonce", "short"), ("pq", "02"), ("pq", "01"),
                                 ("pq", "xyz"), ("fingerprints", []), ("fingerprints", ["bad"])):
                cases.append(("res_pq", {**valid_pq, field: value}))
            for field, value in cases:
                with self.subTest(router=router, field=field, value=value):
                    reply = telegram_report({**telegram_probe(router=router), field: value})
                    code, report = self._run_telegram_report(reply, router=router)
                    self.assertEqual(code, 2)
                    self.assertEqual(report["verdict"], "inconclusive")

    def test_telegram_valid_success_and_degraded_reports_preserve_evidence(self) -> None:
        for router in (True, False):
            for mixed in (False, True):
                with self.subTest(router=router, mixed=mixed):
                    probes = [telegram_probe(router=router)]
                    if mixed:
                        probes.append(telegram_probe(router=router, success=False, address="149.154.167.51"))
                    reply = telegram_report(*probes)
                    code, report = self._run_telegram_report(reply, router=router, destinations=[p["address"] for p in probes])
                    self.assertEqual(code, 1 if mixed else 0)
                    self.assertEqual(report["verdict"], "degraded" if mixed else "responsive")
                    self.assertEqual(report["probes"], probes)
                    self.assertEqual(report["path"], "router" if router else "direct")

    def test_telegram_valid_failures_at_each_phase_remain_failed(self) -> None:
        for router in (True, False):
            for phase in (("tcp", "proxy", "mtproto") if router else ("tcp", "mtproto")):
                with self.subTest(router=router, phase=phase):
                    probe = telegram_probe(router=router, success=False)
                    probe.update(phase=phase, tcp_connected=phase != "tcp",
                                 proxy_accepted=phase == "mtproto" if router else None)
                    code, report = self._run_telegram_report(telegram_report(probe), router=router)
                    self.assertEqual(code, 1)
                    self.assertEqual(report["verdict"], "failed")
                    self.assertEqual(report["probes"], [probe])
            # The parser may finish just as the total deadline expires.
            probe = telegram_probe(router=router)
            probe.update(protocol_response=False, error="total probe I/O budget exhausted")
            code, report = self._run_telegram_report(telegram_report(probe), router=router)
            self.assertEqual(code, 1)
            self.assertEqual(report["probes"], [probe])

    def test_telegram_rejects_contradictory_failure_evidence(self) -> None:
        for router in (True, False):
            for changes in ({"tcp_connected": False}, {"phase": "tcp"}, {"phase": "proxy"},
                            {"error": None}, {"error": False}, {"proxy_accepted": False}):
                with self.subTest(router=router, changes=changes):
                    probe = {**telegram_probe(router=router, success=False), **changes}
                    code, report = self._run_telegram_report(telegram_report(probe), router=router)
                    self.assertEqual(code, 2)
                    self.assertEqual(report["verdict"], "inconclusive")

    def test_telegram_rejects_wrong_report_identity_time_and_destinations(self) -> None:
        valid = telegram_probe(router=True)
        for field, value in (
            ("application", "other"), ("scope", "other"), ("verdict", "failed"),
            ("generated_at", "invalid"), ("generated_at", datetime.now().isoformat()),
            ("generated_at", (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()),
            ("generated_at", (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()),
            ("probes", []), ("probes", [None]), ("probes", [valid, valid]),
            ("probes", [{**valid, "address": "149.154.167.51"}]),
            ("probes", [{**valid, "port": 80}]),
            ("probes", [{**valid, "protocol_response": 1}]),
        ):
            with self.subTest(field=field, value=value):
                code, report = self._run_telegram_report({**telegram_report(valid), field: value})
                self.assertEqual(code, 2)
                self.assertEqual(report["verdict"], "inconclusive")

    def test_telegram_rejects_invalid_input_before_ssh(self) -> None:
        with patch.object(diagnose, "prepare_remote_session") as prepare:
            for addresses in ([], ["149.154.167.50"] * 9, ["example.com"], ["1.1.1.1;reboot"]):
                with self.subTest(addresses=addresses), self.assertRaises(diagnose.AppError):
                    diagnose.diagnose_telegram_workflow("demo", "all", addresses)
            prepare.assert_not_called()

    def test_telegram_incomplete_collection_returns_two_and_json_error(self) -> None:
        env = topology_env(TOPOLOGY_SINGLE, LOCATION_FOREIGN)
        targets = [target(NODE_GATEWAY, LOCATION_FOREIGN)]
        for reply in ('{}', 'not-json'):
            with tempfile.TemporaryDirectory() as tmp, patch.object(diagnose, "OUT_DIR", Path(tmp)), patch.object(diagnose, "prepare_remote_session", return_value=("demo", Path("unused"), env, {}, targets, {})), patch.object(diagnose, "ssh_capture", return_value=reply):
                self.assertEqual(diagnose.diagnose_telegram_workflow("demo", "all", ["149.154.167.50"]), 2)
                report = json.loads(next(Path(tmp).glob("diagnostics/*/telegram.json")).read_text(encoding="utf-8"))
                self.assertEqual(report["nodes"][NODE_GATEWAY]["verdict"], "inconclusive")

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
                    side_effect=lambda remote, *_args, **_kwargs: json.dumps({"node_id": remote.node_id}),
                ) as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_path_workflow("demo", "all"), 0)
                reports = sorted(out_dir.glob("diagnostics/*/*.json"))
                self.assertEqual([path.name for path in reports], ["exit.json", "gateway.json"])
                self.assertEqual(json.loads(reports[0].read_text(encoding="utf-8")), {"node_id": NODE_EXIT})
                self.assertEqual(json.loads(reports[1].read_text(encoding="utf-8")), {"node_id": NODE_GATEWAY})

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
                patch.object(diagnose, "ssh_capture", return_value='{"node_id": "gateway"}') as ssh_mock,
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
                patch.object(diagnose, "ssh_capture", return_value='{"node_id": "gateway"}') as ssh_mock,
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
                self.assertEqual(diagnose.diagnose_path_workflow("demo", NODE_GATEWAY), 1)
                report = next(out_dir.glob("diagnostics/*/gateway.json"))
                self.assertEqual(
                    json.loads(report.read_text(encoding="utf-8")),
                    {"node_id": NODE_GATEWAY, "diagnose_error": "timeout"},
                )

    def test_diagnose_path_returns_nonzero_and_preserves_other_node_on_collection_failure(self) -> None:
        env = topology_env(TOPOLOGY_DUAL, LOCATION_RU)
        targets = [target(NODE_GATEWAY, LOCATION_RU), target(NODE_EXIT, LOCATION_FOREIGN)]
        for failed_node in (NODE_GATEWAY, NODE_EXIT):
            for error_type in (diagnose.AppError, OSError):
                with self.subTest(failed_node=failed_node, error_type=error_type), tempfile.TemporaryDirectory() as tmp:
                    out_dir = Path(tmp) / "out"

                    def collect(remote, *_args, **_kwargs):
                        if remote.node_id == failed_node:
                            raise error_type("collection failed")
                        return json.dumps({"node_id": remote.node_id, "verdict": "verified"})

                    with (
                        patch.object(diagnose, "OUT_DIR", out_dir),
                        patch.object(
                            diagnose,
                            "prepare_remote_session",
                            return_value=("demo", Path("deployments/demo.env"), env, {}, targets, {}),
                        ),
                        patch.object(diagnose, "ssh_capture", side_effect=collect) as ssh_mock,
                    ):
                        self.assertEqual(diagnose.diagnose_path_workflow("demo", "all"), 1)
                    reports = {
                        path.stem: json.loads(path.read_text(encoding="utf-8"))
                        for path in out_dir.glob("diagnostics/*/*.json")
                    }
                    self.assertEqual(set(reports), {NODE_GATEWAY, NODE_EXIT})
                    self.assertEqual(reports[failed_node], {"node_id": failed_node, "diagnose_error": "collection failed"})
                    other_node = NODE_EXIT if failed_node == NODE_GATEWAY else NODE_GATEWAY
                    self.assertEqual(reports[other_node], {"node_id": other_node, "verdict": "verified"})
                    self.assertEqual(ssh_mock.call_count, 2)

    def test_diagnose_path_records_invalid_agent_json_as_collection_failure(self) -> None:
        env = topology_env(TOPOLOGY_SINGLE, LOCATION_RU)
        gateway = target(NODE_GATEWAY, LOCATION_RU)
        for raw_report in ("not json", "[]", "null"):
            with self.subTest(raw_report=raw_report), tempfile.TemporaryDirectory() as tmp:
                out_dir = Path(tmp) / "out"
                with (
                    patch.object(diagnose, "OUT_DIR", out_dir),
                    patch.object(
                        diagnose,
                        "prepare_remote_session",
                        return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {}),
                    ),
                    patch.object(diagnose, "ssh_capture", return_value=raw_report),
                ):
                    self.assertEqual(diagnose.diagnose_path_workflow("demo", "all"), 1)
                report = next(out_dir.glob("diagnostics/*/gateway.json"))
                payload = json.loads(report.read_text(encoding="utf-8"))
                self.assertEqual(payload["node_id"], NODE_GATEWAY)
                self.assertTrue(payload["diagnose_error"])

    def test_diagnose_client_log_reports_front_failure_and_self_tunnel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "client.log"
            log_path.write_text(
                "\n".join(
                    [
                        "connection: open connection to 149.154.175.100:443 using outbound/vless[proxy]: dial tcp 94.232.248.35:443: i/o timeout",
                        "dns: exchange failed for plugins.example.com. IN A: context deadline exceeded",
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
        self.assertIn("Windows direct server route helper", output)

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
