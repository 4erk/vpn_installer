from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from vpn_installer import interserver_transport, server_runtime, server_transport
from vpn_installer.config import generate_default_env
from vpn_installer.render import render_gateway_singbox, server_agent_artifacts


from tests.server_agent_fixtures import AgentFixtures


class ServerTransportTests(AgentFixtures, unittest.TestCase):
    def test_standalone_owners_use_stdlib_and_canonical_transport_policy(self) -> None:
        env = generate_default_env("demo")
        env.update(GATEWAY_PUBLIC_IP="203.0.113.10", EXIT_PUBLIC_IP="198.51.100.20")
        config = json.loads(render_gateway_singbox(env))
        script = """
import builtins, json, sys
sys.path.insert(0, sys.argv[1])
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name.split('.')[0] in {'vpn_installer', 'server_agent', 'cryptography', 'runtime_deps'}:
        raise AssertionError('unexpected dependency: ' + name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
import server_transport, server_lifecycle, server_runtime, interserver_transport
assert server_transport.policy is interserver_transport
assert server_transport.prove_wireguard_overlay.__module__ == 'server_transport'
assert server_lifecycle.health.__module__ == 'server_lifecycle'
assert server_transport.runtime is server_runtime
assert server_lifecycle.runtime is server_runtime
env, config = json.loads(sys.argv[2])
assert server_transport.policy.transport_topology_configured(config, env)
assert server_transport.current_transport_state({'schema_version': 0}) == {}
print('ok')
"""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            for name, content in server_agent_artifacts(interserver=True).items():
                (target / name).write_text(content, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", script, str(target), json.dumps([env, config])],
                text=True, capture_output=True, check=False, timeout=10,
            )
            self.assertFalse((target / "__pycache__").exists())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ok")

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
            patch.object(server_runtime, "read_json", return_value=config),
            patch.object(server_runtime, "run", return_value=sockets),
            patch.object(server_transport, "transport_selection_snapshot", return_value=selection),
            patch.object(server_transport, "transport_state_snapshot", return_value={"state": "healthy", "fresh": True}),
        ):
            transport = server_transport.interserver_transport_snapshot(self.gateway_contract(), env)

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
            patch.object(server_transport, "wireguard_overlay_relay", return_value=relay),
            patch.object(server_transport, "transport_selector_selection", return_value=selector),
        ):
            selection = server_transport.transport_selection_snapshot(config, env, "127.0.0.1:19090")

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
            patch.object(server_transport, "wireguard_overlay_relay", return_value=relay),
            patch.object(server_transport, "transport_selector_selection", return_value=selector),
        ):
            selection = server_transport.transport_selection_snapshot(config, env, "127.0.0.1:19090")

        self.assertFalse(selection["available"])
        self.assertFalse(selection["candidates"]["interserver-underlay-hy2"]["configured"])
        self.assertEqual(selection["reason"], "transport topology is incomplete")

    def test_transport_cycle_probes_alternate_only_after_overlay_failure(self) -> None:
        failed = {"checked": True, "ok": False, "attempts": 1, "error": "timeout"}
        healthy = {"checked": True, "ok": True, "attempts": 1, "delay_ms": 50}
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with (
            patch.object(server_transport, "transport_overlay_path_probe", return_value=failed) as overlay_probe,
            patch.object(interserver_transport, "transport_candidate_probe", return_value=healthy) as probe,
        ):
            result = server_transport.collect_transport_probes(
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
            patch.object(server_transport, "transport_overlay_path_probe", return_value=failed),
            patch.object(interserver_transport, "transport_candidate_probe", return_value=healthy) as probe,
        ):
            result = server_transport.collect_transport_probes(
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

        probe.assert_called_once_with("interserver-underlay-hy2")
        self.assertTrue(result["interserver-underlay-hy2"]["checked"])

        with (
            patch.object(server_transport, "transport_overlay_path_probe", return_value=healthy),
            patch.object(interserver_transport, "transport_candidate_probe", return_value=healthy) as probe,
        ):
            result = server_transport.collect_transport_probes(
                "interserver-underlay-wg",
                {"preferred_probe_at": "2026-08-07T11:59:55+00:00", "quality_probe_at": "2026-08-07T11:59:55+00:00"},
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        probe.assert_not_called()
        self.assertFalse(result["interserver-underlay-hy2"]["checked"])

        with (
            patch.object(server_transport, "transport_overlay_path_probe", return_value=healthy),
            patch.object(interserver_transport, "transport_candidate_probe", return_value=healthy) as probe,
        ):
            server_transport.collect_transport_probes(
                "interserver-underlay-hy2",
                {"preferred_probe_at": "2026-08-07T11:59:29+00:00", "quality_probe_at": "2026-08-07T11:59:55+00:00"},
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        probe.assert_called_once_with(
            "interserver-underlay-wg",
            timeout_ms=interserver_transport.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
            attempts=interserver_transport.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
        )

    def test_transport_reconcile_does_not_switch_during_install_transaction(self) -> None:
        previous = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "selected": "interserver-underlay-wg",
            "state": "healthy",
        }
        with (
            patch.object(server_runtime, "acquire_install_read_lock", return_value=None),
            patch.object(server_runtime, "read_json", return_value=previous),
            patch.object(server_transport, "collect_transport_probes") as probes,
            patch.object(server_transport, "select_transport") as select,
            patch.object(server_runtime, "write_json_atomic"),
        ):
            result = server_transport.reconcile_interserver_transport()

        self.assertEqual(result["state"], "maintenance")
        self.assertEqual(result["selected"], "interserver-underlay-wg")
        probes.assert_not_called()
        select.assert_not_called()

    def test_transport_candidate_probe_uses_path_specific_local_proxy(self) -> None:
        with patch.object(interserver_transport, "_socks_udp_dns_probe") as probe:
            result = interserver_transport.transport_candidate_probe("interserver-underlay-hy2")

        self.assertTrue(result["ok"])
        self.assertEqual(result["scope"], "raw-underlay-udp")
        self.assertEqual(result["target"], "10.75.0.2:1053")
        self.assertTrue(result["health_confirmed"])
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(probe.call_args.args, (19094, "10.75.0.2", 1053, 1.2))
        self.assertIn("deadline", probe.call_args.kwargs)

    def test_transport_candidate_quality_probe_reports_partial_loss(self) -> None:
        with patch.object(
            interserver_transport,
            "_socks_udp_dns_probe",
            side_effect=[None, TimeoutError("timed out"), None, None],
        ) as probe:
            result = interserver_transport.transport_candidate_probe(
                "interserver-underlay-wg",
                timeout_ms=1200,
                attempts=4,
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["health_confirmed"])
        self.assertFalse(result["quality_ok"])
        self.assertEqual(result["packet_loss_pct"], 25.0)
        self.assertEqual(probe.call_count, 4)
        self.assertEqual(probe.call_args.args, (19093, "10.75.0.2", 1053, 0.3))

    def test_overlay_dns_probe_retries_one_lost_exchange_without_failing_the_path(self) -> None:
        def exchange(*_args, evidence, **_kwargs):
            if evidence["attempt"] == 1:
                raise TimeoutError("timed out")
            evidence.update(transmitted=1, received=1)

        with patch.object(
            interserver_transport,
            "_bound_tcp_dns_probe",
            side_effect=exchange,
        ) as probe:
            result = interserver_transport.transport_overlay_dns_probe("wg0", "10.74.0.2")

        self.assertTrue(result["ok"])
        self.assertTrue(result["health_confirmed"])
        self.assertFalse(result["failure_confirmed"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(probe.call_args.args, ("wg0", "10.74.0.2", 1053, 0.6))
        self.assertEqual(set(probe.call_args.kwargs), {"deadline", "evidence"})
        self.assertEqual((result["transmitted"], result["received"], result["valid_responses"]), (1, 1, 1))

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

        self.assertEqual((result["transmitted"], result["received"], result["valid_responses"]), (0, 0, 0))

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
            result = interserver_transport.transport_candidate_probe("interserver-underlay-hy2")

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
            result = interserver_transport.transport_candidate_probe("interserver-underlay-hy2")

        self.assertEqual(control.sendall.call_args_list[0].args[0], b"\x05\x01\x00")
        self.assertTrue(control.sendall.call_args_list[1].args[0].startswith(b"\x05\x03\x00\x01"))
        self.assertEqual(datagram.sendto.call_args.args[1], ("127.0.0.1", 9999))
        self.assertIn(b"\x09localhost\x00", datagram.sendto.call_args.args[0])
        self.assertEqual((result["transmitted"], result["received"], result["valid_responses"]), (1, 1, 1))
        self.assertEqual(result["attempt_results"][0]["io_phase"], "complete")

    def test_candidate_late_response_is_not_healthy_and_stops_attempts(self) -> None:
        clock = [10.0]

        def late(*_args, evidence, **_kwargs):
            evidence.update(transmitted=1, received=1)
            clock[0] += 4.5

        with patch.object(interserver_transport.time, "monotonic", side_effect=lambda: clock[0]), patch.object(
            interserver_transport, "_socks_udp_dns_probe", side_effect=late
        ) as exchange:
            result = interserver_transport.transport_candidate_probe("interserver-underlay-hy2", attempts=4)
        self.assertFalse(result["ok"])
        self.assertFalse(result["health_confirmed"])
        self.assertEqual(result["elapsed_ms"], 4500)
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(result["valid_responses"], 0)
        exchange.assert_called_once()

    def test_socks_fragmented_negotiation_shares_one_deadline(self) -> None:
        clock = [10.0]
        control, datagram = MagicMock(), MagicMock()
        control.__enter__.return_value = control
        datagram.__enter__.return_value = datagram
        datagram.getsockname.return_value = ("127.0.0.1", 54321)
        fragments = iter((b"\x05", b"\x00", b"\x05", b"\x00", b"\x00", b"\x01"))

        def receive(_size):
            clock[0] += 0.25
            return next(fragments)

        control.recv.side_effect = receive
        with (
            patch.object(interserver_transport.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(interserver_transport.socket, "socket", return_value=datagram),
            patch.object(interserver_transport.socket, "create_connection", return_value=control),
        ):
            result = interserver_transport.transport_candidate_probe("interserver-underlay-hy2")
        self.assertFalse(result["ok"])
        self.assertEqual(result["attempt_results"][0]["io_phase"], "socks_associate")
        self.assertEqual((result["transmitted"], result["received"]), (0, 0))
        datagram.sendto.assert_not_called()
        timeouts = [call.args[0] for call in control.settimeout.call_args_list]
        self.assertEqual(timeouts, sorted(timeouts, reverse=True))

    def test_candidate_counts_packets_not_configured_attempts(self) -> None:
        count = [0]

        def exchange(*_args, evidence, **_kwargs):
            count[0] += 1
            if count[0] == 1:
                raise OSError("SOCKS5 proxy rejected probing")
            evidence["transmitted"] = 1
            if count[0] == 2:
                raise TimeoutError("timed out")
            evidence["received"] = 1

        with patch.object(interserver_transport, "_socks_udp_dns_probe", side_effect=exchange):
            result = interserver_transport.transport_candidate_probe("interserver-underlay-wg", attempts=3)
        self.assertEqual(result["attempts"], 3)
        self.assertEqual((result["transmitted"], result["received"], result["valid_responses"]), (2, 1, 1))
        self.assertFalse(result["quality_ok"])

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
        evidence = {}
        with patch.object(interserver_transport.socket, "socket", return_value=connection):
            interserver_transport._bound_tcp_dns_probe("wg0", "10.74.0.2", 1053, 0.6, evidence=evidence)
        self.assertEqual(evidence, {"transmitted": 1, "received": 1})

        connection.connect.assert_called_once_with(("10.74.0.2", 1053))
        framed_query = connection.sendall.call_args.args[0]
        self.assertEqual(int.from_bytes(framed_query[:2], "big"), len(dns_query))
        self.assertEqual(framed_query[2:], dns_query)

    def test_overlay_tcp_counts_only_completed_send_and_full_body_receive(self) -> None:
        for phase, expected in (("connect", (0, 0, 0)), ("send", (0, 0, 0)),
                                ("receive_body", (1, 0, 0)), ("validate", (1, 1, 0))):
            with self.subTest(phase=phase):
                connection = MagicMock()
                connection.__enter__.return_value = connection
                body = b"bad DNS!"
                connection.recv.side_effect = [len(body).to_bytes(2, "big"), body]
                if phase == "connect":
                    connection.connect.side_effect = ConnectionRefusedError("connection refused")
                elif phase == "send":
                    connection.sendall.side_effect = OSError("send failed")
                elif phase == "receive_body":
                    connection.recv.side_effect = [len(body).to_bytes(2, "big"), body[:3], b""]
                with patch.object(interserver_transport.socket, "socket", return_value=connection):
                    result = interserver_transport.transport_overlay_dns_probe("wg0", "10.74.0.2", attempts=1)
                self.assertFalse(result["ok"])
                self.assertEqual(result["attempts"], 1)
                self.assertEqual(result["attempt_results"][0]["io_phase"], phase)
                self.assertEqual((result["transmitted"], result["received"], result["valid_responses"]), expected)
                self.assertEqual(result["attempt_results"][0]["transmitted"], expected[0])
                self.assertEqual(result["attempt_results"][0]["received"], expected[1])

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
        with patch.object(interserver_transport, "transport_overlay_dns_probe", return_value=healthy) as probe:
            result = server_transport.transport_overlay_path_probe(env)

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
        with patch.object(interserver_transport, "transport_overlay_dns_probe", return_value=failed):
            result = server_transport.transport_overlay_path_probe(env)

        self.assertFalse(result["ok"])
        self.assertTrue(result["failure_confirmed"])

    def test_transport_probe_schedules_quality_and_honors_preferred_retry(self) -> None:
        self.assertTrue(server_transport.overlay_quality_probe_due({}, "2026-08-07T12:00:00+00:00"))
        self.assertFalse(
            server_transport.overlay_quality_probe_due(
                {"quality_probe_at": "2026-08-07T11:59:55+00:00", "state": "healthy"},
                "2026-08-07T12:00:00+00:00",
            )
        )
        self.assertFalse(
            server_transport.overlay_quality_probe_due(
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
        self.assertFalse(server_transport.preferred_transport_probe_due(retry, "2026-08-07T12:00:59+00:00"))
        self.assertTrue(server_transport.preferred_transport_probe_due(retry, "2026-08-07T12:01:00+00:00"))

    def test_transport_cycle_runs_quality_only_after_fast_liveness_succeeds(self) -> None:
        liveness = {"checked": True, "ok": True, "attempts": 1, "scope": "overlay-dns", "health_confirmed": True}
        quality = {
            "checked": True,
            "ok": True,
            "attempts": 8,
            "scope": "raw-underlay-udp",
            "quality_checked": True,
            "quality_ok": True,
            "packet_loss_pct": 0.0,
        }
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        with patch.object(
            server_transport,
            "transport_overlay_path_probe",
            return_value=liveness,
        ) as probe, patch.object(interserver_transport, "transport_candidate_probe", return_value=quality) as candidate:
            result = server_transport.collect_transport_probes(
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
        probe.assert_called_once_with(env)
        candidate.assert_called_once_with("interserver-underlay-wg", timeout_ms=2400, attempts=8)
        self.assertEqual(selected["quality_probe"], quality)

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
        with patch.object(server_transport, "transport_overlay_path_probe", return_value=liveness), patch.object(
            interserver_transport, "transport_candidate_probe", side_effect=(quality, alternate_probe)
        ) as alternate:
            result = server_transport.collect_transport_probes(
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
        self.assertEqual(alternate.call_count, 2)
        self.assertEqual(alternate.call_args_list[0].kwargs, alternate.call_args_list[1].kwargs)
        alternate.assert_called_with(
            "interserver-underlay-hy2",
            timeout_ms=interserver_transport.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
            attempts=interserver_transport.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
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
        with patch.object(server_transport, "transport_overlay_path_probe", return_value=liveness), patch.object(
            interserver_transport, "transport_candidate_probe", side_effect=(quality, alternate_probe)
        ) as alternate:
            result = server_transport.collect_transport_probes(
                "interserver-underlay-hy2",
                previous,
                env=env,
                observed_at="2026-08-07T12:00:00+00:00",
            )

        self.assertFalse(result["interserver-underlay-hy2"]["quality_ok"])
        self.assertEqual(result["interserver-underlay-wg"], alternate_probe)
        self.assertEqual(alternate.call_count, 2)
        alternate.assert_called_with(
            "interserver-underlay-wg",
            timeout_ms=interserver_transport.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
            attempts=interserver_transport.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
        )

    def test_live_quality_failure_does_not_probe_alternate_during_switch_backoff(self) -> None:
        selected, target = interserver_transport.TRANSPORT_CANDIDATE_TAGS
        with patch.object(server_transport, "transport_overlay_path_probe", return_value={"checked": True, "ok": True}), patch.object(
            interserver_transport, "transport_candidate_probe",
            return_value={"checked": True, "ok": False, "quality_checked": True, "quality_ok": False},
        ) as probe:
            result = server_transport.collect_transport_probes(selected, {
                "switch_backoff": {"target": target, "retry_at": "2026-09-05T12:05:00+00:00"},
            }, env={}, observed_at="2026-09-05T12:00:00+00:00")
        probe.assert_called_once_with(selected, timeout_ms=2400, attempts=8)
        self.assertTrue(result[selected]["ok"])
        self.assertFalse(result[selected]["quality_ok"])
        self.assertFalse(result[target]["checked"])

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
        with patch.object(server_transport, "transport_overlay_path_probe", return_value=liveness) as probe:
            result = server_transport.collect_transport_probes(
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
        with patch.object(server_transport, "clash_api_json", side_effect=[payload, {}]) as api:
            closed = server_transport.reset_transport_relay("127.0.0.1:19090")

        self.assertEqual(closed, 1)
        self.assertEqual(api.call_args_list[1].args[1], "/connections/relay-id")
        self.assertEqual(api.call_args_list[1].kwargs["method"], "DELETE")

    def test_select_transport_changes_only_the_underlay_selector(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_PUBLIC_KEY": "peer-key", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        selections = [
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-hy2"},
            {"available": True, "selected": "interserver-underlay-hy2"},
        ]
        with (
            patch.object(server_transport, "transport_selector_selection", side_effect=selections),
            patch.object(server_transport, "clash_api_json") as api,
            patch.object(server_transport, "reset_transport_relay", return_value=1) as reset,
            patch.object(server_transport, "prove_wireguard_overlay", return_value={"ok": True, "probe": {"ok": True}}) as proof,
        ):
            result = server_transport.select_transport(env, "127.0.0.1:19090", "interserver-underlay-hy2")

        self.assertTrue(result["ok"])
        self.assertTrue(result["changed"])
        self.assertEqual(result["activation_proof"]["path"], "interserver-underlay-hy2")
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
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-wg"},
        ]
        with (
            patch.object(server_transport, "transport_selector_selection", side_effect=selections),
            patch.object(server_transport, "clash_api_json") as api,
            patch.object(server_transport, "reset_transport_relay", return_value=1) as reset,
            patch.object(server_transport, "prove_wireguard_overlay", return_value={"ok": True, "probe": {"ok": True}}) as proof,
        ):
            with self.assertRaisesRegex(RuntimeError, "previous selector path restored and verified"):
                server_transport.select_transport(env, "127.0.0.1:19090", "interserver-underlay-hy2")

        self.assertEqual([call.kwargs["payload"] for call in api.call_args_list], [
            {"name": "interserver-underlay-hy2"},
            {"name": "interserver-underlay-wg"},
        ])
        reset.assert_called_once_with("127.0.0.1:19090")
        proof.assert_called_once_with(env)

    def test_transport_switch_failure_uses_bounded_backoff(self) -> None:
        first = server_transport.next_transport_switch_failure(
            {},
            "interserver-underlay-hy2",
            "activation failed",
            "2026-08-09T12:00:00+00:00",
        )
        self.assertEqual(first["attempts"], 1)
        self.assertEqual(first["retry_at"], "2026-08-09T12:00:30+00:00")
        self.assertIsNotNone(
            server_transport.transport_switch_backoff_active(
                {"switch_backoff": first},
                "interserver-underlay-hy2",
                "2026-08-09T12:00:29+00:00",
            )
        )
        self.assertIsNone(
            server_transport.transport_switch_backoff_active(
                {"switch_backoff": first},
                "interserver-underlay-hy2",
                "2026-08-09T12:00:30+00:00",
            )
        )
        second = server_transport.next_transport_switch_failure(
            {"switch_backoff": first},
            "interserver-underlay-hy2",
            "activation still failed",
            "2026-08-09T12:00:30+00:00",
        )
        self.assertEqual(second["attempts"], 2)
        self.assertEqual(second["retry_at"], "2026-08-09T12:01:30+00:00")

    def run_transport_cycles(
        self,
        seconds: list[int],
        *,
        fail_switch: bool = False,
        selected: str = "interserver-underlay-wg",
        previous: dict[str, object] | None = None,
        liveness_ok: bool = True,
        unavailable_seconds: tuple[int, ...] = (),
    ) -> tuple[list[dict[str, object]], Mock, Mock]:
        config = {"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}}
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        state = dict(previous or {})
        selector = {"available": True, "selected": selected}
        now = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        live = {"checked": True, "ok": True, "health_confirmed": True, "scope": "overlay-dns"}
        quality_sample = {
            "checked": True, "ok": False, "quality_checked": True,
            "packet_loss_pct": 5.0, "error": "overlay packet loss 5%",
        }
        candidate = {
            "checked": True, "ok": True, "health_confirmed": True,
            "quality_checked": True, "quality_ok": True, "packet_loss_pct": 0.0,
        }
        selection_seconds = iter(seconds)

        def selection_snapshot(*_args: object) -> dict[str, object]:
            if next(selection_seconds) in unavailable_seconds:
                return {"available": False, "selected": "", "reason": "selector API timed out"}
            return dict(selector)

        def read(path: Path, _default: object) -> dict[str, object]:
            return config if path == server_runtime.SINGBOX_CONFIG_PATH else dict(state)

        def write(_path: Path, payload: dict[str, object]) -> None:
            state.clear()
            state.update(payload)

        def overlay(_env: dict[str, str]) -> dict[str, object]:
            return dict(live) if liveness_ok else {
                "checked": True, "ok": False, "failure_confirmed": True, "error": "timed out",
            }

        def api(
            _controller: str, _path: str, *, method: str = "GET",
            payload: dict[str, str] | None = None, **_kwargs: object,
        ) -> dict[str, object]:
            if method == "PUT":
                selector["selected"] = payload["name"]
            return {"connections": []}

        with (
            patch.object(server_runtime, "TRANSPORT_LOCK_PATH", MagicMock()),
            patch.object(server_runtime.fcntl, "flock"),
            patch.object(server_runtime, "read_json", side_effect=read),
            patch.object(server_runtime, "write_json_atomic", side_effect=write),
            patch.object(server_runtime, "parse_env", return_value=env),
            patch.object(interserver_transport, "transport_topology_configured", return_value=True),
            patch.object(server_transport, "transport_selection_snapshot", side_effect=selection_snapshot),
            patch.object(server_transport, "transport_selector_selection", side_effect=lambda *_args: dict(selector)),
            patch.object(server_transport, "transport_overlay_path_probe", side_effect=overlay),
            patch.object(interserver_transport, "transport_candidate_probe", side_effect=lambda tag, **kw: dict(quality_sample if tag == selector["selected"] else candidate)),
            patch.object(interserver_transport, "transport_overlay_dns_probe", return_value=live) as proof,
            patch.object(server_transport, "clash_api_json", side_effect=api),
            patch.object(server_runtime, "utc_now", side_effect=[(now + timedelta(seconds=s)).isoformat() for s in seconds]),
            patch.object(server_runtime, "run", side_effect=AssertionError("unexpected subprocess")),
            patch.object(
                server_transport, "select_transport", wraps=server_transport.select_transport,
                side_effect=server_transport.TransportSwitchError("activation failed", {
                    "selector_before": selected, "selector_after": selected, "rollback_verified": True,
                    "rollback_proof": {"probe": dict(live)},
                }) if fail_switch else None,
            ) as select,
        ):
            trace = [server_transport._reconcile_interserver_transport_unlocked() for _ in seconds]
        return trace, select, proof

    def test_observation_error_preserves_switch_deadline_and_failure_attempts_on_live_path(self) -> None:
        failure = server_transport.next_transport_switch_failure(
            {}, "interserver-underlay-hy2", "activation failed", "2026-09-05T12:00:00+00:00",
        )
        previous = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": "2026-09-05T12:00:00+00:00",
            "selected": "interserver-underlay-wg", "state": "degraded",
            "switch_backoff": failure, "last_switch_failure": failure,
            "last_transition": {"cycle_id": "failed-activation", "ok": False},
            "probes": {"interserver-underlay-wg": {"checked": True, "ok": True}},
            "overlay_probe": {"checked": True, "ok": True},
            "quality_failure": {"path": "interserver-underlay-wg", "confirmations": 2},
        }
        original = deepcopy(previous)
        trace, select, proof = self.run_transport_cycles(
            [2, 4, 28, 30, 44, 60, 62], previous=previous, liveness_ok=True,
            fail_switch=True, unavailable_seconds=(2,),
        )

        self.assertEqual(previous, original)
        self.assertEqual(trace[0]["selected"], "")
        self.assertFalse(trace[0]["would_switch"])
        for key in ("probes", "overlay_probe", "quality_failure", "cycle_id"):
            self.assertNotIn(key, trace[0])
        for state in trace[:3]:
            self.assertEqual(state["switch_backoff"], failure)
            self.assertEqual(state["last_switch_failure"], failure)
            self.assertEqual(state["last_transition"], original["last_transition"])
        self.assertFalse(trace[3]["would_switch"])
        self.assertFalse(trace[4]["would_switch"])
        self.assertEqual(trace[5]["switch_backoff"]["attempts"], 2)
        self.assertEqual(trace[5]["switch_backoff"]["failed_at"], "2026-09-05T12:01:00+00:00")
        self.assertEqual(trace[5]["switch_backoff"]["retry_at"], "2026-09-05T12:02:00+00:00")
        self.assertEqual(trace[6]["switch_backoff"], trace[5]["switch_backoff"])
        select.assert_called_once()
        proof.assert_not_called()

    def test_cached_fallback_quality_does_not_repeat_preferred_probe_every_cycle(self) -> None:
        previous = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "selected": "interserver-underlay-hy2", "state": "healthy",
            "preferred_probe_at": "2026-09-05T11:59:30+00:00",
        }
        original = deepcopy(previous)
        trace, select, proof = self.run_transport_cycles(
            [0, 2, 4, 6, 14], selected="interserver-underlay-hy2", previous=previous,
        )

        self.assertEqual(previous, original)
        self.assertEqual(
            [state["probes"]["interserver-underlay-wg"]["checked"] for state in trace],
            [True, False, False, False, False],
        )
        for state in trace:
            self.assertEqual(state["preferred_probe_at"], "2026-09-05T12:00:00+00:00")
            self.assertEqual(state["quality_failure"]["confirmations"], 1)
        self.assertFalse(server_transport.preferred_transport_probe_due(trace[-1], "2026-09-05T12:00:29+00:00"))
        self.assertTrue(server_transport.preferred_transport_probe_due(trace[-1], "2026-09-05T12:00:30+00:00"))
        select.assert_not_called()
        proof.assert_not_called()

    def test_config_and_watcher_errors_retain_history_without_refreshing_evidence(self) -> None:
        failure = server_transport.next_transport_switch_failure(
            {}, "interserver-underlay-hy2", "activation failed", "2026-09-05T12:00:00+00:00",
        )
        previous = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": "2026-09-05T12:00:00+00:00", "selected": "interserver-underlay-wg",
            "cycle_id": "before-error", "changed": True,
            "switch_backoff": failure, "last_switch_failure": failure,
            "last_transition": {"cycle_id": "before-error", "finished_at": "2026-09-05T12:00:00+00:00"},
            "preferred_retry": {"path": "interserver-underlay-wg", "retry_at": "2026-09-05T12:01:00+00:00"},
            "overlay_probe": {"checked": True, "ok": True},
            "preferred_recovery": {"confirmations": 11},
        }
        original = deepcopy(previous)
        for source in ("config", "watcher"):
            with (
                self.subTest(source=source),
                patch.object(server_runtime, "TRANSPORT_LOCK_PATH", MagicMock()),
                patch.object(server_runtime.fcntl, "flock"),
                patch.object(server_runtime, "read_json", side_effect=lambda path, default: {} if path == server_runtime.SINGBOX_CONFIG_PATH else deepcopy(previous)),
                patch.object(server_runtime, "write_json_atomic") as write,
                patch.object(server_runtime, "parse_env", return_value={}),
                patch.object(server_runtime, "utc_now", return_value="2026-09-05T12:00:02+00:00"),
                patch.object(server_runtime, "run", side_effect=AssertionError("unexpected subprocess")),
                patch.object(interserver_transport, "transport_topology_configured", return_value=False),
                patch.object(server_transport, "reconcile_interserver_transport", side_effect=RuntimeError("collector failed")),
                patch.object(server_transport.time, "sleep", side_effect=KeyboardInterrupt),
                patch("builtins.print") as output,
            ):
                if source == "config":
                    server_transport._reconcile_interserver_transport_unlocked()
                else:
                    with self.assertRaises(KeyboardInterrupt):
                        server_transport.watch_interserver_transport()
                    self.assertEqual(json.loads(output.call_args.args[0]), write.call_args.args[1])
                write.assert_called_once()
                payload = write.call_args.args[1]
                self.assertEqual(payload["updated_at"], "2026-09-05T12:00:02+00:00")
                self.assertEqual(payload["state"], "failed")
                self.assertEqual(payload["selected"], "")
                self.assertFalse(payload["changed"])
                for key in ("last_transition", "switch_backoff", "last_switch_failure", "preferred_retry"):
                    self.assertEqual(payload[key], original[key])
                for key in ("cycle_id", "overlay_probe", "preferred_recovery"):
                    self.assertNotIn(key, payload)
                self.assertEqual(previous, original)

    def test_quality_switches_do_not_ping_pong_after_successful_dns_proof(self) -> None:
        seconds = list(range(0, 85, 2))
        trace, select, proof = self.run_transport_cycles(seconds)

        switches = [second for second, state in zip(seconds, trace) if state.get("changed")]
        self.assertEqual(switches, [16, 80])
        self.assertEqual(select.call_count, 2)
        self.assertEqual(proof.call_count, 2)
        self.assertTrue(all(state["overlay_probe"]["ok"] for state in trace))
        after_switch = trace[seconds.index(18)]
        self.assertNotIn("last_quality_probe", after_switch)
        self.assertNotIn("quality_failure", after_switch)
        self.assertFalse(after_switch["overlay_probe"].get("quality_sampled", False))

    def test_failed_quality_switch_keeps_retry_and_history_across_healthy_cycles(self) -> None:
        trace, select, _proof = self.run_transport_cycles([0, 16, 18, 32, 48, 64], fail_switch=True)

        first_failure = trace[1]["switch_backoff"]
        self.assertEqual(first_failure["retry_at"], "2026-09-05T12:00:46+00:00")
        for state in trace[2:4]:
            self.assertTrue(state["overlay_probe"]["ok"])
            self.assertEqual(state["switch_backoff"], first_failure)
            self.assertEqual(state["last_switch_failure"], first_failure)
        self.assertNotIn("switch_backoff", trace[4])
        self.assertEqual(trace[4]["last_switch_failure"], first_failure)
        self.assertEqual(select.call_count, 2)
        self.assertEqual(trace[5]["switch_backoff"]["attempts"], 2)
        self.assertEqual(trace[5]["switch_backoff"]["retry_at"], "2026-09-05T12:02:04+00:00")

    def test_hard_liveness_failure_bypasses_soft_quality_and_preferred_retry(self) -> None:
        trace, select, proof = self.run_transport_cycles(
            [0, 2], selected="interserver-underlay-hy2", liveness_ok=False,
            previous={
                "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
                "selected": "interserver-underlay-hy2",
                "preferred_retry": {
                    "path": "interserver-underlay-wg", "retry_at": "2026-09-05T12:05:00+00:00",
                },
            },
        )
        self.assertFalse(trace[0].get("changed", False))
        self.assertTrue(trace[1]["changed"])
        self.assertTrue(trace[1]["hard_failure_evidence"])
        self.assertEqual(trace[1]["selected"], "interserver-underlay-wg")
        select.assert_called_once()
        proof.assert_called_once()

    def test_dead_path_bypasses_switch_backoff_only_after_two_fresh_cycles(self) -> None:
        for selected in interserver_transport.TRANSPORT_CANDIDATE_TAGS:
            target = next(tag for tag in interserver_transport.TRANSPORT_CANDIDATE_TAGS if tag != selected)
            failure = {"target": target, "attempts": 5, "failed_at": "2026-09-05T12:00:00+00:00",
                       "retry_at": "2026-09-05T12:05:00+00:00"}
            with self.subTest(selected=selected):
                trace, select, proof = self.run_transport_cycles([0, 2], selected=selected, liveness_ok=False,
                    previous={"schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
                              "selected": selected, "switch_backoff": failure})
                self.assertFalse(trace[0].get("changed", False))
                self.assertTrue(trace[0]["probes"][target]["checked"])
                self.assertEqual(trace[0]["failure"]["confirmations"], 1)
                self.assertTrue(trace[1]["changed"])
                self.assertEqual(trace[1]["selected"], target)
                self.assertTrue(trace[1]["last_transition"]["activation_proof"]["ok"])
                self.assertEqual(trace[1]["last_transition"]["decision_evidence"]["failure"]["confirmations"], 2)
                self.assertNotIn("switch_backoff", trace[1])
                select.assert_called_once()
                proof.assert_called_once()

    def test_failed_hard_switch_requires_two_new_cycles_after_rollback(self) -> None:
        trace, select, proof = self.run_transport_cycles([0, 2, 4, 6], liveness_ok=False, fail_switch=True)
        self.assertEqual([state["state"] for state in trace], ["suspect", "degraded", "suspect", "degraded"])
        self.assertEqual(trace[2]["failure"]["confirmations"], 1)
        self.assertEqual(trace[1]["switch_backoff"]["attempts"], 1)
        self.assertEqual(trace[3]["switch_backoff"]["attempts"], 2)
        self.assertTrue(trace[3]["last_transition"]["rollback_verified"])
        self.assertEqual(select.call_count, 2)
        proof.assert_not_called()

    def test_successful_overlay_proof_clears_target_switch_failure_history(self) -> None:
        failure = server_transport.next_transport_switch_failure(
            {}, "interserver-underlay-hy2", "proof failed", "2026-09-05T11:59:00+00:00",
        )
        trace, select, proof = self.run_transport_cycles([0, 16, 18], previous={
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "selected": "interserver-underlay-wg", "last_switch_failure": failure,
        })
        self.assertEqual(trace[0]["last_switch_failure"], failure)
        self.assertTrue(trace[1]["changed"])
        for state in trace[1:]:
            self.assertNotIn("switch_backoff", state)
            self.assertNotIn("last_switch_failure", state)
        select.assert_called_once()
        proof.assert_called_once()

    def test_reconcile_checks_retry_even_for_a_healthy_path_recommendation(self) -> None:
        failure = server_transport.next_transport_switch_failure(
            {}, "interserver-underlay-wg", "proof failed", "2026-09-05T12:00:00+00:00",
        )
        evaluated = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "selected": "interserver-underlay-hy2", "recommended": "interserver-underlay-wg",
            "would_switch": True, "state": "recovering", "reason": "preferred recovery confirmed",
        }
        with patch.object(interserver_transport, "evaluate_transport_policy", return_value=evaluated):
            trace, select, proof = self.run_transport_cycles([2], selected="interserver-underlay-hy2", previous={
                "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
                "selected": "interserver-underlay-hy2", "switch_backoff": failure,
            })
        self.assertEqual(trace[0]["state"], "degraded")
        self.assertFalse(trace[0]["would_switch"])
        self.assertEqual(trace[0]["switch_backoff"], failure)
        self.assertIn("paused until", trace[0]["reason"])
        select.assert_not_called()
        proof.assert_not_called()

    def test_live_path_does_not_repeat_a_failed_quality_switch_inside_backoff(self) -> None:
        config = {"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}}
        env = {"SSH_PORT": "22"}
        state: dict[str, object] = {}
        probes = {
            "interserver-underlay-wg": {"checked": True, "ok": True, "quality_checked": True,
                                       "quality_sampled": True, "quality_ok": False, "quality_error": "packet loss 25%"},
            "interserver-underlay-hy2": {"checked": True, "ok": True, "health_confirmed": True,
                                        "quality_checked": True, "quality_ok": True, "delay_ms": 70},
        }

        def read(path: Path, _default: object) -> dict[str, object]:
            return config if path == server_runtime.SINGBOX_CONFIG_PATH else dict(state)

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
                patch.object(server_runtime, "TRANSPORT_LOCK_PATH", Path(tmp) / "transport.lock"),
                patch.object(server_runtime, "read_json", side_effect=read),
                patch.object(server_runtime, "write_json_atomic", side_effect=write),
                patch.object(server_runtime, "parse_env", return_value=env),
                patch.object(interserver_transport, "transport_topology_configured", return_value=True),
                patch.object(server_transport, "transport_selection_snapshot", return_value=selection),
                patch.object(server_transport, "collect_transport_probes", return_value=probes),
                patch.object(
                    server_runtime,
                    "utc_now",
                    side_effect=[
                        "2026-08-09T12:00:00+00:00",
                        "2026-08-09T12:00:16+00:00",
                        "2026-08-09T12:00:32+00:00",
                    ],
                ),
                patch.object(
                    server_transport,
                    "select_transport",
                    side_effect=server_transport.TransportSwitchError("activation failed", {
                        "selector_before": "interserver-underlay-wg", "selector_after": "interserver-underlay-wg",
                        "rollback_verified": True, "rollback_proof": {"probe": {"checked": True, "ok": True}},
                    }),
                ) as select,
            ):
                first = server_transport._reconcile_interserver_transport_unlocked()
                second = server_transport._reconcile_interserver_transport_unlocked()
                third = server_transport._reconcile_interserver_transport_unlocked()

        self.assertEqual(first["state"], "degraded")
        self.assertEqual(second["state"], "degraded")
        self.assertIn("switch_backoff", second)
        self.assertEqual(third["state"], "degraded")
        self.assertFalse(third["would_switch"])
        self.assertIn("paused until", third["reason"])
        select.assert_called_once()

    def test_select_transport_restores_previous_selector_when_overlay_proof_fails(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_PUBLIC_KEY": "peer-key", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        selections = [
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-hy2"},
            {"available": True, "selected": "interserver-underlay-hy2"},
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-wg"},
            {"available": True, "selected": "interserver-underlay-wg"},
        ]
        with patch.object(server_transport, "transport_selector_selection", side_effect=selections), patch.object(
            server_transport, "prove_wireguard_overlay", side_effect=[
                server_transport.TransportSwitchError("proof failed", {"ok": False, "probe": {"ok": False}}),
                {"ok": True, "probe": {"ok": True}},
            ]
        ), patch.object(server_transport, "clash_api_json") as api, patch.object(
            server_transport, "reset_transport_relay", return_value=1
        ) as reset:
            with self.assertRaisesRegex(server_transport.TransportSwitchError, "previous selector path restored and verified") as raised:
                server_transport.select_transport(env, "127.0.0.1:19090", "interserver-underlay-hy2")
        self.assertTrue(raised.exception.evidence["rollback_verified"])
        self.assertFalse(raised.exception.evidence["activation_proof"]["ok"])
        self.assertEqual(raised.exception.evidence["rollback_proof"]["phase"], "rollback")
        self.assertEqual(
            [call.kwargs["payload"] for call in api.call_args_list],
            [{"name": "interserver-underlay-hy2"}, {"name": "interserver-underlay-wg"}],
        )
        self.assertEqual(reset.call_count, 2)

    def test_transport_reconcile_persists_maintenance_during_install(self) -> None:
        previous = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "state": "failed",
            "selected": "interserver-underlay-hy2",
            "reason": "old transient failure",
        }
        with (
            patch.object(server_runtime, "acquire_install_read_lock", return_value=None),
            patch.object(server_runtime, "read_json", return_value=previous),
            patch.object(server_runtime, "write_json_atomic") as write,
        ):
            payload = server_transport.reconcile_interserver_transport()

        self.assertEqual(payload["state"], "maintenance")
        self.assertFalse(payload["would_switch"])
        write.assert_called_once_with(server_runtime.TRANSPORT_STATE_PATH, payload)

    def test_maintenance_drops_confirmations_and_preserves_history_before_fresh_cycles(self) -> None:
        selected, target = interserver_transport.TRANSPORT_CANDIDATE_TAGS
        probes = {selected: {"checked": True, "ok": False, "error": "timeout"},
                  target: {"checked": True, "ok": True}}
        previous = interserver_transport.evaluate_transport_policy(
            selected=selected, probes=probes, observed_at="2026-10-08T12:00:00+00:00")
        history = {"last_transition": {"cycle_id": "old"}, "preferred_retry": {"path": selected},
                   "switch_backoff": {"target": target}, "last_switch_failure": {"target": target}}
        previous.update(history)
        previous.update(quality_failure={"confirmations": 2}, preferred_recovery={"confirmations": 2},
                        last_quality_probe={"quality_ok": True}, cycle_id="old", hard_failure_evidence=True,
                        quality_probe_at=previous["updated_at"], preferred_probe_at=previous["updated_at"])
        original = deepcopy(previous)
        with patch.object(server_runtime, "acquire_install_read_lock", return_value=None), patch.object(
            server_runtime, "read_json", return_value=previous
        ), patch.object(server_runtime, "write_json_atomic"), patch.object(
            server_runtime, "utc_now", return_value="2026-10-08T12:05:00+00:00"
        ):
            maintenance = server_transport.reconcile_interserver_transport()
        self.assertEqual(previous, original)
        self.assertEqual(maintenance["state"], "maintenance")
        for key, value in history.items():
            self.assertEqual(maintenance[key], value)
        for key in ("failure", "alternate_health", "quality_failure", "preferred_recovery", "last_quality_probe",
                    "probes", "cycle_id", "hard_failure_evidence", "quality_probe_at", "preferred_probe_at"):
            self.assertNotIn(key, maintenance)
        first = interserver_transport.evaluate_transport_policy(selected=selected, probes=probes, previous=maintenance,
                                                               observed_at="2026-10-08T12:05:02+00:00")
        self.assertFalse(first["would_switch"])
        self.assertEqual(first["failure"]["confirmations"], 1)
        second = interserver_transport.evaluate_transport_policy(selected=selected, probes=probes, previous=first,
                                                                observed_at="2026-10-08T12:05:04+00:00")
        self.assertTrue(second["would_switch"])
        self.assertEqual(second["failure"]["confirmations"], 2)

    def test_transport_reconcile_drops_state_from_an_old_schema(self) -> None:
        previous = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION - 1,
            "state": "failed",
            "last_switch_failure": {"reason": "obsolete endpoint mutation failure"},
        }
        with (
            patch.object(server_runtime, "acquire_install_read_lock", return_value=None),
            patch.object(server_runtime, "read_json", return_value=previous),
            patch.object(server_runtime, "write_json_atomic"),
        ):
            payload = server_transport.reconcile_interserver_transport()

        self.assertEqual(payload["schema_version"], interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION)
        self.assertNotIn("last_switch_failure", payload)

    def test_transport_reconcile_expires_retry_but_retains_recent_failure_history(self) -> None:
        config = {"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}}
        expired_failure = {
            "target": "interserver-underlay-hy2",
            "attempts": 1,
            "failed_at": "2026-08-09T11:59:00+00:00",
            "retry_at": "2026-08-09T11:59:30+00:00",
            "reason": "transient activation failure",
        }
        previous = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "state": "healthy",
            "selected": "interserver-underlay-wg",
            "switch_backoff": expired_failure,
            "last_switch_failure": expired_failure,
        }
        selection = {"available": True, "selected": "interserver-underlay-wg"}
        probes = {"interserver-underlay-wg": {"checked": True, "ok": True}}
        evaluated = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
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
                patch.object(server_runtime, "TRANSPORT_LOCK_PATH", Path(tmp) / "transport.lock"),
                patch.object(server_runtime, "read_json", side_effect=[config, previous]),
                patch.object(server_runtime, "write_json_atomic") as write,
                patch.object(server_runtime, "parse_env", return_value={}),
                patch.object(interserver_transport, "transport_topology_configured", return_value=True),
                patch.object(server_transport, "transport_selection_snapshot", return_value=selection),
                patch.object(server_transport, "collect_transport_probes", return_value=probes),
                patch.object(interserver_transport, "evaluate_transport_policy", return_value=evaluated),
                patch.object(server_runtime, "utc_now", return_value="2026-08-09T12:00:00+00:00"),
            ):
                payload = server_transport._reconcile_interserver_transport_unlocked()

        self.assertNotIn("switch_backoff", payload)
        self.assertEqual(payload["last_switch_failure"], expired_failure)
        write.assert_called_once_with(server_runtime.TRANSPORT_STATE_PATH, payload)

    def test_switch_failure_history_expires_and_does_not_cross_targets(self) -> None:
        failure = server_transport.next_transport_switch_failure(
            {}, "interserver-underlay-hy2", "proof failed", "2026-09-05T12:00:00+00:00",
        )
        previous = {
            "schema_version": interserver_transport.TRANSPORT_STATE_SCHEMA_VERSION,
            "selected": "interserver-underlay-wg", "last_switch_failure": failure,
        }
        recent = server_transport.next_transport_switch_failure(
            previous, "interserver-underlay-hy2", "proof failed", "2026-09-05T12:01:00+00:00",
        )
        stale = server_transport.next_transport_switch_failure(
            previous, "interserver-underlay-hy2", "proof failed", "2026-09-05T12:31:00+00:00",
        )
        other = server_transport.next_transport_switch_failure(
            previous, "interserver-underlay-wg", "proof failed", "2026-09-05T12:01:00+00:00",
        )
        self.assertEqual(recent["attempts"], 2)
        self.assertEqual(stale["attempts"], 1)
        self.assertEqual(other["attempts"], 1)
        trace, _select, _proof = self.run_transport_cycles([1860], previous=previous)
        self.assertNotIn("last_switch_failure", trace[0])

    def test_transport_transition_keeps_before_failure_and_after_activation_proof(self) -> None:
        trace, _select, proof = self.run_transport_cycles([0, 2], liveness_ok=False)
        state = trace[1]
        self.assertEqual(state["selector_before"], "interserver-underlay-wg")
        self.assertEqual(state["selector_after"], "interserver-underlay-hy2")
        self.assertFalse(state["probes"]["interserver-underlay-wg"]["ok"])
        self.assertEqual(state["probes"]["interserver-underlay-wg"]["phase"], "before")
        self.assertTrue(state["overlay_probe"]["ok"])
        self.assertEqual(state["overlay_probe"]["phase"], "activation")
        self.assertEqual(state["overlay_probe"]["path"], state["selected"])
        self.assertEqual(state["last_transition"]["cycle_id"], state["cycle_id"])
        self.assertTrue(state["last_transition"]["activation_proof"]["ok"])
        self.assertEqual(state["last_transition"]["decision_evidence"]["failure"]["confirmations"], 2)
        proof.assert_called_once()

    def test_first_failed_cycle_after_activation_cannot_bounce_back(self) -> None:
        trace, select, _proof = self.run_transport_cycles([0, 2, 4, 6], liveness_ok=False)
        self.assertEqual([bool(s.get("changed")) for s in trace], [False, True, False, True])
        self.assertEqual(trace[2]["failure"]["confirmations"], 1)
        self.assertEqual(trace[2]["selected"], "interserver-underlay-hy2")
        self.assertEqual(trace[3]["selected"], "interserver-underlay-wg")
        self.assertEqual(select.call_count, 2)

    def test_transport_transition_evidence_is_retained_without_refresh(self) -> None:
        trace, _select, _proof = self.run_transport_cycles([0, 16, 18])
        self.assertIn("last_transition", trace[1])
        self.assertEqual(trace[1]["last_transition"], trace[2]["last_transition"])
        self.assertNotEqual(trace[2]["cycle_id"], trace[2]["last_transition"]["cycle_id"])

    def test_transport_rollback_does_not_trust_exception_wording(self) -> None:
        with patch.object(server_transport, "select_transport", side_effect=RuntimeError(
            "previous selector path restored and verified"
        )):
            trace, _select, _proof = self.run_transport_cycles([0, 2], liveness_ok=False)
        self.assertEqual(trace[1]["state"], "failed")
        self.assertFalse(trace[1]["overlay_probe"]["checked"])
        self.assertEqual(trace[1]["selector_after"], "")

    def test_transport_both_overlay_proofs_fail_with_bounded_typed_evidence(self) -> None:
        selector = {"available": True, "selected": "interserver-underlay-wg"}

        def api(_controller, _path, *, payload, **_kwargs):
            selector["selected"] = payload["name"]
            return {}

        with (
            patch.object(server_transport, "transport_selector_selection", side_effect=lambda *_: dict(selector)),
            patch.object(server_transport, "clash_api_json", side_effect=api),
            patch.object(server_transport, "reset_transport_relay", return_value=1) as reset,
            patch.object(server_transport, "prove_wireguard_overlay", side_effect=RuntimeError("x" * 10000)),
        ):
            with self.assertRaises(server_transport.TransportSwitchError) as raised:
                server_transport.select_transport({}, "127.0.0.1:19090", "interserver-underlay-hy2", cycle_id="cycle")
        evidence = raised.exception.evidence
        self.assertFalse(evidence["rollback_verified"])
        self.assertFalse(evidence["ok"])
        self.assertEqual(evidence["selector_after"], "interserver-underlay-wg")
        self.assertEqual(evidence["activation_proof"]["phase"], "activation")
        self.assertEqual(evidence["rollback_proof"]["phase"], "rollback")
        self.assertEqual(reset.call_count, 2)
        self.assertLessEqual(len(str(raised.exception)), 240)
        self.assertLessEqual(len(evidence["rollback_error"]), 240)
        self.assertLess(len(json.dumps(evidence)), 3000)

    def test_transport_same_selector_proves_without_reset_or_put(self) -> None:
        selector = {"available": True, "selected": "interserver-underlay-wg"}
        with (
            patch.object(server_transport, "transport_selector_selection", return_value=selector),
            patch.object(server_transport, "clash_api_json") as api,
            patch.object(server_transport, "reset_transport_relay") as reset,
            patch.object(server_transport, "prove_wireguard_overlay", return_value={"ok": True, "probe": {"ok": True}}),
        ):
            result = server_transport.select_transport({}, "127.0.0.1:19090", "interserver-underlay-wg")
        self.assertTrue(result["ok"])
        self.assertFalse(result["changed"])
        api.assert_not_called()
        reset.assert_not_called()

    def test_transport_selector_change_during_proof_cannot_verify_activation(self) -> None:
        with (
            patch.object(server_transport, "transport_selector_selection", side_effect=[
                {"available": True, "selected": "interserver-underlay-wg"},
                {"available": True, "selected": "interserver-underlay-hy2"},
                {"available": True, "selected": "interserver-underlay-hy2"},
            ]),
            patch.object(server_transport, "prove_wireguard_overlay", return_value={"ok": True, "probe": {"ok": True}}),
            patch.object(server_transport, "reset_transport_relay") as reset,
            patch.object(server_transport, "clash_api_json") as api,
        ):
            with self.assertRaises(server_transport.TransportSwitchError) as raised:
                server_transport.select_transport({}, "127.0.0.1:19090", "interserver-underlay-wg")
        self.assertFalse(raised.exception.evidence["activation_proof"]["ok"])
        self.assertFalse(raised.exception.evidence["activation_proof"]["probe"]["checked"])
        reset.assert_not_called()
        api.assert_not_called()

    def test_transport_watch_emits_new_transitions_with_the_same_signature(self) -> None:
        base = {"state": "failed", "selected": "interserver-underlay-wg", "reason": "activation failed"}
        records = [
            {**base, "cycle_id": "a", "last_transition": {"cycle_id": "a"}},
            {**base, "cycle_id": "b", "last_transition": {"cycle_id": "b"}},
            {**base, "cycle_id": "c", "last_transition": {"cycle_id": "b"}},
            {**base, "cycle_id": "d", "last_transition": None},
        ]
        with (
            patch.object(server_transport, "reconcile_interserver_transport", side_effect=records),
            patch.object(server_transport.time, "sleep", side_effect=[None, None, None, KeyboardInterrupt]),
            patch("builtins.print") as output,
        ):
            with self.assertRaises(KeyboardInterrupt):
                server_transport.watch_interserver_transport()
        self.assertEqual(output.call_count, 2)

    def test_overlay_convergence_scheduler_overrun_starts_no_extra_round(self) -> None:
        clock = [0.0]

        def oversleep(_seconds):
            clock[0] += 7

        with (
            patch.object(server_transport.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(server_transport.time, "sleep", side_effect=oversleep),
            patch.object(interserver_transport, "transport_overlay_dns_probe", return_value={"ok": False, "error": "timeout"}) as probe,
        ):
            with self.assertRaises(server_transport.TransportSwitchError) as raised:
                server_transport.prove_wireguard_overlay({"WG_FOREIGN_ADDRESS": "10.74.0.2/24"})
        probe.assert_called_once_with("wg0", "10.74.0.2", deadline=6.8)
        self.assertEqual(len(raised.exception.evidence["rounds"]), 1)
        self.assertFalse(raised.exception.evidence["ok"])

    def test_overlay_proof_waits_for_exact_dns_dataplane_convergence(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        failed = {"ok": False, "health_confirmed": False, "error": "timed out"}
        healthy = {"ok": True, "health_confirmed": True, "error": ""}
        with patch.object(
            interserver_transport,
            "transport_overlay_dns_probe",
            side_effect=[failed, failed, healthy],
        ) as probe, patch.object(server_transport.time, "sleep") as sleep:
            report = server_transport.prove_wireguard_overlay(env)

        self.assertEqual(probe.call_count, 3)
        self.assertEqual(probe.call_args.args, ("wg0", "10.74.0.2"))
        self.assertEqual(set(probe.call_args.kwargs), {"deadline"})
        self.assertEqual(len({call.kwargs["deadline"] for call in probe.call_args_list}), 1)
        self.assertEqual(report["budget_ms"], 6800)
        self.assertEqual(report["rounds"], [failed, failed, healthy])
        self.assertEqual(sleep.call_count, 2)
        sleep.assert_called_with(interserver_transport.TRANSPORT_SWITCH_PROOF_RETRY_DELAY_SECONDS)

    def test_overlay_proof_fails_after_bounded_dns_attempts(self) -> None:
        env = {"WG_INTERFACE": "wg0", "WG_FOREIGN_ADDRESS": "10.74.0.2/24"}
        failed = {"ok": False, "health_confirmed": False, "error": "timed out"}
        with patch.object(
            interserver_transport,
            "transport_overlay_dns_probe",
            return_value=failed,
        ) as probe, patch.object(server_transport.time, "sleep"):
            with self.assertRaisesRegex(server_transport.TransportSwitchError, "DNS convergence proof failed after 5 rounds"):
                server_transport.prove_wireguard_overlay(env)

        self.assertEqual(probe.call_count, interserver_transport.TRANSPORT_SWITCH_PROOF_ATTEMPTS)

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
        with patch.object(server_runtime, "read_json", return_value=config), patch.object(server_runtime, "run", return_value=sockets):
            transport = server_transport.interserver_transport_snapshot(self.exit_contract(), {"GATEWAY_PUBLIC_IP": "94.232.248.35"})

        self.assertTrue(transport["configured"])
        self.assertTrue(transport["listening"])
        self.assertEqual(transport["source_restricted_to"], "94.232.248.35")
