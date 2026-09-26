from __future__ import annotations

import ast
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import server_agent, server_lifecycle, server_runtime, server_transport
from vpn_installer.config import generate_default_env
from vpn_installer.render import SERVER_AGENT_BASE_MODULES, SERVER_AGENT_INTERSERVER_MODULES, SERVER_RENDER_MODULES


from tests.server_agent_fixtures import AgentFixtures


class ServerRuntimeTests(AgentFixtures, unittest.TestCase):
    def test_timeout_preserves_partial_stdout_without_changing_checked_failures(self) -> None:
        for output in ("partial\n", b"partial\n", b"invalid\xff", None):
            with self.subTest(output=output), patch.object(
                server_runtime.subprocess, "run", side_effect=subprocess.TimeoutExpired("journalctl", 20, output=output),
            ):
                result = server_runtime.run(["journalctl"])
                expected = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output or ""
                self.assertEqual(result.stdout, expected)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("timed out", result.stderr)
                with self.assertRaises(RuntimeError):
                    server_runtime.run(["journalctl"], check=True)

    def test_conntrack_timeout_through_runtime_retains_positive_evidence(self) -> None:
        output = json.dumps({"__REALTIME_TIMESTAMP": "900000000", "MESSAGE": "nf_conntrack: table full"}).encode()
        coverage = {"since_epoch": 0, "discarded_at": [], "error": "", "query_since_epoch": 0, "query_until_epoch": 1000}
        with patch.object(server_runtime.subprocess, "run", side_effect=subprocess.TimeoutExpired("journalctl", 20, output=output)):
            snapshot = server_agent.kernel_conntrack_full_windows(full_logs=False, coverage=coverage, cutoff=1000)
        self.assertIsNone(snapshot["counts"]["5"])
        self.assertEqual(snapshot["observed_counts"]["5"], 1)
        self.assertEqual(len(snapshot["events"]), 1)

    def test_extracted_functions_have_one_owner_without_agent_exports(self) -> None:
        for module, names in (
            (server_runtime, ("run", "read_json", "acquire_install_read_lock", "wireguard_policy_snapshot")),
            (server_lifecycle, ("health", "recover", "apply_network_profile", "reconcile_front_tcp_metrics_cache")),
            (server_transport, ("select_transport", "prove_wireguard_overlay", "TransportSwitchError")),
        ):
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual(getattr(module, name).__module__, module.__name__)
                    self.assertFalse(hasattr(server_agent, name))

    def test_extracted_modules_are_bundled_and_never_import_the_agent(self) -> None:
        for module in (server_runtime, server_lifecycle, server_transport):
            filename = Path(module.__file__).name
            self.assertIn(filename, SERVER_RENDER_MODULES)
            tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append(node.module or "")
                    imports.extend(alias.name for alias in node.names)
            self.assertNotIn("server_agent", imports)
            self.assertNotIn("vpn_installer.server_agent", imports)
        self.assertIn("server_runtime.py", SERVER_AGENT_BASE_MODULES)
        self.assertIn("server_lifecycle.py", SERVER_AGENT_BASE_MODULES)
        self.assertNotIn("server_transport.py", SERVER_AGENT_BASE_MODULES)
        self.assertIn("server_transport.py", SERVER_AGENT_INTERSERVER_MODULES)

    def test_wireguard_policy_snapshot_detects_a_missing_ipv6_rule(self) -> None:
        env = generate_default_env("demo")

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if args[2:4] == ["rule", "show"]:
                output = "" if args[1] == "-6" else "10000: from all fwmark 0x30 lookup 51820\n"
                return subprocess.CompletedProcess(args, 0, output, "")
            destination = args[-1]
            return subprocess.CompletedProcess(args, 0, f"{destination} dev wg0\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            snapshot = server_runtime.wireguard_policy_snapshot(env, managed=True)

        self.assertFalse(snapshot["ok"])
        self.assertEqual(snapshot["missing"], ["ipv6_rule"])
