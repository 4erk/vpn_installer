from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vpn_installer.audit import runner as audit_runner
from vpn_installer.config import load_env_file
from vpn_installer.topology import (
    LOCATION_FOREIGN,
    LOCATION_RU,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
    TopologySpec,
)


def completed(code: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["cmd"], code, stdout=stdout, stderr=stderr)


class AuditRunnerTests(unittest.TestCase):
    def make_runner(self, mode: str = "quick") -> audit_runner.AuditRunner:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        with patch.object(audit_runner, "AUDIT_ROOT", root):
            runner = audit_runner.AuditRunner(mode)
        return runner

    def owner_labels(self, runner: audit_runner.AuditRunner, **overrides) -> dict[str, str]:
        labels = {"": "1", ".checkout": runner.checkout_id, ".run": "previous",
                  ".pid": "1234", ".keep": "0"}
        labels.update(overrides)
        return {f"vpn-installer.audit{key}": value for key, value in labels.items() if value is not None}

    def cleanup_calls(self, runner, resources) -> list[list[str]]:
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            calls.append(args)
            if args[1:3] == ["ps", "-a"] or args[1:3] == ["network", "ls"]:
                kind = "container" if args[1] == "ps" else "network"
                return completed(0, stdout="\n".join(key for key, (item_kind, _) in resources.items() if item_kind == kind))
            if args[1] in ("container", "network") and args[2] == "inspect":
                kind, labels = resources[args[-1]]
                resource = {"Id": args[-1], "Config": {"Labels": labels}} if kind == "container" else {"Id": args[-1], "Labels": labels}
                return completed(0, stdout=json.dumps([resource]))
            return completed(0)

        with patch.object(audit_runner, "require_command"), patch.object(
            audit_runner.subprocess, "run", side_effect=fake_run,
        ):
            runner.cleanup_stale_lab_resources()
        return calls

    def test_build_parser_parses_flags(self) -> None:
        parser = audit_runner.build_parser()
        args = parser.parse_args(["all", "--json", "--keep-docker"])
        self.assertEqual(args.mode, "all")
        self.assertTrue(args.json)
        self.assertTrue(args.keep_docker)
        self.assertEqual(parser.parse_args(["interop"]).mode, "interop")

    def test_runner_record_success_and_failure(self) -> None:
        runner = self.make_runner()
        runner.record("ok", lambda: {"path": "demo"})
        runner.record("fail", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        self.assertEqual(runner.results[0].status, "passed")
        self.assertEqual(runner.results[1].status, "failed")
        self.assertEqual(runner.failures, 1)

    def test_required_skip_makes_summary_incomplete_and_exit_nonzero(self) -> None:
        runner = self.make_runner()
        runner.record("structural", lambda: None)
        runner.skip("runtime", "docker unavailable")
        runner.write_summary()

        payload = json.loads(runner.summary_path().read_text(encoding="utf-8"))
        self.assertEqual(runner.outcome, "incomplete")
        self.assertEqual(runner.exit_code, 2)
        self.assertFalse(runner.success)
        self.assertEqual(payload["outcome"], "incomplete")
        self.assertFalse(payload["success"])
        self.assertFalse(payload["complete"])

    def test_failure_takes_precedence_over_incomplete(self) -> None:
        runner = self.make_runner()
        runner.skip("runtime", "docker unavailable")
        runner.record("broken", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        runner.write_summary()
        payload = json.loads(runner.summary_path().read_text(encoding="utf-8"))
        self.assertEqual(runner.outcome, "failed")
        self.assertEqual(runner.exit_code, 1)
        self.assertFalse(payload["success"])
        self.assertFalse(payload["complete"])

    def test_runner_returns_incomplete_exit_code_for_skipped_check(self) -> None:
        runner = self.make_runner("interop")
        fake_quick = types.SimpleNamespace(run=MagicMock(), run_interop=lambda current: current.skip("runtime", "docker unavailable"))
        fake_docker = types.SimpleNamespace(run=MagicMock())
        fake_lab = types.SimpleNamespace(run=MagicMock())
        import sys

        with patch.dict(sys.modules, {"vpn_installer.audit.quick": fake_quick, "vpn_installer.audit.docker": fake_docker, "vpn_installer.audit.lab": fake_lab}):
            rc = runner.run()
        payload = json.loads(runner.summary_path().read_text(encoding="utf-8"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["outcome"], "incomplete")
        self.assertFalse(payload["success"])

    def test_runner_run_dispatches_modes(self) -> None:
        runner = self.make_runner("all")
        fake_quick = types.SimpleNamespace(run=MagicMock())
        fake_docker = types.SimpleNamespace(run=MagicMock())
        fake_lab = types.SimpleNamespace(run=MagicMock())
        import sys

        with patch.dict(sys.modules, {"vpn_installer.audit.quick": fake_quick, "vpn_installer.audit.docker": fake_docker, "vpn_installer.audit.lab": fake_lab}):
            rc = runner.run()
        self.assertEqual(rc, 0)
        fake_quick.run.assert_called_once_with(runner)
        fake_docker.run.assert_called_once_with(runner)
        fake_lab.run.assert_called_once_with(runner)

        interop_runner = self.make_runner("interop")
        fake_quick = types.SimpleNamespace(run=MagicMock(), run_interop=MagicMock())
        fake_docker = types.SimpleNamespace(run=MagicMock())
        fake_lab = types.SimpleNamespace(run=MagicMock())
        with patch.dict(sys.modules, {"vpn_installer.audit.quick": fake_quick, "vpn_installer.audit.docker": fake_docker, "vpn_installer.audit.lab": fake_lab}):
            rc = interop_runner.run()
        self.assertEqual(rc, 0)
        fake_quick.run_interop.assert_called_once_with(interop_runner)
        fake_docker.run.assert_not_called()
        fake_lab.run.assert_not_called()

    def test_audit_lock_preserves_previous_implementation_marker_without_parsing_pid(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        lock = root / ".run.lock"
        for content in ("", "{", json.dumps({"pid": os.getpid(), "run_id": "active"}), '{"pid":"invalid"}'):
            with self.subTest(content=content):
                lock.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(audit_runner.AuditFailure, "previous audit lock exists"):
                    with audit_runner.audit_run_lock("second", root):
                        self.fail("old audit marker must be preserved")
                self.assertEqual(lock.read_text(encoding="utf-8"), content)
        lock.unlink()
        with audit_runner.audit_run_lock("after-old-audit", root):
            pass

    def test_audit_lock_metadata_is_not_authority_and_file_is_retained(self) -> None:
        runner = self.make_runner()
        root = runner.run_dir.parent
        lock = root / ".run.advisory.lock"
        for content in ("", "{", '{"pid":"invalid"}', json.dumps({"pid": os.getpid(), "run_id": "finished"})):
            lock.write_text(content, encoding="utf-8")
            inode = lock.stat().st_ino
            with self.subTest(content=content), audit_runner.audit_run_lock("replacement", root):
                with self.assertRaisesRegex(audit_runner.AuditFailure, "audit already running"):
                    with audit_runner.audit_run_lock("overlap", root):
                        self.fail("nested owner acquired lock")
            self.assertEqual(lock.stat().st_ino, inode)
            self.assertEqual(json.loads(lock.read_text(encoding="utf-8"))["run_id"], "replacement")

    def test_audit_lock_releases_after_metadata_or_body_failure(self) -> None:
        runner = self.make_runner()
        root = runner.run_dir.parent
        with patch.object(audit_runner, "utc_stamp", side_effect=RuntimeError("metadata failed")):
            with self.assertRaisesRegex(RuntimeError, "metadata failed"):
                with audit_runner.audit_run_lock("first", root):
                    self.fail("metadata failed")
        with self.assertRaisesRegex(RuntimeError, "body failed"):
            with audit_runner.audit_run_lock("second", root):
                raise RuntimeError("body failed")
        with audit_runner.audit_run_lock("third", root):
            pass

    def test_audit_lock_excludes_real_process_before_metadata_and_releases_on_exit(self) -> None:
        script = """
import sys
from pathlib import Path
from unittest.mock import patch
sys.path[:0] = sys.argv[2:]
from vpn_installer.audit import runner
stamp = runner.utc_stamp
def paused_stamp():
    print('LOCKED_BEFORE_METADATA', flush=True)
    if sys.stdin.readline().strip() != 'write':
        raise RuntimeError('missing write command')
    return stamp()
with patch.object(runner, 'utc_stamp', side_effect=paused_stamp):
    with runner.audit_run_lock('child', Path(sys.argv[1])):
        print('ENTERED', flush=True)
        sys.stdin.readline()
print('EXITED', flush=True)
"""
        for terminate in (False, True):
            with self.subTest(terminate=terminate):
                runner = self.make_runner()
                root = runner.run_dir.parent
                child = subprocess.Popen(
                    [sys.executable, "-u", "-c", script, str(root), str(audit_runner.ROOT_DIR), str(audit_runner.RUNTIME_SITE_PACKAGES)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                )
                messages: queue.Queue[str] = queue.Queue()
                def read_output():
                    for line in child.stdout:
                        messages.put(line.strip())
                reader = threading.Thread(target=read_output, daemon=True)
                reader.start()
                try:
                    self.assertEqual(messages.get(timeout=10), "LOCKED_BEFORE_METADATA")
                    lock = root / ".run.advisory.lock"
                    inode = lock.stat().st_ino
                    self.assertEqual(lock.stat().st_size, 0)
                    for _ in range(3):
                        with self.assertRaisesRegex(audit_runner.AuditFailure, "audit already running"):
                            with audit_runner.audit_run_lock("contender", root):
                                self.fail("owner lock stolen before metadata")
                        self.assertEqual(lock.stat().st_ino, inode)
                    child.stdin.write("write\n")
                    child.stdin.flush()
                    self.assertEqual(messages.get(timeout=10), "ENTERED")
                    with self.assertRaises(audit_runner.AuditFailure):
                        with audit_runner.audit_run_lock("contender", root):
                            self.fail("owner lock stolen after metadata")
                    if terminate:
                        child.kill()
                    else:
                        child.stdin.write("release\n")
                        child.stdin.flush()
                    child.wait(timeout=10)
                    if not terminate:
                        self.assertEqual(child.returncode, 0)
                    with audit_runner.audit_run_lock("next", root):
                        pass
                    self.assertEqual(lock.stat().st_ino, inode)
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)
                    child.stdin.close()
                    reader.join(timeout=5)
                    child.stdout.close()

    def test_runner_run_invalid_mode_fails(self) -> None:
        runner = self.make_runner("nope")
        rc = runner.run()
        self.assertEqual(rc, 1)
        self.assertEqual(runner.results[-1].status, "failed")
        self.assertTrue(runner.summary_path().is_file())

    def test_runner_run_captures_top_level_failure_in_summary(self) -> None:
        runner = self.make_runner("quick")
        fake_quick = types.SimpleNamespace(run=MagicMock(side_effect=audit_runner.AuditFailure("boom")))
        fake_docker = types.SimpleNamespace(run=MagicMock())
        fake_lab = types.SimpleNamespace(run=MagicMock())
        import sys

        with patch.dict(sys.modules, {"vpn_installer.audit.quick": fake_quick, "vpn_installer.audit.docker": fake_docker, "vpn_installer.audit.lab": fake_lab}):
            rc = runner.run()
        self.assertEqual(rc, 1)
        self.assertEqual(runner.results[-1].name, "quick-runner")
        self.assertEqual(runner.results[-1].status, "failed")

    def test_run_command_writes_logs_and_respects_codes(self) -> None:
        runner = self.make_runner()
        with patch("vpn_installer.audit.runner.subprocess.run", return_value=completed(0, stdout="ok", stderr="")):
            done = runner.run_command("demo", ["echo", "ok"])
        self.assertEqual(done.stdout, "ok")
        self.assertTrue((runner.logs_dir / "demo" / "stdout.log").is_file())

    def test_run_command_raises_on_unexpected_exit(self) -> None:
        runner = self.make_runner()
        with patch("vpn_installer.audit.runner.subprocess.run", return_value=completed(9, stderr="boom")):
            with self.assertRaises(audit_runner.AuditFailure):
                runner.run_command("demo", ["echo", "ok"])

    def test_run_command_bounds_external_process_and_saves_partial_output(self) -> None:
        runner = self.make_runner()
        expired = subprocess.TimeoutExpired(["docker", "exec"], 7, output="partial-out", stderr="partial-error")
        with patch("vpn_installer.audit.runner.subprocess.run", side_effect=expired) as run:
            with self.assertRaisesRegex(audit_runner.AuditFailure, "timeout after 7s"):
                runner.run_command("bounded", ["docker", "exec"], timeout_seconds=7)

        self.assertEqual(run.call_args.kwargs["timeout"], 7)
        self.assertEqual((runner.logs_dir / "bounded" / "stdout.log").read_text(encoding="utf-8"), "partial-out")
        self.assertEqual((runner.logs_dir / "bounded" / "stderr.log").read_text(encoding="utf-8"), "partial-error")

    def test_run_bash_and_powershell_delegate(self) -> None:
        runner = self.make_runner()
        with patch.object(audit_runner, "require_command"), patch.object(runner, "run_command", return_value=completed(0)) as run:
            runner.run_bash("demo", "echo ok")
        run.assert_called_once()

        with patch.object(audit_runner, "powershell_executable", return_value="powershell"), patch.object(runner, "run_command", return_value=completed(0)) as run:
            runner.run_powershell("demo", ["-File", "vpn.ps1"])
        run.assert_called_once()

    def test_ensure_audit_image_uses_existing_image_or_builds(self) -> None:
        runner = self.make_runner()
        with patch("vpn_installer.audit.runner.subprocess.run", side_effect=[completed(0), completed(0, stdout=f"{audit_runner.AUDIT_SINGBOX_REQUIRED_VERSION}\n")]), patch.object(runner, "docker") as docker:
            runner.ensure_audit_image()
        docker.assert_not_called()
        self.assertTrue(runner.base_image_ready)

        runner = self.make_runner()
        with patch("vpn_installer.audit.runner.subprocess.run", return_value=completed(1)), patch.object(runner, "docker") as docker:
            runner.ensure_audit_image()
        docker.assert_called_once()
        self.assertTrue(runner.base_image_ready)

        runner = self.make_runner()
        with patch("vpn_installer.audit.runner.subprocess.run", side_effect=[completed(0), completed(0, stdout="1.13.7\n")]), patch.object(runner, "docker") as docker:
            runner.ensure_audit_image()
        docker.assert_called_once()
        self.assertTrue(runner.base_image_ready)

    def test_create_env_and_seed_cache(self) -> None:
        runner = self.make_runner()
        env_path, env = runner.create_env("demo", {"WAN_INTERFACE": "eth9"})
        self.assertTrue(env_path.is_file())
        self.assertEqual(env["CONFIG_SCHEMA"], "3")
        self.assertEqual(env["TOPOLOGY"], TOPOLOGY_DUAL)
        self.assertEqual(env["GATEWAY_PUBLIC_IP"], "203.0.113.10")
        self.assertEqual(env["EXIT_PUBLIC_IP"], "198.51.100.20")
        self.assertEqual(env["WAN_INTERFACE"], "eth9")
        assets = runner.seed_foreign_block_cache(env["DEPLOY_NAME"])
        self.assertTrue((assets / "ru-ipv4.zone").is_file())

    def test_create_env_covers_canonical_topology_matrix(self) -> None:
        runner = self.make_runner()
        cases = (
            ("single-ru", TOPOLOGY_SINGLE, LOCATION_RU, "203.0.113.10", None),
            ("single-foreign", TOPOLOGY_SINGLE, LOCATION_FOREIGN, "198.51.100.10", None),
            ("dual", TOPOLOGY_DUAL, LOCATION_RU, "203.0.113.10", "198.51.100.20"),
        )
        for name, topology, location, gateway_ip, exit_ip in cases:
            with self.subTest(name=name):
                env_path, env = runner.create_env(
                    name,
                    topology=topology,
                    gateway_location=location,
                )
                loaded = load_env_file(env_path)
                self.assertEqual(loaded, env)
                self.assertEqual(env["CONFIG_SCHEMA"], "3")
                self.assertEqual(env["GATEWAY_PUBLIC_IP"], gateway_ip)
                self.assertEqual(env.get("EXIT_PUBLIC_IP"), exit_ip)
                self.assertEqual(env.get("WAN_INTERFACE"), "eth1" if topology == TOPOLOGY_DUAL else None)
                spec = TopologySpec.from_env(env)
                self.assertEqual(spec.mode, topology)
                self.assertEqual(spec.gateway.location, location)
                self.assertEqual(len(spec.nodes), 2 if topology == TOPOLOGY_DUAL else 1)

    def test_parse_cloud_init_payload(self) -> None:
        runner = self.make_runner()
        yaml_path = runner.run_dir / "ru.yaml"
        yaml_path.write_text(
            "#cloud-config\nwrite_files:\n"
            "  - path: /root/vpn-stack/install.sh\n"
            "    content: aW5zdGFsbA==\n"
            "  - path: /root/vpn-stack/deployment.env\n"
            "    content: ZGVwbG95\n"
            "runcmd:\n"
            '  - [bash, -lc, "cd /root/vpn-stack && ./install.sh"]\n',
            encoding="utf-8",
        )
        files, runcmd = runner.parse_cloud_init_payload(yaml_path)
        self.assertIn("/root/vpn-stack/install.sh", files)
        self.assertIn("./install.sh", runcmd)

    def test_parse_cloud_init_payload_rejects_incomplete_payload(self) -> None:
        runner = self.make_runner()
        yaml_path = runner.run_dir / "bad.yaml"
        yaml_path.write_text("#cloud-config\nwrite_files:\n", encoding="utf-8")
        with self.assertRaises(audit_runner.AuditFailure):
            runner.parse_cloud_init_payload(yaml_path)

    def test_temp_repo_copy_copies_expected_entries(self) -> None:
        runner = self.make_runner()
        with runner.temp_repo_copy("repo-copy") as copied:
            self.assertTrue((copied / "vpn.ps1").exists())
            self.assertTrue((copied / "vpn.cmd").exists())
            self.assertTrue((copied / "vpn_installer").is_dir())

    def test_ensure_quick_env_is_canonical_dual(self) -> None:
        runner = self.make_runner()
        env_path, out_dir = runner.ensure_quick_env()
        env = load_env_file(env_path)
        self.assertEqual(env["CONFIG_SCHEMA"], "3")
        self.assertEqual(env["TOPOLOGY"], TOPOLOGY_DUAL)
        self.assertEqual(env["GATEWAY_PUBLIC_IP"], "203.0.113.10")
        self.assertEqual(env["EXIT_PUBLIC_IP"], "198.51.100.20")
        self.assertTrue(str(out_dir).endswith("quick"))

    def test_cleanup_preserves_legacy_unattributed_resources(self) -> None:
        runner = self.make_runner()
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            calls.append(args)
            if args[:5] == ["docker", "ps", "-a", "--filter", "label=vpn-installer.audit=1"]:
                return completed(0, stdout=f"ru-current|{runner.run_id}\nru-123-all|old\nclient-123-lab|\n")
            if args[:5] == ["docker", "network", "ls", "--filter", "label=vpn-installer.audit=1"]:
                return completed(0, stdout=f"audit-current|{runner.run_id}\naudit-front-123-all|old\naudit-ru-123-lab|\n")
            return completed(0)

        with patch.object(audit_runner, "require_command"), patch("vpn_installer.audit.runner.subprocess.run", side_effect=fake_run):
            runner.cleanup_stale_lab_resources()
        self.assertFalse(any(args[1] == "rm" or args[1:3] == ["network", "rm"] for args in calls))

    def test_checkout_identity_is_stable_and_scoped_to_checkout_and_host(self) -> None:
        runner = self.make_runner()
        root = runner.work_dir
        with patch.object(audit_runner, "ROOT_DIR", root), patch.object(audit_runner.socket, "gethostname", return_value="host-a"):
            first = audit_runner.checkout_identity()
            self.assertEqual(first, audit_runner.checkout_identity())
            with patch.object(audit_runner, "ROOT_DIR", root / "another-checkout"):
                self.assertNotEqual(first, audit_runner.checkout_identity())
            with patch.object(audit_runner, "ROOT_DIR", root / "child" / ".."):
                self.assertEqual(first, audit_runner.checkout_identity())
            with patch.object(audit_runner.socket, "gethostname", return_value="host-b"):
                self.assertNotEqual(first, audit_runner.checkout_identity())
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_cleanup_only_removes_proven_dead_owned_containers_and_networks(self) -> None:
        runner = self.make_runner()
        labels = [
            self.owner_labels(runner),
            self.owner_labels(runner, **{".checkout": "another-checkout"}),
            self.owner_labels(runner, **{".run": runner.run_id}),
            self.owner_labels(runner, **{".pid": str(runner.owner_pid)}),
            self.owner_labels(runner, **{".checkout": None}),
            self.owner_labels(runner, **{".run": None}),
            self.owner_labels(runner, **{".run": ""}),
            self.owner_labels(runner, **{".run": " "}),
            self.owner_labels(runner, **{".run": ["old"]}),
            self.owner_labels(runner, **{".pid": None}),
            self.owner_labels(runner, **{".pid": "broken"}),
            self.owner_labels(runner, **{".pid": "0"}),
            self.owner_labels(runner, **{".pid": "-1"}),
            self.owner_labels(runner, **{".pid": "2147483648"}),
            self.owner_labels(runner, **{".pid": "9" * 5000}),
            self.owner_labels(runner, **{".pid": 1234}),
            self.owner_labels(runner, **{".keep": "1"}),
            self.owner_labels(runner, **{".keep": None}),
            self.owner_labels(runner, **{"": "0"}),
            {"vpn-installer.audit": "1", "vpn-installer.audit.run": "old"},
            None,
            [],
        ]
        resources = {}
        for kind in ("container", "network"):
            for item in labels:
                resources[f"{len(resources) + 1:064x}"] = (kind, item)
        with patch.object(audit_runner, "process_is_running", side_effect=lambda pid: pid != 1234):
            calls = self.cleanup_calls(runner, resources)
        removals = [args for args in calls if args[1] == "rm" or args[1:3] == ["network", "rm"]]
        self.assertEqual(removals, [
            ["docker", "rm", "-f", f"{1:064x}"],
            ["docker", "network", "rm", f"{len(labels) + 1:064x}"],
        ])
        for args in calls:
            if "--filter" in args:
                self.assertIn(f"label=vpn-installer.audit.checkout={runner.checkout_id}", args)
                self.assertIn("--no-trunc", args)

    def test_cleanup_does_not_probe_a_foreign_checkout_owner(self) -> None:
        runner = self.make_runner()
        other = self.make_runner()
        other.checkout_id = "another-checkout"
        resources = {
            "a" * 64: ("container", self.owner_labels(other)),
            "b" * 64: ("network", self.owner_labels(other)),
        }
        with patch.object(audit_runner, "process_is_running", side_effect=AssertionError("foreign PID must not be checked")):
            calls = self.cleanup_calls(runner, resources)
        self.assertFalse(any(args[1] == "rm" or args[1:3] == ["network", "rm"] for args in calls))

    def test_cleanup_preserves_live_owner_even_without_lock_file(self) -> None:
        runner = self.make_runner()
        labels = self.owner_labels(runner, **{".pid": str(os.getpid())})
        calls = self.cleanup_calls(runner, {"a" * 64: ("container", labels), "b" * 64: ("network", labels)})
        self.assertFalse(any(args[1] == "rm" or args[1:3] == ["network", "rm"] for args in calls))

    def test_cleanup_preserves_resources_when_inspection_is_unusable(self) -> None:
        runner = self.make_runner()
        for inspect in (completed(1), completed(0, "not-json"), completed(0, "[]"), completed(0, "[{}]"),
                        completed(0, json.dumps([{"Id": "b" * 64, "Labels": self.owner_labels(runner),
                                                 "Config": {"Labels": self.owner_labels(runner)}}]))):
            with self.subTest(inspect=inspect.stdout):
                def docker(_name, args, **_kwargs):
                    return inspect if "inspect" in args else completed(0, "a" * 64)
                with patch.object(runner, "docker", side_effect=docker) as mocked, patch.object(
                    audit_runner, "process_is_running", return_value=False,
                ):
                    runner.cleanup_stale_lab_resources()
                self.assertFalse(any("rm" in call.args[1] for call in mocked.call_args_list))

    def test_cleanup_list_failure_never_deletes_partial_results(self) -> None:
        runner = self.make_runner()
        with patch.object(audit_runner, "require_command"), patch.object(
            audit_runner.subprocess, "run", return_value=completed(1, "a" * 64, "daemon unavailable"),
        ) as mocked:
            with self.assertRaises(audit_runner.AuditFailure):
                runner.cleanup_stale_lab_resources()
        self.assertEqual(mocked.call_count, 1)

    def test_cleanup_rechecks_live_owner_for_each_resource(self) -> None:
        runner = self.make_runner()
        resources = {"a" * 64: ("container", self.owner_labels(runner)),
                     "b" * 64: ("network", self.owner_labels(runner))}
        with patch.object(audit_runner, "process_is_running", side_effect=[False, True]) as probe:
            calls = self.cleanup_calls(runner, resources)
        self.assertEqual(probe.call_count, 2)
        self.assertIn(["docker", "rm", "-f", "a" * 64], calls)
        self.assertNotIn(["docker", "network", "rm", "b" * 64], calls)

    def test_posix_process_probe_treats_unknown_owner_as_live(self) -> None:
        for error, live in ((ProcessLookupError(), False), (PermissionError(), True), (OSError(), True), (None, True)):
            with self.subTest(error=error), patch.object(audit_runner.os, "name", "posix"), patch.object(
                audit_runner.os, "kill", side_effect=error,
            ):
                self.assertEqual(audit_runner.process_is_running(1234), live)

    @unittest.skipUnless(os.name == "nt", "Windows process API")
    def test_windows_process_probe_treats_unknown_owner_as_live_and_closes_handle(self) -> None:
        import ctypes
        kernel = types.SimpleNamespace(OpenProcess=MagicMock(return_value=0), GetExitCodeProcess=MagicMock(), CloseHandle=MagicMock())
        with patch.object(ctypes, "WinDLL", return_value=kernel):
            for error, live in ((87, False), (5, True), (0, True)):
                with self.subTest(error=error), patch.object(ctypes, "get_last_error", return_value=error):
                    self.assertEqual(audit_runner.process_is_running(1234), live)
            kernel.OpenProcess.return_value = 123
            kernel.GetExitCodeProcess.return_value = 0
            self.assertTrue(audit_runner.process_is_running(1234))
            kernel.CloseHandle.assert_called_once_with(123)
            for exit_code, live in ((259, True), (0, False)):
                def queried(_handle, pointer):
                    pointer._obj.value = exit_code
                    return 1
                kernel.GetExitCodeProcess.side_effect = queried
                with self.subTest(exit_code=exit_code):
                    self.assertEqual(audit_runner.process_is_running(1234), live)
            self.assertEqual(kernel.CloseHandle.call_count, 3)

    def test_docker_helpers_delegate(self) -> None:
        runner = self.make_runner()
        with patch.object(audit_runner, "require_command"), patch.object(runner, "run_command", return_value=completed(0)) as run_command:
            runner.docker("ps", ["ps"])
            runner.docker_copy("demo", Path("install.sh"), "/tmp/install.sh")
            runner.docker_cp_from("demo", "/tmp/install.sh", Path("install.sh"))
            runner.docker_network_connect("net", "container", "203.0.113.2")
            runner.lab_curl("demo", "http://example.com/")
        self.assertGreaterEqual(run_command.call_count, 5)
        self.assertTrue(all(call.kwargs["timeout_seconds"] == audit_runner.AUDIT_DOCKER_TIMEOUT_SECONDS for call in run_command.call_args_list))

    def test_docker_container_and_network_cleanup_respects_keep_flag(self) -> None:
        runner = self.make_runner()
        for keep in (False, True):
            runner.keep_docker = keep
            with self.subTest(keep=keep), patch.object(runner, "docker", return_value=completed(0, "a" * 64)) as docker:
                with runner.docker_container("demo", "ubuntu:24.04") as name:
                    self.assertEqual(name, "demo")
                with runner.docker_network("net", "198.18.0.0/24", "198.18.0.1") as name:
                    self.assertEqual(name, "net")
            removals = [call.args[1] for call in docker.call_args_list if "rm" in call.args[1]]
            self.assertEqual(removals, [] if keep else [["rm", "-f", "a" * 64], ["network", "rm", "a" * 64]])
            for call in docker.call_args_list:
                args = call.args[1]
                if "create" in args:
                    self.assertIn(f"vpn-installer.audit.checkout={runner.checkout_id}", args)
                    self.assertIn(f"vpn-installer.audit.pid={runner.owner_pid}", args)
                    self.assertIn(f"vpn-installer.audit.keep={int(keep)}", args)

    def test_create_failure_or_missing_id_never_removes_by_name(self) -> None:
        runner = self.make_runner()
        for create in (completed(0), audit_runner.AuditFailure("name already in use")):
            for context in (runner.docker_container("demo", "ubuntu:24.04"), runner.docker_network("demo")):
                with self.subTest(create=create), patch.object(runner, "docker", side_effect=[create]) as docker:
                    with self.assertRaises(audit_runner.AuditFailure):
                        with context:
                            self.fail("resource not created")
                self.assertEqual(docker.call_count, 1)

    def test_failed_container_start_cleans_up_only_the_created_id(self) -> None:
        runner = self.make_runner()
        with patch.object(runner, "docker", side_effect=[completed(0, "a" * 64), audit_runner.AuditFailure("start failed"), completed(0)]) as docker:
            with self.assertRaisesRegex(audit_runner.AuditFailure, "start failed"):
                with runner.docker_container("demo", "ubuntu:24.04"):
                    self.fail("start failed")
        self.assertEqual(docker.call_args_list[-1].args[1], ["rm", "-f", "a" * 64])

    def test_docker_cleanup_ignores_not_found(self) -> None:
        runner = self.make_runner()
        with patch.object(runner, "docker", return_value=completed(1, stderr="Error response from daemon: network demo not found")):
            runner._docker_cleanup("network-rm-demo", ["network", "rm", "demo"])

    def test_docker_cleanup_accepts_an_idempotent_removal_in_progress(self) -> None:
        runner = self.make_runner()
        with patch.object(
            runner,
            "docker",
            return_value=completed(1, stderr="Error response from daemon: removal of container demo is already in progress"),
        ):
            runner._docker_cleanup("rm-demo", ["rm", "-f", "demo"])

    def test_docker_cleanup_raises_for_other_errors(self) -> None:
        runner = self.make_runner()
        with patch.object(runner, "docker", return_value=completed(1, stderr="permission denied")):
            with self.assertRaises(audit_runner.AuditFailure):
                runner._docker_cleanup("network-rm-demo", ["network", "rm", "demo"])


if __name__ == "__main__":
    unittest.main()
