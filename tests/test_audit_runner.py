from __future__ import annotations

import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vpn_installer.audit import runner as audit_runner


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

    def test_build_parser_parses_flags(self) -> None:
        parser = audit_runner.build_parser()
        args = parser.parse_args(["all", "--json", "--keep-docker"])
        self.assertEqual(args.mode, "all")
        self.assertTrue(args.json)
        self.assertTrue(args.keep_docker)

    def test_runner_record_success_and_failure(self) -> None:
        runner = self.make_runner()
        runner.record("ok", lambda: {"path": "demo"})
        runner.record("fail", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        self.assertEqual(runner.results[0].status, "passed")
        self.assertEqual(runner.results[1].status, "failed")
        self.assertEqual(runner.failures, 1)

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
        with patch("vpn_installer.audit.runner.subprocess.run", return_value=completed(0)), patch.object(runner, "docker") as docker:
            runner.ensure_audit_image()
        docker.assert_not_called()
        self.assertTrue(runner.base_image_ready)

        runner = self.make_runner()
        with patch("vpn_installer.audit.runner.subprocess.run", return_value=completed(1)), patch.object(runner, "docker") as docker:
            runner.ensure_audit_image()
        docker.assert_called_once()
        self.assertTrue(runner.base_image_ready)

    def test_create_env_and_seed_cache(self) -> None:
        runner = self.make_runner()
        env_path, env = runner.create_env("demo", {"WAN_INTERFACE": "eth9"})
        self.assertTrue(env_path.is_file())
        self.assertEqual(env["WAN_INTERFACE"], "eth9")
        assets = runner.seed_foreign_block_cache(env["DEPLOY_NAME"])
        self.assertTrue((assets / "ru-ipv4.zone").is_file())

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
            self.assertTrue((copied / "vpn_installer").is_dir())

    def test_ensure_quick_env_rewrites_ips(self) -> None:
        runner = self.make_runner()
        env_path, out_dir = runner.ensure_quick_env()
        text = env_path.read_text(encoding="utf-8")
        self.assertIn("203.0.113.10", text)
        self.assertTrue(str(out_dir).endswith("quick"))

    def test_cleanup_stale_lab_resources_filters_names(self) -> None:
        runner = self.make_runner()
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            calls.append(args)
            if args[:5] == ["docker", "ps", "-a", "--filter", "label=vpn-installer.audit=1"]:
                return completed(0, stdout="ru-123-all\nclient-123-lab\n")
            if args[:5] == ["docker", "network", "ls", "--filter", "label=vpn-installer.audit=1"]:
                return completed(0, stdout="audit-front-123-all\naudit-ru-123-lab\n")
            return completed(0)

        with patch("vpn_installer.audit.runner.subprocess.run", side_effect=fake_run):
            runner.cleanup_stale_lab_resources()
        self.assertIn(["docker", "rm", "-f", "ru-123-all"], calls)
        self.assertIn(["docker", "rm", "-f", "client-123-lab"], calls)
        self.assertIn(["docker", "network", "rm", "audit-front-123-all"], calls)
        self.assertIn(["docker", "network", "rm", "audit-ru-123-lab"], calls)

    def test_docker_helpers_delegate(self) -> None:
        runner = self.make_runner()
        with patch.object(audit_runner, "require_command"), patch.object(runner, "run_command", return_value=completed(0)) as run_command:
            runner.docker("ps", ["ps"])
            runner.docker_copy("demo", Path("install.sh"), "/tmp/install.sh")
            runner.docker_cp_from("demo", "/tmp/install.sh", Path("install.sh"))
            runner.docker_network_connect("net", "container", "203.0.113.2")
            runner.lab_curl("demo", "http://example.com/")
        self.assertGreaterEqual(run_command.call_count, 5)

    def test_docker_container_and_network_cleanup_respects_keep_flag(self) -> None:
        runner = self.make_runner()
        with patch.object(runner, "docker", return_value=completed(0)) as docker:
            with runner.docker_container("demo", "ubuntu:24.04"):
                pass
            with runner.docker_network("net", "198.18.0.0/24", "198.18.0.1"):
                pass
        self.assertTrue(any("rm-demo" in call.args[0] for call in docker.call_args_list))
        self.assertTrue(any("network-rm-net" in call.args[0] for call in docker.call_args_list))

    def test_docker_cleanup_ignores_not_found(self) -> None:
        runner = self.make_runner()
        with patch.object(runner, "docker", return_value=completed(1, stderr="Error response from daemon: network demo not found")):
            runner._docker_cleanup("network-rm-demo", ["network", "rm", "demo"])

    def test_docker_cleanup_raises_for_other_errors(self) -> None:
        runner = self.make_runner()
        with patch.object(runner, "docker", return_value=completed(1, stderr="permission denied")):
            with self.assertRaises(audit_runner.AuditFailure):
                runner._docker_cleanup("network-rm-demo", ["network", "rm", "demo"])


if __name__ == "__main__":
    unittest.main()
