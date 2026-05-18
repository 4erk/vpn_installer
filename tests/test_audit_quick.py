from __future__ import annotations

import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.audit import quick
from vpn_installer.audit.quick import coverage_command, coverage_driver_text, unit_test_modules


class AuditQuickTests(unittest.TestCase):
    def test_coverage_command_uses_embedded_coverage_runner(self) -> None:
        command = coverage_command("report", "--fail-under=90")
        self.assertGreaterEqual(len(command), 4)
        self.assertEqual(command[-2:], ["report", "--fail-under=90"])
        self.assertIn("runpy.run_module('coverage'", command[2])

    def test_coverage_driver_discovers_repo_tests(self) -> None:
        driver = coverage_driver_text()
        self.assertIn("unittest.defaultTestLoader.loadTestsFromName", driver)
        self.assertIn("module_name = sys.argv[1]", driver)
        self.assertTrue(any(name.endswith("test_audit_quick") for name in unit_test_modules()))

    def test_quick_run_skips_docker_and_bash_dependent_checks_when_missing(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.records: list[str] = []
                self.skips: list[str] = []
                self.run_dir = Path(tempfile.mkdtemp())
                self.mode = "quick"

            def ensure_quick_env(self):
                return Path("demo.env"), Path("out/demo")

            def seed_foreign_block_cache(self, _name: str) -> None:
                return None

            def ensure_audit_image(self) -> None:
                raise AssertionError("docker image must not be prepared without docker")

            def record(self, name, _fn):
                self.records.append(name)

            def skip(self, name, _reason):
                self.skips.append(name)

        fake_runner = FakeRunner()
        with patch("vpn_installer.audit.quick.shutil.which", side_effect=lambda name: None if name in {"docker", "bash"} else "found"), patch("vpn_installer.audit.quick.load_env_file", return_value={"DEPLOY_NAME": "demo"}):
            quick.run(fake_runner)
        self.assertIn("quick-unittest", fake_runner.skips)
        self.assertIn("quick-coverage", fake_runner.skips)
        self.assertIn("quick-bash-syntax", fake_runner.skips)
        self.assertIn("quick-singbox-check", fake_runner.skips)
        self.assertIn("quick-linux-launcher-python", fake_runner.skips)

    def test_all_mode_keeps_dev_only_checks_enabled(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.records: list[str] = []
                self.skips: list[str] = []
                self.run_dir = Path(tempfile.mkdtemp())
                self.mode = "all"

            def ensure_quick_env(self):
                return Path("demo.env"), Path("out/demo")

            def seed_foreign_block_cache(self, _name: str) -> None:
                return None

            def ensure_audit_image(self) -> None:
                self.records.append("ensure-audit-image")

            def record(self, name, _fn):
                self.records.append(name)

            def skip(self, name, _reason):
                self.skips.append(name)

        fake_runner = FakeRunner()
        docker_info = subprocess.CompletedProcess(["docker", "info"], 0, stdout="ok", stderr="")
        with patch("vpn_installer.audit.quick.shutil.which", return_value="found"), patch("vpn_installer.audit.quick.subprocess.run", return_value=docker_info), patch("vpn_installer.audit.quick.load_env_file", return_value={"DEPLOY_NAME": "demo"}):
            quick.run(fake_runner)
        self.assertIn("quick-unittest", fake_runner.records)
        self.assertIn("quick-coverage", fake_runner.records)
        self.assertIn("ensure-audit-image", fake_runner.records)

    def test_docker_readiness_treats_missing_daemon_as_unavailable(self) -> None:
        docker_info = subprocess.CompletedProcess(["docker", "info"], 1, stdout="", stderr="daemon down\n")
        with patch("vpn_installer.audit.quick.shutil.which", return_value="docker"), patch("vpn_installer.audit.quick.subprocess.run", return_value=docker_info):
            ready, reason = quick.docker_readiness()
        self.assertFalse(ready)
        self.assertIn("docker daemon недоступен", reason)


if __name__ == "__main__":
    unittest.main()
