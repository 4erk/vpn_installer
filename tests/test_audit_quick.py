from __future__ import annotations

import tempfile
import inspect
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.audit import quick
from vpn_installer.audit.quick import coverage_command, coverage_driver_text


class AuditQuickTests(unittest.TestCase):
    def test_coverage_command_uses_embedded_coverage_runner(self) -> None:
        command = coverage_command("report", "--fail-under=90")
        self.assertGreaterEqual(len(command), 4)
        self.assertEqual(command[-2:], ["report", "--fail-under=90"])
        self.assertIn("runpy.run_module('coverage'", command[2])

    def test_coverage_driver_discovers_repo_tests(self) -> None:
        driver = coverage_driver_text()
        self.assertIn("unittest.defaultTestLoader.discover", driver)
        self.assertIn('pattern="test_*.py"', driver)

    def test_quick_render_uses_local_assets_without_network_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "cache"
            out_dir = root / "out" / "demo"
            cache.mkdir()
            cached = {}
            for name in ("geosite-ru.srs", "geoip-ru.srs"):
                path = cache / name
                path.write_bytes(name.encode("ascii"))
                cached[name] = path

            with (
                patch(
                    "vpn_installer.audit.quick.find_cached_asset",
                    side_effect=lambda name, _target: cached.get(name),
                ),
                patch("vpn_installer.audit.quick.render_all_artifacts") as render_all,
            ):
                quick.test_render_all(
                    root / "demo.env",
                    {"FOREIGN_BLOCK_RU": "0"},
                    out_dir,
                    refresh_assets=False,
                )

            self.assertEqual(
                (out_dir / "assets" / "geosite-ru.srs").read_bytes(),
                b"geosite-ru.srs",
            )
            render_all.assert_called_once_with(
                root / "demo.env",
                {"FOREIGN_BLOCK_RU": "0"},
                fetch_assets_first=False,
            )

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
        self.assertIn("quick-linux-launcher-python", fake_runner.skips)

    def test_all_mode_keeps_dev_only_checks_enabled(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.records: list[str] = []
                self.skips: list[str] = []
                self.actions = {}
                self.run_dir = Path(tempfile.mkdtemp())
                self.mode = "all"

            def ensure_quick_env(self):
                return Path("demo.env"), Path("out/demo")

            def seed_foreign_block_cache(self, _name: str) -> None:
                return None

            def ensure_audit_image(self) -> None:
                self.records.append("ensure-audit-image")

            def record(self, name, fn):
                self.records.append(name)
                self.actions[name] = fn

            def skip(self, name, _reason):
                self.skips.append(name)

        fake_runner = FakeRunner()
        docker_info = subprocess.CompletedProcess(["docker", "info"], 0, stdout="ok", stderr="")
        with patch("vpn_installer.audit.quick.shutil.which", return_value="found"), patch("vpn_installer.audit.quick.subprocess.run", return_value=docker_info), patch("vpn_installer.audit.quick.load_env_file", return_value={"DEPLOY_NAME": "demo"}), patch("vpn_installer.audit.quick.test_render_all", return_value={"out_dir": "out/demo"}) as render:
            quick.run(fake_runner)
            self.assertEqual(fake_runner.actions["quick-render-all"](), {"out_dir": "out/demo"})
        self.assertIn("quick-unittest", fake_runner.skips)
        self.assertIn("quick-coverage", fake_runner.records)
        self.assertIn("quick-xray-reality-interop", fake_runner.records)
        self.assertIn("ensure-audit-image", fake_runner.records)
        render.assert_called_once_with(
            Path("demo.env"),
            {"DEPLOY_NAME": "demo"},
            Path("out/demo"),
            refresh_assets=False,
        )

    def test_docker_readiness_treats_missing_daemon_as_unavailable(self) -> None:
        docker_info = subprocess.CompletedProcess(["docker", "info"], 1, stdout="", stderr="daemon down\n")
        with patch("vpn_installer.audit.quick.shutil.which", return_value="docker"), patch("vpn_installer.audit.quick.subprocess.run", return_value=docker_info):
            ready, reason = quick.docker_readiness()
        self.assertFalse(ready)
        self.assertIn("docker daemon недоступен", reason)

    def test_interop_mode_runs_only_reality_interop(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.records: list[str] = []
                self.skips: list[str] = []
                self.run_dir = Path(tempfile.mkdtemp())
                self.mode = "interop"

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
        with (
            patch("vpn_installer.audit.quick.shutil.which", return_value="found"),
            patch("vpn_installer.audit.quick.subprocess.run", return_value=docker_info),
            patch("vpn_installer.audit.quick.load_env_file", return_value={"DEPLOY_NAME": "demo"}),
            patch("vpn_installer.audit.quick.render_all_artifacts") as render_mock,
        ):
            quick.run_interop(fake_runner)  # type: ignore[arg-type]
        self.assertEqual(fake_runner.records, ["ensure-audit-image", "quick-xray-reality-interop"])
        self.assertEqual(fake_runner.skips, [])
        render_mock.assert_called_once()

    def test_reality_interop_uses_domain_probe_not_ipv6_connect_to(self) -> None:
        source = inspect.getsource(quick.test_xray_reality_interop)
        self.assertIn('"https://example.com/"', source)
        self.assertIn('"predefined": {"example.com": ["127.0.0.1"]}', source)
        self.assertIn('router_config["route"]["default_domain_resolver"] = "interop-hosts"', source)
        self.assertNotIn("--connect-to", source)
        self.assertNotIn("2606:2800:220:1:248:1893:25c8:1946", source)


if __name__ == "__main__":
    unittest.main()
