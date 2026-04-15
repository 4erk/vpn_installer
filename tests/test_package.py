from __future__ import annotations

import importlib
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.config import render_example_env_text


class PackageTests(unittest.TestCase):
    def test_package_main_is_lazy(self) -> None:
        sys.modules.pop("vpn_installer", None)
        sys.modules.pop("vpn_installer.cli", None)
        package = importlib.import_module("vpn_installer")
        self.assertTrue(callable(package.main))
        self.assertNotIn("vpn_installer.cli", sys.modules)

    def test_deployment_example_matches_generated_contract(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        checked_in = (repo_root / "deployments" / "deployment.env.example").read_text(encoding="utf-8")
        self.assertEqual(checked_in, render_example_env_text())

    def test_package_exposes_version_via_getattr(self) -> None:
        package = importlib.import_module("vpn_installer")
        self.assertEqual(package.__version__, "0.2.1")
        with self.assertRaises(AttributeError):
            package.__getattr__("nope")

    def test_package_main_delegates_to_cli(self) -> None:
        package = importlib.import_module("vpn_installer")
        with patch("vpn_installer.cli.main", return_value=7) as mocked:
            self.assertEqual(package.main(["status"]), 7)
        mocked.assert_called_once_with(["status"])

    def test_module_main_exits_with_cli_code(self) -> None:
        with patch("vpn_installer.main", return_value=3):
            with self.assertRaises(SystemExit) as ctx:
                runpy.run_module("vpn_installer.__main__", run_name="__main__")
        self.assertEqual(ctx.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
