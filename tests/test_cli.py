from __future__ import annotations

import unittest
from unittest.mock import patch

from vpn_installer import cli


class CliTests(unittest.TestCase):
    def test_zero_arg_calls_menu(self) -> None:
        with patch("vpn_installer.cli.menu_workflow", return_value=0) as mocked:
            self.assertEqual(cli.main([]), 0)
        mocked.assert_called_once()

    def test_install_help_parser_exists(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["install", "--deployment", "demo"])
        self.assertEqual(args.deployment, "demo")

    def test_audit_dispatch(self) -> None:
        with patch("vpn_installer.audit.runner.main", return_value=0) as mocked:
            self.assertEqual(cli.main(["audit", "quick"]), 0)
        mocked.assert_called_once()

    def test_audit_dispatch_forwards_flags(self) -> None:
        with patch("vpn_installer.audit.runner.main", return_value=7) as mocked:
            self.assertEqual(cli.main(["audit", "--json", "--keep-docker", "docker"]), 7)
        mocked.assert_called_once_with(["--json", "--keep-docker", "docker"])

    def test_cleanup_local_parser_flags(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["cleanup-local", "--deployment", "demo", "--drop-env", "--drop-runtime"])
        self.assertTrue(args.drop_env)
        self.assertTrue(args.drop_runtime)

    def test_reinstall_parser_has_role(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["reinstall", "--deployment", "demo", "--role", "ru-gateway"])
        self.assertEqual(args.role, "ru-gateway")

    def test_android_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.android_diagnose", return_value=0) as mocked:
            self.assertEqual(cli.main(["android-diagnose", "--serial", "ABC123", "--logcat-lines", "50"]), 0)
        mocked.assert_called_once_with(serial="ABC123", package_name="app.hiddify.com", logcat_lines=50)


if __name__ == "__main__":
    unittest.main()
