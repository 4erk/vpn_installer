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

    def test_audit_interop_dispatch(self) -> None:
        with patch("vpn_installer.audit.runner.main", return_value=0) as mocked:
            self.assertEqual(cli.main(["audit", "interop"]), 0)
        mocked.assert_called_once_with(["interop"])

    def test_cleanup_local_parser_flags(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["cleanup-local", "--deployment", "demo", "--drop-env", "--drop-runtime"])
        self.assertTrue(args.drop_env)
        self.assertTrue(args.drop_runtime)

    def test_reinstall_parser_has_role(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["reinstall", "--deployment", "demo", "--role", "ru-gateway"])
        self.assertEqual(args.role, "ru-gateway")

    def test_reinstall_dispatch_forwards_unattended_flags(self) -> None:
        with patch("vpn_installer.cli.remote_action_workflow", return_value=0) as mocked:
            self.assertEqual(
                cli.main(["reinstall", "--deployment", "demo", "--role", "all", "--non-interactive", "--yes"]),
                0,
            )
        mocked.assert_called_once_with("demo", "all", "reinstall", non_interactive=True, yes=True)

    def test_status_dispatch_forwards_non_interactive(self) -> None:
        with patch("vpn_installer.cli.status_workflow", return_value=0) as mocked:
            self.assertEqual(cli.main(["status", "--deployment", "demo", "--role", "all", "--non-interactive"]), 0)
        mocked.assert_called_once_with("demo", "all", non_interactive=True)

    def test_android_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.android_diagnose", return_value=0) as mocked:
            self.assertEqual(cli.main(["android-diagnose", "--serial", "ABC123", "--logcat-lines", "50"]), 0)
        mocked.assert_called_once_with(serial="ABC123", package_name="app.hiddify.com", logcat_lines=50)

    def test_path_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.diagnose_path_workflow", return_value=0) as mocked:
            self.assertEqual(cli.main(["diagnose", "path", "--deployment", "demo", "--role", "all", "--iperf", "--non-interactive"]), 0)
        mocked.assert_called_once_with("demo", "all", iperf=True, non_interactive=True)

    def test_client_log_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.diagnose_client_log_workflow", return_value=1) as mocked:
            self.assertEqual(cli.main(["diagnose", "client-log", "--path", "client.log", "--deployment", "demo", "--role", "ru-gateway"]), 1)
        mocked.assert_called_once_with("client.log", deployment="demo", role="ru-gateway")

    def test_front_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.diagnose_front_workflow", return_value=1) as mocked:
            self.assertEqual(cli.main(["diagnose", "front", "--deployment", "demo", "--source-ip", "203.0.113.44", "--minutes", "60", "--non-interactive"]), 1)
        mocked.assert_called_once_with("demo", source_ip="203.0.113.44", minutes=60, non_interactive=True)

    def test_verify_live_dispatch(self) -> None:
        with patch("vpn_installer.cli.verify_live_workflow", return_value=0) as mocked:
            self.assertEqual(cli.main(["verify", "live", "--deployment", "demo", "--non-interactive"]), 0)
        mocked.assert_called_once_with("demo", non_interactive=True, throughput_seconds=0)


if __name__ == "__main__":
    unittest.main()
