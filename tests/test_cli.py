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

    def test_cleanup_local_parser_flags(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["cleanup-local", "--deployment", "demo", "--drop-env", "--drop-runtime"])
        self.assertTrue(args.drop_env)
        self.assertTrue(args.drop_runtime)


if __name__ == "__main__":
    unittest.main()
