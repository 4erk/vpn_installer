from __future__ import annotations

import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from vpn_installer import launcher
from vpn_installer.models import AppError, UserCancelled


class LauncherTests(unittest.TestCase):
    def test_launcher_returns_success_code(self) -> None:
        with patch("vpn_installer.launcher.main", return_value=0):
            self.assertEqual(launcher.run(["status"]), 0)

    def test_launcher_returns_130_on_user_cancelled(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=UserCancelled("cancelled")):
            self.assertEqual(launcher.run(["install"]), 130)

    def test_launcher_returns_130_on_keyboard_interrupt(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=KeyboardInterrupt()):
            self.assertEqual(launcher.run(["install"]), 130)

    def test_launcher_returns_1_on_eof(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=EOFError()), patch("vpn_installer.launcher.log_exception", return_value=Path("out/logs/runtime/error.log")), patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["install"]), 1)
        self.assertIn(str(Path("out/logs/runtime/error.log")), stream.getvalue())

    def test_launcher_returns_1_on_app_error(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=AppError("boom")), patch("vpn_installer.launcher.log_exception", return_value=Path("out/logs/runtime/error.log")), patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["install"]), 1)
        self.assertIn("Ошибка: boom", stream.getvalue())
        self.assertIn(str(Path("out/logs/runtime/error.log")), stream.getvalue())

    def test_launcher_returns_1_on_unhandled_error_and_mentions_log(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=RuntimeError("boom")), patch("vpn_installer.launcher.log_exception", return_value=Path("out/logs/runtime/error.log")), patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["install"]), 1)
        self.assertIn("Непредвиденная ошибка: boom", stream.getvalue())
        self.assertIn(str(Path("out/logs/runtime/error.log")), stream.getvalue())

    def test_launcher_does_not_log_audit_failure_to_runtime_log(self) -> None:
        AuditFailure = type("AuditFailure", (RuntimeError,), {})
        AuditFailure.__module__ = "vpn_installer.audit.runner"
        with patch("vpn_installer.launcher.main", side_effect=AuditFailure("Не найдена команда: docker")), patch("vpn_installer.launcher.log_exception") as log_mock, patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["audit", "quick"]), 1)
        log_mock.assert_not_called()
        self.assertIn("Самопроверка завершилась с ошибкой", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
