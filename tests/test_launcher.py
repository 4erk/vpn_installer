from __future__ import annotations

import unittest
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
        with patch("vpn_installer.launcher.main", side_effect=EOFError()):
            self.assertEqual(launcher.run(["install"]), 1)

    def test_launcher_returns_1_on_app_error(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=AppError("boom")):
            self.assertEqual(launcher.run(["install"]), 1)


if __name__ == "__main__":
    unittest.main()
