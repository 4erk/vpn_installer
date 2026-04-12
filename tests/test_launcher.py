from __future__ import annotations

import unittest
from unittest.mock import patch

from vpn_installer import launcher
from vpn_installer.models import UserCancelled


class LauncherTests(unittest.TestCase):
    def test_launcher_returns_130_on_user_cancelled(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=UserCancelled("cancelled")):
            self.assertEqual(launcher.run(["install"]), 130)


if __name__ == "__main__":
    unittest.main()
