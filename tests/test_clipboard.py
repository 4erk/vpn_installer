from __future__ import annotations

import unittest
from unittest.mock import patch

from vpn_installer.clipboard import copy_to_clipboard


class ClipboardTests(unittest.TestCase):
    def test_linux_fallback_without_tools(self) -> None:
        with patch("vpn_installer.clipboard.os.name", "posix"):
            with patch("vpn_installer.clipboard.command_exists", return_value=False):
                ok, message = copy_to_clipboard("vless://demo")
        self.assertFalse(ok)
        self.assertIn("Буфер обмена", message)

    def test_windows_powershell_success(self) -> None:
        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        with patch("vpn_installer.clipboard.os.name", "nt"):
            with patch("vpn_installer.clipboard.command_exists", return_value=True):
                with patch("vpn_installer.clipboard.run_command", return_value=Completed()):
                    ok, _message = copy_to_clipboard("vless://demo")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
