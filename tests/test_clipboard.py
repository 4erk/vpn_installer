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

    def test_windows_returns_process_error(self) -> None:
        class Completed:
            returncode = 1
            stdout = ""
            stderr = "clipboard failed"

        with patch("vpn_installer.clipboard.os.name", "nt"), patch("vpn_installer.clipboard.command_exists", return_value=True), patch("vpn_installer.clipboard.run_command", return_value=Completed()):
            ok, message = copy_to_clipboard("vless://demo")
        self.assertFalse(ok)
        self.assertIn("clipboard failed", message)

    def test_linux_uses_first_available_tool(self) -> None:
        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        with patch("vpn_installer.clipboard.os.name", "posix"), patch("vpn_installer.clipboard.command_exists", side_effect=lambda name: name == "xclip"), patch("vpn_installer.clipboard.run_command", return_value=Completed()) as mocked:
            ok, message = copy_to_clipboard("vless://demo")
        self.assertTrue(ok)
        self.assertIn("xclip", message)
        mocked.assert_called_once()


if __name__ == "__main__":
    unittest.main()
