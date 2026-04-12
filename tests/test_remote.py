from __future__ import annotations

import unittest
from unittest.mock import patch

from vpn_installer.models import ROLE_RU, RemoteTarget
from vpn_installer.remote import build_remote_command, preflight_script, use_python_ssh_backend


class RemoteTests(unittest.TestCase):
    def test_preflight_uses_configured_interface(self) -> None:
        self.assertIn("wg-quick@wg-test", preflight_script("wg-test"))

    def test_password_mode_forces_python_backend(self) -> None:
        target = RemoteTarget(role=ROLE_RU, auth_mode="password")
        self.assertTrue(use_python_ssh_backend(target))

    def test_build_remote_command_with_sudo_password(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_user="ubuntu", sudo_mode="password", sudo_password="secret")
        command, input_text = build_remote_command("echo test", target, as_root=True)
        self.assertIn("sudo -S", command)
        self.assertEqual(input_text, "secret\n")

    def test_key_mode_uses_system_ssh_when_available(self) -> None:
        target = RemoteTarget(role=ROLE_RU, auth_mode="key")
        with patch("vpn_installer.remote.command_exists", return_value=True):
            self.assertFalse(use_python_ssh_backend(target))


if __name__ == "__main__":
    unittest.main()
