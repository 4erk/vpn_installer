from __future__ import annotations

import builtins
import unittest
from unittest.mock import patch

from vpn_installer.models import ROLE_RU, RemoteTarget
from vpn_installer.prompts import has_saved_connection, prompt_server_connection, select_deployment


class PromptTests(unittest.TestCase):
    def test_has_saved_connection_requires_core_fields(self) -> None:
        self.assertFalse(has_saved_connection({}))
        self.assertTrue(has_saved_connection({"public_ip": "1.1.1.1", "ssh_host": "1.1.1.1", "ssh_port": "22", "ssh_user": "root"}))

    def test_prompt_server_connection_key_flow(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10")
        answers = iter(["203.0.113.10", "22", "root", "1", "n", ""])
        with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
            updated = prompt_server_connection(target, force_prompt=True, confirm_existing=True)
        self.assertEqual(updated.ssh_host, "203.0.113.10")
        self.assertEqual(updated.auth_mode, "key")

    def test_prompt_server_connection_password_reuses_saved(self) -> None:
        target = RemoteTarget(
            role=ROLE_RU,
            public_ip="203.0.113.10",
            ssh_host="203.0.113.10",
            ssh_port=22,
            ssh_user="root",
            auth_mode="password",
            saved_connection=True,
        )
        answers = iter(["1"])
        with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
            with patch("getpass.getpass", return_value="secret"):
                updated = prompt_server_connection(target, force_prompt=False, confirm_existing=True)
        self.assertEqual(updated.ssh_password, "secret")
        self.assertEqual(updated.auth_mode, "password")

    def test_select_deployment_blank_prefers_new(self) -> None:
        answers = iter(["", "my new vpn"])
        with patch("vpn_installer.prompts.find_existing_deployments", return_value=["alpha", "beta"]):
            with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
                selected = select_deployment(None)
        self.assertEqual(selected, "my-new-vpn")


if __name__ == "__main__":
    unittest.main()
