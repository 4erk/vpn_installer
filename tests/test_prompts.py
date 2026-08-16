from __future__ import annotations

import builtins
import io
import unittest
from unittest.mock import patch

from vpn_installer.models import AppError, ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.prompts import (
    ask_install_action,
    display_target_connection,
    has_saved_connection,
    hydrate_runtime_auth,
    prompt_choice,
    prompt_server_connection,
    prompt_topology,
    prompt_validated_value,
    prompt_yes_no,
    prompt_value,
    select_deployment,
    select_existing_deployment,
    select_node_for_menu,
)


class PromptTests(unittest.TestCase):
    def test_prompt_value_supports_default_and_allow_empty(self) -> None:
        with patch.object(builtins, "input", return_value=""):
            self.assertEqual(prompt_value("Port", default="22"), "22")
        with patch.object(builtins, "input", return_value=""):
            self.assertEqual(prompt_value("Key", allow_empty=True), "")

    def test_prompt_validated_value_retries_after_validation_error(self) -> None:
        answers = iter(["bad", "good"])

        def validator(value: str) -> str:
            if value == "bad":
                raise AppError("nope")
            return value.upper()

        with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
            self.assertEqual(prompt_validated_value("Value", validator=validator), "GOOD")

    def test_prompt_yes_no_accepts_variants(self) -> None:
        with patch.object(builtins, "input", return_value="д"):
            self.assertTrue(prompt_yes_no("ok?", default=False))
        with patch.object(builtins, "input", return_value="нет"):
            self.assertFalse(prompt_yes_no("ok?", default=True))

    def test_prompt_choice_accepts_explicit_value(self) -> None:
        with patch.object(builtins, "input", return_value="password"):
            selected = prompt_choice("mode", [("key", "SSH key"), ("password", "SSH password")], default="key")
        self.assertEqual(selected, "password")

    def test_prompt_choice_rejects_bad_default(self) -> None:
        with self.assertRaises(AppError):
            prompt_choice("mode", [("key", "SSH key")], default="password")

    def test_prompt_topology_collects_single_location(self) -> None:
        with patch("vpn_installer.prompts.prompt_choice", side_effect=["single", "foreign"]):
            self.assertEqual(prompt_topology(), ("single", "foreign"))

    def test_prompt_topology_dual_has_fixed_ru_gateway(self) -> None:
        with patch("vpn_installer.prompts.prompt_choice", return_value="dual") as choose:
            self.assertEqual(prompt_topology(current_location="foreign"), ("dual", "ru"))
        choose.assert_called_once()

    def test_has_saved_connection_requires_core_fields(self) -> None:
        self.assertFalse(has_saved_connection({}))
        self.assertFalse(has_saved_connection({"public_ip": "1.1.1.1", "ssh_host": "1.1.1.1", "ssh_port": "22", "ssh_user": "root"}))
        self.assertTrue(has_saved_connection({"public_ip": "1.1.1.1", "ssh_host": "1.1.1.1", "ssh_port": "22", "ssh_user": "root", "auth_mode": "password"}))

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

    def test_runtime_password_prefers_canonical_node_env_names(self) -> None:
        gateway = RemoteTarget(role=ROLE_RU, auth_mode="password")
        exit_target = RemoteTarget(role=ROLE_FOREIGN, auth_mode="password")
        with patch.dict(
            "os.environ",
            {
                "VPN_GATEWAY_SSH_PASSWORD": "gateway-secret",
                "VPN_RU_SSH_PASSWORD": "legacy-gateway-secret",
                "VPN_EXIT_SSH_PASSWORD": "exit-secret",
                "VPN_FOREIGN_SSH_PASSWORD": "legacy-exit-secret",
            },
            clear=True,
        ):
            self.assertEqual(hydrate_runtime_auth(gateway).ssh_password, "gateway-secret")
            self.assertEqual(hydrate_runtime_auth(exit_target).ssh_password, "exit-secret")

    def test_select_deployment_blank_prefers_new(self) -> None:
        answers = iter(["", "my new vpn"])
        with patch("vpn_installer.prompts.find_existing_deployments", return_value=["alpha", "beta"]):
            with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
                selected = select_deployment(None)
        self.assertEqual(selected, "my-new-vpn")

    def test_select_deployment_prefills_first_install_name(self) -> None:
        with patch("vpn_installer.prompts.find_existing_deployments", return_value=[]), patch.object(builtins, "input", return_value="") as mocked:
            selected = select_deployment(None)
        self.assertEqual(selected, "home-vpn")
        self.assertIn("Enter = home-vpn", mocked.call_args.args[0])

    def test_select_deployment_first_install_accepts_custom_name(self) -> None:
        with patch("vpn_installer.prompts.find_existing_deployments", return_value=[]), patch.object(builtins, "input", return_value="family vpn"):
            selected = select_deployment(None)
        self.assertEqual(selected, "family-vpn")

    def test_display_target_connection_for_saved_password_mode(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_user="root", auth_mode="password", saved_connection=True)
        with patch("sys.stdout", new_callable=io.StringIO) as stream:
            display_target_connection(target)
        self.assertIn("будет запрошен заново", stream.getvalue())

    def test_select_existing_deployment_uses_existing_list(self) -> None:
        with patch("vpn_installer.prompts.find_existing_deployments", return_value=["alpha", "beta"]), patch.object(builtins, "input", return_value="2"):
            selected = select_existing_deployment(None)
        self.assertEqual(selected, "beta")

    def test_select_existing_deployment_fails_when_none_exist(self) -> None:
        with patch("vpn_installer.prompts.find_existing_deployments", return_value=[]):
            with self.assertRaises(AppError):
                select_existing_deployment(None)

    def test_ask_install_action_branches(self) -> None:
        with patch("vpn_installer.prompts.prompt_choice", return_value="install") as mocked:
            self.assertEqual(ask_install_action(ROLE_RU, "demo", {"installed": "0"}), "install")
        mocked.assert_called_once()

        with patch("vpn_installer.prompts.prompt_choice", return_value="skip") as mocked:
            self.assertEqual(ask_install_action(ROLE_RU, "demo", {"installed": "1", "role": ROLE_FOREIGN, "deployment_name": "other"}), "skip")
        mocked.assert_called_once()

    def test_select_node_for_menu_prompts_only_for_node_aware_commands(self) -> None:
        self.assertEqual(select_node_for_menu("install"), "all")
        with patch("vpn_installer.prompts.prompt_choice", return_value="gateway"):
            self.assertEqual(select_node_for_menu("status"), "gateway")


if __name__ == "__main__":
    unittest.main()
