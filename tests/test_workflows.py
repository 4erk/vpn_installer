from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.config import generate_default_env
from vpn_installer import workflows


class WorkflowTests(unittest.TestCase):
    def test_execution_roles_install_foreign_then_ru(self) -> None:
        self.assertEqual(
            workflows.execution_roles("install", [workflows.ROLE_RU, workflows.ROLE_FOREIGN]),
            [workflows.ROLE_FOREIGN, workflows.ROLE_RU],
        )

    def test_execution_roles_remove_ru_then_foreign(self) -> None:
        self.assertEqual(
            workflows.execution_roles("remove", [workflows.ROLE_RU, workflows.ROLE_FOREIGN]),
            [workflows.ROLE_RU, workflows.ROLE_FOREIGN],
        )

    def test_current_wg_interface_defaults_to_wg0(self) -> None:
        self.assertEqual(workflows.current_wg_interface({}), "wg0")

    def test_requested_roles_all(self) -> None:
        self.assertEqual(workflows.requested_roles("all"), [workflows.ROLE_RU, workflows.ROLE_FOREIGN])

    def test_build_target_from_env_without_state(self) -> None:
        env = {"RU_PUBLIC_IP": "203.0.113.10", "SSH_PORT": "22"}
        target = workflows.build_target(workflows.ROLE_RU, env, {})
        self.assertEqual(target.public_ip, "203.0.113.10")
        self.assertFalse(target.saved_connection)

    def test_cleanup_local_uses_existing_deployment_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out" / "demo"
            state_dir = Path(tmp) / "state"
            deploy_dir = Path(tmp) / "deployments"
            out_dir.mkdir(parents=True)
            state_dir.mkdir(parents=True)
            deploy_dir.mkdir(parents=True)
            (state_dir / "demo.json").write_text("{}", encoding="utf-8")
            (deploy_dir / "demo.env").write_text("DEPLOY_NAME=\"demo\"\n", encoding="utf-8")
            with patch.object(workflows, "OUT_DIR", Path(tmp) / "out"), patch.object(workflows, "DEPLOYMENTS_DIR", deploy_dir), patch.object(workflows, "select_existing_deployment", return_value="demo"):
                rc = workflows.cleanup_local_workflow(None, drop_env=True, drop_runtime=False)
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists())

    def test_finalize_install_output_uses_uri_file(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        with tempfile.TemporaryDirectory() as tmp:
            with patch("vpn_installer.workflows.client_artifact_paths", return_value={"uri": Path(tmp) / "hiddify-uri.txt", "hiddify_json": Path(tmp) / "h.json", "linux_json": Path(tmp) / "l.json", "next_steps": Path(tmp) / "NEXT-STEPS.txt"}):
                with patch("vpn_installer.workflows.copy_to_clipboard", return_value=(False, "no clipboard")):
                    workflows.finalize_install_output(env, "demo")


if __name__ == "__main__":
    unittest.main()
