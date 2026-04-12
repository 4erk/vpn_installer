from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vpn_installer.config import generate_default_env
from vpn_installer.models import AppError, ROLE_FOREIGN, ROLE_RU, RemoteTarget, UserCancelled
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

    def test_update_env_with_targets(self) -> None:
        env = {}
        workflows.update_env_with_targets(
            env,
            [
                RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10"),
                RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20"),
            ],
        )
        self.assertEqual(env["RU_PUBLIC_IP"], "203.0.113.10")
        self.assertEqual(env["FOREIGN_PUBLIC_IP"], "198.51.100.20")

    def test_ensure_foreign_wan_interface_prefers_detected_value(self) -> None:
        env = {"WAN_INTERFACE": ""}
        workflows.ensure_foreign_wan_interface(env, {"default_iface": "ens3"})
        self.assertEqual(env["WAN_INTERFACE"], "ens3")

    def test_ensure_foreign_wan_interface_prompts_when_detection_missing(self) -> None:
        env = {"WAN_INTERFACE": ""}
        with patch("vpn_installer.prompts.prompt_value", return_value="eth9"):
            workflows.ensure_foreign_wan_interface(env, {})
        self.assertEqual(env["WAN_INTERFACE"], "eth9")

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

    def test_verify_target_interactively_cancel_raises_user_cancelled(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.workflows.prompt_server_connection", return_value=target):
            with patch("vpn_installer.workflows.remote_preflight", side_effect=AppError("boom")):
                with patch("vpn_installer.workflows.prompt_choice", return_value="cancel"):
                    with self.assertRaises(UserCancelled):
                        workflows.verify_target_interactively(
                            target,
                            wg_interface="wg0",
                            require_privilege=False,
                            validate_os=False,
                            confirm_existing_connection=False,
                        )

    def test_verify_target_interactively_retries_and_then_succeeds(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root", auth_mode="password")
        preflights = [AppError("boom"), {"os_id": "ubuntu", "os_version": "24.04", "default_iface": "eth0"}]
        with patch("vpn_installer.workflows.prompt_server_connection", return_value=target), patch("vpn_installer.workflows.remote_preflight", side_effect=preflights), patch("vpn_installer.workflows.prompt_choice", return_value="retry"), patch("vpn_installer.workflows.print_preflight"), patch("vpn_installer.workflows.time", create=True):
            updated, preflight = workflows.verify_target_interactively(
                target,
                wg_interface="wg0",
                require_privilege=False,
                validate_os=True,
                confirm_existing_connection=False,
            )
        self.assertIs(updated, target)
        self.assertEqual(preflight["os_id"], "ubuntu")
        self.assertEqual(target.ssh_password, "")

    def test_verify_target_interactively_checks_remote_privilege(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.workflows.prompt_server_connection", return_value=target), patch("vpn_installer.workflows.remote_preflight", return_value={"os_id": "ubuntu", "os_version": "24.04"}), patch("vpn_installer.workflows.print_preflight"), patch("vpn_installer.workflows.ensure_remote_privilege") as mocked:
            workflows.verify_target_interactively(
                target,
                wg_interface="wg0",
                require_privilege=True,
                validate_os=True,
                confirm_existing_connection=False,
            )
        mocked.assert_called_once()

    def test_prepare_remote_session_persists_only_selected_roles(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10")
        with patch("vpn_installer.workflows.ensure_directories"), patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.load_existing_deployment_env", return_value=(Path("deployments/demo.env"), {"DEPLOY_NAME": "demo", "WG_INTERFACE": "wgx"})), patch("vpn_installer.workflows.load_state", return_value={}), patch("vpn_installer.workflows.verify_target_interactively", return_value=(ru, {"default_iface": "eth0"})), patch("vpn_installer.workflows.write_text") as write_text_mock, patch("vpn_installer.workflows.write_state") as write_state_mock:
            name, env_path, env, _state, targets, preflights = workflows.prepare_remote_session(
                "demo",
                roles=[ROLE_RU],
                require_privilege=False,
                allow_create=False,
                persist_local=True,
            )
        self.assertEqual(name, "demo")
        self.assertEqual(env_path, Path("deployments/demo.env"))
        self.assertEqual(len(targets), 1)
        self.assertIn(ROLE_RU, preflights)
        write_text_mock.assert_called_once()
        write_state_mock.assert_called_once()

    def test_postcheck_command_uses_selected_interface(self) -> None:
        command = workflows.postcheck_command("wg-test")
        self.assertIn("wg-quick@wg-test", command)

    def test_cleanup_remote_workdir_warns_on_error(self) -> None:
        with patch("vpn_installer.workflows.ssh_stream", side_effect=AppError("fail")), patch("vpn_installer.workflows.warn") as warn_mock:
            workflows.cleanup_remote_workdir(RemoteTarget(role=ROLE_RU), "vpn-installer/demo")
        warn_mock.assert_called_once()

    def test_install_remote_role_uses_bundle_for_install(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        target = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out" / "demo" / "bundle"
            out_dir.mkdir(parents=True)
            bundle = out_dir / "ru-gateway.tar.gz"
            bundle.write_text("bundle", encoding="utf-8")
            with patch("vpn_installer.workflows.deployment_out_dir", return_value=Path(tmp) / "out" / "demo"), patch("vpn_installer.workflows.ssh_stream") as ssh_mock, patch("vpn_installer.workflows.scp_upload") as scp_mock:
                workflows.install_remote_role(target, "demo", env, "install")
        scp_mock.assert_called_once()
        self.assertTrue(ssh_mock.call_count >= 2)

    def test_install_remote_role_uses_install_script_for_remove(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        with patch("vpn_installer.workflows.ssh_stream") as ssh_mock, patch("vpn_installer.workflows.scp_upload") as scp_mock:
            workflows.install_remote_role(target, "demo", {}, "remove")
        scp_mock.assert_called_once()
        self.assertTrue(ssh_mock.call_count >= 2)

    def test_postcheck_remote_role_streams_command(self) -> None:
        with patch("vpn_installer.workflows.ssh_stream") as mocked:
            workflows.postcheck_remote_role(RemoteTarget(role=ROLE_RU), "wg0")
        mocked.assert_called_once()

    def test_load_env_for_render_rewrites_existing_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "demo.env"
            env_path.write_text('DEPLOY_NAME="demo"\nRU_PUBLIC_IP="203.0.113.10"\nFOREIGN_PUBLIC_IP="198.51.100.20"\n', encoding="utf-8")
            with patch("vpn_installer.workflows.write_text") as write_text_mock:
                env = workflows.load_env_for_render(env_path)
        self.assertEqual(env["DEPLOY_NAME"], "demo")
        write_text_mock.assert_called_once()

    def test_run_selected_remote_action_install_orders_roles(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        order: list[str] = []

        def remember(target: RemoteTarget, *_args, **_kwargs):
            order.append(target.role)

        with patch("vpn_installer.workflows.render_all_artifacts"), patch("vpn_installer.workflows.install_remote_role", side_effect=remember), patch("vpn_installer.workflows.postcheck_remote_role"):
            workflows.run_selected_remote_action("install", "demo", Path("deployments/demo.env"), env, [ru, foreign], role_arg="all")
        self.assertEqual(order, [ROLE_FOREIGN, ROLE_RU])

    def test_install_workflow_returns_zero_when_all_skipped(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {ROLE_FOREIGN: {"default_iface": "eth1"}, ROLE_RU: {}})), patch("vpn_installer.workflows.ensure_foreign_wan_interface"), patch("vpn_installer.workflows.write_text"), patch("vpn_installer.workflows.write_state"), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.ask_install_action", return_value="skip"):
            self.assertEqual(workflows.install_workflow("demo"), 0)

    def test_install_workflow_runs_selected_actions(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {ROLE_FOREIGN: {"default_iface": "eth1"}, ROLE_RU: {}})), patch("vpn_installer.workflows.ensure_foreign_wan_interface"), patch("vpn_installer.workflows.write_text"), patch("vpn_installer.workflows.write_state"), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.ask_install_action", side_effect=["skip", "install"]), patch("vpn_installer.workflows.prompt_yes_no", return_value=True), patch("vpn_installer.workflows.render_all_artifacts") as render_all, patch("vpn_installer.workflows.install_remote_role") as install_remote, patch("vpn_installer.workflows.postcheck_remote_role") as postcheck, patch("vpn_installer.workflows.finalize_install_output") as finalize:
            self.assertEqual(workflows.install_workflow("demo"), 0)
        render_all.assert_called_once()
        install_remote.assert_called_once()
        postcheck.assert_called_once()
        finalize.assert_called_once_with(env, "demo")

    def test_remote_action_workflow_stops_on_user_decline(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru], {ROLE_RU: {}})), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.prompt_yes_no", return_value=False):
            self.assertEqual(workflows.remote_action_workflow("demo", ROLE_RU, "remove"), 0)

    def test_remote_action_workflow_reinstall_updates_env_and_finalizes(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [foreign], {ROLE_FOREIGN: {"default_iface": "eth1"}})), patch("vpn_installer.workflows.ensure_foreign_wan_interface"), patch("vpn_installer.workflows.write_text") as write_text_mock, patch("vpn_installer.workflows.write_state") as write_state_mock, patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.prompt_yes_no", return_value=True), patch("vpn_installer.workflows.run_selected_remote_action") as run_selected, patch("vpn_installer.workflows.finalize_install_output") as finalize:
            self.assertEqual(workflows.remote_action_workflow("demo", ROLE_FOREIGN, "reinstall"), 0)
        write_text_mock.assert_called_once()
        write_state_mock.assert_called_once()
        run_selected.assert_called_once()
        finalize.assert_called_once_with(env, "demo")

    def test_status_workflow_prints_summary_without_mutation(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru], {})), patch("vpn_installer.workflows.print_summary") as mocked:
            self.assertEqual(workflows.status_workflow("demo", ROLE_RU), 0)
        mocked.assert_called_once()

    def test_menu_workflow_dispatches_audit_and_exit(self) -> None:
        with patch("vpn_installer.workflows.prompt_choice", side_effect=["audit", "quick"]), patch("vpn_installer.audit.runner.main", return_value=0) as audit_main:
            self.assertEqual(workflows.menu_workflow(), 0)
        audit_main.assert_called_once_with(["quick"])

        with patch("vpn_installer.workflows.prompt_choice", return_value="exit"):
            self.assertEqual(workflows.menu_workflow(), 0)

        with patch("vpn_installer.workflows.prompt_choice", return_value="cleanup-local"), patch("vpn_installer.workflows.cleanup_local_workflow", return_value=0) as cleanup:
            self.assertEqual(workflows.menu_workflow(), 0)
        cleanup.assert_called_once_with(None, drop_env=False, drop_runtime=False)

        with patch("vpn_installer.workflows.prompt_choice", return_value="status"), patch("vpn_installer.workflows.select_role_for_menu", return_value=ROLE_RU), patch("vpn_installer.workflows.status_workflow", return_value=0) as status:
            self.assertEqual(workflows.menu_workflow(), 0)
        status.assert_called_once_with(None, ROLE_RU)

    def test_cleanup_local_reports_when_nothing_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(workflows, "OUT_DIR", Path(tmp) / "out"), patch.object(workflows, "DEPLOYMENTS_DIR", Path(tmp) / "deployments"), patch.object(workflows, "RUNTIME_DIR", Path(tmp) / ".runtime"), patch.object(workflows, "select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.ensure_directories"), patch("sys.stdout", new_callable=__import__('io').StringIO) as stream:
                self.assertEqual(workflows.cleanup_local_workflow(None, drop_env=False, drop_runtime=False), 0)
        self.assertIn("не найдены", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
