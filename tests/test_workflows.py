from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vpn_installer.config import generate_default_env
from vpn_installer.localnet import LocalRoute
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

    def test_apply_env_connection_overrides_supports_unattended_password_login(self) -> None:
        target = RemoteTarget(role=ROLE_RU)
        with patch.dict(
            "vpn_installer.workflows.os.environ",
            {
                "VPN_RU_PUBLIC_IP": "203.0.113.10",
                "VPN_RU_SSH_HOST": "ssh.example.test",
                "VPN_RU_SSH_PORT": "2222",
                "VPN_RU_SSH_USER": "root",
                "VPN_RU_SSH_PASSWORD": "secret",
            },
            clear=False,
        ):
            updated = workflows.apply_env_connection_overrides(target)
        self.assertTrue(updated.saved_connection)
        self.assertEqual(updated.public_ip, "203.0.113.10")
        self.assertEqual(updated.ssh_host, "ssh.example.test")
        self.assertEqual(updated.ssh_port, 2222)
        self.assertEqual(updated.ssh_user, "root")
        self.assertEqual(updated.auth_mode, "password")
        self.assertEqual(updated.ssh_password, "secret")

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

    def test_finalize_install_output_prefers_vless_uri(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        with tempfile.TemporaryDirectory() as tmp:
            paths = {
                "vless_uri": Path(tmp) / "vless-uri.txt",
                "hiddify_uri_compat": Path(tmp) / "hiddify-uri.txt",
                "hiddify_json": Path(tmp) / "h.json",
                "android_hiddify_json": Path(tmp) / "h-android.json",
                "linux_json": Path(tmp) / "l.json",
                "windows_xray_json": Path(tmp) / "xray.json",
                "android_xray_json": Path(tmp) / "android-xray.json",
                "windows_route_bypass": Path(tmp) / "windows-route-bypass.ps1",
                "next_steps": Path(tmp) / "NEXT-STEPS.txt",
            }
            paths["vless_uri"].write_text("vless://demo\n", encoding="utf-8")
            paths["hiddify_uri_compat"].write_text("vless://demo\n", encoding="utf-8")
            paths["hiddify_json"].write_text('{"route":{"final":"ru-gateway"}}', encoding="utf-8")
            with patch("vpn_installer.workflows.client_artifact_paths", return_value=paths):
                with patch("vpn_installer.workflows.copy_to_clipboard", return_value=(False, "no clipboard")) as copy_mock:
                    workflows.finalize_install_output(env, "demo")
            copy_mock.assert_called_once_with("vless://demo\n")

    def test_verify_target_interactively_cancel_raises_user_cancelled(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.workflows.prompt_server_connection", return_value=target), patch("vpn_installer.workflows.assert_server_route_not_self_tunneled"):
            with patch("vpn_installer.workflows.remote_preflight", side_effect=AppError("boom")):
                with patch("vpn_installer.workflows.prompt_choice", return_value="cancel"):
                    with self.assertRaises(UserCancelled):
                        workflows.verify_target_interactively(
                            target,
                            env=generate_default_env("demo"),
                            wg_interface="wg0",
                            require_privilege=False,
                            validate_os=False,
                            confirm_existing_connection=False,
                        )

    def test_verify_target_interactively_retries_and_then_succeeds(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root", auth_mode="password")
        preflights = [AppError("boom"), {"os_id": "ubuntu", "os_version": "24.04", "default_iface": "eth0"}]
        with patch("vpn_installer.workflows.prompt_server_connection", return_value=target), patch("vpn_installer.workflows.assert_server_route_not_self_tunneled"), patch("vpn_installer.workflows.remote_preflight", side_effect=preflights), patch("vpn_installer.workflows.prompt_choice", return_value="retry"), patch("vpn_installer.workflows.print_preflight"), patch("vpn_installer.workflows.time", create=True):
            updated, preflight = workflows.verify_target_interactively(
                target,
                env=generate_default_env("demo"),
                wg_interface="wg0",
                require_privilege=False,
                validate_os=True,
                confirm_existing_connection=False,
            )
        self.assertIs(updated, target)
        self.assertEqual(preflight["os_id"], "ubuntu")
        self.assertEqual(target.ssh_password, "")

    def test_verify_target_non_interactively_uses_existing_target_without_prompts(self) -> None:
        target = RemoteTarget(
            role=ROLE_RU,
            public_ip="203.0.113.10",
            ssh_host="203.0.113.10",
            ssh_port=22,
            ssh_user="root",
            auth_mode="password",
            ssh_password="secret",
            saved_connection=True,
        )
        with patch("vpn_installer.workflows.assert_server_route_not_self_tunneled") as route_check, patch("vpn_installer.workflows.remote_preflight", return_value={"os_id": "ubuntu", "os_version": "24.04", "is_root": "1"}) as preflight, patch("vpn_installer.workflows.print_preflight"), patch("vpn_installer.workflows.prompt_server_connection") as prompt:
            updated, result = workflows.verify_target_non_interactively(
                target,
                env=generate_default_env("demo"),
                wg_interface="wg0",
                require_privilege=True,
                validate_os=True,
            )
        self.assertEqual(updated.sudo_mode, "root")
        self.assertEqual(result["os_id"], "ubuntu")
        route_check.assert_called_once()
        preflight.assert_called_once()
        prompt.assert_not_called()

    def test_verify_target_interactively_checks_remote_privilege(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.workflows.prompt_server_connection", return_value=target), patch("vpn_installer.workflows.assert_server_route_not_self_tunneled"), patch("vpn_installer.workflows.remote_preflight", return_value={"os_id": "ubuntu", "os_version": "24.04"}), patch("vpn_installer.workflows.print_preflight"), patch("vpn_installer.workflows.ensure_remote_privilege") as mocked:
            workflows.verify_target_interactively(
                target,
                env=generate_default_env("demo"),
                wg_interface="wg0",
                require_privilege=True,
                validate_os=True,
                confirm_existing_connection=False,
            )
        mocked.assert_called_once()

    def test_verify_target_interactively_blocks_unsaved_self_tunneled_route_before_ssh(self) -> None:
        env = generate_default_env("demo")
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.workflows.prompt_server_connection", return_value=target), patch("vpn_installer.workflows.assert_server_route_not_self_tunneled", side_effect=AppError("идёт через VPN-интерфейс")), patch("vpn_installer.workflows.remote_preflight") as preflight, patch("vpn_installer.workflows.prompt_choice", return_value="cancel"):
            with self.assertRaises(UserCancelled):
                workflows.verify_target_interactively(
                    target,
                    env=env,
                    wg_interface="wg0",
                    require_privilege=False,
                    validate_os=False,
                    confirm_existing_connection=False,
                )
        preflight.assert_not_called()

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

    def test_prepare_remote_session_blocks_saved_self_tunneled_server_route_before_ssh(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        state = {ROLE_RU: {"public_ip": "203.0.113.10", "ssh_host": "203.0.113.10", "ssh_port": "22", "ssh_user": "root", "auth_mode": "password"}}
        with patch("vpn_installer.workflows.ensure_directories"), patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)), patch("vpn_installer.workflows.load_state", return_value=state), patch("vpn_installer.workflows.assert_server_route_not_self_tunneled", side_effect=AppError("идёт через VPN-интерфейс")), patch("vpn_installer.workflows.verify_target_interactively") as verify:
            with self.assertRaises(AppError) as ctx:
                workflows.prepare_remote_session(
                    "demo",
                    roles=[ROLE_RU],
                    require_privilege=False,
                    allow_create=False,
                    persist_local=False,
                )
        verify.assert_not_called()
        self.assertIn("идёт через VPN-интерфейс", str(ctx.exception))

    def test_client_check_workflow_reports_self_tunnel(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        state = {ROLE_RU: {"public_ip": "203.0.113.10", "ssh_host": "203.0.113.10", "ssh_port": "22", "ssh_user": "root", "auth_mode": "password"}}
        with patch("vpn_installer.workflows.ensure_directories"), patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)), patch("vpn_installer.workflows.load_state", return_value=state), patch("vpn_installer.workflows.local_route_to_server", return_value=LocalRoute(target_ip="203.0.113.10", interface_alias="singbox_tun")), patch("vpn_installer.workflows.find_client_drift", return_value=[]):
            self.assertEqual(workflows.client_check_workflow("demo", ROLE_RU), 1)

    def test_client_check_workflow_reports_stale_client_profile(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        state = {ROLE_RU: {"public_ip": "203.0.113.10", "ssh_host": "203.0.113.10", "ssh_port": "22", "ssh_user": "root", "auth_mode": "password"}}
        finding = __import__("vpn_installer.client_drift", fromlist=["ClientDriftFinding"]).ClientDriftFinding(Path("hiddify.json"), "устаревший порт клиента: 443, ожидается 8443")
        with patch("vpn_installer.workflows.ensure_directories"), patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)), patch("vpn_installer.workflows.load_state", return_value=state), patch("vpn_installer.workflows.local_route_to_server", return_value=LocalRoute(target_ip="203.0.113.10", interface_alias="Беспроводная сеть")), patch("vpn_installer.workflows.find_client_drift", return_value=[finding]), patch("sys.stdout", new_callable=__import__("io").StringIO) as stream:
            self.assertEqual(workflows.client_check_workflow("demo", ROLE_RU), 1)
        self.assertIn("STALE: hiddify.json", stream.getvalue())

    def test_load_remote_authoritative_env_syncs_local_file_and_client_artifacts(self) -> None:
        local_env = generate_default_env("demo")
        local_env["RU_PUBLIC_IP"] = "203.0.113.10"
        local_env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        remote_env = {**local_env, "CLIENT_UUID": "remote-uuid", "RU_REALITY_PUBLIC_KEY": "remote-key"}
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_user="root")
        with patch("vpn_installer.workflows.fetch_remote_deployment_env", return_value=workflows.render_env_text(remote_env)), patch("vpn_installer.workflows.write_text") as write_text_mock, patch("vpn_installer.workflows.render_client_profiles") as render_client_profiles_mock:
            synced_env, synced = workflows.load_remote_authoritative_env(
                "demo",
                Path("deployments/demo.env"),
                local_env,
                [target],
                {ROLE_RU: {"installed": "1", "deployment_name": "demo", "role": ROLE_RU}},
            )
        self.assertTrue(synced)
        self.assertEqual(synced_env["CLIENT_UUID"], "remote-uuid")
        self.assertEqual(synced_env["RU_REALITY_PUBLIC_KEY"], "remote-key")
        self.assertEqual(target.public_ip, "203.0.113.10")
        write_text_mock.assert_called_once()
        render_client_profiles_mock.assert_called_once_with(synced_env)

    def test_load_remote_authoritative_env_fails_closed_on_remote_mismatch(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru_target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_user="root")
        foreign_target = RemoteTarget(role=ROLE_FOREIGN, public_ip="198.51.100.20", ssh_host="198.51.100.20", ssh_user="root")
        ru_remote = workflows.render_env_text(env)
        foreign_env = {**env, "CLIENT_UUID": "different"}
        foreign_remote = workflows.render_env_text(foreign_env)
        with patch("vpn_installer.workflows.fetch_remote_deployment_env", side_effect=[ru_remote, foreign_remote]):
            with self.assertRaises(AppError) as ctx:
                workflows.load_remote_authoritative_env(
                    "demo",
                    Path("deployments/demo.env"),
                    env,
                    [ru_target, foreign_target],
                    {
                        ROLE_RU: {"installed": "1", "deployment_name": "demo", "role": ROLE_RU},
                        ROLE_FOREIGN: {"installed": "1", "deployment_name": "demo", "role": ROLE_FOREIGN},
                    },
                )
        self.assertIn("Remote env mismatch between roles", str(ctx.exception))

    def test_postcheck_command_uses_selected_interface(self) -> None:
        command = workflows.postcheck_command(ROLE_RU, "wg-test")
        self.assertIn("wg-quick@wg-test", command)
        self.assertIn("check_service_active", command)
        self.assertIn("postcheck_failed_service", command)
        self.assertIn('if [[ "$state" == "active" ]]', command)
        self.assertIn('if [[ "$state" != "activating" ]]', command)
        self.assertIn("sleep 1", command)
        self.assertIn("journalctl -u \"$service\" -n 20 --no-pager", command)
        self.assertIn("check_service_active sing-box sing-box", command)
        self.assertIn("check_service_active vpn-stack-xray.service vpn-stack-xray", command)
        self.assertIn("check_service_active vpn-stack-health.timer vpn-stack-health.timer", command)
        self.assertNotIn("vpn-stack-subscription.service", command)

        foreign_command = workflows.postcheck_command(ROLE_FOREIGN, "wg-test")
        self.assertNotIn("check_service_active sing-box sing-box", foreign_command)

    def test_deployment_health_snapshot_reports_expected_verdicts(self) -> None:
        env = generate_default_env("demo")
        healthy = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {"wg_observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "20", "deep_ru_wg_download_min_bps": "800000", "deep_ru_wg_upload_bps": "1200000"},
                ROLE_FOREIGN: {"observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "15", "deep_foreign_direct_download_min_bps": "700000", "deep_foreign_direct_upload_bps": "1400000", "deep_foreign_gateway_ping_loss_pct": "0", "deep_foreign_ru_ping_loss_pct": "0", "deep_foreign_internet_ping_loss_pct": "0"},
            },
        )
        self.assertEqual(healthy["health_verdict"], "ok")
        self.assertEqual(healthy["ru_wg_download_bps"], "800000")
        self.assertEqual(healthy["foreign_direct_upload_bps"], "1400000")
        self.assertEqual(healthy["handshake_grace_s"], "200")

        mismatch = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {"wg_observed_ipv4": "203.0.113.10", "wg_latest_handshake_age_s": "20"},
                ROLE_FOREIGN: {"observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "15"},
            },
        )
        self.assertEqual(mismatch["health_verdict"], "foreign_ru_ip_mismatch")

        stale_with_verified_egress = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {"wg_observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "999"},
                ROLE_FOREIGN: {"observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "999"},
            },
        )
        self.assertEqual(stale_with_verified_egress["health_verdict"], "ok")

        dynamic_grace_env = generate_default_env("demo")
        dynamic_grace_env["WG_KEEPALIVE"] = "40"
        dynamic_grace = workflows.deployment_health_snapshot(
            dynamic_grace_env,
            {
                ROLE_RU: {"wg_observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "300"},
                ROLE_FOREIGN: {"observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "300"},
            },
        )
        self.assertEqual(dynamic_grace["health_verdict"], "ok")
        self.assertEqual(dynamic_grace["handshake_grace_s"], "320")

        degraded = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {"wg_observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "20", "wg_download_bps": "900000", "deep_ru_wg_download_min_bps": "120000"},
                ROLE_FOREIGN: {"observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "15", "direct_download_bps": "900000", "deep_foreign_direct_download_min_bps": "900000"},
            },
        )
        self.assertEqual(degraded["health_verdict"], "ru_wg_download_degraded")

        loss_profile_only = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {"wg_observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "20", "deep_ru_wg_download_min_bps": "900000"},
                ROLE_FOREIGN: {
                    "observed_ipv4": "198.51.100.20",
                    "wg_latest_handshake_age_s": "15",
                    "deep_foreign_direct_download_min_bps": "900000",
                    "deep_foreign_direct_upload_bps": "1400000",
                    "deep_foreign_gateway_ping_loss_pct": "0",
                    "deep_foreign_ru_ping_loss_pct": "12",
                    "deep_foreign_internet_ping_loss_pct": "1",
                },
            },
        )
        self.assertEqual(loss_profile_only["health_verdict"], "foreign_ru_ping_loss_degraded")
        self.assertEqual(loss_profile_only["foreign_ru_ping_loss_pct"], "12")

        gateway_loss_profile_only = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {"wg_observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "20", "deep_ru_wg_download_min_bps": "900000"},
                ROLE_FOREIGN: {
                    "observed_ipv4": "198.51.100.20",
                    "wg_latest_handshake_age_s": "15",
                    "deep_foreign_direct_download_min_bps": "900000",
                    "deep_foreign_direct_upload_bps": "1400000",
                    "deep_foreign_gateway_ping_loss_pct": "12",
                    "deep_foreign_ru_ping_loss_pct": "1",
                    "deep_foreign_internet_ping_loss_pct": "1",
                },
            },
        )
        self.assertEqual(gateway_loss_profile_only["health_verdict"], "foreign_gateway_ping_loss_degraded")
        self.assertEqual(gateway_loss_profile_only["foreign_gateway_ping_loss_pct"], "12")

        partial_target_issue = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {
                    "wg_observed_ipv4": "198.51.100.20",
                    "wg_latest_handshake_age_s": "20",
                    "deep_ru_wg_download_min_bps": "900000",
                    "deep_ru_wg_upload_bps": "1200000",
                    "target_probe_wg": "chatgpt.com:reachable:403:0:172.64.155.209:0.09;github.com:broken:000:1:-:2.0",
                },
                ROLE_FOREIGN: {
                    "observed_ipv4": "198.51.100.20",
                    "wg_latest_handshake_age_s": "15",
                    "deep_foreign_direct_download_min_bps": "900000",
                    "deep_foreign_direct_upload_bps": "1400000",
                    "deep_foreign_gateway_ping_loss_pct": "0",
                    "deep_foreign_ru_ping_loss_pct": "0",
                    "deep_foreign_internet_ping_loss_pct": "0",
                    "target_probe_direct": "chatgpt.com:reachable:403:0:172.64.155.209:0.09;github.com:broken:000:1:-:2.0",
                },
            },
        )
        self.assertEqual(partial_target_issue["health_verdict"], "ok")
        self.assertIn("github.com:broken:000", partial_target_issue["target_probe_issues"])

        target_degraded = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {
                    "wg_observed_ipv4": "198.51.100.20",
                    "wg_latest_handshake_age_s": "20",
                    "deep_ru_wg_download_min_bps": "900000",
                    "deep_ru_wg_upload_bps": "1200000",
                    "target_probe_wg": "chatgpt.com:blocked:451:0:172.64.155.209:0.09;github.com:broken:000:1:-:2.0",
                },
                ROLE_FOREIGN: {
                    "observed_ipv4": "198.51.100.20",
                    "wg_latest_handshake_age_s": "15",
                    "deep_foreign_direct_download_min_bps": "900000",
                    "deep_foreign_direct_upload_bps": "1400000",
                    "deep_foreign_gateway_ping_loss_pct": "0",
                    "deep_foreign_ru_ping_loss_pct": "0",
                    "deep_foreign_internet_ping_loss_pct": "0",
                    "target_probe_direct": "chatgpt.com:blocked:451:0:172.64.155.209:0.09;github.com:broken:000:1:-:2.0",
                },
            },
        )
        self.assertEqual(target_degraded["health_verdict"], "ru_wg_target_degraded")
        self.assertIn("chatgpt.com:blocked:451", target_degraded["target_probe_issues"])

        threshold_jitter = workflows.deployment_health_snapshot(
            env,
            {
                ROLE_RU: {"wg_observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "20", "deep_ru_wg_download_min_bps": "492000", "deep_ru_wg_upload_bps": "1200000"},
                ROLE_FOREIGN: {"observed_ipv4": "198.51.100.20", "wg_latest_handshake_age_s": "15", "deep_foreign_direct_download_min_bps": "900000", "deep_foreign_direct_upload_bps": "1400000"},
            },
        )
        self.assertEqual(threshold_jitter["health_verdict"], "ok")

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
        self.assertIn("check_service_active sing-box sing-box", mocked.call_args.args[1])
        self.assertIn("check_service_active vpn-stack-xray.service vpn-stack-xray", mocked.call_args.args[1])

    def test_filter_targets_for_remove_skips_unmanaged_hosts(self) -> None:
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("sys.stdout", new_callable=__import__("io").StringIO) as stream:
            result = workflows.filter_targets_for_action(
                "remove",
                [ru, foreign],
                {
                    ROLE_RU: {"installed": "0"},
                    ROLE_FOREIGN: {"installed": "1"},
                },
            )
        self.assertEqual(result, [foreign])
        self.assertIn("Российский сервер: стек не найден на сервере, действие remove пропущено.", stream.getvalue())

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

    def test_run_selected_remote_action_install_recovers_after_disconnect(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("vpn_installer.workflows.render_all_artifacts"), patch("vpn_installer.workflows.install_remote_role", side_effect=AppError("Socket exception: An existing connection was forcibly closed by the remote host (10054)")), patch("vpn_installer.workflows.wait_for_remote_recovery", return_value={"installed": "1"}) as wait_mock, patch("vpn_installer.workflows.postcheck_remote_role") as postcheck, patch("vpn_installer.workflows.warn") as warn_mock:
            workflows.run_selected_remote_action("reinstall", "demo", Path("deployments/demo.env"), env, [foreign], role_arg=ROLE_FOREIGN)
        wait_mock.assert_called_once()
        postcheck.assert_called_once_with(foreign, env["WG_INTERFACE"])
        warn_mock.assert_called()

    def test_ensure_deployment_health_repairs_once(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        broken_health = {
            "health_verdict": "ru_wg_egress_failed",
            "foreign_direct_observed_ipv4": "198.51.100.20",
            "ru_wg_observed_ipv4": "-",
            "ru_handshake_age_s": "500",
            "foreign_handshake_age_s": "500",
            "handshake_grace_s": "120",
        }
        fixed_health = {
            "health_verdict": "ok",
            "foreign_direct_observed_ipv4": "198.51.100.20",
            "ru_wg_observed_ipv4": "198.51.100.20",
            "ru_handshake_age_s": "20",
            "foreign_handshake_age_s": "15",
            "handshake_grace_s": "120",
        }
        with patch("vpn_installer.workflows.wait_for_dataplane_health", side_effect=[({}, broken_health), ({ROLE_RU: {}, ROLE_FOREIGN: {}}, fixed_health)]) as wait_mock, patch("vpn_installer.workflows.run_dataplane_repair_cycle") as repair_mock:
            result = workflows.ensure_deployment_health(env, [ru, foreign], auto_repair=True)
        self.assertEqual(result, {ROLE_RU: {}, ROLE_FOREIGN: {}})
        self.assertEqual(wait_mock.call_count, 2)
        repair_mock.assert_called_once()

    def test_prime_runtime_health_warns_and_continues_on_health_failure(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="ru.example")
        with patch("vpn_installer.workflows.ssh_stream", side_effect=AppError("health failed")) as ssh_mock, patch("vpn_installer.workflows.warn") as warn_mock:
            workflows.prime_runtime_health([target])
        ssh_mock.assert_called_once()
        warn_mock.assert_called_once()

    def test_ensure_deployment_health_soft_degradation_warns_without_repair(self) -> None:
        env = generate_default_env("demo")
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        degraded_health = {
            "health_verdict": "foreign_direct_download_degraded",
            "foreign_direct_observed_ipv4": "198.51.100.20",
            "ru_wg_observed_ipv4": "198.51.100.20",
            "ru_handshake_age_s": "20",
            "foreign_handshake_age_s": "15",
            "handshake_grace_s": "120",
            "foreign_direct_download_bps": "120000",
            "ru_wg_download_bps": "700000",
            "min_foreign_direct_download_bps": "500000",
            "min_ru_wg_download_bps": "500000",
            "foreign_direct_upload_bps": "1200000",
            "ru_wg_upload_bps": "1200000",
            "min_foreign_direct_upload_bps": "1000000",
            "min_ru_wg_upload_bps": "1000000",
            "foreign_ru_ping_loss_pct": "0",
            "foreign_internet_ping_loss_pct": "0",
            "max_foreign_ru_ping_loss_pct": "5",
            "max_foreign_internet_ping_loss_pct": "5",
        }
        with patch("vpn_installer.workflows.wait_for_dataplane_health", return_value=({ROLE_RU: {}, ROLE_FOREIGN: {}}, degraded_health)) as wait_mock, patch("vpn_installer.workflows.run_dataplane_repair_cycle") as repair_mock, patch("vpn_installer.workflows.warn") as warn_mock:
            result = workflows.ensure_deployment_health(env, [ru, foreign], auto_repair=True)
        self.assertEqual(result, {ROLE_RU: {}, ROLE_FOREIGN: {}})
        wait_mock.assert_called_once()
        repair_mock.assert_not_called()
        warn_mock.assert_called_once()

    def test_ensure_deployment_health_soft_degradation_after_repair_warns_and_returns(self) -> None:
        env = generate_default_env("demo")
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        broken_health = {
            "health_verdict": "ru_wg_egress_failed",
            "foreign_direct_observed_ipv4": "198.51.100.20",
            "ru_wg_observed_ipv4": "-",
            "ru_handshake_age_s": "500",
            "foreign_handshake_age_s": "500",
            "handshake_grace_s": "120",
        }
        degraded_health = {
            "health_verdict": "foreign_ru_ping_loss_degraded",
            "foreign_direct_observed_ipv4": "198.51.100.20",
            "ru_wg_observed_ipv4": "198.51.100.20",
            "ru_handshake_age_s": "20",
            "foreign_handshake_age_s": "15",
            "handshake_grace_s": "120",
            "foreign_direct_download_bps": "700000",
            "ru_wg_download_bps": "700000",
            "min_foreign_direct_download_bps": "500000",
            "min_ru_wg_download_bps": "500000",
            "foreign_direct_upload_bps": "1200000",
            "ru_wg_upload_bps": "1200000",
            "min_foreign_direct_upload_bps": "1000000",
            "min_ru_wg_upload_bps": "1000000",
            "foreign_ru_ping_loss_pct": "20",
            "foreign_internet_ping_loss_pct": "0",
            "max_foreign_ru_ping_loss_pct": "5",
            "max_foreign_internet_ping_loss_pct": "5",
        }
        with patch("vpn_installer.workflows.wait_for_dataplane_health", side_effect=[({}, broken_health), ({ROLE_RU: {}, ROLE_FOREIGN: {}}, degraded_health)]) as wait_mock, patch("vpn_installer.workflows.run_dataplane_repair_cycle") as repair_mock, patch("vpn_installer.workflows.warn") as warn_mock:
            result = workflows.ensure_deployment_health(env, [ru, foreign], auto_repair=True)
        self.assertEqual(result, {ROLE_RU: {}, ROLE_FOREIGN: {}})
        self.assertEqual(wait_mock.call_count, 2)
        repair_mock.assert_called_once()
        warn_mock.assert_called_once()

    def test_run_dataplane_repair_cycle_uses_nonblocking_systemctl_restart(self) -> None:
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("vpn_installer.workflows.print_header"), patch("vpn_installer.workflows.ssh_stream") as ssh_stream_mock:
            workflows.run_dataplane_repair_cycle({ROLE_RU: ru, ROLE_FOREIGN: foreign}, "wg0")
        self.assertEqual(ssh_stream_mock.call_count, 2)
        foreign_call = ssh_stream_mock.call_args_list[0]
        ru_call = ssh_stream_mock.call_args_list[1]
        self.assertEqual(foreign_call.args[0], foreign)
        self.assertIn("systemctl restart --no-block", foreign_call.args[1])
        self.assertIn("wg-quick@wg0", foreign_call.args[1])
        self.assertIn("vpn-stack-sync.service", foreign_call.args[1])
        self.assertTrue(foreign_call.kwargs["as_root"])
        self.assertEqual(ru_call.args[0], ru)
        self.assertIn("systemctl restart --no-block", ru_call.args[1])
        self.assertIn("wg-quick@wg0", ru_call.args[1])
        self.assertIn("sing-box", ru_call.args[1])
        self.assertTrue(ru_call.kwargs["as_root"])

    def test_ensure_deployment_health_fails_after_repair_exhaustion(self) -> None:
        env = generate_default_env("demo")
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        broken_health = {
            "health_verdict": "wg_handshake_stale",
            "foreign_direct_observed_ipv4": "198.51.100.20",
            "ru_wg_observed_ipv4": "198.51.100.20",
            "ru_handshake_age_s": "500",
            "foreign_handshake_age_s": "500",
            "handshake_grace_s": "120",
        }
        with patch("vpn_installer.workflows.wait_for_dataplane_health", side_effect=[({}, broken_health), ({}, broken_health)]), patch("vpn_installer.workflows.run_dataplane_repair_cycle"):
            with self.assertRaises(AppError) as ctx:
                workflows.ensure_deployment_health(env, [ru, foreign], auto_repair=True)
        self.assertIn("wg_handshake_stale", str(ctx.exception))

    def test_run_selected_remote_action_install_reraises_nonrecoverable_error(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("vpn_installer.workflows.render_all_artifacts"), patch("vpn_installer.workflows.install_remote_role", side_effect=AppError("permission denied")), patch("vpn_installer.workflows.wait_for_remote_recovery") as wait_mock, patch("vpn_installer.workflows.postcheck_remote_role") as postcheck:
            with self.assertRaises(AppError):
                workflows.run_selected_remote_action("reinstall", "demo", Path("deployments/demo.env"), env, [foreign], role_arg=ROLE_FOREIGN)
        wait_mock.assert_not_called()
        postcheck.assert_not_called()

    def test_run_selected_remote_action_remove_noops_when_targets_empty(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        with patch("vpn_installer.workflows.install_remote_role") as install_remote, patch("vpn_installer.workflows.remote_preflight") as remote_preflight, patch("vpn_installer.workflows.print_preflight") as print_preflight:
            workflows.run_selected_remote_action("remove", "demo", Path("deployments/demo.env"), env, [], role_arg=ROLE_RU)
        install_remote.assert_not_called()
        remote_preflight.assert_not_called()
        print_preflight.assert_not_called()

    def test_run_selected_remote_action_remove_all_uses_only_available_roles(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("vpn_installer.workflows.install_remote_role") as install_remote, patch("vpn_installer.workflows.remote_preflight", return_value={"installed": "1"}) as remote_preflight, patch("vpn_installer.workflows.print_preflight") as print_preflight:
            workflows.run_selected_remote_action("remove", "demo", Path("deployments/demo.env"), env, [foreign], role_arg="all")
        install_remote.assert_called_once_with(foreign, "demo", env, "remove")
        remote_preflight.assert_called_once()
        print_preflight.assert_called_once()

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
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {ROLE_FOREIGN: {"default_iface": "eth1"}, ROLE_RU: {}})), patch("vpn_installer.workflows.ensure_foreign_wan_interface"), patch("vpn_installer.workflows.write_text"), patch("vpn_installer.workflows.write_state"), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.ask_install_action", side_effect=["skip", "install"]), patch("vpn_installer.workflows.prompt_yes_no", return_value=True), patch("vpn_installer.workflows.render_all_artifacts") as render_all, patch("vpn_installer.workflows.install_remote_role") as install_remote, patch("vpn_installer.workflows.postcheck_remote_role") as postcheck, patch("vpn_installer.workflows.ensure_deployment_health") as health_check, patch("vpn_installer.workflows.finalize_install_output") as finalize:
            self.assertEqual(workflows.install_workflow("demo"), 0)
        render_all.assert_called_once()
        install_remote.assert_called_once()
        postcheck.assert_called_once()
        health_check.assert_called_once_with(env, [ru, foreign], auto_repair=True)
        finalize.assert_called_once_with(env, "demo")

    def test_remote_action_workflow_stops_on_user_decline(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru], {ROLE_RU: {}})), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.prompt_yes_no", return_value=False):
            self.assertEqual(workflows.remote_action_workflow("demo", ROLE_RU, "remove"), 0)

    def test_remote_action_workflow_skips_remove_when_stack_absent(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru], {ROLE_RU: {"installed": "0"}})), patch("vpn_installer.workflows.print_summary") as print_summary, patch("vpn_installer.workflows.prompt_yes_no") as prompt_yes_no, patch("vpn_installer.workflows.run_selected_remote_action") as run_selected, patch("sys.stdout", new_callable=__import__('io').StringIO) as stream:
            self.assertEqual(workflows.remote_action_workflow("demo", ROLE_RU, "remove"), 0)
        print_summary.assert_called_once()
        prompt_yes_no.assert_not_called()
        run_selected.assert_not_called()
        self.assertIn("Подходящих серверов для действия не найдено.", stream.getvalue())

    def test_remote_action_workflow_remove_all_runs_only_remaining_role(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch(
            "vpn_installer.workflows.prepare_remote_session",
            return_value=(
                "demo",
                Path("deployments/demo.env"),
                env,
                {},
                [ru, foreign],
                {ROLE_RU: {"installed": "0"}, ROLE_FOREIGN: {"installed": "1"}},
            ),
        ), patch("vpn_installer.workflows.print_summary") as print_summary, patch("vpn_installer.workflows.prompt_yes_no", return_value=True) as prompt_yes_no, patch("vpn_installer.workflows.run_selected_remote_action") as run_selected, patch("sys.stdout", new_callable=__import__('io').StringIO) as stream:
            self.assertEqual(workflows.remote_action_workflow("demo", "all", "remove"), 0)
        print_summary.assert_called_once()
        prompt_yes_no.assert_called_once()
        run_selected.assert_called_once()
        call_args = run_selected.call_args
        self.assertEqual(call_args.args[4], [foreign])
        self.assertEqual(call_args.kwargs["role_arg"], "all")
        self.assertIn("Российский сервер: стек не найден на сервере, действие remove пропущено.", stream.getvalue())

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

    def test_status_workflow_runs_health_for_full_deployment(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(role=ROLE_RU)
        foreign = RemoteTarget(role=ROLE_FOREIGN)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {})), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.ensure_deployment_health") as health_mock:
            self.assertEqual(workflows.status_workflow("demo", "all"), 0)
        health_mock.assert_called_once_with(env, [ru, foreign], auto_repair=False)

    def test_menu_workflow_dispatches_actions_and_returns_to_menu(self) -> None:
        with patch("vpn_installer.workflows.prompt_choice", side_effect=["audit", "quick", "back", "exit"]), patch("vpn_installer.audit.runner.main", return_value=0) as audit_main:
            self.assertEqual(workflows.menu_workflow(), 0)
        audit_main.assert_called_once_with(["quick"])

        with patch("vpn_installer.workflows.prompt_choice", side_effect=["cleanup-local", "exit"]), patch("vpn_installer.workflows.cleanup_local_workflow", return_value=0) as cleanup:
            self.assertEqual(workflows.menu_workflow(), 0)
        cleanup.assert_called_once_with(None, drop_env=False, drop_runtime=False)

        with patch("vpn_installer.workflows.prompt_choice", side_effect=["status", "exit"]), patch("vpn_installer.workflows.select_role_for_menu", return_value=ROLE_RU), patch("vpn_installer.workflows.status_workflow", return_value=0) as status:
            self.assertEqual(workflows.menu_workflow(), 0)
        status.assert_called_once_with(None, ROLE_RU)

    def test_run_menu_action_handles_cancel_and_error_without_propagation(self) -> None:
        with patch("sys.stderr", new_callable=__import__("io").StringIO) as stream:
            workflows.run_menu_action(lambda: (_ for _ in ()).throw(UserCancelled("cancelled")), return_to="главное меню")
        self.assertIn("cancelled", stream.getvalue())

        with patch("sys.stdout", new_callable=__import__("io").StringIO) as stdout_stream, patch("sys.stderr", new_callable=__import__("io").StringIO) as stderr_stream:
            with patch("vpn_installer.workflows.log_exception", return_value=Path("out/logs/runtime/error.log")) as log_mock:
                workflows.run_menu_action(lambda: (_ for _ in ()).throw(AppError("broken")), return_to="главное меню")
        log_mock.assert_called_once()
        self.assertIn("Возврат в главное меню", stdout_stream.getvalue())
        self.assertIn(f"Лог ошибки: {Path('out/logs/runtime/error.log')}", stdout_stream.getvalue())
        self.assertIn("Ошибка: broken", stderr_stream.getvalue())

        with patch("sys.stdout", new_callable=__import__("io").StringIO) as stdout_stream, patch("sys.stderr", new_callable=__import__("io").StringIO) as stderr_stream:
            with patch("vpn_installer.workflows.log_exception", return_value=Path("out/logs/runtime/error.log")) as log_mock:
                workflows.run_menu_action(lambda: (_ for _ in ()).throw(RuntimeError("boom")), return_to="меню самопроверки")
        log_mock.assert_called_once()
        self.assertIn("Возврат в меню самопроверки", stdout_stream.getvalue())
        self.assertIn(f"Лог ошибки: {Path('out/logs/runtime/error.log')}", stdout_stream.getvalue())
        self.assertIn("Непредвиденная ошибка: boom", stderr_stream.getvalue())

        AuditFailure = type("AuditFailure", (RuntimeError,), {})
        AuditFailure.__module__ = "vpn_installer.audit.runner"
        with patch("sys.stdout", new_callable=__import__("io").StringIO) as stdout_stream, patch("sys.stderr", new_callable=__import__("io").StringIO) as stderr_stream:
            with patch("vpn_installer.workflows.log_exception") as log_mock:
                workflows.run_menu_action(lambda: (_ for _ in ()).throw(AuditFailure("Не найдена команда: docker")), return_to="меню самопроверки")
        log_mock.assert_not_called()
        self.assertIn("Смотри summary и логи в out/audit/<run_id>/.", stdout_stream.getvalue())
        self.assertIn("Возврат в меню самопроверки", stdout_stream.getvalue())
        self.assertIn("Самопроверка завершилась с ошибкой", stderr_stream.getvalue())

    def test_audit_menu_workflow_loops_until_back(self) -> None:
        with patch("vpn_installer.workflows.prompt_choice", side_effect=["quick", "back"]), patch("vpn_installer.audit.runner.main", return_value=0) as audit_main:
            self.assertEqual(workflows.audit_menu_workflow(), 0)
        audit_main.assert_called_once_with(["quick"])

    def test_audit_menu_workflow_recovers_after_failure(self) -> None:
        with patch("vpn_installer.workflows.prompt_choice", side_effect=["quick", "back"]), patch("vpn_installer.audit.runner.main", side_effect=RuntimeError("boom")) as audit_main:
            self.assertEqual(workflows.audit_menu_workflow(), 0)
        audit_main.assert_called_once_with(["quick"])

    def test_cleanup_local_reports_when_nothing_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(workflows, "OUT_DIR", Path(tmp) / "out"), patch.object(workflows, "DEPLOYMENTS_DIR", Path(tmp) / "deployments"), patch.object(workflows, "RUNTIME_DIR", Path(tmp) / ".runtime"), patch.object(workflows, "select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.ensure_directories"), patch("sys.stdout", new_callable=__import__('io').StringIO) as stream:
                self.assertEqual(workflows.cleanup_local_workflow(None, drop_env=False, drop_runtime=False), 0)
        self.assertIn("не найдены", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
