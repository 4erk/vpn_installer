from __future__ import annotations

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, call, patch

from vpn_installer.config import generate_default_env, merge_env_with_defaults, render_env_text
from vpn_installer.diagnostics import COLLECTOR_NAMES, LOG_WINDOW_KEYS, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot
from vpn_installer.localnet import LocalRoute
from vpn_installer.manifest import render_node_env_text
from vpn_installer.models import AppError, RemoteTarget, UserCancelled
from vpn_installer.topology import NODE_EXIT, NODE_GATEWAY
from vpn_installer import targets
from vpn_installer import workflows


def transaction_state(
    release_id: str = "",
    *,
    target: str = "",
    node_id: str = "",
    rollback_services: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "state": "idle",
        "current_present": bool(release_id),
    }
    if release_id:
        payload.update(
            current_release_id=release_id,
            current_target=target or f"/etc/vpn-stack/releases/{release_id}",
            current_node_id=node_id,
        )
    if rollback_services is not None:
        payload.update(rollback_services_present=True, rollback_services=rollback_services)
    return payload


def rollback_service(
    name: str,
    unit: str,
    *,
    enabled: str = "enabled",
    active: str = "active",
    ownership: str = "managed",
) -> dict[str, str]:
    return {
        "name": name,
        "unit": unit,
        "ownership": ownership,
        "expected_enabled": enabled,
        "expected_active": active,
        "actual_enabled": enabled,
        "actual_active": active,
    }


def compact_snapshot(node_id: str, location: str) -> dict[str, object]:
    collectors = {name: CollectorState.skipped("compact test snapshot") for name in COLLECTOR_NAMES}
    windows = {name: LogWindowSnapshot.skipped("compact test snapshot") for name in LOG_WINDOW_KEYS}
    return DiagnosticsSnapshot(
        topology="dual",
        node_id=node_id,
        location=location,
        capabilities=("router",),
        collectors=collectors,
        log_windows=windows,
        verdict="inconclusive",
    ).to_dict()


def supported_host_preflight(**overrides: str) -> dict[str, str]:
    payload = {
        "os_id": "ubuntu",
        "os_version": "24.04",
        "architecture": "x86_64",
        "init_system": "systemd",
        "security_mode": "apparmor",
        "host_firewall": "none",
    }
    payload.update(overrides)
    return payload


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.host_key_check = patch("vpn_installer.workflows.ensure_target_host_key").start()
        self.runtime_error_log = patch("vpn_installer.workflows.log_exception", return_value=None).start()
        self.addCleanup(patch.stopall)

    def test_build_target_from_env_without_state(self) -> None:
        env = {
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "ru",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "SSH_PORT": "22",
        }
        target = targets.build_target(NODE_GATEWAY, env, {})
        self.assertEqual(target.public_ip, "203.0.113.10")
        self.assertFalse(target.saved_connection)

    def test_existing_deployment_rejects_physical_topology_change_before_ssh(self) -> None:
        env = generate_default_env("demo", topology="dual", gateway_location="ru")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        with tempfile.TemporaryDirectory() as tmp:
            deployment_dir = Path(tmp)
            (deployment_dir / "demo.env").write_text(render_env_text(env), encoding="utf-8")
            with (
                patch.object(workflows, "DEPLOYMENTS_DIR", deployment_dir),
                patch("vpn_installer.workflows.ensure_directories"),
                patch("vpn_installer.workflows.select_deployment", return_value="demo"),
                patch("vpn_installer.workflows.verify_target_non_interactively") as verify,
            ):
                with self.assertRaisesRegex(AppError, "Нельзя менять topology"):
                    workflows.prepare_remote_session(
                        "demo",
                        nodes=None,
                        require_privilege=True,
                        allow_create=True,
                        non_interactive=True,
                        topology_mode="single",
                        gateway_location="ru",
                    )
            verify.assert_not_called()

    def test_apply_env_connection_overrides_supports_unattended_password_login(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY)
        with patch.dict(
            "vpn_installer.targets.os.environ",
            {
                "VPN_GATEWAY_PUBLIC_IP": "203.0.113.10",
                "VPN_GATEWAY_SSH_HOST": "ssh.example.test",
                "VPN_GATEWAY_SSH_PORT": "2222",
                "VPN_GATEWAY_SSH_USER": "root",
                "VPN_GATEWAY_SSH_PASSWORD": "secret",
                "VPN_SSH_BIND_ADDRESS": "192.168.0.101",
            },
            clear=False,
        ):
            updated = targets.apply_env_connection_overrides(target)
        self.assertTrue(updated.saved_connection)
        self.assertEqual(updated.public_ip, "203.0.113.10")
        self.assertEqual(updated.ssh_host, "ssh.example.test")
        self.assertEqual(updated.ssh_port, 2222)
        self.assertEqual(updated.ssh_user, "root")
        self.assertEqual(updated.auth_mode, "password")
        self.assertEqual(updated.ssh_password, "secret")
        self.assertEqual(updated.ssh_bind_address, "192.168.0.101")

    def test_update_env_with_targets(self) -> None:
        env = {"TOPOLOGY": "dual", "GATEWAY_LOCATION": "ru"}
        targets.update_env_with_targets(
            env,
            [
                RemoteTarget(node_id=NODE_GATEWAY, public_ip="203.0.113.10"),
                RemoteTarget(node_id=NODE_EXIT, public_ip="198.51.100.20"),
            ],
        )
        self.assertEqual(env["GATEWAY_PUBLIC_IP"], "203.0.113.10")
        self.assertEqual(env["EXIT_PUBLIC_IP"], "198.51.100.20")
        self.assertNotIn("RU_PUBLIC_IP", env)
        self.assertNotIn("FOREIGN_PUBLIC_IP", env)

    def test_build_target_supports_single_foreign_gateway(self) -> None:
        env = {
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "foreign",
            "GATEWAY_PUBLIC_IP": "198.51.100.20",
            "SSH_PORT": "22",
        }
        target = targets.build_target("gateway", env, {})
        self.assertEqual(target.node_id, "gateway")
        self.assertEqual(target.location, "foreign")
        self.assertEqual(target.public_ip, "198.51.100.20")
        self.assertIn("зарубежный", target.label)

    def test_connection_env_uses_canonical_node_names(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, location="ru")
        with patch.dict(
            "vpn_installer.targets.os.environ",
            {
                "VPN_GATEWAY_PUBLIC_IP": "203.0.113.30",
                "VPN_GATEWAY_SSH_HOST": "gateway.example.test",
                "VPN_GATEWAY_SSH_USER": "root",
                "VPN_GATEWAY_SSH_PORT": "2222",
                "VPN_GATEWAY_SSH_PASSWORD": "secret",
            },
            clear=False,
        ):
            updated = targets.apply_env_connection_overrides(target)
        self.assertEqual(updated.public_ip, "203.0.113.30")
        self.assertEqual(updated.ssh_host, "gateway.example.test")
        self.assertEqual(updated.ssh_port, 2222)

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
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        with tempfile.TemporaryDirectory() as tmp:
            paths = {
                "vless_uri": Path(tmp) / "vless-uri.txt",
                "hiddify_uri_compat": Path(tmp) / "hiddify-uri.txt",
                "hiddify_json": Path(tmp) / "h.json",
                "hysteria2_uri": Path(tmp) / "hysteria2-uri.txt",
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
            with patch("vpn_installer.workflows.client_artifact_paths", return_value=paths), patch("sys.stdout", new_callable=StringIO) as stream:
                with patch("vpn_installer.workflows.copy_to_clipboard", return_value=(False, "no clipboard")) as copy_mock:
                    workflows.finalize_install_output(env, "demo")
            copy_mock.assert_called_once_with("vless://demo\n")
            self.assertIn("Web-admin: http://203.0.113.10:11333", stream.getvalue())

    def test_verify_target_interactively_cancel_raises_user_cancelled(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
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
        target = RemoteTarget(node_id=NODE_GATEWAY, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root", auth_mode="password")
        preflights = [AppError("boom"), supported_host_preflight(default_iface="eth0")]
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
            node_id=NODE_GATEWAY,
            public_ip="203.0.113.10",
            ssh_host="203.0.113.10",
            ssh_port=22,
            ssh_user="root",
            auth_mode="password",
            ssh_password="secret",
            saved_connection=True,
        )
        with patch("vpn_installer.workflows.assert_server_route_not_self_tunneled") as route_check, patch("vpn_installer.workflows.remote_preflight", return_value=supported_host_preflight(is_root="1")) as preflight, patch("vpn_installer.workflows.print_preflight"), patch("vpn_installer.workflows.prompt_server_connection") as prompt:
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
        self.host_key_check.assert_called_with(target, allow_enroll=False)
        preflight.assert_called_once()
        prompt.assert_not_called()

    def test_verify_target_non_interactively_reports_node_password_env(self) -> None:
        target = RemoteTarget(
            node_id=NODE_GATEWAY,
            public_ip="203.0.113.10",
            ssh_host="203.0.113.10",
            ssh_port=22,
            ssh_user="root",
            auth_mode="password",
            saved_connection=True,
        )
        with patch("vpn_installer.workflows.hydrate_runtime_auth", return_value=target):
            with self.assertRaises(AppError) as ctx:
                workflows.verify_target_non_interactively(
                    target,
                    env=generate_default_env("demo"),
                    wg_interface="wg0",
                    require_privilege=True,
                    validate_os=True,
                )
        self.assertIn("VPN_GATEWAY_SSH_PASSWORD", str(ctx.exception))

    def test_verify_target_non_interactively_accepts_system_stored_password(self) -> None:
        target = RemoteTarget(
            node_id=NODE_GATEWAY,
            public_ip="203.0.113.10",
            ssh_host="203.0.113.10",
            ssh_port=22,
            ssh_user="root",
            auth_mode="password",
            saved_connection=True,
        )

        def hydrate(value: RemoteTarget, **_kwargs: object) -> RemoteTarget:
            value.ssh_password = "stored-secret"
            return value

        with patch("vpn_installer.workflows.hydrate_runtime_auth", side_effect=hydrate), patch("vpn_installer.workflows.assert_server_route_not_self_tunneled"), patch("vpn_installer.workflows.remote_preflight", return_value=supported_host_preflight(is_root="1")), patch("vpn_installer.workflows.print_preflight"):
            updated, _result = workflows.verify_target_non_interactively(
                target,
                env=generate_default_env("demo"),
                wg_interface="wg0",
                require_privilege=True,
                validate_os=True,
            )
        self.assertEqual(updated.ssh_password, "stored-secret")

    def test_verify_target_interactively_checks_remote_privilege(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.workflows.prompt_server_connection", return_value=target), patch("vpn_installer.workflows.assert_server_route_not_self_tunneled"), patch("vpn_installer.workflows.remote_preflight", return_value=supported_host_preflight()), patch("vpn_installer.workflows.print_preflight"), patch("vpn_installer.workflows.ensure_remote_privilege") as mocked:
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
        target = RemoteTarget(node_id=NODE_GATEWAY, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
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

    def test_prepare_remote_session_persists_only_selected_nodes(self) -> None:
        ru = RemoteTarget(node_id=NODE_GATEWAY, public_ip="203.0.113.10", ssh_host="203.0.113.10")
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        env["WG_INTERFACE"] = "wgx"
        with patch("vpn_installer.workflows.ensure_directories"), patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)), patch("vpn_installer.workflows.load_state", return_value={}), patch("vpn_installer.workflows.verify_target_interactively", return_value=(ru, {"default_iface": "eth0"})), patch("vpn_installer.workflows.write_private_text") as write_text_mock, patch("vpn_installer.workflows.write_state") as write_state_mock:
            name, env_path, env, _state, targets, preflights = workflows.prepare_remote_session(
                "demo",
                nodes=[NODE_GATEWAY],
                require_privilege=False,
                allow_create=False,
                persist_local=True,
            )
        self.assertEqual(name, "demo")
        self.assertEqual(env_path, Path("deployments/demo.env"))
        self.assertEqual(len(targets), 1)
        self.assertIn(NODE_GATEWAY, preflights)
        write_text_mock.assert_called_once()
        write_state_mock.assert_called_once()

    def test_prepare_remote_session_delegates_safe_route_check_to_target_verification(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        state = {NODE_GATEWAY: {"public_ip": "203.0.113.10", "ssh_host": "203.0.113.10", "ssh_port": "22", "ssh_user": "root", "auth_mode": "password"}}
        target = workflows.build_target(NODE_GATEWAY, env, state)
        with patch("vpn_installer.workflows.ensure_directories"), patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)), patch("vpn_installer.workflows.load_state", return_value=state), patch("vpn_installer.workflows.verify_target_interactively", return_value=(target, {"node": NODE_GATEWAY})) as verify:
            workflows.prepare_remote_session(
                "demo",
                nodes=[NODE_GATEWAY],
                require_privilege=False,
                allow_create=False,
                persist_local=False,
            )
        self.assertTrue(verify.call_args.kwargs["enforce_safe_route"])

    def test_client_check_workflow_reports_self_tunnel(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        state = {NODE_GATEWAY: {"public_ip": "203.0.113.10", "ssh_host": "203.0.113.10", "ssh_port": "22", "ssh_user": "root", "auth_mode": "password"}}
        with patch("vpn_installer.workflows.ensure_directories"), patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)), patch("vpn_installer.workflows.load_state", return_value=state), patch("vpn_installer.workflows.local_route_to_server", return_value=LocalRoute(target_ip="203.0.113.10", interface_alias="singbox_tun")), patch("vpn_installer.workflows.find_client_drift", return_value=[]):
            self.assertEqual(workflows.client_check_workflow("demo", NODE_GATEWAY), 1)

    def test_client_check_workflow_reports_stale_client_profile(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        state = {NODE_GATEWAY: {"public_ip": "203.0.113.10", "ssh_host": "203.0.113.10", "ssh_port": "22", "ssh_user": "root", "auth_mode": "password"}}
        finding = __import__("vpn_installer.client_drift", fromlist=["ClientDriftFinding"]).ClientDriftFinding(Path("hiddify.json"), "устаревший порт клиента: 443, ожидается 8443")
        with patch("vpn_installer.workflows.ensure_directories"), patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"), patch("vpn_installer.workflows.load_existing_deployment_env", return_value=(Path("deployments/demo.env"), env)), patch("vpn_installer.workflows.load_state", return_value=state), patch("vpn_installer.workflows.local_route_to_server", return_value=LocalRoute(target_ip="203.0.113.10", interface_alias="Беспроводная сеть")), patch("vpn_installer.workflows.find_client_drift", return_value=[finding]), patch("sys.stdout", new_callable=__import__("io").StringIO) as stream:
            self.assertEqual(workflows.client_check_workflow("demo", NODE_GATEWAY), 1)
        self.assertIn("STALE: hiddify.json", stream.getvalue())

    def test_remote_node_env_is_drift_evidence_and_never_replaces_local_secrets(self) -> None:
        local_env = generate_default_env("demo")
        local_env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        local_env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        target = RemoteTarget(node_id=NODE_GATEWAY, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_user="root")
        with patch("vpn_installer.workflows.fetch_remote_deployment_env", return_value=render_node_env_text(local_env, "gateway")), patch("vpn_installer.workflows.write_private_text") as write_text_mock:
            synced_env, synced = workflows.load_remote_authoritative_env(
                "demo",
                Path("deployments/demo.env"),
                local_env,
                [target],
                {NODE_GATEWAY: {"installed": "1", "deployment_name": "demo", "node": NODE_GATEWAY}},
            )
        self.assertFalse(synced)
        self.assertIs(synced_env, local_env)
        self.assertEqual(target.public_ip, "203.0.113.10")
        write_text_mock.assert_not_called()

    def test_load_remote_authoritative_env_fails_closed_on_node_projection_drift(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru_target = RemoteTarget(node_id=NODE_GATEWAY, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_user="root")
        drifted = {**env, "CLIENT_UUID": "different"}
        with patch("vpn_installer.workflows.fetch_remote_deployment_env", return_value=render_node_env_text(drifted, "gateway")):
            with self.assertRaises(AppError) as ctx:
                workflows.load_remote_authoritative_env(
                    "demo",
                    Path("deployments/demo.env"),
                    env,
                    [ru_target],
                    {
                        NODE_GATEWAY: {"installed": "1", "deployment_name": "demo", "node": NODE_GATEWAY},
                    },
                )
        self.assertIn("installed node env drift", str(ctx.exception))

    def test_cleanup_remote_workdir_warns_on_error(self) -> None:
        with patch("vpn_installer.workflows.ssh_stream", side_effect=AppError("fail")), patch("vpn_installer.workflows.warn") as warn_mock:
            workflows.cleanup_remote_workdir(RemoteTarget(node_id=NODE_GATEWAY), "vpn-installer/demo")
        warn_mock.assert_called_once()

    def test_remote_install_state_distinguishes_busy_and_accepted_release(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY)
        with patch("vpn_installer.workflows.ssh_capture", return_value="busy"):
            self.assertEqual(workflows.remote_install_transaction_state(target), {"state": "busy"})
        payload = {
            "state": "idle",
            "acceptance_present": True,
            "acceptance_release_id": "release-1",
            "acceptance_node_id": "gateway",
            "acceptance_deployment": "demo",
        }
        with patch("vpn_installer.workflows.ssh_capture", return_value=json.dumps(payload)) as capture:
            self.assertEqual(workflows.remote_install_transaction_state(target), payload)
        self.assertTrue(capture.call_args.kwargs["as_root"])
        self.assertIn('root / "current"', capture.call_args.args[1])
        self.assertIn('service-state.tsv', capture.call_args.args[1])

    def test_wait_for_remote_install_completion_waits_for_lock_release(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY)
        transaction = {"state": "idle", "acceptance_present": True, "acceptance_release_id": "release-1"}
        with (
            patch("vpn_installer.workflows.remote_install_transaction_state", side_effect=[{"state": "busy"}, transaction]),
            patch("vpn_installer.workflows.remote_preflight", return_value={"installed": "1"}),
            patch("vpn_installer.workflows.time.sleep") as sleep,
        ):
            result = workflows.wait_for_remote_install_completion(target, "wg0", timeout_sec=10, interval_sec=1)
        self.assertEqual(result["acceptance_release_id"], "release-1")
        self.assertEqual(result["acceptance_present"], "True")
        sleep.assert_called_once_with(1)

    def test_wait_for_remote_install_idle_waits_out_agent_read_lock(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY)
        idle = transaction_state("old-release", node_id="gateway")
        with (
            patch(
                "vpn_installer.workflows.remote_install_transaction_state",
                side_effect=[{"state": "busy"}, idle],
            ),
            patch("vpn_installer.workflows.time.sleep") as sleep,
        ):
            result = workflows.wait_for_remote_install_idle(
                target,
                timeout_sec=10,
                interval_sec=0.5,
            )
        self.assertEqual(result, idle)
        sleep.assert_called_once_with(0.5)

    def test_wait_for_remote_install_idle_rejects_stuck_writer(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY)
        with (
            patch(
                "vpn_installer.workflows.remote_install_transaction_state",
                return_value={"state": "busy"},
            ),
            patch("vpn_installer.workflows.time.monotonic", side_effect=[0.0, 2.0]),
            patch("vpn_installer.workflows.time.sleep") as sleep,
        ):
            with self.assertRaisesRegex(AppError, "не освободила lock за 1 секунд"):
                workflows.wait_for_remote_install_idle(target, timeout_sec=1)
        sleep.assert_not_called()

    def test_install_remote_node_confirms_normal_transaction(self) -> None:
        target = RemoteTarget(node_id=NODE_EXIT)
        accepted = {
            "installed": "1", "node": NODE_EXIT, "deployment_name": "demo", "release_id": "release-1", "drift": "none",
            "acceptance_present": "True", "acceptance_release_id": "release-1", "acceptance_node_id": "exit",
            "acceptance_deployment": "demo", "current_present": "True", "current_release_id": "release-1",
            "current_target": "/etc/vpn-stack/releases/release-1", "current_node_id": "exit",
        }
        with (
            patch("vpn_installer.workflows.expected_release_id_for_node", return_value="release-1"),
            patch("vpn_installer.workflows.wait_for_remote_install_idle", return_value=transaction_state("old-release", node_id="exit")),
            patch("vpn_installer.workflows.install_remote_node") as install,
            patch("vpn_installer.workflows.wait_for_remote_install_completion", return_value=accepted) as wait,
        ):
            workflows.install_remote_node_with_recovery(target, "demo", {}, "reinstall", "wg0")
        install.assert_called_once_with(target, "demo", {}, "reinstall")
        wait.assert_called_once_with(target, "wg0")

    def test_install_cutover_requires_a_provable_current_transition(self) -> None:
        observed = transaction_state("new-release", target="/etc/vpn-stack/releases/new-release", node_id="exit")
        self.assertTrue(workflows.install_cutover_observed(transaction_state(), observed, "new-release"))
        self.assertTrue(
            workflows.install_cutover_observed(
                transaction_state("old-release", target="/etc/vpn-stack/releases/old-release", node_id="exit"),
                observed,
                "new-release",
            )
        )
        self.assertFalse(
            workflows.install_cutover_observed(
                {"state": "idle", "current_present": True},
                observed,
                "new-release",
            )
        )
        self.assertFalse(
            workflows.install_cutover_observed(
                {
                    **transaction_state("new-release", target="/etc/vpn-stack/releases/new-release", node_id="exit"),
                    "rollback_snapshot": "/etc/vpn-stack/backups/revisions/old",
                },
                {
                    **observed,
                    "rollback_snapshot": "/etc/vpn-stack/backups/revisions/new",
                },
                "new-release",
            )
        )
        self.assertFalse(
            workflows.install_cutover_observed(
                {
                    **transaction_state("old-release", target="/etc/vpn-stack/releases/old-release", node_id="exit"),
                    "rollback_snapshot": "/etc/vpn-stack/backups/revisions/old",
                },
                {
                    **transaction_state("old-release", target="/etc/vpn-stack/releases/old-release", node_id="exit"),
                    "rollback_snapshot": "/etc/vpn-stack/backups/revisions/new",
                },
                "new-release",
            )
        )
        self.assertTrue(
            workflows.install_cutover_observed(
                {
                    **transaction_state("old-release", target="/etc/vpn-stack/releases/old-release", node_id="exit"),
                    "rollback_snapshot": "/etc/vpn-stack/backups/revisions/old",
                },
                {
                    "state": "idle",
                    "current_present": True,
                    "rollback_snapshot": "/etc/vpn-stack/backups/revisions/new",
                },
                "new-release",
            )
        )

    def test_wait_for_ru_transport_ready_reconciles_until_healthy(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY)
        responses = [
            json.dumps({"state": "suspect", "selected": "interserver-underlay-hy2", "reason": "confirmation 1/2"}),
            json.dumps({"state": "healthy", "selected": "interserver-underlay-wg", "reason": "healthy"}),
        ]
        with (
            patch("vpn_installer.workflows.ssh_capture", side_effect=responses) as capture,
            patch("vpn_installer.workflows.time.sleep") as sleep,
        ):
            payload = workflows.wait_for_ru_transport_ready(target, timeout_sec=10, interval_sec=0.5)

        self.assertEqual(payload["state"], "healthy")
        self.assertEqual(capture.call_count, 2)
        sleep.assert_called_once_with(0.5)

    def test_install_remote_node_uses_bundle_for_install(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="ru.example", ssh_user="root")
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out" / "demo" / "bundle"
            out_dir.mkdir(parents=True)
            bundle = out_dir / "gateway.tar.gz"
            bundle.write_text("bundle", encoding="utf-8")
            with patch("vpn_installer.workflows.deployment_out_dir", return_value=Path(tmp) / "out" / "demo"), patch("vpn_installer.workflows.ssh_stream") as ssh_mock, patch("vpn_installer.workflows.scp_upload") as scp_mock:
                workflows.install_remote_node(target, "demo", env, "install")
        scp_mock.assert_called_once()
        self.assertEqual(ssh_mock.call_count, 3)
        self.assertIn("umask 077", ssh_mock.call_args_list[0].args[1])
        self.assertIn("install -d -m 0700 /var/log/vpn-stack", ssh_mock.call_args_list[1].args[1])
        self.assertIn("/var/log/vpn-stack/install.log", ssh_mock.call_args_list[1].args[1])
        install_command = ssh_mock.call_args_list[2].args[1]
        self.assertIn("systemd-run --quiet --wait --collect", install_command)
        self.assertIn("StandardOutput=append:/var/log/vpn-stack/install.log", install_command)
        self.assertIn("chmod 0600 ./deployment.env", install_command)
        self.assertIn("--node gateway", install_command)

    def test_install_remote_node_defers_cleanup_after_any_install_error(self) -> None:
        env = generate_default_env("demo")
        target = RemoteTarget(node_id=NODE_GATEWAY)
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = Path(tmp) / "bundle"
            bundle_dir.mkdir()
            (bundle_dir / "gateway.tar.gz").write_bytes(b"bundle")
            with (
                patch("vpn_installer.workflows.deployment_out_dir", return_value=Path(tmp)),
                patch(
                    "vpn_installer.workflows.ssh_stream",
                    side_effect=[None, None, AppError("remote installer exited with status 137")],
                ),
                patch("vpn_installer.workflows.scp_upload"),
                patch("vpn_installer.workflows.cleanup_remote_workdir") as cleanup,
            ):
                with self.assertRaises(AppError) as raised:
                    workflows.install_remote_node(target, "demo", env, "install")
        cleanup.assert_not_called()
        self.assertIn("/tmp/vpn-stack-installer-demo-gateway-", getattr(raised.exception, "vpn_remote_root"))
        self.assertEqual(getattr(raised.exception, "vpn_remote_log"), "/var/log/vpn-stack/install.log")

    def test_install_remote_node_uses_self_contained_support_bundle_for_remove(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="ru.example", ssh_user="root")
        with tempfile.TemporaryDirectory() as tmp:
            support = Path(tmp) / "installer-support.tar.gz"
            support.write_bytes(b"support")
            with (
                patch("vpn_installer.workflows.package_control_bundle", return_value=support),
                patch("vpn_installer.workflows.ssh_stream") as ssh_mock,
                patch("vpn_installer.workflows.scp_upload") as scp_mock,
            ):
                workflows.install_remote_node(target, "demo", {}, "remove")
        scp_mock.assert_called_once()
        self.assertEqual(ssh_mock.call_count, 3)
        self.assertEqual(scp_mock.call_args.args[0], target)
        self.assertEqual(scp_mock.call_args.args[1], support)
        self.assertIn("tar -xzf installer-support.tar.gz", ssh_mock.call_args_list[2].args[1])
        self.assertIn("--node gateway --action remove", ssh_mock.call_args_list[2].args[1])

    def test_verify_rollback_node_accepts_cross_version_service_evidence(self) -> None:
        observed = {
            "installed": "1", "node": NODE_EXIT, "deployment_name": "demo", "release_id": "old-release",
            "wireguard": "active", "wg_qdisc": "fq", "nftables": "active", "sing_box": "active", "resolver": "active", "drift": "none",
        }
        services = [
            rollback_service("sing-box", "sing-box.service"),
            rollback_service("nftables", "vpn-stack-nftables.service"),
            rollback_service("resolver", "systemd-resolved.service", ownership="borrowed"),
            rollback_service("wireguard", "wg-quick@wg0.service"),
        ]
        with (
            patch("vpn_installer.workflows.remote_preflight", return_value=observed),
            patch("vpn_installer.workflows.remote_install_transaction_state", return_value=transaction_state("old-release", node_id="exit", rollback_services=services)),
        ):
            workflows.verify_rollback_node(RemoteTarget(node_id=NODE_EXIT), "demo", "wg0", "old-release")

    def test_verify_rollback_node_requires_exact_previous_release(self) -> None:
        observed = {
            "installed": "1", "node": NODE_EXIT, "deployment_name": "demo", "release_id": "unexpected",
            "wireguard": "active", "wg_qdisc": "fq", "nftables": "active", "sing_box": "active", "resolver": "active", "drift": "none",
        }
        services = [
            rollback_service("sing-box", "sing-box.service"),
            rollback_service("nftables", "vpn-stack-nftables.service"),
            rollback_service("resolver", "systemd-resolved.service", ownership="borrowed"),
            rollback_service("wireguard", "wg-quick@wg0.service"),
        ]
        with (
            patch("vpn_installer.workflows.remote_preflight", return_value=observed),
            patch("vpn_installer.workflows.remote_install_transaction_state", return_value=transaction_state("old-release", node_id="exit", rollback_services=services)),
        ):
            with self.assertRaisesRegex(AppError, "release_id=unexpected"):
                workflows.verify_rollback_node(RemoteTarget(node_id=NODE_EXIT), "demo", "wg0", "old-release")

    def test_verify_rollback_node_rejects_unrestored_wireguard_qdisc(self) -> None:
        observed = {
            "installed": "1",
            "node": NODE_EXIT,
            "deployment_name": "demo",
            "release_id": "old-release",
            "wg_qdisc": "noqueue",
            "drift": "none",
        }
        services = [
            rollback_service("sing-box", "sing-box.service"),
            rollback_service("nftables", "vpn-stack-nftables.service"),
            rollback_service("resolver", "systemd-resolved.service", ownership="borrowed"),
            rollback_service("wireguard", "wg-quick@wg0.service"),
        ]
        with (
            patch("vpn_installer.workflows.remote_preflight", return_value=observed),
            patch(
                "vpn_installer.workflows.remote_install_transaction_state",
                return_value=transaction_state("old-release", node_id="exit", rollback_services=services),
            ),
        ):
            with self.assertRaisesRegex(AppError, "wg_qdisc=noqueue expected=fq"):
                workflows.verify_rollback_node(
                    RemoteTarget(node_id=NODE_EXIT),
                    "demo",
                    "wg0",
                    "old-release",
                )

    def test_verify_rollback_node_single_does_not_require_wireguard(self) -> None:
        observed = {
            "installed": "1",
            "node": NODE_GATEWAY,
            "deployment_name": "demo",
            "release_id": "old-release",
            "wireguard": "not-applicable",
            "nftables": "active",
            "sing_box": "active",
            "resolver": "active",
            "xray": "active",
            "drift": "none",
        }
        services = [
            rollback_service("sing-box", "sing-box.service"),
            rollback_service("nftables", "vpn-stack-nftables.service"),
            rollback_service("resolver", "systemd-resolved.service", ownership="borrowed"),
            rollback_service("xray", "vpn-stack-xray.service"),
        ]
        with (
            patch("vpn_installer.workflows.remote_preflight", return_value=observed),
            patch("vpn_installer.workflows.remote_install_transaction_state", return_value=transaction_state("old-release", node_id="gateway", rollback_services=services)),
        ):
            workflows.verify_rollback_node(
                RemoteTarget(node_id=NODE_GATEWAY),
                "demo",
                "wg0",
                "old-release",
                wireguard_required=False,
                public_front_required=True,
            )

    def test_verify_rollback_node_accepts_first_install_restored_to_uninstalled(self) -> None:
        services = [
            rollback_service("sing-box", "sing-box.service", enabled="not-found", active="inactive"),
            rollback_service("nftables", "vpn-stack-nftables.service", enabled="not-found", active="inactive"),
            rollback_service("resolver", "systemd-resolved.service", enabled="enabled", active="active", ownership="borrowed"),
            rollback_service("xray", "vpn-stack-xray.service", enabled="not-found", active="inactive"),
        ]
        with (
            patch("vpn_installer.workflows.remote_preflight", return_value={"installed": "0"}),
            patch("vpn_installer.workflows.remote_install_transaction_state", return_value=transaction_state(rollback_services=services)),
        ):
            workflows.verify_rollback_node(
                RemoteTarget(node_id=NODE_GATEWAY),
                "demo",
                "wg0",
                "",
                wireguard_required=False,
                public_front_required=True,
            )

    def test_rollback_changed_nodes_skips_vless_gate_after_first_install_is_removed(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="ru")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        target = RemoteTarget(node_id=NODE_GATEWAY)
        with (
            patch("vpn_installer.workflows.install_remote_node") as rollback,
            patch("vpn_installer.workflows.verify_rollback_node") as verify_node,
            patch("vpn_installer.workflows.verify_postcutover") as verify_vless,
        ):
            workflows.rollback_changed_nodes(
                [NODE_GATEWAY],
                {NODE_GATEWAY: target},
                "demo",
                env,
                {NODE_GATEWAY: ""},
            )
        rollback.assert_called_once_with(target, "demo", env, "rollback")
        self.assertEqual(verify_node.call_args.args[3], "")
        verify_vless.assert_not_called()

    def test_filter_targets_for_remove_skips_unmanaged_hosts(self) -> None:
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        with patch("sys.stdout", new_callable=__import__("io").StringIO) as stream:
            result = workflows.filter_targets_for_action(
                "remove",
                [ru, foreign],
                {
                    NODE_GATEWAY: {"installed": "0"},
                    NODE_EXIT: {"installed": "1"},
                },
            )
        self.assertEqual(result, [foreign])
        self.assertIn("Сервер входа: стек не найден на сервере, действие remove пропущено.", stream.getvalue())

    def test_load_env_for_render_rewrites_existing_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "demo.env"
            env_path.write_text(render_env_text(generate_default_env("demo")), encoding="utf-8")
            with patch("vpn_installer.workflows.write_private_text") as write_text_mock:
                env = workflows.load_env_for_render(env_path)
        self.assertEqual(env["DEPLOY_NAME"], "demo")
        write_text_mock.assert_called_once()

    def test_postcutover_verification_is_functional_only(self) -> None:
        with patch("vpn_installer.verify.verify_live_workflow", return_value=0) as verify:
            workflows.verify_postcutover("demo")

        verify.assert_called_once_with(
            "demo",
            non_interactive=True,
            throughput_seconds=0,
            require_native_agent=True,
            accept_install_gate=True,
        )

    def test_postcutover_verification_confirms_transient_failure(self) -> None:
        with (
            patch("vpn_installer.verify.verify_live_workflow", side_effect=[1, 0]) as verify,
            patch("vpn_installer.workflows.time.sleep") as sleep,
            patch("vpn_installer.workflows.warn") as warning,
        ):
            workflows.verify_postcutover("demo")

        self.assertEqual(verify.call_count, 2)
        sleep.assert_called_once_with(workflows.POSTCUTOVER_VERIFY_RETRY_DELAY_SECONDS)
        warning.assert_called_once()

    def test_postcutover_verification_rejects_confirmed_failure(self) -> None:
        with (
            patch("vpn_installer.verify.verify_live_workflow", return_value=1) as verify,
            patch("vpn_installer.workflows.time.sleep"),
        ):
            with self.assertRaisesRegex(AppError, "двух последовательных циклах"):
                workflows.verify_postcutover("demo")

        self.assertEqual(verify.call_count, 2)

    def test_run_selected_remote_action_install_orders_nodes(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        order: list[str] = []

        def remember(target: RemoteTarget, *_args, **_kwargs):
            order.append(target.node_id)

        with patch("vpn_installer.workflows.render_all_artifacts"), patch("vpn_installer.workflows.install_remote_node_with_recovery", side_effect=remember), patch("vpn_installer.workflows.wait_for_ru_transport_ready") as ready, patch("vpn_installer.workflows.verify_postcutover"):
            workflows.run_selected_remote_action(
                "install",
                "demo",
                Path("deployments/demo.env"),
                env,
                [ru, foreign],
                node_arg="all",
                preflights={NODE_GATEWAY: {"installed": "1"}, NODE_EXIT: {"installed": "1"}},
            )
        self.assertEqual(order, [NODE_EXIT, NODE_GATEWAY])
        self.assertEqual(ready.call_args_list, [call(ru), call(ru)])

    def test_settle_transport_after_install_is_not_applicable_to_single_topology(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="ru")
        gateway = RemoteTarget(node_id=NODE_GATEWAY)
        with patch("vpn_installer.workflows.wait_for_ru_transport_ready") as ready:
            workflows.settle_transport_after_install(
                NODE_GATEWAY,
                {NODE_GATEWAY: gateway},
                {NODE_GATEWAY: {"installed": "1"}},
                env,
            )
        ready.assert_not_called()

    def test_run_selected_remote_action_install_recovers_after_disconnect(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(node_id=NODE_EXIT)
        recovered = {
            "installed": "1", "node": NODE_EXIT, "deployment_name": "demo", "release_id": "release-1", "drift": "none",
            "acceptance_present": "True", "acceptance_release_id": "release-1", "acceptance_node_id": "exit",
            "acceptance_deployment": "demo", "current_present": "True", "current_release_id": "release-1",
            "current_target": "/etc/vpn-stack/releases/release-1", "current_node_id": "exit",
        }
        with patch("vpn_installer.workflows.render_all_artifacts"), patch("vpn_installer.workflows.install_remote_node", side_effect=AppError("Socket exception: An existing connection was forcibly closed by the remote host (10054)")), patch("vpn_installer.workflows.wait_for_remote_install_completion", return_value=recovered) as wait_mock, patch("vpn_installer.workflows.remote_install_transaction_state", return_value=transaction_state("old-release", node_id="exit")), patch("vpn_installer.workflows.expected_release_id_for_node", return_value="release-1"), patch("vpn_installer.workflows.warn") as warn_mock, patch("vpn_installer.workflows.verify_postcutover"):
            workflows.run_selected_remote_action("reinstall", "demo", Path("deployments/demo.env"), env, [foreign], node_arg=NODE_EXIT)
        wait_mock.assert_called_once()
        warn_mock.assert_called()

    def test_run_selected_remote_action_rejects_unconfirmed_disconnect(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(node_id=NODE_EXIT)
        recovered = {
            "installed": "1", "node": NODE_EXIT, "deployment_name": "demo", "release_id": "old-release", "drift": "none",
            "acceptance_present": "True", "acceptance_release_id": "old-release", "acceptance_node_id": "exit",
            "acceptance_deployment": "demo", "current_present": "True", "current_release_id": "old-release",
            "current_target": "/etc/vpn-stack/releases/old-release", "current_node_id": "exit",
        }
        with patch("vpn_installer.workflows.render_all_artifacts"), patch("vpn_installer.workflows.install_remote_node", side_effect=AppError("connection reset by peer")), patch("vpn_installer.workflows.wait_for_remote_install_completion", return_value=recovered), patch("vpn_installer.workflows.remote_install_transaction_state", return_value=transaction_state("old-release", node_id="exit")), patch("vpn_installer.workflows.expected_release_id_for_node", return_value="new-release"):
            with self.assertRaisesRegex(AppError, "установка не подтверждена"):
                workflows.run_selected_remote_action("reinstall", "demo", Path("deployments/demo.env"), env, [foreign], node_arg=NODE_EXIT)

    def test_run_selected_remote_action_reconciles_exit_137_and_rolls_back_cutover(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(node_id=NODE_EXIT)
        recovered = {
            "installed": "1", "node": NODE_EXIT, "deployment_name": "demo", "release_id": "new-release", "drift": "none",
            "acceptance_present": "True", "acceptance_release_id": "old-release", "acceptance_node_id": "exit",
            "acceptance_deployment": "demo", "current_present": "True", "current_release_id": "new-release",
            "current_target": "/etc/vpn-stack/releases/new-release", "current_node_id": "exit",
        }
        with (
            patch("vpn_installer.workflows.render_all_artifacts"),
            patch("vpn_installer.workflows.install_remote_node", side_effect=[AppError("remote installer exited with status 137"), None]) as install,
            patch("vpn_installer.workflows.wait_for_remote_install_completion", return_value=recovered),
            patch("vpn_installer.workflows.remote_install_transaction_state", return_value=transaction_state("old-release", node_id="exit")),
            patch("vpn_installer.workflows.expected_release_id_for_node", return_value="new-release"),
            patch("vpn_installer.workflows.verify_rollback_node"),
            patch("vpn_installer.workflows.verify_postcutover"),
        ):
            with self.assertRaisesRegex(AppError, "автоматически возвращены"):
                workflows.run_selected_remote_action("reinstall", "demo", Path("deployments/demo.env"), env, [foreign], node_arg=NODE_EXIT)
        self.assertEqual(install.call_count, 2)
        self.assertEqual(install.call_args_list[-1].args[-1], "rollback")

    def test_run_selected_remote_action_install_reraises_nonrecoverable_error(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(node_id=NODE_EXIT)
        recovered = {
            "installed": "1", "node": NODE_EXIT, "deployment_name": "demo", "release_id": "old-release", "drift": "none",
            "acceptance_present": "True", "acceptance_release_id": "old-release", "acceptance_node_id": "exit",
            "acceptance_deployment": "demo", "current_present": "True", "current_release_id": "old-release",
            "current_target": "/etc/vpn-stack/releases/old-release", "current_node_id": "exit",
        }
        with patch("vpn_installer.workflows.render_all_artifacts"), patch("vpn_installer.workflows.install_remote_node", side_effect=AppError("permission denied")) as install, patch("vpn_installer.workflows.wait_for_remote_install_completion", return_value=recovered) as wait_mock, patch("vpn_installer.workflows.remote_install_transaction_state", return_value=transaction_state("old-release", node_id="exit")), patch("vpn_installer.workflows.expected_release_id_for_node", return_value="new-release"):
            with self.assertRaises(AppError):
                workflows.run_selected_remote_action("reinstall", "demo", Path("deployments/demo.env"), env, [foreign], node_arg=NODE_EXIT)
        wait_mock.assert_called_once()
        install.assert_called_once()

    def test_run_selected_remote_action_remove_noops_when_targets_empty(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        with patch("vpn_installer.workflows.install_remote_node") as install_remote, patch("vpn_installer.workflows.remote_preflight") as remote_preflight, patch("vpn_installer.workflows.print_preflight") as print_preflight:
            workflows.run_selected_remote_action("remove", "demo", Path("deployments/demo.env"), env, [], node_arg=NODE_GATEWAY)
        install_remote.assert_not_called()
        remote_preflight.assert_not_called()
        print_preflight.assert_not_called()

    def test_run_selected_remote_action_remove_all_uses_only_available_nodes(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(node_id=NODE_EXIT)
        with patch("vpn_installer.workflows.install_remote_node") as install_remote, patch("vpn_installer.workflows.remote_preflight", return_value={"installed": "1"}) as remote_preflight, patch("vpn_installer.workflows.print_preflight") as print_preflight:
            workflows.run_selected_remote_action("remove", "demo", Path("deployments/demo.env"), env, [foreign], node_arg="all")
        install_remote.assert_called_once_with(foreign, "demo", env, "remove")
        remote_preflight.assert_called_once()
        print_preflight.assert_called_once()

    def test_install_workflow_returns_zero_when_all_skipped(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {NODE_EXIT: {"default_iface": "eth1"}, NODE_GATEWAY: {}})), patch("vpn_installer.workflows.ensure_foreign_wan_interface"), patch("vpn_installer.workflows.write_private_text"), patch("vpn_installer.workflows.write_state"), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.ask_install_action", return_value="skip"):
            self.assertEqual(workflows.install_workflow("demo"), 0)

    def test_install_workflow_runs_selected_actions(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {NODE_EXIT: {"default_iface": "eth1"}, NODE_GATEWAY: {}})), patch("vpn_installer.workflows.ensure_foreign_wan_interface"), patch("vpn_installer.workflows.write_private_text"), patch("vpn_installer.workflows.write_state"), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.ask_install_action", side_effect=["skip", "install"]), patch("vpn_installer.workflows.prompt_yes_no", return_value=True), patch("vpn_installer.workflows.render_all_artifacts") as render_all, patch("vpn_installer.workflows.install_remote_node_with_recovery") as install_remote, patch("vpn_installer.workflows.verify_postcutover") as verify_postcutover, patch("vpn_installer.workflows.finalize_install_output") as finalize:
            self.assertEqual(workflows.install_workflow("demo"), 0)
        render_all.assert_called_once()
        install_remote.assert_called_once()
        verify_postcutover.assert_called_once_with("demo")
        finalize.assert_called_once_with(env, "demo")

    def test_install_workflow_single_foreign_touches_only_gateway(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "198.51.100.20"
        gateway = RemoteTarget(node_id=NODE_GATEWAY, location="foreign", public_ip="198.51.100.20")
        with (
            patch(
                "vpn_installer.workflows.prepare_remote_session",
                return_value=(
                    "demo",
                    Path("deployments/demo.env"),
                    env,
                    {},
                    [gateway],
                    {NODE_GATEWAY: {"installed": "0"}},
                ),
            ) as prepare,
            patch("vpn_installer.workflows.ensure_foreign_wan_interface") as ensure_wan,
            patch("vpn_installer.workflows.write_private_text"),
            patch("vpn_installer.workflows.write_state"),
            patch("vpn_installer.workflows.print_summary"),
            patch("vpn_installer.workflows.render_all_artifacts"),
            patch("vpn_installer.workflows.install_remote_node_with_recovery") as install_remote,
            patch("vpn_installer.workflows.verify_postcutover"),
            patch("vpn_installer.workflows.finalize_install_output"),
        ):
            self.assertEqual(
                workflows.install_workflow(
                    "demo",
                    non_interactive=True,
                    yes=True,
                    topology_mode="single",
                    gateway_location="foreign",
                ),
                0,
            )
        self.assertIsNone(prepare.call_args.kwargs["nodes"])
        self.assertFalse(prepare.call_args.kwargs["sync_remote_env"])
        ensure_wan.assert_not_called()
        install_remote.assert_called_once()
        self.assertIs(install_remote.call_args.args[0], gateway)

    def test_install_workflow_rolls_back_changed_nodes_when_vless_gate_fails(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        calls: list[tuple[str, str]] = []

        def install(target: RemoteTarget, _deployment: str, _env: dict[str, str], action: str, *_args) -> None:
            calls.append((target.node_id, action))

        with (
            patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {NODE_EXIT: {"default_iface": "eth1", "installed": "1"}, NODE_GATEWAY: {"installed": "1"}})),
            patch("vpn_installer.workflows.ensure_foreign_wan_interface"),
            patch("vpn_installer.workflows.write_private_text"),
            patch("vpn_installer.workflows.write_state"),
            patch("vpn_installer.workflows.print_summary"),
            patch("vpn_installer.workflows.prompt_yes_no", return_value=True),
            patch("vpn_installer.workflows.render_all_artifacts"),
            patch("vpn_installer.workflows.install_remote_node_with_recovery", side_effect=install),
            patch("vpn_installer.workflows.wait_for_ru_transport_ready"),
            patch("vpn_installer.workflows.install_remote_node", side_effect=install),
            patch("vpn_installer.workflows.verify_rollback_node"),
            patch("vpn_installer.workflows.verify_postcutover", side_effect=[AppError("gate failed"), None]),
        ):
            with self.assertRaisesRegex(AppError, "автоматически возвращены"):
                workflows.install_workflow("demo", non_interactive=True, yes=True)

        self.assertEqual(
            calls,
            [
                (NODE_EXIT, "reinstall"),
                (NODE_GATEWAY, "reinstall"),
                (NODE_GATEWAY, "rollback"),
                (NODE_EXIT, "rollback"),
            ],
        )

    def test_maintain_reports_updates_without_mutating_servers(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        snapshot = DiagnosticsSnapshot(maintenance={"upgradable": 4, "security_upgradable": 2, "reboot_required": False}).to_dict()
        with (
            patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {})),
            patch("vpn_installer.workflows.remote_agent_snapshot", return_value=snapshot) as agent_snapshot,
            patch("vpn_installer.workflows.ssh_stream") as ssh_stream,
        ):
            self.assertEqual(workflows.maintain_workflow("demo", apply_updates=False, refresh_assets=False, reboot=False, non_interactive=True), 0)
        self.assertEqual(agent_snapshot.call_count, 2)
        ssh_stream.assert_not_called()

    def test_maintain_single_uses_only_the_configured_gateway(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "198.51.100.20"
        gateway = RemoteTarget(node_id=NODE_GATEWAY, location="foreign")
        snapshot = DiagnosticsSnapshot(
            maintenance={"upgradable": 0, "security_upgradable": 0, "reboot_required": False}
        ).to_dict()
        with (
            patch(
                "vpn_installer.workflows.prepare_remote_session",
                return_value=("demo", Path("deployments/demo.env"), env, {}, [gateway], {}),
            ),
            patch("vpn_installer.workflows.remote_agent_snapshot", return_value=snapshot) as agent_snapshot,
        ):
            self.assertEqual(
                workflows.maintain_workflow(
                    "demo",
                    apply_updates=False,
                    refresh_assets=False,
                    reboot=False,
                    non_interactive=True,
                ),
                0,
            )
        agent_snapshot.assert_called_once_with(gateway)

    def test_maintain_runs_full_vless_gate_after_each_changed_node(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        collectors = {
            name: CollectorState(status="ok", observed_at="2026-08-16T12:00:00+00:00")
            for name in COLLECTOR_NAMES
        }
        snapshot = DiagnosticsSnapshot(
            collectors=collectors,
            component_verdicts={"server_path": "verified", "public_front": "verified"},
            maintenance={"reboot_required": False},
        ).to_dict()
        events: list[str] = []

        def install(target: RemoteTarget, *_args, **_kwargs) -> None:
            events.append(f"assets:{target.node_id}")

        def update(target: RemoteTarget, *_args, **_kwargs) -> None:
            events.append(f"updates:{target.node_id}")

        def verify(_deployment: str, *_args, **_kwargs) -> None:
            events.append("verify")

        with (
            patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {})),
            patch("vpn_installer.workflows.render_config_artifacts"),
            patch("vpn_installer.workflows.package_bundle"),
            patch("vpn_installer.workflows.install_remote_node_with_recovery", side_effect=install),
            patch("vpn_installer.workflows.ssh_stream", side_effect=update),
            patch("vpn_installer.workflows.remote_agent_snapshot", return_value=snapshot),
            patch("vpn_installer.workflows.verify_postcutover", side_effect=verify) as verify_vless,
        ):
            result = workflows.maintain_workflow(
                "demo",
                apply_updates=True,
                refresh_assets=True,
                reboot=False,
                non_interactive=True,
                yes=True,
            )

        self.assertEqual(result, 0)
        self.assertEqual(
            events,
            [
                f"assets:{NODE_EXIT}",
                "verify",
                f"assets:{NODE_GATEWAY}",
                "verify",
                f"updates:{NODE_EXIT}",
                "verify",
                f"updates:{NODE_GATEWAY}",
                "verify",
            ],
        )
        self.assertEqual(verify_vless.call_count, 4)

    def test_remote_action_workflow_stops_on_user_decline(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru], {NODE_GATEWAY: {}})), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.prompt_yes_no", return_value=False):
            self.assertEqual(workflows.remote_action_workflow("demo", NODE_GATEWAY, "remove"), 0)

    def test_remote_action_workflow_skips_remove_when_stack_absent(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru], {NODE_GATEWAY: {"installed": "0"}})), patch("vpn_installer.workflows.print_summary") as print_summary, patch("vpn_installer.workflows.prompt_yes_no") as prompt_yes_no, patch("vpn_installer.workflows.run_selected_remote_action") as run_selected, patch("sys.stdout", new_callable=__import__('io').StringIO) as stream:
            self.assertEqual(workflows.remote_action_workflow("demo", NODE_GATEWAY, "remove"), 0)
        print_summary.assert_called_once()
        prompt_yes_no.assert_not_called()
        run_selected.assert_not_called()
        self.assertIn("Подходящих серверов для действия не найдено.", stream.getvalue())

    def test_remote_action_workflow_remove_all_runs_only_remaining_node(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        with patch(
            "vpn_installer.workflows.prepare_remote_session",
            return_value=(
                "demo",
                Path("deployments/demo.env"),
                env,
                {},
                [ru, foreign],
                {NODE_GATEWAY: {"installed": "0"}, NODE_EXIT: {"installed": "1"}},
            ),
        ), patch("vpn_installer.workflows.print_summary") as print_summary, patch("vpn_installer.workflows.prompt_yes_no", return_value=True) as prompt_yes_no, patch("vpn_installer.workflows.run_selected_remote_action") as run_selected, patch("sys.stdout", new_callable=__import__('io').StringIO) as stream:
            self.assertEqual(workflows.remote_action_workflow("demo", "all", "remove"), 0)
        print_summary.assert_called_once()
        prompt_yes_no.assert_called_once()
        run_selected.assert_called_once()
        call_args = run_selected.call_args
        self.assertEqual(call_args.args[4], [foreign])
        self.assertEqual(call_args.kwargs["node_arg"], "all")
        self.assertIn("Сервер входа: стек не найден на сервере, действие remove пропущено.", stream.getvalue())

    def test_remote_action_workflow_reinstall_updates_env_and_finalizes(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        foreign = RemoteTarget(node_id=NODE_EXIT)
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [foreign], {NODE_EXIT: {"default_iface": "eth1"}})), patch("vpn_installer.workflows.ensure_foreign_wan_interface"), patch("vpn_installer.workflows.write_private_text") as write_text_mock, patch("vpn_installer.workflows.write_state") as write_state_mock, patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.prompt_yes_no", return_value=True), patch("vpn_installer.workflows.run_selected_remote_action") as run_selected, patch("vpn_installer.workflows.finalize_install_output") as finalize:
            self.assertEqual(workflows.remote_action_workflow("demo", NODE_EXIT, "reinstall"), 0)
        write_text_mock.assert_called_once()
        write_state_mock.assert_called_once()
        run_selected.assert_called_once()
        finalize.assert_called_once_with(env, "demo")

    def test_remote_action_single_all_reinstall_does_not_require_an_exit(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="ru")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        gateway = RemoteTarget(node_id=NODE_GATEWAY, location="ru")
        with (
            patch(
                "vpn_installer.workflows.prepare_remote_session",
                return_value=(
                    "demo",
                    Path("deployments/demo.env"),
                    env,
                    {},
                    [gateway],
                    {NODE_GATEWAY: {"installed": "1"}},
                ),
            ),
            patch("vpn_installer.workflows.ensure_foreign_wan_interface") as ensure_wan,
            patch("vpn_installer.workflows.write_private_text"),
            patch("vpn_installer.workflows.write_state"),
            patch("vpn_installer.workflows.print_summary"),
            patch("vpn_installer.workflows.run_selected_remote_action") as run_selected,
            patch("vpn_installer.workflows.finalize_install_output"),
        ):
            self.assertEqual(
                workflows.remote_action_workflow(
                    "demo",
                    "all",
                    "reinstall",
                    non_interactive=True,
                    yes=True,
                ),
                0,
            )
        ensure_wan.assert_not_called()
        self.assertEqual(run_selected.call_args.args[4], [gateway])

    def test_client_check_all_ignores_unconfigured_exit_in_single_topology(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "198.51.100.20"
        with (
            patch("vpn_installer.workflows.ensure_directories"),
            patch("vpn_installer.workflows.select_existing_deployment", return_value="demo"),
            patch(
                "vpn_installer.workflows.load_existing_deployment_env",
                return_value=(Path("deployments/demo.env"), env),
            ),
            patch("vpn_installer.workflows.load_state", return_value={}),
            patch("vpn_installer.workflows.build_target", wraps=targets.build_target) as build,
            patch("vpn_installer.workflows.local_route_to_server", return_value=None),
            patch("vpn_installer.workflows.find_client_drift", return_value=[]),
        ):
            self.assertEqual(workflows.client_check_workflow("demo", "all"), 0)
        self.assertEqual(build.call_count, 1)
        self.assertEqual(build.call_args.args[0], NODE_GATEWAY)

    def test_status_workflow_prints_summary_without_mutation(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        payload = compact_snapshot(NODE_GATEWAY, "ru")
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru], {})), patch("vpn_installer.workflows.print_summary") as mocked, patch("vpn_installer.workflows.remote_agent_snapshot", return_value=payload) as agent_snapshot:
            self.assertEqual(workflows.status_workflow("demo", NODE_GATEWAY), 0)
        mocked.assert_called_once()
        agent_snapshot.assert_called_once_with(ru, compact=True)

    def test_status_workflow_prints_one_structured_snapshot_per_node(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        foreign = RemoteTarget(node_id=NODE_EXIT)
        snapshots = [compact_snapshot(NODE_GATEWAY, "ru"), compact_snapshot(NODE_EXIT, "foreign")]
        with patch("vpn_installer.workflows.prepare_remote_session", return_value=("demo", Path("deployments/demo.env"), env, {}, [ru, foreign], {})), patch("vpn_installer.workflows.print_summary"), patch("vpn_installer.workflows.remote_agent_snapshot", side_effect=snapshots) as agent_snapshot:
            self.assertEqual(workflows.status_workflow("demo", "all"), 0)
        self.assertEqual(agent_snapshot.call_count, 2)
        for call in agent_snapshot.call_args_list:
            self.assertTrue(call.kwargs["compact"])

    def test_status_workflow_accepts_native_compact_snapshot_without_false_errors(self) -> None:
        env = generate_default_env("demo")
        ru = RemoteTarget(node_id=NODE_GATEWAY)
        observed_at = "2026-08-07T04:26:48+00:00"
        collectors = {name: CollectorState.ok(observed_at) for name in COLLECTOR_NAMES}
        collectors["route_probes"] = CollectorState.skipped("live route probes were not requested")
        collectors["maintenance"] = CollectorState.skipped("maintenance state was not requested")
        windows = {
            name: LogWindowSnapshot.empty(observed_at=observed_at)
            for name in LOG_WINDOW_KEYS
        }
        windows["30m"] = LogWindowSnapshot.skipped("30m window was not requested")
        windows["24h"] = LogWindowSnapshot.skipped("24h window was not requested")
        snapshot = DiagnosticsSnapshot(
            topology="dual",
            generated_at=observed_at,
            node_id=NODE_GATEWAY,
            location="ru",
            capabilities=("router",),
            collectors=collectors,
            log_windows=windows,
            drift="none",
            verdict="inconclusive",
            route_probes={"profile": "none", "ok": None},
        )
        with (
            patch(
                "vpn_installer.workflows.prepare_remote_session",
                return_value=("demo", Path("deployments/demo.env"), env, {}, [ru], {}),
            ),
            patch("vpn_installer.workflows.print_summary"),
            patch("vpn_installer.workflows.remote_agent_snapshot", return_value=snapshot.to_dict()),
        ):
            self.assertEqual(workflows.status_workflow("demo", NODE_GATEWAY), 0)

    def test_menu_workflow_dispatches_actions_and_returns_to_menu(self) -> None:
        with patch("vpn_installer.workflows.prompt_choice", side_effect=["audit", "quick", "back", "exit"]), patch("vpn_installer.audit.runner.main", return_value=0) as audit_main:
            self.assertEqual(workflows.menu_workflow(), 0)
        audit_main.assert_called_once_with(["quick"])

        with patch("vpn_installer.workflows.prompt_choice", side_effect=["cleanup-local", "exit"]), patch("vpn_installer.workflows.cleanup_local_workflow", return_value=0) as cleanup:
            self.assertEqual(workflows.menu_workflow(), 0)
        cleanup.assert_called_once_with(None, drop_env=False, drop_runtime=False)

        with patch("vpn_installer.workflows.prompt_choice", side_effect=["status", "exit"]), patch("vpn_installer.workflows.select_node_for_menu", return_value="gateway"), patch("vpn_installer.workflows.status_workflow", return_value=0) as status:
            self.assertEqual(workflows.menu_workflow(), 0)
        status.assert_called_once_with(None, "gateway")

        with patch("vpn_installer.workflows.prompt_choice", side_effect=["admin", "exit"]), patch("vpn_installer.workflows.admin_access_workflow", return_value=0) as admin, patch("sys.stdout", new_callable=StringIO) as stream:
            self.assertEqual(workflows.menu_workflow(), 0)
        admin.assert_called_once_with(None)
        self.assertIn("VPN Installer", stream.getvalue())
        self.assertIn(workflows.VERSION, stream.getvalue())

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
