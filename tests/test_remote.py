from __future__ import annotations

import io
import json
import logging
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from vpn_installer.models import AppError, ROLE_RU, RemoteTarget
from vpn_installer.remote import (
    build_remote_command,
    configure_paramiko_logging,
    ensure_remote_privilege,
    fetch_remote_deployment_env,
    parse_kv_output,
    paramiko_connect,
    open_bound_ssh_socket,
    paramiko_exec,
    paramiko_stream,
    paramiko_upload,
    preflight_script,
    bootstrap_from_snapshot,
    print_preflight,
    remote_preflight,
    scp_base_args,
    scp_upload,
    ssh_base_args,
    ssh_capture,
    ssh_stream,
    use_python_ssh_backend,
)


class RemoteTests(unittest.TestCase):
    def test_preflight_bootstrap_collects_only_install_prerequisites(self) -> None:
        script = preflight_script("wg-test")
        self.assertIn("WG_INTERFACE=wg-test", script)
        self.assertIn("wg-quick@${WG_INTERFACE}.service", script)
        self.assertIn("os_id", script)
        self.assertIn("deployment_name", script)
        self.assertIn("wg_latest_handshake_age_s", script)
        self.assertNotIn("journalctl", script)
        self.assertNotIn("curl", script)
        self.assertNotIn("probe_target_urls", script)

    def test_preflight_bootstrap_ignores_live_probe_options(self) -> None:
        script = preflight_script("wg0", fresh_since_epoch=1783733000, run_live_probes=True)
        self.assertIn("WG_INTERFACE=wg0", script)
        self.assertNotIn("run_live_probes", script)
        self.assertNotIn("1783733000", script)
    def test_password_mode_forces_python_backend(self) -> None:
        target = RemoteTarget(role=ROLE_RU, auth_mode="password")
        self.assertTrue(use_python_ssh_backend(target))

    def test_build_remote_command_with_sudo_password(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_user="ubuntu", sudo_mode="password", sudo_password="secret")
        command, input_text = build_remote_command("echo test", target, as_root=True)
        self.assertIn("sudo -S", command)
        self.assertEqual(input_text, "secret\n")

    def test_build_remote_command_quotes_heredoc_and_single_quotes(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_user="root")
        body = "python3 - <<'PY'\nprint('ok')\nPY"
        command, input_text = build_remote_command(body, target, as_root=True)
        self.assertIsNone(input_text)
        self.assertTrue(command.startswith("bash -lc "))
        self.assertIn("'\"'\"'PY'\"'\"'", command)
        self.assertIn("print('\"'\"'ok'\"'\"')", command)

    def test_key_mode_uses_system_ssh_when_available(self) -> None:
        target = RemoteTarget(role=ROLE_RU, auth_mode="key")
        with patch("vpn_installer.remote.command_exists", return_value=True):
            self.assertFalse(use_python_ssh_backend(target))

    def test_ssh_and_scp_base_args_include_identity(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_port=2222, ssh_user="root", identity_path="/tmp/id")
        self.assertIn("-i", ssh_base_args(target))
        self.assertIn("/tmp/id", ssh_base_args(target))
        self.assertIn("-P", scp_base_args(target))

    def test_ssh_and_scp_base_args_include_explicit_bind_address(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_bind_address="192.168.0.101")
        self.assertIn("BindAddress=192.168.0.101", ssh_base_args(target))
        self.assertIn("BindAddress=192.168.0.101", scp_base_args(target))

    def test_ssh_capture_passes_timeout_to_system_ssh_backend(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_user="root", auth_mode="key")
        completed = SimpleNamespace(stdout="ok")
        with (
            patch("vpn_installer.remote.command_exists", return_value=True),
            patch("vpn_installer.remote.run_command", return_value=completed) as run_mock,
        ):
            self.assertEqual(ssh_capture(target, "echo ok", command_timeout=12), "ok")
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 12)

    def test_ssh_capture_passes_timeout_to_paramiko_backend(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_user="root", auth_mode="password")
        with patch("vpn_installer.remote.paramiko_exec", return_value=(0, "ok", "")) as exec_mock:
            self.assertEqual(ssh_capture(target, "echo ok", command_timeout=12), "ok")
        self.assertEqual(exec_mock.call_args.kwargs["command_timeout"], 12)

    def test_build_remote_command_requires_privilege_confirmation(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_user="ubuntu", sudo_mode="unknown")
        with self.assertRaises(AppError):
            build_remote_command("echo test", target, as_root=True)

    def test_paramiko_connect_uses_password_mode(self) -> None:
        fake_client = Mock()
        fake_paramiko = Mock(SSHClient=Mock(return_value=fake_client), AutoAddPolicy=Mock(return_value="policy"))
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root", auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko):
            client = paramiko_connect(target)
        self.assertIs(client, fake_client)
        fake_client.connect.assert_called_once()
        kwargs = fake_client.connect.call_args.kwargs
        self.assertEqual(kwargs["password"], "secret")
        self.assertFalse(kwargs["look_for_keys"])

    def test_paramiko_connect_uses_bound_socket_when_requested(self) -> None:
        fake_client = Mock()
        fake_paramiko = Mock(SSHClient=Mock(return_value=fake_client), AutoAddPolicy=Mock(return_value="policy"))
        bound_socket = Mock()
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", auth_mode="password", ssh_password="secret", ssh_bind_address="192.168.0.101")
        with patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko), patch("vpn_installer.remote.open_bound_ssh_socket", return_value=bound_socket) as opener:
            client = paramiko_connect(target)
        self.assertIs(client, fake_client)
        opener.assert_called_once_with(target)
        self.assertIs(fake_client.connect.call_args.kwargs["sock"], bound_socket)

    def test_open_bound_ssh_socket_closes_socket_after_connect_error(self) -> None:
        fake_socket = Mock()
        fake_socket.connect.side_effect = OSError("blocked")
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_bind_address="192.168.0.101")
        with patch("vpn_installer.remote.socket.getaddrinfo", side_effect=[[(2, 1, 6, "", ("192.168.0.101", 0))], [(2, 1, 6, "", ("203.0.113.10", 22))]]), patch("vpn_installer.remote.socket.socket", return_value=fake_socket):
            with self.assertRaises(AppError):
                open_bound_ssh_socket(target)
        fake_socket.close.assert_called_once()

    def test_paramiko_connect_raises_on_failure(self) -> None:
        fake_client = Mock()
        fake_client.connect.side_effect = RuntimeError("fail")
        fake_paramiko = Mock(SSHClient=Mock(return_value=fake_client), AutoAddPolicy=Mock(return_value="policy"))
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko):
            with self.assertRaises(AppError):
                paramiko_connect(target)

    def test_paramiko_connect_retries_password_auth_timeout(self) -> None:
        class FakeAuthTimeout(Exception):
            pass

        first_client = Mock()
        first_client.connect.side_effect = FakeAuthTimeout("Authentication timeout.")
        second_client = Mock()
        ssh_client_factory = Mock(side_effect=[first_client, second_client])
        fake_paramiko = SimpleNamespace(
            SSHClient=ssh_client_factory,
            AutoAddPolicy=Mock(return_value="policy"),
            ssh_exception=SimpleNamespace(AuthenticationException=FakeAuthTimeout),
        )
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root", auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko), patch("vpn_installer.remote.time.sleep") as sleep_mock:
            client = paramiko_connect(target)
        self.assertIs(client, second_client)
        first_client.close.assert_called_once()
        sleep_mock.assert_called_once()

    def test_paramiko_connect_retries_tcp_connect_timeout(self) -> None:
        first_client = Mock()
        first_client.connect.side_effect = TimeoutError("timed out")
        second_client = Mock()
        ssh_client_factory = Mock(side_effect=[first_client, second_client])
        fake_paramiko = SimpleNamespace(
            SSHClient=ssh_client_factory,
            AutoAddPolicy=Mock(return_value="policy"),
            ssh_exception=SimpleNamespace(AuthenticationException=Exception),
        )
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko), patch("vpn_installer.remote.time.sleep") as sleep_mock:
            client = paramiko_connect(target)
        self.assertIs(client, second_client)
        first_client.close.assert_called_once()
        sleep_mock.assert_called_once()

    def test_configure_paramiko_logging_installs_null_handler(self) -> None:
        logger = logging.getLogger("paramiko")
        original_handlers = list(logger.handlers)
        original_level = logger.level
        original_propagate = logger.propagate
        try:
            logger.handlers = []
            logger.setLevel(logging.NOTSET)
            logger.propagate = True
            with patch("vpn_installer.remote._PARAMIKO_LOGGER_CONFIGURED", False):
                configure_paramiko_logging()
            self.assertTrue(any(isinstance(handler, logging.NullHandler) for handler in logger.handlers))
            self.assertEqual(logger.level, logging.CRITICAL)
            self.assertFalse(logger.propagate)
        finally:
            logger.handlers = original_handlers
            logger.setLevel(original_level)
            logger.propagate = original_propagate

    def test_paramiko_connect_rewrites_banner_timeout(self) -> None:
        class FakeSshException(Exception):
            pass

        fake_client = Mock()
        fake_client.connect.side_effect = FakeSshException("Error reading SSH protocol banner")
        fake_paramiko = SimpleNamespace(
            SSHClient=Mock(return_value=fake_client),
            AutoAddPolicy=Mock(return_value="policy"),
            ssh_exception=SimpleNamespace(AuthenticationException=Exception),
        )
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
        with patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko), patch("vpn_installer.remote.configure_paramiko_logging"), patch("vpn_installer.remote.time.sleep"):
            with self.assertRaises(AppError) as ctx:
                paramiko_connect(target)
        self.assertIn("Сервер не отдал SSH banner вовремя", str(ctx.exception))

    def test_paramiko_exec_collects_stdout_stderr_and_tolerates_shutdown_failure(self) -> None:
        channel = Mock()
        channel.recv_ready.side_effect = [True, False, False]
        channel.recv_stderr_ready.side_effect = [True, False, False]
        channel.exit_status_ready.side_effect = [False, True, True]
        channel.recv.return_value = b"out"
        channel.recv_stderr.return_value = b"err"
        channel.recv_exit_status.return_value = 5
        stdin = Mock()
        stdin.channel.shutdown_write.side_effect = RuntimeError("ignore")
        stdout = Mock(channel=channel)
        stderr = Mock(channel=channel)
        client = Mock()
        client.exec_command.return_value = (stdin, stdout, stderr)
        target = RemoteTarget(role=ROLE_RU)
        with patch("vpn_installer.remote.paramiko_connect", return_value=client), patch("vpn_installer.remote.time.sleep"):
            code, out, err = paramiko_exec(target, "echo test", input_text="secret\n")
        self.assertEqual((code, out, err), (5, "out", "err"))
        client.exec_command.assert_called_once_with("echo test", get_pty=False)
        client.close.assert_called_once()

    def test_paramiko_exec_times_out_stuck_channel(self) -> None:
        channel = Mock()
        channel.recv_ready.return_value = False
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = False
        stdin = Mock()
        stdout = Mock(channel=channel)
        stderr = Mock(channel=channel)
        client = Mock()
        client.exec_command.return_value = (stdin, stdout, stderr)
        target = RemoteTarget(role=ROLE_RU)
        with (
            patch("vpn_installer.remote.paramiko_connect", return_value=client),
            patch("vpn_installer.remote.time.monotonic", side_effect=[0.0, 2.0]),
            patch("vpn_installer.remote.time.sleep"),
        ):
            with self.assertRaises(AppError) as ctx:
                paramiko_exec(target, "journalctl -f", command_timeout=1)
        self.assertIn("не завершилась за 1 сек", str(ctx.exception))
        channel.close.assert_called_once()
        client.close.assert_called_once()

    def test_paramiko_stream_writes_output_as_it_arrives(self) -> None:
        channel = Mock()
        channel.recv_ready.side_effect = [True, False, False]
        channel.recv_stderr_ready.side_effect = [True, False, False]
        channel.exit_status_ready.side_effect = [False, True, True]
        channel.recv.return_value = b"out\n"
        channel.recv_stderr.return_value = b"err\n"
        channel.recv_exit_status.return_value = 0
        stdin = Mock()
        stdout = Mock(channel=channel)
        stderr = Mock(channel=channel)
        client = Mock()
        client.exec_command.return_value = (stdin, stdout, stderr)
        target = RemoteTarget(role=ROLE_RU)
        with (
            patch("vpn_installer.remote.paramiko_connect", return_value=client),
            patch("vpn_installer.remote.time.sleep"),
            patch("sys.stdout", new_callable=io.StringIO) as out_stream,
            patch("sys.stderr", new_callable=io.StringIO) as err_stream,
        ):
            code = paramiko_stream(target, "echo test", input_text="secret\n")
        self.assertEqual(code, 0)
        self.assertIn("out", out_stream.getvalue())
        self.assertIn("err", err_stream.getvalue())
        client.exec_command.assert_called_once_with("echo test", get_pty=False)
        client.close.assert_called_once()

    def test_paramiko_upload_wraps_error(self) -> None:
        client = Mock()
        sftp = Mock()
        sftp.put.side_effect = RuntimeError("copy failed")
        client.open_sftp.return_value = sftp
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "demo.txt"
            local.write_text("x", encoding="utf-8")
            with patch("vpn_installer.remote.paramiko_connect", return_value=client):
                with self.assertRaises(AppError):
                    paramiko_upload(RemoteTarget(role=ROLE_RU), local, "/tmp/demo.txt")
        client.close.assert_called_once()

    def test_ssh_capture_uses_paramiko_backend(self) -> None:
        target = RemoteTarget(role=ROLE_RU, auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.paramiko_exec", return_value=(0, "ok", "")) as mocked:
            result = ssh_capture(target, "echo ok", as_root=False)
        self.assertEqual(result, "ok")
        mocked.assert_called_once()

    def test_ssh_capture_raises_on_remote_error(self) -> None:
        target = RemoteTarget(role=ROLE_RU, auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.paramiko_exec", return_value=(9, "", "boom")):
            with self.assertRaises(AppError) as ctx:
                ssh_capture(target, "echo ok", as_root=False)
        self.assertIn("boom", str(ctx.exception))

    def test_ssh_stream_uses_system_ssh_for_key_mode(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_user="root", auth_mode="key")
        with patch("vpn_installer.remote.command_exists", return_value=True), patch("vpn_installer.remote.run_command") as mocked:
            ssh_stream(target, "echo ok", as_root=False)
        mocked.assert_called_once()

    def test_ssh_stream_prints_paramiko_output(self) -> None:
        target = RemoteTarget(role=ROLE_RU, auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.paramiko_stream", return_value=0) as mocked:
            ssh_stream(target, "echo ok", as_root=False)
        mocked.assert_called_once()

    def test_ssh_stream_uses_pty_only_for_sudo_password_input(self) -> None:
        target = RemoteTarget(role=ROLE_RU, auth_mode="password", ssh_password="secret", ssh_user="ubuntu", sudo_mode="password", sudo_password="sudo-secret")
        with patch("vpn_installer.remote.paramiko_stream", return_value=0) as mocked:
            ssh_stream(target, "echo ok", as_root=True)
        self.assertTrue(mocked.call_args.kwargs["get_pty"])
        self.assertEqual(mocked.call_args.kwargs["input_text"], "sudo-secret\n")

    def test_scp_upload_uses_system_scp(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_user="root", auth_mode="key")
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "bundle.tar.gz"
            local.write_text("bundle", encoding="utf-8")
            with patch("vpn_installer.remote.command_exists", return_value=True), patch("vpn_installer.remote.run_command") as mocked:
                scp_upload(target, local, "/tmp/bundle.tar.gz")
        mocked.assert_called_once()

    def test_parse_kv_output_ignores_invalid_lines(self) -> None:
        payload = "a=1\nbroken\nb = 2 \n"
        self.assertEqual(parse_kv_output(payload), {"a": "1", "b": "2"})

    def test_remote_preflight_uses_ssh_capture(self) -> None:
        snapshot = {"schema_version": 2, "role": "ru-gateway", "services": {}, "artifacts": {}, "logs": {"fresh": {}, "windows_minutes": {}}, "release": {}, "wireguard": {}, "network": {}, "front": {}}
        with patch("vpn_installer.remote.ssh_capture", return_value=json.dumps(snapshot)) as mocked:
            payload = remote_preflight(RemoteTarget(role=ROLE_RU), "wgx")
        mocked.assert_called_once()
        self.assertEqual(payload["role"], "ru-gateway")

    def test_remote_preflight_uses_compact_bootstrap_when_agent_is_unavailable(self) -> None:
        with patch("vpn_installer.remote.ssh_capture", return_value="role=ru-gateway\n") as mocked:
            remote_preflight(RemoteTarget(role=ROLE_RU), "wgx", fresh_since_epoch=1783733001)
        self.assertEqual(mocked.call_count, 2)
        self.assertIn("WG_INTERFACE=wgx", mocked.call_args.args[1])

    def test_fetch_remote_deployment_env_uses_root_capture(self) -> None:
        with patch("vpn_installer.remote.ssh_capture", return_value='DEPLOY_NAME="demo"\n') as mocked:
            payload = fetch_remote_deployment_env(RemoteTarget(role=ROLE_RU))
        self.assertEqual(payload, 'DEPLOY_NAME="demo"\n')
        mocked.assert_called_once_with(unittest.mock.ANY, "cat /etc/vpn-stack/deployment.env", as_root=True)
    def test_bootstrap_from_snapshot_uses_agent_host_and_lifecycle_fields(self) -> None:
        preflight = bootstrap_from_snapshot(
            {
                "schema_version": 2,
                "deployment": "demo",
                "role": ROLE_RU,
                "release": {"release_id": "release-1", "installed_at": "2026-07-15T00:00:00Z", "policy_version": "0.11.0"},
                "host": {"hostname": "demo", "login_user": "root", "is_root": True, "has_sudo": True, "os_id": "ubuntu", "os_version": "24.04", "default_interface": "eth0"},
                "services": {"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active", "resolver": "active", "transport": "active", "health_timer": "active"},
                "artifacts": {"drift": "none", "files": {}},
                "wireguard": {"peers": []},
                "network": {
                    "interfaces": {"eth0": {}},
                    "tcp_adaptation": {
                        "congestion_control": "bbr",
                        "qdisc": "fq",
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 1,
                        "probe_interval_seconds": 600,
                    },
                },
                "front": {"rtt_ms": {"p95": 40}, "socket_retransmissions": 3, "bytes_retrans": 1200, "retransmit_ratio_pct": 1.2, "state_counts": {"FIN-WAIT-1": 0}},
            }
        )
        self.assertEqual(preflight["is_root"], "1")
        self.assertEqual(preflight["installed"], "1")
        self.assertEqual(preflight["default_iface"], "eth0")
        self.assertEqual(preflight["resolver"], "active")
        self.assertEqual(preflight["transport"], "active")

    def test_print_preflight_emits_lifecycle_summary(self) -> None:
        with patch("sys.stdout", new_callable=io.StringIO) as stream:
            print_preflight(
                RemoteTarget(role=ROLE_RU),
                {
                    "hostname": "demo",
                    "login_user": "root",
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "default_iface": "eth0",
                    "installed": "1",
                    "deployment_name": "demo",
                    "role": "ru-gateway",
                    "drift": "none",
                    "wireguard": "active",
                    "nftables": "active",
                    "sing_box": "active",
                    "xray": "active",
                    "resolver": "active",
                    "transport": "active",
                    "health_timer": "active",
                    "wg_latest_handshake_age_s": "4",
                    "wg_transfer_rx": "1",
                    "wg_transfer_tx": "2",
                    "front_rtt_p95_ms": "40",
                    "front_retransmissions_lifetime": "3",
                    "front_retransmit_ratio_pct": "1.2",
                    "front_retransmissions_scope": "lifetime counters of currently open sockets",
                    "front_fin_wait_1": "0",
                    "tcp_congestion_control": "bbr",
                    "tcp_default_qdisc": "fq",
                    "tcp_mtu_probing": "1",
                    "tcp_mtu_probe_floor": "536",
                    "tcp_metrics_save_disabled": "1",
                    "tcp_probe_interval_seconds": "600",
                },
            )
        output = stream.getvalue()
        self.assertIn("host: demo", output)
        self.assertIn("services: wg=active, nft=active, sing-box=active, xray=active, resolver=active, transport=active, health=active", output)
        self.assertIn("wireguard: handshake_age_s=4, transfer_rx_tx=1/2", output)
        self.assertIn("front: rtt_p95_ms=40, retransmissions_lifetime=3, retransmit_ratio_pct=1.2, active=0, closing=0, fin_wait_1=0", output)
        self.assertIn("front retransmission scope: lifetime counters of currently open sockets", output)
        self.assertIn(
            "tcp adaptation: cc=bbr, qdisc=fq, mtu_probing=1, mtu_floor=536, "
            "metrics_save_disabled=1, probe_interval_s=600",
            output,
        )
    def test_ensure_remote_privilege_paths(self) -> None:
        target = RemoteTarget(role=ROLE_RU)
        ensure_remote_privilege(target, {"is_root": "1"}, prompt_yes_no=lambda *_args, **_kwargs: True, prompt_secret=lambda *_args, **_kwargs: "x")
        self.assertEqual(target.sudo_mode, "root")

        target = RemoteTarget(role=ROLE_RU)
        ensure_remote_privilege(target, {"is_root": "0", "has_sudo": "1"}, prompt_yes_no=lambda *_args, **_kwargs: True, prompt_secret=lambda *_args, **_kwargs: "x")
        self.assertEqual(target.sudo_mode, "nopasswd")

        target = RemoteTarget(role=ROLE_RU)
        ensure_remote_privilege(target, {"is_root": "0", "has_sudo": "0", "login_user": "ubuntu", "hostname": "demo"}, prompt_yes_no=lambda *_args, **_kwargs: True, prompt_secret=lambda *_args, **_kwargs: "secret")
        self.assertEqual(target.sudo_mode, "password")
        self.assertEqual(target.sudo_password, "secret")

    def test_ensure_remote_privilege_can_fail(self) -> None:
        target = RemoteTarget(role=ROLE_RU)
        with self.assertRaises(AppError):
            ensure_remote_privilege(target, {"is_root": "0", "has_sudo": "0", "login_user": "ubuntu", "hostname": "demo"}, prompt_yes_no=lambda *_args, **_kwargs: False, prompt_secret=lambda *_args, **_kwargs: "secret")


if __name__ == "__main__":
    unittest.main()
