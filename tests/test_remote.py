from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from vpn_installer.models import AppError, ROLE_RU, RemoteTarget
from vpn_installer.remote import (
    build_remote_command,
    ensure_remote_privilege,
    parse_kv_output,
    paramiko_connect,
    paramiko_exec,
    paramiko_upload,
    preflight_script,
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

    def test_ssh_and_scp_base_args_include_identity(self) -> None:
        target = RemoteTarget(role=ROLE_RU, ssh_host="203.0.113.10", ssh_port=2222, ssh_user="root", identity_path="/tmp/id")
        self.assertIn("-i", ssh_base_args(target))
        self.assertIn("/tmp/id", ssh_base_args(target))
        self.assertIn("-P", scp_base_args(target))

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
        with patch("vpn_installer.remote.paramiko_exec", return_value=(0, "out\n", "err\n")), patch("sys.stdout", new_callable=io.StringIO) as stdout, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            ssh_stream(target, "echo ok", as_root=False)
        self.assertIn("out", stdout.getvalue())
        self.assertIn("err", stderr.getvalue())

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
        with patch("vpn_installer.remote.ssh_capture", return_value="host=demo\nrole=ru-gateway\n") as mocked:
            payload = remote_preflight(RemoteTarget(role=ROLE_RU), "wgx")
        mocked.assert_called_once()
        self.assertEqual(payload["role"], "ru-gateway")

    def test_print_preflight_emits_expected_lines(self) -> None:
        with patch("sys.stdout", new_callable=io.StringIO) as stream:
            print_preflight(
                RemoteTarget(role=ROLE_RU),
                {
                    "hostname": "demo",
                    "login_user": "root",
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "default_iface": "eth0",
                    "configured_wan_interface": "eth0",
                    "wan_mtu": "1500",
                    "default_qdisc": "fq_codel",
                    "tcp_cc": "bbr",
                    "tcp_mtu_probing": "1",
                    "netdev_backlog": "8192",
                    "rmem_max": "8388608",
                    "wmem_max": "8388608",
                    "udp_rmem_min": "16384",
                    "udp_wmem_min": "16384",
                    "iface_rx_drops": "0",
                    "iface_tx_drops": "0",
                    "installed": "1",
                    "role": "ru-gateway",
                    "deployment_name": "demo",
                    "sing_box": "active",
                    "nftables": "active",
                    "wireguard": "active",
                    "wg_transfer_rx": "1",
                    "wg_transfer_tx": "2",
                    "wg_latest_handshake": "3",
                    "sync_timer": "active",
                },
            )
        output = stream.getvalue()
        self.assertIn("host: demo", output)
        self.assertIn("configured WAN iface: eth0", output)
        self.assertIn("tcp cc: bbr", output)
        self.assertIn("wireguard transfer rx/tx: 1/2", output)

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
