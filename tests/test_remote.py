from __future__ import annotations

import io
import json
import logging
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from vpn_installer.models import AppError, RemoteTarget
from vpn_installer.topology import NODE_GATEWAY
from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.remote import (
    build_remote_command,
    configure_paramiko_logging,
    canonical_host_key_type,
    ensure_remote_privilege,
    ensure_target_host_key,
    fetch_remote_deployment_env,
    parse_kv_output,
    paramiko_connect,
    known_host_disabled_algorithms,
    known_host_key_types,
    load_trusted_host_keys,
    host_key_alias,
    open_bound_ssh_socket,
    paramiko_exec,
    paramiko_stream,
    paramiko_upload,
    preflight_script,
    bootstrap_from_snapshot,
    print_preflight,
    remote_agent_snapshot,
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
        self.assertIn("/etc/vpn-stack/node-id", script)
        self.assertIn("/etc/vpn-stack/installed-at", script)
        self.assertIn("printf 'node_id=%s", script)
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
        target = RemoteTarget(node_id=NODE_GATEWAY, auth_mode="password")
        self.assertTrue(use_python_ssh_backend(target))

    def test_build_remote_command_with_sudo_password(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_user="ubuntu", sudo_mode="password", sudo_password="secret")
        command, input_text = build_remote_command("echo test", target, as_root=True)
        self.assertIn("sudo -S", command)
        self.assertEqual(input_text, "secret\n")

    def test_build_remote_command_quotes_heredoc_and_single_quotes(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_user="root")
        body = "python3 - <<'PY'\nprint('ok')\nPY"
        command, input_text = build_remote_command(body, target, as_root=True)
        self.assertIsNone(input_text)
        self.assertTrue(command.startswith("timeout --signal=TERM --kill-after=5s 1800s bash -lc "))
        self.assertIn("'\"'\"'PY'\"'\"'", command)
        self.assertIn("print('\"'\"'ok'\"'\"')", command)

    def test_build_remote_command_enforces_target_side_timeout(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_user="root")
        command, _ = build_remote_command("sleep 60", target, as_root=True, command_timeout=7)
        self.assertTrue(command.startswith("timeout --signal=TERM --kill-after=5s 7s bash -lc "))

    def test_key_mode_uses_system_ssh_when_available(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, auth_mode="key")
        with patch("vpn_installer.remote.command_exists", return_value=True):
            self.assertFalse(use_python_ssh_backend(target))

    def test_ssh_and_scp_base_args_include_identity(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_port=2222, ssh_user="root", identity_path="/tmp/id")
        with tempfile.TemporaryDirectory() as tmp, patch("vpn_installer.remote.KNOWN_HOSTS_PATH", Path(tmp) / "known_hosts"):
            ssh_args = ssh_base_args(target)
            scp_args = scp_base_args(target)
        self.assertIn("-i", ssh_args)
        self.assertIn("/tmp/id", ssh_args)
        self.assertIn("-P", scp_args)
        self.assertTrue(any(value.startswith("UserKnownHostsFile=") for value in ssh_args))
        self.assertTrue(any(value.startswith("UserKnownHostsFile=") for value in scp_args))
        self.assertIn("StrictHostKeyChecking=yes", ssh_args)
        self.assertIn("StrictHostKeyChecking=yes", scp_args)
        for option in ("BatchMode=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "PreferredAuthentications=publickey", "LogLevel=ERROR"):
            self.assertIn(option, ssh_args)
            self.assertIn(option, scp_args)

    def test_ssh_and_scp_base_args_include_explicit_bind_address(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_bind_address="192.168.0.101")
        self.assertIn("BindAddress=192.168.0.101", ssh_base_args(target))
        self.assertIn("BindAddress=192.168.0.101", scp_base_args(target))

    def test_ssh_capture_passes_timeout_to_system_ssh_backend(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_user="root", auth_mode="key")
        completed = SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with (
            patch("vpn_installer.remote.command_exists", return_value=True),
            patch("vpn_installer.remote.run_command", return_value=completed) as run_mock,
        ):
            self.assertEqual(ssh_capture(target, "echo ok", command_timeout=12), "ok")
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 22)
        self.assertFalse(run_mock.call_args.kwargs["check"])
        self.assertIn("timeout --signal=TERM --kill-after=5s 12s", run_mock.call_args.args[0][-1])

    def test_ssh_capture_reports_key_failure_without_password_fallback(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_user="root", auth_mode="key")
        completed = SimpleNamespace(returncode=255, stdout="", stderr="Permission denied (publickey).")
        with (
            patch("vpn_installer.remote.command_exists", return_value=True),
            patch("vpn_installer.remote.run_command", return_value=completed),
        ):
            with self.assertRaises(AppError) as ctx:
                ssh_capture(target, "echo ok")
        lines = str(ctx.exception).splitlines()
        self.assertIn("вход по SSH key не выполнен", lines[0])
        self.assertEqual(lines[1], "Permission denied (publickey).")

    def test_ssh_capture_passes_timeout_to_paramiko_backend(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_user="root", auth_mode="password")
        with patch("vpn_installer.remote.paramiko_exec", return_value=(0, "ok", "")) as exec_mock:
            self.assertEqual(ssh_capture(target, "echo ok", command_timeout=12), "ok")
        self.assertEqual(exec_mock.call_args.kwargs["command_timeout"], 22)
        self.assertIn("timeout --signal=TERM --kill-after=5s 12s", exec_mock.call_args.args[1])

    def test_build_remote_command_requires_privilege_confirmation(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_user="ubuntu", sudo_mode="unknown")
        with self.assertRaises(AppError):
            build_remote_command("echo test", target, as_root=True)

    def test_paramiko_connect_uses_password_mode(self) -> None:
        fake_client = Mock()
        fake_paramiko = Mock(SSHClient=Mock(return_value=fake_client), AutoAddPolicy=Mock(return_value="policy"))
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root", auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko):
            client = paramiko_connect(target)
        self.assertIs(client, fake_client)
        fake_client.connect.assert_called_once()
        kwargs = fake_client.connect.call_args.kwargs
        self.assertEqual(kwargs["password"], "secret")
        self.assertFalse(kwargs["look_for_keys"])

    def test_known_rsa_host_disables_unrecorded_key_families(self) -> None:
        system_keys = Mock()
        system_keys.lookup.return_value = {"ssh-rsa": object()}
        local_keys = Mock()
        local_keys.lookup.return_value = None
        client = SimpleNamespace(_system_host_keys=system_keys, _host_keys=local_keys)
        paramiko = SimpleNamespace(
            Transport=SimpleNamespace(
                _preferred_keys=("ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")
            )
        )

        self.assertEqual(known_host_key_types(client, "example.test"), {"ssh-rsa"})
        self.assertEqual(
            known_host_disabled_algorithms(paramiko, client, "example.test"),
            {"keys": ["ssh-ed25519", "ecdsa-sha2-nistp256"]},
        )
        self.assertEqual(canonical_host_key_type("rsa-sha2-512"), "ssh-rsa")
        self.assertEqual(canonical_host_key_type("ssh-ed25519-cert-v01@openssh.com"), "ssh-ed25519")

    def test_unknown_host_does_not_restrict_first_negotiation(self) -> None:
        keys = Mock()
        keys.lookup.return_value = None
        client = SimpleNamespace(_system_host_keys=keys, _host_keys=keys)
        paramiko = SimpleNamespace(Transport=SimpleNamespace(_preferred_keys=("ssh-ed25519", "ssh-rsa")))
        self.assertIsNone(known_host_disabled_algorithms(paramiko, client, "new.example"))

    def test_managed_host_key_overrides_stale_system_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch("vpn_installer.remote.KNOWN_HOSTS_PATH", Path(tmp) / "known_hosts"):
            known_hosts = Path(tmp) / "known_hosts"
            known_hosts.write_text("managed entry\n", encoding="utf-8")
            managed_store = Mock()
            managed_store.lookup.return_value = {"ssh-ed25519": object()}
            client = SimpleNamespace(
                _host_keys=managed_store,
                load_host_keys=Mock(),
                load_system_host_keys=Mock(),
            )
            self.assertEqual(load_trusted_host_keys(client, "example.test"), known_hosts)
        client.load_host_keys.assert_called_once_with(str(known_hosts))
        client.load_system_host_keys.assert_not_called()

    def test_empty_managed_store_does_not_implicitly_trust_system_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch("vpn_installer.remote.KNOWN_HOSTS_PATH", Path(tmp) / "known_hosts"):
            managed_store = Mock()
            managed_store.lookup.return_value = None
            client = SimpleNamespace(
                _host_keys=managed_store,
                load_host_keys=Mock(),
                load_system_host_keys=Mock(),
            )
            load_trusted_host_keys(client, "example.test")
        client.load_system_host_keys.assert_not_called()

    def test_unknown_host_key_is_rejected_non_interactively(self) -> None:
        fake_store = Mock()
        fake_store.lookup.return_value = None
        fake_client = SimpleNamespace(
            _host_keys=fake_store,
            _system_host_keys=fake_store,
            load_host_keys=Mock(),
            load_system_host_keys=Mock(),
        )
        fake_key = Mock()
        fake_key.get_name.return_value = "ssh-ed25519"
        fake_key.asbytes.return_value = b"key"
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="example.test", ssh_port=2222)
        fake_paramiko = SimpleNamespace(SSHClient=Mock(return_value=fake_client), HostKeys=Mock(return_value=fake_store))
        with tempfile.TemporaryDirectory() as tmp, patch("vpn_installer.remote.KNOWN_HOSTS_PATH", Path(tmp) / "known_hosts"), patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko), patch("vpn_installer.remote.probe_host_key", return_value=fake_key):
            with self.assertRaises(AppError) as ctx:
                ensure_target_host_key(target, allow_enroll=False)
        self.assertIn("SHA256:", str(ctx.exception))
        self.assertEqual(host_key_alias(target), "[example.test]:2222")

    def test_unknown_host_key_requires_explicit_interactive_acceptance(self) -> None:
        fake_store = Mock()
        fake_store.lookup.return_value = None
        fake_client = SimpleNamespace(
            _host_keys=fake_store,
            _system_host_keys=fake_store,
            load_host_keys=Mock(),
            load_system_host_keys=Mock(),
        )
        fake_key = Mock()
        fake_key.get_name.return_value = "ssh-ed25519"
        fake_key.asbytes.return_value = b"key"
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="example.test")
        fake_paramiko = SimpleNamespace(SSHClient=Mock(return_value=fake_client), HostKeys=Mock(return_value=fake_store))
        prompt = Mock(return_value=True)
        with tempfile.TemporaryDirectory() as tmp, patch("vpn_installer.remote.KNOWN_HOSTS_PATH", Path(tmp) / "known_hosts"), patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko), patch("vpn_installer.remote.probe_host_key", return_value=fake_key), patch("vpn_installer.remote.persist_host_key") as persist:
            ensure_target_host_key(target, allow_enroll=True, prompt_yes_no=prompt)
        prompt.assert_called_once()
        persist.assert_called_once_with("example.test", fake_key)

    def test_paramiko_connect_uses_bound_socket_when_requested(self) -> None:
        fake_client = Mock()
        fake_paramiko = Mock(SSHClient=Mock(return_value=fake_client), AutoAddPolicy=Mock(return_value="policy"))
        bound_socket = Mock()
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", auth_mode="password", ssh_password="secret", ssh_bind_address="192.168.0.101")
        with patch("vpn_installer.remote.ensure_paramiko_installed", return_value=fake_paramiko), patch("vpn_installer.remote.open_bound_ssh_socket", return_value=bound_socket) as opener:
            client = paramiko_connect(target)
        self.assertIs(client, fake_client)
        opener.assert_called_once_with(target)
        self.assertIs(fake_client.connect.call_args.kwargs["sock"], bound_socket)

    def test_open_bound_ssh_socket_closes_socket_after_connect_error(self) -> None:
        fake_socket = Mock()
        fake_socket.connect.side_effect = OSError("blocked")
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_bind_address="192.168.0.101")
        with patch("vpn_installer.remote.socket.getaddrinfo", side_effect=[[(2, 1, 6, "", ("192.168.0.101", 0))], [(2, 1, 6, "", ("203.0.113.10", 22))]]), patch("vpn_installer.remote.socket.socket", return_value=fake_socket):
            with self.assertRaises(AppError):
                open_bound_ssh_socket(target)
        fake_socket.close.assert_called_once()

    def test_paramiko_connect_raises_on_failure(self) -> None:
        fake_client = Mock()
        fake_client.connect.side_effect = RuntimeError("fail")
        fake_paramiko = Mock(SSHClient=Mock(return_value=fake_client), AutoAddPolicy=Mock(return_value="policy"))
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
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
            RejectPolicy=Mock(return_value="reject"),
            AutoAddPolicy=Mock(return_value="policy"),
            ssh_exception=SimpleNamespace(AuthenticationException=FakeAuthTimeout),
        )
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root", auth_mode="password", ssh_password="secret")
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
            RejectPolicy=Mock(return_value="reject"),
            AutoAddPolicy=Mock(return_value="policy"),
            ssh_exception=SimpleNamespace(AuthenticationException=Exception),
        )
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
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
            RejectPolicy=Mock(return_value="reject"),
            AutoAddPolicy=Mock(return_value="policy"),
            ssh_exception=SimpleNamespace(AuthenticationException=Exception),
        )
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
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
        target = RemoteTarget(node_id=NODE_GATEWAY)
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
        target = RemoteTarget(node_id=NODE_GATEWAY)
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
        target = RemoteTarget(node_id=NODE_GATEWAY)
        with (
            patch("vpn_installer.remote.paramiko_connect", return_value=client),
            patch("vpn_installer.remote.time.sleep"),
            patch("sys.stdout", new_callable=io.StringIO) as out_stream,
            patch("sys.stderr", new_callable=io.StringIO) as err_stream,
        ):
            code = paramiko_stream(target, "echo test", input_text="secret\n")
        self.assertEqual(code, 0)
        self.assertIn("out", out_stream.getvalue())
        self.assertEqual(err_stream.getvalue(), "")
        client.exec_command.assert_called_once_with("echo test", get_pty=False)
        client.close.assert_called_once()

    def test_paramiko_stream_hides_stderr_and_raises_with_detail(self) -> None:
        channel = Mock()
        channel.recv_ready.side_effect = [False, False, False]
        channel.recv_stderr_ready.side_effect = [True, False, False]
        channel.exit_status_ready.side_effect = [False, True, True]
        channel.recv_stderr.return_value = b"remote failure\n"
        channel.recv_exit_status.return_value = 7
        stdout = Mock(channel=channel)
        stderr = Mock(channel=channel)
        client = Mock()
        client.exec_command.return_value = (Mock(), stdout, stderr)
        with (
            patch("vpn_installer.remote.paramiko_connect", return_value=client),
            patch("vpn_installer.remote.time.sleep"),
            patch("sys.stderr", new_callable=io.StringIO) as err_stream,
        ):
            with self.assertRaisesRegex(AppError, "remote failure"):
                paramiko_stream(RemoteTarget(node_id=NODE_GATEWAY), "false")
        self.assertEqual(err_stream.getvalue(), "")
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
                    paramiko_upload(RemoteTarget(node_id=NODE_GATEWAY), local, "/tmp/demo.txt")
        client.close.assert_called_once()

    def test_ssh_capture_uses_paramiko_backend(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.paramiko_exec", return_value=(0, "ok", "")) as mocked:
            result = ssh_capture(target, "echo ok", as_root=False)
        self.assertEqual(result, "ok")
        mocked.assert_called_once()

    def test_ssh_capture_raises_on_remote_error(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.paramiko_exec", return_value=(9, "", "boom")):
            with self.assertRaises(AppError) as ctx:
                ssh_capture(target, "echo ok", as_root=False)
        self.assertIn("boom", str(ctx.exception))

    def test_ssh_stream_uses_system_ssh_for_key_mode(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_user="root", auth_mode="key")
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("vpn_installer.remote.command_exists", return_value=True), patch("vpn_installer.remote.run_command", return_value=completed) as mocked:
            ssh_stream(target, "echo ok", as_root=False)
        mocked.assert_called_once()
        self.assertTrue(mocked.call_args.kwargs["capture_stderr"])
        self.assertNotIn("capture_output", mocked.call_args.kwargs)

    def test_ssh_stream_prints_paramiko_output(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, auth_mode="password", ssh_password="secret")
        with patch("vpn_installer.remote.paramiko_stream", return_value=0) as mocked:
            ssh_stream(target, "echo ok", as_root=False)
        mocked.assert_called_once()

    def test_ssh_stream_uses_pty_only_for_sudo_password_input(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, auth_mode="password", ssh_password="secret", ssh_user="ubuntu", sudo_mode="password", sudo_password="sudo-secret")
        with patch("vpn_installer.remote.paramiko_stream", return_value=0) as mocked:
            ssh_stream(target, "echo ok", as_root=True)
        self.assertTrue(mocked.call_args.kwargs["get_pty"])
        self.assertEqual(mocked.call_args.kwargs["input_text"], "sudo-secret\n")

    def test_scp_upload_uses_system_scp(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY, ssh_host="203.0.113.10", ssh_user="root", auth_mode="key")
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "bundle.tar.gz"
            local.write_text("bundle", encoding="utf-8")
            completed = SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch("vpn_installer.remote.command_exists", return_value=True), patch("vpn_installer.remote.run_command", return_value=completed) as mocked:
                scp_upload(target, local, "/tmp/bundle.tar.gz")
        mocked.assert_called_once()

    def test_parse_kv_output_ignores_invalid_lines(self) -> None:
        payload = "a=1\nbroken\nb = 2 \n"
        self.assertEqual(parse_kv_output(payload), {"a": "1", "b": "2"})

    def test_remote_preflight_uses_ssh_capture(self) -> None:
        snapshot = DiagnosticsSnapshot(
            generated_at="2026-08-06T12:00:00+00:00",
            deployment="demo",
            topology="dual",
            node_id=NODE_GATEWAY,
            location="ru",
            capabilities=("interserver-client", "local-egress", "public-front", "router", "ru-split-routing", "web-admin"),
            release={"release_id": "release-1"},
        ).to_dict()
        with patch("vpn_installer.remote.ssh_capture", return_value=json.dumps(snapshot)) as mocked:
            payload = remote_preflight(RemoteTarget(node_id=NODE_GATEWAY), "wgx")
        mocked.assert_called_once()
        self.assertIn("test -r /usr/local/lib/vpn-stack/vpn-stack-agent.py", mocked.call_args.args[1])
        self.assertNotIn("test -x /usr/local/lib/vpn-stack/vpn-stack-agent.py", mocked.call_args.args[1])
        self.assertEqual(payload["node"], NODE_GATEWAY)

    def test_snapshot_rejects_out_of_window_release_before_reading_old_schema(self) -> None:
        snapshot = {"schema_version": 4, "release": {"version": "0.19.10"}}
        with patch("vpn_installer.remote.ssh_capture", return_value=json.dumps(snapshot)):
            with self.assertRaisesRegex(AppError, "cannot be updated by 0.21.0.*tag 0.19.10"):
                remote_agent_snapshot(RemoteTarget(node_id=NODE_GATEWAY))

    def test_snapshot_rejects_wrong_schema_from_compatible_release(self) -> None:
        snapshot = {"schema_version": 4, "release": {"version": "0.20.2"}}
        with patch("vpn_installer.remote.ssh_capture", return_value=json.dumps(snapshot)):
            with self.assertRaisesRegex(AppError, "unsupported snapshot schema"):
                remote_agent_snapshot(RemoteTarget(node_id=NODE_GATEWAY))

    def test_remote_preflight_uses_compact_bootstrap_when_agent_is_unavailable(self) -> None:
        with patch("vpn_installer.remote.ssh_capture", side_effect=["not-json", "0", "node_id=ru-gateway\n"]) as mocked:
            remote_preflight(RemoteTarget(node_id=NODE_GATEWAY), "wgx", fresh_since_epoch=1783733001)
        self.assertEqual(mocked.call_count, 3)
        self.assertIn("WG_INTERFACE=wgx", mocked.call_args.args[1])

    def test_remote_preflight_does_not_hide_broken_installed_agent(self) -> None:
        with patch("vpn_installer.remote.ssh_capture", side_effect=["not-json", "1"]) as mocked:
            with self.assertRaises(json.JSONDecodeError):
                remote_preflight(RemoteTarget(node_id=NODE_GATEWAY), "wgx")
        self.assertEqual(mocked.call_count, 2)

    def test_fetch_remote_deployment_env_uses_root_capture(self) -> None:
        with patch("vpn_installer.remote.ssh_capture", return_value='DEPLOY_NAME="demo"\n') as mocked:
            payload = fetch_remote_deployment_env(RemoteTarget(node_id=NODE_GATEWAY))
        self.assertEqual(payload, 'DEPLOY_NAME="demo"\n')
        mocked.assert_called_once_with(unittest.mock.ANY, "cat /etc/vpn-stack/deployment.env", as_root=True)
    def test_bootstrap_from_snapshot_uses_agent_host_and_lifecycle_fields(self) -> None:
        preflight = bootstrap_from_snapshot(
            DiagnosticsSnapshot(
                generated_at="2026-08-06T12:00:00+00:00",
                deployment="demo",
                topology="dual",
                node_id=NODE_GATEWAY,
                location="ru",
                capabilities=("interserver-client", "local-egress", "public-front", "router", "ru-split-routing", "web-admin"),
                release={"release_id": "release-1", "installed_at": "2026-07-15T00:00:00Z", "policy_version": "0.11.0"},
                host={"hostname": "demo", "login_user": "root", "is_root": True, "has_sudo": True, "os_id": "ubuntu", "os_version": "24.04", "default_interface": "eth0"},
                services={"wireguard": "active", "nftables": "active", "sing-box": "active", "xray": "active", "resolver": "active", "health_timer": "active"},
                artifacts={"drift": "none", "files": {}},
                wg_state={"peers": []},
                network={
                    "interfaces": {"eth0": {}},
                    "tcp_adaptation": {
                        "congestion_control": "bbr",
                        "qdisc": "fq",
                        "qdisc_limit": 10000,
                        "qdisc_flow_limit": 512,
                        "qdisc_drops": 7,
                        "qdisc_flow_limit_drops": 7,
                        "overlay_qdisc": "fq",
                        "overlay_qdisc_limit": 10000,
                        "overlay_qdisc_flow_limit": 512,
                        "overlay_qdisc_drops": 0,
                        "overlay_qdisc_flow_limit_drops": 0,
                        "mtu_probing": 1,
                        "mtu_probe_floor": 536,
                        "metrics_save_disabled": 0,
                        "probe_interval_seconds": 600,
                        "udp_rmem_default": 8388608,
                        "udp_rmem_max": 16777216,
                        "udp_wmem_default": 8388608,
                        "udp_wmem_max": 16777216,
                    },
                },
                front={"rtt_ms": {"p95": 40}, "socket_retransmissions": 3, "bytes_retrans": 1200, "retransmit_ratio_pct": 1.2, "state_counts": {"FIN-WAIT-1": 0}},
            ).to_dict()
        )
        self.assertEqual(preflight["is_root"], "1")
        self.assertEqual(preflight["installed"], "1")
        self.assertEqual(preflight["release_id"], "release-1")
        self.assertEqual(preflight["default_iface"], "eth0")
        self.assertEqual(preflight["resolver"], "active")
        self.assertEqual(preflight["udp_wmem_default"], "8388608")
        self.assertEqual(preflight["tcp_qdisc_flow_limit"], "512")
        self.assertEqual(preflight["wg_qdisc"], "fq")

    def test_print_preflight_emits_lifecycle_summary(self) -> None:
        with patch("sys.stdout", new_callable=io.StringIO) as stream:
            print_preflight(
                RemoteTarget(node_id=NODE_GATEWAY),
                {
                    "hostname": "demo",
                    "login_user": "root",
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "default_iface": "eth0",
                    "installed": "1",
                    "deployment_name": "demo",
                    "topology": "dual",
                    "node": "gateway",
                    "location": "ru",
                    "capabilities": "interserver-client,local-egress,public-front,router,ru-split-routing,web-admin",
                    "drift": "none",
                    "wireguard": "active",
                    "nftables": "active",
                    "sing_box": "active",
                    "xray": "active",
                    "resolver": "active",
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
                    "tcp_qdisc_limit": "10000",
                    "tcp_qdisc_flow_limit": "512",
                    "tcp_qdisc_drops": "7",
                    "tcp_qdisc_flow_limit_drops": "7",
                    "wg_qdisc": "fq",
                    "wg_qdisc_limit": "10000",
                    "wg_qdisc_flow_limit": "512",
                    "wg_qdisc_drops": "0",
                    "wg_qdisc_flow_limit_drops": "0",
                    "tcp_mtu_probing": "1",
                    "tcp_mtu_probe_floor": "536",
                    "tcp_metrics_save_disabled": "0",
                    "tcp_probe_interval_seconds": "600",
                    "udp_rmem_default": "8388608",
                    "udp_rmem_max": "16777216",
                    "udp_wmem_default": "8388608",
                    "udp_wmem_max": "16777216",
                },
            )
        output = stream.getvalue()
        self.assertIn("host: demo", output)
        self.assertIn("services: nft=active, sing-box=active, resolver=active, health=active, wg=active, xray=active, admin=-", output)
        self.assertIn("wireguard: handshake_age_s=4, transfer_rx_tx=1/2", output)
        self.assertIn("front: rtt_p95_ms=40, retransmissions_lifetime=3, retransmit_ratio_pct=1.2, active=0, closing=0, fin_wait_1=0", output)
        self.assertIn("front retransmission scope: lifetime counters of currently open sockets", output)
        self.assertIn(
            "tcp adaptation: cc=bbr, qdisc=fq(limit=10000,flow_limit=512,drops=7,flow_limit_drops=7), "
            "wg_qdisc=fq(limit=10000,flow_limit=512,drops=0,flow_limit_drops=0), "
            "mtu_probing=1, mtu_floor=536, "
            "metrics_save_disabled=0, probe_interval_s=600",
            output,
        )
        self.assertIn("udp_rmem=8388608/16777216, udp_wmem=8388608/16777216", output)

        without_admin = dict(
            hostname="demo",
            installed="1",
            topology="single",
            node="gateway",
            location="foreign",
            capabilities="local-egress,public-front,router",
        )
        with patch("sys.stdout", new_callable=io.StringIO) as stream:
            print_preflight(RemoteTarget(node_id=NODE_GATEWAY), without_admin)
        self.assertIn("xray=-", stream.getvalue())
        self.assertNotIn("admin=", stream.getvalue())

    def test_ensure_remote_privilege_paths(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY)
        ensure_remote_privilege(target, {"is_root": "1"}, prompt_yes_no=lambda *_args, **_kwargs: True, prompt_secret=lambda *_args, **_kwargs: "x")
        self.assertEqual(target.sudo_mode, "root")

        target = RemoteTarget(node_id=NODE_GATEWAY)
        ensure_remote_privilege(target, {"is_root": "0", "has_sudo": "1"}, prompt_yes_no=lambda *_args, **_kwargs: True, prompt_secret=lambda *_args, **_kwargs: "x")
        self.assertEqual(target.sudo_mode, "nopasswd")

        target = RemoteTarget(node_id=NODE_GATEWAY)
        ensure_remote_privilege(target, {"is_root": "0", "has_sudo": "0", "login_user": "ubuntu", "hostname": "demo"}, prompt_yes_no=lambda *_args, **_kwargs: True, prompt_secret=lambda *_args, **_kwargs: "secret")
        self.assertEqual(target.sudo_mode, "password")
        self.assertEqual(target.sudo_password, "secret")

    def test_ensure_remote_privilege_can_fail(self) -> None:
        target = RemoteTarget(node_id=NODE_GATEWAY)
        with self.assertRaises(AppError):
            ensure_remote_privilege(target, {"is_root": "0", "has_sudo": "0", "login_user": "ubuntu", "hostname": "demo"}, prompt_yes_no=lambda *_args, **_kwargs: False, prompt_secret=lambda *_args, **_kwargs: "secret")


if __name__ == "__main__":
    unittest.main()
