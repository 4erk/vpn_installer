from __future__ import annotations

import io
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
    paramiko_exec,
    paramiko_stream,
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
        script = preflight_script("wg-test")
        self.assertIn("wg-quick@wg-test", script)
        self.assertIn("wg_latest_handshake_age_s", script)
        self.assertIn("observed_ipv4", script)
        self.assertIn("wg_observed_ipv4", script)
        self.assertIn("direct_download_bps", script)
        self.assertIn("wg_download_bps", script)
        self.assertIn("deep_probe_verdict", script)
        self.assertIn("deep_foreign_direct_download_min_bps", script)
        self.assertIn("deep_ru_wg_upload_bps", script)
        self.assertIn("wan_offload_gro", script)
        self.assertIn("wan_offload_tso", script)
        self.assertGreaterEqual(script.count("latest-handshakes"), 2)
        self.assertIn("reality_invalid_recent_count", script)
        self.assertIn("nft_port_packets", script)
        self.assertIn("nft_vless_drop_packets", script)
        self.assertIn('nft_vless_drop_packets="0"', script)
        self.assertIn("head -n1 || true", script)
        self.assertIn("dns: (lookup|exchange) failed", script)
        self.assertIn("exchange failed for", script)

    def test_target_probe_uses_header_probe_with_short_range_fallback(self) -> None:
        script = preflight_script("wg-test")
        self.assertIn("curl -4kIsS", script)
        self.assertIn("--range 0-0", script)
        self.assertNotIn("curl -4kLsS --interface \"${bind_iface}\" --connect-timeout 8 --max-time 20", script)
        self.assertNotIn("curl -4kLsS --connect-timeout 8 --max-time 20", script)

    def test_target_probe_uses_path_specific_lists_and_short_timeouts(self) -> None:
        script = preflight_script("wg0")
        self.assertIn('ru_direct_target_probe_urls="$(env_value HEALTH_RU_DIRECT_TARGET_PROBE_URLS)"', script)
        self.assertIn('target_probe_connect_timeout="$(env_value HEALTH_TARGET_CONNECT_TIMEOUT_SECONDS)"', script)
        self.assertIn('target_probe_max_time="$(env_value HEALTH_TARGET_MAX_TIME_SECONDS)"', script)
        self.assertIn('probe_target_urls "" "${target_probe_urls}" "${target_probe_connect_timeout}" "${target_probe_max_time}"', script)
        self.assertIn('probe_target_urls "" "${ru_direct_target_probe_urls}" "${target_probe_connect_timeout}" "${target_probe_max_time}"', script)
        self.assertIn('probe_target_urls "wg0" "${target_probe_urls}" "${target_probe_connect_timeout}" "${target_probe_max_time}"', script)
        self.assertIn('ipv6_literal_tcp_probe="$(probe_ipv6_literal_tcp_path "wg0")"', script)
        self.assertIn('"cloudflare_v6=https://[2606:4700:4700::1111]/cdn-cgi/trace"', script)
        self.assertIn('route_mark="$(env_value APP_ROUTE_MARK)"', script)
        self.assertIn('"routing_mark": ${route_mark}', script)
        self.assertIn('curl -kLsS --proxy "socks5h://127.0.0.1:${port}"', script)
        self.assertNotIn('curl -6kLsS --proxy "socks5h://127.0.0.1:${port}"', script)
        self.assertIn("target_probe_needs_body_fallback", script)
        self.assertIn('--connect-timeout "${connect_timeout}" --max-time "${max_time}"', script)
        self.assertNotIn("--connect-timeout 6 --max-time 10", script)

    def test_preflight_log_grouping_does_not_fail_on_pipe_sigpipe(self) -> None:
        script = preflight_script("wg0")
        self.assertIn("set -euo pipefail", script)
        self.assertIn("set +o pipefail", script)
        self.assertIn("set -o pipefail\n\nprintf 'login_user=%s", script)

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
        with patch("vpn_installer.remote.ssh_capture", return_value="host=demo\nrole=ru-gateway\n") as mocked:
            payload = remote_preflight(RemoteTarget(role=ROLE_RU), "wgx")
        mocked.assert_called_once()
        self.assertEqual(payload["role"], "ru-gateway")

    def test_fetch_remote_deployment_env_uses_root_capture(self) -> None:
        with patch("vpn_installer.remote.ssh_capture", return_value='DEPLOY_NAME="demo"\n') as mocked:
            payload = fetch_remote_deployment_env(RemoteTarget(role=ROLE_RU))
        self.assertEqual(payload, 'DEPLOY_NAME="demo"\n')
        mocked.assert_called_once_with(unittest.mock.ANY, "cat /etc/vpn-stack/deployment.env", as_root=True)

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
                    "singbox_configured_log_level": "warn",
                    "global_doh_server": "8.8.8.8",
                    "global_doh_server_name": "dns.google",
                    "ru_ipv6_literal_policy": "route-with-budget",
                    "wan_mtu": "1500",
                    "default_qdisc": "fq_codel",
                    "wan_offload_gro": "off",
                    "wan_offload_gso": "off",
                    "wan_offload_tso": "off",
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
                    "nft_ssh_accept_packets": "10",
                    "nft_ssh_drop_packets": "1",
                    "nft_vless_accept_packets": "200",
                    "nft_vless_drop_packets": "5",
                    "wireguard": "active",
                    "wg_transfer_rx": "1",
                    "wg_transfer_tx": "2",
                    "wg_latest_handshake": "3",
                    "wg_latest_handshake_age_s": "4",
                    "observed_ipv4": "198.51.100.20",
                    "wg_observed_ipv4": "198.51.100.20",
                    "direct_download_bps": "6000000",
                    "wg_download_bps": "700000",
                    "target_probe_direct": "chatgpt.com:reachable:403:0:172.64.0.1:0.1;github.com:reachable:200:0:140.82.0.1:0.2",
                    "target_probe_wg": "chatgpt.com:reachable:403:0:172.64.0.1:0.1;github.com:reachable:200:0:140.82.0.1:0.2",
                    "ipv6_literal_tcp_probe": "cloudflare_v6:reachable:200:0:2606:4700:4700::1111:0.08;google_v6:reachable:204:0:2a00:1450:400f:807::200e:0.09",
                    "deep_probe_at": "2026-04-24T12:00:00+00:00",
                    "deep_probe_verdict": "degraded",
                    "deep_probe_reasons": "ru_wg_download=120000",
                    "deep_foreign_direct_download_min_bps": "300000",
                    "deep_foreign_direct_upload_bps": "900000",
                    "deep_foreign_gateway_ping_loss_pct": "15",
                    "deep_foreign_ru_ping_loss_pct": "10",
                    "deep_foreign_internet_ping_loss_pct": "5",
                    "deep_ru_wg_download_min_bps": "120000",
                    "deep_ru_wg_upload_bps": "800000",
                    "fast_ru_foreign_ping_loss_pct": "25",
                    "profile_updated_at": "2026-06-17T19:00:00+00:00",
                    "profile_handshake_age_s": "130",
                    "profile_handshake_grace_s": "200",
                    "profile_wg_path_ok": "1",
                    "profile_fast_ping_loss_pct": "25",
                    "profile_stale_handshake_live_path_s": "130",
                    "good_wg_path_at": "2026-06-17T19:01:00+00:00",
                    "good_wg_path_age_s": "45",
                    "good_wg_path_source": "health-hard-probe",
                    "good_wg_path_handshake_age_s": "12",
                    "good_cache_ttl_seconds": "900",
                    "route_fail_cache_ttl_seconds": "300",
                    "route_fail_ipv4_literal_count": "4",
                    "route_fail_ipv4_literal_top_dest": "91.108.56.103:443=4",
                    "route_fail_ipv4_literal_age_s": "20",
                    "route_fail_ipv6_literal_count": "5",
                    "route_fail_ipv6_literal_top_dest": "[2001:db8::1]:443=5",
                    "route_fail_ipv6_literal_age_s": "30",
                    "self_heal_last_reason": "soft:wireguard_path",
                    "self_heal_consecutive": "2",
                    "self_heal_last_action": "restart-wireguard",
                    "self_heal_last_action_result": "scheduled",
                    "self_heal_last_action_reason": "soft:wireguard_path",
                    "self_heal_last_action_age_s": "3600",
                    "reality_invalid_recent_count": "7",
                    "reality_invalid_recent_sources": "178.66.129.100=7",
                    "singbox_to_foreign_timeout_count": "11",
                    "singbox_to_foreign_ip_literal_timeout_count": "4",
                    "singbox_to_foreign_ipv6_literal_timeout_count": "5",
                    "singbox_direct_ru_timeout_count": "2",
                    "singbox_dns_timeout_count": "1",
                    "singbox_recent_timeout_sample": "connection: open connection to [2001:db8::1]:443 using outbound/direct[to-foreign-ip-literal]: i/o timeout",
                    "singbox_log_window_minutes": "30",
                    "singbox_recent_effective_since": "@1783600000",
                    "singbox_recent_blocked_count": "22",
                    "singbox_recent_mux_closed_count": "36",
                    "singbox_recent_eof_count": "38",
                    "singbox_recent_dns_failed_count": "1",
                    "singbox_recent_timeout_count": "0",
                    "singbox_recent_invalid_reality_count": "3",
                    "singbox_recent_to_foreign_timeout_count": "2",
                    "singbox_recent_to_foreign_ip_literal_timeout_count": "4",
                    "singbox_recent_to_foreign_ipv6_literal_timeout_count": "5",
                    "singbox_recent_direct_ru_timeout_count": "1",
                    "singbox_recent_sources": "91.193.149.187=36,193.46.56.226=2",
                    "singbox_recent_blocked_destinations": "[fdfd::1ad5:632a]:55517=6,172.19.0.2:853=1",
                    "singbox_recent_mux_sources": "91.193.149.187=36",
                    "singbox_recent_to_foreign_count": "44",
                    "singbox_recent_to_foreign_ip_literal_count": "9",
                    "singbox_recent_to_foreign_ipv6_literal_count": "7",
                    "singbox_recent_direct_ru_count": "12",
                    "singbox_recent_to_foreign_destinations": "20.42.65.94:443=5,8.8.8.8:443=1",
                    "singbox_recent_to_foreign_ip_literal_destinations": "91.108.56.103:443=4",
                    "singbox_recent_to_foreign_ipv6_literal_destinations": "[2400:52e0:1e00::722:1]:443=4",
                    "singbox_recent_direct_ru_destinations": "142.251.143.131:80=2",
                    "singbox_recent_timeout_destinations": "[185.234.59.121]=2,ipv6.msftncsi.com:AAAA=1",
                    "singbox_recent_ip_literal_timeout_destinations": "91.108.56.103:443=4",
                    "singbox_fresh_timeout_destinations": "ipv6.msftconnecttest.com:AAAA=2",
                    "singbox_recent_ipv6_literal_count": "7",
                    "singbox_recent_ipv6_literal_destinations": "[2400:52e0:1e00::722:1]:443=4,[fdfd::1ad5:632a]:55517=3",
                    "singbox_recent_inbound_destinations": "chatgpt.com:443=2,[2606:4700::6810:5c12]:443=1",
                    "singbox_recent_error_sample": "connection: listen packet connection using outbound/block[blocked]: operation not permitted",
                    "xray_log_window_minutes": "30",
                    "xray_recent_effective_since": "@1783600000",
                    "xray_recent_error_count": "1",
                    "xray_recent_invalid_reality_count": "0",
                    "xray_recent_disabled_invalid_count": "3",
                    "xray_recent_accepted_count": "55",
                    "xray_recent_sources": "178.66.131.179=44,213.109.48.231=11",
                    "xray_recent_accepted_destinations": "chatgpt.com:443=10,8.8.8.8:53=5",
                    "xray_recent_ipv6_literal_count": "2",
                    "xray_recent_ipv6_literal_destinations": "[2001:4860:4860::8888]:443=2",
                    "xray_recent_error_sample": "REALITY: processed invalid connection from 203.0.113.20:12345",
                    "sync_timer": "active",
                },
            )
        output = stream.getvalue()
        self.assertIn("host: demo", output)
        self.assertIn("configured WAN iface: eth0", output)
        self.assertIn("warning: sing-box log level is warn; routed diagnostics need info-level connection logs.", output)
        self.assertIn("wan offloads gro/gso/tso: off/off/off", output)
        self.assertIn("tcp cc: bbr", output)
        self.assertIn("wireguard transfer rx/tx: 1/2", output)
        self.assertIn("nft SSH accept/drop packets: 10/1", output)
        self.assertIn("nft VLESS accept/drop packets: 200/5", output)
        self.assertIn("wireguard handshake age (s): 4", output)
        self.assertIn("observed IPv4: 198.51.100.20", output)
        self.assertIn("RU over wg IPv4: 198.51.100.20", output)
        self.assertIn("direct download B/s: 6000000", output)
        self.assertIn("RU over wg download B/s: 700000", output)
        self.assertIn("target probes direct: chatgpt.com:reachable:403:0", output)
        self.assertIn("target probes RU over wg: chatgpt.com:reachable:403:0", output)
        self.assertIn("IPv6 literal TCP path: cloudflare_v6:reachable:200:0", output)
        self.assertIn("deep probe verdict: degraded", output)
        self.assertIn("foreign direct min download B/s: 300000", output)
        self.assertIn("RU over wg upload B/s: 800000", output)
        self.assertIn("foreign ping loss to gateway (%): 15", output)
        self.assertIn("fast RU->foreign ping loss (%): 25", output)
        self.assertIn("runtime profile at: 2026-06-17T19:00:00+00:00", output)
        self.assertIn("profile handshake age/grace (s): 130/200", output)
        self.assertIn("profile wg path ok: 1", output)
        self.assertIn("profile stale handshake with live path (s): 130", output)
        self.assertIn("dataplane cache good WG path: age=45s/ttl=900s, source=health-hard-probe, handshake_age=12s", output)
        self.assertIn("dataplane route-fail cache: ttl=300s, ipv4_literal=4@20s 91.108.56.103:443=4, ipv6_literal=5@30s [2001:db8::1]:443=5", output)
        self.assertIn("self-heal last action: restart-wireguard/scheduled age=3600s", output)
        self.assertIn("recent invalid Reality handshakes: 7", output)
        self.assertIn("invalid Reality sources: 178.66.129.100=7", output)
        self.assertIn("diagnosis: invalid Reality happens before routing", output)
        self.assertIn("sing-box to-foreign timeouts / 4h: 11", output)
        self.assertIn("sing-box IPv4-literal to-foreign timeouts / 4h: 4", output)
        self.assertIn("sing-box IPv6-literal to-foreign timeouts / 4h: 5", output)
        self.assertIn("sing-box direct-ru timeouts / 4h: 2", output)
        self.assertIn("sing-box DNS timeouts / 4h: 1", output)
        self.assertIn("sing-box global DoH: 8.8.8.8/dns.google", output)
        self.assertIn("sing-box IP-literal timeout destinations / 4h: 91.108.56.103:443=4", output)
        self.assertIn("sing-box timeout destinations / 4h: [185.234.59.121]=2,ipv6.msftncsi.com:AAAA=1", output)
        self.assertIn("sing-box last timeout sample: connection: open connection to [2001:db8::1]:443", output)
        self.assertIn("Xray front recent window (min): 30", output)
        self.assertIn("Xray front recent since: @1783600000", output)
        self.assertIn("Xray front recent: accepted=55, errors=1, invalid_reality=0, disabled_invalid=3, ipv6_literals=2", output)
        self.assertIn("Xray front recent sources: 178.66.131.179=44,213.109.48.231=11", output)
        self.assertIn("Xray front recent destinations: chatgpt.com:443=10,8.8.8.8:53=5", output)
        self.assertIn("Xray front recent IPv6 literal destinations: [2001:4860:4860::8888]:443=2", output)
        self.assertIn("Xray front recent sample: REALITY: processed invalid connection from 203.0.113.20:12345", output)
        self.assertIn("sing-box recent window (min): 30", output)
        self.assertIn("sing-box recent since: @1783600000", output)
        self.assertIn("sing-box recent grouped errors: blocked=22, mux_closed=36, eof=38, dns_failed=1, timeout=0, invalid_reality=3", output)
        self.assertIn("sing-box recent timeout classes: domain_to_foreign=2, ipv4_literal=4, ipv6_literal=5, direct_ru=1", output)
        self.assertIn("sing-box recent timeout destinations: ipv6.msftconnecttest.com:AAAA=2", output)
        self.assertIn("sing-box recent sources: 91.193.149.187=36,193.46.56.226=2", output)
        self.assertIn("sing-box recent blocked destinations: [fdfd::1ad5:632a]:55517=6,172.19.0.2:853=1", output)
        self.assertIn("sing-box recent mux sources: 91.193.149.187=36", output)
        self.assertIn("sing-box recent sample: connection: listen packet connection using outbound/block[blocked]: operation not permitted", output)
        self.assertIn("sing-box recent routed: to_foreign=44, to_foreign_ip_literal=9, to_foreign_ipv6_literal=7, direct_ru=12, ipv6_literals=7", output)
        self.assertIn("sing-box recent to-foreign destinations: 20.42.65.94:443=5,8.8.8.8:443=1", output)
        self.assertIn("sing-box recent IPv4-literal to-foreign destinations: 91.108.56.103:443=4", output)
        self.assertIn("sing-box recent IPv6-literal to-foreign destinations: [2400:52e0:1e00::722:1]:443=4", output)
        self.assertIn("sing-box recent direct-ru destinations: 142.251.143.131:80=2", output)
        self.assertIn("sing-box recent IPv6 literal destinations: [2400:52e0:1e00::722:1]:443=4,[fdfd::1ad5:632a]:55517=3", output)
        self.assertIn("diagnosis: clients sent IPv6 literal destinations; current RU IPv6 literal policy routes them through the dedicated IPv6-literal foreign outbound.", output)
        self.assertIn("sing-box recent inbound destinations: chatgpt.com:443=2,[2606:4700::6810:5c12]:443=1", output)

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
