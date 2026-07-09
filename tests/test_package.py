from __future__ import annotations

import importlib
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.audit.runner import AUDIT_IMAGE, AUDIT_SINGBOX_REQUIRED_VERSION
from vpn_installer.config import render_example_env_text


class PackageTests(unittest.TestCase):
    def test_package_main_is_lazy(self) -> None:
        sys.modules.pop("vpn_installer", None)
        sys.modules.pop("vpn_installer.cli", None)
        package = importlib.import_module("vpn_installer")
        self.assertTrue(callable(package.main))
        self.assertNotIn("vpn_installer.cli", sys.modules)

    def test_deployment_example_matches_generated_contract(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        example_path = repo_root / "deployments" / "deployment.env.example"
        if not example_path.is_file():
            self.skipTest("deployment.env.example удалён локально, сравнение checked-in примера пропущено")
        checked_in = example_path.read_text(encoding="utf-8")
        self.assertEqual(checked_in, render_example_env_text())

    def test_install_script_starts_sync_timer_after_enabling(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        install_script = (repo_root / "install.sh").read_text(encoding="utf-8")
        self.assertIn('systemctl enable vpn-stack-sync.timer', install_script)
        self.assertIn('systemctl restart vpn-stack-sync.timer', install_script)
        self.assertIn('systemctl enable vpn-stack-health.timer', install_script)
        self.assertIn('systemctl restart vpn-stack-health.timer', install_script)
        self.assertIn('systemctl reset-failed vpn-stack-health.service >/dev/null 2>&1 || true', install_script)
        self.assertIn('systemctl enable vpn-stack-guard.timer', install_script)
        self.assertIn('systemctl restart vpn-stack-guard.timer', install_script)
        self.assertIn('systemctl disable --now ssh.socket', install_script)
        self.assertIn('systemctl enable ssh.service', install_script)
        self.assertIn('SSHD_CONFIG_PATH="/etc/ssh/sshd_config.d/90-vpn-stack.conf"', install_script)
        self.assertIn('HEALTH_SCRIPT_PATH="/usr/local/lib/vpn-stack/health-check.sh"', install_script)
        self.assertIn('GUARD_SCRIPT_PATH="/usr/local/lib/vpn-stack/guard.sh"', install_script)
        self.assertIn('GUARD_INTERVAL_MINUTES="${GUARD_INTERVAL_MINUTES:-5}"', install_script)
        self.assertIn('GUARD_SSH_FAILURE_THRESHOLD="${GUARD_SSH_FAILURE_THRESHOLD:-6}"', install_script)
        self.assertIn('GUARD_REALITY_BLOCK_ENABLED="${GUARD_REALITY_BLOCK_ENABLED:-0}"', install_script)
        self.assertIn('HEALTH_THROUGHPUT_URLS="${HEALTH_THROUGHPUT_URLS:-https://cachefly.cachefly.net/1mb.test https://proof.ovh.net/files/1Mb.dat}"', install_script)
        self.assertIn('HEALTH_DEEP_PROBE_INTERVAL_MINUTES="${HEALTH_DEEP_PROBE_INTERVAL_MINUTES:-15}"', install_script)
        self.assertIn('HEALTH_HANDSHAKE_GRACE_SECONDS="${HEALTH_HANDSHAKE_GRACE_SECONDS:-180}"', install_script)
        self.assertIn('HEALTH_HANDSHAKE_MIN_GRACE_SECONDS="${HEALTH_HANDSHAKE_MIN_GRACE_SECONDS:-180}"', install_script)
        self.assertIn('HEALTH_HANDSHAKE_GRACE_MULTIPLIER="${HEALTH_HANDSHAKE_GRACE_MULTIPLIER:-8}"', install_script)
        self.assertIn('HEALTH_SELF_HEAL="${HEALTH_SELF_HEAL:-1}"', install_script)
        self.assertIn('HEALTH_SELF_HEAL_COOLDOWN_MINUTES="${HEALTH_SELF_HEAL_COOLDOWN_MINUTES:-15}"', install_script)
        self.assertIn('HEALTH_SELF_HEAL_MAX_ACTIONS_PER_HOUR="${HEALTH_SELF_HEAL_MAX_ACTIONS_PER_HOUR:-2}"', install_script)
        self.assertIn('HEALTH_SELF_HEAL_CONFIRMATIONS="${HEALTH_SELF_HEAL_CONFIRMATIONS:-2}"', install_script)
        self.assertIn('HEALTH_GOOD_CACHE_TTL_SECONDS="${HEALTH_GOOD_CACHE_TTL_SECONDS:-900}"', install_script)
        self.assertIn('HEALTH_ROUTE_FAIL_CACHE_TTL_SECONDS="${HEALTH_ROUTE_FAIL_CACHE_TTL_SECONDS:-300}"', install_script)
        self.assertIn('HEALTH_ROUTE_FAIL_THRESHOLD="${HEALTH_ROUTE_FAIL_THRESHOLD:-3}"', install_script)
        self.assertIn('HEALTH_TARGET_PROBE_URLS="${HEALTH_TARGET_PROBE_URLS:-https://chatgpt.com/ https://discord.com/ https://github.com/ https://www.google.com/generate_204 https://telegram.org/ https://api.telegram.org/ https://t.me/}"', install_script)
        self.assertIn('HEALTH_RU_DIRECT_TARGET_PROBE_URLS="${HEALTH_RU_DIRECT_TARGET_PROBE_URLS:-https://api.ipify.org/ https://2ip.ru/}"', install_script)
        self.assertIn('HEALTH_TARGET_CONNECT_TIMEOUT_SECONDS="${HEALTH_TARGET_CONNECT_TIMEOUT_SECONDS:-2}"', install_script)
        self.assertIn('HEALTH_TARGET_MAX_TIME_SECONDS="${HEALTH_TARGET_MAX_TIME_SECONDS:-4}"', install_script)
        self.assertIn('JOURNAL_LIMIT_ENABLED="${JOURNAL_LIMIT_ENABLED:-1}"', install_script)
        self.assertIn('JOURNAL_SYSTEM_MAX_USE="${JOURNAL_SYSTEM_MAX_USE:-256M}"', install_script)
        self.assertIn('JOURNAL_MAX_RETENTION_SEC="${JOURNAL_MAX_RETENTION_SEC:-14day}"', install_script)
        self.assertIn('JOURNALD_DROPIN_PATH="/etc/systemd/journald.conf.d/90-vpn-stack.conf"', install_script)
        self.assertIn("configure_journald_limits", install_script)
        self.assertIn('journalctl --vacuum-size="${JOURNAL_SYSTEM_MAX_USE}"', install_script)
        self.assertIn('ADMIN_WEB_ENABLED="${ADMIN_WEB_ENABLED:-1}"', install_script)
        self.assertIn('ADMIN_WEB_BIND="${ADMIN_WEB_BIND:-0.0.0.0}"', install_script)
        self.assertIn('ADMIN_WEB_PORT="${ADMIN_WEB_PORT:-11333}"', install_script)
        self.assertIn('ADMIN_WEB_ACTIVE_CLIENT_REQUIRED="${ADMIN_WEB_ACTIVE_CLIENT_REQUIRED:-1}"', install_script)
        self.assertIn('ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS="${ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS:-5}"', install_script)
        self.assertIn('ADMIN_WEB_ALLOW_TUNNEL_CLIENTS="${ADMIN_WEB_ALLOW_TUNNEL_CLIENTS:-1}"', install_script)
        self.assertIn('ADMIN_WEB_USERNAME="${ADMIN_WEB_USERNAME:-user}"', install_script)
        self.assertIn('ADMIN_WEB_PASSWORD="${ADMIN_WEB_PASSWORD:-password}"', install_script)
        self.assertIn('python3 "${ADMIN_APPLY_SCRIPT_PATH}" --no-restart', install_script)
        self.assertIn('systemctl enable vpn-stack-admin.service', install_script)
        self.assertIn('FOREIGN_BLOCK_RU="${FOREIGN_BLOCK_RU:-0}"', install_script)
        self.assertIn('RU_BLOCK_IP_CIDR="${RU_BLOCK_IP_CIDR:-}"', install_script)
        self.assertIn('RU_IPV6_POLICY="${RU_IPV6_POLICY:-to-foreign}"', install_script)
        self.assertIn('RU_LITERAL_POLICY="${RU_LITERAL_POLICY:-fail-fast}"', install_script)
        self.assertIn('RU_IPV6_LITERAL_POLICY="${RU_IPV6_LITERAL_POLICY:-route-with-budget}"', install_script)
        self.assertIn('RU_BLOCK_QUIC="${RU_BLOCK_QUIC:-0}"', install_script)
        self.assertIn('RU_GEOIP_DIRECT="${RU_GEOIP_DIRECT:-0}"', install_script)
        self.assertIn('if [[ "${RU_BLOCK_IP_CIDR}" == "91.108.56.0/22" ]]; then', install_script)
        self.assertIn('if [[ "${RU_IPV6_POLICY}" == "fast-fail" ]]; then', install_script)
        self.assertIn('if [[ "${TO_FOREIGN_CONNECT_TIMEOUT}" == "1s" || "${TO_FOREIGN_CONNECT_TIMEOUT}" == "2s" ]]; then', install_script)
        self.assertIn("timeout 60s systemctl start vpn-stack-sync.service", install_script)
        self.assertIn("continuing with bootstrap assets", install_script)
        self.assertIn('RU_LISTEN_PORT="${RU_LISTEN_PORT:-443}"', install_script)
        self.assertIn('RU_REALITY_ACCEPT_EMPTY_SHORT_ID="${RU_REALITY_ACCEPT_EMPTY_SHORT_ID:-1}"', install_script)
        self.assertIn('RU_REALITY_MAX_TIME_DIFFERENCE="${RU_REALITY_MAX_TIME_DIFFERENCE:-24h}"', install_script)
        self.assertIn('SING_BOX_LOG_LEVEL="${SING_BOX_LOG_LEVEL:-info}"', install_script)
        self.assertIn('RU_SNIFF_TIMEOUT="${RU_SNIFF_TIMEOUT:-250ms}"', install_script)
        self.assertIn('RU_LITERAL_POLICY="${RU_LITERAL_POLICY:-fail-fast}"', install_script)
        self.assertIn('RU_IPV6_LITERAL_POLICY="${RU_IPV6_LITERAL_POLICY:-route-with-budget}"', install_script)
        self.assertIn('TO_FOREIGN_CONNECT_TIMEOUT="${TO_FOREIGN_CONNECT_TIMEOUT:-}"', install_script)
        self.assertIn('TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT="${TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT-2s}"', install_script)
        self.assertIn('TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT="${TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT-3s}"', install_script)
        self.assertIn('if [[ "${RU_LISTEN_PORT}" == "8443" ]]; then', install_script)
        self.assertIn('seen_ru_listen_port="0"', install_script)
        self.assertIn('seen_ip_literal_timeout="0"', install_script)
        self.assertIn('seen_ipv6_literal_timeout="0"', install_script)
        self.assertIn('seen_literal_policy="0"', install_script)
        self.assertIn('seen_ipv6_literal_policy="0"', install_script)
        self.assertIn('render-manifest.json', install_script)
        self.assertNotIn('seen_ru_compat_ports="0"', install_script)
        self.assertIn('APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-900}"', install_script)
        self.assertIn('apt-get -o DPkg::Lock::Timeout="${APT_LOCK_TIMEOUT_SECONDS}" "$@"', install_script)
        self.assertIn("restore_install_state_on_error()", install_script)
        self.assertIn("Install failed after applying changes started; restoring previous files and services.", install_script)
        self.assertIn('RUNTIME_QDISC="${RUNTIME_QDISC:-fq}"', install_script)
        self.assertIn('net.core.default_qdisc=fq', install_script)
        self.assertIn('net.core.somaxconn=4096', install_script)
        self.assertIn('net.core.netdev_max_backlog=8192', install_script)
        self.assertIn('net.core.rmem_max=8388608', install_script)
        self.assertIn('net.ipv4.tcp_syncookies=1', install_script)
        self.assertIn('net.ipv4.udp_rmem_min=16384', install_script)
        self.assertIn('net.ipv4.tcp_congestion_control=bbr', install_script)
        self.assertIn('net.ipv4.tcp_mtu_probing=1', install_script)
        self.assertIn('net.ipv4.tcp_max_syn_backlog=2048', install_script)
        self.assertIn("ethtool", install_script)
        self.assertIn("iperf3", install_script)
        self.assertIn("mtr-tiny", install_script)
        self.assertIn('ethtool -K "${iface}" gro off', install_script)
        self.assertIn('ethtool -K "${iface}" gso off', install_script)
        self.assertIn('ethtool -K "${iface}" tso off', install_script)
        self.assertIn("iputils-ping", install_script)
        self.assertIn('SINGBOX_REQUIRED_VERSION="1.13.12"', install_script)
        self.assertEqual(AUDIT_SINGBOX_REQUIRED_VERSION, "1.13.12")
        self.assertIn(AUDIT_SINGBOX_REQUIRED_VERSION, AUDIT_IMAGE)
        self.assertIn('bash -s -- --version "${SINGBOX_REQUIRED_VERSION}"', install_script)
        self.assertIn('current_singbox_version', install_script)
        self.assertIn('apply_runtime_interface_tuning "${RUNTIME_QDISC_INTERFACE}"', install_script)
        self.assertIn('apply_runtime_qdisc "${WG_INTERFACE}"', install_script)
        self.assertIn('tc qdisc replace dev "${iface}" root fq', install_script)
        self.assertIn("cleanup_failed_rc_local()", install_script)
        self.assertIn("Fixing failed rc-local.service caused by non-executable /etc/rc.local.", install_script)
        self.assertIn("disable_legacy_proxy_services()", install_script)
        self.assertIn('systemctl disable --now "${unit}"', install_script)
        self.assertIn("cleanup_failed_rc_local\ndisable_legacy_proxy_services\nconfigure_ssh_daemon_mode", install_script)
        self.assertIn("cleanup_stale_wireguard_interface()", install_script)
        self.assertIn('ip link delete dev "${WG_INTERFACE}"', install_script)
        self.assertIn("restart_wireguard_service()", install_script)
        self.assertIn('systemctl start "wg-quick@${WG_INTERFACE}"', install_script)
        self.assertNotIn('systemctl restart "wg-quick@${WG_INTERFACE}"', install_script)

    def test_reinstall_waits_for_apt_before_stopping_services(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        install_script = (repo_root / "install.sh").read_text(encoding="utf-8")
        apt_index = install_script.index("run_apt_get update")
        stop_index = install_script.index('if [[ "$ACTION" == "reinstall" ]]; then\n  stop_managed_services\nfi')
        copy_index = install_script.index('copy_role_artifacts "${ROLE_ARTIFACTS_DIR}"')
        self.assertLess(apt_index, stop_index)
        self.assertLess(stop_index, copy_index)

    def test_package_exposes_version_via_getattr(self) -> None:
        package = importlib.import_module("vpn_installer")
        self.assertEqual(package.__version__, "0.9.7")
        with self.assertRaises(AttributeError):
            package.__getattr__("nope")

    def test_package_main_delegates_to_cli(self) -> None:
        package = importlib.import_module("vpn_installer")
        with patch("vpn_installer.cli.main", return_value=7) as mocked:
            self.assertEqual(package.main(["status"]), 7)
        mocked.assert_called_once_with(["status"])

    def test_module_main_exits_with_cli_code(self) -> None:
        with patch("vpn_installer.main", return_value=3):
            with self.assertRaises(SystemExit) as ctx:
                runpy.run_module("vpn_installer.__main__", run_name="__main__")
        self.assertEqual(ctx.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
