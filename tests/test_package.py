from __future__ import annotations

import importlib
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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
        self.assertIn('systemctl disable --now ssh.socket', install_script)
        self.assertIn('systemctl enable ssh.service', install_script)
        self.assertIn('SSHD_CONFIG_PATH="/etc/ssh/sshd_config.d/90-vpn-stack.conf"', install_script)
        self.assertIn('HEALTH_SCRIPT_PATH="/usr/local/lib/vpn-stack/health-check.sh"', install_script)
        self.assertIn('HEALTH_THROUGHPUT_URLS="${HEALTH_THROUGHPUT_URLS:-https://cachefly.cachefly.net/1mb.test https://proof.ovh.net/files/1Mb.dat}"', install_script)
        self.assertIn('HEALTH_DEEP_PROBE_INTERVAL_MINUTES="${HEALTH_DEEP_PROBE_INTERVAL_MINUTES:-30}"', install_script)
        self.assertIn('HEALTH_SELF_HEAL="${HEALTH_SELF_HEAL:-1}"', install_script)
        self.assertIn('HEALTH_SELF_HEAL_COOLDOWN_MINUTES="${HEALTH_SELF_HEAL_COOLDOWN_MINUTES:-15}"', install_script)
        self.assertIn('HEALTH_SELF_HEAL_MAX_ACTIONS_PER_HOUR="${HEALTH_SELF_HEAL_MAX_ACTIONS_PER_HOUR:-2}"', install_script)
        self.assertIn('HEALTH_SELF_HEAL_CONFIRMATIONS="${HEALTH_SELF_HEAL_CONFIRMATIONS:-2}"', install_script)
        self.assertIn('HEALTH_TARGET_PROBE_URLS="${HEALTH_TARGET_PROBE_URLS:-https://chatgpt.com/ https://discord.com/ https://github.com/ https://www.google.com/generate_204}"', install_script)
        self.assertIn('RU_LISTEN_PORT="${RU_LISTEN_PORT:-443}"', install_script)
        self.assertIn('RU_REALITY_MAX_TIME_DIFFERENCE="${RU_REALITY_MAX_TIME_DIFFERENCE:-24h}"', install_script)
        self.assertIn('if [[ "${RU_LISTEN_PORT}" == "8443" ]]; then', install_script)
        self.assertIn('seen_ru_listen_port="0"', install_script)
        self.assertNotIn('seen_ru_compat_ports="0"', install_script)
        self.assertIn('APT_LOCK_TIMEOUT_SECONDS="${APT_LOCK_TIMEOUT_SECONDS:-900}"', install_script)
        self.assertIn('apt-get -o DPkg::Lock::Timeout="${APT_LOCK_TIMEOUT_SECONDS}" "$@"', install_script)
        self.assertIn("restore_install_state_on_error()", install_script)
        self.assertIn("Install failed after applying changes started; restoring previous files and services.", install_script)
        self.assertIn('net.core.default_qdisc=fq_codel', install_script)
        self.assertIn('net.core.somaxconn=4096', install_script)
        self.assertIn('net.core.netdev_max_backlog=8192', install_script)
        self.assertIn('net.core.rmem_max=8388608', install_script)
        self.assertIn('net.ipv4.tcp_syncookies=1', install_script)
        self.assertIn('net.ipv4.udp_rmem_min=16384', install_script)
        self.assertIn('net.ipv4.tcp_congestion_control=bbr', install_script)
        self.assertIn('net.ipv4.tcp_mtu_probing=1', install_script)
        self.assertIn('net.ipv4.tcp_max_syn_backlog=2048', install_script)
        self.assertIn("ethtool", install_script)
        self.assertIn('ethtool -K "${iface}" gro off', install_script)
        self.assertIn('ethtool -K "${iface}" gso off', install_script)
        self.assertIn('ethtool -K "${iface}" tso off', install_script)
        self.assertIn("iputils-ping", install_script)
        self.assertIn('SINGBOX_REQUIRED_VERSION="1.13.12"', install_script)
        self.assertIn('bash -s -- --version "${SINGBOX_REQUIRED_VERSION}"', install_script)
        self.assertIn('current_singbox_version', install_script)
        self.assertIn('apply_runtime_interface_tuning "${RUNTIME_QDISC_INTERFACE}"', install_script)
        self.assertIn('apply_runtime_qdisc "${WG_INTERFACE}"', install_script)
        self.assertIn("stop_legacy_xray_port_conflicts()", install_script)
        self.assertIn('systemctl disable --now xray-vpnstack.service xray.service', install_script)
        self.assertIn("stop_legacy_xray_port_conflicts\n  systemctl enable sing-box", install_script)
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
        self.assertEqual(package.__version__, "0.3.8")
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
