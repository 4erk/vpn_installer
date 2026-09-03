from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.platforms import (
    HostFacts,
    PlatformError,
    PlatformSpec,
    _host_firewall,
    _selinux_port_owners,
    apply_updates,
    install_platform,
    install_packages,
    maintenance_snapshot,
    prepare_host_platform,
    requirements_for,
    resolve_platform,
)


class PlatformTests(unittest.TestCase):
    def test_supported_matrix_resolves_exact_provider(self) -> None:
        cases = (
            ("ubuntu", "22.04", "apt", "deb"),
            ("ubuntu", "24.04", "apt", "deb"),
            ("ubuntu", "26.04", "apt", "deb"),
            ("debian", "12", "apt", "deb"),
            ("debian", "13", "apt", "deb"),
            ("almalinux", "9.6", "dnf4", "rpm"),
            ("almalinux", "10.0", "dnf4", "rpm"),
            ("rocky", "9.5", "dnf4", "rpm"),
            ("rocky", "10.0", "dnf4", "rpm"),
            ("fedora", "43", "dnf5", "rpm"),
            ("fedora", "44", "dnf5", "rpm"),
        )
        for os_id, version, provider, family in cases:
            with self.subTest(os_id=os_id, version=version):
                spec = resolve_platform(HostFacts(os_id, version, "amd64", init_system="systemd"))
                self.assertEqual(spec.package_provider, provider)
                self.assertEqual(spec.family, family)
                self.assertEqual(spec.resolver_provider, "dnsmasq")
                self.assertEqual(spec.firewall_provider, "nftables")
                self.assertEqual(PlatformSpec.from_dict(spec.to_dict()), spec)

    def test_unknown_version_architecture_and_init_are_rejected(self) -> None:
        cases = (
            HostFacts("ubuntu", "20.04", "x86_64", init_system="systemd"),
            HostFacts("debian", "14", "x86_64", init_system="systemd"),
            HostFacts("fedora", "42", "x86_64", init_system="systemd"),
            HostFacts("ubuntu", "24.04", "aarch64", init_system="systemd"),
            HostFacts("ubuntu", "24.04", "x86_64", init_system="openrc"),
            HostFacts("ubuntu", "24.04", "x86_64", init_system=""),
        )
        for facts in cases:
            with self.subTest(facts=facts), self.assertRaises(PlatformError):
                resolve_platform(facts)

    def test_install_platform_rejects_competing_or_unknown_firewall(self) -> None:
        clean = HostFacts("ubuntu", "24.04", "x86_64", init_system="systemd", host_firewall="none")
        self.assertEqual(install_platform(clean).package_provider, "apt")
        for firewall in ("ufw", "firewalld", "unknown"):
            with self.subTest(firewall=firewall), self.assertRaisesRegex(PlatformError, "host firewall"):
                install_platform(
                    HostFacts("ubuntu", "24.04", "x86_64", init_system="systemd", host_firewall=firewall)
                )

    def test_firewall_detection_fails_closed_on_query_errors(self) -> None:
        with patch("vpn_installer.platforms.shutil.which", side_effect=lambda name: name == "firewall-cmd"), patch(
            "vpn_installer.platforms.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, "", "Failed to connect to bus"),
        ):
            self.assertEqual(_host_firewall(), "unknown")

        with patch("vpn_installer.platforms.shutil.which", side_effect=lambda name: name == "ufw"), patch(
            "vpn_installer.platforms.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, "", "permission denied"),
        ):
            self.assertEqual(_host_firewall(), "unknown")

    def test_firewall_detection_accepts_only_explicitly_inactive_state(self) -> None:
        with patch("vpn_installer.platforms.shutil.which", side_effect=lambda name: name == "firewall-cmd"), patch(
            "vpn_installer.platforms.subprocess.run",
            return_value=subprocess.CompletedProcess([], 3, "inactive\n", ""),
        ):
            self.assertEqual(_host_firewall(), "none")

        with patch("vpn_installer.platforms.shutil.which", side_effect=lambda name: name == "ufw"), patch(
            "vpn_installer.platforms.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, "Status: active\n", ""),
        ):
            self.assertEqual(_host_firewall(), "ufw")

    def test_logical_requirements_add_selinux_tools_only_for_rpm(self) -> None:
        deb = resolve_platform(HostFacts("debian", "12", "x86_64", init_system="systemd"))
        rpm = resolve_platform(HostFacts("rocky", "9.5", "x86_64", init_system="systemd"))
        deb_requirements = requirements_for(public_front=True, interserver=True, platform=deb)
        rpm_requirements = requirements_for(public_front=True, interserver=True, platform=rpm)
        self.assertNotIn("selinux-policy-tools", deb_requirements)
        self.assertIn("selinux-policy-tools", rpm_requirements)
        self.assertIn("dnsmasq-base", deb.resolve_packages(deb_requirements))
        self.assertIn("dnsmasq", rpm.resolve_packages(rpm_requirements))
        self.assertIn("policycoreutils-python-utils", rpm.resolve_packages(rpm_requirements))
        self.assertIn("curl-minimal", rpm.resolve_packages(rpm_requirements))
        self.assertNotIn("curl", rpm.resolve_packages(rpm_requirements))
        el10 = resolve_platform(HostFacts("rocky", "10.0", "x86_64", init_system="systemd"))
        self.assertIn("curl", el10.resolve_packages(rpm_requirements))

    def test_apt_and_dnf_install_commands_are_provider_owned(self) -> None:
        calls: list[list[str]] = []

        def runner(command, **_kwargs):
            calls.append(list(command))
            return subprocess.CompletedProcess(command, 0, "", "")

        apt = resolve_platform(HostFacts("ubuntu", "24.04", "x86_64", init_system="systemd"))
        install_packages(apt, ["python3", "curl"], runner=runner)
        self.assertEqual(calls[0], ["apt-get", "update"])
        self.assertEqual(calls[1], ["apt-get", "install", "-y", "--no-install-recommends", "curl", "python3"])
        self.assertEqual(calls[2], ["apt-get", "clean"])

        calls.clear()
        fedora = resolve_platform(HostFacts("fedora", "43", "x86_64", init_system="systemd"))
        install_packages(fedora, ["python3", "curl"], runner=runner)
        self.assertEqual(calls[0][0:5], ["dnf5", "-y", "--setopt=install_weak_deps=False", "install", "curl"])
        self.assertEqual(calls[1], ["dnf5", "clean", "all"])

    def test_dnf_retries_only_transient_repository_failures(self) -> None:
        spec = resolve_platform(HostFacts("almalinux", "10.0", "x86_64", init_system="systemd"))
        responses = iter(
            (
                subprocess.CompletedProcess([], 1, "", "Curl error (35): mirrorlist TLS failure"),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 0, "", ""),
            )
        )
        calls: list[list[str]] = []

        def transient_runner(command, **_kwargs):
            calls.append(list(command))
            return next(responses)

        with patch("vpn_installer.platforms.time.sleep") as sleep:
            install_packages(spec, ["python3"], runner=transient_runner)
        self.assertEqual(
            [call[:4] for call in calls[:2]],
            [["dnf", "-y", "--setopt=install_weak_deps=False", "install"]] * 2,
        )
        sleep.assert_called_once_with(2)

        solver_calls = 0

        def solver_failure(command, **_kwargs):
            nonlocal solver_calls
            solver_calls += 1
            return subprocess.CompletedProcess(command, 1, "", "package conflicts with curl-minimal")

        with self.assertRaisesRegex(RuntimeError, "package conflicts"):
            install_packages(spec, ["curl"], runner=solver_failure)
        self.assertEqual(solver_calls, 1)

    def test_maintenance_is_provider_neutral(self) -> None:
        apt = resolve_platform(HostFacts("debian", "13", "x86_64", init_system="systemd"))
        with patch("vpn_installer.platforms.Path.exists", return_value=True):
            snapshot = maintenance_snapshot(
                apt,
                runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                    command,
                    0,
                    "Listing...\nopenssl/stable-security 2 amd64 [upgradable]\ncurl/stable 3 amd64 [upgradable]\n",
                    "",
                ),
            )
        self.assertEqual(snapshot["provider"], "apt")
        self.assertEqual(snapshot["upgradable"], 2)
        self.assertEqual(snapshot["security_upgradable"], 1)
        self.assertTrue(snapshot["reboot_required"])

    def test_selinux_label_is_persistent_and_restored(self) -> None:
        spec = resolve_platform(HostFacts("rocky", "9.5", "x86_64", init_system="systemd"))
        calls: list[list[str]] = []

        def runner(command, **_kwargs):
            calls.append(list(command))
            stdout = "dns_port_t tcp 53, 1054\ndns_port_t udp 53, 1054\n" if command == ["semanage", "port", "-l"] else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with patch("vpn_installer.platforms.require_host_matches"):
            prepare_host_platform(spec, Path("/etc/vpn-stack/releases/candidate-test"), runner=runner)
        self.assertEqual(calls[0][:4], ["semanage", "fcontext", "-a", "-t"])
        self.assertEqual(calls[1][:5], ["semanage", "fcontext", "-a", "-t", "dnsmasq_etc_t"])
        self.assertEqual(calls[2], ["semanage", "port", "-l"])
        self.assertEqual(calls[3][:2], ["restorecon", "-RF"])
        self.assertEqual(calls[3][2].replace("\\", "/"), "/etc/vpn-stack/releases/candidate-test/bin")
        self.assertEqual(
            calls[3][3].replace("\\", "/"),
            "/etc/vpn-stack/releases/candidate-test/dnsmasq-vpn-stack.conf",
        )

    def test_selinux_dns_port_is_added_or_conflict_is_rejected(self) -> None:
        self.assertEqual(
            _selinux_port_owners("dns_port_t tcp 53, 1054\ndns_port_t udp 53, 1000-1100\n", 1054),
            {"tcp": "dns_port_t", "udp": "dns_port_t"},
        )
        with self.assertRaisesRegex(PlatformError, "multiple owners"):
            _selinux_port_owners("dns_port_t tcp 1054\nother_port_t tcp 1054\n", 1054)

        spec = resolve_platform(HostFacts("fedora", "43", "x86_64", init_system="systemd"))
        calls: list[list[str]] = []

        def runner(command, **_kwargs):
            calls.append(list(command))
            stdout = "other_port_t tcp 1054\n" if command == ["semanage", "port", "-l"] else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        with patch("vpn_installer.platforms.require_host_matches"), self.assertRaisesRegex(
            PlatformError, "refusing to reassign"
        ):
            prepare_host_platform(spec, Path("/etc/vpn-stack/releases/test"), runner=runner)
        self.assertFalse(any(command[:3] == ["semanage", "port", "-a"] for command in calls))

    def test_apply_updates_uses_provider_specific_command(self) -> None:
        calls: list[list[str]] = []

        def runner(command, **_kwargs):
            calls.append(list(command))
            return subprocess.CompletedProcess(command, 0, "", "")

        spec = resolve_platform(HostFacts("fedora", "44", "x86_64", init_system="systemd"))
        apply_updates(spec, runner=runner)
        self.assertEqual(calls, [["dnf5", "-y", "upgrade", "--refresh"]])


if __name__ == "__main__":
    unittest.main()
