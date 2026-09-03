from __future__ import annotations

import unittest

from vpn_installer.audit import docker as audit_docker


class PlatformDockerContractTests(unittest.TestCase):
    def test_matrix_covers_every_supported_distribution_release_once(self) -> None:
        actual = {
            (case.os_id, case.version, case.version_match, case.package_provider)
            for case in audit_docker.PLATFORM_DOCKER_CASES
        }
        expected = {
            ("ubuntu", "22.04", "exact", "apt"),
            ("ubuntu", "24.04", "exact", "apt"),
            ("ubuntu", "26.04", "exact", "apt"),
            ("debian", "12", "exact", "apt"),
            ("debian", "13", "exact", "apt"),
            ("almalinux", "9", "major", "dnf4"),
            ("almalinux", "10", "major", "dnf4"),
            ("rocky", "9", "major", "dnf4"),
            ("rocky", "10", "major", "dnf4"),
            ("fedora", "43", "exact", "dnf5"),
            ("fedora", "44", "exact", "dnf5"),
        }
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), len(audit_docker.PLATFORM_DOCKER_CASES))
        self.assertEqual(len({case.name for case in audit_docker.PLATFORM_DOCKER_CASES}), len(actual))
        self.assertEqual(len({case.image for case in audit_docker.PLATFORM_DOCKER_CASES}), len(actual))

    def test_container_driver_validates_detection_plan_allowlist_and_package_database(self) -> None:
        driver = audit_docker.platform_contract_driver_text()
        compile(driver, "<platform-contract-driver>", "exec")
        self.assertNotIn("\x00", driver)
        for required in (
            "detect_host_facts",
            "resolve_platform",
            "validate_bundle",
            "logical_requirements",
            "spec.package_map.values()",
            "install_packages(spec, packages, runner=run_package_command)",
            "dpkg-query",
            "rpm",
            'Path("/usr/sbin/dnsmasq")',
            "dynamic_uid = 61111",
            '"--keep-in-foreground"',
            'b"localhost"',
            'socket.inet_aton("127.0.0.1")',
            "dns_query()",
            "os.setuid(dynamic_uid)",
            'pid1 == "systemd"',
        ):
            self.assertIn(required, driver)

    def test_container_shell_bootstraps_only_python_and_has_a_bounded_runtime(self) -> None:
        script = audit_docker.platform_contract_shell()
        self.assertIn("source /work/install.sh", script)
        self.assertIn("bootstrap_python", script)
        self.assertIn('PYTHONPATH=/work "$PYTHON_BIN" /work/platform-contract.py', script)
        self.assertNotIn("apt-get install", script)
        self.assertNotIn("dnf5", script)
        self.assertNotIn("systemctl", script)
        self.assertEqual(audit_docker.PLATFORM_CONTRACT_TIMEOUT_SECONDS, 480)
        self.assertEqual(audit_docker.PLATFORM_PACKAGE_COMMAND_TIMEOUT_SECONDS, 300)
        self.assertLess(
            audit_docker.PLATFORM_PACKAGE_COMMAND_TIMEOUT_SECONDS,
            audit_docker.PLATFORM_CONTRACT_TIMEOUT_SECONDS,
        )
        self.assertGreaterEqual(audit_docker.PLATFORM_CONTRACT_MAX_WORKERS, 2)
        self.assertLessEqual(audit_docker.PLATFORM_CONTRACT_MAX_WORKERS, 4)


if __name__ == "__main__":
    unittest.main()
