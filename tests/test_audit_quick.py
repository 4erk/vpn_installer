from __future__ import annotations

import unittest

from vpn_installer.audit.quick import coverage_command, coverage_driver_text, unit_test_modules


class AuditQuickTests(unittest.TestCase):
    def test_coverage_command_uses_embedded_coverage_runner(self) -> None:
        command = coverage_command("report", "--fail-under=90")
        self.assertGreaterEqual(len(command), 4)
        self.assertEqual(command[-2:], ["report", "--fail-under=90"])
        self.assertIn("runpy.run_module('coverage'", command[2])

    def test_coverage_driver_discovers_repo_tests(self) -> None:
        driver = coverage_driver_text()
        self.assertIn("unittest.defaultTestLoader.loadTestsFromName", driver)
        self.assertIn("module_name = sys.argv[1]", driver)
        self.assertTrue(any(name.endswith("test_audit_quick") for name in unit_test_modules()))


if __name__ == "__main__":
    unittest.main()
