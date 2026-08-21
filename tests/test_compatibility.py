from __future__ import annotations

import re
import unittest

from vpn_installer import VERSION
from vpn_installer.common import cli_entrypoint
from vpn_installer.compatibility import (
    COMPATIBLE_INSTALLED_MAX,
    COMPATIBLE_INSTALLED_MIN,
    INSTALLED_CONTRACT_DELTAS,
    CompatibilityError,
    CompatibilityWindow,
    Version,
    installed_contract_delta,
    require_compatible_installed,
)


class VersionTests(unittest.TestCase):
    def test_strict_semver_order(self) -> None:
        self.assertLess(Version.parse("0.20.2"), Version.parse("0.21.0"))
        self.assertEqual(str(Version.parse("10.2.3")), "10.2.3")
        for invalid in ("", "v0.20.1", "0.20", "0.20.01", "0.20.1-rc1"):
            with self.subTest(invalid=invalid), self.assertRaises(CompatibilityError):
                Version.parse(invalid)

    def test_current_window_is_one_upgrade_step(self) -> None:
        window = CompatibilityWindow.current()
        self.assertEqual(COMPATIBLE_INSTALLED_MIN, "0.21.2")
        self.assertEqual(COMPATIBLE_INSTALLED_MAX, VERSION)
        self.assertEqual(set(INSTALLED_CONTRACT_DELTAS), {COMPATIBLE_INSTALLED_MIN})
        self.assertTrue(window.accepts("0.21.2"))
        self.assertTrue(window.accepts(VERSION))
        self.assertFalse(window.accepts("0.21.0"))

    def test_previous_release_contract_delta_is_explicit_and_bounded(self) -> None:
        delta = installed_contract_delta(COMPATIBLE_INSTALLED_MIN)
        self.assertEqual(delta.added_artifacts, {"btmp-vpn-stack.conf", "resource_control.py"})
        self.assertEqual(delta.added_packages, {"logrotate"})
        self.assertFalse(installed_contract_delta(VERSION).added_artifacts)

    def test_manifest_declares_same_schema_upgrade_step(self) -> None:
        contract = CompatibilityWindow.current().to_manifest()
        self.assertEqual(contract["installed_min"], "0.21.2")
        self.assertEqual(contract["installed_max"], "0.21.3")
        self.assertEqual(
            contract["transitions"],
            [{"from": "0.21.2", "to": "0.21.3"}],
        )

    def test_declared_previous_window_is_parsed_without_schema_adapter(self) -> None:
        window = CompatibilityWindow.from_manifest(
            {"installed_min": "0.20.1", "installed_max": "0.20.1", "transitions": []}
        )
        self.assertTrue(window.accepts("0.20.1"))
        with self.assertRaises(CompatibilityError):
            CompatibilityWindow.from_manifest({"installed_min": "0.20.1", "installed_max": "0.20.1"})

    def test_out_of_window_release_has_removal_guidance(self) -> None:
        for version in ("0.21.1", "0.21.4"):
            with self.subTest(version=version), self.assertRaisesRegex(
                CompatibilityError,
                rf"installed release {re.escape(version)}.*{re.escape(cli_entrypoint())} from tag {re.escape(version)}.*remove or purge",
            ):
                require_compatible_installed({"version": version})


if __name__ == "__main__":
    unittest.main()
