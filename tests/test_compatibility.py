from __future__ import annotations

import re
import unittest

from vpn_installer import VERSION
from vpn_installer.compatibility import (
    COMPATIBLE_INSTALLED_MAX,
    COMPATIBLE_INSTALLED_MIN,
    CompatibilityError,
    CompatibilityWindow,
    Version,
    require_compatible_installed,
)


class VersionTests(unittest.TestCase):
    def test_strict_semver_order(self) -> None:
        self.assertLess(Version.parse("0.20.1"), Version.parse("0.20.2"))
        self.assertEqual(str(Version.parse("10.2.3")), "10.2.3")
        for invalid in ("", "v0.20.1", "0.20", "0.20.01", "0.20.1-rc1"):
            with self.subTest(invalid=invalid), self.assertRaises(CompatibilityError):
                Version.parse(invalid)

    def test_current_window_is_one_upgrade_step(self) -> None:
        window = CompatibilityWindow.current()
        self.assertEqual(COMPATIBLE_INSTALLED_MIN, "0.20.1")
        self.assertEqual(COMPATIBLE_INSTALLED_MAX, VERSION)
        self.assertTrue(window.accepts("0.20.1"))
        self.assertTrue(window.accepts(VERSION))
        self.assertFalse(window.accepts("0.19.10"))

    def test_manifest_declares_same_schema_upgrade_step(self) -> None:
        contract = CompatibilityWindow.current().to_manifest()
        self.assertEqual(contract["installed_min"], "0.20.1")
        self.assertEqual(contract["installed_max"], "0.20.2")
        self.assertEqual(
            contract["transitions"],
            [{"from": "0.20.1", "to": "0.20.2"}],
        )

    def test_declared_previous_window_is_parsed_without_version_specific_code(self) -> None:
        window = CompatibilityWindow.from_manifest(
            {"installed_min": "0.20.1", "installed_max": "0.20.1", "transitions": []}
        )
        self.assertTrue(window.accepts("0.20.1"))
        with self.assertRaises(CompatibilityError):
            CompatibilityWindow.from_manifest({"installed_min": "0.20.1", "installed_max": "0.20.1"})

    def test_out_of_window_release_has_removal_guidance(self) -> None:
        for version in ("0.19.10", "0.20.3"):
            with self.subTest(version=version), self.assertRaisesRegex(
                CompatibilityError,
                rf"installed release {re.escape(version)}.*vpn\.cmd from tag {re.escape(version)}.*remove or purge",
            ):
                require_compatible_installed({"version": version})


if __name__ == "__main__":
    unittest.main()
