from __future__ import annotations

import re
import unittest

from vpn_installer import VERSION
from vpn_installer.compatibility import (
    COMPATIBLE_INSTALLED_MAX,
    COMPATIBLE_INSTALLED_MIN,
    TRANSITION_REMOVE_IN,
    CompatibilityError,
    CompatibilityWindow,
    Version,
    require_compatible_installed,
)


class VersionTests(unittest.TestCase):
    def test_strict_semver_order(self) -> None:
        self.assertLess(Version.parse("0.20.0"), Version.parse("0.20.1"))
        self.assertEqual(str(Version.parse("10.2.3")), "10.2.3")
        for invalid in ("", "v0.20.0", "0.20", "0.20.01", "0.20.0-rc1"):
            with self.subTest(invalid=invalid), self.assertRaises(CompatibilityError):
                Version.parse(invalid)

    def test_current_window_is_one_upgrade_step(self) -> None:
        window = CompatibilityWindow.current()
        self.assertEqual(COMPATIBLE_INSTALLED_MIN, "0.20.0")
        self.assertEqual(COMPATIBLE_INSTALLED_MAX, VERSION)
        self.assertTrue(window.accepts("0.20.0"))
        self.assertTrue(window.accepts(VERSION))
        self.assertFalse(window.accepts("0.19.10"))

    def test_manifest_declares_removable_transition(self) -> None:
        contract = CompatibilityWindow.current().to_manifest()
        self.assertEqual(contract["installed_min"], "0.20.0")
        self.assertEqual(contract["installed_max"], "0.20.1")
        self.assertEqual(
            contract["transitions"],
            [{"from": "0.20.0", "to": "0.20.1", "remove_in": TRANSITION_REMOVE_IN}],
        )

    def test_out_of_window_release_has_removal_guidance(self) -> None:
        for version in ("0.19.10", "0.20.2"):
            with self.subTest(version=version), self.assertRaisesRegex(
                CompatibilityError,
                rf"installed release {re.escape(version)}.*vpn\.cmd from tag {re.escape(version)}.*remove or purge",
            ):
                require_compatible_installed({"version": version})


if __name__ == "__main__":
    unittest.main()
