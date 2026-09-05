from __future__ import annotations

import re
import unittest

from vpn_installer import VERSION
from vpn_installer.common import cli_entrypoint
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
        self.assertLess(Version.parse("0.20.2"), Version.parse("0.21.0"))
        self.assertEqual(str(Version.parse("10.2.3")), "10.2.3")
        for invalid in ("", "v0.20.1", "0.20", "0.20.01", "0.20.1-rc1"):
            with self.subTest(invalid=invalid), self.assertRaises(CompatibilityError):
                Version.parse(invalid)

    def test_transition_window_accepts_only_0223_and_current(self) -> None:
        window = CompatibilityWindow.current()
        self.assertEqual(COMPATIBLE_INSTALLED_MIN, "0.22.3")
        self.assertEqual(COMPATIBLE_INSTALLED_MAX, VERSION)
        self.assertTrue(window.accepts("0.22.3"))
        self.assertTrue(window.accepts(VERSION))
        self.assertFalse(window.accepts("0.21.8"))

    def test_manifest_declares_exact_adapter_free_transition(self) -> None:
        contract = CompatibilityWindow.current().to_manifest()
        self.assertEqual(contract["installed_min"], "0.22.3")
        self.assertEqual(contract["installed_max"], "0.22.4")
        self.assertEqual(contract["transitions"], [{"from": "0.22.3", "to": "0.22.4"}])

    def test_previous_release_manifest_needs_no_adapter(self) -> None:
        contract = {"installed_min": "0.22.2", "installed_max": "0.22.3",
                    "transitions": [{"from": "0.22.2", "to": "0.22.3"}]}
        self.assertEqual(CompatibilityWindow.from_manifest(contract).to_manifest(), contract)

    def test_unused_adapter_metadata_is_rejected(self) -> None:
        contract = CompatibilityWindow.current().to_manifest()
        schemas = {"config": 3, "state": 3, "manifest": 5, "install_plan": 5, "diagnostics": 6}
        contract["transitions"][0].update({"source": schemas, "target": schemas,
                                             "adapter": "unused", "remove_in": "0.22.4"})
        with self.assertRaisesRegex(CompatibilityError, "transition fields"):
            CompatibilityWindow.from_manifest(contract)

    def test_declared_previous_window_is_parsed_without_schema_adapter(self) -> None:
        window = CompatibilityWindow.from_manifest(
            {"installed_min": "0.20.1", "installed_max": "0.20.1", "transitions": []}
        )
        self.assertTrue(window.accepts("0.20.1"))
        with self.assertRaises(CompatibilityError):
            CompatibilityWindow.from_manifest({"installed_min": "0.20.1", "installed_max": "0.20.1"})

    def test_out_of_window_release_has_removal_guidance(self) -> None:
        for version in ("0.22.2", "0.22.5"):
            with self.subTest(version=version), self.assertRaisesRegex(
                CompatibilityError,
                rf"installed release {re.escape(version)}.*{re.escape(cli_entrypoint())} from tag {re.escape(version)}.*remove or purge",
            ):
                require_compatible_installed({"version": version})


if __name__ == "__main__":
    unittest.main()
