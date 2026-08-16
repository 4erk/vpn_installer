from __future__ import annotations

import unittest
from types import MappingProxyType

from vpn_installer.migration import EnvMigrationError, migrate_env


class EnvMigrationTests(unittest.TestCase):
    def canonical_dual(self) -> dict[str, str]:
        return {
            "CONFIG_SCHEMA": "2",
            "DEPLOY_NAME": "demo",
            "TOPOLOGY": "dual",
            "GATEWAY_LOCATION": "ru",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "EXIT_PUBLIC_IP": "198.51.100.20",
            "CLIENT_UUID": "client-contract-value",
        }

    def test_full_legacy_dual_becomes_canonical_with_evidence(self) -> None:
        source = {
            "DEPLOY_NAME": "demo",
            "RU_PUBLIC_IP": "203.0.113.10",
            "FOREIGN_PUBLIC_IP": "198.51.100.20",
            "CLIENT_UUID": "client-contract-value",
        }

        result = migrate_env(source)

        self.assertEqual(result.env["CONFIG_SCHEMA"], "2")
        self.assertEqual(result.env["TOPOLOGY"], "dual")
        self.assertEqual(result.env["GATEWAY_LOCATION"], "ru")
        self.assertEqual(result.env["GATEWAY_PUBLIC_IP"], source["RU_PUBLIC_IP"])
        self.assertEqual(result.env["EXIT_PUBLIC_IP"], source["FOREIGN_PUBLIC_IP"])
        self.assertEqual(result.env["CLIENT_UUID"], source["CLIENT_UUID"])
        self.assertEqual(result.legacy_inputs, ("RU_PUBLIC_IP", "FOREIGN_PUBLIC_IP"))
        self.assertNotIn("RU_PUBLIC_IP", result.env)
        self.assertNotIn("FOREIGN_PUBLIC_IP", result.env)

    def test_canonical_schema_two_is_returned_as_a_detached_canonical_dict(self) -> None:
        source = self.canonical_dual()

        result = migrate_env(MappingProxyType(source))

        self.assertEqual(result.env, source)
        self.assertIsNot(result.env, source)
        self.assertEqual(result.legacy_inputs, ())

    def test_canonical_single_foreign_is_supported(self) -> None:
        source = {
            "CONFIG_SCHEMA": "2",
            "DEPLOY_NAME": "single-foreign",
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "foreign",
            "GATEWAY_PUBLIC_IP": "198.51.100.20",
            "EXIT_PUBLIC_IP": "",
        }

        result = migrate_env(source)

        self.assertEqual(result.env, source)
        self.assertEqual(result.legacy_inputs, ())

    def test_matching_legacy_aliases_on_canonical_env_are_evidence_not_writers(self) -> None:
        source = {
            **self.canonical_dual(),
            "RU_PUBLIC_IP": "203.0.113.10",
            "FOREIGN_PUBLIC_IP": "198.51.100.20",
        }

        result = migrate_env(source)

        self.assertEqual(result.legacy_inputs, ("RU_PUBLIC_IP", "FOREIGN_PUBLIC_IP"))
        self.assertNotIn("RU_PUBLIC_IP", result.env)
        self.assertNotIn("FOREIGN_PUBLIC_IP", result.env)

    def test_canonical_legacy_conflicts_are_rejected(self) -> None:
        cases = (
            {**self.canonical_dual(), "RU_PUBLIC_IP": "203.0.113.99"},
            {**self.canonical_dual(), "FOREIGN_PUBLIC_IP": "198.51.100.99"},
            {
                "RU_PUBLIC_IP": "203.0.113.10",
                "FOREIGN_PUBLIC_IP": "198.51.100.20",
                "GATEWAY_PUBLIC_IP": "203.0.113.99",
            },
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaisesRegex(EnvMigrationError, "canonical/legacy conflict"):
                    migrate_env(source)

    def test_partial_legacy_dual_is_rejected(self) -> None:
        cases = (
            {"RU_PUBLIC_IP": "203.0.113.10"},
            {"FOREIGN_PUBLIC_IP": "198.51.100.20"},
            {},
        )
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaisesRegex(EnvMigrationError, "must contain both"):
                    migrate_env(source)

    def test_unknown_schema_is_rejected_even_with_complete_legacy_addresses(self) -> None:
        source = {
            "CONFIG_SCHEMA": "3",
            "RU_PUBLIC_IP": "203.0.113.10",
            "FOREIGN_PUBLIC_IP": "198.51.100.20",
        }

        with self.assertRaisesRegex(EnvMigrationError, "unsupported CONFIG_SCHEMA: 3"):
            migrate_env(source)

    def test_source_is_never_mutated_on_success_or_failure(self) -> None:
        successful = {
            "RU_PUBLIC_IP": "203.0.113.10",
            "FOREIGN_PUBLIC_IP": "198.51.100.20",
            "CLIENT_UUID": "unchanged",
        }
        successful_before = successful.copy()
        migrate_env(successful)
        self.assertEqual(successful, successful_before)

        failing = {**self.canonical_dual(), "RU_PUBLIC_IP": "203.0.113.99"}
        failing_before = failing.copy()
        with self.assertRaises(EnvMigrationError):
            migrate_env(failing)
        self.assertEqual(failing, failing_before)


if __name__ == "__main__":
    unittest.main()
