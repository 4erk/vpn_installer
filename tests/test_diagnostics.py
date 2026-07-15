from __future__ import annotations

import unittest

from vpn_installer.diagnostics import DiagnosticsSnapshot


class DiagnosticsTests(unittest.TestCase):
    def test_snapshot_roundtrips_json_without_shell_parsing(self) -> None:
        snapshot = DiagnosticsSnapshot(
            deployment="demo",
            role="ru-gateway",
            services={"sing-box": "active"},
            drift="none",
            log_buckets={"ipv4_literal_timeout": 2},
            top_destinations={"ipv4_literal_timeout": "91.108.56.103:443=2"},
            verdict="verified",
        )
        restored = DiagnosticsSnapshot.from_json(snapshot.to_json())
        self.assertEqual(restored.deployment, "demo")
        self.assertEqual(restored.log_buckets["ipv4_literal_timeout"], 2)
        self.assertEqual(restored.drift, "none")

    def test_snapshot_rejects_legacy_schema(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported diagnostics snapshot schema"):
            DiagnosticsSnapshot.from_json('{"schema_version":1}')


if __name__ == "__main__":
    unittest.main()
