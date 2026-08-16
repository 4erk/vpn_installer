from __future__ import annotations

import json
import unittest

from vpn_installer.diagnostics import (
    COLLECTOR_NAMES,
    LOG_WINDOW_KEYS,
    CollectorState,
    DiagnosticsSnapshot,
    LogWindowSnapshot,
    classify_interserver_adaptation,
)
from vpn_installer.log_classifier import BUCKETS


OBSERVED_AT = "2026-08-06T18:00:00+00:00"


def ok_collectors() -> dict[str, CollectorState]:
    return {name: CollectorState.ok(OBSERVED_AT) for name in COLLECTOR_NAMES}


def empty_windows() -> dict[str, LogWindowSnapshot]:
    return {
        name: LogWindowSnapshot.empty(observed_at=OBSERVED_AT, since=name, until=OBSERVED_AT)
        for name in LOG_WINDOW_KEYS
    }


class DiagnosticsTests(unittest.TestCase):
    def test_interserver_adaptation_separates_failure_from_staleness(self) -> None:
        self.assertEqual(
            classify_interserver_adaptation({"state": "failed", "fresh": True, "reason": "both paths unavailable"}),
            ("interserver_adaptation=both paths unavailable", ""),
        )
        self.assertEqual(
            classify_interserver_adaptation({"state": "healthy", "fresh": False, "reason": "selected underlay is healthy"}),
            ("", "interserver_adaptation=stale"),
        )
        self.assertEqual(classify_interserver_adaptation({"state": "healthy", "fresh": True}), ("", ""))

    def test_snapshot_v4_roundtrips_without_shell_parsing(self) -> None:
        windows = empty_windows()
        windows["5m"] = LogWindowSnapshot.collected(
            {bucket: 2 if bucket == "ipv4_literal_timeout" else 0 for bucket in BUCKETS},
            observed_at=OBSERVED_AT,
            since="2026-08-06T17:55:00+00:00",
            until=OBSERVED_AT,
            top_destinations={"ipv4_literal_timeout": {"91.108.56.103:443": 2}},
        )
        snapshot = DiagnosticsSnapshot(
            deployment="demo",
            topology="dual",
            node_id="gateway",
            location="ru",
            capabilities=("public-front", "router", "local-egress", "interserver-client"),
            role="ru-gateway",
            collectors=ok_collectors(),
            log_windows=windows,
            services={"sing-box": "active"},
            drift="none",
            storage={"root_filesystem": {"filesystem": "ext4", "state": "clean", "verdict": "verified"}},
            verdict="verified",
        )

        restored = DiagnosticsSnapshot.from_json(snapshot.to_json())

        self.assertEqual(restored.schema_version, 4)
        self.assertEqual(restored.deployment, "demo")
        self.assertEqual(restored.topology, "dual")
        self.assertEqual(restored.node_id, "gateway")
        self.assertEqual(restored.location, "ru")
        self.assertEqual(restored.capabilities, ("interserver-client", "local-egress", "public-front", "router"))
        self.assertEqual(restored.collector_status, "ok")
        self.assertEqual(restored.log_windows["5m"].counts["ipv4_literal_timeout"], 2)
        self.assertEqual(restored.log_windows["30m"].counts["ipv4_literal_timeout"], 0)
        self.assertEqual(restored.drift, "none")
        self.assertEqual(restored.storage["root_filesystem"]["verdict"], "verified")

    def test_generic_parser_rejects_legacy_schema(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported diagnostics snapshot schema"):
            DiagnosticsSnapshot.from_json('{"schema_version":2}')

    def test_legacy_agent_migration_is_explicit_and_never_marks_data_fresh(self) -> None:
        empty_summary = {"counts": {"dns_failed": 0}}
        payload = {
            "schema_version": 2,
            "generated_at": OBSERVED_AT,
            "deployment": "demo",
            "role": "ru-gateway",
            "services": {"sing-box": "active"},
            "artifacts": {"drift": "none", "files": {}},
            "wireguard": {},
            "probes": {"profile": "none", "ok": None},
            "logs": {
                "fresh": {"since": "2026-08-06T17:30:00+00:00", "counts": {"dns_failed": 3}},
                "windows_minutes": {"5": empty_summary, "30": empty_summary, "1440": empty_summary},
            },
            "storage": {},
            "network": {},
            "front": {},
            "transport": {},
            "maintenance": {},
            "verdicts": {"overall": "verified", "reasons": []},
        }

        migrated = DiagnosticsSnapshot.migrate_agent_v2(payload)

        self.assertEqual(migrated.schema_version, 4)
        self.assertEqual(migrated.collector_status, "stale")
        self.assertEqual(migrated.verdict, "inconclusive")
        self.assertEqual(migrated.migration["boundary"], "DiagnosticsSnapshot.migrate_agent_v2")
        self.assertEqual(migrated.log_windows["5m"].counts["dns_nodata"], 0)
        self.assertIsNone(migrated.log_windows["since_release"].counts["dns_nodata"])
        self.assertIsNone(migrated.log_windows["since_release"].counts["dns_refused"])
        self.assertIsNone(migrated.log_windows["since_release"].counts["dns_servfail"])
        self.assertIn("cannot be split", migrated.migration["warnings"][0])

    def test_agent_adapter_rejects_v2_outside_the_offline_migration_helper(self) -> None:
        payload = {
            "schema_version": 2,
            "generated_at": OBSERVED_AT,
            "services": {},
            "artifacts": {},
            "wireguard": {},
            "probes": {},
            "logs": {"fresh": {"counts": {}}, "windows_minutes": {}},
            "storage": {},
            "network": {},
            "front": {},
            "transport": {},
            "maintenance": {},
            "verdicts": {"overall": "inconclusive", "reasons": []},
        }
        with self.assertRaisesRegex(ValueError, "unsupported vpn-stack-agent snapshot schema"):
            DiagnosticsSnapshot.from_agent(payload)

    def test_agent_adapter_migrates_v3_as_stale_inconclusive_evidence(self) -> None:
        payload = DiagnosticsSnapshot(
            role="ru-gateway",
            collectors=ok_collectors(),
            log_windows=empty_windows(),
            verdict="verified",
        ).to_dict()
        payload["schema_version"] = 3
        for name in ("topology", "node_id", "location", "capabilities"):
            del payload[name]

        migrated = DiagnosticsSnapshot.from_agent(payload)

        self.assertEqual(migrated.schema_version, 4)
        self.assertEqual(migrated.verdict, "inconclusive")
        self.assertEqual(migrated.collector_status, "stale")
        self.assertEqual(migrated.topology, "dual")
        self.assertEqual(migrated.node_id, "gateway")
        self.assertEqual(migrated.location, "ru")
        self.assertIn("public-front", migrated.capabilities)
        self.assertEqual(migrated.migration["source_schema_version"], 3)
        self.assertEqual(migrated.migration["boundary"], "DiagnosticsSnapshot.migrate_agent_v3")
        self.assertTrue(all(state.status == "stale" for state in migrated.collectors.values()))
        self.assertTrue(all(window.collector.status == "stale" for window in migrated.log_windows.values()))

    def test_strict_parser_rejects_missing_fixed_window(self) -> None:
        payload = DiagnosticsSnapshot().to_dict()
        del payload["log_windows"]["24h"]
        with self.assertRaisesRegex(ValueError, "log windows must match"):
            DiagnosticsSnapshot.from_json(json.dumps(payload))

    def test_strict_parser_rejects_invalid_collector_status(self) -> None:
        payload = DiagnosticsSnapshot().to_dict()
        payload["collectors"]["logs"]["status"] = "unknown"
        with self.assertRaisesRegex(ValueError, "invalid collector status"):
            DiagnosticsSnapshot.from_json(json.dumps(payload))

    def test_absent_log_data_is_not_serialized_as_zero(self) -> None:
        unavailable = DiagnosticsSnapshot().log_windows["5m"]
        collected = LogWindowSnapshot.empty(observed_at=OBSERVED_AT)

        self.assertEqual(unavailable.collector.status, "error")
        self.assertIsNone(unavailable.counts)
        self.assertEqual(collected.collector.status, "ok")
        self.assertEqual(collected.counts["dns_timeout"], 0)

    def test_explicitly_skipped_collectors_roundtrip_without_claiming_collection(self) -> None:
        collectors = ok_collectors()
        collectors["route_probes"] = CollectorState.skipped("not requested")
        windows = empty_windows()
        windows["30m"] = LogWindowSnapshot.skipped("not requested")
        snapshot = DiagnosticsSnapshot(collectors=collectors, log_windows=windows)

        restored = DiagnosticsSnapshot.from_json(snapshot.to_json())

        self.assertEqual(restored.collector_status, "skipped")
        self.assertEqual(restored.collectors["route_probes"].message, "not requested")
        self.assertEqual(restored.log_windows["30m"].collector.status, "skipped")
        self.assertIsNone(restored.log_windows["30m"].counts)

    def test_not_applicable_is_distinct_and_does_not_degrade_applicable_collectors(self) -> None:
        collectors = ok_collectors()
        collectors["wireguard"] = CollectorState.not_applicable("single topology has no interserver overlay")
        collectors["transport"] = CollectorState.not_applicable("single topology has no interserver transport")
        snapshot = DiagnosticsSnapshot(
            topology="single",
            node_id="gateway",
            location="foreign",
            capabilities=("local-egress", "public-front", "router", "web-admin"),
            collectors=collectors,
            log_windows=empty_windows(),
        )

        restored = DiagnosticsSnapshot.from_json(snapshot.to_json())

        self.assertEqual(restored.collector_status, "ok")
        self.assertEqual(restored.collectors["wireguard"].status, "not_applicable")
        self.assertNotEqual(restored.collectors["wireguard"].status, "skipped")
        self.assertIsNone(LogWindowSnapshot.not_applicable("not part of this contract").counts)

    def test_native_contract_matrix_roundtrips_single_and_dual_nodes(self) -> None:
        cases = (
            ("single-ru", "single", "gateway", "ru", ("local-egress", "public-front", "router", "web-admin")),
            ("single-foreign", "single", "gateway", "foreign", ("local-egress", "public-front", "router", "web-admin")),
            ("dual-gateway", "dual", "gateway", "ru", ("interserver-client", "local-egress", "public-front", "router", "ru-split-routing", "web-admin")),
            ("dual-exit", "dual", "exit", "foreign", ("interserver-server", "nat-exit")),
        )
        for name, topology, node_id, location, capabilities in cases:
            with self.subTest(name=name):
                collectors = ok_collectors()
                if "interserver-client" not in capabilities and "interserver-server" not in capabilities:
                    collectors["wireguard"] = CollectorState.not_applicable("not required by node plan")
                    collectors["transport"] = CollectorState.not_applicable("not required by node plan")
                if "public-front" not in capabilities:
                    collectors["front"] = CollectorState.not_applicable("not required by node plan")
                snapshot = DiagnosticsSnapshot(
                    topology=topology,
                    node_id=node_id,
                    location=location,
                    capabilities=capabilities,
                    collectors=collectors,
                    log_windows=empty_windows(),
                )

                restored = DiagnosticsSnapshot.from_json(snapshot.to_json())

                self.assertTrue(restored.has_capability_contract)
                self.assertEqual(restored.collector_status, "ok")
                self.assertEqual(restored.topology, topology)
                self.assertEqual(restored.node_id, node_id)

    def test_native_contract_rejects_partial_or_invalid_topology(self) -> None:
        with self.assertRaisesRegex(ValueError, "must include topology"):
            DiagnosticsSnapshot(topology="single")
        with self.assertRaisesRegex(ValueError, "single topology cannot contain an exit"):
            DiagnosticsSnapshot(
                topology="single",
                node_id="exit",
                location="foreign",
                capabilities=("nat-exit",),
            )

    def test_ok_window_rejects_unknown_counts(self) -> None:
        counts = LogWindowSnapshot.empty(observed_at=OBSERVED_AT).counts
        counts["dns_timeout"] = None
        with self.assertRaisesRegex(ValueError, "ok log window cannot contain unknown counts"):
            LogWindowSnapshot(collector=CollectorState.ok(OBSERVED_AT), counts=counts)


if __name__ == "__main__":
    unittest.main()
