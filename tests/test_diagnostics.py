from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

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
    def test_absolute_log_window_rejects_inverted_bounds(self) -> None:
        for since in ("2026-08-07T18:00:00Z", "2026-08-06T21:00:01+03:00"):
            with self.subTest(since=since), self.assertRaisesRegex(ValueError, "since.*until"):
                LogWindowSnapshot.empty(observed_at=OBSERVED_AT, since=since, until=OBSERVED_AT)

    def test_native_parser_rejects_inverted_window_without_new_schema_fields(self) -> None:
        snapshot = DiagnosticsSnapshot(generated_at=OBSERVED_AT, log_windows=empty_windows())
        payload = snapshot.to_dict()
        payload["log_windows"]["since_release"]["since"] = "2026-08-07T18:00:00Z"
        with self.assertRaisesRegex(ValueError, "since.*until"):
            DiagnosticsSnapshot.from_dict(payload)
        object.__setattr__(snapshot.log_windows["since_release"], "since", "2026-08-07T18:00:00Z")
        self.assertEqual(snapshot.freshness_issues(now=datetime.fromisoformat(OBSERVED_AT)),
                         ["log window since_release: log window since must be <= until"])

    def test_absolute_since_requires_timezone_but_relative_since_does_not(self) -> None:
        with self.assertRaisesRegex(ValueError, "since.*timezone"):
            LogWindowSnapshot.empty(observed_at=OBSERVED_AT, since="2026-08-06T18:00:00", until=OBSERVED_AT)

    def test_log_window_bounds_allow_equal_offsets_and_legacy_relative_since(self) -> None:
        for since in ("2026-08-06T21:00:00+03:00", "2026-08-05T18:00:00Z", "5 minutes ago", "30 minutes ago", "1440 minutes ago"):
            with self.subTest(since=since):
                snapshot = DiagnosticsSnapshot(generated_at=OBSERVED_AT)
                snapshot.log_windows["5m"] = LogWindowSnapshot.empty(
                    observed_at=OBSERVED_AT, since=since, until=OBSERVED_AT,
                )
                restored = DiagnosticsSnapshot.from_json(snapshot.to_json())
                self.assertEqual(restored.schema_version, 6)
                self.assertEqual(restored.log_windows["5m"].since, since)
                self.assertEqual(restored.freshness_issues(now=datetime.fromisoformat(OBSERVED_AT)), [])

    def test_timestamp_validation_requires_an_explicit_timezone(self) -> None:
        for invalid in ("not-a-timestamp", "2026-08-06", "2026-08-06T18:00:00", "2026-08-06T18:00:00+25:00"):
            with self.subTest(value=invalid):
                with self.assertRaises(ValueError):
                    CollectorState.ok(invalid)
                with self.assertRaises(ValueError):
                    DiagnosticsSnapshot(generated_at=invalid)
                with self.assertRaises(ValueError):
                    LogWindowSnapshot.empty(observed_at=OBSERVED_AT, until=invalid)

    def test_freshness_checks_each_collector_without_rewriting_historical_evidence(self) -> None:
        now = datetime.fromisoformat(OBSERVED_AT)
        for name in COLLECTOR_NAMES:
            for age in (181, -31):
                with self.subTest(collector=name, age=age):
                    collectors = ok_collectors()
                    collectors[name] = CollectorState.ok((now - timedelta(seconds=age)).isoformat())
                    snapshot = DiagnosticsSnapshot(generated_at=OBSERVED_AT, collectors=collectors, log_windows=empty_windows())
                    before = snapshot.to_json()
                    issues = snapshot.freshness_issues(now=now, max_age_seconds=180, future_skew_seconds=30)
                    self.assertEqual(len(issues), 1)
                    self.assertIn(f"collector {name}", issues[0])
                    self.assertEqual(snapshot.to_json(), before)

    def test_freshness_uses_explicit_inclusive_budgets_and_offsets(self) -> None:
        now = datetime.fromisoformat(OBSERVED_AT)
        for age, expected in ((180, False), (180.001, True), (-30, False), (-30.001, True)):
            observed = (now - timedelta(seconds=age)).astimezone(timezone(timedelta(hours=3))).isoformat()
            snapshot = DiagnosticsSnapshot(generated_at=observed)
            with self.subTest(age=age):
                self.assertEqual(bool(snapshot.freshness_issues(now=now)), expected)
        snapshot = DiagnosticsSnapshot(generated_at=(now - timedelta(seconds=4)).isoformat())
        self.assertTrue(snapshot.freshness_issues(now=now, max_age_seconds=3, future_skew_seconds=0))
        self.assertFalse(snapshot.freshness_issues(now=now, max_age_seconds=4, future_skew_seconds=0))

    def test_log_window_freshness_is_observation_age_not_history_length(self) -> None:
        now = datetime.fromisoformat(OBSERVED_AT)
        snapshot = DiagnosticsSnapshot(generated_at=OBSERVED_AT, collectors=ok_collectors(), log_windows=empty_windows())
        snapshot.log_windows["24h"] = replace(snapshot.log_windows["24h"], since=(now - timedelta(days=1)).isoformat())
        self.assertEqual(snapshot.freshness_issues(now=now), [])
        for name in LOG_WINDOW_KEYS:
            for field in ("collector", "until"):
                with self.subTest(window=name, field=field):
                    windows = empty_windows()
                    stale = (now - timedelta(seconds=181)).isoformat()
                    windows[name] = replace(windows[name], **{field: CollectorState.ok(stale) if field == "collector" else stale})
                    snapshot = DiagnosticsSnapshot(generated_at=OBSERVED_AT, collectors=ok_collectors(), log_windows=windows)
                    issues = snapshot.freshness_issues(now=now)
                    self.assertEqual(len(issues), 1)
                    self.assertIn(f"log window {name}", issues[0])

    def test_collected_window_requires_end_time_for_freshness_not_for_deserialization(self) -> None:
        snapshot = DiagnosticsSnapshot(generated_at=OBSERVED_AT)
        snapshot.log_windows["5m"] = LogWindowSnapshot.empty(observed_at=OBSERVED_AT)
        restored = DiagnosticsSnapshot.from_json(snapshot.to_json())
        self.assertEqual(restored.freshness_issues(now=datetime.fromisoformat(OBSERVED_AT)), ["log window 5m until is missing"])

    def test_freshness_preserves_explicit_stale_and_ignores_uncollected_states(self) -> None:
        snapshot = DiagnosticsSnapshot(generated_at=OBSERVED_AT, collectors=ok_collectors(), log_windows=empty_windows())
        snapshot.collectors["front"] = CollectorState.stale(OBSERVED_AT)
        snapshot.log_windows["5m"] = replace(snapshot.log_windows["5m"], collector=CollectorState.stale(OBSERVED_AT))
        snapshot.collectors["transport"] = CollectorState.not_applicable("single topology")
        snapshot.collectors["maintenance"] = CollectorState.skipped("not requested")
        snapshot.collectors["wireguard"] = CollectorState.error("not available")
        snapshot.log_windows["30m"] = LogWindowSnapshot.skipped("not requested")
        snapshot.log_windows["since_release"] = LogWindowSnapshot.unavailable("outside retention")
        self.assertEqual(snapshot.freshness_issues(now=datetime.fromisoformat(OBSERVED_AT)),
                         ["collector front is marked stale", "log window 5m is marked stale"])

    def test_freshness_rejects_invalid_clock_and_budgets(self) -> None:
        snapshot = DiagnosticsSnapshot()
        for now in (datetime(2026, 8, 6), OBSERVED_AT, None):
            with self.subTest(now=now), self.assertRaisesRegex(ValueError, "now must be"):
                snapshot.freshness_issues(now=now)
        for name in ("max_age_seconds", "future_skew_seconds"):
            for value in (-1, float("nan"), float("inf"), True, "180"):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    snapshot.freshness_issues(now=datetime.now(timezone.utc), **{name: value})

    def test_mutated_snapshot_timestamp_cannot_bypass_freshness(self) -> None:
        snapshot = DiagnosticsSnapshot()
        snapshot.generated_at = "invalid"
        self.assertEqual(snapshot.freshness_issues(now=datetime.now(timezone.utc)),
                         ["snapshot generated_at must be a timezone-aware timestamp"])

    def test_native_parser_rejects_bad_timestamp_without_changing_wire_fields(self) -> None:
        snapshot = DiagnosticsSnapshot(generated_at=OBSERVED_AT, collectors=ok_collectors(), log_windows=empty_windows())
        before = snapshot.to_dict()
        self.assertEqual(snapshot.schema_version, 6)
        snapshot.freshness_issues(now=datetime.fromisoformat(OBSERVED_AT))
        self.assertEqual(snapshot.to_dict(), before)
        for timestamp in ("2026-08-06T18:00:00Z", "2026-08-06T21:00:00+03:00"):
            payload = snapshot.to_dict()
            payload["collectors"]["services"]["observed_at"] = timestamp
            self.assertEqual(DiagnosticsSnapshot.from_dict(payload).freshness_issues(now=datetime.fromisoformat(OBSERVED_AT)), [])
        for field in ("generated_at", "observed_at", "until"):
            payload = snapshot.to_dict()
            if field == "generated_at":
                payload[field] = "invalid"
            elif field == "observed_at":
                payload["collectors"]["services"][field] = "invalid"
            else:
                payload["log_windows"]["5m"][field] = "invalid"
            with self.subTest(field=field), self.assertRaises(ValueError):
                DiagnosticsSnapshot.from_dict(payload)

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

    def test_snapshot_v5_roundtrips_without_shell_parsing(self) -> None:
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
            collectors=ok_collectors(),
            log_windows=windows,
            services={"sing-box": "active"},
            drift="none",
            storage={"root_filesystem": {"filesystem": "ext4", "state": "clean", "verdict": "verified"}},
            verdict="verified",
        )

        restored = DiagnosticsSnapshot.from_json(snapshot.to_json())

        self.assertEqual(restored.schema_version, 6)
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

    def test_generic_parser_rejects_non_native_schema(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported diagnostics snapshot schema"):
            DiagnosticsSnapshot.from_json('{"schema_version":2}')

    def test_agent_parser_rejects_non_native_schema(self) -> None:
        payload = DiagnosticsSnapshot().to_dict()
        payload["schema_version"] = 2
        with self.assertRaisesRegex(ValueError, "unsupported diagnostics snapshot schema"):
            DiagnosticsSnapshot.from_agent(payload)

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
            capabilities=("local-egress", "public-front", "router"),
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
            ("single-ru", "single", "gateway", "ru", ("local-egress", "public-front", "router")),
            ("single-foreign", "single", "gateway", "foreign", ("local-egress", "public-front", "router")),
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
