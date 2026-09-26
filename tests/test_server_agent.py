from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from vpn_installer import interserver_transport, journal_evidence, server_agent, server_lifecycle, server_runtime, server_transport
from vpn_installer.diagnostics import DiagnosticsSnapshot
from vpn_installer.log_classifier import classify_line
from vpn_installer.render import server_agent_artifacts


from tests.server_agent_fixtures import AgentFixtures
from tests.test_journal_evidence import front_evidence


def front_snapshot(result, *, source=None, active=True, cutoff=1000, coverage_changes=None, failed_path=False, failed_front=False):
    client_source = source or "203.0.113.20"
    flow = f"{client_source}:50123"
    front = {"listening": True, "clients": {client_source: {"connections": 1}} if active else {},
             "flows": {flow: {"source": client_source, "phase": "active", "quality": "observed"}} if active else {}}
    coverage = {"since_epoch": 0, "discarded_at": [], "error": "", "query_since_epoch": 0,
                "query_until_epoch": cutoff, **(coverage_changes or {})}
    with (
        patch.object(server_runtime, "run", return_value=result),
        patch.object(server_runtime, "parse_env", return_value={}),
        patch.object(server_runtime, "read_json", return_value={}),
        patch.object(server_agent, "installed_runtime_contract", return_value={"capabilities": [server_runtime.CAP_PUBLIC_FRONT]}),
        patch.object(server_agent, "tcp_front_snapshot", return_value=front),
        patch.object(server_agent, "service_state", return_value="inactive" if failed_front else "active"),
        patch.object(server_agent, "udp_443_policy", return_value="routed"),
        patch.object(server_agent, "public_hy2_snapshot", return_value={}),
        patch.object(server_agent, "run_probes", return_value={"ok": not failed_path, "requirements": {}}),
        patch.object(server_agent.time, "time", return_value=cutoff),
        patch.object(journal_evidence, "journal_coverage", return_value=coverage),
    ):
        return server_agent.front_client_snapshot(source, 5) if source else server_agent.public_front_snapshot(5, live_probes=True)


class FrontJournalTests(unittest.TestCase):
    def test_query_failures_and_partial_records_propagate_to_front_and_client(self) -> None:
        message = "from 203.0.113.20:50123 accepted tcp:example.org:443"
        record = json.dumps({"__REALTIME_TIMESTAMP": "900000000", "MESSAGE": message, "_SYSTEMD_UNIT": "vpn-stack-xray.service"})
        for result in (subprocess.CompletedProcess([], 2, "", "denied"),
                       subprocess.CompletedProcess([], 2, record, "partial"),
                       subprocess.CompletedProcess([], 0, record, "corrupt"),
                       subprocess.CompletedProcess([], 0, record + "\nbroken", "")):
            for source in (None, "203.0.113.20"):
                for active in (False, True):
                    with self.subTest(result=result, source=source, active=active):
                        snapshot = front_snapshot(result, source=source, active=active)
                        self.assertEqual(snapshot["verdict"], "inconclusive")
                        self.assertTrue(all(count is None for count in snapshot["events"].values()))
                        self.assertEqual(snapshot["observed_events"]["accepted"], int(bool(result.stdout)))
                        self.assertTrue(journal_evidence.journal_snapshot_error(snapshot["journal_evidence"], window="front"))
                        if source and active and result.stdout:
                            self.assertEqual(snapshot["flow_events"]["203.0.113.20:50123"], {"example.org:443": 1})
                            self.assertEqual(snapshot["client_transport"]["status"], "inconclusive")

    def test_no_matches_requires_complete_retention_and_preserves_independent_failure(self) -> None:
        empty = subprocess.CompletedProcess([], 1, "", "")
        self.assertEqual(front_snapshot(empty)["verdict"], "verified")
        self.assertEqual(front_snapshot(empty, source="203.0.113.20", active=False)["verdict"], "not_seen_on_server")
        for changes in ({"since_epoch": 800}, {"discarded_at": [900]}, {"error": "header failed"}):
            for source in (None, "203.0.113.20"):
                with self.subTest(changes=changes, source=source):
                    snapshot = front_snapshot(empty, source=source, coverage_changes=changes)
                    self.assertEqual(snapshot["verdict"], "inconclusive")
                    self.assertIsNone(snapshot["events"]["accepted"])
                    self.assertEqual(snapshot["observed_events"]["accepted"], 0)
        failed = front_snapshot(empty, coverage_changes={"error": "header failed"}, failed_path=True)
        self.assertEqual(failed["verdict"], "failed")
        self.assertEqual(failed["verdicts"]["server_path"], "failed")
        for result in (empty, subprocess.CompletedProcess([], 2, "", "denied")):
            failed = front_snapshot(result, source="203.0.113.20", failed_front=True)
            self.assertEqual(failed["verdict"], "failed")


class ServerAgentTests(AgentFixtures, unittest.TestCase):
    def setUp(self) -> None:
        coverage = patch.object(journal_evidence, "journal_coverage", return_value={"since_epoch": 0, "discarded_at": [], "error": ""})
        coverage.start()
        self.addCleanup(coverage.stop)

    def test_truncated_history_is_unavailable_even_when_all_buckets_are_zero(self) -> None:
        facts = self.diagnostics_facts()
        facts["logs"]["fresh"]["coverage_error"] = "requested start precedes retained journal sequence"
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            payload = server_agent.diagnostics_snapshot(live_probes=True)
        snapshot = DiagnosticsSnapshot.from_agent(payload)
        window = snapshot.log_windows["since_release"]
        self.assertEqual(window.collector.status, "error")
        self.assertIsNone(window.counts)
        partial = snapshot.storage["journal_coverage"]["partial_windows"]["since_release"]
        self.assertTrue(all(value == 0 for value in partial["counts"].values()))

    def test_unavailable_windows_preserve_raw_observations_and_final_error(self) -> None:
        for failure in ("coverage", "observed_at", "until", "invalid-since", "old-release", "collector-error"):
            with self.subTest(failure=failure):
                facts = self.diagnostics_facts()
                name = "since_release" if failure in {"old-release", "collector-error"} else "5m"
                raw = facts["logs"]["fresh"] if name == "since_release" else facts["logs"]["windows_minutes"]["5"]
                raw.update(server_agent.summarize_lines([
                    "ERROR dns: exchange failed for example.com. IN A: context deadline exceeded",
                ]))
                raw["since"] = facts["release"]["installed_at"]
                if failure == "old-release":
                    raw["since"] = "5 minutes ago"
                elif failure == "collector-error":
                    facts["logs"]["collector_error"] = "partial journal query failed"
                    raw["coverage_error"] = "retention is also incomplete"
                elif failure == "invalid-since":
                    raw["since"] = facts["generated_at"]
                else:
                    del raw[failure]
                original = dict(raw)
                with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
                    snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(live_probes=True))
                window = snapshot.log_windows[name]
                self.assertEqual(window.collector.status, "error")
                self.assertIsNone(window.counts)
                partial = snapshot.storage["journal_coverage"]["partial_windows"][name]
                self.assertEqual(partial, {**original, "error": window.collector.message})
                self.assertEqual(partial["counts"]["dns_timeout"], 1)
                self.assertEqual(raw, original)

    def test_skipped_windows_do_not_publish_partial_observations(self) -> None:
        facts = self.diagnostics_facts()
        facts["logs"]["windows_minutes"]["1440"]["coverage_error"] = "retention is incomplete"
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(full_logs=False))
        self.assertEqual(snapshot.log_windows["24h"].collector.status, "skipped")
        self.assertNotIn("24h", snapshot.storage["journal_coverage"]["partial_windows"])

    def test_agent_main_dispatches_every_managed_command(self) -> None:
        payload = {"state": "healthy"}
        targets = (
            (server_agent, 'diagnostics_snapshot'),
            (server_agent, 'run_confirmed_probes'),
            (server_agent, 'front_client_snapshot'),
            (server_agent, 'public_front_snapshot'),
            (server_agent, 'private_reject_correlations'),
            (server_lifecycle, 'health'),
            (server_lifecycle, 'health_log_summary'),
            (server_transport, 'reconcile_interserver_transport'),
            (server_transport, 'watch_interserver_transport'),
            (server_transport, 'select_transport'),
            (server_lifecycle, 'apply_network_profile'),
            (server_agent, 'prepare_memory_reserve'),
            (server_agent, 'exec_router'),
            (server_agent, 'storage_maintenance'),
            (server_agent, 'routes_command'),
            (server_agent, 'assets_snapshot'),
        )
        commands = (
            ["snapshot", "--compact"],
            ["probe", "--profile", "acceptance"],
            ["client", "--source", "203.0.113.5", "--since", "10"],
            ["front", "--since", "10", "--live-probes"],
            [
                "private-reject-correlate",
                "--since",
                "2026-08-30T00:00:00Z",
                "--inbound",
                "router-in",
                "--target",
                "10.0.0.1:80",
            ],
            ["health"],
            ["transport-reconcile"],
            ["transport-watch"],
            ["transport-select", "--tag", "interserver-underlay-hy2"],
            ["network-apply"],
            ["memory-prepare"],
            ["exec-router", "/bin/true"],
            ["storage-maintain", "--deep"],
            ["routes", "list"],
            ["assets"],
        )
        with ExitStack() as stack:
            mocks = {
                name: stack.enter_context(patch.object(module, name, return_value=payload))
                for module, name in targets
            }
            stack.enter_context(patch.object(server_runtime, "parse_env", return_value={"WG_INTERFACE": "wg0"}))
            stack.enter_context(
                patch.object(
                    server_runtime,
                    "read_json",
                    return_value={"experimental": {"clash_api": {"external_controller": "127.0.0.1:19090"}}},
                )
            )
            stack.enter_context(patch.object(server_agent, "runtime_contract", return_value={}))
            stack.enter_context(patch.object(server_agent, "installed_runtime_contract", return_value={}))
            stack.enter_context(patch.object(server_runtime, "contract_has", return_value=True))
            stack.enter_context(patch("builtins.print"))

            for command in commands:
                with self.subTest(command=command):
                    self.assertEqual(server_agent.main(command), 0)

        for name, mocked in mocks.items():
            with self.subTest(dispatched=name):
                mocked.assert_called()

    def test_agent_main_health_returns_failure_status(self) -> None:
        with patch.object(server_lifecycle, "health", return_value={"state": "failed"}), patch.object(
            server_lifecycle, "health_log_summary", return_value={"state": "failed"}
        ), patch("builtins.print"):
            self.assertEqual(server_agent.main(["health"]), 1)

    def test_installed_at_uses_only_canonical_hyphenated_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "installed-at").write_text("2026-08-16T12:00:00Z\n", encoding="utf-8")
            (root / "installed_at").write_text("ignored\n", encoding="utf-8")
            with patch.object(server_runtime, "ROOT", root):
                self.assertEqual(server_agent.installed_at_value(), "2026-08-16T12:00:00Z")
                (root / "installed-at").unlink()
                self.assertEqual(server_agent.installed_at_value(), "")

    def test_runtime_contract_is_fail_closed_and_accepts_native_single_gateway(self) -> None:
        with patch.object(server_agent, "load_transport", side_effect=AssertionError("single imported interserver control")):
            contract = server_agent.runtime_contract(self.single_manifest())
            server_agent.build_parser()

        self.assertEqual(contract["topology"], "single")
        self.assertEqual(contract["node_id"], "gateway")
        self.assertNotIn("interserver-client", contract["capabilities"])
        self.assertEqual(contract["capabilities"], frozenset({"local-egress", "public-front", "router"}))
        with self.assertRaisesRegex(RuntimeError, "unsupported render manifest schema"):
            server_agent.runtime_contract({"schema_version": 99})

    def test_runtime_contract_single_excludes_web_admin(self) -> None:
        contract = server_agent.runtime_contract(self.single_manifest())

        self.assertNotIn("web-admin", contract["capabilities"])
        self.assertNotIn("admin", contract["required_services"])

    def test_runtime_contract_rejects_capability_and_install_plan_drift(self) -> None:
        manifest = self.single_manifest()
        manifest["install_plan"] = {**manifest["install_plan"], "capabilities": ["local-egress"]}  # type: ignore[index]

        with self.assertRaisesRegex(RuntimeError, "install plan capabilities conflict"):
            server_agent.runtime_contract(manifest)

    def test_agent_emits_native_diagnostics_v6_end_to_end(self) -> None:
        facts = self.diagnostics_facts()
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            payload = server_agent.diagnostics_snapshot(live_probes=True, full_logs=True, include_maintenance=True)

        snapshot = DiagnosticsSnapshot.from_agent(payload)
        self.assertEqual(snapshot.schema_version, 6)
        self.assertEqual(snapshot.collector_status, "ok")
        self.assertEqual(snapshot.host["login_user"], "root")
        self.assertEqual(snapshot.log_windows["since_release"].counts["dns_timeout"], 0)
        self.assertEqual(
            {name: state.observed_at for name, state in snapshot.collectors.items()},
            facts["collector_observed_at"],
        )
        self.assertNotIn("collector_observed_at", payload)

    def test_snapshot_envelope_does_not_refresh_collectors_or_log_windows(self) -> None:
        facts = self.diagnostics_facts()
        facts["generated_at"] = "2026-08-06T18:10:00+00:00"
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(live_probes=True))
        for name, state in snapshot.collectors.items():
            self.assertEqual(state.observed_at, facts["collector_observed_at"][name])
        for window in snapshot.log_windows.values():
            self.assertEqual(window.collector.observed_at, "2026-08-06T17:59:30+00:00")
            self.assertEqual(window.until, "2026-08-06T17:59:30+00:00")
        issues = snapshot.freshness_issues(now=datetime.fromisoformat(facts["generated_at"]))
        self.assertEqual(len(issues), len(server_agent.COLLECTOR_NAMES) + 2 * len(snapshot.log_windows))
        self.assertTrue(all("is stale" in issue for issue in issues))

    def test_snapshot_preserves_future_collector_time_for_skew_validation(self) -> None:
        facts = self.diagnostics_facts()
        now = datetime.fromisoformat(facts["generated_at"])
        future = (now + timedelta(seconds=31)).isoformat()
        facts["collector_observed_at"]["front"] = future
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(live_probes=True))
        self.assertEqual(snapshot.collectors["front"].observed_at, future)
        issues = snapshot.freshness_issues(now=now)
        self.assertEqual(len(issues), 1)
        self.assertIn("collector front observed_at is from the future", issues[0])

    def test_missing_collector_timestamp_is_not_replaced_by_envelope(self) -> None:
        for name in server_agent.COLLECTOR_NAMES:
            with self.subTest(collector=name):
                facts = self.diagnostics_facts()
                del facts["collector_observed_at"][name]
                with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
                    snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(live_probes=True))
                self.assertEqual(snapshot.collectors[name].status, "error")
                self.assertIsNone(snapshot.collectors[name].observed_at)

    def test_missing_log_timestamps_are_not_replaced_by_envelope(self) -> None:
        for key in ("observed_at", "until"):
            with self.subTest(key=key):
                facts = self.diagnostics_facts()
                del facts["logs"]["windows_minutes"]["5"][key]
                with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
                    snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot())
                self.assertEqual(snapshot.log_windows["5m"].collector.status, "error")
                self.assertIsNone(snapshot.log_windows["5m"].counts)

    def test_kernel_collector_errors_make_verified_snapshot_inconclusive(self) -> None:
        for name, window in (("storage", "5m"), ("network", "5")):
            with self.subTest(collector=name):
                facts = self.diagnostics_facts()
                evidence = (
                    facts["storage"]["runtime_events"]["oom_kills"]
                    if name == "storage"
                    else facts["network"]["conntrack"]["journal_evidence"]
                )
                evidence.update(
                    counts={window: None}, observed_counts={window: 2},
                    collector_error="kernel journal unavailable",
                )
                with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
                    snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(live_probes=True))
                self.assertEqual(snapshot.verdict, "inconclusive")
                self.assertEqual(snapshot.collector_status, "error")
                self.assertEqual(snapshot.collectors[name].status, "error")
                self.assertEqual(snapshot.collectors[name].message, "kernel journal unavailable")
                self.assertIsNone(snapshot.collectors[name].observed_at)
                self.assertEqual(snapshot.collectors["logs"].status, "ok")
                other = "network" if name == "storage" else "storage"
                self.assertEqual(snapshot.collectors[other].status, "ok")
                self.assertIn(f"collector {name}: kernel journal unavailable", snapshot.reasons)
                retained = (
                    snapshot.storage["runtime_events"]["oom_kills"]
                    if name == "storage"
                    else snapshot.network["conntrack"]["journal_evidence"]
                )
                self.assertIsNone(retained["counts"][window])
                self.assertEqual(retained["observed_counts"][window], 2)

    def test_missing_kernel_evidence_makes_verified_snapshot_inconclusive(self) -> None:
        for name, label in (("storage", "OOM"), ("network", "conntrack")):
            for missing in ("evidence", "counts", "window"):
                with self.subTest(collector=name, missing=missing):
                    facts = self.diagnostics_facts()
                    container, key = (
                        (facts["storage"]["runtime_events"], "oom_kills")
                        if name == "storage"
                        else (facts["network"]["conntrack"], "journal_evidence")
                    )
                    if missing == "evidence":
                        del container[key]
                    elif missing == "counts":
                        del container[key]["counts"]
                    else:
                        container[key]["counts"] = {}
                    with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
                        snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(live_probes=True))
                    message = f"kernel {label} evidence is missing"
                    self.assertEqual(snapshot.verdict, "inconclusive")
                    self.assertEqual(snapshot.collector_status, "error")
                    self.assertEqual(snapshot.collectors[name].status, "error")
                    self.assertEqual(snapshot.collectors[name].message, message)
                    self.assertIsNone(snapshot.collectors[name].observed_at)
                    self.assertEqual(snapshot.collectors["logs"].status, "ok")
                    other = "network" if name == "storage" else "storage"
                    self.assertEqual(snapshot.collectors[other].status, "ok")
                    self.assertIn(f"collector {name}: {message}", snapshot.reasons)

    def test_compact_snapshot_marks_intentional_omissions_as_skipped(self) -> None:
        generated_at = "2026-08-06T18:00:00+00:00"
        empty_logs = server_agent.summarize_lines([])
        facts = {
            **self.gateway_contract(),
            "generated_at": generated_at,
            "collector_observed_at": dict.fromkeys(server_agent.COLLECTOR_NAMES, generated_at),
            "deployment": "demo",
            "host": {},
            "release": {"installed_at": generated_at},
            "services": {name: "active" for name in ("wireguard", "nftables", "sing-box", "resolver", "xray")},
            "artifacts": {"manifest": {"schema_version": 5}, "drift": "none", "files": {}},
            "wireguard": {"interface": "wg0", "state": "up"},
            "probes": {"profile": "none", "ok": None},
            "storage": self.diagnostics_facts()["storage"],
            "network": self.diagnostics_facts()["network"],
            "front": {"listening": True},
            "transport": {"interserver": {"configured": True}},
            "maintenance": {},
            "redundancy": {},
            "logs": {
                "collector_error": "",
                "windows_minutes": {"5": {**empty_logs, "observed_at": generated_at, "until": generated_at}},
                "fresh": {"since": generated_at, **empty_logs, "observed_at": generated_at, "until": generated_at},
            },
            "verdicts": {"overall": "inconclusive", "reasons": []},
        }
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            snapshot = DiagnosticsSnapshot.from_agent(
                server_agent.diagnostics_snapshot(
                    live_probes=False,
                    full_logs=False,
                    include_maintenance=False,
                )
            )

        self.assertEqual(snapshot.collector_status, "skipped")
        self.assertEqual(snapshot.collectors["route_probes"].status, "skipped")
        self.assertEqual(snapshot.collectors["maintenance"].status, "skipped")
        self.assertEqual(snapshot.log_windows["30m"].collector.status, "skipped")
        self.assertEqual(snapshot.log_windows["24h"].collector.status, "skipped")

    def test_journal_failure_is_not_reported_as_zero_events(self) -> None:
        failure = subprocess.CompletedProcess(["journalctl"], 1, "", "journal unavailable")
        with patch.object(server_runtime, "run", return_value=failure):
            windows, fresh, error = server_agent.summarize_problem_windows(full_logs=True, fresh_since="5 minutes ago")
        self.assertEqual(error, "journal unavailable")
        self.assertEqual(windows["5"]["counts"]["dns_timeout"], 0)
        self.assertEqual(fresh["counts"]["dns_timeout"], 0)

        facts = {
            **self.exit_contract(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "release": {},
            "logs": {"collector_error": error, "windows_minutes": windows, "fresh": fresh},
        }
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot())
        self.assertEqual(snapshot.collectors["logs"].status, "error")
        self.assertTrue(all(window.counts is None for window in snapshot.log_windows.values()))

    def test_journal_no_matches_is_a_collected_zero_window(self) -> None:
        no_matches = subprocess.CompletedProcess(["journalctl"], 1, "", "")
        with patch.object(server_runtime, "run", return_value=no_matches):
            windows, fresh, error = server_agent.summarize_problem_windows(
                full_logs=True,
                fresh_since="5 minutes ago",
            )

        self.assertEqual(error, "")
        self.assertTrue(all(count == 0 for count in windows["5"]["counts"].values()))
        self.assertTrue(all(count == 0 for count in fresh["counts"].values()))

    def test_log_collection_covers_release_within_journal_retention(self) -> None:
        now = 1_786_040_000.0
        installed_at = datetime.fromtimestamp(now - 7 * 24 * 60 * 60, timezone.utc).isoformat()
        with patch.object(server_agent.time, "time", return_value=now), patch.object(
            server_agent, "journal_problem_events", return_value=([], "")
        ) as journal:
            server_agent.summarize_problem_windows(full_logs=True, fresh_since=installed_at)
        journal.assert_called_once_with(7 * 24 * 60, until=now)

    def test_log_windows_preserve_acquisition_time_and_exclude_later_events(self) -> None:
        now = 1_786_040_000.0
        line = "ERROR dns: exchange failed for example.com. IN A: context deadline exceeded"
        with patch.object(server_agent.time, "time", return_value=now), patch.object(
            server_agent, "journal_problem_events", return_value=([(now - 1, line), (now + 1, line)], "")
        ) as journal:
            windows, fresh, error = server_agent.summarize_problem_windows(full_logs=True, fresh_since="5 minutes ago")
        self.assertEqual(error, "")
        journal.assert_called_once_with(1440, until=now)
        expected = datetime.fromtimestamp(now, timezone.utc).isoformat()
        for window in [*windows.values(), fresh]:
            self.assertEqual(window["observed_at"], expected)
            self.assertEqual(window["until"], expected)
            self.assertEqual(window["counts"]["dns_timeout"], 1)
        self.assertEqual(windows["5"]["since"], datetime.fromtimestamp(now - 300, timezone.utc).isoformat())

    def test_log_windows_share_context_without_extending_journal_query(self) -> None:
        now = 1_786_040_000.0
        inbound = "[unit=sing-box.service] INFO [42 0ms] inbound/mixed[router-in]: inbound connection to media.example:443"
        error = "[unit=sing-box.service] ERROR [42 10s] open connection to 203.0.113.5:443 using outbound/direct[to-foreign]: dial tcp 203.0.113.5:443: i/o timeout"
        old_error = "[unit=sing-box.service] ERROR [43 1s] dns: exchange failed for old.example. IN A: context deadline exceeded"
        events = [(now - 305, inbound), (now - 295, error), (now - 310, old_error)]
        with patch.object(server_agent.time, "time", return_value=now), patch.object(
            server_agent, "journal_problem_events", return_value=(events, "")
        ) as journal:
            windows, fresh, collector_error = server_agent.summarize_problem_windows(
                full_logs=True, fresh_since=datetime.fromtimestamp(now - 300, timezone.utc).isoformat(),
            )
        journal.assert_called_once_with(1440, until=now)
        self.assertEqual(collector_error, "")
        for window in [*windows.values(), fresh]:
            self.assertEqual(window["counts"]["domain_to_foreign_timeout"], 1)
            self.assertEqual(window["counts"]["ipv4_literal_timeout"], 0)
            self.assertEqual(window["top_destinations"]["domain_to_foreign_timeout"], {"media.example:443": 1})
        self.assertEqual(windows["5"]["counts"]["dns_timeout"], 0)
        self.assertEqual(fresh["counts"]["dns_timeout"], 0)
        self.assertEqual(windows["30"]["counts"]["dns_timeout"], 1)

    def test_log_windows_without_request_context_do_not_claim_literal_target(self) -> None:
        now = 1_786_040_000.0
        line = "[unit=sing-box.service] ERROR [42 10s] open connection to 203.0.113.5:443 using outbound/direct[to-foreign]: dial tcp 203.0.113.5:443: i/o timeout"
        with patch.object(server_agent.time, "time", return_value=now), patch.object(
            server_agent, "journal_problem_events", return_value=([(now - 1, line)], "")
        ) as journal:
            windows, fresh, error = server_agent.summarize_problem_windows(full_logs=False, fresh_since="5 minutes ago")
        journal.assert_called_once_with(5, until=now)
        self.assertEqual(error, "")
        for window in (windows["5"], fresh):
            self.assertEqual(window["counts"]["unclassified_error"], 1)
            self.assertEqual(window["counts"]["ipv4_literal_timeout"], 0)
            self.assertEqual(window["counts"]["domain_to_foreign_timeout"], 0)
            self.assertEqual(window["samples"]["unclassified_error"], line)

    def test_future_release_window_is_unavailable_not_a_collected_zero(self) -> None:
        facts = self.diagnostics_facts()
        now = datetime.fromisoformat(facts["generated_at"])
        future = (now + timedelta(days=1)).isoformat()
        with patch.object(server_agent.time, "time", return_value=now.timestamp()), patch.object(
            server_agent, "journal_problem_events", return_value=([], "")
        ):
            windows, fresh, error = server_agent.summarize_problem_windows(full_logs=True, fresh_since=future)
        facts["release"]["installed_at"] = future
        facts["logs"] = {"windows_minutes": windows, "fresh": fresh, "collector_error": error}
        with patch.object(server_agent, "collect_runtime_facts", return_value=facts):
            snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(live_probes=True))
        window = snapshot.log_windows["since_release"]
        self.assertEqual(window.collector.status, "error")
        self.assertIsNone(window.counts)
        self.assertEqual(window.collector.message, "requested or collected journal interval is invalid")
        self.assertEqual(snapshot.log_windows["5m"].collector.status, "ok")

    def test_future_journal_context_cannot_supply_a_request_identity(self) -> None:
        now = 1_786_040_000.0
        context = "[unit=sing-box.service] INFO [42 0ms] inbound/mixed[router-in]: inbound connection to media.example:443"
        line = "[unit=sing-box.service] ERROR [42 10s] open connection to 203.0.113.5:443 using outbound/direct[to-foreign]: dial tcp 203.0.113.5:443: i/o timeout"
        with patch.object(server_agent.time, "time", return_value=now), patch.object(
            server_agent, "journal_problem_events", return_value=([(now + 1, context), (now - 1, line)], "")
        ):
            windows, _fresh, _error = server_agent.summarize_problem_windows(full_logs=True, fresh_since="5 minutes ago")
        for window in windows.values():
            self.assertEqual(window["counts"]["unclassified_error"], 1)
            self.assertEqual(window["counts"]["domain_to_foreign_timeout"], 0)

    def test_failed_journal_context_query_keeps_request_identity_unknown(self) -> None:
        now = 1_786_040_000.0
        message = "ERROR [42 10s] open connection to 203.0.113.5:443 using outbound/direct[to-foreign]: dial tcp 203.0.113.5:443: i/o timeout"
        record = {"__REALTIME_TIMESTAMP": str(int((now - 1) * 1_000_000)), "_SYSTEMD_UNIT": "sing-box.service", "MESSAGE": message}
        results = [subprocess.CompletedProcess([], 0, json.dumps(record), ""), subprocess.CompletedProcess([], 2, "", "context unavailable")]
        with patch.object(server_agent.time, "time", return_value=now), patch.object(server_runtime, "run", side_effect=results) as command:
            windows, _fresh, error = server_agent.summarize_problem_windows(full_logs=False, fresh_since="5 minutes ago")
        self.assertEqual(error, "")
        self.assertEqual(command.call_count, 2)
        for call in command.call_args_list:
            args = call.args[0]
            self.assertEqual(args[args.index("--since") + 1], f"@{now - 300:.6f}")
            self.assertEqual(args[args.index("--until") + 1], f"@{now:.6f}")
        self.assertEqual(windows["5"]["counts"]["unclassified_error"], 1)
        self.assertEqual(windows["5"]["counts"]["ipv4_literal_timeout"], 0)

    def test_journal_context_query_keeps_its_event_id_bound(self) -> None:
        limit = server_agent.LOG_CONTEXT_MAX_EVENT_IDS
        events = [(0, f"[unit=sing-box.service] ERROR [{number} 10s] connection: i/o timeout") for number in range(limit + 1)]
        with patch.object(server_runtime, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as command:
            self.assertEqual(server_agent._journal_event_context(5, events, until=1000), [])
        args = command.call_args.args[0]
        expected_ids = "|".join(str(number) for number in range(1, limit + 1))
        self.assertEqual(args[-1], rf"--grep=\[(?:\x1B\[[0-9;]*m)*(?:{expected_ids})\b")
        self.assertEqual(args[args.index("--since") + 1], "@700.000000")
        self.assertEqual(args[args.index("--until") + 1], "@1000.000000")

    def test_cached_future_observations_are_not_fresh(self) -> None:
        now = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)
        for age in (-86400, -0.001, 0, 60, 86400):
            observed = (now - timedelta(seconds=age)).isoformat()
            state = {"state": "healthy", "updated_at": observed}
            interval = {"observed_at": observed, "degraded_sources": []}
            with self.subTest(age=age), patch.object(server_runtime, "datetime", wraps=datetime) as clock, patch.object(
                server_runtime, "read_json", return_value=state
            ):
                clock.now.return_value = now
                transport = server_transport.transport_state_snapshot()
                recent = server_agent.recent_observation(interval, max_age_seconds=300)
            self.assertEqual(transport["fresh"], 0 <= age <= interserver_transport.TRANSPORT_PROBE_INTERVAL_SECONDS * 6)
            self.assertEqual(transport["updated_at"], observed)
            self.assertEqual(transport["age_seconds"], round(age, 1))
            self.assertEqual(recent, interval if 0 <= age <= 300 else {})
            self.assertEqual(server_runtime.iso_age_seconds(observed, now=now), max(0, age))

    def test_future_transport_cache_cannot_produce_verified_snapshot(self) -> None:
        now = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)
        installed = (now - timedelta(minutes=1)).isoformat()
        state = {"state": "healthy", "updated_at": (now + timedelta(days=1)).isoformat()}
        with patch.object(server_runtime, "datetime", wraps=datetime) as clock, patch.object(server_runtime, "read_json", return_value=state):
            clock.now.return_value = now
            adaptive = server_transport.transport_state_snapshot()
        with patch.object(server_agent.time, "time", return_value=now.timestamp()), patch.object(server_agent, "journal_problem_events", return_value=([], "")):
            logs = server_agent.summarize_problem_windows(full_logs=True, fresh_since=installed)
        fixtures = {
            (server_runtime, 'utc_now'): now.isoformat(), (server_runtime, 'parse_env'): {}, (server_agent, 'runtime_contract'): self.gateway_contract(),
            (server_agent, 'manifest_snapshot'): {"manifest": {"release_id": "fixture"}, "drift": "none"},
            (server_runtime, 'default_interface'): "eth0", (server_agent, 'service_state'): "active", (server_agent, 'fresh_log_since'): (installed, 1),
            (server_agent, 'installed_at_value'): installed, (server_agent, 'maintenance_snapshot'): {"upgradable": 0},
            (server_agent, 'summarize_problem_windows'): logs, (server_agent, 'tcp_front_snapshot'): {"listening": True},
            (server_agent, 'run_confirmed_probes'): {"profile": "light", "ok": True, "requirements": {}},
            (server_transport, 'interserver_transport_snapshot'): {"configured": True, "selection": {"available": True}, "adaptive_state": adaptive},
            (server_agent, 'udp_443_policy'): "routed", (server_agent, 'public_hy2_snapshot'): {"configured": True, "listening": True, "firewall": True},
            (server_agent, 'tcp_adaptation_snapshot'): {"qdisc": "fq"}, (server_agent, 'resolver_snapshot'): {"managed_config": True},
            (server_agent, 'root_filesystem_snapshot'): {"verdict": "verified"},
            (server_agent, 'storage_snapshot'): {**self.diagnostics_facts()["storage"], "memory": {"reserve_ready": True, "router": {"go_memory_limit_active": True}}},
            (server_agent, 'conntrack_snapshot'): self.diagnostics_facts()["network"]["conntrack"], (server_agent, 'xray_conntrack_bypass_snapshot'): {"active": True},
            (server_agent, 'network_profile_mismatches'): [], (server_runtime, 'wireguard_policy_snapshot'): {"managed": True, "ok": True},
            (server_runtime, 'read_json'): {}, (server_agent, 'host_snapshot'): {}, (server_agent, 'wireguard_snapshot'): {"interface": "wg0", "state": "up"},
            (server_agent, 'interface_counters'): {}, (server_agent, 'protocol_counters_snapshot'): {}, (server_agent, 'softnet_counters_snapshot'): {},
        }
        with ExitStack() as stack:
            for (module, name), value in fixtures.items():
                stack.enter_context(patch.object(module, name, return_value=value))
            stack.enter_context(patch.object(server_runtime, "run", side_effect=AssertionError("unexpected OS command")))
            snapshot = DiagnosticsSnapshot.from_agent(server_agent.diagnostics_snapshot(live_probes=True))
        self.assertEqual(snapshot.verdict, "degraded")
        self.assertEqual(snapshot.reasons, ["interserver_adaptation=stale"])
        self.assertFalse(snapshot.transport["interserver"]["adaptive_state"]["fresh"])
        self.assertEqual(snapshot.transport["interserver"]["adaptive_state"]["updated_at"], state["updated_at"])
        self.assertEqual(snapshot.schema_version, 6)

    def test_journal_problem_and_context_queries_use_the_same_fixed_window(self) -> None:
        now = 1_786_040_000.0
        record = {
            "__REALTIME_TIMESTAMP": str(int(now * 1_000_000)), "_SYSTEMD_UNIT": "sing-box.service",
            "MESSAGE": "ERROR [42 10s] connection: i/o timeout",
        }
        result = subprocess.CompletedProcess(["journalctl"], 0, json.dumps(record), "")
        with patch.object(server_runtime, "run", return_value=result) as command:
            server_agent.journal_problem_events(5, until=now)
        self.assertEqual(command.call_count, 2)
        for call in command.call_args_list:
            args = call.args[0]
            self.assertEqual(args[args.index("--since") + 1], f"@{now - 300:.6f}")
            self.assertEqual(args[args.index("--until") + 1], f"@{now:.6f}")

    def test_journal_json_preserves_unit_identity(self) -> None:
        records = [
            {"__REALTIME_TIMESTAMP": "1786040000000000", "_SYSTEMD_UNIT": "sing-box.service", "MESSAGE": "ERROR [42 1s] dns: exchange failed for a.example. IN A: context deadline exceeded"},
            {"__REALTIME_TIMESTAMP": "1786040001000000", "_SYSTEMD_UNIT": "vpn-stack-xray.service", "MESSAGE": "ERROR [42 1s] connection reset"},
        ]
        completed = subprocess.CompletedProcess(["journalctl"], 0, "\n".join(json.dumps(item) for item in records), "")
        with patch.object(server_runtime, "run", return_value=completed):
            events, error = server_agent.journal_problem_events(5)
        self.assertEqual(error, "")
        self.assertIn("[unit=sing-box.service]", events[0][1])
        summary = server_agent.summarize_lines(message for _timestamp, message in events)
        self.assertEqual(summary["counts"]["dns_timeout"], 1)
        self.assertEqual(summary["counts"]["client_reset_eof"], 1)

    def test_journal_json_decodes_binary_ansi_messages(self) -> None:
        message = (
            "+0000 2026-08-07 04:13:07 \x1b[36mERROR\x1b[0m "
            "[\x1b[38;5;51m4252783395\x1b[0m 10s] dns: exchange failed for example.com. IN A: context deadline exceeded"
        )
        record = {
            "__REALTIME_TIMESTAMP": "1786075987103741",
            "_SYSTEMD_UNIT": "sing-box.service",
            "MESSAGE": list(message.encode("utf-8")),
        }
        completed = subprocess.CompletedProcess(["journalctl"], 0, json.dumps(record), "")
        with patch.object(server_runtime, "run", return_value=completed):
            events, error = server_agent.journal_problem_events(5)

        self.assertEqual(error, "")
        self.assertNotIn("\x1b", events[0][1])
        self.assertEqual(server_agent.summarize_lines(line for _timestamp, line in events)["counts"]["dns_timeout"], 1)

    def test_journal_problem_events_adds_matching_inbound_context(self) -> None:
        problem = {
            "__REALTIME_TIMESTAMP": "1786075987103741",
            "_SYSTEMD_UNIT": "sing-box.service",
            "MESSAGE": "ERROR [4252783395 10s] open connection to 185.178.210.193:443 using outbound/direct[direct-ru]: i/o timeout",
        }
        context = {
            "__REALTIME_TIMESTAMP": "1786075977103741",
            "_SYSTEMD_UNIT": "sing-box.service",
            "MESSAGE": "INFO [4252783395 0ms] inbound/mixed[router-in]: inbound connection to service.example.com:443",
        }
        results = [
            subprocess.CompletedProcess(["journalctl"], 0, json.dumps(problem), ""),
            subprocess.CompletedProcess(["journalctl"], 0, json.dumps(context), ""),
        ]
        with patch.object(server_runtime, "run", side_effect=results) as command:
            events, error = server_agent.journal_problem_events(30)

        self.assertEqual(error, "")
        self.assertEqual(len(events), 2)
        self.assertIn("4252783395", command.call_args_list[1].args[0][-1])
        summary = server_agent.summarize_lines(line for _timestamp, line in events)
        self.assertEqual(summary["top_destinations"]["direct_ru_timeout"], {"service.example.com:443": 1})

    def test_classifier_assigns_timeout_to_one_bucket(self) -> None:
        line = "ERROR dns: exchange failed for connectivity.example.com. IN A: context deadline exceeded"
        classified = classify_line(line)
        self.assertIsNotNone(classified)
        self.assertEqual(classified.bucket, "dns_timeout")

    def test_classifier_separates_ipv6_literal_from_domain_timeout(self) -> None:
        line = "ERROR open connection to [2a0a:f280:203:a:5000::100]:443 using outbound/direct[to-foreign]: i/o timeout"
        classified = classify_line(line, requested_destination="[2a0a:f280:203:a:5000::100]:443")
        self.assertIsNotNone(classified)
        self.assertEqual(classified.bucket, "ipv6_literal_timeout")

    def test_private_reject_requires_fast_rejection_for_each_target(self) -> None:
        failed = subprocess.CompletedProcess(["curl"], 7, "", "blocked")
        with (
            patch.object(server_runtime, "run", return_value=failed),
            patch.object(server_agent.time, "monotonic", side_effect=[1.0, 1.01, 2.0, 2.01]),
        ):
            result = server_agent.probe_private_reject("socks5h://127.0.0.1:2080")

        self.assertTrue(result["ok"])
        self.assertEqual([item["target"] for item in result["targets"]], ["http://10.0.0.1:80/", "http://172.19.0.2:853/"])

    def test_private_reject_rejects_a_slow_failure(self) -> None:
        failed = subprocess.CompletedProcess(["curl"], 28, "", "timeout")
        with (
            patch.object(server_runtime, "run", return_value=failed),
            patch.object(server_agent.time, "monotonic", side_effect=[1.0, 3.1, 4.0, 4.01]),
        ):
            result = server_agent.probe_private_reject("socks5h://127.0.0.1:2080")

        self.assertFalse(result["ok"])

    def test_private_reject_correlation_requires_clean_ordered_policy_and_exact_events(self) -> None:
        marker = datetime.now(timezone.utc) - timedelta(seconds=1)
        event_time = datetime.now(timezone.utc)
        records = [
            {
                "__REALTIME_TIMESTAMP": str(int(event_time.timestamp() * 1_000_000)),
                "__CURSOR": "cursor-1",
                "MESSAGE": list(
                    (
                        "+0000 2026-08-07 03:54:45 \x1b[36mINFO\x1b[0m "
                        "[\x1b[38;5;218m3039373591\x1b[0m 0ms] inbound/mixed[router-in]: inbound connection to 10.0.0.1:80"
                    ).encode("utf-8")
                ),
            },
            {
                "__REALTIME_TIMESTAMP": str(int(event_time.timestamp() * 1_000_000)),
                "__CURSOR": "cursor-2",
                "MESSAGE": list(
                    (
                        "+0000 2026-08-07 03:54:46 \x1b[36mINFO\x1b[0m "
                        "[\x1b[38;5;71m3886298263\x1b[0m 0ms] inbound/mixed[router-in]: inbound connection to 172.19.0.2:853"
                    ).encode("utf-8")
                ),
            },
            {
                "__REALTIME_TIMESTAMP": str(int(event_time.timestamp() * 1_000_000)),
                "__CURSOR": "wrong-inbound",
                "MESSAGE": "+0000 2026-08-07 03:54:47 INFO [999999999 0ms] inbound/hysteria2[public-hy2-in]: inbound connection to 10.0.0.1:80",
            },
        ]
        journal = subprocess.CompletedProcess(
            ["journalctl"],
            0,
            "\n".join(json.dumps(record) for record in records),
            "",
        )
        config = {
            "route": {
                "rules": [
                    {"ip_is_private": True, "action": "reject", "method": "default", "no_drop": True},
                    {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"},
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_runtime, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(
                    server_agent,
                    "manifest_snapshot",
                    return_value={"drift": "none", "manifest": self.single_manifest()},
                ),
                patch.object(server_runtime, "run", return_value=journal) as run,
            ):
                result = server_agent.private_reject_correlations(
                    marker.isoformat(),
                    "router-in",
                    ["10.0.0.1:80", "172.19.0.2:853"],
                )

        self.assertEqual(result["verdict"], "verified")
        self.assertTrue(result["policy"]["verified"])
        self.assertEqual([item["event_id"] for item in result["targets"]], ["3039373591", "3886298263"])
        self.assertIn(marker.isoformat(), run.call_args.args[0])

    def test_private_reject_correlation_refuses_dirty_or_unordered_config(self) -> None:
        marker = datetime.now(timezone.utc).isoformat()
        config = {
            "route": {
                "rules": [
                    {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"},
                    {"ip_is_private": True, "action": "reject", "method": "default", "no_drop": True},
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_runtime, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(
                    server_agent,
                    "manifest_snapshot",
                    return_value={"drift": "none", "manifest": self.single_manifest()},
                ),
                patch.object(server_runtime, "run") as run,
            ):
                result = server_agent.private_reject_correlations(marker, "router-in", ["10.0.0.1:80"])

        self.assertEqual(result["verdict"], "failed")
        self.assertFalse(result["policy"]["verified"])
        run.assert_not_called()

    def test_private_reject_correlation_treats_empty_journal_as_inconclusive(self) -> None:
        config = {
            "route": {
                "rules": [
                    {"ip_is_private": True, "action": "reject", "method": "default", "no_drop": True},
                    {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"},
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with (
                patch.object(server_runtime, "SINGBOX_CONFIG_PATH", config_path),
                patch.object(
                    server_agent,
                    "manifest_snapshot",
                    return_value={"drift": "none", "manifest": self.single_manifest()},
                ),
                patch.object(
                    server_runtime,
                    "run",
                    return_value=subprocess.CompletedProcess(["journalctl"], 1, "", ""),
                ),
            ):
                result = server_agent.private_reject_correlations(
                    datetime.now(timezone.utc).isoformat(),
                    "router-in",
                    ["10.0.0.1:80"],
                )

        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("not observed", result["reason"])

    def test_manifest_snapshot_detects_asset_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset = root / "geosite-ru.srs"
            asset.write_bytes(b"good")
            env_path = root / "env"
            env_path.write_text("DEPLOY_NAME=demo\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        **self.single_manifest(),
                        "env_sha256": server_agent.sha256_file(env_path),
                        "assets": {
                            "geosite-ru.srs": {
                                "sha256": server_agent.sha256_file(asset),
                                "install_path": str(asset),
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_runtime, "MANIFEST_PATH", manifest), patch.object(
                server_runtime, "ENV_PATH", env_path
            ), patch.object(server_agent, "release_tree_snapshot", return_value={"state": "ok"}):
                self.assertEqual(server_agent.manifest_snapshot()["drift"], "none")
                asset.write_bytes(b"changed")
                self.assertEqual(server_agent.manifest_snapshot()["drift"], "server-mutated")

    def test_manifest_snapshot_detects_binary_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "sing-box"
            binary.write_bytes(b"known-binary")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        **self.single_manifest(),
                        "binaries": {"sing-box": {"version": "1.13.12", "path": str(binary), "sha256": server_agent.sha256_file(binary)}},
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_runtime, "MANIFEST_PATH", manifest), patch.object(
                server_runtime, "ENV_PATH", root / "env"
            ), patch.object(server_agent, "release_tree_snapshot", return_value={"state": "ok"}):
                self.assertEqual(server_agent.manifest_snapshot()["binaries"]["sing-box"]["state"], "ok")
                binary.write_bytes(b"mutated-binary")
                snapshot = server_agent.manifest_snapshot()
        self.assertEqual(snapshot["drift"], "server-mutated")
        self.assertEqual(snapshot["binaries"]["sing-box"]["state"], "mutated")

    def test_manifest_snapshot_rejects_binary_not_used_by_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "sing-box"
            binary.write_bytes(b"known-binary")
            env = root / "env"
            env.write_text("DEPLOY_NAME=test\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        **self.single_manifest(),
                        "env_sha256": server_agent.sha256_file(env),
                        "binaries": {
                            "sing-box": {
                                "path": str(binary),
                                "sha256": server_agent.sha256_file(binary),
                                "service": "sing-box.service",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_runtime, "MANIFEST_PATH", manifest), patch.object(
                server_runtime, "ENV_PATH", env
            ), patch.object(server_agent, "service_exec_path", return_value="/usr/bin/sing-box"), patch.object(
                server_agent, "release_tree_snapshot", return_value={"state": "ok"}
            ):
                snapshot = server_agent.manifest_snapshot()
        self.assertEqual(snapshot["drift"], "server-mutated")
        self.assertEqual(snapshot["binaries"]["sing-box"]["state"], "wrong-exec")

    def test_manifest_snapshot_accepts_exec_launcher_actual_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "sing-box"
            binary.write_bytes(b"known-binary")
            env = root / "env"
            env.write_text("DEPLOY_NAME=test\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        **self.single_manifest(),
                        "env_sha256": server_agent.sha256_file(env),
                        "binaries": {
                            "sing-box": {
                                "path": str(binary),
                                "sha256": server_agent.sha256_file(binary),
                                "service": "sing-box.service",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(server_runtime, "MANIFEST_PATH", manifest), patch.object(
                server_runtime, "ENV_PATH", env
            ), patch.object(server_agent, "service_exec_path", return_value=str(binary)), patch.object(
                server_agent, "release_tree_snapshot", return_value={"state": "ok"}
            ):
                snapshot = server_agent.manifest_snapshot()
        self.assertEqual(snapshot["drift"], "none")
        self.assertEqual(snapshot["binaries"]["sing-box"]["state"], "ok")

    def test_service_exec_path_reads_the_actual_main_process(self) -> None:
        service = subprocess.CompletedProcess(["systemctl"], 0, "42\n", "")
        with patch.object(server_runtime, "run", return_value=service), patch.object(
            server_agent.os, "readlink", return_value="/opt/sing-box"
        ):
            self.assertEqual(server_agent.service_exec_path("sing-box.service"), "/opt/sing-box")

    def test_release_tree_snapshot_detects_content_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            releases = root / "releases"
            candidate = releases / "candidate"
            candidate.mkdir(parents=True)
            (candidate / "render-manifest.json").write_text(
                json.dumps(self.single_manifest()) + "\n",
                encoding="utf-8",
            )
            (candidate / "agent.py").write_text("print('ok')\n", encoding="utf-8")
            digest = server_agent.release_tree_digest(candidate)
            release = releases / f"0.18.0-test-{digest[:12]}"
            candidate.rename(release)

            clean = server_agent.release_tree_snapshot(release, releases, require_symlink=False)
            cache = release / "__pycache__"
            cache.mkdir()
            (cache / "agent.cpython-312.pyc").write_bytes(b"derived-bytecode")
            cached = server_agent.release_tree_snapshot(release, releases, require_symlink=False)
            (release / "agent.py").write_text("print('mutated')\n", encoding="utf-8")
            mutated = server_agent.release_tree_snapshot(release, releases, require_symlink=False)

        self.assertEqual(clean["state"], "ok")
        self.assertEqual(cached["state"], "ok")
        self.assertEqual(mutated["state"], "mutated")

    def test_manifest_snapshot_rejects_release_tree_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_path = root / "env"
            env_path.write_text("DEPLOY_NAME=demo\n", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({**self.single_manifest(), "env_sha256": server_agent.sha256_file(env_path)}),
                encoding="utf-8",
            )
            with patch.object(server_runtime, "MANIFEST_PATH", manifest), patch.object(
                server_runtime, "ENV_PATH", env_path
            ), patch.object(server_agent, "release_tree_snapshot", return_value={"state": "mutated"}):
                snapshot = server_agent.manifest_snapshot()

        self.assertEqual(snapshot["drift"], "server-mutated")
        self.assertIn("release-tree", snapshot["mismatches"])

    def test_assets_command_only_reports_manifest_bound_state(self) -> None:
        with patch.object(server_agent, "manifest_snapshot", return_value={"drift": "none", "assets": {"geoip-ru.srs": {"state": "ok"}}}):
            payload = server_agent.assets_snapshot()
        self.assertEqual(payload, {"drift": "none", "assets": {"geoip-ru.srs": {"state": "ok"}}})

    def test_root_filesystem_snapshot_verifies_clean_ext4_and_boot_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounts = root / "mounts"
            fstab = root / "fstab"
            sysfs = root / "sysfs" / "vda1"
            sysfs.mkdir(parents=True)
            mounts.write_text("/dev/vda1 / ext4 rw,relatime 0 0\n", encoding="utf-8")
            fstab.write_text("LABEL=root / ext4 defaults 0 1\n", encoding="utf-8")
            for name, value in (("errors_count", "0"), ("first_error_time", "0"), ("last_error_time", "0")):
                (sysfs / name).write_text(value, encoding="utf-8")
            tune = subprocess.CompletedProcess(
                ["tune2fs"],
                0,
                "Filesystem state:         clean\nFS Error count:          0\nLast checked:             Sat Aug  1 19:56:37 2026\n",
                "",
            )
            with patch.object(server_runtime, "run", return_value=tune):
                result = server_agent.root_filesystem_snapshot(mounts, fstab, root / "sysfs")

        self.assertEqual(result["verdict"], "verified")
        self.assertTrue(result["boot_check_enabled"])
        self.assertEqual(result["errors_count"], 0)
        self.assertEqual(result["state"], "clean")

    def test_block_device_name_resolves_dev_root_alias_through_sysfs_device_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            metadata = Mock(st_rdev=123)
            with (
                patch.object(server_agent.os, "stat", return_value=metadata),
                patch.object(server_agent.os, "major", return_value=253, create=True),
                patch.object(server_agent.os, "minor", return_value=1, create=True),
                patch.object(server_agent.Path, "read_text", autospec=True, return_value="MAJOR=253\nMINOR=1\nDEVNAME=vda1\n") as read_text,
            ):
                name = server_agent.block_device_name("/dev/root", Path(tmp))

        self.assertEqual(name, "vda1")
        self.assertEqual(read_text.call_args.args[0], Path(tmp) / "253:1" / "uevent")
        self.assertEqual(read_text.call_args.kwargs, {"encoding": "utf-8"})

    def test_root_filesystem_snapshot_fails_on_ext4_metadata_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounts = root / "mounts"
            fstab = root / "fstab"
            sysfs = root / "sysfs" / "vda1"
            sysfs.mkdir(parents=True)
            mounts.write_text("/dev/vda1 / ext4 rw,relatime 0 0\n", encoding="utf-8")
            fstab.write_text("LABEL=root / ext4 defaults 0 1\n", encoding="utf-8")
            (sysfs / "errors_count").write_text("3", encoding="utf-8")
            tune = subprocess.CompletedProcess(["tune2fs"], 0, "Filesystem state:         clean with errors\n", "")
            with patch.object(server_runtime, "run", return_value=tune):
                result = server_agent.root_filesystem_snapshot(mounts, fstab, root / "sysfs")

        self.assertEqual(result["verdict"], "failed")
        self.assertIn("offline fsck", result["reason"])

    def test_root_filesystem_snapshot_degrades_when_boot_check_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounts = root / "mounts"
            fstab = root / "fstab"
            sysfs = root / "sysfs" / "vda1"
            sysfs.mkdir(parents=True)
            mounts.write_text("/dev/vda1 / ext4 rw,relatime 0 0\n", encoding="utf-8")
            fstab.write_text("LABEL=root / ext4 defaults 0 0\n", encoding="utf-8")
            (sysfs / "errors_count").write_text("0", encoding="utf-8")
            tune = subprocess.CompletedProcess(["tune2fs"], 0, "Filesystem state:         clean\n", "")
            with patch.object(server_runtime, "run", return_value=tune):
                result = server_agent.root_filesystem_snapshot(mounts, fstab, root / "sysfs")

        self.assertEqual(result["verdict"], "degraded")
        self.assertFalse(result["boot_check_enabled"])

    def test_root_filesystem_snapshot_is_inconclusive_without_runtime_error_counter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mounts = root / "mounts"
            fstab = root / "fstab"
            mounts.write_text("/dev/vda1 / ext4 rw,relatime 0 0\n", encoding="utf-8")
            fstab.write_text("LABEL=root / ext4 defaults 0 1\n", encoding="utf-8")
            tune = subprocess.CompletedProcess(["tune2fs"], 0, "Filesystem state:         clean\n", "")
            with patch.object(server_runtime, "run", return_value=tune):
                result = server_agent.root_filesystem_snapshot(mounts, fstab, root / "missing-sysfs")

        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("error counter is unavailable", result["reason"])

    def test_front_degradation_evidence_is_bounded(self) -> None:
        flows = {
            f"203.0.113.20:{port}": {"source": "203.0.113.20", "quality": "degraded", "bytes_retrans": port}
            for port in range(100, 125)
        }
        evidence = server_agent.front_degradation_evidence(
            {
                "flows": flows,
                "degraded_sources": ["203.0.113.20"],
                "recent_degraded_sources": ["203.0.113.20"],
                "connections": len(flows),
                "bytes_sent": 1_000_000,
                "bytes_retrans": 20_000,
                "retransmit_ratio_pct": 2.0,
            },
            "2026-07-20T08:00:00+00:00",
        )
        self.assertEqual(len(evidence["flows"]), 20)
        self.assertIn("203.0.113.20:124", evidence["flows"])
        self.assertNotIn("203.0.113.20:100", evidence["flows"])

    def test_protocol_snapshot_collects_tcp_out_and_retrans_segments(self) -> None:
        completed = subprocess.CompletedProcess(
            ["nstat"],
            0,
            "TcpOutSegs 10000 0.0\nTcpRetransSegs 125 0.0\nTcpExtTCPSACKReorder 20 0.0\nTcpExtTCPDSACKRecv 7 0.0\nUdpRcvbufErrors 3 0.0\n",
            "",
        )
        with patch.object(server_runtime, "run", return_value=completed):
            counters = server_agent.protocol_counters_snapshot()
        self.assertEqual(counters["TcpOutSegs"], 10_000)
        self.assertEqual(counters["TcpRetransSegs"], 125)
        self.assertEqual(counters["TcpExtTCPSACKReorder"], 20)
        self.assertEqual(counters["TcpExtTCPDSACKRecv"], 7)

    def test_snapshot_includes_bootstrap_identity_for_lifecycle_preflight(self) -> None:
        manifest = {
            **self.single_manifest(),
            "version": "0.21.0",
            "release_id": "release-1",
            "policy_version": "0.21.0",
        }
        with (
            patch.object(server_runtime, "parse_env", return_value={"DEPLOY_NAME": "demo", "WAN_INTERFACE": "eth0", "WG_INTERFACE": "wg0", "RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "manifest_snapshot", return_value={"manifest": manifest, "drift": "none", "files": {}}),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "fresh_log_since", return_value=("5 minutes ago", 5)),
            patch.object(server_agent, "maintenance_snapshot", return_value={"upgradable": 0}),
            patch.object(server_agent, "tcp_front_snapshot", return_value={"listening": True, "state_counts": {}, "socket_retransmissions": 0}),
            patch.object(server_agent, "public_hy2_snapshot", return_value={"configured": True, "listening": True, "firewall": True}),
            patch.object(server_agent, "wireguard_snapshot", return_value={"peers": []}),
            patch.object(server_runtime, "default_interface", return_value="ens3"),
            patch.object(server_agent, "interface_counters", return_value={"ens3": {}}),
            patch.object(
                server_agent,
                "tcp_adaptation_snapshot",
                return_value={"congestion_control": "bbr", "qdisc": "fq", "qdisc_limit": 10_000, "qdisc_flow_limit": 512, "mtu_probing": 1},
            ),
            patch.object(server_runtime, "wireguard_policy_snapshot", return_value={"managed": True, "ok": True, "checks": {}, "missing": []}),
            patch.object(server_agent, "conntrack_snapshot", return_value={}),
            patch.object(server_agent, "xray_conntrack_bypass_snapshot", return_value={"active": True, "ingress": True, "egress": True}),
            patch.object(server_agent, "host_snapshot", return_value={"hostname": "ru-host", "login_user": "root", "is_root": True, "has_sudo": True, "os_id": "ubuntu", "os_version": "24.04", "default_interface": "ens3"}) as host_snapshot,
            patch.object(server_agent, "installed_at_value", return_value="2026-07-15T00:00:00Z"),
        ):
            snapshot = server_agent.collect_runtime_facts()
        self.assertEqual(snapshot["host"]["login_user"], "root")
        self.assertTrue(snapshot["host"]["is_root"])
        host_snapshot.assert_called_once_with("ens3")
        self.assertEqual(snapshot["release"]["installed_at"], "2026-07-15T00:00:00Z")
        self.assertEqual(snapshot["network"]["tcp_adaptation"]["mtu_probing"], 1)

    def test_runtime_facts_timestamp_each_collector_before_its_acquisition(self) -> None:
        clock = datetime(2026, 9, 5, 12, tzinfo=timezone.utc)
        acquired = {}
        fixtures = {
            (server_agent, 'manifest_snapshot'): ("artifacts", {"manifest": {"release_id": "fixture"}, "drift": "none"}),
            (server_agent, 'service_state'): ("services", "active"),
            (server_agent, 'maintenance_snapshot'): ("maintenance", {"upgradable": 0}),
            (server_agent, 'summarize_problem_windows'): ("logs", ({}, {}, "")),
            (server_agent, 'tcp_front_snapshot'): ("front", {"listening": True}),
            (server_agent, 'run_confirmed_probes'): ("route_probes", {"profile": "acceptance", "requirements": {}}),
            (server_transport, 'interserver_transport_snapshot'): ("transport", {"configured": True}),
            (server_agent, 'tcp_adaptation_snapshot'): ("network", {"qdisc": "fq"}),
            (server_agent, 'root_filesystem_snapshot'): ("storage", {"verdict": "verified"}),
            (server_agent, 'wireguard_snapshot'): ("wireguard", {"interface": "wg0", "state": "up"}),
        }

        def collector(name, value):
            def acquire(*_args, **_kwargs):
                nonlocal clock
                acquired.setdefault(name, clock.isoformat())
                clock += timedelta(seconds=20)
                return value
            return acquire

        with ExitStack() as stack:
            stack.enter_context(patch.object(server_runtime, "utc_now", side_effect=lambda: clock.isoformat()))
            for (module, function), (name, value) in fixtures.items():
                stack.enter_context(patch.object(module, function, side_effect=collector(name, value)))
            for (module, function), value in {
                (server_runtime, 'parse_env'): {}, (server_agent, 'runtime_contract'): self.gateway_contract(), (server_runtime, 'default_interface'): "eth0",
                (server_agent, 'fresh_log_since'): ("5 minutes ago", 5), (server_agent, 'installed_at_value'): "2026-09-05T11:59:00+00:00",
                (server_agent, 'udp_443_policy'): "routed", (server_agent, 'public_hy2_snapshot'): {}, (server_agent, 'resolver_snapshot'): {},
                (server_agent, 'storage_snapshot'): {}, (server_agent, 'conntrack_snapshot'): {}, (server_agent, 'xray_conntrack_bypass_snapshot'): {},
                (server_agent, 'network_profile_mismatches'): [], (server_runtime, 'wireguard_policy_snapshot'): {}, (server_runtime, 'read_json'): {},
                (server_agent, 'host_snapshot'): {}, (server_agent, 'interface_counters'): {}, (server_agent, 'protocol_counters_snapshot'): {},
                (server_agent, 'softnet_counters_snapshot'): {},
            }.items():
                stack.enter_context(patch.object(module, function, return_value=value))
            stack.enter_context(patch.object(server_runtime, "run", side_effect=AssertionError("unexpected OS command")))
            facts = server_agent.collect_runtime_facts(live_probes=True)
        self.assertEqual(set(acquired), set(server_agent.COLLECTOR_NAMES))
        self.assertEqual(facts["collector_observed_at"], acquired)
        self.assertEqual(facts["generated_at"], clock.isoformat())
        self.assertGreater((clock - datetime.fromisoformat(acquired["artifacts"])).total_seconds(), 180)

    def test_tcp_adaptation_snapshot_reads_runtime_kernel_state(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            values = {
                "net.ipv4.tcp_congestion_control": "bbr\n",
                "net.ipv4.tcp_mtu_probing": "1\n",
                "net.ipv4.tcp_mtu_probe_floor": "536\n",
                "net.ipv4.tcp_probe_interval": "600\n",
                "net.ipv4.tcp_no_metrics_save": "0\n",
                "net.ipv4.tcp_thin_linear_timeouts": "1\n",
                "net.core.rmem_default": "8388608\n",
                "net.core.rmem_max": "16777216\n",
                "net.core.wmem_default": "8388608\n",
                "net.core.wmem_max": "16777216\n",
            }
            if args[0] == "sysctl":
                return subprocess.CompletedProcess(args, 0, values[args[-1]], "")
            return subprocess.CompletedProcess(
                args,
                0,
                '[{"kind":"fq","root":true,"options":{"limit":10000,"flow_limit":512},"drops":3,"flows_plimit":2}]\n',
                "",
            )

        with patch.object(server_runtime, "run", side_effect=fake_run):
            snapshot = server_agent.tcp_adaptation_snapshot("ens3", "wg0")
        self.assertEqual(
            snapshot,
            {
                "congestion_control": "bbr",
                "mtu_probing": 1,
                "mtu_probe_floor": 536,
                "probe_interval_seconds": 600,
                "metrics_save_disabled": 0,
                "thin_linear_timeouts": 1,
                "udp_rmem_default": 8388608,
                "udp_rmem_max": 16777216,
                "udp_wmem_default": 8388608,
                "udp_wmem_max": 16777216,
                "qdisc": "fq",
                "qdisc_limit": 10000,
                "qdisc_flow_limit": 512,
                "qdisc_drops": 3,
                "qdisc_flow_limit_drops": 2,
                "overlay_qdisc": "fq",
                "overlay_qdisc_limit": 10000,
                "overlay_qdisc_flow_limit": 512,
                "overlay_qdisc_drops": 3,
                "overlay_qdisc_flow_limit_drops": 2,
            },
        )

    def test_conntrack_snapshot_reports_capacity_and_fresh_kernel_events(self) -> None:
        def read_text(path: Path, *_args: object, **_kwargs: object) -> str:
            values = {
                "/proc/sys/net/netfilter/nf_conntrack_count": "6144",
                "/proc/sys/net/netfilter/nf_conntrack_max": "6144",
            }
            return values[str(path).replace("\\", "/")]

        cutoff = 1_786_040_000.0
        coverage = {"since_epoch": cutoff - 300, "query_since_epoch": cutoff - 300, "query_until_epoch": cutoff, "discarded_at": [], "error": ""}
        for total in (2, None):
            with self.subTest(total=total):
                evidence = {
                    "counts": {"5": total}, "observed_counts": {"5": 2},
                    "windows": {"5": {"scope": "complete" if total is not None else "unavailable"}},
                    "coverage": coverage, "collector_error": "" if total is not None else "partial journal query failed",
                    "query_since": datetime.fromtimestamp(cutoff - 300, timezone.utc).isoformat(),
                    "query_until": datetime.fromtimestamp(cutoff, timezone.utc).isoformat(),
                    "observed_at": datetime.fromtimestamp(cutoff, timezone.utc).isoformat(),
                    "events": [{"epoch": cutoff - 1, "message": "nf_conntrack: table full"}],
                }
                retained = {key: value for key, value in evidence.items() if key != "events"}
                with (
                    patch.object(Path, "read_text", autospec=True, side_effect=read_text),
                    patch.object(server_agent, "kernel_conntrack_full_windows", return_value=evidence) as events,
                ):
                    snapshot = server_agent.conntrack_snapshot(full_logs=False, coverage=coverage, cutoff=cutoff)

                self.assertEqual(snapshot, {
                    "count": 6144, "max": 6144, "percent": 100.0,
                    "table_full_events": {"5": total}, "table_full_observed": {"5": 2},
                    "journal_evidence": retained,
                })
                self.assertNotIn("events", snapshot["journal_evidence"])
                events.assert_called_once_with(full_logs=False, coverage=coverage, cutoff=cutoff)

    def test_kernel_conntrack_events_are_bucketed_from_one_journal_read(self) -> None:
        cutoff = 1_786_040_000.0
        records = "\n".join(json.dumps({
            "__REALTIME_TIMESTAMP": str(int(timestamp * 1_000_000)),
            "MESSAGE": "nf_conntrack: table full, dropping packet",
        }) for timestamp in (cutoff - 100, cutoff - 500, cutoff + 1))
        completed = subprocess.CompletedProcess(["journalctl"], 0, records, "")
        coverage = {"since_epoch": cutoff - 86400, "query_since_epoch": cutoff - 86400, "query_until_epoch": cutoff, "discarded_at": [], "error": ""}
        for full_logs in (True, False):
            with self.subTest(full_logs=full_logs), patch.object(server_runtime, "run", return_value=completed) as run_mock, patch.object(journal_evidence, "journal_coverage") as coverage_mock:
                evidence = server_agent.kernel_conntrack_full_windows(full_logs=full_logs, coverage=coverage, cutoff=cutoff)

                expected = {"5": 1, "30": 2, "1440": 2} if full_logs else {"5": 1}
                self.assertEqual(evidence["counts"], expected)
                self.assertEqual(evidence["observed_counts"], expected)
                self.assertEqual(evidence["collector_error"], "")
                self.assertEqual(evidence["coverage"], coverage)
                self.assertTrue(all(window["scope"] == "complete" for window in evidence["windows"].values()))
                run_mock.assert_called_once()
                coverage_mock.assert_not_called()
                args = run_mock.call_args.args[0]
                self.assertIn("_TRANSPORT=kernel", args)
                self.assertIn("--output=json", args)
                self.assertIn(f"--grep={server_agent.CONNTRACK_FULL_GREP}", args)
                self.assertEqual(args[args.index("--until") + 1], f"@{cutoff:.6f}")
                since = cutoff - (86400 if full_logs else 300)
                self.assertEqual(args[args.index("--since") + 1], f"@{since:.6f}")

    def test_xray_conntrack_bypass_requires_both_runtime_rules(self) -> None:
        rules = (
            'tcp dport 443 counter packets 1 bytes 60 notrack comment "vpnstack-xray-in-notrack"\n'
            'tcp sport 443 counter packets 1 bytes 60 notrack comment "vpnstack-xray-out-notrack"\n'
        )
        with patch.object(server_runtime, "run", return_value=subprocess.CompletedProcess(["nft"], 0, rules, "")):
            active = server_agent.xray_conntrack_bypass_snapshot(443)
        with patch.object(server_runtime, "run", return_value=subprocess.CompletedProcess(["nft"], 0, rules.splitlines()[0], "")):
            incomplete = server_agent.xray_conntrack_bypass_snapshot(443)

        self.assertEqual(active, {"active": True, "ingress": True, "egress": True})
        self.assertEqual(incomplete, {"active": False, "ingress": True, "egress": False})

    def test_managed_network_profile_detects_runtime_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sysctl.conf"
            path.write_text(
                "net.core.rmem_max=16777216\n"
                "net.core.rmem_default=8388608\n"
                "net.core.wmem_default=8388608\n"
                "net.core.wmem_max=16777216\n"
                "net.ipv4.tcp_mtu_probe_floor=536\n"
                "net.ipv4.tcp_no_metrics_save=0\n"
                "net.ipv4.tcp_thin_linear_timeouts=1\n",
                encoding="utf-8",
            )
            expected = server_agent.managed_network_profile(path)
        self.assertEqual(
            expected,
            {
                "udp_rmem_default": 8_388_608,
                "udp_rmem_max": 16_777_216,
                "udp_wmem_default": 8_388_608,
                "udp_wmem_max": 16_777_216,
                "mtu_probe_floor": 536,
                "metrics_save_disabled": 0,
                "thin_linear_timeouts": 1,
                "qdisc": "fq",
                "qdisc_limit": 10_000,
                "qdisc_flow_limit": 512,
                "overlay_qdisc": "fq",
                "overlay_qdisc_limit": 10_000,
                "overlay_qdisc_flow_limit": 512,
            },
        )
        self.assertEqual(
            server_agent.network_profile_mismatches(
                {
                    "udp_rmem_default": 212_992,
                    "udp_rmem_max": 16_777_216,
                    "udp_wmem_default": 8_388_608,
                    "udp_wmem_max": 16_777_216,
                    "mtu_probe_floor": 536,
                    "metrics_save_disabled": 0,
                    "thin_linear_timeouts": 1,
                    "qdisc": "fq",
                    "qdisc_limit": 10_000,
                    "qdisc_flow_limit": 512,
                    "overlay_qdisc": "fq",
                    "overlay_qdisc_limit": 10_000,
                    "overlay_qdisc_flow_limit": 512,
                },
                expected,
            ),
            ["udp_rmem_default"],
        )

    def test_managed_network_profile_includes_conntrack_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sysctl.conf"
            path.write_text("net.netfilter.nf_conntrack_max=32768\n", encoding="utf-8")
            expected = server_agent.managed_network_profile(path)
        self.assertEqual(
            expected,
            {
                "conntrack_max": 32768,
                "qdisc": "fq",
                "qdisc_limit": 10_000,
                "qdisc_flow_limit": 512,
                "overlay_qdisc": "fq",
                "overlay_qdisc_limit": 10_000,
                "overlay_qdisc_flow_limit": 512,
            },
        )
        self.assertEqual(
            server_agent.network_profile_mismatches(
                {
                    "conntrack_max": 6144,
                    "qdisc": "fq",
                    "qdisc_limit": 10_000,
                    "qdisc_flow_limit": 512,
                    "overlay_qdisc": "fq",
                    "overlay_qdisc_limit": 10_000,
                    "overlay_qdisc_flow_limit": 512,
                },
                expected,
            ),
            ["conntrack_max"],
        )

    def test_front_snapshot_groups_tcp_metrics_by_client_source(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123 sk:2D43A0\n\t cubic rtt:45.2/3.1 mss:1428 pmtu:1500 cwnd:12 bytes_sent:2000000 bytes_retrans:80000 data_segs_out:1400 delivery_rate 12000000bps retrans:0/3 reord_seen:7 dsack_dups:4 reordering:300 rcv_ooopack:5 unacked:2 lastsnd:100 lastrcv:200\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertTrue(front["listening"])
        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        client = front["clients"]["203.0.113.20"]
        self.assertEqual(client["retransmissions"], 3)
        self.assertEqual(client["bytes_retrans"], 80000)
        self.assertEqual(client["retransmit_ratio_pct"], 4.0)
        self.assertEqual(client["quality"], "loss_observed")
        self.assertEqual(client["pmtu"], 1500)
        self.assertEqual(client["reord_seen"], 7)
        self.assertEqual(client["dsack_dups"], 4)
        self.assertEqual(client["rcv_ooopack"], 5)
        self.assertEqual(client["reordering"], 300)
        self.assertEqual(client["unacked"], 2)
        self.assertEqual(client["rtt_ms"]["p95"], 45.2)
        self.assertEqual(client["rtt_ms"]["samples"], 1)
        flow = front["flows"]["203.0.113.20:50123"]
        self.assertEqual(flow["source_port"], 50123)
        self.assertEqual(flow["socket_id"], "2d43a0")
        self.assertEqual(flow["retransmit_ratio_pct"], 4.0)
        self.assertEqual(front["degraded_sources"], [])
        self.assertEqual(front["loss_observed_sources"], ["203.0.113.20"])

    def test_front_snapshot_does_not_classify_fin_retransmits_as_active_loss(self) -> None:
        sockets = "".join(
            f"FIN-WAIT-1 0 0 192.0.2.10:443 203.0.113.20:{port}\n"
            for port in range(50100, 50125)
        )
        details = "".join(
            f"FIN-WAIT-1 0 0 192.0.2.10:443 203.0.113.20:{port}\n"
            "\t cubic rtt:900/100 rto:76000 bytes_sent:0 bytes_retrans:64000 retrans:0/20\n"
            for port in range(50100, 50125)
        )

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, sockets, "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(args, 0, details, "")
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 192.0.2.10:443 0.0.0.0:*\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["active_connections"], 0)
        self.assertEqual(front["closing_connections"], 25)
        self.assertEqual(front["bytes_retrans"], 0)
        self.assertEqual(front["degraded_sources"], [])
        self.assertEqual(front["closing_churn_sources"], ["203.0.113.20"])
        self.assertEqual(server_agent.front_observation(front), "observed")
        self.assertEqual(server_agent.closing_churn_observation(front), "client_specific")

    def test_front_client_metrics_exclude_closing_socket_counters(self) -> None:
        sockets = (
            "ESTAB 0 0 192.0.2.10:443 203.0.113.20:50000\n"
            + "".join(
                f"FIN-WAIT-1 0 0 192.0.2.10:443 203.0.113.20:{port}\n"
                for port in range(50100, 50125)
            )
        )
        details = (
            "ESTAB 0 0 192.0.2.10:443 203.0.113.20:50000\n"
            "\t cubic rtt:65/5 rto:220 bytes_sent:1000000 bytes_retrans:1000 retrans:0/1\n"
            + "".join(
                f"FIN-WAIT-1 0 0 192.0.2.10:443 203.0.113.20:{port}\n"
                "\t cubic rtt:900/100 rto:76000 bytes_sent:0 bytes_retrans:64000 retrans:0/20\n"
                for port in range(50100, 50125)
            )
        )

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, sockets, "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(args, 0, details, "")
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 192.0.2.10:443 0.0.0.0:*\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        client = front["clients"]["203.0.113.20"]
        self.assertEqual(client["phase"], "active")
        self.assertEqual(client["states"], {"ESTAB": 1})
        self.assertEqual(client["bytes_retrans"], 1000)
        self.assertEqual(front["closing_churn_sources"], ["203.0.113.20"])

    def test_front_interval_uses_monotonic_counters_from_the_same_socket(self) -> None:
        first = {
            "flows": {
                "203.0.113.20:50123": {
                    "socket_id": "2d43a0",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 100_000,
                    "bytes_retrans": 1_000,
                    "retransmissions": 1,
                    "data_segs_out": 80,
                }
            }
        }
        second = {
            "flows": {
                "203.0.113.20:50123": {
                    "socket_id": "2d43a0",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 2_100_000,
                    "bytes_retrans": 81_000,
                    "retransmissions": 7,
                    "data_segs_out": 1_480,
                    "pmtu": 1480,
                    "mss": 1408,
                    "rtt_ms": {"median": 28.0, "p95": 35.0},
                    "rto_ms": {"p95": 210, "max": 220},
                    "cwnd": {"median": 18, "max": 24},
                    "delivery_rate_bps": {"median": 42_000_000, "max": 55_000_000},
                    "reordering": 3,
                }
            }
        }

        baseline, counters = server_agent.front_interval_snapshot(first, {}, "2026-07-30T20:00:00+00:00")
        interval, _counters = server_agent.front_interval_snapshot(second, counters, "2026-07-30T20:02:00+00:00")

        self.assertTrue(baseline["baseline"])
        self.assertEqual(baseline["sampled_flows"], 0)
        self.assertEqual(interval["degraded_sources"], ["203.0.113.20"])
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["bytes_retrans"], 80_000)
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["quality"], "degraded")
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["pmtu"], 1480)
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["mss"], 1408)
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["rtt_ms"]["p95"], 35.0)
        self.assertEqual(interval["flows"]["203.0.113.20:50123"]["rto_ms"]["max"], 220)

    def test_front_interval_replaces_stale_client_specific_verdict(self) -> None:
        current = {
            "front": {"listening": True, "recent_degraded_sources": ["203.0.113.20"]},
            "services": {"xray": "active"},
            "verdicts": {
                "server_path": "verified",
                "public_front": "degraded",
                "public_quic": "verified",
                "client_observation": "client_specific",
                "host_integrity": "verified",
                "overall": "degraded",
                "reasons": ["public_front=client_specific"],
            },
        }
        interval = {
            "baseline": False,
            "observation": "observed",
            "degraded_sources": [],
        }

        server_agent.apply_front_interval_verdict(current, interval)

        self.assertEqual(current["verdicts"]["client_observation"], "observed")
        self.assertEqual(current["verdicts"]["public_front"], "verified")
        self.assertEqual(current["verdicts"]["overall"], "verified")
        self.assertEqual(current["verdicts"]["reasons"], [])

    def test_front_interval_aggregates_loss_across_one_clients_flows(self) -> None:
        first = {
            "flows": {
                f"203.0.113.20:{port}": {
                    "socket_id": f"socket-{port}",
                    "source": "203.0.113.20",
                    "source_port": port,
                    "bytes_sent": 100_000,
                    "bytes_retrans": 1_000,
                    "retransmissions": 1,
                    "data_segs_out": 80,
                }
                for port in (50123, 50124)
            }
        }
        second = {
            "flows": {
                f"203.0.113.20:{port}": {
                    "socket_id": f"socket-{port}",
                    "source": "203.0.113.20",
                    "source_port": port,
                    "bytes_sent": 700_000,
                    "bytes_retrans": 13_000,
                    "retransmissions": 3,
                    "data_segs_out": 500,
                }
                for port in (50123, 50124)
            }
        }

        _baseline, counters = server_agent.front_interval_snapshot(first, {}, "2026-08-01T20:00:00+00:00")
        interval, _counters = server_agent.front_interval_snapshot(second, counters, "2026-08-01T20:02:00+00:00")

        self.assertEqual({flow["quality"] for flow in interval["flows"].values()}, {"observed"})
        self.assertEqual(interval["sources"]["203.0.113.20"]["activity_bytes"], 1_200_000)
        self.assertEqual(interval["sources"]["203.0.113.20"]["retransmit_ratio_pct"], 2.0)
        self.assertEqual(interval["sources"]["203.0.113.20"]["quality"], "degraded")
        self.assertEqual(interval["degraded_sources"], ["203.0.113.20"])
        self.assertEqual(interval["observation"], "client_specific")

    def test_front_interval_detects_fresh_loss_before_lifetime_threshold(self) -> None:
        metrics = server_agent.front_interval_metrics(
            {
                "bytes_sent": 300_000,
                "bytes_retrans": 3_600,
                "retransmissions": 3,
                "data_segs_out": 200,
            }
        )

        self.assertEqual(metrics["retransmit_ratio_pct"], 1.2)
        self.assertEqual(metrics["quality"], "degraded")

    def test_front_interval_marks_tiny_samples_insufficient(self) -> None:
        metrics = server_agent.front_interval_metrics(
            {
                "bytes_sent": 183,
                "bytes_retrans": 122,
                "retransmissions": 2,
                "data_segs_out": 3,
            }
        )

        self.assertEqual(metrics["retransmit_ratio_pct"], 66.667)
        self.assertEqual(metrics["quality"], "insufficient")

    def test_front_interval_does_not_join_replaced_or_reset_sockets(self) -> None:
        previous = {
            "observed_at": "2026-07-30T20:00:00+00:00",
            "flows": {
                "old": {
                    "endpoint": "203.0.113.20:50123",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 2_000_000,
                    "bytes_retrans": 80_000,
                    "retransmissions": 8,
                    "data_segs_out": 1_400,
                },
                "reset": {
                    "endpoint": "203.0.113.21:50124",
                    "source": "203.0.113.21",
                    "source_port": 50124,
                    "bytes_sent": 2_000_000,
                    "bytes_retrans": 80_000,
                    "retransmissions": 8,
                    "data_segs_out": 1_400,
                },
                "reused": {
                    "endpoint": "203.0.113.22:50125",
                    "source": "203.0.113.22",
                    "source_port": 50125,
                    "bytes_sent": 1_000,
                    "bytes_retrans": 0,
                    "retransmissions": 0,
                    "data_segs_out": 10,
                },
            },
        }
        current = {
            "flows": {
                "203.0.113.20:50123": {
                    "socket_id": "new",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 100_000,
                    "bytes_retrans": 20_000,
                    "retransmissions": 4,
                    "data_segs_out": 70,
                },
                "203.0.113.21:50124": {
                    "socket_id": "reset",
                    "source": "203.0.113.21",
                    "source_port": 50124,
                    "bytes_sent": 100,
                    "bytes_retrans": 0,
                    "retransmissions": 0,
                    "data_segs_out": 1,
                },
                "203.0.113.23:50126": {
                    "socket_id": "reused",
                    "source": "203.0.113.23",
                    "source_port": 50126,
                    "bytes_sent": 2_000_000,
                    "bytes_retrans": 100_000,
                    "retransmissions": 10,
                    "data_segs_out": 1_400,
                },
            }
        }

        interval, _counters = server_agent.front_interval_snapshot(
            current,
            previous,
            "2026-07-30T20:02:00+00:00",
        )

        self.assertEqual(interval["sampled_flows"], 0)
        self.assertEqual(interval["degraded_sources"], [])

    def test_front_interval_resets_a_stale_baseline(self) -> None:
        current = {
            "flows": {
                "203.0.113.20:50123": {
                    "socket_id": "2d43a0",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 2_000_000,
                    "bytes_retrans": 100_000,
                    "retransmissions": 10,
                    "data_segs_out": 1_400,
                }
            }
        }
        previous = {
            "observed_at": "2026-07-30T20:00:00+00:00",
            "flows": {
                "2d43a0": {
                    "endpoint": "203.0.113.20:50123",
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "bytes_sent": 1_000,
                    "bytes_retrans": 0,
                    "retransmissions": 0,
                    "data_segs_out": 10,
                }
            },
        }

        interval, _counters = server_agent.front_interval_snapshot(
            current,
            previous,
            "2026-07-30T20:10:00+00:00",
        )

        self.assertTrue(interval["baseline"])
        self.assertEqual(interval["baseline_reason"], "stale")
        self.assertEqual(interval["sampled_flows"], 0)
        self.assertEqual(interval["degraded_sources"], [])

    def test_front_snapshot_normalizes_ipv4_mapped_socket_source(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 [::ffff:94.232.248.35]:443 [::ffff:203.0.113.20]:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 [::ffff:94.232.248.35]:443 [::ffff:203.0.113.20]:50123\n\t cubic rtt:45.2/3.1 retrans:0/3 unacked:2\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 [::]:443 [::]:*\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        self.assertEqual(front["clients"]["203.0.113.20"]["retransmissions"], 3)
        self.assertIn("203.0.113.20:50123", front["flows"])

    def test_front_snapshot_keeps_flows_separate_behind_one_nat(self) -> None:
        sockets = (
            "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n"
            "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50124\n"
        )
        details = (
            "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n\t cubic rtt:30/2 bytes_sent:2000000 bytes_retrans:0 retrans:0/0\n"
            "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50124\n\t cubic rtt:400/20 rto:1200 bytes_sent:2000000 bytes_retrans:100000 retrans:0/8\n"
        )

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, sockets, "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(args, 0, details, "")
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["clients"]["203.0.113.20"]["connections"], 2)
        self.assertEqual(front["flows"]["203.0.113.20:50123"]["quality"], "observed")
        self.assertEqual(front["flows"]["203.0.113.20:50124"]["quality"], "degraded")
        self.assertEqual(front["degraded_sources"], ["203.0.113.20"])

    def test_front_snapshot_reports_keepalive_and_stale_socket_lifecycle(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123 timer:(keepalive,12sec,0)\n"
                    "\t cubic rtt:45/3 lastsnd:3600001 lastrcv:3600001\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["keepalive_timer_connections"], 1)
        self.assertEqual(front["stale_connections_5m"], 1)
        self.assertEqual(front["stale_connections_1h"], 1)
        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        self.assertIn("203.0.113.20", front["clients"])
        self.assertIn("203.0.113.20:50123", front["flows"])
        self.assertNotIn("timer", front["clients"])
        self.assertEqual(server_agent.front_observation(front), "observed")

    def test_front_snapshot_keeps_idle_lifetime_loss_out_of_current_sources(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n"
                    "\t cubic rtt:400/20 rto:1200 lastsnd:60001 lastrcv:60001 bytes_sent:2000000 bytes_retrans:100000 retrans:0/8\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["degraded_sources"], ["203.0.113.20"])
        self.assertEqual(front["recent_degraded_sources"], [])
        self.assertEqual(server_agent.front_observation(front), "observed")

    def test_front_snapshot_ignores_optional_ss_fields_before_endpoints(self) -> None:
        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-Htan" in args:
                return subprocess.CompletedProcess(args, 0, "ESTAB 0 0 94.232.248.35:443 203.0.113.20:50123\n", "")
            if "-Htoein" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "ESTAB 0 0 timer:(keepalive,12sec,0) 94.232.248.35:443 203.0.113.20:50123\n"
                    "\t cubic rtt:45/3\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 0, "LISTEN 0 4096 94.232.248.35:443 0.0.0.0:*\n", "")

        with patch.object(server_runtime, "run", side_effect=fake_run):
            front = server_agent.tcp_front_snapshot(443)

        self.assertEqual(front["top_sources"], {"203.0.113.20": 1})
        self.assertEqual(front["keepalive_timer_connections"], 1)
        self.assertIn("203.0.113.20:50123", front["flows"])

    def test_client_snapshot_matches_ipv4_mapped_xray_source(self) -> None:
        front = {"listening": True, "clients": {"203.0.113.20": {"connections": 1}}, "top_sources": {"203.0.113.20": 1}}
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with (
            patch.object(server_runtime, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
            patch.object(server_agent, "journal_filtered_events", return_value=front_evidence(["from [::ffff:203.0.113.20]:50123 accepted tcp:example.org:443"])),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_runtime, "run", return_value=completed),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["events"]["accepted"], 1)
        self.assertEqual(payload["front"]["client"], {"connections": 1})

    def test_front_observation_separates_closing_churn_from_active_loss(self) -> None:
        isolated = {"closing_churn_sources": ["203.0.113.20"]}
        shared = {"closing_churn_sources": [f"203.0.113.{index}" for index in range(1, 4)]}
        self.assertEqual(server_agent.front_observation(isolated), "observed")
        self.assertEqual(server_agent.front_observation(shared), "observed")
        self.assertEqual(server_agent.closing_churn_observation(isolated), "client_specific")
        self.assertEqual(server_agent.closing_churn_observation(shared), "shared")

    def test_front_observation_does_not_treat_lifetime_retransmissions_as_fresh_failure(self) -> None:
        front = {"clients": {"203.0.113.20": {"states": {"ESTAB": 1}, "retransmissions": 200}}}
        self.assertEqual(server_agent.front_observation(front), "observed")

    def test_front_observation_does_not_promote_client_lifetime_loss(self) -> None:
        front = {"clients": {"203.0.113.20": {"states": {"ESTAB": 1}, "bytes_sent": 5_000_000, "retransmit_ratio_pct": 4.5, "quality": "degraded"}}}
        self.assertEqual(server_agent.front_observation(front), "observed")

    def test_public_front_verdict_uses_socket_quality_not_only_listener_state(self) -> None:
        degraded = {
            "listening": True,
            "degraded_sources": ["203.0.113.20"],
            "recent_degraded_sources": ["203.0.113.20"],
            "fin_wait_1_sources": [],
        }
        self.assertEqual(server_agent.public_front_verdict("active", degraded), "degraded")
        self.assertEqual(server_agent.public_front_verdict("inactive", degraded), "failed")

    def test_public_front_verdict_uses_fresh_interval_loss(self) -> None:
        front = {"listening": True, "degraded_sources": [], "fin_wait_1_sources": []}
        interval = {"degraded_sources": ["203.0.113.20"], "observation": "client_specific"}
        self.assertEqual(server_agent.public_front_verdict("active", front, interval), "degraded")

    def test_release_scoped_observation_excludes_previous_release_interval(self) -> None:
        previous = {
            "observed_at": "2026-08-16T22:22:43+00:00",
            "degraded_sources": ["203.0.113.20"],
        }
        current = {
            "observed_at": "2026-08-16T22:23:43+00:00",
            "degraded_sources": ["203.0.113.20"],
        }
        installed_at = "2026-08-16T22:23:00+00:00"
        self.assertEqual(server_agent.release_scoped_observation(previous, installed_at), {})
        self.assertIs(server_agent.release_scoped_observation(current, installed_at), current)
        self.assertIs(server_agent.release_scoped_observation(current, ""), current)

    def test_public_front_ignores_degraded_lifetime_metrics_after_flow_is_idle(self) -> None:
        front = {
            "listening": True,
            "degraded_sources": ["203.0.113.20"],
            "recent_degraded_sources": [],
            "stale_connections_5m": 1,
            "keepalive_timer_connections": 1,
        }
        self.assertEqual(server_agent.front_observation(front), "observed")
        self.assertEqual(server_agent.public_front_verdict("active", front), "verified")

    def test_public_front_reports_accumulated_reality_handshakes_as_degraded(self) -> None:
        front = {
            "listening": True,
            "recent_degraded_sources": [],
            "reality_pending_handshakes": server_agent.REALITY_PENDING_HANDSHAKE_DEGRADED,
        }
        self.assertEqual(server_agent.front_observation(front), "degraded")
        self.assertEqual(server_agent.public_front_verdict("active", front), "degraded")

    def test_reality_pending_handshakes_count_only_xray_target_sockets(self) -> None:
        output = (
            '0 1 10.0.0.1:50001 13.107.21.200:443 users:(("xray",pid=1,fd=1))\n'
            '0 1 10.0.0.1:50002 13.107.21.200:443 users:(("curl",pid=2,fd=2))\n'
            '0 1 10.0.0.1:50003 13.107.21.200:80 users:(("xray",pid=1,fd=3))\n'
        )
        completed = subprocess.CompletedProcess(["ss"], 0, output, "")
        with patch.object(server_runtime, "run", return_value=completed):
            self.assertEqual(server_agent.xray_reality_pending_handshakes("r.bing.com:443"), 1)

    def test_xray_front_socket_policy_reads_inbound_liveness_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "xray.json"
            config.write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "port": 443,
                                "streamSettings": {
                                    "realitySettings": {
                                        "target": "r.bing.com:443",
                                        "serverNames": ["www.bing.com"],
                                    },
                                    "sockopt": {
                                        "tcpKeepAliveIdle": 90,
                                        "tcpKeepAliveInterval": 15,
                                    }
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch.object(server_agent, "XRAY_CONFIG_PATH", config),
                patch.object(server_agent, "xray_reality_pending_handshakes", return_value=0),
            ):
                policy = server_agent.xray_front_socket_policy(443)

        self.assertEqual(
            policy,
            {
                "tcp_keepalive_idle_seconds": 90,
                "tcp_keepalive_interval_seconds": 15,
                "reality_target": "r.bing.com:443",
                "reality_target_config_key": "target",
                "reality_server_names": ["www.bing.com"],
                "reality_pending_handshakes": 0,
            },
        )

    def test_public_hysteria_snapshot_requires_config_listener_and_firewall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "sing-box.json"
            config.write_text(
                json.dumps(
                    {
                        "inbounds": [
                            {
                                "type": "hysteria2",
                                "tag": "public-hy2-in",
                                "listen_port": 443,
                                "users": [{"password": "secret"}],
                                "tls": {"enabled": True},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                if args[0] == "ss":
                    return subprocess.CompletedProcess(args, 0, "UNCONN 0 0 0.0:443 0.0.0.0:*\n", "")
                return subprocess.CompletedProcess(
                    args,
                    0,
                    'udp dport 443 notrack comment "vpnstack-hy2-in-notrack"\n'
                    'udp sport 443 notrack comment "vpnstack-hy2-out-notrack"\n'
                    "udp dport 443 counter accept\n",
                    "",
                )

            with patch.object(server_runtime, "SINGBOX_CONFIG_PATH", config), patch.object(server_runtime, "run", side_effect=fake_run):
                result = server_agent.public_hy2_snapshot(443)

        self.assertEqual(result, {"port": 443, "protocol": "hysteria2", "configured": True, "listening": True, "firewall": True})

    def test_front_live_diagnostics_fail_when_downstream_path_fails(self) -> None:
        with (
            patch.object(server_runtime, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
            patch.object(server_agent, "journal_filtered_events", return_value=front_evidence()),
            patch.object(server_agent, "tcp_front_snapshot", return_value={"listening": True, "clients": {}, "flows": {}}),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "udp_443_policy", return_value="routed"),
            patch.object(server_agent, "public_hy2_snapshot", return_value={"configured": True, "listening": True, "firewall": True}),
            patch.object(
                server_agent,
                "run_probes",
                return_value={"profile": "light", "ok": False, "requirements": {"ru_direct": True, "via_wg": False, "router": False}},
            ),
        ):
            payload = server_agent.public_front_snapshot(30, live_probes=True)

        self.assertEqual(payload["verdicts"]["public_front"], "verified")
        self.assertEqual(payload["verdicts"]["server_path"], "failed")
        self.assertEqual(payload["verdict"], "failed")

    def test_client_quality_detects_rto_backed_rtt_inflation(self) -> None:
        metrics = {
            "bytes_sent": 200_000,
            "retransmit_ratio_pct": 0.5,
            "rtt_ms": {"samples": 4, "min": 24.0, "median": 70.0, "p95": 385.0},
            "rto_ms": {"max": 1_183},
        }
        self.assertEqual(server_agent.client_front_quality(metrics), "degraded")

    def test_client_quality_keeps_lifetime_loss_separate_from_current_stall(self) -> None:
        metrics = {
            "bytes_sent": 12_251,
            "bytes_retrans": 2_829,
            "retransmissions": 3,
            "retransmit_ratio_pct": 23.092,
            "rtt_ms": {"samples": 1, "min": 70.0, "p95": 70.0},
            "rto_ms": {"max": 391},
        }
        self.assertEqual(server_agent.client_front_quality(metrics), "loss_observed")

    def test_client_quality_detects_one_stalled_flow_without_mixing_connections(self) -> None:
        metrics = {
            "bytes_sent": 96_410,
            "bytes_retrans": 5_237,
            "retransmissions": 16,
            "retransmit_ratio_pct": 5.465,
            "rtt_ms": {"samples": 1, "min": 1_232.49, "p95": 1_232.49},
            "rto_ms": {"max": 3_429},
        }
        self.assertEqual(server_agent.client_front_quality(metrics), "degraded")

    def test_client_quality_keeps_stable_high_rtt_as_observation(self) -> None:
        metrics = {
            "bytes_sent": 5_000_000,
            "retransmit_ratio_pct": 0.5,
            "rtt_ms": {"samples": 4, "min": 280.0, "median": 310.0, "p95": 350.0},
            "rto_ms": {"max": 1_200},
        }
        self.assertEqual(server_agent.client_front_quality(metrics), "observed")

    def test_client_snapshot_reports_lifetime_loss_separately_from_current_degradation(self) -> None:
        front = {"listening": True, "clients": {"203.0.113.20": {"connections": 1, "quality": "loss_observed"}}, "top_sources": {"203.0.113.20": 1}}
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with (
            patch.object(server_runtime, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
            patch.object(server_agent, "journal_filtered_events", return_value=front_evidence(["from 203.0.113.20:50123 accepted tcp:example.org:443"])),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_runtime, "run", return_value=completed),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)
        self.assertEqual(payload["verdict"], "loss_observed")

    def test_client_snapshot_uses_degraded_active_flow_and_omits_stale_ports(self) -> None:
        front = {
            "listening": True,
            "clients": {"203.0.113.20": {"connections": 1, "quality": "observed"}},
            "flows": {
                "203.0.113.20:50123": {
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "quality": "degraded",
                }
            },
            "top_sources": {"203.0.113.20": 1},
        }
        lines = [
            "from 203.0.113.20:50123 accepted tcp:current.example:443",
            "from 203.0.113.20:59999 accepted tcp:stale.example:443",
        ]
        with (
            patch.object(server_runtime, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
            patch.object(server_agent, "journal_filtered_events", return_value=front_evidence(lines)),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "udp_443_policy", return_value="routed"),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["verdict"], "degraded")
        self.assertEqual(payload["flow_events"], {"203.0.113.20:50123": {"current.example:443": 1}})
        self.assertFalse(payload["client_transport"]["multiplex_detected"])
        self.assertEqual(payload["client_transport"]["status"], "not_observed")

    def test_client_snapshot_detects_tcp_multiplex_on_active_outer_flow(self) -> None:
        front = {
            "listening": True,
            "clients": {"203.0.113.20": {"connections": 1, "quality": "observed"}},
            "flows": {
                "203.0.113.20:50123": {
                    "source": "203.0.113.20",
                    "source_port": 50123,
                    "phase": "active",
                    "quality": "observed",
                }
            },
            "top_sources": {"203.0.113.20": 1},
        }
        lines = [
            "from 203.0.113.20:50123 accepted tcp:first.example:443",
            "from 203.0.113.20:50123 accepted udp:1.1.1.1:53",
            "from 203.0.113.20:50123 accepted tcp:second.example:443",
        ]
        with (
            patch.object(server_runtime, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
            patch.object(server_agent, "journal_filtered_events", return_value=front_evidence(lines)),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_agent, "udp_443_policy", return_value="routed"),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        transport = payload["client_transport"]
        self.assertTrue(transport["multiplex_detected"])
        self.assertEqual(transport["status"], "detected")
        self.assertEqual(transport["multiplexed_flow_count"], 1)
        self.assertEqual(transport["risk"], "tcp_head_of_line")
        self.assertEqual(
            transport["flows"]["203.0.113.20:50123"],
            {
                "accepted_tcp_requests": 2,
                "destinations": {"first.example:443": 1, "second.example:443": 1},
            },
        )

    def test_client_transport_is_inconclusive_without_active_outer_flow(self) -> None:
        observation = server_agent.client_transport_observation({}, active_outer_flows=0)

        self.assertEqual(observation["status"], "inconclusive")
        self.assertFalse(observation["multiplex_detected"])
        self.assertEqual(observation["risk"], "unknown")

    def test_udp_443_policy_rejects_only_global_transport_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sing-box.json"
            config_path.write_text(json.dumps({"route": {"rules": [{"network": ["udp"], "port": [443], "action": "reject"}]}}), encoding="utf-8")
            with patch.object(server_runtime, "SINGBOX_CONFIG_PATH", config_path):
                self.assertEqual(server_agent.udp_443_policy(), "rejected")
            config_path.write_text(json.dumps({"route": {"rules": [{"network": "udp", "port": 443, "domain": ["private.example"], "action": "reject"}]}}), encoding="utf-8")
            with patch.object(server_runtime, "SINGBOX_CONFIG_PATH", config_path):
                self.assertEqual(server_agent.udp_443_policy(), "routed")
            config_path.write_text(json.dumps({"route": {"rules": [{"action": "resolve", "server": "dns-global", "strategy": "ipv4_only"}]}}), encoding="utf-8")
            with patch.object(server_runtime, "SINGBOX_CONFIG_PATH", config_path):
                self.assertEqual(server_agent.udp_443_policy(), "routed")

    def test_standalone_agent_loads_bundled_log_classifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            agent = target / "vpn-stack-agent.py"
            for name, content in server_agent_artifacts(interserver=True).items():
                (target / name).write_text(content, encoding="utf-8")
            result = subprocess.run([sys.executable, "-I", "-S", "-B", str(agent), "--help"], text=True, capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vpn-stack-agent", result.stdout)

    def test_standalone_single_agent_does_not_require_interserver_module(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            agent = target / "vpn-stack-agent.py"
            for name, content in server_agent_artifacts(interserver=False).items():
                (target / name).write_text(content, encoding="utf-8")
            result = subprocess.run([sys.executable, "-I", "-S", "-B", str(agent), "--help"], text=True, capture_output=True, check=False, timeout=10)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vpn-stack-agent", result.stdout)

    def test_client_snapshot_prefers_accepted_xray_event_over_socket_state(self) -> None:
        front = {
            "listening": True,
            "clients": {"203.0.113.20": {"connections": 1}},
            "flows": {"203.0.113.20:50123": {"source": "203.0.113.20", "source_port": 50123, "quality": "observed"}},
            "top_sources": {"203.0.113.20": 1},
        }
        completed = subprocess.CompletedProcess(["nft"], 0, "", "")
        with (
            patch.object(server_runtime, "parse_env", return_value={"RU_LISTEN_PORT": "443"}),
            patch.object(server_agent, "installed_runtime_contract", return_value=self.gateway_contract()),
            patch.object(server_agent, "journal_filtered_events", return_value=front_evidence(["from 203.0.113.20:50123 accepted tcp:example.org:443"])),
            patch.object(server_agent, "tcp_front_snapshot", return_value=front),
            patch.object(server_agent, "service_state", return_value="active"),
            patch.object(server_runtime, "run", return_value=completed),
        ):
            payload = server_agent.front_client_snapshot("203.0.113.20", 15)

        self.assertEqual(payload["events"]["accepted"], 1)
        self.assertEqual(payload["events"]["accepted_tcp"], 1)
        self.assertEqual(payload["events"]["accepted_udp"], 0)
        self.assertEqual(payload["verdict"], "reached_xray")
        self.assertEqual(payload["flow_events"], {"203.0.113.20:50123": {"example.org:443": 1}})
        self.assertEqual(payload["front"]["flows"]["203.0.113.20:50123"]["accepted_destinations"], {"example.org:443": 1})

    def test_ru_acceptance_requires_router_paths_not_direct_foreign_access(self) -> None:
        observed_url = server_agent.ACCEPTANCE_OBSERVED_TARGETS[0]

        def probe(url: str, *, interface: str = "", proxy: str = "", **_kwargs: object) -> dict[str, object]:
            unavailable_observed_target = url == observed_url
            unavailable_wg_ipv6 = "2606:4700:4700::1111" in url and interface == "wg0"
            return {"target": url, "ok": not (unavailable_observed_target or unavailable_wg_ipv6)}

        def identity(*, interface: str = "", proxy: str = "") -> dict[str, object]:
            return {"ok": True, "egress_ip": "198.51.100.20" if interface or proxy else "203.0.113.10"}

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", side_effect=identity),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(interserver_transport, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0", "GATEWAY_PUBLIC_IP": "203.0.113.10", "EXIT_PUBLIC_IP": "198.51.100.20"}, self.gateway_contract(), "acceptance")

        observed_target = next(item for item in result["direct"] if item["target"] == observed_url)
        self.assertFalse(observed_target["ok"])
        self.assertEqual(result["required_targets"], ["https://github.com/", "https://www.google.com/generate_204"])
        self.assertEqual(result["observations"][observed_url]["direct"], observed_target)
        self.assertFalse(result["observations"][observed_url]["via_wg"]["ok"])
        self.assertFalse(result["observations"][observed_url]["router"]["ok"])
        self.assertFalse(result["ipv6_literal"]["via_wg"]["ok"])
        self.assertTrue(result["requirements"]["foreign_domains_via_wg"])
        self.assertTrue(result["requirements"]["ipv6_literal_via_router"])
        self.assertTrue(result["ok"])
        self.assertTrue(result["release_gate_ok"])

    def test_light_health_profile_does_not_duplicate_the_selected_transport_probe(self) -> None:
        calls: list[dict[str, object]] = []

        def probe(url: str, **kwargs: object) -> dict[str, object]:
            calls.append(kwargs)
            return {"target": url, "ok": True}

        with patch.object(server_agent, "probe_url", side_effect=probe):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0"}, self.gateway_contract(), "light")

        self.assertTrue(result["ok"])
        self.assertEqual(result["via_wg"], [])
        self.assertNotIn("via_wg", result["requirements"])
        self.assertFalse(any(call.get("interface") == "wg0" for call in calls))

    def test_external_ipv6_failure_rejects_release_acceptance(self) -> None:
        def probe(url: str, **_kwargs: object) -> dict[str, object]:
            return {"target": url, "ok": "2606:4700:4700::1111" not in url}

        def identity(*, interface: str = "", proxy: str = "") -> dict[str, object]:
            return {"ok": True, "egress_ip": "198.51.100.20" if interface or proxy else "203.0.113.10"}

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", side_effect=identity),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(interserver_transport, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0", "GATEWAY_PUBLIC_IP": "203.0.113.10", "EXIT_PUBLIC_IP": "198.51.100.20"}, self.gateway_contract(), "acceptance")

        self.assertFalse(result["requirements"]["ipv6_literal_via_router"])
        self.assertFalse(result["ok"])
        self.assertFalse(result["release_gate_ok"])
        self.assertFalse(result["release_gate_requirements"]["ipv6_literal_via_router"])
        self.assertFalse(server_agent.release_gate_ok(result))

    def test_wireguard_candidate_failure_is_degraded_when_router_path_is_healthy(self) -> None:
        def probe(url: str, *, interface: str = "", proxy: str = "", **_kwargs: object) -> dict[str, object]:
            return {"target": url, "ok": not bool(interface)}

        def identity(*, interface: str = "", proxy: str = "") -> dict[str, object]:
            return {
                "ok": not bool(interface),
                "egress_ip": "198.51.100.20" if interface or proxy else "203.0.113.10",
            }

        with (
            patch.object(server_agent, "probe_url", side_effect=probe),
            patch.object(server_agent, "probe_identity", side_effect=identity),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(interserver_transport, "transport_candidate_probe", return_value={"ok": True}),
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0", "GATEWAY_PUBLIC_IP": "203.0.113.10", "EXIT_PUBLIC_IP": "198.51.100.20"}, self.gateway_contract(), "acceptance")

        self.assertFalse(result["requirements"]["foreign_domains_via_wg"])
        self.assertFalse(result["requirements"]["wireguard_candidate_identity"])
        self.assertTrue(result["requirements"]["foreign_domains_via_router"])
        self.assertTrue(result["release_gate_ok"])

    def test_hysteria_candidate_failure_is_reported_without_rejecting_a_healthy_router(self) -> None:
        def identity(*, interface: str = "", proxy: str = "") -> dict[str, object]:
            return {"ok": True, "egress_ip": "198.51.100.20" if interface or proxy else "203.0.113.10"}

        with (
            patch.object(server_agent, "probe_url", return_value={"ok": True}),
            patch.object(server_agent, "probe_identity", side_effect=identity),
            patch.object(server_agent, "probe_private_reject", return_value={"ok": True}),
            patch.object(
                interserver_transport,
                "transport_candidate_probe",
                return_value={"ok": False, "error": "timeout"},
            ) as candidate_probe,
        ):
            result = server_agent.run_probes({"WG_INTERFACE": "wg0", "GATEWAY_PUBLIC_IP": "203.0.113.10", "EXIT_PUBLIC_IP": "198.51.100.20"}, self.gateway_contract(), "acceptance")

        candidate_probe.assert_called_once_with("interserver-underlay-hy2")
        self.assertFalse(result["requirements"]["hysteria_candidate_reachable"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["release_gate_ok"])
        self.assertEqual(result["capability_failures"]["transport"], ["hysteria_candidate_reachable"])

    def test_release_gate_still_rejects_core_foreign_path_failure(self) -> None:
        probes = {
            "profile": "acceptance",
            "ok": False,
            "release_gate_ok": False,
            "requirements": {"foreign_domains_via_router": False, "ipv6_literal_via_router": False},
        }
        self.assertFalse(server_agent.release_gate_ok(probes))

    def test_route_probe_uses_headers_instead_of_downloading_unbounded_body(self) -> None:
        completed = subprocess.CompletedProcess(["curl"], 0, "200|0.010|0.020|203.0.113.10", "")
        with patch.object(server_runtime, "run", return_value=completed) as run_mock:
            result = server_agent.probe_url("https://github.com/")

        self.assertTrue(result["ok"])
        self.assertIn("--head", run_mock.call_args.args[0])
        self.assertIn("-L", run_mock.call_args.args[0])
        self.assertEqual(run_mock.call_args.args[0][run_mock.call_args.args[0].index("--connect-timeout") + 1], "5")

    def test_literal_probe_does_not_follow_a_domain_redirect(self) -> None:
        completed = subprocess.CompletedProcess(["curl"], 0, "302|0.010|0.020|1.1.1.1", "")
        with patch.object(server_runtime, "run", return_value=completed) as run_mock:
            result = server_agent.probe_url(
                "https://1.1.1.1/cdn-cgi/trace",
                insecure=True,
                follow_redirects=False,
            )

        self.assertTrue(result["ok"])
        self.assertNotIn("-L", run_mock.call_args.args[0])

    def test_identity_probe_uses_dns_independent_trace_endpoint(self) -> None:
        completed = subprocess.CompletedProcess(["curl"], 0, "fl=1\nip=203.0.113.9\nwarp=off\n", "")
        with patch.object(server_runtime, "run", return_value=completed) as run_mock:
            result = server_agent.probe_identity()

        self.assertEqual(result, {"ok": True, "egress_ip": "203.0.113.9", "error": ""})
        self.assertIn("https://1.1.1.1/cdn-cgi/trace", run_mock.call_args.args[0])
        self.assertNotIn("api.ipify.org", run_mock.call_args.args[0])

    def test_resolver_snapshot_reports_managed_cache_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "dnsmasq.conf"
            config.write_text(
                "listen-address=127.0.0.1\nport=1054\nno-resolv\nall-servers\n"
                "cache-size=4096\nserver=1.1.1.1\nserver=9.9.9.9\nserver=8.8.8.8\n",
                encoding="utf-8",
            )
            with patch.object(server_agent, "DNS_CACHE_CONFIG_PATH", config):
                resolver = server_agent.resolver_snapshot()

        self.assertTrue(resolver["managed_config"])
        self.assertTrue(resolver["concurrent_upstreams"])
        self.assertEqual(resolver["listen_port"], 1054)
        self.assertEqual(resolver["cache_capacity"], 4096)
        self.assertEqual(resolver["upstreams"], ["1.1.1.1", "9.9.9.9", "8.8.8.8"])

    def test_proxy_probe_does_not_force_ip_family_on_ipv4_loopback_proxy(self) -> None:
        completed = subprocess.CompletedProcess(["curl"], 0, "200|0.001|0.100|127.0.0.1", "")
        with patch.object(server_runtime, "run", return_value=completed) as run_mock:
            result = server_agent.probe_url(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace",
                proxy="socks5h://127.0.0.1:2080",
                ip_version=6,
            )

        self.assertTrue(result["ok"])
        self.assertNotIn("-6", run_mock.call_args.args[0])

    def test_acceptance_retries_one_failed_cycle_without_declaring_hard_failure(self) -> None:
        failed = {
            "profile": "acceptance",
            "ok": False,
            "release_gate_ok": False,
            "requirements": {"foreign_domains_via_router": False, "foreign_domains_via_wg": False},
        }
        recovered = {
            "profile": "acceptance",
            "ok": False,
            "release_gate_ok": True,
            "requirements": {"foreign_domains_via_router": True, "foreign_domains_via_wg": False},
        }
        with patch.object(server_agent, "run_probes", side_effect=[failed, recovered]), patch.object(server_agent.time, "sleep") as sleep:
            result = server_agent.run_confirmed_probes({}, self.gateway_contract(), "acceptance")

        self.assertFalse(result["ok"])
        self.assertTrue(result["release_gate_ok"])
        self.assertEqual(result["confirmation"]["cycles"], 2)
        self.assertTrue(result["confirmation"]["recovered_on_retry"])
        self.assertFalse(result["confirmation"]["confirmed_failure"])
        self.assertEqual(
            result["confirmation"]["initial_failed_requirements"],
            ["foreign_domains_via_router", "foreign_domains_via_wg"],
        )
        sleep.assert_called_once_with(server_agent.PROBE_CONFIRMATION_DELAY_SECONDS)

    def test_acceptance_reports_confirmed_failure_after_two_cycles(self) -> None:
        failed = {
            "profile": "acceptance",
            "ok": False,
            "release_gate_ok": False,
            "requirements": {"foreign_domains_via_router": False},
        }
        with patch.object(server_agent, "run_probes", side_effect=[failed, failed]), patch.object(server_agent.time, "sleep"):
            result = server_agent.run_confirmed_probes({}, self.gateway_contract(), "acceptance")

        self.assertFalse(result["ok"])
        self.assertEqual(result["confirmation"]["cycles"], 2)
        self.assertTrue(result["confirmation"]["confirmed_failure"])
        self.assertFalse(result["confirmation"]["recovered_on_retry"])


class JournalWindowIntegrationTests(unittest.TestCase):
    def test_fractional_release_age_does_not_clip_initial_events(self) -> None:
        now = 1_786_040_000.75
        for full_logs, age, expected_minutes in ((True, 86400.5, 1441), (False, 300.5, 6)):
            with self.subTest(full_logs=full_logs):
                since = now - age
                installed = datetime.fromtimestamp(since, timezone.utc).isoformat()
                event = (since + 0.25, "ERROR dns: exchange failed for example.com. IN A: context deadline exceeded")

                def query(minutes, *, until):
                    return ([event] if until - minutes * 60 <= event[0] <= until else []), ""

                with patch.object(server_agent.time, "time", return_value=now), patch.object(
                    server_agent, "journal_problem_events", side_effect=query,
                ) as problem_query, patch.object(journal_evidence, "journal_coverage", return_value={"since_epoch": 0, "discarded_at": [], "error": ""}):
                    _windows, fresh, error = server_agent.summarize_problem_windows(full_logs=full_logs, fresh_since=installed)
                self.assertEqual(error, "")
                problem_query.assert_called_once_with(expected_minutes, until=now)
                self.assertEqual(fresh["coverage_error"], "")
                self.assertEqual(fresh["counts"]["dns_timeout"], 1)
                self.assertEqual(fresh["since"], installed)

    def test_retained_but_unqueried_release_prefix_is_not_complete(self) -> None:
        now = 1_786_040_000.75
        since = now - server_agent.COMPLETE_LOG_RETENTION_MINUTES * 60 - 0.5
        installed = datetime.fromtimestamp(since, timezone.utc).isoformat()
        event = (now - 1, "ERROR dns: exchange failed for example.com. IN A: context deadline exceeded")
        with patch.object(server_agent.time, "time", return_value=now), patch.object(
            server_agent, "journal_problem_events", return_value=([event], ""),
        ) as problem_query, patch.object(journal_evidence, "journal_coverage", return_value={"since_epoch": 0, "discarded_at": [], "error": ""}):
            windows, fresh, error = server_agent.summarize_problem_windows(full_logs=True, fresh_since=installed)
        self.assertEqual(error, "")
        problem_query.assert_called_once_with(1440, until=now)
        self.assertEqual(windows["5"]["coverage_error"], "")
        self.assertEqual(fresh["coverage_error"], "requested start precedes collected journal interval")
        self.assertEqual(fresh["coverage"]["query_since_epoch"], now - 86400)
        self.assertEqual(fresh["coverage"]["query_until_epoch"], now)
        self.assertEqual(fresh["since"], installed)
        self.assertEqual(fresh["counts"]["dns_timeout"], 1)
        self.assertEqual(server_agent._diagnostics_log_window(fresh, since=installed).collector.status, "error")

    def test_old_window_is_partial_but_retained_fresh_window_is_complete(self) -> None:
        base = 1_786_000_000
        coverage = {"since_epoch": base + 1000, "discarded_at": [base + 1500], "error": ""}
        with patch.object(journal_evidence, "journal_coverage", return_value=coverage), patch.object(server_agent, "journal_problem_events", return_value=([], "")), patch.object(server_agent.time, "time", return_value=base + 3000):
            windows, fresh, error = server_agent.summarize_problem_windows(full_logs=True, fresh_since=datetime.fromtimestamp(base + 1800, timezone.utc).isoformat())
        self.assertEqual(error, "")
        self.assertEqual(windows["5"]["coverage_error"], "")
        self.assertIn("discarded", windows["30"]["coverage_error"])
        self.assertIn("precedes", windows["1440"]["coverage_error"])
        self.assertEqual(fresh["coverage_error"], "")


if __name__ == "__main__":
    unittest.main()
