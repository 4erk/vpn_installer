from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import Mock

from vpn_installer import journal_evidence as journal


def header(head: int, tail: int, since: float, until: float, *, state: str = "ARCHIVED") -> str:
    return (
        f"File path: /var/log/journal/machine/system{head}.journal\n"
        "Sequential number ID: 7868558e4bed47e98aa6f9fd64d292b3\n"
        f"State: {state}\nHead sequential number: {head} (unused)\n"
        f"Tail sequential number: {tail} (unused)\nEntry objects: {tail-head+1}\n"
        f"Head realtime timestamp: ignored locale ({int(since*1e6):x})\n"
        f"Tail realtime timestamp: ignored locale ({int(until*1e6):x})\n\n"
    )


def record(timestamp: float, message: str = "nf_conntrack: table full, dropping packet", **fields: object) -> str:
    return json.dumps({"__REALTIME_TIMESTAMP": str(int(timestamp * 1e6)), "MESSAGE": message, **fields})


def result(stdout: str = "", *, code: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, stdout, stderr)


def coverage(**changes: object) -> dict[str, object]:
    return {"since_epoch": 0, "query_since_epoch": 0, "query_until_epoch": 1000, "discarded_at": [], "error": "", **changes}


class JournalEvidenceTests(unittest.TestCase):
    def test_retained_range_stops_at_missing_file(self) -> None:
        old = header(10, 19, 100, 200)
        active = header(30, 39, 300, 400, state="ONLINE")
        self.assertEqual(journal.journal_retained_range(old + active)["since_epoch"], 300)
        complete = journal.journal_retained_range(old + header(20, 29, 201, 299) + active)
        self.assertEqual(complete["since_epoch"], 100)
        self.assertEqual(complete["files"], 3)

    def test_retained_range_requires_valid_unique_active_inventory(self) -> None:
        active = header(10, 19, 100, 200, state="ONLINE")
        for value in (
            "", active.replace("Entry objects: 10", "Entry objects: 9"),
            active.replace("State: ONLINE", "State: OFFLINE"), active + active,
            active.replace("7868558e4bed47e98aa6f9fd64d292b3", "invalid"),
            active * 129, active + "x" * 256_000,
        ):
            with self.subTest(value=value[:80]), self.assertRaises(ValueError):
                journal.journal_retained_range(value)

    def test_retained_range_does_not_cross_sequence_or_clock_discontinuity(self) -> None:
        active = header(20, 29, 201, 299, state="ONLINE")
        for previous in (
            header(10, 19, 100, 202),
            header(10, 19, 100, 200).replace("7868558e4bed47e98aa6f9fd64d292b3", "0" * 32),
            header(10, 19, 100, 200) * 2,
        ):
            with self.subTest(previous=previous):
                self.assertEqual(journal.journal_retained_range(previous + active)["since_epoch"], 201)

    def test_command_error_distinguishes_empty_match_from_failure_or_warning(self) -> None:
        for completed, error in (
            (result(), False), (result(code=1), False), (result(code=2), True),
            (result("partial", code=1), True), (result(stderr="corrupt journal"), True),
            (result(code=1, stderr="denied"), True),
        ):
            with self.subTest(completed=completed):
                self.assertEqual(bool(journal.journal_command_error(completed)), error)

    def test_parser_preserves_unit_and_binary_message_without_ansi(self) -> None:
        payload = record(175, "\x1b[31mfailed\x1b[0m", _SYSTEMD_UNIT="sing-box.service")
        binary = json.dumps({"__REALTIME_TIMESTAMP": "176000000", "MESSAGE": list(b"kernel event"), "SYSLOG_IDENTIFIER": "kernel"})
        parsed, malformed = journal.parse_journal_events(result(payload + "\n" + binary))
        self.assertEqual(parsed, [(175, "[unit=sing-box.service] failed"), (176, "[unit=kernel] kernel event")])
        self.assertEqual(malformed, 0)
        self.assertEqual(journal.parse_journal_events(result(payload), include_unit=False)[0], [(175, "failed")])

    def test_parser_counts_bad_records_without_losing_positive_evidence(self) -> None:
        invalid = [
            "broken", "[]", "null", "{}",
            *[json.dumps({"__REALTIME_TIMESTAMP": value, "MESSAGE": "event"}) for value in (True, 1.5, "nan", "-1", "0", "9" * 400)],
            json.dumps({"__REALTIME_TIMESTAMP": "175000000", "MESSAGE": [999]}),
            record(175, ""),
        ]
        parsed, malformed = journal.parse_journal_events(result("\n".join([record(180), *invalid])))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(malformed, len(invalid))

    def test_acquisition_uses_explicit_runner_and_bounded_loss_query(self) -> None:
        runner = Mock(side_effect=[result(header(10, 19, 100, 200, state="ONLINE")), result(code=1)])
        evidence = journal.journal_coverage(runner=runner, since=150, until=300)
        self.assertEqual(evidence["error"], "")
        self.assertEqual(evidence["since_epoch"], 100)
        self.assertEqual(evidence["query_since_epoch"], 150)
        self.assertEqual(evidence["query_until_epoch"], 300)
        self.assertEqual(evidence["discarded_at"], [])
        self.assertIn("--system", runner.call_args_list[0].args[0])
        args = runner.call_args_list[1].args[0]
        self.assertEqual(args[args.index("--since") + 1], "@150.000000")
        self.assertEqual(args[args.index("--until") + 1], "@300.000000")
        self.assertIn("--lines=257", args)
        self.assertIn("--all", args)

    def test_acquisition_preserves_suppression_timestamps(self) -> None:
        runner = Mock(side_effect=[result(header(10, 19, 100, 200, state="ONLINE")), result(record(175, "Suppressed 7 messages"))])
        self.assertEqual(journal.journal_coverage(runner=runner, since=150, until=300)["discarded_at"], [175])

    def test_long_kernel_and_suppression_messages_are_requested_and_preserved(self) -> None:
        message = "nf_conntrack: table full " + "x" * 6000
        loss = "Suppressed 7 messages " + "x" * 6000

        def runner(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
            if "--header" in args:
                return result(header(10, 19, 100, 900, state="ONLINE"))
            self.assertIn("--all", args)
            self.assertGreater(timeout, 0)
            return result(record(900, message) if "_TRANSPORT=kernel" in args else record(800, loss))

        snapshot = journal.kernel_event_snapshot(
            runner=runner, pattern="table full", window_starts={"5": 700}, query_since=200, cutoff=1000,
        )
        self.assertEqual(snapshot["events"][0]["message"], message)
        self.assertEqual(snapshot["observed_counts"]["5"], 1)
        self.assertEqual(snapshot["coverage"]["discarded_at"], [800])
        self.assertEqual(snapshot["collector_error"], "")
        self.assertIsNone(snapshot["counts"]["5"])
        self.assertIn("discarded", snapshot["windows"]["5"]["coverage_error"])

    def test_acquisition_does_not_accept_header_or_loss_query_failures(self) -> None:
        for response in (result(code=1, stderr="denied"), result(stderr="corrupt journal"), subprocess.TimeoutExpired("journalctl", 10)):
            for stage in ("header", "loss"):
                responses = [response] if stage == "header" else [result(header(10, 19, 100, 200, state="ONLINE")), response]
                with self.subTest(response=response, stage=stage):
                    evidence = journal.journal_coverage(runner=Mock(side_effect=responses), since=150, until=300)
                    self.assertTrue(evidence["error"])
                    if stage == "loss":
                        self.assertEqual(evidence["since_epoch"], 100)

    def test_acquisition_rejects_malformed_or_truncated_loss_evidence(self) -> None:
        for loss in ("broken", "\n".join(record(175, "Missed 1 messages") for _ in range(257))):
            with self.subTest(loss=loss[:80]):
                runner = Mock(side_effect=[result(header(10, 19, 100, 200, state="ONLINE")), result(loss)])
                self.assertEqual(journal.journal_coverage(runner=runner, since=150, until=300)["error"], "journal loss evidence is incomplete")

    def test_invalid_acquisition_interval_never_runs_command(self) -> None:
        runner = Mock()
        for since, until in ((300, 150), (float("nan"), 300), (0, 10**400)):
            self.assertTrue(journal.journal_coverage(runner=runner, since=since, until=until)["error"])
        runner.assert_not_called()

    def test_window_checks_retention_query_and_reused_loss_interval(self) -> None:
        cases = (
            (coverage(), 700, 0, 1000, ""),
            (coverage(since_epoch=800), 700, 0, 1000, "retained"),
            (coverage(), 700, 800, 1000, "start precedes collected"),
            (coverage(), 700, 0, 900, "end exceeds collected"),
            (coverage(query_since_epoch=800), 700, 0, 1000, "loss-evidence"),
            (coverage(query_until_epoch=999), 700, 0, 1000, "loss-evidence"),
            (coverage(discarded_at=[750]), 700, 0, 1000, "discarded"),
            (coverage(discarded_at=[699]), 700, 0, 1000, ""),
            (coverage(error="denied"), 700, 0, 1000, "denied"),
            ({}, 700, 0, 1000, "retained"),
            (coverage(discarded_at=None), 700, 0, 1000, "incomplete"),
            (coverage(), None, 0, 1000, "invalid"),
            (coverage(), 1001, 0, 1000, "invalid"),
        )
        for evidence, since, query_since, query_until, expected in cases:
            with self.subTest(evidence=evidence, since=since, expected=expected):
                error = journal.journal_window_error(evidence, since=since, until=1000, query_since=query_since, query_until=query_until)
                self.assertIn(expected, error) if expected else self.assertEqual(error, "")

    def test_kernel_helper_uses_one_all_boot_query_and_fixed_cutoff(self) -> None:
        runner = Mock(return_value=result("\n".join([
            record(500, _BOOT_ID="old"), record(900, _BOOT_ID="new"), record(1000), record(1000.1), record(100),
        ])))
        evidence = coverage()
        snapshot = journal.kernel_event_snapshot(
            runner=runner, pattern="nf_conntrack.*table full", window_starts={"5": 700, "30": 200},
            query_since=200, cutoff=1000, coverage=evidence,
        )
        self.assertEqual(snapshot["counts"], {"5": 2, "30": 3})
        self.assertEqual(snapshot["observed_counts"], snapshot["counts"])
        self.assertEqual(len(snapshot["events"]), 3)
        self.assertEqual(snapshot["coverage"], evidence)
        runner.assert_called_once()
        args = runner.call_args.args[0]
        self.assertIn("_TRANSPORT=kernel", args)
        self.assertNotIn("-k", args)
        self.assertNotIn("-b", args)
        self.assertIn("--all", args)
        self.assertEqual(args[args.index("--until") + 1], "@1000.000000")

    def test_kernel_helper_acquires_coverage_only_when_not_supplied(self) -> None:
        runner = Mock(side_effect=[result(code=1), result(header(10, 19, 100, 900, state="ONLINE")), result(code=1)])
        snapshot = journal.kernel_event_snapshot(runner=runner, pattern="table full", window_starts={"5": 700}, query_since=200, cutoff=1000)
        self.assertEqual(snapshot["counts"], {"5": 0})
        self.assertEqual(runner.call_count, 3)

    def test_kernel_helper_unknown_totals_keep_positive_lower_bounds(self) -> None:
        for completed in (
            result(record(900), code=2, stderr="partial query failed"),
            result(record(900), stderr="truncated journal"),
            result(record(900) + "\nmalformed"),
        ):
            with self.subTest(completed=completed):
                snapshot = journal.kernel_event_snapshot(
                    runner=Mock(return_value=completed), pattern="table full", window_starts={"5": 700},
                    query_since=200, cutoff=1000, coverage=coverage(),
                )
                self.assertEqual(snapshot["counts"], {"5": None})
                self.assertEqual(snapshot["observed_counts"], {"5": 1})
                self.assertTrue(snapshot["collector_error"])
                self.assertEqual(len(snapshot["events"]), 1)

    def test_kernel_helper_timeout_preserves_complete_records_in_partial_output(self) -> None:
        runner = Mock(side_effect=subprocess.TimeoutExpired("journalctl", 20, output=record(900).encode()))
        snapshot = journal.kernel_event_snapshot(
            runner=runner, pattern="table full", window_starts={"5": 700}, query_since=200, cutoff=1000, coverage=coverage(),
        )
        self.assertEqual(snapshot["counts"]["5"], None)
        self.assertEqual(snapshot["observed_counts"]["5"], 1)
        self.assertTrue(snapshot["collector_error"])

    def test_kernel_helper_no_matches_is_zero_only_for_complete_windows(self) -> None:
        snapshot = journal.kernel_event_snapshot(
            runner=Mock(return_value=result(code=1)), pattern="table full", window_starts={"5": 700, "30": 200, "unknown": None},
            query_since=200, cutoff=1000, coverage=coverage(since_epoch=600),
        )
        self.assertEqual(snapshot["counts"], {"5": 0, "30": None, "unknown": None})
        self.assertEqual(snapshot["observed_counts"], {"5": 0, "30": 0, "unknown": None})
        self.assertEqual(snapshot["windows"]["30"]["scope"], "unavailable")
        self.assertEqual(snapshot["collector_error"], "")


if __name__ == "__main__":
    unittest.main()
