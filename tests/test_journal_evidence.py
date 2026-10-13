from __future__ import annotations

import json
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from vpn_installer import journal_evidence as journal


# Required fields from the saved Oct 8 inventory. OFFLINE variants model a normal
# sync transition, not the unrecorded state at the time of the incident.
EXIT_CURRENT_HEADER = """File path: /var/log/journal/3f8498c7c1ad40e6b84ace8bd060ce23/system.journal
Sequential number ID: e8a8a771d6f8422cb662eb7b33d52683
State: ONLINE
Head sequential number: 5657490 (565392)
Tail sequential number: 5658849 (5658e1)
Head realtime timestamp: Thu 2026-10-08 10:36:31 UTC (65d51ce11f8be)
Tail realtime timestamp: Thu 2026-10-08 11:48:36 UTC (65d52cfdf0a31)
Entry objects: 1360

"""
EXIT_PREVIOUS_HEADER = """File path: /var/log/journal/3f8498c7c1ad40e6b84ace8bd060ce23/system@e8a8a771d6f8422cb662eb7b33d52683-0000000000562a85-00065d4e42ece8b1.journal
Sequential number ID: e8a8a771d6f8422cb662eb7b33d52683
State: ARCHIVED
Head sequential number: 5646981 (562a85)
Tail sequential number: 5657489 (565391)
Head realtime timestamp: Thu 2026-10-08 06:22:51 UTC (65d4e42ece8b1)
Tail realtime timestamp: Thu 2026-10-08 10:36:28 UTC (65d51cde63a60)
Entry objects: 10509

"""


def header(head: int, tail: int, since: float, until: float, *, state: str = "ARCHIVED", filename: str | None = None) -> str:
    filename = filename or ("system.journal" if state in ("ONLINE", "OFFLINE") else f"system@{head}.journal")
    return (
        f"File path: /var/log/journal/machine/{filename}\n"
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


def front_evidence(lines=(), *, cutoff: float | None = None) -> dict:
    cutoff = time.time() - 10 if cutoff is None else cutoff
    return journal.journal_event_snapshot(
        runner=Mock(return_value=result("\n".join(record(cutoff - 1, line, _SYSTEMD_UNIT="vpn-stack-xray.service") for line in lines))),
        pattern="accepted", matches=("-u", "vpn-stack-xray.service"), window_starts={"front": cutoff - 300},
        query_since=cutoff - 300, cutoff=cutoff, coverage=coverage(query_until_epoch=cutoff),
    )


class JournalEvidenceTests(unittest.TestCase):
    def test_bounded_reader_waits_for_exit_after_pipes_close(self) -> None:
        line = record(175, "positive evidence")
        code = f"import os, time; print({line!r}, flush=True); os.close(1); os.close(2); time.sleep(0.05)"
        completed = journal.run_bounded([sys.executable, "-u", "-c", code], timeout=5)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(journal.parse_journal_events(completed, include_unit=False), ([(175, "positive evidence")], 0))

    def test_stream_parser_preserves_complete_records_before_truncated_json(self) -> None:
        lines = iter((record(175, "positive evidence") + "\n", '{"MESSAGE":"truncated'))
        parsed, malformed = journal.parse_journal_lines(lines, include_unit=False)
        self.assertEqual(parsed, [(175, "positive evidence")])
        self.assertEqual(malformed, 1)

    def test_bounded_reader_preserves_output_and_terminates_a_stalled_query(self) -> None:
        line = record(175, "positive evidence")
        command = [sys.executable, "-u", "-c", f"import time; print({line!r}, flush=True); time.sleep(10)"]
        started = time.monotonic()
        completed = journal.run_bounded(command, timeout=1)
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn("deadline", completed.stderr)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(journal.parse_journal_events(completed, include_unit=False), ([(175, "positive evidence")], 0))

    def test_bounded_reader_caps_total_bytes_and_single_records(self) -> None:
        line = record(175, "positive evidence")
        for oversized in (True, False):
            code = f"print({line!r}, flush=True); print('x' * 300)" if oversized else f"print(({line!r} + '\\n') * 100, end='')"
            with self.subTest(oversized=oversized), patch.object(journal, "JOURNAL_MAX_BYTES", 512), patch.object(
                journal, "JOURNAL_MAX_RECORD_BYTES", 256,
            ):
                completed = journal.run_bounded([sys.executable, "-u", "-c", code], timeout=5)
            self.assertIn("byte bound", completed.stderr)
            self.assertLessEqual(len(completed.stdout.encode()), 512)
            parsed, malformed = journal.parse_journal_events(completed, include_unit=False)
            self.assertGreaterEqual(len(parsed), 1)
            self.assertEqual(malformed, 0)

    def test_bounded_reader_does_not_start_after_deadline_or_hide_missing_binary(self) -> None:
        with patch.object(journal.subprocess, "Popen") as process:
            self.assertIn("deadline", journal.run_bounded(["journalctl"], timeout=0).stderr)
            process.assert_not_called()
        with patch.object(journal.subprocess, "Popen", side_effect=FileNotFoundError("not installed")):
            self.assertIn("not installed", journal.run_bounded(["journalctl"], timeout=1).stderr)

    def test_unit_and_kernel_queries_share_failure_and_partial_record_handling(self) -> None:
        for completed in (result(code=1), result(code=2, stderr="denied"),
                          result(record(900), code=2, stderr="partial"),
                          result(record(900), stderr="corrupt"), result(record(900) + "\nbroken"),
                          subprocess.TimeoutExpired("journalctl", 30, output=record(900).encode()),
                          FileNotFoundError("journalctl missing")):
            with self.subTest(completed=completed):
                runner = Mock(side_effect=completed) if isinstance(completed, Exception) else Mock(return_value=completed)
                snapshot = journal.journal_event_snapshot(
                    runner=runner, pattern="accepted", matches=("-u", "vpn-stack-xray.service"),
                    window_starts={"front": 700}, query_since=700, cutoff=1000, coverage=coverage(), timeout=30,
                )
                no_match = not isinstance(completed, Exception) and completed.returncode == 1
                self.assertEqual(snapshot["counts"]["front"], 0 if no_match else None)
                self.assertEqual(bool(journal.journal_snapshot_error(snapshot, window="front")), not no_match)
                expected_observed = int(isinstance(completed, subprocess.TimeoutExpired) or (
                    not isinstance(completed, Exception) and bool(completed.stdout)))
                self.assertEqual(snapshot["observed_counts"]["front"], expected_observed)
                args = runner.call_args.args[0]
                self.assertIn("--all", args)
                self.assertIn("--output=json", args)
                self.assertEqual(args[args.index("--since") + 1], "@700.000000")
                self.assertEqual(args[args.index("--until") + 1], "@1000.000000")
                self.assertEqual(runner.call_args.kwargs["timeout"], 30)

    def test_consumer_rejects_missing_partial_or_contradictory_journal_evidence(self) -> None:
        complete = front_evidence(cutoff=1000)
        self.assertEqual(journal.journal_snapshot_error(complete, window="front"), "")
        for key in ("collector_error", "coverage", "windows", "counts", "query_since_epoch", "query_until_epoch"):
            incomplete = dict(complete)
            del incomplete[key]
            self.assertTrue(journal.journal_snapshot_error(incomplete, window="front"), key)
        for incomplete in (None, {}, {**complete, "collector_error": "partial"},
                           {**complete, "counts": {"front": None}}, {**complete, "counts": {"front": True}},
                           {**complete, "coverage": coverage(since_epoch=800)},
                           {**complete, "coverage": coverage(discarded_at=[900])}):
            self.assertTrue(journal.journal_snapshot_error(incomplete, window="front"))

    def test_unit_query_preserves_float_cutoff_and_bounds(self) -> None:
        cutoff = 1789366998.4848592
        since = cutoff - 300
        runner = Mock(return_value=result("\n".join(record(stamp) for stamp in (since - 1, since + 1, cutoff - 1, cutoff + 1))))
        snapshot = journal.journal_event_snapshot(
            runner=runner, pattern="accepted", matches=("-u", "vpn-stack-xray.service"),
            window_starts={"front": since}, query_since=since, cutoff=cutoff,
            coverage=coverage(query_until_epoch=cutoff),
        )
        self.assertEqual(snapshot["counts"]["front"], 2)
        self.assertEqual(snapshot["query_until_epoch"], cutoff)
        self.assertEqual(journal.journal_snapshot_error(snapshot, window="front"), "")

    def test_retained_range_stops_at_missing_file(self) -> None:
        old = header(10, 19, 100, 200)
        for state in ("ONLINE", "OFFLINE"):
            with self.subTest(state=state):
                active = header(30, 39, 300, 400, state=state)
                self.assertEqual(journal.journal_retained_range(old + active)["since_epoch"], 300)
                complete = journal.journal_retained_range(old + header(20, 29, 201, 299) + active)
                self.assertEqual(complete["since_epoch"], 100)
                self.assertEqual(complete["files"], 3)

    def test_retained_range_accepts_pinned_current_headers_online_or_synced_offline(self) -> None:
        for state in ("ONLINE", "OFFLINE"):
            current = EXIT_CURRENT_HEADER.replace("State: ONLINE", f"State: {state}")
            for inventory in (current + EXIT_PREVIOUS_HEADER, EXIT_PREVIOUS_HEADER + current):
                for newline in ("\n", "\r\n"):
                    with self.subTest(state=state, newline=newline, current_first=inventory.startswith(current)):
                        self.assertEqual(journal.journal_retained_range(inventory.replace("\n", newline)), {
                            "since_epoch": 1791440571.918513,
                            "sequence_id": "e8a8a771d6f8422cb662eb7b33d52683", "files": 2,
                        })

    def test_retained_range_requires_current_filename_not_just_online_state(self) -> None:
        for state in ("ONLINE", "OFFLINE"):
            for filename in ("system@old.journal", "system.journal~", "user-1000.journal", "not-system.journal"):
                with self.subTest(state=state, filename=filename), self.assertRaises(ValueError):
                    journal.journal_retained_range(header(10, 19, 100, 200, state=state, filename=filename))

    def test_retained_range_rejects_multiple_current_or_unarchived_files(self) -> None:
        for state in ("ONLINE", "OFFLINE"):
            current = header(20, 29, 201, 300, state=state)
            for other_state in ("ONLINE", "OFFLINE", "ARCHIVED"):
                other = header(10, 19, 100, 200, state=other_state, filename="system.journal")
                for extra in (other, other.replace("/var/log/", "/run/log/"),
                              other.replace("7868558e4bed47e98aa6f9fd64d292b3", "0" * 32),
                              other.replace("Entry objects: 10", "Entry objects: 0")):
                    with self.subTest(state=state, other_state=other_state, extra=extra), self.assertRaises(ValueError):
                        journal.journal_retained_range(current + extra)
            for other_state in ("ONLINE", "OFFLINE"):
                other = header(10, 19, 100, 200, state=other_state, filename="system@old.journal")
                with self.subTest(state=state, other_state=other_state), self.assertRaises(ValueError):
                    journal.journal_retained_range(other + current)

    def test_retained_range_rejects_empty_current_and_archived_only_inventories(self) -> None:
        archived = header(10, 19, 100, 200)
        empty_archive = header(0, 0, 0, 0).replace("Entry objects: 1", "Entry objects: 0")
        for inventory in ("", archived, empty_archive, archived + empty_archive):
            with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                journal.journal_retained_range(inventory)
        for state in ("ONLINE", "OFFLINE"):
            empty = header(0, 0, 0, 0, state=state).replace("Entry objects: 1", "Entry objects: 0")
            for inventory in (empty, archived + empty):
                with self.subTest(state=state, inventory=inventory), self.assertRaises(ValueError):
                    journal.journal_retained_range(inventory)
            current = header(20, 29, 201, 300, state=state)
            self.assertEqual(journal.journal_retained_range(empty_archive + current)["since_epoch"], 201)

    def test_retained_range_rejects_current_behind_or_overlapping_its_archive(self) -> None:
        for state in ("ONLINE", "OFFLINE"):
            current = header(20, 29, 201, 300, state=state)
            for archived in (header(10, 20, 100, 201), header(20, 29, 201, 300), header(30, 39, 301, 400)):
                with self.subTest(state=state, archived=archived), self.assertRaises(ValueError):
                    journal.journal_retained_range(archived + current)

    def test_retained_range_requires_valid_unique_active_inventory(self) -> None:
        active = header(10, 19, 100, 200, state="ONLINE")
        for value in (
            "", active.replace("Entry objects: 10", "Entry objects: 9"),
            active.replace("State: ONLINE", "State: ARCHIVED"), active + active,
            active.replace("7868558e4bed47e98aa6f9fd64d292b3", "invalid"),
            active * 129, active + "x" * 256_000,
        ):
            with self.subTest(value=value[:80]), self.assertRaises(ValueError):
                journal.journal_retained_range(value)

    def test_retained_range_rejects_malformed_offline_headers(self) -> None:
        current = EXIT_CURRENT_HEADER.replace("State: ONLINE", "State: OFFLINE")
        for old, new in (
            ("Entry objects: 1360", "Entry objects: -1"),
            ("Entry objects: 1360", "Entry objects: invalid"),
            ("Entry objects: 1360", "Entry objects: 1359"),
            ("Head sequential number: 5657490 (565392)\n", ""),
            ("Head sequential number: 5657490", "Head sequential number: 0"),
            ("State: OFFLINE\n", ""), ("State: OFFLINE", "State: UNKNOWN"),
            ("e8a8a771d6f8422cb662eb7b33d52683", "invalid"),
            ("(65d51ce11f8be)", "(0)"), ("(65d52cfdf0a31)", "(invalid)"),
            ("(65d52cfdf0a31)", "(65d51ce11f8bd)"),
        ):
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                journal.journal_retained_range(EXIT_PREVIOUS_HEADER + current.replace(old, new))

    def test_retained_range_does_not_cross_sequence_or_clock_discontinuity(self) -> None:
        for state in ("ONLINE", "OFFLINE"):
            active = header(20, 29, 201, 299, state=state)
            for previous in (
                header(10, 19, 100, 202),
                header(10, 19, 100, 200).replace("7868558e4bed47e98aa6f9fd64d292b3", "0" * 32),
                header(10, 19, 100, 200) * 2,
            ):
                with self.subTest(state=state, previous=previous):
                    self.assertEqual(journal.journal_retained_range(previous + active)["since_epoch"], 201)

    def test_offline_window_completeness_still_requires_retention_and_loss_evidence(self) -> None:
        inventory = header(10, 19, 100, 200) + header(30, 39, 300, 400, state="OFFLINE")
        for loss, complete in ((result(code=1), True), (result(record(350, "Suppressed 7 messages")), False),
                               (result("malformed"), False), (result(code=2, stderr="denied"), False)):
            with self.subTest(loss=loss):
                runner = Mock(side_effect=[result(record(350)), result(inventory), loss])
                snapshot = journal.kernel_event_snapshot(
                    runner=runner, pattern="table full", window_starts={"recent": 300, "gap": 150},
                    query_since=150, cutoff=400,
                )
                self.assertEqual(snapshot["observed_counts"], {"recent": 1, "gap": 1})
                self.assertEqual(snapshot["counts"], {"recent": 1 if complete else None, "gap": None})
                self.assertEqual(snapshot["windows"]["recent"]["scope"], "complete" if complete else "unavailable")
                self.assertEqual(snapshot["windows"]["gap"]["scope"], "unavailable")
                self.assertEqual(snapshot["coverage"]["since_epoch"], 300)
                self.assertEqual(runner.call_count, 3)

    def test_unavailable_current_keeps_zero_and_positive_totals_unknown(self) -> None:
        current = header(30, 39, 300, 400, state="OFFLINE")
        archived = header(10, 19, 100, 200)
        for inventory in ("", archived, current + current,
                          current.replace("Entry objects: 10", "Entry objects: 0"),
                          current.replace("State: OFFLINE", "State: ARCHIVED"),
                          current.replace("Entry objects: 10", "Entry objects: 9")):
            for events, observed in ((result(code=1), 0), (result(record(350)), 1)):
                with self.subTest(inventory=inventory, observed=observed):
                    runner = Mock(side_effect=[events, result(inventory)])
                    snapshot = journal.kernel_event_snapshot(
                        runner=runner, pattern="table full", window_starts={"recent": 300},
                        query_since=300, cutoff=400,
                    )
                    self.assertIsNone(snapshot["counts"]["recent"])
                    self.assertEqual(snapshot["observed_counts"]["recent"], observed)
                    self.assertEqual(snapshot["windows"]["recent"]["scope"], "unavailable")
                    self.assertTrue(snapshot["coverage"]["error"])
                    self.assertIsNone(snapshot["coverage"]["since_epoch"])
                    self.assertEqual(runner.call_count, 2)

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
