from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vpn_installer import resource_control


class ResourceControlTests(unittest.TestCase):
    @staticmethod
    def oom_coverage(now: datetime, **changes: object) -> dict[str, object]:
        return {
            "since_epoch": (now - timedelta(days=14)).timestamp(),
            "query_since_epoch": (now - timedelta(days=14)).timestamp(),
            "query_until_epoch": now.timestamp(), "discarded_at": [], "error": "", **changes,
        }

    def test_disk_usage_uses_allocated_blocks_for_sparse_files(self) -> None:
        sparse = SimpleNamespace(st_blocks=8, st_size=128 * resource_control.MIB)
        portable = SimpleNamespace(st_size=4096)

        self.assertEqual(resource_control._allocated_bytes(sparse), 4096)
        self.assertEqual(resource_control._allocated_bytes(portable), 4096)

    def test_router_budget_preserves_host_headroom_on_small_vps(self) -> None:
        total = 710 * resource_control.MIB
        limit = resource_control.router_go_memory_limit_bytes(total)

        self.assertEqual(limit, 326 * resource_control.MIB)
        self.assertGreaterEqual(total - limit, resource_control.ROUTER_RESERVED_MEMORY_BYTES)

    def test_effective_memory_honors_a_finite_cgroup_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            limit_path = Path(tmp) / "memory.max"
            limit_path.write_text(str(512 * resource_control.MIB), encoding="utf-8")
            self.assertEqual(
                resource_control.effective_memory_bytes(2 * 1024 * resource_control.MIB, limit_path),
                512 * resource_control.MIB,
            )
            limit_path.write_text("max", encoding="utf-8")
            self.assertEqual(resource_control.effective_memory_bytes(2 * 1024 * resource_control.MIB, limit_path), 2 * 1024 * resource_control.MIB)

    def test_exec_router_replaces_agent_with_budgeted_process(self) -> None:
        command = ["/opt/sing-box", "run"]
        with (
            patch.object(resource_control, "meminfo_snapshot", return_value={"MemTotal": 710 * resource_control.MIB}),
            patch.object(resource_control, "effective_memory_bytes", return_value=710 * resource_control.MIB),
            patch.object(resource_control.os, "execvpe") as execvpe,
        ):
            resource_control.exec_router(command)

        executable, arguments, environment = execvpe.call_args.args
        self.assertEqual(executable, command[0])
        self.assertEqual(arguments, command)
        self.assertEqual(environment["GOMEMLIMIT"], "326MiB")

    def test_low_memory_host_creates_bounded_swap_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meminfo = root / "meminfo"
            swaps = root / "swaps"
            swap = root / "state" / "swapfile"
            meminfo.write_text("MemTotal: 700000 kB\nSwapTotal: 0 kB\n", encoding="utf-8")
            swaps.write_text("Filename Type Size Used Priority\n", encoding="utf-8")

            def command(args: list[str], *, timeout: int = 30) -> None:
                del timeout
                if args[0] == "fallocate":
                    Path(args[-1]).write_bytes(b"\0" * 1024)

            with patch.object(resource_control, "_require_command", side_effect=command) as runner:
                result = resource_control.prepare_memory_reserve(
                    meminfo_path=meminfo,
                    swaps_path=swaps,
                    swap_path=swap,
                    swap_bytes=1024,
                )

            self.assertTrue(result["changed"])
            self.assertEqual([call.args[0][0] for call in runner.call_args_list], ["fallocate", "mkswap", "swapon"])
            if os.name != "nt":
                self.assertEqual(os.stat(swap).st_mode & 0o777, 0o600)

    def test_existing_system_swap_needs_no_managed_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meminfo = root / "meminfo"
            swaps = root / "swaps"
            meminfo.write_text("MemTotal: 700000 kB\nSwapTotal: 1048576 kB\n", encoding="utf-8")
            swaps.write_text("Filename Type Size Used Priority\n/swap.img file 1048576 0 -2\n", encoding="utf-8")
            with patch.object(resource_control, "_require_command") as runner:
                result = resource_control.prepare_memory_reserve(
                    meminfo_path=meminfo,
                    swaps_path=swaps,
                    swap_path=root / "managed-swap",
                )
            self.assertFalse(result["required"])
            runner.assert_not_called()

    def test_active_managed_swap_is_ready_despite_kernel_header_accounting(self) -> None:
        with (
            patch.object(
                resource_control,
                "meminfo_snapshot",
                return_value={
                    "MemTotal": 710 * resource_control.MIB,
                    "MemAvailable": 400 * resource_control.MIB,
                    "SwapTotal": resource_control.MANAGED_SWAP_BYTES - 4096,
                    "SwapFree": resource_control.MANAGED_SWAP_BYTES - 4096,
                },
            ),
            patch.object(resource_control, "active_swap_paths", return_value={str(resource_control.MANAGED_SWAP_PATH)}),
            patch.object(resource_control, "_service_resources", return_value={}),
        ):
            snapshot = resource_control.memory_runtime_snapshot()

        self.assertTrue(snapshot["reserve_required"])
        self.assertTrue(snapshot["reserve_ready"])
        self.assertTrue(snapshot["managed_swap_active"])

    def test_storage_maintenance_rotates_only_oversized_btmp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            btmp = root / "btmp"
            config = root / "btmp.conf"
            state = root / "state"
            btmp.write_bytes(b"x" * 65)
            config.write_text("/var/log/btmp {}\n", encoding="utf-8")
            with (
                patch.object(resource_control, "BTMP_PATH", btmp),
                patch.object(resource_control, "BTMP_LOGROTATE_CONFIG_PATH", config),
                patch.object(resource_control, "BTMP_LOGROTATE_STATE_PATH", state),
                patch.object(resource_control, "BTMP_ROTATE_BYTES", 64),
                patch.object(resource_control, "_require_command") as runner,
            ):
                result = resource_control.storage_maintenance({}, deep=False)
            self.assertEqual(result["actions"], ["btmp-rotated"])
            self.assertEqual(runner.call_args.args[0][0], "logrotate")

    def test_transaction_backup_snapshot_accounts_for_bounded_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            revisions = root / "revisions"
            baseline = root / "baseline"
            revisions.mkdir()
            baseline.mkdir()
            (revisions / "one").mkdir()
            (revisions / "two").mkdir()
            (revisions / "one" / "state").write_bytes(b"a" * 4096)
            (revisions / "two" / "state").write_bytes(b"b" * 4096)
            (baseline / "state").write_bytes(b"c" * 4096)
            with (
                patch.object(resource_control, "REVISION_BACKUPS_PATH", revisions),
                patch.object(resource_control, "BASELINE_BACKUP_PATH", baseline),
            ):
                snapshot = resource_control._transaction_backups_snapshot()

        self.assertEqual(snapshot["revision_count"], 2)
        self.assertGreater(snapshot["revision_bytes"], 0)
        self.assertGreater(snapshot["baseline_bytes"], 0)
        self.assertEqual(snapshot["bytes"], snapshot["revision_bytes"] + snapshot["baseline_bytes"])

    def test_oom_snapshot_preserves_recent_kernel_evidence(self) -> None:
        now = datetime.now(timezone.utc)
        record = {
            "__REALTIME_TIMESTAMP": str(int(now.timestamp() * 1_000_000)),
            "MESSAGE": "Out of memory: Killed process 42 (sing-box)",
        }
        completed = subprocess.CompletedProcess(["journalctl"], 0, json.dumps(record) + "\n", "")
        with patch.object(resource_control, "_run", return_value=completed):
            snapshot = resource_control._kernel_oom_snapshot(
                (now - timedelta(seconds=1)).isoformat(), coverage=self.oom_coverage(now), cutoff=now.timestamp(),
            )

        self.assertEqual(snapshot["counts"]["5m"], 1)
        self.assertEqual(snapshot["counts"]["since_release"], 1)
        self.assertIn("sing-box", snapshot["latest"]["message"])
        self.assertEqual(snapshot["latest_since_release"], snapshot["latest"])

    def test_oom_history_before_reinstall_stays_in_24h_but_not_since_release(self) -> None:
        now = datetime.now(timezone.utc)
        event_at = now - timedelta(hours=4)
        record = {
            "__REALTIME_TIMESTAMP": str(int(event_at.timestamp() * 1_000_000)),
            "MESSAGE": "Out of memory: Killed process 42 (sing-box)",
        }
        completed = subprocess.CompletedProcess(["journalctl"], 0, json.dumps(record) + "\n", "")
        with patch.object(resource_control, "_run", return_value=completed) as runner:
            snapshot = resource_control._kernel_oom_snapshot(now.isoformat(), coverage=self.oom_coverage(now), cutoff=now.timestamp())

        self.assertEqual(snapshot["counts"]["24h"], 1)
        self.assertEqual(snapshot["counts"]["since_release"], 0)
        self.assertEqual(snapshot["since_release_scope"], "complete")
        self.assertEqual(snapshot["latest_since_release"], {})
        query_since = datetime.fromisoformat(snapshot["query_since"])
        self.assertLessEqual(query_since, now - timedelta(hours=23, minutes=59))
        runner.assert_called_once()
        self.assertIn("_TRANSPORT=kernel", runner.call_args.args[0])
        self.assertNotIn("-k", runner.call_args.args[0])

    def test_shared_submicrosecond_cutoff_is_not_rounded_by_oom(self) -> None:
        for cutoff in (1789366998.4848592, 1789366998.4848588):
            evidence = {"since_epoch": 0, "query_since_epoch": cutoff - 86400,
                        "query_until_epoch": cutoff, "discarded_at": [], "error": ""}
            with self.subTest(cutoff=cutoff), patch.object(
                resource_control, "_run", return_value=subprocess.CompletedProcess([], 1, "", ""),
            ):
                snapshot = resource_control._kernel_oom_snapshot(
                    "2026-09-14T06:17:02Z", coverage=evidence, cutoff=cutoff,
                )
            self.assertEqual(snapshot["counts"], {"5m": 0, "30m": 0, "24h": 0, "since_release": 0})
            self.assertTrue(all(window["scope"] == "complete" for window in snapshot["windows"].values()))

    def test_oom_snapshot_treats_no_journal_matches_as_an_empty_result(self) -> None:
        now = datetime.now(timezone.utc)
        completed = subprocess.CompletedProcess(["journalctl"], 1, "", "")
        with patch.object(resource_control, "_run", return_value=completed):
            snapshot = resource_control._kernel_oom_snapshot(now.isoformat(), coverage=self.oom_coverage(now), cutoff=now.timestamp())

        self.assertEqual(snapshot["counts"]["30m"], 0)
        self.assertEqual(snapshot["collector_error"], "")

    def test_oom_release_before_retained_start_has_unknown_total_not_zero(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        retained = datetime(2026, 9, 11, tzinfo=timezone.utc).timestamp()
        installed = datetime(2026, 9, 9, tzinfo=timezone.utc)
        with patch.object(resource_control, "_run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            snapshot = resource_control._kernel_oom_snapshot(
                installed.isoformat(), coverage=self.oom_coverage(now, since_epoch=retained), cutoff=now.timestamp(),
            )
        self.assertIsNone(snapshot["counts"]["since_release"])
        self.assertEqual(snapshot["observed_counts"]["since_release"], 0)
        self.assertEqual(snapshot["since_release_scope"], "unavailable")
        self.assertIn("retained", snapshot["windows"]["since_release"]["coverage_error"])
        self.assertEqual(snapshot["counts"]["24h"], 0)

    def test_partial_oom_history_preserves_latest_since_release(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        event_at = now - timedelta(seconds=10)
        record = {"__REALTIME_TIMESTAMP": str(int(event_at.timestamp() * 1e6)), "MESSAGE": "Out of memory: Killed process 42 (sing-box)"}
        evidence = self.oom_coverage(now, since_epoch=(now - timedelta(minutes=1)).timestamp())
        with patch.object(resource_control, "_run", return_value=subprocess.CompletedProcess([], 0, json.dumps(record), "")):
            snapshot = resource_control._kernel_oom_snapshot((now - timedelta(days=5)).isoformat(), coverage=evidence, cutoff=now.timestamp())
        self.assertTrue(all(value is None for value in snapshot["counts"].values()))
        self.assertTrue(all(value == 1 for value in snapshot["observed_counts"].values()))
        self.assertEqual(snapshot["latest_since_release"]["timestamp"], event_at.isoformat())
        self.assertEqual(snapshot["latest_since_release"], snapshot["latest"])
        self.assertNotIn("epoch", snapshot["latest"])

    def test_oom_query_errors_are_unavailable_and_keep_valid_evidence(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        record = json.dumps({"__REALTIME_TIMESTAMP": str(int((now.timestamp() - 10) * 1e6)), "MESSAGE": "Out of memory: Killed process 42"})
        for response in (
            subprocess.CompletedProcess([], 2, "", "denied"),
            subprocess.CompletedProcess([], 1, "", "denied"),
            subprocess.CompletedProcess([], 0, record, "truncated journal"),
            subprocess.CompletedProcess([], 2, record, "partial failure"),
            subprocess.CompletedProcess([], 0, record + "\nbad JSON", ""),
        ):
            with self.subTest(response=response), patch.object(resource_control, "_run", return_value=response):
                snapshot = resource_control._kernel_oom_snapshot((now - timedelta(hours=1)).isoformat(), coverage=self.oom_coverage(now), cutoff=now.timestamp())
            self.assertTrue(all(value is None for value in snapshot["counts"].values()))
            self.assertTrue(snapshot["collector_error"])
            self.assertEqual(snapshot["observed_counts"]["30m"], int(bool(response.stdout)))
            self.assertEqual(bool(snapshot["latest_since_release"]), bool(response.stdout))

    def test_oom_fixed_cutoff_excludes_future_events(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        records = [json.dumps({"__REALTIME_TIMESTAMP": str(int((now.timestamp() + offset) * 1e6)), "MESSAGE": "Out of memory: Killed process 42"}) for offset in (-300, 0, 1)]
        with patch.object(resource_control, "_run", return_value=subprocess.CompletedProcess([], 0, "\n".join(records), "")) as runner:
            snapshot = resource_control._kernel_oom_snapshot((now - timedelta(minutes=10)).isoformat(), coverage=self.oom_coverage(now), cutoff=now.timestamp())
        self.assertEqual(snapshot["counts"]["5m"], 2)
        self.assertEqual(snapshot["latest"]["timestamp"], now.isoformat())
        self.assertEqual(snapshot["query_until"], now.isoformat())
        args = runner.call_args.args[0]
        self.assertEqual(args[args.index("--until") + 1], f"@{now.timestamp():.6f}")

    def test_oom_timeout_retains_positive_records_through_resource_runner(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        record = json.dumps({"__REALTIME_TIMESTAMP": str(int((now.timestamp() - 10) * 1e6)), "MESSAGE": "Out of memory: Killed process 42"})
        for output in (record, record.encode()):
            with self.subTest(output_type=type(output)), patch.object(
                resource_control.subprocess, "run", side_effect=subprocess.TimeoutExpired("journalctl", 20, output=output),
            ):
                snapshot = resource_control._kernel_oom_snapshot(
                    (now - timedelta(hours=1)).isoformat(), coverage=self.oom_coverage(now), cutoff=now.timestamp(),
                )
            self.assertIsNone(snapshot["counts"]["30m"])
            self.assertEqual(snapshot["observed_counts"]["30m"], 1)
            self.assertTrue(snapshot["latest_since_release"])
            self.assertIn("timed out", snapshot["collector_error"])

    def test_oom_default_cutoff_is_acquired_once(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        with patch.object(resource_control, "datetime", wraps=datetime) as clock, patch.object(
            resource_control, "_run", return_value=subprocess.CompletedProcess([], 1, "", ""),
        ):
            clock.now.return_value = now
            snapshot = resource_control._kernel_oom_snapshot(now.isoformat(), coverage=self.oom_coverage(now))
        clock.now.assert_called_once_with(timezone.utc)
        self.assertEqual(snapshot["query_until"], now.isoformat())

    def test_oom_old_release_is_query_limited_even_when_history_is_retained(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        evidence = self.oom_coverage(now, since_epoch=0, query_since_epoch=0)
        with patch.object(resource_control, "_run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            snapshot = resource_control._kernel_oom_snapshot((now - timedelta(days=15)).isoformat(), coverage=evidence, cutoff=now.timestamp())
        self.assertIsNone(snapshot["counts"]["since_release"])
        self.assertIn("collected journal interval", snapshot["windows"]["since_release"]["coverage_error"])
        self.assertEqual(datetime.fromisoformat(snapshot["query_since"]), now - timedelta(days=14))

    def test_oom_invalid_or_future_release_does_not_claim_complete_zero(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        for installed in ("", "invalid", (now + timedelta(seconds=1)).isoformat()):
            with self.subTest(installed=installed), patch.object(resource_control, "_run", return_value=subprocess.CompletedProcess([], 1, "", "")):
                snapshot = resource_control._kernel_oom_snapshot(installed, coverage=self.oom_coverage(now), cutoff=now.timestamp())
            self.assertIsNone(snapshot["counts"]["since_release"])
            self.assertIsNone(snapshot["observed_counts"]["since_release"])
            self.assertEqual(snapshot["latest_since_release"], {})
            self.assertEqual(snapshot["counts"]["30m"], 0)

    def test_oom_missing_or_narrow_coverage_cannot_certify_counts(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        for evidence in ({}, self.oom_coverage(now, query_since_epoch=now.timestamp() - 300)):
            with self.subTest(evidence=evidence), patch.object(resource_control, "_run", return_value=subprocess.CompletedProcess([], 1, "", "")):
                snapshot = resource_control._kernel_oom_snapshot((now - timedelta(days=1)).isoformat(), coverage=evidence, cutoff=now.timestamp())
            self.assertIsNone(snapshot["counts"]["30m"])
            self.assertEqual(snapshot["observed_counts"]["30m"], 0)

    def test_storage_snapshot_forwards_acquired_coverage_and_cutoff(self) -> None:
        now = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
        evidence = self.oom_coverage(now)
        with ExitStack() as stack:
            for name in ("_disk_capacity_snapshot", "_managed_releases_snapshot", "_transaction_backups_snapshot", "memory_runtime_snapshot"):
                stack.enter_context(patch.object(resource_control, name, return_value={}))
            stack.enter_context(patch.object(resource_control, "path_tree_disk_usage", return_value=0))
            stack.enter_context(patch.object(Path, "glob", return_value=[]))
            oom = stack.enter_context(patch.object(resource_control, "_kernel_oom_snapshot", return_value={"counts": {"30m": None}}))
            snapshot = resource_control.storage_snapshot({}, now.isoformat(), coverage=evidence, cutoff=now.timestamp())
        oom.assert_called_once_with(now.isoformat(), coverage=evidence, cutoff=now.timestamp())
        self.assertEqual(snapshot["runtime_events"]["oom_kills"], oom.return_value)


if __name__ == "__main__":
    unittest.main()
