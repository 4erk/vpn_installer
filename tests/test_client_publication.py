from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import client_publication as publication
from vpn_installer.models import AppError


_ROOT = str(Path(__file__).resolve().parents[1])
_CHILD = r"""
import os,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from vpn_installer import client_publication as p
client=Path(sys.argv[2]);point=sys.argv[3]
def checkpoint(name):
    if name==point:
        print('READY',flush=True)
        time.sleep(60)
p._checkpoint=checkpoint
with p.publication_lock(client):
    p.publish_locked(client,{'vless-uri.txt':'NEW\n','alias.txt':'NEW\n','NEXT-STEPS.txt':'NEW\n'},())
"""


class ClientPublicationTests(unittest.TestCase):
    def test_dangling_retired_pointer_is_removed_by_publication_not_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            old = self.publish(client, "OLD")
            stale = old / "retired"
            missing = Path(tmp) / "absent"
            if os.name == "nt":
                stale.mkdir()
                publication._set_junction(stale, missing)
            else:
                stale.symlink_to(missing, target_is_directory=True)
            self.assertTrue(os.path.lexists(stale))
            with publication.publication_lock(client):
                new = publication.publish_locked(client, self.payloads("OLD"), ("retired",))
            self.assertNotEqual(new, old)
            self.assertFalse(os.path.lexists(client / "retired"))

    def test_unchanged_render_reuses_generation_even_at_retention_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            first = self.publish(client, "OLD")
            (first / "operator.txt").write_text("current note")
            with patch.object(publication, "MAX_GENERATIONS", 1), patch.object(publication, "_activate") as switch:
                self.assertEqual(self.publish(client, "OLD"), first)
                switch.assert_not_called()
            self.assertEqual(len(list((client.parent / publication.GENERATIONS).iterdir())), 1)
            self.assertEqual((first / "operator.txt").read_text(), "current note")

    def payloads(self, label: str) -> dict[str, str]:
        return {name: label + "\n" for name in ("vless-uri.txt", "alias.txt", "NEXT-STEPS.txt")}

    def publish(self, client: Path, label: str) -> Path:
        client.parent.mkdir(parents=True, exist_ok=True)
        with publication.publication_lock(client):
            return publication.publish_locked(client, self.payloads(label), ())

    def assert_set(self, client: Path, label: str) -> None:
        with publication.snapshot(client) as pinned:
            for name, value in self.payloads(label).items():
                self.assertEqual((pinned / name).read_text(encoding="utf-8"), value)

    def test_native_switch_retains_open_file_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            old = self.publish(client, "OLD")
            with publication.snapshot(client) as pinned, (client / "vless-uri.txt").open() as old_file:
                self.publish(client, "NEW")
                self.assertEqual(old_file.read(), "OLD\n")
                self.assertEqual(pinned, old)
                self.assertEqual((pinned / "alias.txt").read_text(), "OLD\n")
            self.assert_set(client, "NEW")

    def test_unpinned_multi_file_reader_can_mix_generations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            self.publish(client, "OLD")
            first = (client / "vless-uri.txt").read_text()
            self.publish(client, "NEW")
            second = (client / "alias.txt").read_text()
            self.assertEqual((first, second), ("OLD\n", "NEW\n"))

    def test_real_native_switches_with_concurrent_pinned_readers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            old = self.publish(client, "OLD")
            new = self.publish(client, "NEW")
            stop = threading.Event()
            failures: list[str] = []
            reads = [0, 0]

            def reader(index: int) -> None:
                while not stop.is_set():
                    try:
                        with publication.snapshot(client) as pinned:
                            values = [(pinned / name).read_text() for name in self.payloads("OLD")]
                        if len(set(values)) != 1 or values[0] not in {"OLD\n", "NEW\n"}:
                            failures.append(repr(values))
                        reads[index] += 1
                    except Exception as exc:
                        failures.append(repr(exc))

            workers = [threading.Thread(target=reader, args=(i,)) for i in range(2)]
            for worker in workers:
                worker.start()
            try:
                for index in range(300):
                    publication._activate(client, (old, new)[index % 2])
            finally:
                stop.set()
                for worker in workers:
                    worker.join(timeout=10)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertGreater(sum(reads), 0)
            self.assertEqual(failures, [])

    def test_legacy_migration_preserves_bytes_and_stable_operator_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            client.mkdir()
            for name, value in self.payloads("OLD").items():
                (client / name).write_text(value)
            state = b'{\r\n  "Routes": [{"owned": true}]\r\n}\r\n'
            (client / publication.ROUTE_STATE).write_bytes(state)
            (client / "operator.txt").write_bytes(b"operator\r\nnotes\r\n")
            self.publish(client, "NEW")
            self.assert_set(client, "NEW")
            self.assertEqual((client / "operator.txt").read_bytes(), b"operator\r\nnotes\r\n")
            stable = client.parent / publication.STATE_DIRECTORY / publication.ROUTE_STATE
            self.assertEqual(stable.read_bytes(), state)
            legacy = list(client.parent.glob(".client-legacy-*"))
            self.assertEqual(len(legacy), 1)
            self.assertEqual((legacy[0] / publication.ROUTE_STATE).read_bytes(), state)
            stable.write_bytes(b'{"Routes": ["latest"]}')
            self.publish(client, "NEWER")
            self.assertEqual(stable.read_bytes(), b'{"Routes": ["latest"]}')

    def test_rollback_keeps_latest_operator_state_and_notes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            old = self.publish(client, "OLD")
            self.publish(client, "NEW")
            (client / "operator.txt").write_bytes(b"new operator note")
            stable = client.parent / publication.STATE_DIRECTORY / publication.ROUTE_STATE
            stable.write_bytes(b'{"owned": "new route"}')
            restored = publication.rollback(client, old)
            self.assertNotEqual(restored, old)
            self.assert_set(client, "OLD")
            self.assertEqual((client / "operator.txt").read_bytes(), b"new operator note")
            self.assertEqual(stable.read_bytes(), b'{"owned": "new route"}')

    def test_conflicting_state_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            client.mkdir()
            (client / publication.ROUTE_STATE).write_bytes(b"legacy")
            stable = client.parent / publication.STATE_DIRECTORY
            stable.mkdir()
            (stable / publication.ROUTE_STATE).write_bytes(b"foreign")
            with self.assertRaisesRegex(AppError, "conflicts"):
                self.publish(client, "NEW")
            self.assertFalse(publication._is_link(client))
            self.assertEqual((stable / publication.ROUTE_STATE).read_bytes(), b"foreign")
            self.assertEqual((client / publication.ROUTE_STATE).read_bytes(), b"legacy")

    @unittest.skipUnless(os.name == "nt", "case-insensitive NTFS names")
    def test_native_casevariant_legacy_artifacts_cannot_overwrite_rendered_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            client.mkdir()
            (client / "VLESS-URI.TXT").write_text("OLD\n")
            (client / "ALIAS.TXT").write_text("OLD\n")
            (client / "NEXT-STEPS.TXT").write_text("OLD\n")
            (client / "Operator-Notes.TXT").write_bytes(b"keep")
            self.publish(client, "NEW")
            self.assert_set(client, "NEW")
            self.assertEqual((client / "Operator-Notes.TXT").read_bytes(), b"keep")

    def test_post_copy_verification_uses_rendered_bytes_not_copied_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            self.publish(client, "OLD")
            original_copy = publication._copy_operator

            def corrupt(source, destination, excluded, budget):
                original_copy(source, destination, excluded, budget)
                (destination / "vless-uri.txt").write_text("CORRUPTED\n")

            with patch.object(publication, "_copy_operator", corrupt):
                with self.assertRaisesRegex(AppError, "Incomplete client generation"):
                    self.publish(client, "NEW")
            self.assert_set(client, "OLD")

    def test_retention_and_size_limits_leave_current_generation_usable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            self.publish(client, "OLD")
            with patch.object(publication, "MAX_GENERATIONS", 1):
                with self.assertRaisesRegex(AppError, "retention limit"):
                    self.publish(client, "NEW")
            with patch.object(publication, "MAX_GENERATION_BYTES", 1):
                with self.assertRaisesRegex(AppError, "exceeds"):
                    self.publish(client, "NEW")
            self.assert_set(client, "OLD")

    def test_real_0228_root_instructions_after_killed_legacy_migration(self) -> None:
        from vpn_installer.client_artifacts import client_artifact_snapshot

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = root / "demo" / "client"
            client.mkdir(parents=True)
            (client / "vless-uri.txt").write_text("LEGACY-URI\n")
            (client.parent / "NEXT-STEPS.txt").write_text("LEGACY-INSTRUCTIONS\n")
            process = subprocess.Popen([sys.executable, "-B", "-u", "-c", _CHILD, _ROOT, str(client), "legacy-moved"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ready: list[str] = []
            reader = threading.Thread(target=lambda: ready.append(process.stdout.readline()), daemon=True)
            reader.start()
            try:
                reader.join(timeout=15)
                self.assertFalse(reader.is_alive())
                self.assertEqual(ready, ["READY\n"])
                process.kill()
                process.communicate(timeout=10)
                self.assertFalse(client.exists())
                with client_artifact_snapshot({"DEPLOY_NAME": "demo"}, out_dir=root) as paths:
                    self.assertEqual(paths["vless_uri"].read_text(), "LEGACY-URI\n")
                    self.assertEqual(paths["next_steps"].read_text(), "LEGACY-INSTRUCTIONS\n")
                self.assertFalse(client.exists(), "read path must not silently repair migration")
                with publication.publication_lock(client):
                    publication.recover_locked(client)
                self.assertEqual((client / "vless-uri.txt").read_text(), "LEGACY-URI\n")
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=10)
                reader.join(timeout=5)

    def test_failed_recovery_retains_durable_journal_and_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "client"
            client.mkdir()
            (client / "vless-uri.txt").write_text("OLD\n")

            def interrupt(point: str) -> None:
                if point == "legacy-moved":
                    raise OSError("interrupt")

            with patch.object(publication, "_checkpoint", interrupt), patch.object(publication, "recover_locked", side_effect=[None, OSError("recovery failed")]):
                with self.assertRaisesRegex(OSError, "recovery failed"):
                    self.publish(client, "NEW")
            self.assertTrue((client.parent / publication.JOURNAL).is_file())
            self.assertFalse(client.exists())
            with publication.snapshot(client) as selected:
                self.assertEqual((selected / "vless-uri.txt").read_text(), "OLD\n")
            with publication.publication_lock(client):
                publication.recover_locked(client)
            self.assertEqual((client / "vless-uri.txt").read_text(), "OLD\n")

    def test_unsafe_journal_and_foreign_pointer_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = root / "client"
            self.publish(client, "OLD")
            before = publication._pointer_target(client)
            (root / publication.JOURNAL).write_text(json.dumps({"target": "../foreign", "legacy": "", "previous": ""}))
            with self.assertRaisesRegex(AppError, "Unsafe"):
                self.publish(client, "NEW")
            self.assertEqual(publication._pointer_target(client), before)
            (root / publication.JOURNAL).unlink()
            foreign = root / "foreign"
            foreign.mkdir()
            (foreign / "keep").write_bytes(b"untouched")
            if os.name == "nt":
                publication._set_junction(client, foreign)
            else:
                client.unlink()
                client.symlink_to(foreign)
            with self.assertRaisesRegex(AppError, "escapes"):
                self.publish(client, "NEW")
            self.assertEqual((foreign / "keep").read_bytes(), b"untouched")

    def test_process_kill_at_every_boundary_and_restart(self) -> None:
        points = [*("staged:" + name for name in self.payloads("NEW")), "generation-ready", "journal-ready",
                  "before-switch", "pointer-set", "after-switch", "before-journal-clear"]
        for legacy in (False, True):
            for point in [*points, *(["legacy-moved"] if legacy else [])]:
                with self.subTest(legacy=legacy, point=point), tempfile.TemporaryDirectory() as tmp:
                    client = Path(tmp) / "client"
                    if legacy:
                        client.mkdir()
                        for name, value in self.payloads("OLD").items():
                            (client / name).write_text(value)
                    else:
                        self.publish(client, "OLD")
                    process = subprocess.Popen([sys.executable, "-B", "-u", "-c", _CHILD, _ROOT, str(client), point],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    ready: list[str] = []
                    reader = threading.Thread(target=lambda: ready.append(process.stdout.readline()), daemon=True)
                    reader.start()
                    try:
                        reader.join(timeout=15)
                        self.assertFalse(reader.is_alive(), "child checkpoint timeout")
                        self.assertEqual(ready, ["READY\n"])
                        process.kill()
                        process.communicate(timeout=10)
                        # On first NTFS activation pointer-set occurs while the
                        # prepared junction still has its temporary name.
                        committed = point in {"after-switch", "before-journal-clear"} or (point == "pointer-set" and not (legacy and os.name == "nt"))
                        if client.exists():
                            self.assert_set(client, "NEW" if committed else "OLD")
                        else:
                            self.assertTrue(legacy)
                            self.assertTrue((client.parent / publication.JOURNAL).is_file())
                        with publication.publication_lock(client):
                            publication.recover_locked(client)
                        self.assert_set(client, "NEW" if committed else "OLD")
                        self.publish(client, "RECOVERED")
                        self.assert_set(client, "RECOVERED")
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=10)
                        reader.join(timeout=5)

    @unittest.skipUnless(os.name == "nt", "NTFS junction contract")
    def test_windows_nonempty_directory_is_not_atomically_convertible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = root / "client"
            client.mkdir()
            (client / "vless-uri.txt").write_text("OLD")
            target = root / "new"
            target.mkdir()
            with self.assertRaises(OSError) as raised:
                publication._set_junction(client, target)
            self.assertEqual(raised.exception.winerror, 145)
            self.assertEqual((client / "vless-uri.txt").read_text(), "OLD")


if __name__ == "__main__":
    unittest.main()
