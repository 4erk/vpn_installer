from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import contextmanager, nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from vpn_installer.audit import docker, runner as audit_runner, xray_dns
from vpn_installer.audit.runner import AuditFailure, AuditRunner


class XrayDnsAuditTests(unittest.TestCase):
    def test_release_download_verifies_archive_and_binary_then_reuses_cache(self):
        binary = b"fixture-binary"
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("xray", binary)
        data = bundle.getvalue()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = Mock(work_dir=root / "work")

            def download(_name, command, **_kwargs):
                Path(command[-1]).write_bytes(data)

            runner.run_command.side_effect = download
            with patch.object(xray_dns, "AUDIT_ROOT", root), \
                 patch.object(xray_dns, "XRAY_LINUX_AMD64_SHA256", hashlib.sha256(data).hexdigest()), \
                 patch.object(xray_dns, "XRAY_LINUX_AMD64_BINARY_SHA256", hashlib.sha256(binary).hexdigest()):
                result = xray_dns.ensure_xray_binary(runner)
                self.assertEqual(result.read_bytes(), binary)
                self.assertEqual(xray_dns.ensure_xray_binary(runner), result)
            runner.run_command.assert_called_once()
            self.assertEqual(runner.run_command.call_args.kwargs["timeout_seconds"], 65)
            self.assertIn("--max-time", runner.run_command.call_args.args[1])

    def test_corrupt_cache_is_not_used_or_silently_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "binaries" / f"xray-{xray_dns.XRAY_LINUX_AMD64_BINARY_SHA256}"
            cache.parent.mkdir()
            cache.write_bytes(b"wrong")
            runner = Mock(work_dir=root / "work")
            with patch.object(xray_dns, "AUDIT_ROOT", root), self.assertRaisesRegex(AuditFailure, "cached.*hash mismatch"):
                xray_dns.ensure_xray_binary(runner)
            runner.run_command.assert_not_called()

    def test_wrong_archive_or_binary_fails_before_cache_publication(self):
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("xray", b"wrong-binary")
        data = bundle.getvalue()
        for archive_hash, message in (("wrong", "archive hash"), (hashlib.sha256(data).hexdigest(), "binary hash")):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                runner = Mock(work_dir=root / "work")
                runner.run_command.side_effect = lambda _name, command, **_kwargs: Path(command[-1]).write_bytes(data)
                with patch.object(xray_dns, "AUDIT_ROOT", root), \
                     patch.object(xray_dns, "XRAY_LINUX_AMD64_SHA256", archive_hash), \
                     self.assertRaisesRegex(AuditFailure, message):
                    xray_dns.ensure_xray_binary(runner)
                self.assertFalse((root / "binaries").exists())

    def test_runtime_is_network_isolated_bounded_and_failure_cleans_up(self):
        for failure in (False, True):
            with self.subTest(failure=failure):
                cleaned = []

                @contextmanager
                def container(*_args, **_kwargs):
                    try:
                        yield "owned-container"
                    finally:
                        cleaned.append(True)

                runner = Mock(run_id="fixture")
                runner.docker.return_value = subprocess.CompletedProcess([], 0, "sha256:base")
                runner.docker_container.side_effect = container
                runner.docker_exec.side_effect = [None, AuditFailure("runtime failed") if failure else Mock(stdout=json.dumps({"status": "passed"}))]
                with patch.object(xray_dns, "ensure_xray_binary", return_value=Path("pinned-xray")), \
                     self.assertRaisesRegex(AuditFailure, "runtime failed") if failure else nullcontext():
                    xray_dns.test_xray_dns_port(runner)
                self.assertEqual(cleaned, [True])
                self.assertEqual(runner.docker_container.call_args.kwargs["network"], "none")
                self.assertEqual(runner.docker_container.call_args.kwargs["extra_args"], ["--cap-drop=ALL"])
                self.assertEqual(runner.docker_exec.call_args.kwargs["timeout_seconds"], 20)

    def test_probe_failure_marks_registered_full_docker_gate_failed(self):
        registered = {}
        fake = Mock()
        fake.record.side_effect = lambda name, fn: registered.update({name: fn})
        with patch.object(docker, "test_xray_dns_port", side_effect=AuditFailure("DNS runtime failed")):
            docker.run(fake)
            self.assertIn("docker-xray-dns-port", registered)
            with tempfile.TemporaryDirectory() as temporary, patch.object(audit_runner, "AUDIT_ROOT", Path(temporary)), patch("sys.stdout", new_callable=io.StringIO):
                runner = AuditRunner("docker")
                runner.record("docker-xray-dns-port", registered["docker-xray-dns-port"])
                self.assertEqual(runner.exit_code, 1)
                self.assertEqual(runner.results[0].status, "failed")


if __name__ == "__main__":
    unittest.main()
