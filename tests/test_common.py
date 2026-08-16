from __future__ import annotations

import subprocess
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.common import (
    AppError,
    cli_command,
    cli_entrypoint,
    command_exists,
    ensure_directories,
    env_line,
    error_summary,
    parse_env_value,
    run_command,
    sanitize_name,
    shell_env_quote,
    write_json,
    write_private_json,
    write_private_text,
)


class CommonTests(unittest.TestCase):
    def test_cli_entrypoint_is_platform_specific(self) -> None:
        self.assertEqual(cli_entrypoint("nt"), r".\vpn.cmd")
        self.assertEqual(cli_entrypoint("posix"), "./vpn.sh")
        self.assertEqual(cli_command("status", platform_name="nt"), r".\vpn.cmd status")

    def test_error_summary_returns_one_bounded_line(self) -> None:
        self.assertEqual(error_summary(AppError("short reason\ntechnical detail")), "short reason")
        self.assertEqual(error_summary(AppError("x" * 20), max_length=10), "xxxxxxx...")

    def test_sanitize_name_replaces_invalid_chars(self) -> None:
        self.assertEqual(sanitize_name("my vpn/01"), "my-vpn-01")

    def test_shell_env_quote_escapes_backslashes_and_quotes(self) -> None:
        self.assertEqual(shell_env_quote('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(env_line("KEY", 'a"b'), 'KEY="a\\"b"')

    def test_parse_env_value_supports_plain_and_quoted_values(self) -> None:
        self.assertEqual(parse_env_value("plain"), "plain")
        self.assertEqual(parse_env_value('"quoted value"'), "quoted value")
        with self.assertRaises(AppError):
            parse_env_value('"unterminated')

    def test_command_exists_uses_shutil_which(self) -> None:
        with patch("vpn_installer.common.shutil.which", return_value="C:/bin/demo.exe"):
            self.assertTrue(command_exists("demo"))

    def test_run_command_success_with_capture(self) -> None:
        completed = subprocess.CompletedProcess(["echo"], 0, stdout="ok", stderr="")
        with patch("vpn_installer.common.subprocess.run", return_value=completed) as mocked:
            result = run_command(["echo", "ok"], capture_output=True, input_text="x")
        self.assertEqual(result.stdout, "ok")
        mocked.assert_called_once()

    def test_run_command_can_stream_stdout_while_capturing_stderr(self) -> None:
        completed = subprocess.CompletedProcess(["demo"], 0, stdout=None, stderr="diagnostic")
        with patch("vpn_installer.common.subprocess.run", return_value=completed) as mocked:
            result = run_command(["demo"], capture_stderr=True)
        self.assertEqual(result.stderr, "diagnostic")
        self.assertIsNone(mocked.call_args.kwargs["stdout"])
        self.assertIs(mocked.call_args.kwargs["stderr"], subprocess.PIPE)

    def test_run_command_raises_on_missing_binary(self) -> None:
        with patch("vpn_installer.common.subprocess.run", side_effect=FileNotFoundError()):
            with self.assertRaises(AppError):
                run_command(["missing"])

    def test_run_command_raises_with_stderr_detail(self) -> None:
        completed = subprocess.CompletedProcess(["demo"], 7, stdout="", stderr="boom")
        with patch("vpn_installer.common.subprocess.run", return_value=completed):
            with self.assertRaises(AppError) as ctx:
                run_command(["demo"], capture_output=True)
        self.assertIn("boom", str(ctx.exception))

    def test_run_command_raises_with_exit_code_without_output(self) -> None:
        completed = subprocess.CompletedProcess(["demo"], 3, stdout="", stderr="")
        with patch("vpn_installer.common.subprocess.run", return_value=completed):
            with self.assertRaises(AppError) as ctx:
                run_command(["demo"], capture_output=True)
        self.assertIn("код 3", str(ctx.exception))

    def test_run_command_raises_on_timeout_with_partial_output(self) -> None:
        error = subprocess.TimeoutExpired(["demo"], timeout=2, output="partial", stderr="")
        with patch("vpn_installer.common.subprocess.run", side_effect=error):
            with self.assertRaises(AppError) as ctx:
                run_command(["demo"], capture_output=True, timeout=2)
        self.assertIn("не завершилась за 2 сек", str(ctx.exception))
        self.assertIn("partial", str(ctx.exception))

    def test_write_json_creates_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "data.json"
            write_json(path, {"ok": True})
            self.assertTrue(path.is_file())
            self.assertIn('"ok": true', path.read_text(encoding="utf-8"))

    def test_write_private_text_is_atomic_and_owner_only_on_posix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "secret.txt"
            write_private_text(path, "first\n")
            write_private_text(path, "second\n")
            self.assertEqual(path.read_text(encoding="utf-8"), "second\n")
            self.assertEqual(list(path.parent.glob(f".{path.name}.*")), [])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_write_private_json_uses_the_same_private_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            write_private_json(path, {"secret": "value"})
            self.assertEqual(__import__("json").loads(path.read_text(encoding="utf-8")), {"secret": "value"})
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_ensure_directories_creates_runtime_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with patch("vpn_installer.common.DEPLOYMENTS_DIR", base / "deployments"), patch("vpn_installer.common.STATE_DIR", base / "state"), patch("vpn_installer.common.OUT_DIR", base / "out"), patch("vpn_installer.common.RUNTIME_DIR", base / ".runtime"), patch("vpn_installer.common.RUNTIME_SITE_PACKAGES", base / ".runtime" / "python-packages"):
                ensure_directories()
            self.assertTrue((base / "deployments").is_dir())
            self.assertTrue((base / ".runtime" / "python-packages").is_dir())


if __name__ == "__main__":
    unittest.main()
