from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.common import (
    AppError,
    command_exists,
    ensure_directories,
    env_line,
    parse_env_value,
    run_command,
    sanitize_name,
    shell_env_quote,
    write_json,
)


class CommonTests(unittest.TestCase):
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

    def test_ensure_directories_creates_runtime_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with patch("vpn_installer.common.DEPLOYMENTS_DIR", base / "deployments"), patch("vpn_installer.common.STATE_DIR", base / "state"), patch("vpn_installer.common.OUT_DIR", base / "out"), patch("vpn_installer.common.RUNTIME_DIR", base / ".runtime"), patch("vpn_installer.common.RUNTIME_SITE_PACKAGES", base / ".runtime" / "python-packages"):
                ensure_directories()
            self.assertTrue((base / "deployments").is_dir())
            self.assertTrue((base / ".runtime" / "python-packages").is_dir())


if __name__ == "__main__":
    unittest.main()
