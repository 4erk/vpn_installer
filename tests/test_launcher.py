from __future__ import annotations

import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from vpn_installer import launcher
from vpn_installer.models import AppError, UserCancelled


class LauncherTests(unittest.TestCase):
    def test_launcher_returns_success_code(self) -> None:
        with patch("vpn_installer.launcher.main", return_value=0):
            self.assertEqual(launcher.run(["status"]), 0)

    def test_launcher_returns_130_on_user_cancelled(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=UserCancelled("cancelled")):
            self.assertEqual(launcher.run(["install"]), 130)

    def test_launcher_returns_130_on_keyboard_interrupt(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=KeyboardInterrupt()):
            self.assertEqual(launcher.run(["install"]), 130)

    def test_launcher_returns_1_on_eof(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=EOFError()), patch("vpn_installer.launcher.log_exception", return_value=Path("out/logs/runtime/error.log")), patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["install"]), 1)
        self.assertIn(str(Path("out/logs/runtime/error.log")), stream.getvalue())

    def test_launcher_returns_1_on_app_error(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=AppError("boom")), patch("vpn_installer.launcher.log_exception", return_value=Path("out/logs/runtime/error.log")), patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["install"]), 1)
        self.assertIn("Ошибка: boom", stream.getvalue())
        self.assertIn(str(Path("out/logs/runtime/error.log")), stream.getvalue())

    def test_launcher_hides_multiline_technical_detail(self) -> None:
        error = AppError("Краткая причина\nOpenSSH debug detail")
        with patch("vpn_installer.launcher.main", side_effect=error), patch("vpn_installer.launcher.log_exception", return_value=Path("out/logs/runtime/error.log")) as log_mock, patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["status"]), 1)
        self.assertIn("Ошибка: Краткая причина", stream.getvalue())
        self.assertNotIn("OpenSSH debug detail", stream.getvalue())
        self.assertIs(log_mock.call_args.args[1], error)

    def test_launcher_returns_1_on_unhandled_error_and_mentions_log(self) -> None:
        with patch("vpn_installer.launcher.main", side_effect=RuntimeError("boom")), patch("vpn_installer.launcher.log_exception", return_value=Path("out/logs/runtime/error.log")), patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["install"]), 1)
        self.assertIn("Непредвиденная ошибка: boom", stream.getvalue())
        self.assertIn(str(Path("out/logs/runtime/error.log")), stream.getvalue())

    def test_launcher_does_not_log_audit_failure_to_runtime_log(self) -> None:
        AuditFailure = type("AuditFailure", (RuntimeError,), {})
        AuditFailure.__module__ = "vpn_installer.audit.runner"
        with patch("vpn_installer.launcher.main", side_effect=AuditFailure("Не найдена команда: docker")), patch("vpn_installer.launcher.log_exception") as log_mock, patch("sys.stderr", new_callable=StringIO) as stream:
            self.assertEqual(launcher.run(["audit", "quick"]), 1)
        log_mock.assert_not_called()
        self.assertIn("Самопроверка завершилась с ошибкой", stream.getvalue())


@unittest.skipUnless(os.name == "nt", "Windows launcher subprocess")
class WindowsLauncherTests(unittest.TestCase):
    def test_piped_cmd_streams_progress_before_python_exits(self) -> None:
        for outcome, exit_code in (("success", 0), ("failure", 7), ("cancel", 130), ("error", 1)):
            with self.subTest(outcome=outcome):
                self.check_piped_cmd(outcome, exit_code)

    def check_piped_cmd(self, outcome: str, exit_code: int) -> None:
        root = Path(__file__).resolve().parents[1]
        runtime = root / ".runtime" / "python" / "windows"
        if not (runtime / "python.exe").is_file():
            self.skipTest("Repository embedded Windows Python is unavailable")
        with tempfile.TemporaryDirectory(prefix="vpn launcher ") as temporary:
            copied = Path(temporary)
            for name in ("vpn.cmd", "vpn.ps1"):
                shutil.copy2(root / name, copied / name)
            package = copied / "vpn_installer"
            package.mkdir()
            for name in ("__init__.py", "launcher.py", "common.py", "error_logging.py", "models.py", "topology.py"):
                shutil.copy2(root / "vpn_installer" / name, package / name)
            portable = copied / ".runtime" / "python" / "windows"
            portable.mkdir(parents=True)
            # Copy only the embedded runtime, never installed packages or live VPN state.
            for path in runtime.iterdir():
                if path.is_file():
                    shutil.copy2(path, portable / path.name)
            (package / "cli.py").write_text(
                "import time\n"
                "from pathlib import Path\n"
                "from .models import AppError\n"
                "def main(argv):\n"
                "    root = Path(__file__).resolve().parents[1]\n"
                "    print('CLI03_PROGRESS')\n"
                "    (root / 'ready').touch()\n"
                "    deadline = time.monotonic() + 30\n"
                "    while not (root / 'release').exists():\n"
                "        if time.monotonic() >= deadline:\n"
                "            return 99\n"
                "        time.sleep(0.01)\n"
                "    (root / 'finished').touch()\n"
                "    if argv == ['error']:\n"
                "        raise AppError('Concise failure\\nCLI03_PRIVATE_DETAIL')\n"
                "    print('CLI03_FINISHED')\n"
                "    return {'success': 0, 'failure': 7, 'cancel': 130}[argv[0]]\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.pop("PYTHONUNBUFFERED", None)
            env.pop("VPN_WINDOWS_ENTRYPOINT", None)
            env["VPN_NO_PAUSE"] = "1"
            child = subprocess.Popen(
                [env.get("COMSPEC", "cmd.exe"), "/d", "/c", "vpn.cmd", outcome],
                cwd=copied, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, errors="replace",
            )
            messages: queue.Queue[str] = queue.Queue()
            output: list[str] = []

            def read_output() -> None:
                for line in child.stdout:
                    output.append(line)
                    messages.put(line.strip())

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            try:
                deadline = time.monotonic() + 15
                while not (copied / "ready").exists():
                    self.assertIsNone(child.poll(), "".join(output))
                    self.assertLess(time.monotonic(), deadline, "Python fixture did not start: " + "".join(output))
                    time.sleep(0.01)
                try:
                    self.assertEqual(messages.get(timeout=5), "CLI03_PROGRESS")
                except queue.Empty:
                    self.fail("Piped vpn.cmd buffered progress while Python was waiting for release")
                self.assertIsNone(child.poll())
                self.assertFalse((copied / "finished").exists())
                (copied / "release").touch()
                # Keep stdin open: VPN_NO_PAUSE must allow exit without another input.
                self.assertEqual(child.wait(timeout=15), exit_code)
                reader.join(timeout=5)
                self.assertFalse(reader.is_alive())
                console = "".join(output)
                self.assertEqual(console.count("CLI03_PROGRESS"), 1)
                self.assertNotIn("CLI03_PRIVATE_DETAIL", console)
                logs = copied / "out" / "logs" / "runtime"
                self.assertIn(f"exit_code: {exit_code}", (logs / "latest-console.log").read_text())
                self.assertIn("launcher: vpn.cmd", (logs / "latest-bootstrap.log").read_text())
                self.assertTrue((logs / "latest-transcript.log").is_file())
                if outcome == "error":
                    self.assertIn("Concise failure", console)
                    trace = (logs / "latest-error.log").read_text(encoding="utf-8")
                    self.assertIn("CLI03_PRIVATE_DETAIL", trace)
                    self.assertIn("Traceback (most recent call last)", trace)
                else:
                    self.assertIn("CLI03_FINISHED", console)
            finally:
                (copied / "release").touch()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    subprocess.run(
                        ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                        capture_output=True, timeout=10, check=False,
                    )
                    child.wait(timeout=5)
                child.stdin.close()
                reader.join(timeout=5)
                child.stdout.close()


if __name__ == "__main__":
    unittest.main()
