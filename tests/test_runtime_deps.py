from __future__ import annotations

import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from vpn_installer.models import AppError
from vpn_installer import runtime_deps


def completed(code: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["python"], code, stdout=stdout, stderr=stderr)


class RuntimeDepsTests(unittest.TestCase):
    def test_ensure_pip_available_returns_when_pip_exists(self) -> None:
        with patch("vpn_installer.runtime_deps.run_command", return_value=completed(0)) as mocked:
            runtime_deps.ensure_pip_available()
        mocked.assert_called_once()

    def test_ensure_pip_available_download_failure_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch("vpn_installer.runtime_deps.RUNTIME_DIR", Path(tmp)), patch("vpn_installer.runtime_deps.run_command", return_value=completed(1)) as run, patch("vpn_installer.runtime_deps.urllib.request.urlretrieve", side_effect=OSError("nope")):
                with self.assertRaises(AppError) as ctx:
                    runtime_deps.ensure_pip_available()
        self.assertIn("get-pip.py", str(ctx.exception))
        self.assertNotIn("ensurepip", run.call_args.args[0])

    def test_ensure_pip_available_get_pip_failure_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_file = Path(tmp) / "get-pip.py"
            fake_file.write_text("print('x')", encoding="utf-8")
            with patch("vpn_installer.runtime_deps.RUNTIME_DIR", Path(tmp)), patch("vpn_installer.runtime_deps.run_command", side_effect=[completed(1), completed(2, stderr="bad pip")]), patch("vpn_installer.runtime_deps.urllib.request.urlretrieve", return_value=(str(fake_file), None)):
                with self.assertRaises(AppError) as ctx:
                    runtime_deps.ensure_pip_available()
        self.assertIn("bad pip", str(ctx.exception))

    def test_get_pip_bootstrap_is_scoped_to_runtime_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp)
            get_pip = runtime / "downloads" / "get-pip.py"
            responses = [completed(1), completed(0), completed(0)]
            with (
                patch.object(runtime_deps, "RUNTIME_DIR", runtime),
                patch.object(runtime_deps, "RUNTIME_SITE_PACKAGES", runtime / "site"),
                patch.object(runtime_deps, "run_command", side_effect=responses) as run,
                patch.object(runtime_deps.urllib.request, "urlretrieve", side_effect=lambda _url, path: (Path(path).write_text("", encoding="utf-8"), None)),
            ):
                runtime_deps.ensure_pip_available()

        bootstrap = run.call_args_list[1].args[0]
        self.assertIn(str(get_pip), bootstrap)
        self.assertEqual(bootstrap[-2:], ["--target", str(runtime / "site")])
        self.assertIn("runpy.run_module('pip'", run.call_args_list[2].args[0][2])

    def test_ensure_python_package_returns_existing_module(self) -> None:
        module = types.SimpleNamespace(name="demo")
        with patch("vpn_installer.runtime_deps.importlib.import_module", return_value=module) as mocked:
            result = runtime_deps.ensure_python_package("demo", "demo>=1")
        self.assertIs(result, module)
        mocked.assert_called_once_with("demo")

    def test_ensure_python_package_installs_missing_module(self) -> None:
        module = types.SimpleNamespace(name="paramiko")
        importer = Mock(side_effect=[ImportError(), module])
        with tempfile.TemporaryDirectory() as tmp:
            with patch("vpn_installer.runtime_deps.RUNTIME_SITE_PACKAGES", Path(tmp) / "site"), patch.object(runtime_deps.importlib, "import_module", importer), patch.object(runtime_deps, "ensure_pip_available") as ensure_pip, patch.object(runtime_deps, "run_command", return_value=completed(0)) as run:
                result = runtime_deps.ensure_python_package("paramiko", "paramiko>=3.5,<4")
        self.assertIs(result, module)
        ensure_pip.assert_called_once()
        self.assertEqual(importer.call_count, 2)
        self.assertEqual(run.call_count, 1)
        self.assertIn("runpy.run_module('pip'", run.call_args.args[0][2])
        self.assertEqual(run.call_args.args[0][-1], "paramiko>=3.5,<4")

    def test_ensure_python_package_install_failure_raises(self) -> None:
        importer = Mock(side_effect=ImportError())
        with tempfile.TemporaryDirectory() as tmp:
            with patch("vpn_installer.runtime_deps.RUNTIME_SITE_PACKAGES", Path(tmp) / "site"), patch.object(runtime_deps.importlib, "import_module", importer), patch.object(runtime_deps, "ensure_pip_available"), patch.object(runtime_deps, "run_command", return_value=completed(9, stderr="pip fail")):
                with self.assertRaises(AppError) as ctx:
                    runtime_deps.ensure_python_package("demo", "demo>=1")
        self.assertIn("pip fail", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
