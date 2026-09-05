from __future__ import annotations

import importlib
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.audit.runner import AUDIT_IMAGE, AUDIT_SINGBOX_REQUIRED_VERSION
from vpn_installer.config import render_example_env_text
from vpn_installer.manifest import (
    SING_BOX_LINUX_AMD64_ARCHIVE_SHA256,
    SING_BOX_LINUX_AMD64_BINARY_SHA256,
    SING_BOX_VERSION,
    XRAY_LINUX_AMD64_BINARY_SHA256,
    XRAY_LINUX_AMD64_SHA256,
    XRAY_VERSION,
    _binary_entries,
)
from vpn_installer import render
from vpn_installer.topology import (
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    NodeSpec,
    TopologySpec,
)


class PackageTests(unittest.TestCase):
    @staticmethod
    def binary_contract(node_id: str) -> dict[str, dict[str, str]]:
        topology = TopologySpec(
            mode=TOPOLOGY_DUAL,
            gateway=NodeSpec(NODE_GATEWAY, LOCATION_RU, "203.0.113.10"),
            exit=NodeSpec(NODE_EXIT, LOCATION_FOREIGN, "198.51.100.20"),
        )
        return _binary_entries(topology.plan(node_id))

    def test_package_main_is_lazy(self) -> None:
        sys.modules.pop("vpn_installer", None)
        sys.modules.pop("vpn_installer.cli", None)
        package = importlib.import_module("vpn_installer")
        self.assertTrue(callable(package.main))
        self.assertNotIn("vpn_installer.cli", sys.modules)

    def test_deployment_example_matches_generated_contract(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        example_path = repo_root / "deployments" / "deployment.env.example"
        if not example_path.is_file():
            self.skipTest("deployment.env.example is absent")
        self.assertEqual(example_path.read_text(encoding="utf-8"), render_example_env_text())

    def test_installer_uses_staged_release_agent_and_pinned_xray(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        gateway_binaries = self.binary_contract(NODE_GATEWAY)
        exit_binaries = self.binary_contract(NODE_EXIT)
        self.assertEqual(
            gateway_binaries["xray"],
            {
                "version": XRAY_VERSION,
                "archive_sha256": XRAY_LINUX_AMD64_SHA256,
                "sha256": XRAY_LINUX_AMD64_BINARY_SHA256,
                "path": "/etc/vpn-stack/current/bin/xray",
                "service": "vpn-stack-xray.service",
            },
        )
        self.assertNotIn("xray", exit_binaries)

        install_body = script.split("install_action() {", 1)[1].split("\n}\n\ncurrent_release_contract()", 1)[0]
        ordered_steps = [
            'validate_bundle "${source_bundle}" "${NODE}" "${source_contract}" "${ASSETS_DIR}" 1 0',
            'stage_release "${source_bundle}" "${source_contract}"',
            'validate_bundle "${STAGED_RELEASE_DIR}" "${NODE}" "${staged_contract}" "" 1 1',
            'validate_staged_payloads "${STAGED_RELEASE_DIR}" "${staged_contract}"',
            'publish_staged_release "${STAGED_RELEASE_DIR}" "${staged_contract}"',
            'install_planned_links "${staged_contract}" "${PREVIOUS_CONTRACT}"',
            'switch_current_release "${PUBLISHED_RELEASE_DIR}"',
            'start_planned_services "${staged_contract}"',
            'verify_active_release "${staged_contract}"',
        ]
        positions = [install_body.index(step) for step in ordered_steps]
        self.assertEqual(positions, sorted(positions))

        self.assertIn('done <"${contract_dir}/artifacts.tsv"', script)
        self.assertIn('done <"${contract_dir}/binaries.tsv"', script)
        self.assertIn(
            'stage_xray_binary "${version}" "${archive_sha}" "${binary_sha}" "${release_dir}/bin/xray"',
            script,
        )
        self.assertIn(
            'https://github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-64.zip',
            script,
        )
        self.assertIn('verify_sha256 "${temp}/xray.zip" "${archive_sha}"', script)
        self.assertIn('verify_sha256 "${destination}" "${binary_sha}"', script)
        self.assertNotIn("XRAY_REQUIRED_VERSION=", script)

        agent_lookup = 'agent_path="$(contract_artifact_path "${contract_dir}" vpn-stack-agent.py)"'
        self.assertGreaterEqual(script.count(agent_lookup), 2)
        self.assertIn('"${PYTHON_BIN}" "${agent_path}" network-apply', script)
        self.assertIn('"${PYTHON_BIN}" "${agent_path}" snapshot --live-probes --profile acceptance', script)
        self.assertNotIn("AGENT_SCRIPT_PATH=", script)
        self.assertIn("normalize_acceptance_snapshot", script)
        self.assertIn('payload.get("artifacts", {}).get("drift") != "none"', script)
        self.assertIn('payload.get("verdict") != "verified"', script)
        self.assertIn("from vpn_installer.install_contract import is_planned_install_maintenance, normalize_acceptance_snapshot", script)
        self.assertIn("and not is_planned_install_maintenance(payload)", script)
        self.assertIn("release_tree_digest()", script)
        self.assertIn("from vpn_installer.release_integrity import main", script)
        self.assertNotIn("for path in sorted(item for item in root.rglob", script)
        self.assertIn("immutable release collision", script)
        self.assertIn("create_transaction_snapshots", install_body)
        self.assertIn("restore_managed_runtime_state", script)
        self.assertIn('FAILED_ACCEPTANCE_STASH="${WORK_DIR}/failed-acceptance.json"', script)
        self.assertIn('install -m 0600 "${FAILED_ACCEPTANCE_STASH}" "${VPNSTACK_FAILED_ACCEPTANCE_PATH}"', script)
        self.assertIn('rm -f -- "${VPNSTACK_ROOT}"/.acceptance.*.json', script)
        restore_body = script.split("restore_snapshot() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(restore_body.index('restore_service_state "${snapshot}"'), restore_body.index("restore_managed_runtime_state"))
        self.assertIn("safe_operational_path", script)
        self.assertIn("flock -w 60 9", script)

    def test_control_bundle_contains_installer_dependency_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(render, "OUT_DIR", Path(tmp)):
            bundle = render.package_control_bundle()
            with tarfile.open(bundle, "r:gz") as archive:
                names = set(archive.getnames())

        self.assertIn("install.sh", names)
        self.assertIn("vpn_installer/install_support.py", names)
        self.assertIn("vpn_installer/release_integrity.py", names)
        self.assertNotIn("deployment.env", names)

    def test_singbox_version_contract_is_shared_with_audit(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        expected_binary = {
            "version": SING_BOX_VERSION,
            "archive_sha256": SING_BOX_LINUX_AMD64_ARCHIVE_SHA256,
            "sha256": SING_BOX_LINUX_AMD64_BINARY_SHA256,
            "path": "/etc/vpn-stack/current/bin/sing-box",
            "service": "sing-box.service",
        }
        self.assertEqual(AUDIT_SINGBOX_REQUIRED_VERSION, SING_BOX_VERSION)
        self.assertIn(AUDIT_SINGBOX_REQUIRED_VERSION, AUDIT_IMAGE)
        self.assertEqual(SING_BOX_LINUX_AMD64_ARCHIVE_SHA256, "1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4")
        self.assertEqual(SING_BOX_LINUX_AMD64_BINARY_SHA256, "989e848637725005fdac7f1d3fa3d6eeb16992c5e0a68789da96b6b3fde06ea2")
        self.assertEqual(self.binary_contract(NODE_GATEWAY)["sing-box"], expected_binary)
        self.assertEqual(self.binary_contract(NODE_EXIT)["sing-box"], expected_binary)
        self.assertNotIn("SINGBOX_REQUIRED_VERSION=", script)
        self.assertNotIn("SINGBOX_LINUX_AMD64_SHA256=", script)
        self.assertIn(
            'stage_sing_box_binary "${version}" "${archive_sha}" "${binary_sha}" "${release_dir}/bin/sing-box"',
            script,
        )
        self.assertIn(
            'https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-amd64.tar.gz',
            script,
        )
        self.assertIn('verify_sha256 "${temp}/sing-box.tar.gz" "${archive_sha}"', script)
        self.assertIn('verify_sha256 "${destination}" "${binary_sha}"', script)
        self.assertIn('done <"${contract_dir}/binaries.tsv"', script)
        self.assertNotIn("sing-box.sagernet.org/installation/tools/install.sh | bash", script)

    @unittest.skipIf(os.name == "nt", "POSIX flock behavior is exercised on Linux CI")
    def test_installer_lock_serializes_concurrent_writer(self) -> None:
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is unavailable")
        if subprocess.run([bash, "-lc", "command -v flock"], capture_output=True).returncode != 0:
            self.skipTest("flock is unavailable")
        install_script = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        lock_function = "acquire_install_lock() {" + install_script.split("acquire_install_lock() {", 1)[1].split("\n}", 1)[0] + "\n}"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness = root / "lock-test.sh"
            lock_path = root / "install.lock"
            events_path = root / "events.log"
            release_path = root / "release-first"
            harness.write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\n"
                + "die() { echo \"ERROR: $*\" >&2; exit 1; }\n"
                + lock_function
                + "\nINSTALL_LOCK_PATH=$1\n"
                + "printf '%s-attempt\\n' \"$2\" >>\"$3\"\n"
                + "acquire_install_lock\n"
                + "printf '%s-start\\n' \"$2\" >>\"$3\"\n"
                + "if [ \"$2\" = first ]; then while [ ! -e \"$4\" ]; do sleep 0.02; done; fi\n"
                + "printf '%s-end\\n' \"$2\" >>\"$3\"\n",
                encoding="utf-8",
            )

            def shell_path(path: Path) -> str:
                value = path.resolve().as_posix()
                if os.name == "nt" and len(value) > 2 and value[1] == ":":
                    return f"/{value[0].lower()}{value[2:]}"
                return value

            first = subprocess.Popen(
                [bash, shell_path(harness), shell_path(lock_path), "first", shell_path(events_path), shell_path(release_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 2
            while (not events_path.exists() or "first-start" not in events_path.read_text(encoding="utf-8")) and time.monotonic() < deadline:
                time.sleep(0.02)
            first_events = events_path.read_text(encoding="utf-8") if events_path.exists() else ""
            self.assertIn("first-start", first_events, "first writer did not acquire the lock")
            second = subprocess.Popen(
                [bash, shell_path(harness), shell_path(lock_path), "second", shell_path(events_path), shell_path(release_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.1)
            blocked_events = events_path.read_text(encoding="utf-8")
            self.assertIn("second-attempt", blocked_events, "second writer did not attempt the lock")
            self.assertNotIn("second-start", blocked_events)
            self.assertIsNone(second.poll(), "second writer did not wait for the active transaction")
            release_path.touch()
            first_stdout, first_stderr = first.communicate(timeout=2)
            second_stdout, second_stderr = second.communicate(timeout=2)
            events = events_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(first.returncode, 0, first_stdout + first_stderr)
        self.assertEqual(second.returncode, 0, second_stdout + second_stderr)
        self.assertEqual(
            events,
            ["first-attempt", "first-start", "second-attempt", "first-end", "second-start", "second-end"],
        )

    def test_package_exposes_version_via_getattr(self) -> None:
        package = importlib.import_module("vpn_installer")
        self.assertEqual(package.__version__, package.VERSION)
        with self.assertRaises(AttributeError):
            package.__getattr__("nope")

    def test_package_main_delegates_to_cli(self) -> None:
        package = importlib.import_module("vpn_installer")
        with patch("vpn_installer.cli.main", return_value=7) as mocked:
            self.assertEqual(package.main(["status"]), 7)
        mocked.assert_called_once_with(["status"])

    def test_module_main_exits_with_cli_code(self) -> None:
        with patch("vpn_installer.main", return_value=3):
            with self.assertRaises(SystemExit) as ctx:
                runpy.run_module("vpn_installer.__main__", run_name="__main__")
        self.assertEqual(ctx.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
