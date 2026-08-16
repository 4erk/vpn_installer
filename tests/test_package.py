from __future__ import annotations

import importlib
import os
import runpy
import shutil
import subprocess
import sys
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
)


class PackageTests(unittest.TestCase):
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
        self.assertIn('AGENT_SCRIPT_PATH="/usr/local/lib/vpn-stack/vpn-stack-agent.py"', script)
        self.assertIn('AGENT_LOG_CLASSIFIER_PATH="/usr/local/lib/vpn-stack/log_classifier.py"', script)
        self.assertIn('AGENT_TRANSPORT_POLICY_PATH="/usr/local/lib/vpn-stack/interserver_transport.py"', script)
        self.assertIn('AGENT_NETWORK_PROFILE_PATH="/usr/local/lib/vpn-stack/network_profile.py"', script)
        self.assertIn('TRANSPORT_SERVICE_PATH="/etc/systemd/system/vpn-stack-transport.service"', script)
        self.assertIn('NFTABLES_PATH="${VPNSTACK_ROOT}/nftables.conf"', script)
        self.assertIn('NFT_SERVICE_PATH="/etc/systemd/system/vpn-stack-nftables.service"', script)
        self.assertIn("stage_release()", script)
        self.assertIn("publish_staged_release()", script)
        self.assertIn("release_tree_digest()", script)
        self.assertIn("export PYTHONDONTWRITEBYTECODE=1", script)
        self.assertIn("! -path '*/__pycache__/*'", script)
        self.assertIn("prune_revision_snapshots()", script)
        self.assertIn("normalize_staged_release_permissions", script)
        self.assertIn('chmod 0600 "${source_dir}/sing-box.json"', script)
        self.assertIn('chmod 0600 "${source_dir}/${WG_INTERFACE}.conf"', script)
        self.assertIn("validate_staged_release()", script)
        self.assertIn("-name '*.pyc' -o -name '*.pyo'", script)
        self.assertIn("-name __pycache__ -empty -delete", script)
        self.assertIn('python3 "${source_dir}/vpn-stack-agent.py" --help', script)
        self.assertIn('python3 "${AGENT_SCRIPT_PATH}" network-apply', script)
        self.assertLess(
            script.rindex("restart_wireguard_service"),
            script.rindex('python3 "${AGENT_SCRIPT_PATH}" network-apply'),
        )
        self.assertNotIn("capture_preserved_transport_tag", script)
        self.assertIn("activate_staged_release", script)
        self.assertIn("mv -Tf", script)
        self.assertIn("vpn-stack-sync.timer vpn-stack-sync.service", script)
        self.assertNotIn("systemctl enable vpn-stack-sync.timer", script)
        self.assertIn("manifest_binary_field()", script)
        self.assertIn('manifest_binary_field "${source_dir}" xray version', script)
        self.assertNotIn("XRAY_REQUIRED_VERSION=", script)
        self.assertIn("sha256sum -c", script)
        self.assertIn("record_binary_digests()", script)
        self.assertIn("stage_sing_box_binary()", script)
        self.assertIn("stage_xray_binary()", script)
        self.assertIn("prune_old_releases()", script)
        self.assertIn('SINGBOX_SERVICE_PATH="/etc/systemd/system/sing-box.service"', script)
        self.assertIn("verify_active_release()", script)
        self.assertNotIn("reset_public_front_tcp_metrics()", script)
        self.assertNotIn("ip tcp_metrics flush all", script)
        self.assertIn("snapshot --live-probes --profile acceptance", script)
        self.assertIn('verdicts.get("host_integrity") != "verified"', script)
        self.assertIn("post-activation network profile drift detected", script)
        self.assertIn("e2fsprogs", script)
        self.assertIn("VPNSTACK_FAILED_ACCEPTANCE_FILE", script)
        self.assertIn("VPNSTACK_PREVIOUS_RELEASE", script)
        self.assertIn('"${VPNSTACK_RENDER_MANIFEST_FILE}"', script)
        self.assertIn('"${HEALTH_STATE_PATH}"', script)
        self.assertIn('"${TRANSPORT_STATE_PATH}"', script)
        self.assertNotIn('rm -rf "${release_dir}"', script)
        self.assertIn("configure_unattended_security_updates", script)
        self.assertIn("for ((attempt = 0; attempt < 50; attempt++))", script)
        self.assertIn('ss -H -lnt "sport = :${SSH_PORT}"', script)
        self.assertIn("sleep 0.1", script)
        self.assertNotIn("preserving the previous SSH activation mode", script)
        self.assertIn('link_release_file "${source_dir}" "apt-vpn-stack-unattended.conf"', script)
        self.assertIn('link_release_file "${source_dir}" "resolved-vpn-stack.conf"', script)
        self.assertIn("systemd-resolved", script)
        self.assertIn('ln -sfn "../run/systemd/resolve/stub-resolv.conf"', script)
        self.assertIn("resolver_release_config_unchanged", script)
        self.assertIn("local resolver refused", script)
        self.assertIn("extend_baseline_contract", script)
        self.assertIn('link_release_file "${source_dir}" "modules-vpn-stack.conf"', script)
        self.assertIn("modprobe nf_conntrack", script)
        self.assertIn("acquire_install_lock", script)
        self.assertIn("flock -w 60 8", script)
        self.assertLess(script.index("acquire_install_lock\nfi"), script.index("run_apt_get update"))
        self.assertNotIn("systemctl enable nftables\n", script)
        self.assertNotIn("systemctl restart nftables\n", script)
        self.assertIn("systemctl disable --now nftables.service", script)
        self.assertIn("restorable_legacy_nftables_flag", script)
        self.assertIn('"${service}" == "nftables" && ! -s "${LEGACY_NFTABLES_PATH}"', script)
        self.assertIn("systemctl enable vpn-stack-nftables.service", script)
        self.assertIn("systemctl restart vpn-stack-nftables.service", script)
        self.assertIn('"${NFT_APPLY_SCRIPT_PATH}" --delete', script)
        remove_body = script.split("remove_managed_files() {", 1)[1].split("\n}", 1)[0]
        self.assertIn('"${MODULES_LOAD_PATH}"', remove_body)
        self.assertIn('"${AGENT_DIAGNOSTICS_PATH}"', remove_body)
        self.assertIn('stage_preseed_assets "${ROLE_ARTIFACTS_DIR}/assets"', script)
        self.assertNotIn('cat >"${SYSCTL_PATH}"', script)

    def test_singbox_version_contract_is_shared_with_audit(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        self.assertEqual(AUDIT_SINGBOX_REQUIRED_VERSION, SING_BOX_VERSION)
        self.assertIn(AUDIT_SINGBOX_REQUIRED_VERSION, AUDIT_IMAGE)
        self.assertEqual(SING_BOX_LINUX_AMD64_ARCHIVE_SHA256, "1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4")
        self.assertEqual(SING_BOX_LINUX_AMD64_BINARY_SHA256, "989e848637725005fdac7f1d3fa3d6eeb16992c5e0a68789da96b6b3fde06ea2")
        self.assertNotIn("SINGBOX_REQUIRED_VERSION=", script)
        self.assertNotIn("SINGBOX_LINUX_AMD64_SHA256=", script)
        self.assertIn('manifest_binary_field "${source_dir}" sing-box archive_sha256', script)
        self.assertNotIn("sing-box.sagernet.org/installation/tools/install.sh | bash", script)

    @unittest.skipIf(os.name == "nt", "POSIX flock behavior is exercised on Linux CI")
    def test_installer_lock_serializes_concurrent_writers(self) -> None:
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
            harness.write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\n"
                + lock_function
                + "\nINSTALL_LOCK_PATH=$1\nacquire_install_lock\n"
                + "printf '%s-start\\n' \"$2\" >>\"$3\"\n"
                + "sleep \"$4\"\n"
                + "printf '%s-end\\n' \"$2\" >>\"$3\"\n",
                encoding="utf-8",
            )

            def shell_path(path: Path) -> str:
                value = path.resolve().as_posix()
                if os.name == "nt" and len(value) > 2 and value[1] == ":":
                    return f"/{value[0].lower()}{value[2:]}"
                return value

            first = subprocess.Popen(
                [bash, shell_path(harness), shell_path(lock_path), "first", shell_path(events_path), "0.5"],
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
                [bash, shell_path(harness), shell_path(lock_path), "second", shell_path(events_path), "0"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.1)
            self.assertNotIn("second-start", events_path.read_text(encoding="utf-8"))
            first_stdout, first_stderr = first.communicate(timeout=2)
            second_stdout, second_stderr = second.communicate(timeout=2)
            events = events_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(first.returncode, 0, first_stdout + first_stderr)
        self.assertEqual(second.returncode, 0, second_stdout + second_stderr)
        self.assertEqual(events, ["first-start", "first-end", "second-start", "second-end"])

    def test_package_exposes_version_via_getattr(self) -> None:
        package = importlib.import_module("vpn_installer")
        self.assertEqual(package.__version__, "0.19.10")
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
