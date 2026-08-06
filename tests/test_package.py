from __future__ import annotations

import importlib
import runpy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.audit.runner import AUDIT_IMAGE, AUDIT_SINGBOX_REQUIRED_VERSION
from vpn_installer.config import render_example_env_text
from vpn_installer.manifest import XRAY_LINUX_AMD64_SHA256, XRAY_VERSION


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
        self.assertIn('TRANSPORT_SERVICE_PATH="/etc/systemd/system/vpn-stack-transport.service"', script)
        self.assertIn("stage_release()", script)
        self.assertIn("publish_staged_release()", script)
        self.assertIn("release_tree_digest()", script)
        self.assertIn("prune_revision_snapshots()", script)
        self.assertIn("normalize_staged_release_permissions", script)
        self.assertIn('chmod 0600 "${source_dir}/sing-box.json"', script)
        self.assertIn('chmod 0600 "${source_dir}/${WG_INTERFACE}.conf"', script)
        self.assertIn("validate_staged_release()", script)
        self.assertIn('python3 "${source_dir}/vpn-stack-agent.py" --help', script)
        self.assertIn("activate_staged_release", script)
        self.assertIn("mv -Tf", script)
        self.assertIn("vpn-stack-sync.timer vpn-stack-sync.service", script)
        self.assertNotIn("systemctl enable vpn-stack-sync.timer", script)
        self.assertIn(f'XRAY_REQUIRED_VERSION="${{XRAY_REQUIRED_VERSION:-{XRAY_VERSION}}}"', script)
        self.assertIn(XRAY_LINUX_AMD64_SHA256, script)
        self.assertIn("sha256sum -c", script)
        self.assertIn("record_binary_digests()", script)
        self.assertIn("verify_active_release()", script)
        self.assertNotIn("reset_public_front_tcp_metrics()", script)
        self.assertNotIn("ip tcp_metrics flush all", script)
        self.assertIn("snapshot --live-probes --profile acceptance", script)
        self.assertIn('verdicts.get("host_integrity") != "verified"', script)
        self.assertIn("e2fsprogs", script)
        self.assertIn("VPNSTACK_FAILED_ACCEPTANCE_FILE", script)
        self.assertIn("VPNSTACK_PREVIOUS_RELEASE", script)
        self.assertIn('"${VPNSTACK_RENDER_MANIFEST_FILE}"', script)
        self.assertIn('"${HEALTH_STATE_PATH}"', script)
        self.assertIn('"${TRANSPORT_STATE_PATH}"', script)
        self.assertNotIn('rm -rf "${release_dir}"', script)
        self.assertIn("configure_unattended_security_updates", script)
        self.assertIn('copy_if_present "${source_dir}/apt-vpn-stack-unattended.conf"', script)
        self.assertIn('copy_if_present "${source_dir}/resolved-vpn-stack.conf"', script)
        self.assertIn("systemd-resolved", script)
        self.assertIn('ln -sfn "../run/systemd/resolve/stub-resolv.conf"', script)
        self.assertIn("extend_baseline_contract", script)
        self.assertIn('copy_if_present "${source_dir}/modules-vpn-stack.conf"', script)
        self.assertIn("modprobe nf_conntrack", script)
        remove_body = script.split("remove_managed_files() {", 1)[1].split("\n}", 1)[0]
        self.assertIn('"${MODULES_LOAD_PATH}"', remove_body)
        self.assertIn('stage_preseed_assets "${ROLE_ARTIFACTS_DIR}/assets"', script)
        self.assertNotIn('cat >"${SYSCTL_PATH}"', script)

    def test_singbox_version_contract_is_shared_with_audit(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        self.assertIn('SINGBOX_REQUIRED_VERSION="1.13.12"', script)
        self.assertEqual(AUDIT_SINGBOX_REQUIRED_VERSION, "1.13.12")
        self.assertIn(AUDIT_SINGBOX_REQUIRED_VERSION, AUDIT_IMAGE)

    def test_package_exposes_version_via_getattr(self) -> None:
        package = importlib.import_module("vpn_installer")
        self.assertEqual(package.__version__, "0.15.2")
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
