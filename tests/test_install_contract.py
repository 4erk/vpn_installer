from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.config import generate_default_env
from vpn_installer.install_contract import InstallContractError, is_planned_install_maintenance, validate_bundle, validate_installed_bundle
from vpn_installer.install_support import main as install_support_main
from vpn_installer.render import copy_python_package, write_node_rendered_files


CONTRACT_FILES = (
    "artifacts.tsv",
    "assets.tsv",
    "binaries.tsv",
    "services.tsv",
    "packages.tsv",
    "meta.tsv",
)


class InstallContractTests(unittest.TestCase):
    def test_installed_bundle_uses_one_current_schema_validator_for_previous_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "render-manifest.json").write_text('{"version":"0.20.2"}', encoding="utf-8")
            with patch("vpn_installer.install_contract._validate_bundle") as validator:
                validate_installed_bundle(bundle, "gateway", root / "contract")

        self.assertEqual(validator.call_args.kwargs["expected_version"], "0.20.2")
        self.assertNotIn("require_current_compatibility", validator.call_args.kwargs)

    def test_installed_bundle_rejects_out_of_window_version_before_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "render-manifest.json").write_text('{"version":"0.19.10"}', encoding="utf-8")
            with patch("vpn_installer.install_contract._validate_bundle") as validator:
                with self.assertRaisesRegex(InstallContractError, "tag 0.19.10"):
                    validate_installed_bundle(bundle, "gateway", root / "contract")

        validator.assert_not_called()

    def test_planned_install_maintenance_requires_exact_snapshot_evidence(self) -> None:
        snapshot = {
            "verdict": "degraded",
            "reasons": ["interserver_adaptation=maintenance"],
            "transport": {
                "interserver": {
                    "adaptive_state": {
                        "state": "maintenance",
                        "reason": "install transaction is active",
                    }
                }
            },
        }
        self.assertTrue(is_planned_install_maintenance(snapshot))
        self.assertFalse(is_planned_install_maintenance({**snapshot, "verdict": "failed"}))
        self.assertFalse(
            is_planned_install_maintenance(
                {**snapshot, "reasons": [*snapshot["reasons"], "public_front=degraded"]}
            )
        )
        self.assertFalse(
            is_planned_install_maintenance(
                {
                    **snapshot,
                    "transport": {
                        "interserver": {
                            "adaptive_state": {
                                "state": "maintenance",
                                "reason": "operator maintenance",
                            }
                        }
                    },
                }
            )
        )

    def render_single_gateway(self, root: Path) -> Path:
        env = generate_default_env(
            "install-contract",
            topology="single",
            gateway_location="foreign",
        )
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = ""
        env.pop("RU_PUBLIC_IP", None)
        env.pop("FOREIGN_PUBLIC_IP", None)
        bundle = root / "bundle"
        write_node_rendered_files(env, "gateway", bundle)
        return bundle

    @staticmethod
    def contract_payload(contract_dir: Path) -> dict[str, bytes]:
        return {name: (contract_dir / name).read_bytes() for name in CONTRACT_FILES}

    def test_function_and_cli_emit_identical_schema_four_tsv_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.render_single_gateway(root)
            direct_contract = root / "direct"
            cli_contract = root / "cli"

            validate_bundle(bundle, "gateway", direct_contract)
            result = install_support_main(
                [
                    "validate-bundle",
                    "--bundle",
                    str(bundle),
                    "--expected-node",
                    "gateway",
                    "--contract-dir",
                    str(cli_contract),
                ]
            )

            self.assertEqual(result, 0)
            self.assertEqual(self.contract_payload(cli_contract), self.contract_payload(direct_contract))
            meta = (direct_contract / "meta.tsv").read_text(encoding="utf-8").splitlines()
            self.assertEqual(meta[0], "schema_version\t4")
            self.assertIn("topology\tsingle", meta)
            self.assertIn("node_id\tgateway", meta)
            self.assertIn("location\tforeign", meta)

    def test_invalid_bundle_fails_before_any_tsv_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.render_single_gateway(root)
            manifest_path = bundle / "render-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schema_version"] = 99
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            contract_dir = root / "contract"

            with self.assertRaisesRegex(InstallContractError, "unsupported render manifest schema"):
                validate_bundle(bundle, "gateway", contract_dir)

            self.assertFalse(contract_dir.exists())

    def test_cli_preserves_concise_fail_closed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.render_single_gateway(root)
            (bundle / "node.env").unlink()

            with self.assertRaisesRegex(SystemExit, "missing bundle control file: node.env"):
                install_support_main(
                    [
                        "validate-bundle",
                        "--bundle",
                        str(bundle),
                        "--expected-node",
                        "gateway",
                        "--contract-dir",
                        str(root / "contract"),
                    ]
                )

    def test_server_package_contains_install_contract_module(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            package = copy_python_package(Path(temp))

            self.assertTrue((package / "install_contract.py").is_file())


if __name__ == "__main__":
    unittest.main()
