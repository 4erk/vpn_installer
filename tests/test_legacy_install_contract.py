from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from vpn_installer.install_contract import InstallContractError
from vpn_installer.legacy_install_contract import (
    REMOVE_IN_VERSION,
    _COMMON_ARTIFACT_PATHS,
    _GATEWAY_ARTIFACT_PATHS,
    adapt_schema2_install,
)
from vpn_installer.topology import LEGACY_ROLE_FOREIGN, LEGACY_ROLE_RU


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class LegacyInstallContractTests(unittest.TestCase):
    def build_install(self, root: Path, role: str) -> tuple[Path, Path]:
        current = root / "etc/vpn-stack/releases/0.19.10-test"
        current.mkdir(parents=True)
        deployment_env = root / "etc/vpn-stack/deployment.env"
        deployment_env.parent.mkdir(parents=True, exist_ok=True)
        env_payload = b'DEPLOY_NAME="demo"\n'
        deployment_env.write_bytes(env_payload)

        paths = dict(_COMMON_ARTIFACT_PATHS)
        if role == LEGACY_ROLE_RU:
            paths.update(_GATEWAY_ARTIFACT_PATHS)
        paths["wg0.conf"] = "/etc/wireguard/wg0.conf"
        artifacts: dict[str, dict[str, object]] = {}
        for name, manifest_path in paths.items():
            payload = f"payload:{name}\n".encode()
            (current / name).write_bytes(payload)
            artifacts[name] = {
                "sha256": digest(payload),
                "install_path": manifest_path,
                "required": True,
            }
            effective_paths = [manifest_path]
            if role == LEGACY_ROLE_FOREIGN and name == "sing-box.json":
                effective_paths.append("/etc/sing-box/config.json")
            for effective_path in effective_paths:
                live = root / effective_path.lstrip("/")
                live.parent.mkdir(parents=True, exist_ok=True)
                live.write_bytes(payload)

        asset_names = {"geoip-ru.srs", "geosite-ru.srs"} if role == LEGACY_ROLE_RU else set()
        assets: dict[str, dict[str, object]] = {}
        for name in asset_names:
            payload = f"asset:{name}\n".encode()
            release_asset = current / "assets" / name
            release_asset.parent.mkdir(parents=True, exist_ok=True)
            release_asset.write_bytes(payload)
            install_path = f"/var/lib/vpn-stack/rules/{name}"
            live = root / install_path.lstrip("/")
            live.parent.mkdir(parents=True, exist_ok=True)
            live.write_bytes(payload)
            assets[name] = {"sha256": digest(payload), "install_path": install_path, "required": True}

        binary_services = {"sing-box": "sing-box.service"}
        if role == LEGACY_ROLE_RU:
            binary_services["xray"] = "vpn-stack-xray.service"
        binaries: dict[str, dict[str, str]] = {}
        for name, service in binary_services.items():
            payload = f"binary:{name}\n".encode()
            binary = current / "bin" / name
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(payload)
            binaries[name] = {
                "version": "1.2.3",
                "archive_sha256": digest(f"archive:{name}".encode()),
                "sha256": digest(payload),
                "path": f"/etc/vpn-stack/current/bin/{name}",
                "service": service,
            }

        manifest = {
            "schema_version": 2,
            "version": "0.19.10",
            "release_id": "0.19.10-0123456789ab",
            "role": role,
            "env_sha256": digest(env_payload),
            "artifacts": artifacts,
            "assets": assets,
            "binaries": binaries,
        }
        (current / "render-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return current, deployment_env

    def test_gateway_contract_owns_interserver_for_transactional_retirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current, env_path = self.build_install(root, LEGACY_ROLE_RU)
            contract = root / "contract"

            adapt_schema2_install(current, env_path, contract, system_root=root)

            services = (contract / "services.tsv").read_text(encoding="utf-8")
            artifacts = (contract / "artifacts.tsv").read_text(encoding="utf-8")
            meta = (contract / "meta.tsv").read_text(encoding="utf-8")
            self.assertIn("wireguard\twg-quick@wg0.service\tmanaged", services)
            self.assertIn("transport\tvpn-stack-transport.service\tmanaged", services)
            self.assertIn("node.env\t/etc/vpn-stack/deployment.env\tmanaged", artifacts)
            self.assertIn("deployment\tdemo", meta)
            self.assertIn(f"remove_in\t{REMOVE_IN_VERSION}", meta)

    def test_foreign_contract_corrects_known_schema_two_singbox_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current, env_path = self.build_install(root, LEGACY_ROLE_FOREIGN)
            contract = root / "contract"

            adapt_schema2_install(current, env_path, contract, system_root=root)

            artifacts = (contract / "artifacts.tsv").read_text(encoding="utf-8")
            self.assertIn("sing-box.json\t/etc/sing-box/config.json\tmanaged", artifacts)
            self.assertIn("sing-box.json\t/etc/vpn-stack/sing-box.base.json\tmanaged", artifacts)

    def test_modified_live_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current, env_path = self.build_install(root, LEGACY_ROLE_RU)
            (root / "etc/xray/config.json").write_text("modified", encoding="utf-8")

            with self.assertRaisesRegex(InstallContractError, "owned live path was modified"):
                adapt_schema2_install(current, env_path, root / "contract", system_root=root)

    def test_unknown_artifact_path_is_rejected_without_writing_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current, env_path = self.build_install(root, LEGACY_ROLE_RU)
            manifest_path = current / "render-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["artifacts"]["unknown.service"] = {
                "sha256": "0" * 64,
                "install_path": "/etc/systemd/system/unknown.service",
                "required": True,
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            contract = root / "contract"

            with self.assertRaisesRegex(InstallContractError, "unknown=.*unknown.service"):
                adapt_schema2_install(current, env_path, contract, system_root=root)
            self.assertFalse(contract.exists())

    def test_deployment_env_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current, env_path = self.build_install(root, LEGACY_ROLE_RU)
            env_path.write_text('DEPLOY_NAME="other"\n', encoding="utf-8")

            with self.assertRaisesRegex(InstallContractError, "deployment.env differs"):
                adapt_schema2_install(current, env_path, root / "contract", system_root=root)


if __name__ == "__main__":
    unittest.main()
