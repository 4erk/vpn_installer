from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.client_drift import default_candidate_paths, find_client_drift
from vpn_installer.config import generate_default_env


class ClientDriftTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env.update(
            {
                "CONFIG_SCHEMA": "3",
                "TOPOLOGY": "dual",
                "GATEWAY_LOCATION": "ru",
                "GATEWAY_PUBLIC_IP": "203.0.113.10",
                "EXIT_PUBLIC_IP": "198.51.100.20",
                "RU_LISTEN_PORT": "8443",
            }
        )
        env.pop("RU_PUBLIC_IP", None)
        env.pop("FOREIGN_PUBLIC_IP", None)
        return env

    def test_detects_stale_hiddify_json_port(self) -> None:
        env = self.make_env()
        payload = {"outbounds": [{"type": "vless", "server": env["GATEWAY_PUBLIC_IP"], "server_port": 443, "uuid": env["CLIENT_UUID"]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hiddify.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            findings = find_client_drift(env, [path])
        self.assertEqual(len(findings), 1)
        self.assertIn("устаревший порт клиента: 443, ожидается 8443", findings[0].issue)

    def test_detects_stale_vless_uri_port(self) -> None:
        env = self.make_env()
        uri = f"vless://{env['CLIENT_UUID']}@{env['GATEWAY_PUBLIC_IP']}:443?security=reality#demo\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.txt"
            path.write_text(uri, encoding="utf-8")
            findings = find_client_drift(env, [path])
        self.assertEqual(len(findings), 1)
        self.assertIn("устаревший VLESS URI порт: 443, ожидается 8443", findings[0].issue)

    def test_current_profile_has_no_findings(self) -> None:
        env = self.make_env()
        payload = {"outbounds": [{"type": "vless", "server": env["GATEWAY_PUBLIC_IP"], "server_port": 8443, "uuid": env["CLIENT_UUID"], "public_key": env["RU_REALITY_PUBLIC_KEY"], "short_id": env["RU_REALITY_SHORT_ID"]}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            findings = find_client_drift(env, [path])
        self.assertEqual(findings, [])

    def test_detects_identity_mismatches(self) -> None:
        env = self.make_env()
        payload = {
            "outbounds": [
                {
                    "type": "vless",
                    "server": env["GATEWAY_PUBLIC_IP"],
                    "server_port": 8443,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "public_key": "old-key",
                    "short_id": "old-short-id",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            findings = find_client_drift(env, [path])
        issues = "\n".join(finding.issue for finding in findings)
        self.assertIn("устаревший CLIENT_UUID", issues)
        self.assertIn("устаревший REALITY public key", issues)
        self.assertIn("устаревший REALITY short_id", issues)

    def test_invalid_json_falls_back_to_uri_scan(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("{" + f"vless://{env['CLIENT_UUID']}@{env['GATEWAY_PUBLIC_IP']}:443", encoding="utf-8")
            findings = find_client_drift(env, [path])
        self.assertEqual(len(findings), 1)
        self.assertIn("устаревший VLESS URI порт", findings[0].issue)

    def test_skips_missing_and_large_files(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            large = Path(tmp) / "large.txt"
            large.write_bytes(b"x" * (5 * 1024 * 1024 + 1))
            findings = find_client_drift(env, [missing, large])
        self.assertEqual(findings, [])

    def test_single_gateway_drift_uses_canonical_public_address(self) -> None:
        env = generate_default_env("single", topology="single", gateway_location="foreign")
        env.update(
            {
                "CONFIG_SCHEMA": "3",
                "TOPOLOGY": "single",
                "GATEWAY_LOCATION": "foreign",
                "GATEWAY_PUBLIC_IP": "192.0.2.44",
                "EXIT_PUBLIC_IP": "",
                "RU_LISTEN_PORT": "8443",
            }
        )
        env.pop("RU_PUBLIC_IP", None)
        env.pop("FOREIGN_PUBLIC_IP", None)
        uri = f"vless://{env['CLIENT_UUID']}@{env['GATEWAY_PUBLIC_IP']}:443?security=reality#single\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.txt"
            path.write_text(uri, encoding="utf-8")
            findings = find_client_drift(env, [path])

        self.assertEqual(len(findings), 1)
        self.assertIn("устаревший VLESS URI порт", findings[0].issue)

    def test_default_candidate_paths_includes_known_client_locations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            appdata = root / "AppData"
            userprofile = root / "User"
            hiddify_config = appdata / "Hiddify" / "hiddify" / "configs" / "profile.json"
            hiddify_download = userprofile / "Downloads" / "hiddify-cross-platform.json"
            v2ray_config = userprofile / "Downloads" / "v2rayN-windows-64-desktop" / "guiConfigs" / "config.json"
            for path in (hiddify_config, hiddify_download, v2ray_config):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}", encoding="utf-8")
            with patch.dict(os.environ, {"APPDATA": str(appdata), "USERPROFILE": str(userprofile)}):
                candidates = {path.name for path in default_candidate_paths()}
        self.assertIn("profile.json", candidates)
        self.assertIn("hiddify-cross-platform.json", candidates)
        self.assertIn("config.json", candidates)


if __name__ == "__main__":
    unittest.main()
