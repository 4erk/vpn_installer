from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import config


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return self.payload


class ConfigTests(unittest.TestCase):
    def test_validate_deployment_name_normalizes(self) -> None:
        self.assertEqual(config.validate_deployment_name("my vpn!!"), "my-vpn")

    def test_validate_ip_literal_rejects_empty(self) -> None:
        with self.assertRaises(Exception):
            config.validate_ip_literal("")

    def test_validate_ssh_port_accepts_valid(self) -> None:
        self.assertEqual(config.validate_ssh_port("2222"), "2222")

    def test_validate_ssh_user_rejects_spaces(self) -> None:
        with self.assertRaises(Exception):
            config.validate_ssh_user("bad user")

    def test_validate_auth_mode_accepts_password(self) -> None:
        self.assertEqual(config.validate_auth_mode("password"), "password")

    def test_validate_identity_path_allows_empty(self) -> None:
        self.assertEqual(config.validate_identity_path(""), "")

    def test_default_reality_keys_are_urlsafe_without_padding(self) -> None:
        env = config.generate_default_env("sample")
        self.assertNotIn("=", env["RU_REALITY_PRIVATE_KEY"])
        self.assertNotIn("+", env["RU_REALITY_PRIVATE_KEY"])
        self.assertNotIn("/", env["RU_REALITY_PRIVATE_KEY"])

    def test_render_env_roundtrip(self) -> None:
        env = config.generate_default_env("sample")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        text = config.render_env_text(env)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.env"
            path.write_text(text, encoding="utf-8")
            loaded = config.load_env_file(path)
        self.assertEqual(loaded["DEPLOY_NAME"], "sample")
        self.assertEqual(loaded["RU_PUBLIC_IP"], "203.0.113.10")

    def test_merge_env_with_defaults_preserves_allowed_empty(self) -> None:
        merged = config.merge_env_with_defaults({"WAN_INTERFACE": ""}, "sample")
        self.assertIn("WAN_INTERFACE", merged)
        self.assertEqual(merged["WAN_INTERFACE"], "")

    def test_split_asset_sources_supports_spaces_and_pipe(self) -> None:
        self.assertEqual(
            config.split_asset_sources("https://a.example/file https://b.example/file|https://c.example/file"),
            ["https://a.example/file", "https://b.example/file", "https://c.example/file"],
        )

    def test_download_asset_converts_ripe_json_to_prefix_file(self) -> None:
        payload = {
            "data": {
                "resources": {
                    "ipv4": ["5.8.0.0/21", "31.13.24.0/21"],
                    "ipv6": ["2a00:1450::/32"],
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "ru-ipv4.zone"
            with patch("urllib.request.urlopen", return_value=_FakeResponse(json.dumps(payload).encode("utf-8"))):
                config.download_asset(
                    "https://stat.ripe.net/data/country-resource-list/data.json?resource=ru&v4_format=prefix",
                    output,
                    "ru-ipv4.zone",
                )
            self.assertEqual(output.read_text(encoding="utf-8"), "5.8.0.0/21\n31.13.24.0/21\n")


if __name__ == "__main__":
    unittest.main()
