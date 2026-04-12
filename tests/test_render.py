from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.config import generate_default_env
from vpn_installer import render
import json


class RenderTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        env["WAN_INTERFACE"] = "eth1"
        return env

    def test_render_vless_uri(self) -> None:
        env = self.make_env()
        self.assertTrue(render.render_vless_uri(env).startswith("vless://"))

    def test_ru_server_config_sets_default_domain_resolver(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_ru_singbox(env))
        self.assertEqual(payload["route"]["default_domain_resolver"]["server"], "dns-global")

    def test_render_next_steps_mentions_hiddify_and_status(self) -> None:
        env = self.make_env()
        text = render.render_next_steps(env)
        self.assertIn("Hiddify", text)
        self.assertIn("vpn status", text)

    def test_render_client_profiles_writes_user_artifacts(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                render.render_client_profiles(env)
                client_dir = Path(tmp) / "demo" / "client"
                self.assertTrue((client_dir / "hiddify-uri.txt").is_file())
                self.assertTrue((client_dir.parent / "NEXT-STEPS.txt").is_file())

    def test_fetch_assets_fail_fast_without_cache(self) -> None:
        env = self.make_env()
        env["RU_GEOSITE_URL"] = "http://127.0.0.1:9/geosite-ru.srs"
        env["RU_GEOIP_URL"] = "http://127.0.0.1:9/geoip-ru.srs"
        env["FOREIGN_RU_IPV4_LIST_URL"] = "http://127.0.0.1:9/ru-ipv4.zone"
        env["FOREIGN_RU_IPV6_LIST_URL"] = "http://127.0.0.1:9/ru-ipv6.zone"
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(Exception):
                    render.fetch_assets(env, Path(tmp))

    def test_fetch_assets_tries_next_source_after_failure(self) -> None:
        env = self.make_env()
        env["RU_GEOSITE_URL"] = "https://bad.example/geosite-ru.srs https://good.example/geosite-ru.srs"
        env["RU_GEOIP_URL"] = "https://good.example/geoip-ru.srs"
        env["FOREIGN_RU_IPV4_LIST_URL"] = "https://good.example/ru-ipv4.zone"
        env["FOREIGN_RU_IPV6_LIST_URL"] = "https://good.example/ru-ipv6.zone"

        calls: list[str] = []

        def fake_download(source: str, destination: Path, asset_name: str) -> None:
            calls.append(source)
            if source.startswith("https://bad.example/"):
                raise OSError("boom")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(f"{asset_name}\n", encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "download_asset", side_effect=fake_download):
                result = render.fetch_assets(env, Path(tmp))
                self.assertTrue(result["geosite-ru.srs"].is_file())
        self.assertIn("https://bad.example/geosite-ru.srs", calls)
        self.assertIn("https://good.example/geosite-ru.srs", calls)

    def test_client_artifact_paths_contract(self) -> None:
        env = self.make_env()
        paths = render.client_artifact_paths(env)
        self.assertEqual(paths["uri"].name, "hiddify-uri.txt")
        self.assertEqual(paths["next_steps"].name, "NEXT-STEPS.txt")


if __name__ == "__main__":
    unittest.main()
