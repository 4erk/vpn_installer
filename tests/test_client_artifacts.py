from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from vpn_installer import client_artifacts
from vpn_installer.config import generate_default_env


class ClientArtifactTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        return env

    def test_primary_vless_uri_dual_contract_is_byte_stable(self) -> None:
        env = self.make_env()
        env.update(
            {
                "CLIENT_UUID": "00000000-0000-0000-0000-000000000000",
                "RU_REALITY_PUBLIC_KEY": "public-key",
                "RU_REALITY_SHORT_ID": "0123456789abcdef",
            }
        )
        self.assertEqual(
            client_artifacts.render_vless_uri(env),
            "vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?"
            "security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&"
            "fp=chrome&type=tcp&flow=xtls-rprx-vision#demo-ru-gateway\n",
        )

    def test_single_client_excludes_only_its_gateway(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "198.51.100.20"
        self.assertEqual(client_artifacts.client_route_excludes(env), ["198.51.100.20/32"])
        self.assertIn("@198.51.100.20:443?", client_artifacts.render_vless_uri(env))
        self.assertNotIn("203.0.113.10", client_artifacts.render_client_profile(env, auto_redirect=False))

    def test_client_artifact_paths_honor_explicit_out_dir(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            paths = client_artifacts.client_artifact_paths(env, out_dir=Path(tmp))

        self.assertEqual(paths["client_dir"], Path(tmp) / "demo" / "client")
        self.assertEqual(paths["vless_uri"].name, "vless-uri.txt")
        self.assertEqual(paths["v2rayn_uri"].name, "v2rayn-uri.txt")
        self.assertEqual(paths["android_xray_json"].name, "android-v2rayng-xray.json")
        self.assertEqual(paths["hysteria2_uri"].name, "hysteria2-uri.txt")
        self.assertEqual(paths["next_steps"], Path(tmp) / "demo" / "NEXT-STEPS.txt")

    def test_next_steps_use_canonical_node_selector(self) -> None:
        rendered = client_artifacts.render_next_steps(self.make_env())

        self.assertIn("status --deployment demo --node gateway", rendered)
        self.assertIn("diagnose client --deployment demo --source <public-ip>", rendered)
        self.assertNotIn("--role ru-gateway", rendered)

    def test_render_client_profiles_honors_explicit_out_dir(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            client_dir = client_artifacts.render_client_profiles(env, out_dir=Path(tmp))

            self.assertEqual(client_dir, Path(tmp) / "demo" / "client")
            self.assertTrue((client_dir / "vless-uri.txt").is_file())
            self.assertEqual(
                (client_dir / "v2rayn-uri.txt").read_text(encoding="utf-8"),
                (client_dir / "vless-uri.txt").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (client_dir / "hiddify-uri.txt").read_text(encoding="utf-8"),
                (client_dir / "vless-uri.txt").read_text(encoding="utf-8"),
            )
            self.assertTrue((client_dir / "android-v2rayng-xray.json").is_file())
            self.assertTrue((client_dir / "hiddify-cross-platform.json").is_file())
            hiddify = json.loads((client_dir / "hiddify-cross-platform.json").read_text(encoding="utf-8"))
            self.assertEqual(hiddify["route"]["final"], client_artifacts.PUBLIC_VLESS_OUTBOUND_TAG)
            self.assertEqual(hiddify["outbounds"][0]["multiplex"], {"enabled": False})
            self.assertTrue((client_dir / "hysteria2-uri.txt").read_text(encoding="utf-8").startswith("hysteria2://"))
            self.assertEqual(
                (client_dir / "android-v2rayng-xray.json").read_text(encoding="utf-8"),
                (client_dir / "windows-xray.json").read_text(encoding="utf-8"),
            )
            self.assertTrue((Path(tmp) / "demo" / "NEXT-STEPS.txt").is_file())
            if os.name != "nt":
                for path in client_dir.iterdir():
                    if path.is_file():
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)

    def test_render_client_profiles_replaces_stale_generated_directory(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            client_dir = Path(tmp) / "demo" / "client"
            stale_path = client_dir / "android-v2rayng-xray.json"
            stale_path.mkdir(parents=True)
            (client_dir / "sing-box-adaptive.json").write_text("stale", encoding="utf-8")
            (client_dir / "live-xray-smoke.json").write_text("stale", encoding="utf-8")
            operator_notes = client_dir / "operator-notes.txt"
            operator_notes.write_text("keep", encoding="utf-8")

            client_artifacts.render_client_profiles(env, out_dir=Path(tmp))

            self.assertTrue(stale_path.is_file())
            self.assertIn('"protocol": "vless"', stale_path.read_text(encoding="utf-8"))
            self.assertFalse((client_dir / "sing-box-adaptive.json").exists())
            self.assertFalse((client_dir / "live-xray-smoke.json").exists())
            self.assertEqual(operator_notes.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
