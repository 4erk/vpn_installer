from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vpn_installer import client_artifacts
from vpn_installer.config import generate_default_env


class ClientArtifactTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        return env

    def test_client_artifact_paths_honor_explicit_out_dir(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            paths = client_artifacts.client_artifact_paths(env, out_dir=Path(tmp))

        self.assertEqual(paths["client_dir"], Path(tmp) / "demo" / "client")
        self.assertEqual(paths["vless_uri"].name, "vless-uri.txt")
        self.assertEqual(paths["android_xray_json"].name, "android-v2rayng-xray.json")
        self.assertEqual(paths["next_steps"], Path(tmp) / "demo" / "NEXT-STEPS.txt")

    def test_render_client_profiles_honors_explicit_out_dir(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            client_dir = client_artifacts.render_client_profiles(env, out_dir=Path(tmp))

            self.assertEqual(client_dir, Path(tmp) / "demo" / "client")
            self.assertTrue((client_dir / "vless-uri.txt").is_file())
            self.assertTrue((client_dir / "android-v2rayng-xray.json").is_file())
            self.assertTrue((client_dir / "hiddify-cross-platform.json").is_file())
            self.assertEqual(
                (client_dir / "android-v2rayng-xray.json").read_text(encoding="utf-8"),
                (client_dir / "windows-xray.json").read_text(encoding="utf-8"),
            )
            self.assertTrue((Path(tmp) / "demo" / "NEXT-STEPS.txt").is_file())

    def test_render_client_profiles_replaces_stale_generated_directory(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            stale_path = Path(tmp) / "demo" / "client" / "android-v2rayng-xray.json"
            stale_path.mkdir(parents=True)

            client_artifacts.render_client_profiles(env, out_dir=Path(tmp))

            self.assertTrue(stale_path.is_file())
            self.assertIn('"protocol": "vless"', stale_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
