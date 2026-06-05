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
        self.assertEqual(paths["vless_compat_uri"].name, "vless-uri-compatible.txt")
        self.assertEqual(paths["next_steps"], Path(tmp) / "demo" / "NEXT-STEPS.txt")

    def test_render_client_profiles_honors_explicit_out_dir(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            client_dir = client_artifacts.render_client_profiles(env, out_dir=Path(tmp))

            self.assertEqual(client_dir, Path(tmp) / "demo" / "client")
            self.assertTrue((client_dir / "vless-uri.txt").is_file())
            self.assertTrue((client_dir / "vless-uri-compatible.txt").is_file())
            self.assertTrue((client_dir / "hiddify-cross-platform.json").is_file())
            self.assertTrue((Path(tmp) / "demo" / "NEXT-STEPS.txt").is_file())


if __name__ == "__main__":
    unittest.main()
