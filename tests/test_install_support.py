from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vpn_installer.config import generate_default_env, render_env_text
from vpn_installer.install_support import main as install_support_main


class InstallSupportTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        return env

    def test_render_role_writes_flat_ru_artifacts(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            output_dir = tmp_path / "out"
            env_path.write_text(render_env_text(env), encoding="utf-8")
            rc = install_support_main(["render-role", "--role", "ru-gateway", "--env-file", str(env_path), "--output-dir", str(output_dir)])
            self.assertEqual(rc, 0)
            payload = json.loads((output_dir / "sing-box.json").read_text(encoding="utf-8"))
            xray_payload = json.loads((output_dir / "xray.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["route"]["final"], "to-foreign")
            self.assertNotIn("multiplex", payload["inbounds"][0])
            self.assertEqual(payload["inbounds"][0]["listen_port"], 2080)
            self.assertEqual(xray_payload["inbounds"][0]["port"], 443)
            self.assertTrue((output_dir / "vpn-stack-agent.py").is_file())
            self.assertFalse((output_dir / "guard.sh").exists())
            self.assertTrue((output_dir / "admin_apply.py").is_file())
            self.assertTrue((output_dir / "admin_web.py").is_file())
            self.assertTrue((output_dir / "vpn-stack-xray.service").is_file())
            self.assertTrue((output_dir / "vpn-stack-admin.service").is_file())
            self.assertFalse((output_dir / "vpn-stack-sync.service").exists())
            self.assertTrue((output_dir / "vpn-stack-health.service").is_file())
            self.assertFalse((output_dir / "vpn-stack-guard.service").exists())
            self.assertFalse((output_dir / "vpn-stack-subscription.service").exists())

    def test_render_role_preserves_explicit_ru_port(self) -> None:
        env = self.make_env()
        env["RU_LISTEN_PORT"] = "8443"
        env["RU_REALITY_MAX_TIME_DIFFERENCE"] = "24h"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            output_dir = tmp_path / "out"
            env_path.write_text(render_env_text(env), encoding="utf-8")
            rc = install_support_main(["render-role", "--role", "ru-gateway", "--env-file", str(env_path), "--output-dir", str(output_dir)])
            self.assertEqual(rc, 0)
            router_payload = json.loads((output_dir / "sing-box.json").read_text(encoding="utf-8"))
            xray_payload = json.loads((output_dir / "xray.json").read_text(encoding="utf-8"))
        self.assertEqual([inbound["listen_port"] for inbound in router_payload["inbounds"]], [2080, 8443])
        self.assertEqual(xray_payload["inbounds"][0]["port"], 8443)
        self.assertNotIn("maxTimeDiff", xray_payload["inbounds"][0]["streamSettings"]["realitySettings"])

    def test_render_role_applies_wan_override(self) -> None:
        env = self.make_env()
        env["WAN_INTERFACE"] = ""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            output_dir = tmp_path / "out"
            env_path.write_text(render_env_text(env), encoding="utf-8")
            rc = install_support_main(
                [
                    "render-role",
                    "--role",
                    "foreign-exit",
                    "--env-file",
                    str(env_path),
                    "--output-dir",
                    str(output_dir),
                    "--set",
                    "WAN_INTERFACE=ens7",
                ]
            )
            self.assertEqual(rc, 0)
            nftables = (output_dir / "nftables.conf").read_text(encoding="utf-8")
            self.assertIn('oifname "ens7"', nftables)


if __name__ == "__main__":
    unittest.main()
