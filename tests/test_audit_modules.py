from __future__ import annotations

import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.audit import docker as audit_docker
from vpn_installer.audit import lab as audit_lab
from vpn_installer.audit import quick as audit_quick
from vpn_installer.audit.runner import AuditFailure


class FakeRunner:
    def __init__(self) -> None:
        self.records: list[str] = []
        self.skips: list[str] = []
        self.run_id = "rid"
        self.mode = "quick"

    def ensure_audit_image(self) -> None:
        self.records.append("ensure")

    def record(self, name, fn):
        self.records.append(name)

    def skip(self, name, _reason):
        self.skips.append(name)


class AuditModuleTests(unittest.TestCase):
    def test_quick_run_registers_expected_checks(self) -> None:
        class QuickRunner(FakeRunner):
            def ensure_quick_env(self):
                with tempfile.TemporaryDirectory() as tmp:
                    pass
                path = Path(tempfile.gettempdir()) / "demo.env"
                path.write_text('DEPLOY_NAME="demo"\n', encoding="utf-8")
                return path, Path(tempfile.gettempdir()) / "demo"

            def seed_foreign_block_cache(self, _name):
                return None

        runner = QuickRunner()
        no_op = patch.multiple(
            audit_quick,
            test_coverage=lambda *_args, **_kwargs: {},
            test_install_ux_helpers=lambda *_args, **_kwargs: {},
            test_render_all=lambda *_args, **_kwargs: {},
            test_validate_json=lambda *_args, **_kwargs: {},
            test_user_artifacts=lambda *_args, **_kwargs: {},
            test_validate_bundle=lambda *_args, **_kwargs: {},
            test_singbox_check=lambda *_args, **_kwargs: {},
            test_cloud_init_schema=lambda *_args, **_kwargs: {},
            test_cloud_init_render_only=lambda *_args, **_kwargs: {},
            test_bundle_render_only=lambda *_args, **_kwargs: {},
            test_windows_clean_room=lambda *_args, **_kwargs: {},
            test_linux_launcher_no_python=lambda *_args, **_kwargs: {},
            test_linux_launcher_with_python=lambda *_args, **_kwargs: {},
            test_vpn_menu_exit=lambda *_args, **_kwargs: {},
            load_env_file=lambda *_args, **_kwargs: {"DEPLOY_NAME": "demo"},
        )
        with (
            no_op,
            patch("vpn_installer.audit.quick.shutil.which", return_value="found"),
            patch("vpn_installer.audit.quick.docker_readiness", return_value=(True, "")),
        ):
            audit_quick.run(runner)  # type: ignore[arg-type]
        self.assertNotIn("quick-unittest", runner.records)
        self.assertIn("quick-install-ux", runner.records)
        self.assertIn("quick-interserver-hysteria-runtime", runner.records)
        self.assertIn("quick-unittest", runner.skips)
        self.assertIn("quick-linux-launcher-python", runner.skips)

    def test_quick_helper_validations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            preview = out_dir / "preview"
            client = out_dir / "client"
            bundle = out_dir / "bundle"
            cloud = out_dir / "cloud-init"
            (preview / "ru").mkdir(parents=True)
            (preview / "foreign").mkdir(parents=True)
            client.mkdir(parents=True)
            bundle.mkdir(parents=True)
            cloud.mkdir(parents=True)
            server = out_dir / "server"
            server.mkdir(parents=True)
            (server / "ru.env").write_text('DEPLOY_NAME="demo"\n', encoding="utf-8")
            for path in [
                preview / "ru" / "sing-box.json",
                preview / "ru" / "xray.json",
                preview / "foreign" / "sing-box.json",
                client / "hiddify-cross-platform.json",
                client / "linux-sing-box.json",
            ]:
                path.write_text("{}\n", encoding="utf-8")
            (client / "android-v2rayng-xray.json").write_text(
                json.dumps(
                    {
                        "inbounds": [{"sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}}],
                        "routing": {
                            "domainStrategy": "AsIs",
                            "rules": [{"type": "field", "ip": ["::/0"], "outboundTag": "block"}],
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (client / "vless-uri.txt").write_text("vless://demo\n", encoding="utf-8")
            (client / "hiddify-cross-platform.json").write_text("{}\n", encoding="utf-8")
            (client / "hiddify-android.json").write_text("{}\n", encoding="utf-8")
            (client / "hiddify-uri.txt").write_text("vless://demo\n", encoding="utf-8")
            (out_dir / "NEXT-STEPS.txt").write_text("VLESS URI\nv2rayNG\nandroid-v2rayng-xray.json\nvpn status\n", encoding="utf-8")
            for name in ("ru-gateway.tar.gz", "foreign-exit.tar.gz"):
                with tarfile.open(bundle / name, "w:gz") as archive:
                    keep = out_dir / f"{name}.txt"
                    keep.write_text("x", encoding="utf-8")
                    archive.add(keep, arcname="demo.txt")
            with self.assertRaises(AuditFailure):
                audit_quick.test_validate_bundle(out_dir)
            self.assertIn("validated", audit_quick.test_validate_json(out_dir))
            self.assertIn("vless_uri", audit_quick.test_user_artifacts(out_dir))

    def test_quick_vpn_menu_exit_accepts_expected_output(self) -> None:
        class Runner:
            def run_command(self, *_args, **_kwargs):
                import subprocess

                return subprocess.CompletedProcess(["pwsh"], 0, stdout="VPN Installer\nВыбери действие\nЗавершено.\n", stderr="")

        with patch("vpn_installer.audit.quick.powershell_executable", return_value="powershell"):
            result = audit_quick.test_vpn_menu_exit(Runner())
        self.assertIn("launcher", result)

    def test_docker_run_registers_checks(self) -> None:
        runner = FakeRunner()
        audit_docker.run(runner)  # type: ignore[arg-type]
        self.assertIn("docker-unmanaged-remove-purge-render-only", runner.records)
        self.assertIn("docker-remote-action-purge-role", runner.records)

    def test_lab_builders_return_expected_content(self) -> None:
        self.assertIn("address=/ya.ru/", audit_lab.build_lab_dnsmasq())
        self.assertIn("server=ru-web", audit_lab.build_lab_web_server("ru-web"))
        env = {
            "RU_LISTEN_PORT": "443",
            "CLIENT_UUID": "00000000-0000-0000-0000-000000000000",
            "WG_INTERFACE": "wg0",
            "RU_PUBLIC_IP": "203.0.113.10",
            "FOREIGN_PUBLIC_IP": "198.51.100.20",
        }
        client_cfg = audit_lab.build_lab_client_config(env)
        self.assertIn('"server": "198.18.0.10"', client_cfg)

    def test_lab_run_registers_dataplane_check(self) -> None:
        runner = FakeRunner()
        audit_lab.run(runner)  # type: ignore[arg-type]
        self.assertIn("lab-dataplane", runner.records)


if __name__ == "__main__":
    unittest.main()
