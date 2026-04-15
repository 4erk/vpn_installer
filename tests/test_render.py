from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.config import generate_default_env
from vpn_installer import render
import json


def preferred_bash() -> str | None:
    candidates = [
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return shutil.which("bash")


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

    def test_render_subscription_urls(self) -> None:
        env = self.make_env()
        subscription = render.render_subscription_url(env).strip()
        deeplink = render.render_hiddify_import_url(env).strip()
        self.assertEqual(subscription, f"http://203.0.113.10:{env['SUBSCRIPTION_PORT']}/{env['SUBSCRIPTION_TOKEN']}/hiddify-cross-platform.json")
        self.assertEqual(deeplink, f"hiddify://import/{subscription}#demo")

    def test_client_profile_keeps_hiddify_as_simple_ru_tunnel(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_client_profile(env, auto_redirect=False))
        servers = {server["tag"]: server for server in payload["dns"]["servers"]}
        self.assertEqual(set(servers), {"dns-remote"})
        self.assertNotIn("reverse_mapping", payload["dns"])
        self.assertEqual(payload["dns"]["rules"], [{"query_type": ["AAAA"], "action": "reject"}])
        self.assertEqual(payload["route"]["final"], "ru-gateway")
        self.assertEqual(payload["route"]["default_domain_resolver"]["server"], "dns-remote")

    def test_ru_server_config_sets_default_domain_resolver(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_ru_singbox(env))
        self.assertEqual(payload["route"]["default_domain_resolver"]["server"], "dns-ru-direct")

    def test_ru_server_dns_servers_keep_global_detour_but_not_direct_detour(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_ru_singbox(env))
        servers = {server["tag"]: server for server in payload["dns"]["servers"]}
        self.assertIn("dns-ru-direct", servers)
        self.assertNotIn("detour", servers["dns-ru-direct"])
        self.assertEqual(servers["dns-global"]["detour"], "to-foreign")

    def test_ru_server_config_forces_selected_domains_and_suffixes_direct(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_ru_singbox(env))
        dns_rules = payload["dns"]["rules"]
        route_rules = payload["route"]["rules"]

        direct_domain_dns_rule = next(rule for rule in dns_rules if "domain" in rule)
        self.assertIn("api.oneme.ru", direct_domain_dns_rule["domain"])
        self.assertIn("api.ok.ru", direct_domain_dns_rule["domain"])
        self.assertIn("checkip.amazonaws.com", direct_domain_dns_rule["domain"])
        self.assertIn("ident.me", direct_domain_dns_rule["domain"])

        direct_suffix_dns_rule = next(rule for rule in dns_rules if "domain_suffix" in rule)
        self.assertIn(".gstatic.com", direct_suffix_dns_rule["domain_suffix"])
        self.assertIn(".ipify.org", direct_suffix_dns_rule["domain_suffix"])
        self.assertIn(".ipinfo.io", direct_suffix_dns_rule["domain_suffix"])

        direct_domain_route_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain" in rule)
        self.assertIn("gosuslugi.ru", direct_domain_route_rule["domain"])
        self.assertIn("ipapi.co", direct_domain_route_rule["domain"])
        self.assertIn("icanhazip.com", direct_domain_route_rule["domain"])

        direct_suffix_route_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain_suffix" in rule)
        self.assertIn(".ident.me", direct_suffix_route_rule["domain_suffix"])
        self.assertIn(".icanhazip.com", direct_suffix_route_rule["domain_suffix"])

        self.assertFalse(any(rule.get("domain") == ["api.ok.ru"] and rule.get("outbound") == "block" for rule in route_rules))

    def test_ru_server_config_supports_forced_direct_ip_cidr(self) -> None:
        env = self.make_env()
        env["RU_FORCE_DIRECT_IP_CIDR"] = "203.0.113.0/24,198.51.100.4/32"
        payload = json.loads(render.render_ru_singbox(env))
        cidr_rule = next(rule for rule in payload["route"]["rules"] if rule.get("outbound") == "direct-ru" and "ip_cidr" in rule)
        self.assertEqual(cidr_rule["ip_cidr"], ["203.0.113.0/24", "198.51.100.4/32"])

    def test_render_next_steps_mentions_hiddify_and_status(self) -> None:
        env = self.make_env()
        text = render.render_next_steps(env)
        self.assertIn("Hiddify", text)
        self.assertIn("vpn status", text)
        self.assertIn("hiddify-subscription-url.txt", text)
        self.assertIn("hiddify-import-url.txt", text)
        self.assertIn("сырой запасной", text)

    def test_render_client_profiles_writes_user_artifacts(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                render.render_client_profiles(env)
                client_dir = Path(tmp) / "demo" / "client"
                self.assertTrue((client_dir / "hiddify-subscription-url.txt").is_file())
                self.assertTrue((client_dir / "hiddify-import-url.txt").is_file())
                self.assertTrue((client_dir / "hiddify-uri.txt").is_file())
                self.assertTrue((client_dir.parent / "NEXT-STEPS.txt").is_file())

    def test_cloud_init_artifacts_embed_renderer_and_pre_rendered_role_files(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                out_dir = Path(tmp) / "demo"
                assets_dir = out_dir / "assets"
                assets_dir.mkdir(parents=True, exist_ok=True)
                for asset_name in ("geosite-ru.srs", "geoip-ru.srs", "ru-ipv4.zone", "ru-ipv6.zone"):
                    (assets_dir / asset_name).write_text("dummy\n", encoding="utf-8")
                cloud_dir = render.render_cloud_init_artifacts(env)
                ru_yaml = (cloud_dir / "ru.yaml").read_text(encoding="utf-8")
                self.assertIn("/root/vpn-stack/vpn_installer/install_support.py", ru_yaml)
                self.assertIn("/root/vpn-stack/rendered/sing-box.json", ru_yaml)
                self.assertIn("/root/vpn-stack/rendered/sync-state.sh", ru_yaml)

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
        self.assertEqual(paths["subscription_url"].name, "hiddify-subscription-url.txt")
        self.assertEqual(paths["hiddify_import_url"].name, "hiddify-import-url.txt")
        self.assertEqual(paths["uri"].name, "hiddify-uri.txt")
        self.assertEqual(paths["next_steps"].name, "NEXT-STEPS.txt")

    def test_rendered_files_for_role_contains_core_contract(self) -> None:
        env = self.make_env()
        files = render.rendered_files_for_role(env, render.ROLE_RU)
        self.assertIn("sing-box.json", files)
        self.assertIn(f"{env['WG_INTERFACE']}.conf", files)
        self.assertIn("vpn-stack-sync.service", files)
        self.assertIn("vpn-stack-subscription.service", files)
        self.assertIn(f"subscription/{env['SUBSCRIPTION_TOKEN']}/hiddify-cross-platform.json", files)

    def test_load_env_file_from_text_parses_text_payload(self) -> None:
        payload = render.load_env_file_from_text('DEPLOY_NAME="demo"\nRU_PUBLIC_IP="203.0.113.10"\n')
        self.assertEqual(payload["DEPLOY_NAME"], "demo")
        self.assertEqual(payload["RU_PUBLIC_IP"], "203.0.113.10")

    def test_write_role_rendered_files_and_package_bundle(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                out_dir = render.deployment_out_dir(env)
                assets_dir = out_dir / "assets"
                assets_dir.mkdir(parents=True, exist_ok=True)
                for asset_name in ("geosite-ru.srs", "geoip-ru.srs", "ru-ipv4.zone", "ru-ipv6.zone"):
                    (assets_dir / asset_name).write_text("dummy\n", encoding="utf-8")
                render.write_role_rendered_files(env, render.ROLE_RU, out_dir / "preview" / "ru")
                render.write_role_rendered_files(env, render.ROLE_FOREIGN, out_dir / "preview" / "foreign")
                server_dir = out_dir / "server"
                server_dir.mkdir(parents=True, exist_ok=True)
                (server_dir / "ru.env").write_text(render.render_env_text(env), encoding="utf-8")
                (server_dir / "foreign.env").write_text(render.render_env_text(env), encoding="utf-8")
                bundle_dir = render.package_bundle(env)
                self.assertTrue((bundle_dir / "ru-gateway.tar.gz").is_file())
                self.assertTrue((bundle_dir / "foreign-exit.tar.gz").is_file())

    @unittest.skipUnless(preferred_bash(), "bash is required for install.sh render-only test")
    def test_install_sh_render_only_contains_forced_direct_rules(self) -> None:
        env = self.make_env()
        env["RU_FORCE_DIRECT_IP_CIDR"] = "203.0.113.0/24"
        repo_root = Path(__file__).resolve().parents[1]
        install_sh = repo_root / "install.sh"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_file = tmp_path / "demo.env"
            output_dir = tmp_path / "preview"
            env_file.write_text(render.render_env_text(env), encoding="utf-8")
            command = [
                preferred_bash() or "bash",
                str(install_sh),
                "--role",
                "ru-gateway",
                "--env-file",
                str(env_file),
                "--render-only",
                "--output-dir",
                str(output_dir),
            ]
            completed = subprocess.run(
                command,
                cwd=repo_root,
                capture_output=True,
                text=True,
                env={**os.environ, "LC_ALL": "C.UTF-8"},
                check=False,
            )
            self.assertEqual(completed.returncode, 0, msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}")
            payload = json.loads((output_dir / "sing-box.json").read_text(encoding="utf-8"))
        dns_rules = payload["dns"]["rules"]
        route_rules = payload["route"]["rules"]
        servers = {server["tag"]: server for server in payload["dns"]["servers"]}
        direct_domain_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain" in rule)
        self.assertIn("api.ok.ru", direct_domain_rule["domain"])
        self.assertIn("checkip.amazonaws.com", direct_domain_rule["domain"])
        direct_suffix_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain_suffix" in rule)
        self.assertIn(".ipify.org", direct_suffix_rule["domain_suffix"])
        cidr_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "ip_cidr" in rule)
        self.assertEqual(cidr_rule["ip_cidr"], ["203.0.113.0/24"])
        dns_direct_rule = next(rule for rule in dns_rules if "domain" in rule)
        self.assertIn("api.oneme.ru", dns_direct_rule["domain"])
        self.assertNotIn("detour", servers["dns-ru-direct"])
        self.assertEqual(servers["dns-global"]["detour"], "to-foreign")


if __name__ == "__main__":
    unittest.main()
