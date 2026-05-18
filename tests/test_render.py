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

    def test_render_xray_client_profile_uses_reality_vless(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_xray_client_profile(env))
        self.assertEqual(payload["inbounds"][0]["protocol"], "socks")
        outbound = payload["outbounds"][0]
        self.assertEqual(outbound["protocol"], "vless")
        self.assertEqual(outbound["settings"]["vnext"][0]["address"], env["RU_PUBLIC_IP"])
        self.assertEqual(outbound["settings"]["vnext"][0]["port"], int(env["RU_LISTEN_PORT"]))
        self.assertEqual(outbound["settings"]["vnext"][0]["users"][0]["id"], env["CLIENT_UUID"])
        self.assertEqual(outbound["streamSettings"]["security"], "reality")
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["publicKey"], env["RU_REALITY_PUBLIC_KEY"])
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["shortId"], env["RU_REALITY_SHORT_ID"])

    def test_client_profile_is_simple_ru_tunnel(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_client_profile(env, auto_redirect=False))
        servers = {server["tag"]: server for server in payload["dns"]["servers"]}
        self.assertEqual(set(servers), {"dns-remote"})
        self.assertNotIn("reverse_mapping", payload["dns"])
        self.assertEqual(payload["dns"]["rules"], [{"query_type": ["AAAA"], "action": "reject"}])
        self.assertEqual(payload["route"]["final"], "ru-gateway")
        self.assertEqual(payload["route"]["default_domain_resolver"]["server"], "dns-remote")
        self.assertEqual(payload["inbounds"][0]["address"], [env["CLIENT_TUN_ADDRESS_V4"], env["CLIENT_TUN_ADDRESS_V6"]])
        self.assertEqual(
            payload["inbounds"][0]["route_exclude_address"][:2],
            [f"{env['RU_PUBLIC_IP']}/32", f"{env['FOREIGN_PUBLIC_IP']}/32"],
        )

    def test_android_client_profile_is_ipv4_only_and_sets_android_override(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_client_profile(env, auto_redirect=False, android_safe=True))
        self.assertEqual(payload["inbounds"][0]["address"], [env["CLIENT_TUN_ADDRESS_V4"]])
        self.assertTrue(payload["route"]["override_android_vpn"])
        self.assertEqual(payload["route"]["final"], "ru-gateway")
        self.assertEqual(
            payload["inbounds"][0]["route_exclude_address"][:2],
            [f"{env['RU_PUBLIC_IP']}/32", f"{env['FOREIGN_PUBLIC_IP']}/32"],
        )

    def test_client_profile_preserves_manual_route_excludes_after_server_ips(self) -> None:
        env = self.make_env()
        env["CLIENT_ROUTE_EXCLUDE_V4"] = "198.51.100.10/32,198.51.100.11/32"
        env["CLIENT_ROUTE_EXCLUDE_V6"] = "2001:db8::/32"
        payload = json.loads(render.render_client_profile(env, auto_redirect=False))
        self.assertEqual(
            payload["inbounds"][0]["route_exclude_address"],
            [
                f"{env['RU_PUBLIC_IP']}/32",
                f"{env['FOREIGN_PUBLIC_IP']}/32",
                "198.51.100.10/32",
                "198.51.100.11/32",
                "2001:db8::/32",
            ],
        )

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
        self.assertIn("ip.mail.ru", direct_domain_dns_rule["domain"])
        self.assertIn("ipv4-internet.yandex.net", direct_domain_dns_rule["domain"])
        self.assertIn("ipv6-internet.yandex.net", direct_domain_dns_rule["domain"])
        self.assertIn("2ip.ru", direct_domain_dns_rule["domain"])

        direct_suffix_dns_rule = next(rule for rule in dns_rules if "domain_suffix" in rule)
        self.assertIn(".gstatic.com", direct_suffix_dns_rule["domain_suffix"])
        self.assertIn(".ipify.org", direct_suffix_dns_rule["domain_suffix"])
        self.assertIn(".ipinfo.io", direct_suffix_dns_rule["domain_suffix"])

        direct_domain_route_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain" in rule)
        self.assertIn("gosuslugi.ru", direct_domain_route_rule["domain"])
        self.assertIn("ipapi.co", direct_domain_route_rule["domain"])
        self.assertIn("icanhazip.com", direct_domain_route_rule["domain"])
        self.assertIn("ip.mail.ru", direct_domain_route_rule["domain"])
        self.assertIn("ipv4-internet.yandex.net", direct_domain_route_rule["domain"])
        self.assertIn("ipv6-internet.yandex.net", direct_domain_route_rule["domain"])
        self.assertIn("2ip.ru", direct_domain_route_rule["domain"])

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

    def test_render_next_steps_mentions_uri_first_contract(self) -> None:
        env = self.make_env()
        text = render.render_next_steps(env)
        self.assertIn("VLESS URI", text)
        self.assertIn("v2rayNG", text)
        self.assertIn("NekoBox", text)
        self.assertIn("Hiddify", text)
        self.assertIn("windows-xray.json", text)
        self.assertIn("Xray core", text)
        self.assertIn("vpn status", text)
        self.assertIn("vless-uri.txt", text)
        self.assertIn("hiddify-cross-platform.json", text)
        self.assertIn("hiddify-android.json", text)
        self.assertIn("совместимый alias", text)

    def test_render_client_profiles_writes_user_artifacts(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                render.render_client_profiles(env)
                client_dir = Path(tmp) / "demo" / "client"
                self.assertTrue((client_dir / "vless-uri.txt").is_file())
                self.assertTrue((client_dir / "windows-xray.json").is_file())
                self.assertTrue((client_dir / "hiddify-cross-platform.json").is_file())
                self.assertTrue((client_dir / "hiddify-android.json").is_file())
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
        self.assertEqual(paths["vless_uri"].name, "vless-uri.txt")
        self.assertEqual(paths["hiddify_uri_compat"].name, "hiddify-uri.txt")
        self.assertEqual(paths["hiddify_json"].name, "hiddify-cross-platform.json")
        self.assertEqual(paths["android_hiddify_json"].name, "hiddify-android.json")
        self.assertEqual(paths["linux_json"].name, "linux-sing-box.json")
        self.assertEqual(paths["windows_xray_json"].name, "windows-xray.json")
        self.assertEqual(paths["next_steps"].name, "NEXT-STEPS.txt")

    def test_render_client_profiles_keeps_hiddify_uri_alias_equal_to_primary_uri(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                render.render_client_profiles(env)
                client_dir = Path(tmp) / "demo" / "client"
                self.assertEqual(
                    (client_dir / "vless-uri.txt").read_text(encoding="utf-8"),
                    (client_dir / "hiddify-uri.txt").read_text(encoding="utf-8"),
                )

    def test_rendered_files_for_role_contains_core_contract(self) -> None:
        env = self.make_env()
        files = render.rendered_files_for_role(env, render.ROLE_RU)
        self.assertIn("sing-box.json", files)
        self.assertIn(f"{env['WG_INTERFACE']}.conf", files)
        self.assertIn("sshd-vpn-stack.conf", files)
        self.assertIn("health-check.sh", files)
        self.assertIn("vpn-stack-sync.service", files)
        self.assertIn("vpn-stack-health.service", files)
        self.assertIn("vpn-stack-health.timer", files)

    def test_render_health_script_hardens_ru_runtime(self) -> None:
        env = self.make_env()
        script = render.render_health_script(env, render.ROLE_RU)
        self.assertIn('ROLE="ru-gateway"', script)
        self.assertIn('DISABLE_NIC_OFFLOADS="1"', script)
        self.assertIn('SELF_HEAL_ENABLED="1"', script)
        self.assertIn('SELF_HEAL_COOLDOWN_MINUTES="15"', script)
        self.assertIn('SELF_HEAL_MAX_ACTIONS_PER_HOUR="2"', script)
        self.assertIn('SELF_HEAL_CONFIRMATIONS="2"', script)
        self.assertIn('systemctl restart --no-block "wg-quick@${WG_INTERFACE}"', script)
        self.assertNotIn("systemctl restart --no-block sing-box", script)
        self.assertIn('probe_http_ipv4 "${WG_INTERFACE}"', script)
        self.assertIn('probe_ping_loss_pct_fast "${FOREIGN_PUBLIC_IP}"', script)
        self.assertIn("ru_foreign_ping_loss_fast", script)
        self.assertIn('HEALTH_THROUGHPUT_URLS="https://cachefly.cachefly.net/1mb.test https://proof.ovh.net/files/1Mb.dat"', script)
        self.assertIn('HEALTH_STATE_PATH="/var/lib/vpn-stack/health-state.env"', script)
        self.assertIn("run_deep_probe()", script)
        self.assertIn('DEEP_RU_WG_DOWNLOAD_MIN_BPS=', script)
        self.assertIn('probe_upload_bps "${WG_INTERFACE}"', script)
        self.assertIn('ethtool -K "${iface}" gro off', script)
        self.assertIn('ethtool -K "${iface}" gso off', script)
        self.assertIn('ethtool -K "${iface}" tso off', script)
        self.assertIn("cloudflare.com/cdn-cgi/trace", script)
        self.assertIn("ssh_banner_ok", script)
        self.assertIn("collect_hard_reasons()", script)
        self.assertIn("collect_soft_reasons()", script)
        self.assertIn('log "runtime degraded without hard failure: ${soft_reasons[*]}"', script)
        self.assertIn('log "runtime hard failure: ${hard_reasons[*]}"', script)
        self.assertIn('maybe_self_heal "soft" "${soft_reasons[@]}"', script)
        self.assertIn('maybe_self_heal "hard" "${hard_reasons[@]}"', script)

    def test_render_health_script_hardens_foreign_runtime(self) -> None:
        env = self.make_env()
        script = render.render_health_script(env, render.ROLE_FOREIGN)
        self.assertIn('ROLE="foreign-exit"', script)
        self.assertIn('WAN_INTERFACE="eth1"', script)
        self.assertIn('SELF_HEAL_ENABLED="1"', script)
        self.assertIn('systemctl restart --no-block "wg-quick@${WG_INTERFACE}"', script)
        self.assertIn('systemctl restart --no-block nftables vpn-stack-sync.service', script)
        self.assertIn('probe_ping_loss_pct "${RU_PUBLIC_IP}"', script)
        self.assertIn('probe_ping_loss_pct_fast "${RU_PUBLIC_IP}"', script)
        self.assertIn("foreign_ru_ping_loss_fast", script)
        self.assertIn('DEEP_FOREIGN_DIRECT_DOWNLOAD_MIN_BPS=', script)
        self.assertIn('DEEP_FOREIGN_RU_PING_LOSS_PCT=', script)
        self.assertIn('probe_http_ipv4 ""', script)
        self.assertIn("detect_default_iface", script)
        self.assertIn('log "latest deep degradation snapshot: ${soft_reasons[*]}"', script)

    @unittest.skipUnless(preferred_bash(), "bash is required for health script syntax test")
    def test_render_health_script_is_bash_valid_for_both_roles(self) -> None:
        env = self.make_env()
        bash = preferred_bash() or "bash"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for role in (render.ROLE_RU, render.ROLE_FOREIGN):
                script_path = tmp_path / f"{role}.sh"
                script_path.write_text(render.render_health_script(env, role), encoding="utf-8")
                completed = subprocess.run(
                    [bash, "-n", str(script_path)],
                    capture_output=True,
                    text=True,
                    env={**os.environ, "LC_ALL": "C.UTF-8"},
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    msg=f"{role} health script syntax error:\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
                )

    def test_render_sshd_hardening_uses_expected_limits(self) -> None:
        env = self.make_env()
        config = render.render_sshd_hardening(env)
        self.assertIn("LoginGraceTime 20", config)
        self.assertIn("MaxAuthTries 3", config)
        self.assertIn("MaxStartups 5:30:20", config)
        self.assertIn("PerSourceMaxStartups 2", config)

    def test_render_ru_nftables_rate_limits_public_ports(self) -> None:
        env = self.make_env()
        rules = render.render_ru_firewall_nftables(env)
        self.assertIn("ct state invalid drop", rules)
        self.assertIn(f"tcp dport {env['SSH_PORT']} ct state new meter ssh_guard", rules)
        self.assertIn(f"limit rate {env['SSH_INPUT_RATE']} burst {env['SSH_INPUT_BURST']} packets", rules)
        self.assertIn(f"tcp dport {env['RU_LISTEN_PORT']} ct state new meter vless_guard", rules)
        self.assertIn(f"limit rate {env['RU_HTTPS_INPUT_RATE']} burst {env['RU_HTTPS_INPUT_BURST']} packets", rules)
        self.assertNotIn("subscription_guard", rules)

    def test_render_foreign_nftables_rate_limits_ssh(self) -> None:
        env = self.make_env()
        rules = render.render_foreign_nftables(env, "eth0")
        self.assertIn("ct state invalid drop", rules)
        self.assertIn(f"tcp dport {env['SSH_PORT']} ct state new meter ssh_guard", rules)
        self.assertIn(f"limit rate {env['SSH_INPUT_RATE']} burst {env['SSH_INPUT_BURST']} packets", rules)
        self.assertIn(f"udp dport {env['WG_PORT']} accept", rules)

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

    def test_render_all_artifacts_merges_local_ru_direct_overlay_files(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            env_path.write_text(render.render_env_text(env), encoding="utf-8")
            (tmp_path / "demo.ru-direct-domains.txt").write_text("overlay.example\n", encoding="utf-8")
            with patch.object(render, "OUT_DIR", tmp_path / "out"), patch.object(render, "fetch_assets", return_value={}):
                render.render_all_artifacts(env_path, env)
                payload = json.loads((tmp_path / "out" / "demo" / "preview" / "ru" / "sing-box.json").read_text(encoding="utf-8"))
        direct_domain_rule = next(rule for rule in payload["route"]["rules"] if rule.get("outbound") == "direct-ru" and "domain" in rule)
        self.assertIn("overlay.example", direct_domain_rule["domain"])

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
        self.assertIn("2ip.ru", direct_domain_rule["domain"])
        direct_suffix_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain_suffix" in rule)
        self.assertIn(".ipify.org", direct_suffix_rule["domain_suffix"])
        cidr_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "ip_cidr" in rule)
        self.assertEqual(cidr_rule["ip_cidr"], ["203.0.113.0/24"])
        dns_direct_rule = next(rule for rule in dns_rules if "domain" in rule)
        self.assertIn("api.oneme.ru", dns_direct_rule["domain"])
        self.assertIn("ip.mail.ru", dns_direct_rule["domain"])
        self.assertNotIn("detour", servers["dns-ru-direct"])
        self.assertEqual(servers["dns-global"]["detour"], "to-foreign")


if __name__ == "__main__":
    unittest.main()
