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

    def test_validate_ssh_host_accepts_domain_and_rejects_bad(self) -> None:
        self.assertEqual(config.validate_ssh_host("ssh.example.com"), "ssh.example.com")
        with self.assertRaises(Exception):
            config.validate_ssh_host("bad host")

    def test_validate_auth_mode_accepts_password(self) -> None:
        self.assertEqual(config.validate_auth_mode("password"), "password")

    def test_validate_identity_path_allows_empty(self) -> None:
        self.assertEqual(config.validate_identity_path(""), "")

    def test_normalize_identity_path_resolves_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "id_ed25519"
            key_path.write_text("key", encoding="utf-8")
            with patch("pathlib.Path.cwd", return_value=Path(tmp)):
                normalized = config.normalize_identity_path("id_ed25519")
        self.assertEqual(Path(normalized), key_path.resolve())

    def test_default_reality_keys_are_urlsafe_without_padding(self) -> None:
        env = config.generate_default_env("sample")
        self.assertNotIn("=", env["RU_REALITY_PRIVATE_KEY"])
        self.assertNotIn("+", env["RU_REALITY_PRIVATE_KEY"])
        self.assertNotIn("/", env["RU_REALITY_PRIVATE_KEY"])

    def test_default_utls_fingerprint_uses_broad_client_compatible_value(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["UTLS_FINGERPRINT"], "chrome")

    def test_merge_env_with_defaults_migrates_randomized_fingerprint(self) -> None:
        env = config.merge_env_with_defaults({"UTLS_FINGERPRINT": "randomized"}, "sample")
        self.assertEqual(env["UTLS_FINGERPRINT"], "chrome")

    def test_merge_env_with_defaults_migrates_legacy_cloudflare_reality_sni(self) -> None:
        env = config.merge_env_with_defaults(
            {
                "RU_REALITY_SERVER_NAME": "www.cloudflare.com",
                "RU_REALITY_HANDSHAKE_SERVER": "www.cloudflare.com",
            },
            "sample",
        )
        self.assertEqual(env["RU_REALITY_SERVER_NAME"], "www.bing.com")
        self.assertEqual(env["RU_REALITY_HANDSHAKE_SERVER"], "www.bing.com")

    def test_merge_env_with_defaults_migrates_legacy_ssh_rate_limit(self) -> None:
        env = config.merge_env_with_defaults({"SSH_INPUT_RATE": "12/minute", "SSH_INPUT_BURST": "6"}, "sample")
        self.assertEqual(env["SSH_INPUT_RATE"], "6/minute")
        self.assertEqual(env["SSH_INPUT_BURST"], "3")

    def test_default_ru_listen_port_stays_public_443(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["RU_LISTEN_PORT"], "443")

    def test_merge_env_with_defaults_migrates_temporary_ru_listen_port_8443_back_to_443(self) -> None:
        env = config.merge_env_with_defaults({"RU_LISTEN_PORT": "8443"}, "sample")
        self.assertEqual(env["RU_LISTEN_PORT"], "443")

    def test_merge_env_with_defaults_removes_deprecated_compat_values(self) -> None:
        env = config.merge_env_with_defaults(
            {
                "CLIENT_COMPAT_UUID": "11111111-1111-1111-1111-111111111111",
                "RU_COMPAT_LISTEN_PORTS": "8443",
            },
            "sample",
        )
        self.assertNotIn("CLIENT_COMPAT_UUID", env)
        self.assertNotIn("RU_COMPAT_LISTEN_PORTS", env)

    def test_default_reality_time_tolerance_is_explicit(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["RU_REALITY_MAX_TIME_DIFFERENCE"], "24h")

    def test_default_reality_accepts_empty_short_id_for_mobile_compat(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["RU_REALITY_ACCEPT_EMPTY_SHORT_ID"], "1")

    def test_merge_env_with_defaults_restores_empty_reality_time_tolerance_to_default(self) -> None:
        env = config.merge_env_with_defaults({"RU_REALITY_MAX_TIME_DIFFERENCE": ""}, "sample")
        self.assertEqual(env["RU_REALITY_MAX_TIME_DIFFERENCE"], "24h")

    def test_default_subscription_settings_are_not_generated_anymore(self) -> None:
        env = config.generate_default_env("sample")
        self.assertNotIn("SUBSCRIPTION_PORT", env)
        self.assertNotIn("SUBSCRIPTION_TOKEN", env)

    def test_default_ru_forced_direct_domains_include_ip_check_services(self) -> None:
        env = config.generate_default_env("sample")
        self.assertIn("api.ok.ru", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("checkip.amazonaws.com", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("ident.me", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("ip.mail.ru", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("ipv4-internet.yandex.net", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("ipv6-internet.yandex.net", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("2ip.ru", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn(".ipify.org", env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"])
        self.assertIn(".ipinfo.io", env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"])

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

    def test_parse_env_text_parses_payload(self) -> None:
        payload = config.parse_env_text('DEPLOY_NAME="demo"\nRU_PUBLIC_IP="203.0.113.10"\n')
        self.assertEqual(payload["DEPLOY_NAME"], "demo")
        self.assertEqual(payload["RU_PUBLIC_IP"], "203.0.113.10")

    def test_merge_env_with_defaults_preserves_allowed_empty(self) -> None:
        merged = config.merge_env_with_defaults({"WAN_INTERFACE": ""}, "sample")
        self.assertIn("WAN_INTERFACE", merged)
        self.assertEqual(merged["WAN_INTERFACE"], "")

    def test_merge_env_with_defaults_appends_new_direct_domain_defaults(self) -> None:
        merged = config.merge_env_with_defaults(
            {
                "RU_FORCE_DIRECT_DOMAIN": "api.oneme.ru,legacy.example",
                "RU_FORCE_DIRECT_DOMAIN_SUFFIX": ".legacy.example,.ipify.org",
            },
            "sample",
        )
        domains = merged["RU_FORCE_DIRECT_DOMAIN"].split(",")
        suffixes = merged["RU_FORCE_DIRECT_DOMAIN_SUFFIX"].split(",")
        self.assertIn("legacy.example", domains)
        self.assertIn("api.oneme.ru", domains)
        self.assertIn("2ip.ru", domains)
        self.assertIn("ip.mail.ru", domains)
        self.assertEqual(domains.count("api.oneme.ru"), 1)
        self.assertIn(".legacy.example", suffixes)
        self.assertIn(".ipify.org", suffixes)
        self.assertEqual(suffixes.count(".ipify.org"), 1)

    def test_merge_env_with_defaults_appends_new_asset_sources(self) -> None:
        merged = config.merge_env_with_defaults({"RU_GEOSITE_URL": "https://legacy.example/geosite.srs"}, "sample")
        geosite_sources = config.split_asset_sources(merged["RU_GEOSITE_URL"])
        self.assertEqual(geosite_sources[0], "https://legacy.example/geosite.srs")
        self.assertTrue(any("raw.githubusercontent.com/SagerNet/sing-geosite" in source for source in geosite_sources))
        self.assertTrue(any("cdn.jsdelivr.net/gh/SagerNet/sing-geosite" in source for source in geosite_sources))

    def test_apply_ru_direct_overlays_merges_files_with_comments_and_deduplicates(self) -> None:
        env = config.generate_default_env("demo")
        env["RU_FORCE_DIRECT_DOMAIN"] = "api.oneme.ru"
        env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"] = ".gstatic.com"
        env["RU_FORCE_DIRECT_IP_CIDR"] = "203.0.113.0/24"
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "demo.env"
            env_path.write_text(config.render_env_text(env), encoding="utf-8")
            (Path(tmp) / "demo.ru-direct-domains.txt").write_text("# comment\napi.oneme.ru,example.com\nanother.example\n", encoding="utf-8")
            (Path(tmp) / "demo.ru-direct-suffixes.txt").write_text(".gstatic.com\n# keep\n.example.com\n", encoding="utf-8")
            (Path(tmp) / "demo.ru-direct-cidrs.txt").write_text("203.0.113.0/24\n198.51.100.10/32\n", encoding="utf-8")
            merged = config.apply_ru_direct_overlays(env, env_path)
        self.assertEqual(merged["RU_FORCE_DIRECT_DOMAIN"], "api.oneme.ru,example.com,another.example")
        self.assertEqual(merged["RU_FORCE_DIRECT_DOMAIN_SUFFIX"], ".gstatic.com,.example.com")
        self.assertEqual(merged["RU_FORCE_DIRECT_IP_CIDR"], "203.0.113.0/24,198.51.100.10/32")

    def test_critical_env_view_includes_expected_keys(self) -> None:
        env = config.generate_default_env("demo")
        view = config.critical_env_view(env)
        self.assertEqual(view["DEPLOY_NAME"], "demo")
        self.assertIn("CLIENT_UUID", view)
        self.assertIn("RU_LISTEN_PORT", view)
        self.assertIn("RU_REALITY_PUBLIC_KEY", view)
        self.assertIn("WG_RU_PRIVATE_KEY", view)
        self.assertIn("RU_FORCE_DIRECT_DOMAIN", view)

    def test_generate_example_env_contains_public_ip_placeholders(self) -> None:
        env = config.generate_example_env()
        self.assertEqual(env["DEPLOY_NAME"], "my-stack")
        self.assertEqual(env["RU_PUBLIC_IP"], "203.0.113.10")
        self.assertEqual(env["RU_LISTEN_PORT"], "443")
        self.assertEqual(env["RU_REALITY_MAX_TIME_DIFFERENCE"], "24h")

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

    def test_require_env_and_existing_deployment_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            deploy_dir = Path(tmp) / "deployments"
            deploy_dir.mkdir()
            env_path = deploy_dir / "demo.env"
            env_path.write_text('DEPLOY_NAME="demo"\nRU_PUBLIC_IP="203.0.113.10"\nFOREIGN_PUBLIC_IP="198.51.100.20"\n', encoding="utf-8")
            with patch("vpn_installer.config.DEPLOYMENTS_DIR", deploy_dir):
                loaded_path, loaded_env = config.load_existing_deployment_env("demo")
                names = config.find_existing_deployments()
        self.assertEqual(loaded_path, env_path)
        self.assertEqual(names, ["demo"])
        config.require_env(
            {
                "DEPLOY_NAME": "demo",
                "RU_PUBLIC_IP": "203.0.113.10",
                "FOREIGN_PUBLIC_IP": "198.51.100.20",
                "CLIENT_UUID": "x",
                "RU_REALITY_SERVER_NAME": "a",
                "RU_REALITY_HANDSHAKE_SERVER": "a",
                "RU_REALITY_PRIVATE_KEY": "a",
                "RU_REALITY_PUBLIC_KEY": "a",
                "RU_REALITY_SHORT_ID": "a",
                "WG_RU_ADDRESS": "a",
                "WG_FOREIGN_ADDRESS": "a",
                "WG_RU_ADDRESS_V6": "a",
                "WG_FOREIGN_ADDRESS_V6": "a",
                "WG_IPV6_PREFIX": "a",
                "WG_RU_PRIVATE_KEY": "a",
                "WG_RU_PUBLIC_KEY": "a",
                "WG_FOREIGN_PRIVATE_KEY": "a",
                "WG_FOREIGN_PUBLIC_KEY": "a",
                "WG_PRESHARED_KEY": "a",
            }
        )
        self.assertEqual(loaded_env["DEPLOY_NAME"], "demo")

    def test_ensure_deployment_env_creates_and_merges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "demo.env"
            env = config.ensure_deployment_env(env_path, "demo")
            env_path.write_text(config.render_env_text({**env, "WAN_INTERFACE": "eth9"}), encoding="utf-8")
            updated = config.ensure_deployment_env(env_path, "demo")
        self.assertEqual(updated["WAN_INTERFACE"], "eth9")

    def test_write_prefix_lines_and_download_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ru.zone"
            config._write_prefix_lines(path, ["203.0.113.0/24"])  # type: ignore[attr-defined]
            self.assertEqual(path.read_text(encoding="utf-8"), "203.0.113.0/24\n")
            with self.assertRaises(Exception):
                config._write_prefix_lines(path, [])  # type: ignore[attr-defined]
            fake_response = _FakeResponse(b"payload")
            with patch("urllib.request.urlopen", return_value=fake_response):
                config.download_file("https://example.com/file", path)
            self.assertEqual(path.read_bytes(), b"payload")


if __name__ == "__main__":
    unittest.main()
