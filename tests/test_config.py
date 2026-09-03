from __future__ import annotations

import http.client
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

    def test_normalize_identity_path_resolves_bare_name_in_standard_ssh_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            key_path = home / ".ssh" / "id_ed25519"
            key_path.parent.mkdir()
            key_path.write_text("key", encoding="utf-8")
            with patch("pathlib.Path.home", return_value=home):
                normalized = config.normalize_identity_path("id_ed25519")
        self.assertEqual(Path(normalized), key_path.resolve())

    def test_normalize_identity_path_preserves_explicit_relative_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_path = root / "keys" / "operator"
            with patch("pathlib.Path.cwd", return_value=root):
                normalized = config.normalize_identity_path("keys/operator")
        self.assertEqual(Path(normalized), key_path.resolve())

    def test_default_reality_keys_are_urlsafe_without_padding(self) -> None:
        env = config.generate_default_env("sample")
        self.assertNotIn("=", env["RU_REALITY_PRIVATE_KEY"])
        self.assertNotIn("+", env["RU_REALITY_PRIVATE_KEY"])
        self.assertNotIn("/", env["RU_REALITY_PRIVATE_KEY"])

    def test_default_utls_fingerprint_uses_broad_client_compatible_value(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["UTLS_FINGERPRINT"], "chrome")

    def test_default_sing_box_log_level_bounds_connection_log_volume(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["SING_BOX_LOG_LEVEL"], "warn")
        self.assertEqual(env["RU_SNIFF_TIMEOUT"], "250ms")
        self.assertNotIn("RU_LITERAL_POLICY", env)
        self.assertNotIn("RU_IPV6_LITERAL_POLICY", env)
        self.assertNotIn("TO_FOREIGN_CONNECT_TIMEOUT", env)
        self.assertNotIn("TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT", env)
        self.assertNotIn("TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT", env)
        self.assertNotIn("RU_DIRECT_DNS_SERVER", env)
        self.assertNotIn("RU_DIRECT_DNS_PORT", env)
        self.assertEqual(env["GLOBAL_DOH_SERVER"], "8.8.8.8")
        self.assertEqual(env["GLOBAL_DOH_SERVER_NAME"], "dns.google")
        self.assertTrue(config.DEPRECATED_SSH_ENV_KEYS.isdisjoint(env))

    def test_normalize_deployment_env_removes_all_deprecated_ssh_settings(self) -> None:
        source = config.generate_default_env("sample")
        source.update(
            {
                "SSH_LOGIN_GRACE_TIME": "45",
                "SSH_MAX_AUTH_TRIES": "4",
                "SSH_MAX_STARTUPS": "5:30:20",
                "SSH_PER_SOURCE_MAX_STARTUPS": "2",
                "SSH_PER_SOURCE_NETBLOCK_SIZE": "24:64",
            }
        )

        normalized = config.normalize_deployment_env(source)

        self.assertTrue(config.DEPRECATED_SSH_ENV_KEYS.isdisjoint(normalized))
        self.assertEqual(normalized["SSH_PORT"], "22")
        self.assertEqual(normalized["DEPLOY_NAME"], "sample")

    def test_current_schema_rejects_removed_routing_knobs(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported deployment env keys"):
            config.merge_env_with_defaults({"RU_LITERAL_POLICY": "reject"}, "sample")

    def test_merge_env_with_defaults_preserves_explicit_operator_values(self) -> None:
        env = config.merge_env_with_defaults(
            {
                "RU_SNIFF_TIMEOUT": "1s",
                "SING_BOX_LOG_LEVEL": "warn",
                "GLOBAL_DOH_SERVER": "1.1.1.1",
                "GLOBAL_DOH_SERVER_NAME": "cloudflare-dns.com",
                "UTLS_FINGERPRINT": "randomized",
                "RU_REALITY_SERVER_NAME": "www.cloudflare.com",
                "WG_MTU": "1380",
                "RU_LISTEN_PORT": "8443",
                "RU_BLOCK_IP_CIDR": "91.108.56.0/22",
            },
            "sample",
        )
        for key, value in {
            "RU_SNIFF_TIMEOUT": "1s",
            "SING_BOX_LOG_LEVEL": "warn",
            "GLOBAL_DOH_SERVER": "1.1.1.1",
            "GLOBAL_DOH_SERVER_NAME": "cloudflare-dns.com",
            "UTLS_FINGERPRINT": "randomized",
            "RU_REALITY_SERVER_NAME": "www.cloudflare.com",
            "WG_MTU": "1380",
            "RU_LISTEN_PORT": "8443",
            "RU_BLOCK_IP_CIDR": "91.108.56.0/22",
        }.items():
            self.assertEqual(env[key], value, key)

    def test_default_network_contract_keeps_only_stable_wireguard_settings(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["WG_MTU"], "1360")
        self.assertNotIn("WG_KEEPALIVE", env)
        self.assertNotIn("RU_BLOCK_QUIC", env)
        self.assertNotIn("RUNTIME_QDISC", env)
        self.assertNotIn("DISABLE_NIC_OFFLOADS", env)

    def test_merge_env_uses_one_local_identity_for_missing_remote_fields(self) -> None:
        local = config.generate_default_env("sample")
        remote = {key: value for key, value in local.items() if not key.startswith("INTERSERVER_HY2_")}
        merged = config.merge_env_with_defaults(remote, "sample", fallback_defaults=local)
        for key in (
            "INTERSERVER_HY2_CERTIFICATE_B64",
            "INTERSERVER_HY2_PRIVATE_KEY_B64",
            "INTERSERVER_HY2_PUBLIC_KEY_SHA256",
        ):
            self.assertEqual(merged[key], local[key])

    def test_merge_complete_env_does_not_regenerate_transport_identity(self) -> None:
        existing = config.generate_default_env("sample")
        with patch.object(
            config,
            "generate_transport_identity",
            side_effect=AssertionError("existing identity must be reused"),
        ):
            merged = config.merge_env_with_defaults(existing, "sample")

        for key in config.TRANSPORT_IDENTITY_KEYS:
            self.assertEqual(merged[key], existing[key])

    def test_merge_does_not_mix_partial_and_fallback_transport_identities(self) -> None:
        fallback = config.generate_default_env("sample")
        existing = {"INTERSERVER_HY2_CERTIFICATE_B64": "partial-invalid-certificate"}
        merged = config.merge_env_with_defaults(existing, "sample", fallback_defaults=fallback)

        for key in config.TRANSPORT_IDENTITY_KEYS:
            self.assertEqual(merged[key], fallback[key])

    def test_generate_defaults_rejects_a_partial_transport_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "transport identity must be complete"):
            config.generate_default_env(
                "sample",
                transport_identity={"INTERSERVER_HY2_CERTIFICATE_B64": "partial"},
            )

    def test_default_ru_listen_port_stays_public_443(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["RU_LISTEN_PORT"], "443")

    def test_current_schema_rejects_removed_compat_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "CLIENT_COMPAT_UUID"):
            config.merge_env_with_defaults({"CLIENT_COMPAT_UUID": "unused"}, "sample")

    def test_default_reality_time_tolerance_is_explicit(self) -> None:
        env = config.generate_default_env("sample")
        self.assertEqual(env["RU_REALITY_MAX_TIME_DIFFERENCE"], "24h")

    def test_reality_handshake_target_override_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "RU_REALITY_HANDSHAKE"):
            config.merge_env_with_defaults({"RU_REALITY_HANDSHAKE_SERVER": "www.bing.com"}, "sample")

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

    def test_default_ru_forced_direct_domains_do_not_capture_global_ip_checks(self) -> None:
        env = config.generate_default_env("sample")
        self.assertIn("api.ok.ru", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertNotIn("checkip.amazonaws.com", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertNotIn("ident.me", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("ip.mail.ru", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("ipv4-internet.yandex.net", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertNotIn("ipv6-internet.yandex.net", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertIn("2ip.ru", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertNotIn("mtalk.google.com", env["RU_FORCE_DIRECT_DOMAIN"])
        self.assertNotIn(".ipify.org", env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"])
        self.assertNotIn(".ipinfo.io", env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"])
        self.assertEqual(env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"], ".gosuslugi.ru")
        self.assertNotIn(".gstatic.com", env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"])
        self.assertEqual(env["RU_BLOCK_IP_CIDR"], "")
        self.assertNotIn("RU_BLOCK_QUIC", env)
        self.assertEqual(env["CLIENT_ENABLE_IPV6"], "0")
        self.assertNotIn("GUARD_REALITY_BLOCK_ENABLED", env)
        self.assertNotIn("HEALTH_TARGET_PROBE_URLS", env)
        self.assertNotIn("HEALTH_TARGET_CONNECT_TIMEOUT_SECONDS", env)
        self.assertNotIn("HEALTH_GOOD_CACHE_TTL_SECONDS", env)

    def test_render_env_roundtrip(self) -> None:
        env = config.generate_default_env("sample")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        text = config.render_env_text(env)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.env"
            path.write_text(text, encoding="utf-8")
            loaded = config.load_env_file(path)
        self.assertEqual(loaded["DEPLOY_NAME"], "sample")
        self.assertEqual(loaded["GATEWAY_PUBLIC_IP"], "203.0.113.10")
        self.assertNotIn("RU_PUBLIC_IP", loaded)

    def test_parse_env_text_parses_payload(self) -> None:
        payload = config.parse_env_text('DEPLOY_NAME="demo"\nRU_PUBLIC_IP="203.0.113.10"\n')
        self.assertEqual(payload["DEPLOY_NAME"], "demo")
        self.assertEqual(payload["RU_PUBLIC_IP"], "203.0.113.10")

    def test_merge_env_with_defaults_preserves_allowed_empty(self) -> None:
        merged = config.merge_env_with_defaults({"WAN_INTERFACE": ""}, "sample")
        self.assertIn("WAN_INTERFACE", merged)
        self.assertEqual(merged["WAN_INTERFACE"], "")

    def test_dual_to_single_migration_removes_interserver_secrets(self) -> None:
        dual = config.generate_default_env("sample")
        dual.update(
            {
                "TOPOLOGY": "single",
                "GATEWAY_LOCATION": "foreign",
                "GATEWAY_PUBLIC_IP": "198.51.100.20",
                "EXIT_PUBLIC_IP": "",
            }
        )
        single = config.merge_env_with_defaults(dual, "sample")
        self.assertEqual(single["TOPOLOGY"], "single")
        self.assertEqual(single["GATEWAY_LOCATION"], "foreign")
        self.assertFalse(config.DUAL_ONLY_ENV_KEYS & single.keys())

    def test_single_to_dual_migration_generates_interserver_secrets(self) -> None:
        single = config.generate_default_env("sample", topology="single", gateway_location="ru")
        single.update(
            {
                "TOPOLOGY": "dual",
                "GATEWAY_PUBLIC_IP": "203.0.113.10",
                "EXIT_PUBLIC_IP": "198.51.100.20",
            }
        )
        dual = config.merge_env_with_defaults(single, "sample")
        self.assertEqual(dual["TOPOLOGY"], "dual")
        for key in config.DUAL_REQUIRED_ENV_VARS:
            self.assertTrue(dual[key], key)

    def test_merge_env_with_defaults_preserves_operator_values_and_appends_defaults(self) -> None:
        merged = config.merge_env_with_defaults(
            {
                "RU_FORCE_DIRECT_DOMAIN": "api.oneme.ru,custom.example,mtalk.google.com,checkip.amazonaws.com",
                "RU_FORCE_DIRECT_DOMAIN_SUFFIX": ".custom.example,.ipify.org,.gstatic.com",
            },
            "sample",
        )
        domains = merged["RU_FORCE_DIRECT_DOMAIN"].split(",")
        suffixes = merged["RU_FORCE_DIRECT_DOMAIN_SUFFIX"].split(",")
        self.assertIn("custom.example", domains)
        self.assertIn("api.oneme.ru", domains)
        self.assertIn("2ip.ru", domains)
        self.assertIn("ip.mail.ru", domains)
        self.assertEqual(domains.count("api.oneme.ru"), 1)
        self.assertIn("mtalk.google.com", domains)
        self.assertIn("checkip.amazonaws.com", domains)
        self.assertIn(".custom.example", suffixes)
        self.assertIn(".ipify.org", suffixes)
        self.assertIn(".gstatic.com", suffixes)

    def test_current_schema_rejects_removed_network_policy(self) -> None:
        with self.assertRaisesRegex(ValueError, "RU_IPV6_POLICY"):
            config.merge_env_with_defaults({"RU_IPV6_POLICY": "block"}, "sample")

    def test_merge_env_with_defaults_appends_new_asset_sources(self) -> None:
        merged = config.merge_env_with_defaults({"RU_GEOSITE_URL": "https://custom.example/geosite.srs"}, "sample")
        geosite_sources = config.split_asset_sources(merged["RU_GEOSITE_URL"])
        self.assertEqual(geosite_sources[0], "https://custom.example/geosite.srs")
        self.assertTrue(any("raw.githubusercontent.com/SagerNet/sing-geosite" in source for source in geosite_sources))
        self.assertTrue(any("cdn.jsdelivr.net/gh/SagerNet/sing-geosite" in source for source in geosite_sources))

    def test_current_schema_rejects_removed_health_parameters(self) -> None:
        with self.assertRaisesRegex(ValueError, "HEALTH_TARGET_PROBE_URLS"):
            config.merge_env_with_defaults({"HEALTH_TARGET_PROBE_URLS": "https://example.com"}, "sample")

    def test_apply_ru_direct_overlays_merges_files_with_comments_and_deduplicates(self) -> None:
        env = config.generate_default_env("demo")
        env["RU_FORCE_DIRECT_DOMAIN"] = "api.oneme.ru"
        env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"] = ".custom.example"
        env["RU_FORCE_DIRECT_IP_CIDR"] = "203.0.113.0/24"
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "demo.env"
            env_path.write_text(config.render_env_text(env), encoding="utf-8")
            (Path(tmp) / "demo.ru-direct-domains.txt").write_text("# comment\napi.oneme.ru,example.com\nanother.example\n", encoding="utf-8")
            (Path(tmp) / "demo.ru-direct-suffixes.txt").write_text(".custom.example\n# keep\n.example.com\n", encoding="utf-8")
            (Path(tmp) / "demo.ru-direct-cidrs.txt").write_text("203.0.113.0/24\n198.51.100.10/32\n", encoding="utf-8")
            merged = config.apply_ru_direct_overlays(env, env_path)
        self.assertEqual(merged["RU_FORCE_DIRECT_DOMAIN"], "api.oneme.ru,example.com,another.example")
        self.assertEqual(merged["RU_FORCE_DIRECT_DOMAIN_SUFFIX"], ".custom.example,.example.com")
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
        self.assertEqual(env["GATEWAY_PUBLIC_IP"], "203.0.113.10")
        self.assertNotIn("RU_PUBLIC_IP", env)
        self.assertNotIn("FOREIGN_PUBLIC_IP", env)
        self.assertEqual(env["RU_LISTEN_PORT"], "443")
        self.assertEqual(env["RU_REALITY_MAX_TIME_DIFFERENCE"], "24h")
        self.assertEqual(env["FOREIGN_BLOCK_RU"], "0")
        self.assertIn("ADMIN_WEB_PORT", env)
        self.assertNotIn("ADMIN_WEB_ENABLED", env)
        self.assertNotIn("ADMIN_WEB_BIND", env)
        self.assertNotIn("ADMIN_WEB_ACTIVE_CLIENT_REQUIRED", env)

    def test_removed_admin_inputs_are_rejected_fail_closed(self) -> None:
        legacy_keys = {
            "ADMIN_WEB_BIND": "0.0.0.0",
            "ADMIN_WEB_ACTIVE_CLIENT_REQUIRED": "1",
            "ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS": "30",
            "ADMIN_WEB_ALLOW_TUNNEL_CLIENTS": "1",
            "ADMIN_WEB_ALLOWED_CIDR": "0.0.0.0/0",
            "ADMIN_WEB_ALLOW_WG": "1",
        }
        with self.assertRaisesRegex(ValueError, "unsupported deployment env keys"):
            config.merge_env_with_defaults(legacy_keys, "sample")

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

    def test_download_file_converts_incomplete_read_to_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch("urllib.request.urlopen", side_effect=http.client.IncompleteRead(b"partial", 10)):
            with self.assertRaises(RuntimeError):
                config.download_file("https://example.invalid/file.srs", Path(tmp) / "file.srs")

    def test_require_env_and_existing_deployment_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            deploy_dir = Path(tmp) / "deployments"
            deploy_dir.mkdir()
            env_path = deploy_dir / "demo.env"
            current = config.generate_default_env("demo")
            current["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
            current["EXIT_PUBLIC_IP"] = "198.51.100.20"
            env_path.write_text(config.render_env_text(current), encoding="utf-8")
            with patch("vpn_installer.config.DEPLOYMENTS_DIR", deploy_dir):
                loaded_path, loaded_env = config.load_existing_deployment_env("demo")
                names = config.find_existing_deployments()
        self.assertEqual(loaded_path, env_path)
        self.assertEqual(names, ["demo"])
        config.require_env(loaded_env)
        self.assertEqual(loaded_env["DEPLOY_NAME"], "demo")

    def test_ensure_deployment_env_creates_and_merges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "demo.env"
            env = config.ensure_deployment_env(env_path, "demo")
            self.assertFalse(env_path.exists())
            env_path.write_text(
                config.render_env_text(
                    {
                        **env,
                        "GATEWAY_PUBLIC_IP": "203.0.113.10",
                        "EXIT_PUBLIC_IP": "198.51.100.20",
                        "WAN_INTERFACE": "eth9",
                    }
                ),
                encoding="utf-8",
            )
            updated = config.ensure_deployment_env(env_path, "demo")
        self.assertEqual(updated["WAN_INTERFACE"], "eth9")

    def test_retired_config_schema_is_rejected_without_rewriting(self) -> None:
        payload = (
            'CONFIG_SCHEMA="2"\nTOPOLOGY="single"\nGATEWAY_LOCATION="ru"\n'
            'GATEWAY_PUBLIC_IP="203.0.113.10"\nRU_PUBLIC_IP="198.51.100.20"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "demo.env"
            env_path.write_text(payload, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "current release accepts only schema 3"):
                config.ensure_deployment_env(env_path, "demo")
            observed = env_path.read_text(encoding="utf-8")

        self.assertEqual(observed, payload)

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
