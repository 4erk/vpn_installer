from __future__ import annotations

import json
import http.client
import subprocess
import sys
import threading
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer

from vpn_installer import admin_apply, admin_web
from vpn_installer.config import generate_default_env
from vpn_installer.render import render_ru_singbox


class AdminWebTests(unittest.TestCase):
    def basic_header(self, username: str = "user", password: str = "password") -> str:
        import base64

        return "Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")

    def test_password_hash_does_not_store_plaintext(self) -> None:
        payload = admin_web.hash_password("correct horse")
        self.assertNotIn("correct horse", json.dumps(payload))
        self.assertTrue(admin_web.verify_password("correct horse", payload))
        self.assertFalse(admin_web.verify_password("wrong", payload))
        self.assertFalse(admin_web.verify_password("wrong", {}))

    def test_load_env_parses_quoted_values_and_ignores_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "deployment.env"
            env_path.write_text('# comment\nADMIN_WEB_BIND="127.0.0.1"\nBAD\nADMIN_WEB_PORT=11333\n', encoding="utf-8")
            self.assertEqual(admin_web.load_env(env_path), {"ADMIN_WEB_BIND": "127.0.0.1", "ADMIN_WEB_PORT": "11333"})

    def test_check_basic_auth_rejects_missing_and_malformed_headers(self) -> None:
        self.assertFalse(admin_web.check_basic_auth(None))
        self.assertFalse(admin_web.check_basic_auth("Bearer nope"))
        self.assertFalse(admin_web.check_basic_auth("Basic definitely-not-base64"))

    def test_check_basic_auth_accepts_current_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            with patch.object(admin_web, "AUTH_PATH", auth_path), patch.object(admin_web, "ENV_PATH", Path(tmp) / "deployment.env"):
                admin_web.init_auth("operator", "secret-password")
                self.assertTrue(admin_web.check_basic_auth(self.basic_header("operator", "secret-password")))
                self.assertFalse(admin_web.check_basic_auth(self.basic_header("operator", "bad-password")))

    def test_load_auth_initializes_from_env_when_hash_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "deployment.env"
            auth_path = tmp_path / "admin-auth.json"
            env_path.write_text('ADMIN_WEB_USERNAME="operator"\nADMIN_WEB_PASSWORD="secret-password"\n', encoding="utf-8")
            with patch.object(admin_web, "ENV_PATH", env_path), patch.object(admin_web, "AUTH_PATH", auth_path):
                auth = admin_web.load_auth()
        self.assertEqual(auth["username"], "operator")
        self.assertTrue(admin_web.verify_password("secret-password", auth["password"]))

    def test_public_bind_allows_default_credentials_only_with_active_client_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            with patch.object(admin_web, "AUTH_PATH", auth_path):
                admin_web.init_auth("user", "password")
                admin_web.assert_safe_bind({"ADMIN_WEB_BIND": "0.0.0.0"})
                with self.assertRaises(RuntimeError):
                    admin_web.assert_safe_bind({"ADMIN_WEB_BIND": "0.0.0.0", "ADMIN_WEB_ACTIVE_CLIENT_REQUIRED": "0"})
                with self.assertRaises(RuntimeError):
                    admin_web.assert_safe_bind({"ADMIN_WEB_BIND": "0.0.0.0", "ADMIN_WEB_ALLOW_WG": "1"})
                with self.assertRaises(RuntimeError):
                    admin_web.assert_safe_bind({"ADMIN_WEB_BIND": "0.0.0.0", "ADMIN_WEB_ALLOWED_CIDR": "0.0.0.0/0"})

    def test_public_bind_allows_custom_credentials_and_allowed_cidr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            with patch.object(admin_web, "AUTH_PATH", auth_path):
                admin_web.init_auth("operator", "strong-password", force=True)
                admin_web.assert_safe_bind({"ADMIN_WEB_BIND": "0.0.0.0"})
        env = {"ADMIN_WEB_BIND": "0.0.0.0", "ADMIN_WEB_ALLOWED_CIDR": "203.0.113.4/32"}
        self.assertTrue(admin_web.client_ip_allowed("203.0.113.4", env))
        self.assertFalse(admin_web.client_ip_allowed("203.0.113.5", env))

    def test_wg_allowlist_accepts_wireguard_peer_ip(self) -> None:
        env = {
            "ADMIN_WEB_BIND": "0.0.0.0",
            "ADMIN_WEB_ACTIVE_CLIENT_REQUIRED": "0",
            "ADMIN_WEB_ALLOW_WG": "1",
            "WG_RU_ADDRESS": "10.74.0.1/32",
            "WG_FOREIGN_ADDRESS": "10.74.0.2/32",
        }
        self.assertTrue(admin_web.client_ip_allowed("10.74.0.2", env))
        self.assertFalse(admin_web.client_ip_allowed("10.74.0.3", env))

    def test_active_client_parsing_uses_all_current_vpn_peers(self) -> None:
        sample = "\n".join(
            [
                "short",
                "0 0 94.232.248.35:443 198.51.100.10:53000",
                "0 0 94.232.248.35:443 203.0.113.20:53001",
                "0 0 94.232.248.35:11333 203.0.113.30:53002",
                "0 0 94.232.248.35:443 not-an-ip:53004",
                "0 0 [::ffff:94.232.248.35]:443 [::ffff:192.0.2.44]:53005",
                "0 0 [::ffff:94.232.248.35]:443 [2001:db8::1]:53003",
            ]
        )
        self.assertEqual(admin_web.parse_established_client_ips(sample, 443), {"198.51.100.10", "203.0.113.20", "192.0.2.44"})
        self.assertEqual(admin_web.split_endpoint("missing-port"), ("", ""))

    def test_active_client_access_allows_any_current_vpn_peer(self) -> None:
        env = {"ADMIN_WEB_BIND": "0.0.0.0", "RU_LISTEN_PORT": "443"}
        with patch.object(admin_web, "active_xray_client_ips", return_value={"198.51.100.10", "203.0.113.20"}):
            self.assertTrue(admin_web.client_ip_allowed("198.51.100.10", env))
            self.assertTrue(admin_web.client_ip_allowed("203.0.113.20", env))
            self.assertFalse(admin_web.client_ip_allowed("203.0.113.21", env))

    def test_active_client_cache_and_fallback_paths(self) -> None:
        admin_web.CLIENT_IP_CACHE.update({"expires_at": 0.0, "listen_port": None, "ips": set()})
        completed = subprocess.CompletedProcess(["ss"], 0, stdout="0 0 94.232.248.35:443 198.51.100.10:53000\n", stderr="")
        with patch("vpn_installer.admin_web.subprocess.run", return_value=completed) as run_mock:
            self.assertEqual(admin_web.active_xray_client_ips(443), {"198.51.100.10"})
            self.assertEqual(admin_web.active_xray_client_ips(443), {"198.51.100.10"})
        run_mock.assert_called_once()

        admin_web.CLIENT_IP_CACHE.update({"expires_at": 0.0, "listen_port": None, "ips": set()})
        with patch("vpn_installer.admin_web.subprocess.run", side_effect=OSError("no ss")):
            self.assertEqual(admin_web.active_xray_client_ips(443), set())

    def test_active_client_helpers_handle_disabled_and_bad_ports(self) -> None:
        with patch.object(admin_web, "active_xray_client_ips", return_value={"198.51.100.10"}) as active_mock:
            self.assertFalse(admin_web.active_client_ip_allowed("198.51.100.10", {"ADMIN_WEB_ACTIVE_CLIENT_REQUIRED": "0"}))
            self.assertTrue(admin_web.active_client_ip_allowed("198.51.100.10", {"RU_LISTEN_PORT": "bad"}))
            self.assertTrue(admin_web.any_active_client({"RU_LISTEN_PORT": "bad"}))
            self.assertTrue(admin_web.any_active_client({"ADMIN_WEB_ACTIVE_CLIENT_REQUIRED": "0"}))
        active_mock.assert_any_call(443)

    def test_tunnel_source_requires_at_least_one_active_client(self) -> None:
        env = {
            "ADMIN_WEB_BIND": "0.0.0.0",
            "ADMIN_WEB_ALLOW_TUNNEL_CLIENTS": "1",
            "RU_PUBLIC_IP": "94.232.248.35",
            "FOREIGN_PUBLIC_IP": "132.243.21.108",
            "WG_RU_ADDRESS": "10.74.0.1/32",
            "WG_FOREIGN_ADDRESS": "10.74.0.2/32",
        }
        with patch.object(admin_web, "active_xray_client_ips", return_value=set()):
            self.assertFalse(admin_web.client_ip_allowed("94.232.248.35", env))
            self.assertFalse(admin_web.client_ip_allowed("132.243.21.108", env))
        with patch.object(admin_web, "active_xray_client_ips", return_value={"198.51.100.10"}):
            self.assertTrue(admin_web.client_ip_allowed("94.232.248.35", env))
            self.assertTrue(admin_web.client_ip_allowed("132.243.21.108", env))
        self.assertFalse(admin_web.tunnel_source_allowed("not-an-ip", env))
        self.assertFalse(admin_web.tunnel_source_allowed("94.232.248.35", {**env, "ADMIN_WEB_ALLOW_TUNNEL_CLIENTS": "0"}))
        with patch.object(admin_web, "active_xray_client_ips", return_value={"198.51.100.10"}):
            self.assertFalse(admin_web.tunnel_source_allowed("94.232.248.36", {**env, "RU_PUBLIC_IP": "bad-cidr"}))

    def test_sync_admin_client_nft_set_adds_current_peers_with_timeout(self) -> None:
        env = {"RU_LISTEN_PORT": "443", "ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS": "5"}
        with patch.object(admin_web, "active_xray_client_ips", return_value={"198.51.100.10"}), patch("vpn_installer.admin_web.subprocess.run") as run_mock:
            admin_web.sync_admin_client_nft_set(env)
        run_mock.assert_called_once()
        self.assertEqual(
            run_mock.call_args.args[0],
            ["nft", "add", "element", "inet", "vpnstack", "admin_clients_ipv4", "{ 198.51.100.10 timeout 5s }"],
        )

    def test_sync_admin_client_nft_set_handles_disabled_bad_values_and_clamps_timeout(self) -> None:
        with patch("vpn_installer.admin_web.subprocess.run") as run_mock:
            admin_web.sync_admin_client_nft_set({"ADMIN_WEB_ACTIVE_CLIENT_REQUIRED": "0"})
        run_mock.assert_not_called()

        with patch.object(admin_web, "active_xray_client_ips", return_value={"198.51.100.10"}), patch("vpn_installer.admin_web.subprocess.run") as run_mock:
            admin_web.sync_admin_client_nft_set({"RU_LISTEN_PORT": "bad", "ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS": "1"})
        self.assertEqual(run_mock.call_args.args[0][-1], "{ 198.51.100.10 timeout 5s }")

    def test_client_ip_allowed_rejects_bad_sources_and_invalid_allowlist_entries(self) -> None:
        self.assertTrue(admin_web.is_loopback_bind("localhost"))
        self.assertFalse(admin_web.is_loopback_bind("not-an-ip"))
        self.assertTrue(admin_web.client_ip_allowed("127.0.0.1", {"ADMIN_WEB_BIND": "0.0.0.0"}))
        self.assertFalse(admin_web.client_ip_allowed("not-an-ip", {"ADMIN_WEB_BIND": "0.0.0.0"}))
        env = {
            "ADMIN_WEB_BIND": "0.0.0.0",
            "ADMIN_WEB_ACTIVE_CLIENT_REQUIRED": "0",
            "ADMIN_WEB_ALLOW_WG": "1",
            "WG_RU_ADDRESS": "",
            "WG_FOREIGN_ADDRESS": "bad-cidr",
            "ADMIN_WEB_ALLOWED_CIDR": "bad-cidr 203.0.113.4/32",
        }
        self.assertTrue(admin_web.client_ip_allowed("203.0.113.4", env))
        self.assertFalse(admin_web.client_ip_allowed("203.0.113.5", env))

    def test_load_rules_and_apply_rules_failure_edges(self) -> None:
        with patch("vpn_installer.admin_web.admin_apply.load_rules", side_effect=ValueError("bad rules")):
            self.assertEqual(admin_web.load_rules(), [])
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "admin_apply.py"
            script.write_text("print('bad')\n", encoding="utf-8")
            failure = subprocess.CalledProcessError(1, ["python"], output="stdout detail", stderr="")
            with patch.object(admin_web, "APPLY_SCRIPT", script), patch("vpn_installer.admin_web.subprocess.run", side_effect=failure):
                self.assertEqual(admin_web.apply_rules(), (False, "stdout detail"))

    def test_stealth_admin_server_closes_disallowed_sources_before_http(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.shutdown_called = False
                self.close_called = False

            def shutdown(self, _how: int) -> None:
                self.shutdown_called = True

            def close(self) -> None:
                self.close_called = True

        server = object.__new__(admin_web.StealthAdminServer)
        sock = FakeSocket()
        with patch("vpn_installer.admin_web.load_env", return_value={"ADMIN_WEB_BIND": "0.0.0.0"}), patch("vpn_installer.admin_web.client_ip_allowed", return_value=False):
            self.assertFalse(admin_web.StealthAdminServer.verify_request(server, sock, ("198.51.100.10", 12345)))
        self.assertTrue(sock.shutdown_called)
        self.assertTrue(sock.close_called)

        with patch("vpn_installer.admin_web.load_env", return_value={"ADMIN_WEB_BIND": "0.0.0.0"}), patch("vpn_installer.admin_web.client_ip_allowed", return_value=True):
            self.assertTrue(admin_web.StealthAdminServer.verify_request(server, sock, ("198.51.100.10", 12345)))

    def test_page_and_settings_escape_untrusted_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            with patch.object(admin_web, "AUTH_PATH", auth_path):
                admin_web.init_auth('<script>', "password", force=True)
                html = admin_web.settings_body("changed <ok>").decode("utf-8")
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("changed &lt;ok&gt;", html)
        self.assertIn("VPN Admin", admin_web.page("T", "routes", admin_web.ROUTES_BODY).decode("utf-8"))

    def test_apply_rules_uses_script_when_available_and_reports_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "admin_apply.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            with patch.object(admin_web, "APPLY_SCRIPT", script), patch("vpn_installer.admin_web.subprocess.run") as run_mock:
                self.assertEqual(admin_web.apply_rules(), (True, "Правила проверены и записаны."))
            run_mock.assert_called_once()
            self.assertEqual(run_mock.call_args.args[0], [sys.executable, str(script), "--no-restart"])
            with patch.object(admin_web, "APPLY_SCRIPT", script), patch("vpn_installer.admin_web.subprocess.run", side_effect=Exception("boom")):
                ok, message = admin_web.apply_rules()
        self.assertFalse(ok)
        self.assertIn("boom", message)

    def test_apply_rules_falls_back_to_in_process_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.py"
            with patch.object(admin_web, "APPLY_SCRIPT", missing), patch("vpn_installer.admin_web.admin_apply.apply_rules") as apply_mock:
                self.assertEqual(admin_web.apply_rules(), (True, "Правила проверены и записаны."))
            apply_mock.assert_called_once_with(restart=False)

    def test_commit_rules_rolls_back_when_apply_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "rules.json"
            old_rules = [admin_apply.normalize_rule({"id": "1", "value": "old.example", "outbound": "direct-ru"})]
            new_rules = [admin_apply.normalize_rule({"id": "2", "value": "new.example", "outbound": "direct-ru"})]
            with patch.object(admin_web, "RULES_PATH", rules_path), patch("vpn_installer.admin_web.apply_rules", return_value=(False, "bad apply")):
                ok, message = admin_web.commit_rules(new_rules, old_rules)
                self.assertFalse(ok)
                self.assertEqual(message, "bad apply")
                self.assertEqual(admin_web.load_rules(), old_rules)

    def test_routes_payload_reports_foreign_block_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "deployment.env"
            rules_path = tmp_path / "rules.json"
            env_path.write_text('FOREIGN_BLOCK_RU="1"\n', encoding="utf-8")
            rules_path.write_text(json.dumps({"rules": []}), encoding="utf-8")
            with patch.object(admin_web, "ENV_PATH", env_path), patch.object(admin_web, "RULES_PATH", rules_path):
                payload = admin_web.routes_payload()
            self.assertEqual(payload["rules"], [])
            self.assertTrue(payload["config"]["foreign_block_ru"])

    def test_serve_and_main_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "deployment.env"
            auth_path = tmp_path / "admin-auth.json"
            env_path.write_text('ADMIN_WEB_BIND="127.0.0.1"\nADMIN_WEB_PORT="11333"\n', encoding="utf-8")

            class FakeServer:
                def __init__(self, address: tuple[str, int], handler: type[admin_web.Handler]) -> None:
                    self.address = address
                    self.handler = handler
                    self.served = False

                def serve_forever(self) -> None:
                    self.served = True

            created: list[FakeServer] = []

            def fake_server(address: tuple[str, int], handler: type[admin_web.Handler]) -> FakeServer:
                server = FakeServer(address, handler)
                created.append(server)
                return server

            with patch.object(admin_web, "ENV_PATH", env_path), patch.object(admin_web, "AUTH_PATH", auth_path), patch("vpn_installer.admin_web.StealthAdminServer", side_effect=fake_server), patch("vpn_installer.admin_web.sync_admin_client_nft_set"), patch("vpn_installer.admin_web.threading.Thread"):
                self.assertEqual(admin_web.main(["init-auth", "operator", "new-password", "--force"]), 0)
                self.assertTrue(admin_web.check_basic_auth(self.basic_header("operator", "new-password")))
                self.assertEqual(admin_web.main([]), 0)
            self.assertEqual(created[0].address, ("127.0.0.1", 11333))
            self.assertTrue(created[0].served)

    def test_http_routes_crud_and_settings_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            tmp_path = Path(tmp)
            env_path = tmp_path / "deployment.env"
            auth_path = tmp_path / "admin-auth.json"
            rules_path = tmp_path / "rules.json"
            env_path.write_text('ADMIN_WEB_BIND="127.0.0.1"\nADMIN_WEB_PORT="11333"\n', encoding="utf-8")
            stack.enter_context(patch.object(admin_web, "ENV_PATH", env_path))
            stack.enter_context(patch.object(admin_web, "AUTH_PATH", auth_path))
            stack.enter_context(patch.object(admin_web, "RULES_PATH", rules_path))
            apply_mock = stack.enter_context(patch.object(admin_web, "apply_rules", return_value=(True, "applied")))
            restart_mock = stack.enter_context(patch.object(admin_web, "schedule_singbox_restart"))
            admin_web.init_auth("user", "password")
            server = ThreadingHTTPServer(("127.0.0.1", 0), admin_web.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_address[1]}"
                auth = self.basic_header()

                with self.assertRaises(urllib.error.HTTPError) as unauth:
                    urllib.request.urlopen(f"{base_url}/api/routes", timeout=5)
                self.assertEqual(unauth.exception.code, 401)

                html_request = urllib.request.Request(f"{base_url}/routes", headers={"Authorization": auth})
                html = urllib.request.urlopen(html_request, timeout=5).read().decode("utf-8")
                self.assertIn("Новое исключение", html)
                self.assertIn("foreign-block-warning", html)
                self.assertIn("Загружаю исключения", html)

                root_request = urllib.request.Request(f"{base_url}/", headers={"Authorization": auth})
                root_html = urllib.request.urlopen(root_request, timeout=5).read().decode("utf-8")
                self.assertIn("Новое исключение", root_html)

                settings_get = urllib.request.Request(f"{base_url}/settings", headers={"Authorization": auth})
                settings_page = urllib.request.urlopen(settings_get, timeout=5).read().decode("utf-8")
                self.assertIn("Настройка доступа", settings_page)

                missing_get = urllib.request.Request(f"{base_url}/missing", headers={"Authorization": auth})
                with self.assertRaises(urllib.error.HTTPError) as missing_error:
                    urllib.request.urlopen(missing_get, timeout=5)
                self.assertEqual(missing_error.exception.code, 404)

                api_request = urllib.request.Request(f"{base_url}/api/routes", headers={"Authorization": auth})
                api_response = json.loads(urllib.request.urlopen(api_request, timeout=5).read().decode("utf-8"))
                self.assertEqual(api_response["rules"], [])
                self.assertFalse(api_response["config"]["foreign_block_ru"])

                forbidden_request = urllib.request.Request(f"{base_url}/api/routes", headers={"Authorization": auth})
                with patch("vpn_installer.admin_web.client_ip_allowed", return_value=False):
                    with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError, urllib.error.URLError)):
                        urllib.request.urlopen(forbidden_request, timeout=5)

                no_csrf_request = urllib.request.Request(
                    f"{base_url}/api/routes",
                    data=b"{}",
                    method="POST",
                    headers={"Authorization": auth, "Content-Type": "application/json"},
                )
                with self.assertRaises(urllib.error.HTTPError) as csrf_error:
                    urllib.request.urlopen(no_csrf_request, timeout=5)
                self.assertEqual(csrf_error.exception.code, 403)

                empty_post_request = urllib.request.Request(
                    f"{base_url}/api/routes",
                    data=b"",
                    method="POST",
                    headers={"Authorization": auth, "Content-Type": "application/json", "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                with self.assertRaises(urllib.error.HTTPError) as empty_post_error:
                    urllib.request.urlopen(empty_post_request, timeout=5)
                self.assertEqual(empty_post_error.exception.code, 400)

                invalid_payload = json.dumps({"value": "not a domain", "outbound": "direct-ru"}).encode("utf-8")
                invalid_request = urllib.request.Request(
                    f"{base_url}/api/routes",
                    data=invalid_payload,
                    method="POST",
                    headers={"Authorization": auth, "Content-Type": "application/json", "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                with self.assertRaises(urllib.error.HTTPError) as invalid_error:
                    urllib.request.urlopen(invalid_request, timeout=5)
                self.assertEqual(invalid_error.exception.code, 400)

                apply_mock.return_value = (False, "apply failed")
                apply_fail_payload = json.dumps({"value": "fail.example", "outbound": "direct-ru"}).encode("utf-8")
                apply_fail_request = urllib.request.Request(
                    f"{base_url}/api/routes",
                    data=apply_fail_payload,
                    method="POST",
                    headers={"Authorization": auth, "Content-Type": "application/json", "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                with self.assertRaises(urllib.error.HTTPError) as apply_error:
                    urllib.request.urlopen(apply_fail_request, timeout=5)
                self.assertEqual(apply_error.exception.code, 400)
                apply_mock.return_value = (True, "applied")

                payload = json.dumps({"value": "*.example.com", "outbound": "to-foreign"}).encode("utf-8")
                add_request = urllib.request.Request(
                    f"{base_url}/api/routes",
                    data=payload,
                    method="POST",
                    headers={"Authorization": auth, "Content-Type": "application/json", "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                add_response = json.loads(urllib.request.urlopen(add_request, timeout=5).read().decode("utf-8"))
                self.assertEqual(add_response["rules"][0]["value"], "example.com")
                self.assertTrue(add_response["rules"][0]["enabled"])
                self.assertTrue(add_response["rules"][0]["include_subdomains"])
                rule_id = add_response["rules"][0]["id"]
                restart_mock.assert_called()

                patch_request = urllib.request.Request(
                    f"{base_url}/api/routes/{urllib.parse.quote(rule_id)}",
                    data=json.dumps({"enabled": False, "include_subdomains": False, "outbound": "direct-ru"}).encode("utf-8"),
                    method="PATCH",
                    headers={"Authorization": auth, "Content-Type": "application/json", "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                patch_response = json.loads(urllib.request.urlopen(patch_request, timeout=5).read().decode("utf-8"))
                self.assertFalse(patch_response["rules"][0]["enabled"])
                self.assertFalse(patch_response["rules"][0]["include_subdomains"])
                self.assertEqual(patch_response["rules"][0]["outbound"], "direct-ru")

                missing_patch = urllib.request.Request(
                    f"{base_url}/api/routes/missing",
                    data=json.dumps({"enabled": True}).encode("utf-8"),
                    method="PATCH",
                    headers={"Authorization": auth, "Content-Type": "application/json", "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                with self.assertRaises(urllib.error.HTTPError) as missing_patch_error:
                    urllib.request.urlopen(missing_patch, timeout=5)
                self.assertEqual(missing_patch_error.exception.code, 404)

                delete_request = urllib.request.Request(
                    f"{base_url}/api/routes/{urllib.parse.quote(rule_id)}",
                    method="DELETE",
                    headers={"Authorization": auth, "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                delete_response = json.loads(urllib.request.urlopen(delete_request, timeout=5).read().decode("utf-8"))
                self.assertEqual(delete_response["rules"], [])

                missing_delete = urllib.request.Request(
                    f"{base_url}/api/routes/{urllib.parse.quote(rule_id)}",
                    method="DELETE",
                    headers={"Authorization": auth, "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                with self.assertRaises(urllib.error.HTTPError) as missing_delete_error:
                    urllib.request.urlopen(missing_delete, timeout=5)
                self.assertEqual(missing_delete_error.exception.code, 404)

                bad_delete = urllib.request.Request(
                    f"{base_url}/not-routes/{urllib.parse.quote(rule_id)}",
                    method="DELETE",
                    headers={"Authorization": auth, "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                with self.assertRaises(urllib.error.HTTPError) as bad_delete_error:
                    urllib.request.urlopen(bad_delete, timeout=5)
                self.assertEqual(bad_delete_error.exception.code, 404)

                no_csrf_delete = urllib.request.Request(
                    f"{base_url}/api/routes/{urllib.parse.quote(rule_id)}",
                    method="DELETE",
                    headers={"Authorization": auth},
                )
                with self.assertRaises(urllib.error.HTTPError) as delete_csrf_error:
                    urllib.request.urlopen(no_csrf_delete, timeout=5)
                self.assertEqual(delete_csrf_error.exception.code, 403)

                second_payload = json.dumps({"value": "delete-fail.example", "outbound": "direct-ru"}).encode("utf-8")
                second_add = urllib.request.Request(
                    f"{base_url}/api/routes",
                    data=second_payload,
                    method="POST",
                    headers={"Authorization": auth, "Content-Type": "application/json", "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                second_response = json.loads(urllib.request.urlopen(second_add, timeout=5).read().decode("utf-8"))
                second_rule_id = second_response["rules"][0]["id"]
                apply_mock.return_value = (False, "delete failed")
                delete_fail = urllib.request.Request(
                    f"{base_url}/api/routes/{urllib.parse.quote(second_rule_id)}",
                    method="DELETE",
                    headers={"Authorization": auth, "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                with self.assertRaises(urllib.error.HTTPError) as delete_apply_error:
                    urllib.request.urlopen(delete_fail, timeout=5)
                self.assertEqual(delete_apply_error.exception.code, 400)
                apply_mock.return_value = (True, "applied")

                bad_settings_csrf = urllib.parse.urlencode({"csrf": "bad"}).encode("utf-8")
                bad_settings_request = urllib.request.Request(
                    f"{base_url}/settings",
                    data=bad_settings_csrf,
                    method="POST",
                    headers={"Authorization": auth, "Content-Type": "application/x-www-form-urlencoded"},
                )
                with self.assertRaises(urllib.error.HTTPError) as bad_settings_error:
                    urllib.request.urlopen(bad_settings_request, timeout=5)
                self.assertEqual(bad_settings_error.exception.code, 403)

                for bad_form in (
                    {"csrf": admin_web.CSRF_TOKEN, "username": "", "current_password": "password", "new_password": "new-password", "confirm_password": "new-password"},
                    {"csrf": admin_web.CSRF_TOKEN, "username": "operator", "current_password": "wrong", "new_password": "new-password", "confirm_password": "new-password"},
                    {"csrf": admin_web.CSRF_TOKEN, "username": "operator", "current_password": "password", "new_password": "short", "confirm_password": "short"},
                    {"csrf": admin_web.CSRF_TOKEN, "username": "operator", "current_password": "password", "new_password": "new-password", "confirm_password": "different"},
                ):
                    request = urllib.request.Request(
                        f"{base_url}/settings",
                        data=urllib.parse.urlencode(bad_form).encode("utf-8"),
                        method="POST",
                        headers={"Authorization": auth, "Content-Type": "application/x-www-form-urlencoded"},
                    )
                    with self.assertRaises(urllib.error.HTTPError) as form_error:
                        urllib.request.urlopen(request, timeout=5)
                    self.assertEqual(form_error.exception.code, 400)

                unknown_post = urllib.request.Request(
                    f"{base_url}/unknown",
                    data=b"",
                    method="POST",
                    headers={"Authorization": auth},
                )
                with self.assertRaises(urllib.error.HTTPError) as unknown_post_error:
                    urllib.request.urlopen(unknown_post, timeout=5)
                self.assertEqual(unknown_post_error.exception.code, 404)

                form = urllib.parse.urlencode(
                    {
                        "csrf": admin_web.CSRF_TOKEN,
                        "username": "operator",
                        "current_password": "password",
                        "new_password": "new-password",
                        "confirm_password": "new-password",
                    }
                ).encode("utf-8")
                settings_request = urllib.request.Request(
                    f"{base_url}/settings",
                    data=form,
                    method="POST",
                    headers={"Authorization": auth, "Content-Type": "application/x-www-form-urlencoded"},
                )
                settings_html = urllib.request.urlopen(settings_request, timeout=5).read().decode("utf-8")
                self.assertIn("Доступ обновлён", settings_html)
                self.assertTrue(admin_web.check_basic_auth(self.basic_header("operator", "new-password")))
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

    def test_normalize_domain_rule_accepts_wildcard(self) -> None:
        rule = admin_apply.normalize_rule({"value": "*.example.com", "outbound": "to-foreign"})
        self.assertEqual(rule["type"], "domain")
        self.assertEqual(rule["value"], "example.com")
        self.assertTrue(rule["include_subdomains"])
        self.assertEqual(rule["outbound"], "to-foreign")

    def test_normalize_rule_rejects_invalid_domain(self) -> None:
        with self.assertRaises(ValueError):
            admin_apply.normalize_rule({"value": "not a domain", "outbound": "direct-ru"})

    def test_apply_rules_inserts_foreign_override_before_ru_geosite(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        base = json.loads(render_ru_singbox(env))
        config = admin_apply.apply_admin_rules_to_config(
            base,
            [
                admin_apply.normalize_rule(
                    {
                        "id": "1",
                        "value": "gosuslugi.ru",
                        "include_subdomains": True,
                        "outbound": "to-foreign",
                    }
                )
            ],
        )
        route_rules = config["route"]["rules"]
        override_index = next(i for i, rule in enumerate(route_rules) if rule.get("outbound") == "to-foreign" and rule.get("domain") == ["gosuslugi.ru"])
        geosite_index = next(i for i, rule in enumerate(route_rules) if rule.get("rule_set") == ["ru-geosite"] and rule.get("outbound") == "direct-ru")
        self.assertLess(override_index, geosite_index)
        dns_rule = next(rule for rule in config["dns"]["rules"] if rule.get("domain") == ["gosuslugi.ru"])
        self.assertEqual(dns_rule["server"], "dns-global")

    def test_apply_rules_writes_checked_config_without_restart(self) -> None:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base = tmp_path / "base.json"
            config = tmp_path / "config.json"
            rules = tmp_path / "rules.json"
            base.write_text(render_ru_singbox(env), encoding="utf-8")
            rules.write_text(
                json.dumps({"rules": [{"id": "1", "value": "*.example.com", "outbound": "direct-ru"}]}),
                encoding="utf-8",
            )
            with patch("vpn_installer.admin_apply.shutil.which", return_value=None):
                admin_apply.apply_rules(base, config, rules, restart=False)
            payload = json.loads(config.read_text(encoding="utf-8"))
        direct_rule = next(rule for rule in payload["route"]["rules"] if rule.get("outbound") == "direct-ru" and rule.get("domain") == ["example.com"])
        self.assertEqual(direct_rule["domain"], ["example.com"])

    def test_admin_apply_helpers_cover_cidr_and_indexes(self) -> None:
        cidr_rule = admin_apply.normalize_rule({"value": "203.0.113.4/32", "outbound": "direct-ru"})
        self.assertEqual(cidr_rule["type"], "cidr")
        self.assertEqual(cidr_rule["value"], "203.0.113.4/32")
        self.assertEqual(admin_apply.rule_domains({"value": "example.com", "include_subdomains": True}), (["example.com"], [".example.com"]))
        self.assertEqual(admin_apply.route_insert_index([]), 0)
        self.assertEqual(admin_apply.dns_insert_index([]), 0)

    def test_load_rules_deduplicates_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "rules.json"
            rules_path.write_text(
                json.dumps(
                    {
                        "rules": [
                            {"id": "1", "value": "example.com", "outbound": "direct-ru"},
                            {"id": "2", "value": "example.com", "outbound": "direct-ru"},
                            "bad",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            rules = admin_apply.load_rules(rules_path)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "1")


if __name__ == "__main__":
    unittest.main()
