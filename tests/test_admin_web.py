from __future__ import annotations

import json
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
from vpn_installer.render import render_gateway_singbox


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

    def test_missing_bootstrap_does_not_create_default_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            with patch.object(admin_web, "AUTH_PATH", auth_path), patch.object(admin_web, "load_env", return_value={}):
                with self.assertRaisesRegex(ValueError, "credentials are missing"):
                    admin_web.load_auth()
                self.assertFalse(auth_path.exists())
                with self.assertRaisesRegex(ValueError, "explicit username and password"):
                    admin_web.main(["init-auth"])

    def test_existing_auth_is_not_rotated_by_new_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            with patch.object(admin_web, "AUTH_PATH", auth_path), patch.object(admin_web, "load_env", return_value={}):
                admin_web.init_auth("operator", "existing-password")
                before = auth_path.read_bytes()
                admin_web.init_auth("other", "new-bootstrap")
                self.assertEqual(before, auth_path.read_bytes())
                self.assertTrue(admin_web.check_basic_auth(self.basic_header("operator", "existing-password")))
                self.assertFalse(admin_web.check_basic_auth(self.basic_header("\u044e\u0437\u0435\u0440", "existing-password")))

    def test_malformed_hash_fails_closed_without_unbounded_kdf(self) -> None:
        valid = admin_web.hash_password("secret")
        for changes in ({"salt": "not-hex"}, {"hash": "not-hex"}, {"rounds": -1}, {"rounds": 10**12}, {"algorithm": "unknown"}):
            with self.subTest(changes=changes):
                self.assertFalse(admin_web.verify_password("secret", {**valid, **changes}))

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

    def test_load_rules_propagates_invalid_state(self) -> None:
        with patch("vpn_installer.admin_web.admin_apply.load_rules", side_effect=ValueError("bad rules")):
            with self.assertRaisesRegex(ValueError, "bad rules"):
                admin_web.load_rules()

    def test_page_and_settings_escape_untrusted_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            with patch.object(admin_web, "AUTH_PATH", auth_path):
                admin_web.init_auth('<script>', "password", force=True)
                html = admin_web.settings_body("changed <ok>").decode("utf-8")
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("changed &lt;ok&gt;", html)
        self.assertIn("VPN Admin", admin_web.page("T", "routes", admin_web.ROUTES_BODY).decode("utf-8"))

    def test_web_commit_delegates_to_transactional_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "rules.json"
            new_rules = [admin_apply.normalize_rule({"id": "1", "value": "new.example", "outbound": "direct-ru"})]
            with patch.object(admin_web, "RULES_PATH", rules_path), patch("vpn_installer.admin_web.admin_apply.commit_rules") as commit_mock:
                ok, message = admin_web.commit_rules(new_rules, [])
            commit_mock.assert_called_once_with(
                new_rules,
                rules_path=rules_path,
                restart=True,
                expected_generation=admin_apply.rules_generation([]),
            )
            self.assertTrue(ok)
            self.assertIn("применены", message)

            with patch.object(admin_web, "RULES_PATH", rules_path), patch(
                "vpn_installer.admin_web.admin_apply.commit_rules", side_effect=RuntimeError("boom")
            ):
                ok, message = admin_web.commit_rules(new_rules, [])
        self.assertFalse(ok)
        self.assertIn("boom", message)

    def test_transactional_commit_restores_rules_and_config_when_restart_fails(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base_path = tmp_path / "base.json"
            config_path = tmp_path / "config.json"
            rules_path = tmp_path / "rules.json"
            lock_path = tmp_path / "rules.lock"
            sing_box_binary = tmp_path / "sing-box"
            sing_box_binary.write_bytes(b"pinned-test-binary")
            base_path.write_text(render_gateway_singbox(env), encoding="utf-8")
            config_path.write_text(render_gateway_singbox(env), encoding="utf-8")
            old_rules = [admin_apply.normalize_rule({"id": "1", "value": "old.example", "outbound": "direct-ru"})]
            new_rules = [admin_apply.normalize_rule({"id": "2", "value": "new.example", "outbound": "direct-ru"})]
            admin_apply.write_json_atomic(rules_path, {"schema_version": 1, "rules": old_rules})
            old_config = config_path.read_bytes()
            with patch("vpn_installer.admin_apply.subprocess.run"), patch(
                "vpn_installer.admin_apply.restart_and_verify_singbox",
                side_effect=[RuntimeError("bad apply"), None],
            ) as restart_mock:
                with self.assertRaisesRegex(RuntimeError, "bad apply"):
                    admin_apply.commit_rules(
                        new_rules,
                        base_path,
                        config_path,
                        rules_path,
                        restart=True,
                        lock_path=lock_path,
                        sing_box_binary=sing_box_binary,
                    )
            self.assertEqual(admin_apply.load_rules(rules_path), old_rules)
            self.assertEqual(config_path.read_bytes(), old_config)
            self.assertEqual(restart_mock.call_count, 2)

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
            self.assertIn("topology", payload["config"])
            self.assertIn("gateway_location", payload["config"])

    def test_web_ui_preserves_unavailable_migrated_outbound_visibility(self) -> None:
        self.assertIn("(недоступно)", admin_web.ROUTES_SCRIPT)
        self.assertIn("rule.conflict", admin_web.ROUTES_SCRIPT)

    def test_serve_and_main_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "deployment.env"
            auth_path = tmp_path / "admin-auth.json"
            env_path.write_text('ADMIN_WEB_BIND="0.0.0.0"\nADMIN_WEB_PORT="11333"\n', encoding="utf-8")

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

            with patch.object(admin_web, "ENV_PATH", env_path), patch.object(admin_web, "AUTH_PATH", auth_path), patch(
                "vpn_installer.admin_web.ThreadingHTTPServer", side_effect=fake_server
            ):
                self.assertEqual(admin_web.main(["init-auth", "operator", "new-password", "--force"]), 0)
                self.assertTrue(admin_web.check_basic_auth(self.basic_header("operator", "new-password")))
                self.assertEqual(admin_web.main([]), 0)
            self.assertEqual(created[0].address, ("0.0.0.0", 11333))
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
            commit_error: dict[str, str | None] = {"message": None}

            def fake_commit(raw_rules: list[dict[str, object]], *args: object, **kwargs: object) -> list[dict[str, object]]:
                if commit_error["message"]:
                    raise RuntimeError(commit_error["message"])
                normalized = admin_apply.normalize_rules(raw_rules)
                admin_apply.write_json_atomic(rules_path, {"schema_version": 1, "rules": normalized})
                return normalized

            commit_mock = stack.enter_context(patch("vpn_installer.admin_web.admin_apply.commit_rules", side_effect=fake_commit))
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

                commit_error["message"] = "apply failed"
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
                commit_error["message"] = None

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
                self.assertTrue(commit_mock.called)

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
                commit_error["message"] = "delete failed"
                delete_fail = urllib.request.Request(
                    f"{base_url}/api/routes/{urllib.parse.quote(second_rule_id)}",
                    method="DELETE",
                    headers={"Authorization": auth, "X-CSRF-Token": admin_web.CSRF_TOKEN},
                )
                with self.assertRaises(urllib.error.HTTPError) as delete_apply_error:
                    urllib.request.urlopen(delete_fail, timeout=5)
                self.assertEqual(delete_apply_error.exception.code, 400)
                commit_error["message"] = None

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
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        base = json.loads(render_gateway_singbox(env))
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
        private_index = next(i for i, rule in enumerate(route_rules) if rule.get("ip_is_private") is True)
        override_resolve_index = next(i for i, rule in enumerate(route_rules) if rule.get("action") == "resolve" and rule.get("domain") == ["gosuslugi.ru"])
        base_resolve_index = next(i for i, rule in enumerate(route_rules) if rule.get("action") == "resolve" and rule.get("rule_set") == ["ru-geosite"])
        self.assertLess(override_index, geosite_index)
        self.assertLess(override_resolve_index, private_index)
        self.assertLess(private_index, override_index)
        self.assertLess(override_index, base_resolve_index)
        dns_rule = next(rule for rule in config["dns"]["rules"] if rule.get("domain") == ["gosuslugi.ru"])
        self.assertEqual(dns_rule["server"], "dns-global")

    def test_single_gateway_admin_rejects_unavailable_dual_outbound(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "198.51.100.20"
        base = json.loads(render_gateway_singbox(env))
        catalog = admin_apply.outbound_catalog(base)
        self.assertEqual(
            catalog,
            {
                "local-egress": {
                    "tag": "local-egress",
                    "label": "текущий сервер",
                    "dns_server": "dns-local",
                }
            },
        )
        rule = admin_apply.normalize_rule({"value": "example.com", "outbound": "to-foreign"})
        with self.assertRaisesRegex(ValueError, "отсутствует в текущей topology"):
            admin_apply.apply_admin_rules_to_config(base, [rule])

    def test_topology_migration_disables_unavailable_admin_rule_without_remapping(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "198.51.100.20"
        base = json.loads(render_gateway_singbox(env))
        rule = admin_apply.normalize_rule({"value": "example.com", "outbound": "to-foreign"})

        migrated = admin_apply.reconcile_rules_with_catalog(
            [rule],
            admin_apply.outbound_catalog(base),
            migrate_unavailable=True,
        )

        self.assertFalse(migrated[0]["enabled"])
        self.assertEqual(migrated[0]["outbound"], "to-foreign")
        self.assertIn("unavailable", migrated[0]["conflict"])
        config = admin_apply.apply_admin_rules_to_config(base, migrated)
        self.assertFalse(any(rule.get("domain") == ["example.com"] for rule in config["route"]["rules"]))

    def test_apply_rules_writes_checked_config_without_restart(self) -> None:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            base = tmp_path / "base.json"
            config = tmp_path / "config.json"
            rules = tmp_path / "rules.json"
            sing_box_binary = tmp_path / "sing-box"
            sing_box_binary.write_bytes(b"pinned-test-binary")
            base.write_text(render_gateway_singbox(env), encoding="utf-8")
            rules.write_text(
                json.dumps({"rules": [{"id": "1", "value": "*.example.com", "outbound": "direct-ru"}]}),
                encoding="utf-8",
            )
            with patch("vpn_installer.admin_apply.subprocess.run") as check_mock:
                admin_apply.apply_rules(base, config, rules, restart=False, sing_box_binary=sing_box_binary)
            check_mock.assert_called_once()
            payload = json.loads(config.read_text(encoding="utf-8"))
        direct_rule = next(rule for rule in payload["route"]["rules"] if rule.get("outbound") == "direct-ru" and rule.get("domain") == ["example.com"])
        self.assertEqual(direct_rule["domain"], ["example.com"])

    def test_admin_apply_helpers_cover_cidr_and_indexes(self) -> None:
        cidr_rule = admin_apply.normalize_rule({"value": "8.8.8.8/32", "outbound": "direct-ru"})
        self.assertEqual(cidr_rule["type"], "cidr")
        self.assertEqual(cidr_rule["value"], "8.8.8.8/32")
        self.assertEqual(admin_apply.rule_domains({"value": "example.com", "include_subdomains": True}), (["example.com"], [".example.com"]))
        self.assertEqual(admin_apply.route_insert_index([]), 0)
        self.assertEqual(
            admin_apply.route_insert_index(
                [{"inbound": ["public-hy2-in"], "port": 53, "action": "route", "outbound": "to-foreign"}]
            ),
            1,
        )
        self.assertEqual(admin_apply.dns_insert_index([]), 0)

    def test_admin_cidr_cannot_override_private_guard(self) -> None:
        with self.assertRaisesRegex(ValueError, "публичных"):
            admin_apply.normalize_rule({"value": "10.0.0.0/8", "outbound": "direct-ru"})

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
