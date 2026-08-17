from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from vpn_installer.client_artifacts import PUBLIC_VLESS_OUTBOUND_TAG, render_client_profile, render_hysteria2_uri, render_vless_uri
from vpn_installer.config import generate_default_env
from vpn_installer.public_transport import derive_public_hy2_password, render_public_hy2_outbound
from vpn_installer.render import render_ru_firewall_nftables, render_ru_singbox


class PublicTransportTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env.update(
            {
                "CONFIG_SCHEMA": "3",
                "TOPOLOGY": "dual",
                "GATEWAY_LOCATION": "ru",
                "GATEWAY_PUBLIC_IP": "203.0.113.10",
                "EXIT_PUBLIC_IP": "198.51.100.20",
            }
        )
        env.pop("RU_PUBLIC_IP", None)
        env.pop("FOREIGN_PUBLIC_IP", None)
        return env

    def make_single_env(self) -> dict[str, str]:
        env = generate_default_env("single", topology="single", gateway_location="foreign")
        env.update(
            {
                "CONFIG_SCHEMA": "3",
                "TOPOLOGY": "single",
                "GATEWAY_LOCATION": "foreign",
                "GATEWAY_PUBLIC_IP": "192.0.2.44",
                "EXIT_PUBLIC_IP": "",
            }
        )
        env.pop("RU_PUBLIC_IP", None)
        env.pop("FOREIGN_PUBLIC_IP", None)
        return env

    def test_public_hysteria_credential_is_stable_and_transport_scoped(self) -> None:
        env = self.make_env()
        first = derive_public_hy2_password(env["CLIENT_UUID"])
        self.assertEqual(first, derive_public_hy2_password(env["CLIENT_UUID"]))
        self.assertNotEqual(first, env["CLIENT_UUID"])
        self.assertGreaterEqual(len(first), 40)

    def test_ru_router_exposes_authenticated_hysteria_on_udp_public_port(self) -> None:
        env = self.make_env()
        config = json.loads(render_ru_singbox(env))
        inbound = next(item for item in config["inbounds"] if item.get("tag") == "public-hy2-in")
        self.assertEqual(inbound["type"], "hysteria2")
        self.assertEqual(inbound["listen_port"], int(env["RU_LISTEN_PORT"]))
        self.assertEqual(inbound["users"], [{"password": derive_public_hy2_password(env["CLIENT_UUID"])}])
        self.assertTrue(inbound["tls"]["enabled"])

        firewall = render_ru_firewall_nftables(env)
        self.assertIn("udp dport 443 counter notrack", firewall)
        self.assertIn("udp sport 443 counter notrack", firewall)
        self.assertIn("udp dport 443 counter accept", firewall)

    def test_managed_profile_uses_mux_free_vless_transport(self) -> None:
        env = self.make_env()
        profile = json.loads(render_client_profile(env, auto_redirect=False))
        outbounds = {item["tag"]: item for item in profile["outbounds"]}
        self.assertEqual(outbounds[PUBLIC_VLESS_OUTBOUND_TAG]["multiplex"], {"enabled": False})
        self.assertNotIn("network", outbounds[PUBLIC_VLESS_OUTBOUND_TAG])
        self.assertEqual({item["type"] for item in profile["outbounds"]}, {"vless", "direct", "block"})
        self.assertFalse(any(item["type"] == "urltest" for item in profile["outbounds"]))
        self.assertEqual(profile["route"]["final"], PUBLIC_VLESS_OUTBOUND_TAG)
        self.assertEqual(profile["dns"]["servers"][0]["detour"], PUBLIC_VLESS_OUTBOUND_TAG)

    def test_primary_vless_uri_contract_remains_tcp_reality(self) -> None:
        env = self.make_env()
        env.update(
            {
                "CLIENT_UUID": "11111111-2222-3333-4444-555555555555",
                "RU_LISTEN_PORT": "443",
                "RU_REALITY_SERVER_NAME": "www.microsoft.com",
                "RU_REALITY_PUBLIC_KEY": "fixed-public-key",
                "RU_REALITY_SHORT_ID": "0123456789abcdef",
                "UTLS_FINGERPRINT": "chrome",
                "CLIENT_FLOW": "xtls-rprx-vision",
            }
        )

        self.assertEqual(
            render_vless_uri(env),
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?"
            "security=reality&sni=www.microsoft.com&pbk=fixed-public-key&sid=0123456789abcdef&"
            "fp=chrome&type=tcp&flow=xtls-rprx-vision#demo-ru-gateway\n",
        )

    def test_standard_hysteria2_uri_uses_pinned_certificate(self) -> None:
        env = self.make_env()
        parsed = urlsplit(render_hysteria2_uri(env).strip())
        query = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, "hysteria2")
        self.assertEqual(parsed.hostname, env["GATEWAY_PUBLIC_IP"])
        self.assertEqual(parsed.port, int(env["RU_LISTEN_PORT"]))
        self.assertEqual(unquote(parsed.username or ""), derive_public_hy2_password(env["CLIENT_UUID"]))
        self.assertEqual(query["sni"], ["vpn-stack.internal"])
        self.assertEqual(query["insecure"], ["1"])
        self.assertRegex(query["pinSHA256"][0], r"^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$")

    def test_single_gateway_public_uris_and_outbound_use_the_gateway_address(self) -> None:
        env = self.make_single_env()

        vless = urlsplit(render_vless_uri(env).strip())
        hysteria = urlsplit(render_hysteria2_uri(env).strip())
        outbound = render_public_hy2_outbound(env)

        self.assertEqual(vless.hostname, env["GATEWAY_PUBLIC_IP"])
        self.assertEqual(vless.fragment, "single-foreign-gateway")
        self.assertEqual(hysteria.hostname, env["GATEWAY_PUBLIC_IP"])
        self.assertEqual(outbound["server"], env["GATEWAY_PUBLIC_IP"])


if __name__ == "__main__":
    unittest.main()
