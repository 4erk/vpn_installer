from __future__ import annotations

import json
import unittest

from vpn_installer.client_artifacts import render_client_profile, render_vless_uri
from vpn_installer.config import generate_default_env
from vpn_installer.public_transport import (
    PUBLIC_HY2_OUTBOUND_TAG,
    PUBLIC_SELECTOR_TAG,
    PUBLIC_VLESS_OUTBOUND_TAG,
    derive_public_hy2_password,
)
from vpn_installer.render import render_ru_firewall_nftables, render_ru_singbox


class PublicTransportTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
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

    def test_adaptive_profile_prefers_quic_and_falls_back_to_canonical_vless(self) -> None:
        env = self.make_env()
        profile = json.loads(render_client_profile(env, auto_redirect=False))
        outbounds = {item["tag"]: item for item in profile["outbounds"]}
        selector = outbounds[PUBLIC_SELECTOR_TAG]
        self.assertEqual(selector["type"], "urltest")
        self.assertEqual(selector["outbounds"], [PUBLIC_HY2_OUTBOUND_TAG, PUBLIC_VLESS_OUTBOUND_TAG])
        self.assertEqual(selector["interval"], "30s")
        self.assertFalse(selector["interrupt_exist_connections"])
        self.assertNotIn("up_mbps", outbounds[PUBLIC_HY2_OUTBOUND_TAG])
        self.assertNotIn("down_mbps", outbounds[PUBLIC_HY2_OUTBOUND_TAG])
        self.assertEqual(outbounds[PUBLIC_VLESS_OUTBOUND_TAG]["flow"], env["CLIENT_FLOW"])
        self.assertEqual(profile["route"]["final"], PUBLIC_SELECTOR_TAG)
        self.assertEqual(profile["dns"]["servers"][0]["detour"], PUBLIC_SELECTOR_TAG)

    def test_primary_vless_uri_contract_remains_tcp_reality(self) -> None:
        env = self.make_env()
        uri = render_vless_uri(env)
        self.assertIn("security=reality", uri)
        self.assertIn("type=tcp", uri)
        self.assertNotIn("hysteria", uri.lower())


if __name__ == "__main__":
    unittest.main()
