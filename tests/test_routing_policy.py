from __future__ import annotations

import unittest

from vpn_installer.config import generate_default_env
from vpn_installer.routing_policy import TRAFFIC_CLASSES, build_ru_routing_policy


class RoutingPolicyTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        return env

    def test_policy_declares_all_traffic_classes(self) -> None:
        policy = build_ru_routing_policy(self.make_env())
        self.assertEqual(set(policy.classes), set(TRAFFIC_CLASSES))
        self.assertEqual(policy.classes["ipv4_literal_foreign"].outbound, "to-foreign-ip-literal")
        self.assertEqual(policy.classes["ipv6_literal_foreign"].outbound, "to-foreign-ipv6-literal")
        self.assertEqual(policy.classes["domain_foreign"].outbound, "to-foreign")

    def test_policy_renders_stable_literal_order_and_outbounds(self) -> None:
        parts = build_ru_routing_policy(self.make_env()).singbox_parts()
        route_rules = parts["route_rules"]
        outbounds = {outbound["tag"]: outbound for outbound in parts["outbounds"]}
        ipv6_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_version") == 6)
        ipv4_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        resolve_index = next(index for index, rule in enumerate(route_rules) if rule.get("server") == "dns-global")

        self.assertLess(ipv6_index, ipv4_index)
        self.assertLess(ipv4_index, resolve_index)
        self.assertEqual(route_rules[ipv4_index]["outbound"], "to-foreign-ip-literal")
        self.assertNotIn("connect_timeout", outbounds["to-foreign"])
        self.assertEqual(outbounds["to-foreign-ip-literal"]["connect_timeout"], "2s")
        self.assertEqual(outbounds["to-foreign-ipv6-literal"]["connect_timeout"], "3s")

    def test_high_level_literal_policies_change_routes_without_new_timeout_knobs(self) -> None:
        env = self.make_env()
        env["RU_LITERAL_POLICY"] = "reject"
        env["RU_IPV6_LITERAL_POLICY"] = "reject"
        rules = build_ru_routing_policy(env).route_rules
        self.assertIn({"ip_version": 6, "action": "reject"}, rules)
        self.assertIn({"ip_cidr": ["0.0.0.0/0"], "action": "reject"}, rules)

    def test_deprecated_overrides_are_reported(self) -> None:
        env = self.make_env()
        env["TO_FOREIGN_CONNECT_TIMEOUT"] = "5s"
        env["TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT"] = ""
        policy = build_ru_routing_policy(env)
        self.assertIn("TO_FOREIGN_CONNECT_TIMEOUT", policy.deprecated_overrides)
        self.assertIn("TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT", policy.deprecated_overrides)


if __name__ == "__main__":
    unittest.main()
