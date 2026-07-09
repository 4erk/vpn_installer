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
        self.assertEqual(policy.classes["private_dot_recovery"].outbound, "to-foreign")
        self.assertEqual(policy.classes["connectivity_check"].outbound, "direct-ru")
        self.assertEqual(policy.classes["connectivity_check_ipv6_only"].outbound, "blocked")

    def test_connectivity_checks_are_direct_without_operator_knobs(self) -> None:
        parts = build_ru_routing_policy(self.make_env()).singbox_parts()
        dns_rule = next(rule for rule in parts["dns_rules"] if rule.get("action") == "route" and rule.get("server") == "dns-ru-direct" and "domain" in rule)
        direct_resolve_index = next(
            index
            for index, rule in enumerate(parts["route_rules"])
            if rule.get("domain") and "www.msftconnecttest.com" in rule["domain"] and rule.get("action") == "resolve"
        )
        direct_route_index = next(
            index
            for index, rule in enumerate(parts["route_rules"])
            if rule.get("domain") and "www.msftconnecttest.com" in rule["domain"] and rule.get("outbound") == "direct-ru"
        )
        global_resolve_index = next(index for index, rule in enumerate(parts["route_rules"]) if rule.get("server") == "dns-global")

        self.assertIn("www.msftconnecttest.com", dns_rule["domain"])
        dns_reject_rule = next(rule for rule in parts["dns_rules"] if rule.get("domain") == ["ipv6.msftconnecttest.com", "ipv6.msftncsi.com"])
        route_reject_index = next(
            index
            for index, rule in enumerate(parts["route_rules"])
            if rule.get("domain") == ["ipv6.msftconnecttest.com", "ipv6.msftncsi.com"] and rule.get("action") == "reject"
        )
        self.assertEqual(dns_reject_rule["action"], "reject")
        self.assertLess(direct_resolve_index, direct_route_index)
        self.assertLess(route_reject_index, direct_resolve_index)
        self.assertLess(direct_route_index, global_resolve_index)

    def test_policy_renders_stable_literal_order_and_outbounds(self) -> None:
        parts = build_ru_routing_policy(self.make_env()).singbox_parts()
        route_rules = parts["route_rules"]
        outbounds = {outbound["tag"]: outbound for outbound in parts["outbounds"]}
        ipv6_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_version") == 6)
        ipv4_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        resolve_index = next(index for index, rule in enumerate(route_rules) if rule.get("server") == "dns-global")

        self.assertLess(ipv6_index, ipv4_index)
        self.assertLess(ipv4_index, resolve_index)
        self.assertEqual(route_rules[ipv6_index], {"ip_version": 6, "action": "reject"})
        self.assertEqual(route_rules[ipv4_index]["outbound"], "to-foreign-ip-literal")
        self.assertNotIn("connect_timeout", outbounds["to-foreign"])
        self.assertEqual(outbounds["to-foreign-ip-literal"]["connect_timeout"], "2s")
        self.assertEqual(outbounds["to-foreign-ipv6-literal"]["connect_timeout"], "3s")

    def test_client_tun_dot_leak_is_recovered_before_private_block(self) -> None:
        parts = build_ru_routing_policy(self.make_env()).singbox_parts()
        route_rules = parts["route_rules"]
        dot_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == ["172.19.0.0/30"] and rule.get("port") == 853)
        private_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_is_private") is True)

        self.assertLess(dot_index, private_index)
        self.assertEqual(
            route_rules[dot_index],
            {
                "ip_cidr": ["172.19.0.0/30"],
                "port": 853,
                "action": "route",
                "outbound": "to-foreign",
                "override_address": "8.8.8.8",
                "override_port": 853,
            },
        )

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
