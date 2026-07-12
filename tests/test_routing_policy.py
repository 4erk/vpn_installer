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
        self.assertEqual(policy.classes["resolved_ru_ip"].outbound, "direct-ru")
        self.assertEqual(policy.classes["resolved_ru_ip"].resolver, "dns-global")
        self.assertEqual(policy.classes["client_dns_dot"].outbound, "direct-ru")
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
        ipv6_reject_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_version") == 6 and rule.get("action") == "reject")
        ipv4_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        resolve_index = next(index for index, rule in enumerate(route_rules) if rule.get("server") == "dns-global")

        self.assertLess(ipv6_reject_index, ipv4_index)
        self.assertLess(ipv4_index, resolve_index)
        self.assertEqual(route_rules[ipv6_reject_index], {"ip_version": 6, "action": "reject"})
        self.assertEqual(route_rules[ipv4_index]["outbound"], "to-foreign-ip-literal")
        self.assertNotIn("connect_timeout", outbounds["to-foreign"])
        self.assertEqual(outbounds["to-foreign-ip-literal"]["connect_timeout"], "750ms")
        self.assertEqual(outbounds["to-foreign-ipv6-literal"]["connect_timeout"], "2s")

    def test_resolved_ru_geoip_direct_only_after_domain_resolution(self) -> None:
        parts = build_ru_routing_policy(self.make_env()).singbox_parts()
        route_rules = parts["route_rules"]
        ipv4_literal_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        resolve_index = next(index for index, rule in enumerate(route_rules) if rule.get("server") == "dns-global")
        ru_geoip_indexes = [index for index, rule in enumerate(route_rules) if rule.get("rule_set") == ["ru-geoip"] and rule.get("outbound") == "direct-ru"]

        self.assertEqual(len(ru_geoip_indexes), 1)
        self.assertLess(ipv4_literal_index, resolve_index)
        self.assertLess(resolve_index, ru_geoip_indexes[0])

        env = self.make_env()
        env["RU_GEOIP_DIRECT"] = "1"
        route_rules = build_ru_routing_policy(env).route_rules
        ipv4_literal_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        ru_geoip_indexes = [index for index, rule in enumerate(route_rules) if rule.get("rule_set") == ["ru-geoip"] and rule.get("outbound") == "direct-ru"]
        self.assertEqual(len(ru_geoip_indexes), 2)
        self.assertLess(ru_geoip_indexes[0], ipv4_literal_index)

    def test_ipv6_literal_route_budget_stays_explicit_operator_mode(self) -> None:
        env = self.make_env()
        env["RU_IPV6_LITERAL_POLICY"] = "route-with-budget"
        rules = build_ru_routing_policy(env).route_rules
        ipv6_index = next(index for index, rule in enumerate(rules) if rule.get("ip_version") == 6 and rule.get("port") == 443)
        ipv6_reject_index = next(index for index, rule in enumerate(rules) if rule.get("ip_version") == 6 and rule.get("action") == "reject")

        self.assertEqual(rules[ipv6_index], {"ip_version": 6, "port": 443, "action": "route", "outbound": "to-foreign-ipv6-literal"})
        self.assertLess(ipv6_index, ipv6_reject_index)

    def test_client_tun_dot_uses_direct_ru_not_foreign_path(self) -> None:
        parts = build_ru_routing_policy(self.make_env()).singbox_parts()
        route_rules = parts["route_rules"]
        dot_index = next(index for index, rule in enumerate(route_rules) if rule.get("port") == 853 and rule.get("override_address") == "8.8.8.8")
        private_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_is_private") is True)

        self.assertLess(dot_index, private_index)
        self.assertEqual(route_rules[dot_index]["outbound"], "direct-ru")
        self.assertIn("172.19.0.0/30", route_rules[dot_index]["ip_cidr"])
        self.assertIn("198.18.0.0/15", route_rules[dot_index]["ip_cidr"])
        self.assertIn("fd00::/8", route_rules[dot_index]["ip_cidr"])
        self.assertIn({"ip_is_private": True, "action": "route", "outbound": "blocked"}, route_rules)

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
