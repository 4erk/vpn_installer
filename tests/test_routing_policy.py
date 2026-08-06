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

    def test_policy_declares_every_traffic_class(self) -> None:
        policy = build_ru_routing_policy(self.make_env())
        self.assertEqual(set(policy.classes), set(TRAFFIC_CLASSES))
        self.assertEqual(policy.classes["ipv4_literal_foreign"].outbound, "to-foreign")
        self.assertEqual(policy.classes["ipv6_literal_foreign"].outbound, "to-foreign")
        self.assertEqual(policy.classes["domain_foreign"].outbound, "to-foreign")
        self.assertEqual(policy.classes["global_foreign"].outbound, "to-foreign")
        self.assertNotIn("resolved_ru_ip", policy.classes)
        self.assertNotIn("client_dns_dot", policy.classes)

    def test_policy_uses_one_stable_wireguard_overlay_without_artificial_timeouts(self) -> None:
        parts = build_ru_routing_policy(self.make_env()).singbox_parts()
        outbounds = {outbound["tag"]: outbound for outbound in parts["outbounds"]}
        self.assertEqual(set(outbounds), {"direct-ru", "to-foreign"})
        self.assertEqual(outbounds["to-foreign"]["type"], "direct")
        self.assertEqual(outbounds["to-foreign"]["bind_interface"], "wg0")
        self.assertEqual(outbounds["to-foreign"]["domain_resolver"]["server"], "dns-ru-direct")
        self.assertFalse(any("connect_timeout" in outbound for outbound in outbounds.values()))

    def test_domain_policy_finishes_before_literal_policy(self) -> None:
        rules = build_ru_routing_policy(self.make_env()).route_rules
        domain_foreign_index = next(
            i
            for i, rule in enumerate(rules)
            if rule.get("domain_regex") == ["^[^:]*[A-Za-z][^:]*$"]
            and rule.get("action") == "route"
            and rule.get("outbound") == "to-foreign"
        )
        raw_ru_geoip_index = next(i for i, rule in enumerate(rules) if rule.get("rule_set") == ["ru-geoip"])
        ipv6_index = next(i for i, rule in enumerate(rules) if rule.get("ip_version") == 6)
        ipv4_index = next(i for i, rule in enumerate(rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        self.assertEqual(rules[raw_ru_geoip_index]["outbound"], "direct-ru")
        self.assertEqual(rules[domain_foreign_index]["outbound"], "to-foreign")
        self.assertEqual(rules[ipv6_index], {"ip_version": 6, "action": "route", "outbound": "to-foreign"})
        self.assertEqual(rules[ipv4_index], {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"})
        self.assertLess(domain_foreign_index, raw_ru_geoip_index)
        self.assertLess(raw_ru_geoip_index, ipv6_index)
        self.assertLess(ipv6_index, ipv4_index)

    def test_domain_resolution_precedes_guards_and_terminal_routes(self) -> None:
        rules = build_ru_routing_policy(self.make_env()).route_rules
        direct_resolve_index = next(i for i, rule in enumerate(rules) if rule.get("action") == "resolve" and rule.get("rule_set") == ["ru-geosite"])
        direct_route_index = next(i for i, rule in enumerate(rules) if rule.get("outbound") == "direct-ru" and rule.get("rule_set") == ["ru-geosite"])
        foreign_resolve_index = next(
            i
            for i, rule in enumerate(rules)
            if rule.get("action") == "resolve"
            and rule.get("server") == "dns-global"
            and "domain_regex" in rule
        )
        foreign_route_index = next(i for i, rule in enumerate(rules) if rule.get("outbound") == "to-foreign" and "domain_regex" in rule)
        global_resolve_index = next(
            i
            for i, rule in enumerate(rules)
            if rule.get("action") == "resolve"
            and rule.get("server") == "dns-global"
            and "mtalk.google.com" in rule.get("domain", [])
        )
        direct_exact_route_index = next(i for i, rule in enumerate(rules) if rule.get("outbound") == "direct-ru" and "domain" in rule)
        private_indexes = [i for i, rule in enumerate(rules) if rule.get("ip_is_private") is True]
        self.assertTrue(any(direct_resolve_index < i < direct_route_index for i in private_indexes))
        self.assertTrue(any(foreign_resolve_index < i < foreign_route_index for i in private_indexes))
        self.assertLess(global_resolve_index, direct_exact_route_index)
        self.assertLess(direct_exact_route_index, direct_resolve_index)
        self.assertLess(direct_route_index, foreign_resolve_index)
        self.assertEqual(sum(rule.get("rule_set") == ["ru-geoip"] for rule in rules), 1)

    def test_client_dns_and_routed_domains_have_private_guards(self) -> None:
        rules = build_ru_routing_policy(self.make_env()).dns_rules
        self.assertIn({"ip_is_private": True, "action": "reject", "server": "dns-global"}, rules)
        route_rules = build_ru_routing_policy(self.make_env()).route_rules
        self.assertTrue(any(rule.get("server") == "dns-ru-direct" and rule.get("action") == "resolve" for rule in route_rules))
        self.assertTrue(any(rule.get("server") == "dns-global" and rule.get("action") == "resolve" for rule in route_rules))
        self.assertIn({"ip_is_private": True, "action": "reject"}, route_rules)

    def test_ipv6_only_probe_cannot_leak_from_legacy_direct_domains(self) -> None:
        env = self.make_env()
        env["RU_FORCE_DIRECT_DOMAIN"] += ",ipv6-internet.yandex.net"
        policy = build_ru_routing_policy(env)
        rejected = next(rule for rule in policy.dns_rules if rule.get("action") == "reject" and "domain" in rule)
        routed_domains = [domain for rule in policy.dns_rules if rule.get("action") == "route" for domain in rule.get("domain", [])]
        self.assertIn("ipv6-internet.yandex.net", rejected["domain"])
        self.assertNotIn("ipv6-internet.yandex.net", routed_domains)

    def test_global_services_cannot_leak_from_legacy_direct_policy(self) -> None:
        env = self.make_env()
        env["RU_FORCE_DIRECT_DOMAIN"] += ",mtalk.google.com,www.msftconnecttest.com"
        env["RU_FORCE_DIRECT_DOMAIN_SUFFIX"] += ",.gstatic.com"
        policy = build_ru_routing_policy(env)
        direct_domains = {
            domain.lower()
            for rule in policy.route_rules
            if rule.get("outbound") == "direct-ru"
            for domain in rule.get("domain", [])
        }
        direct_suffixes = {
            suffix.lower()
            for rule in policy.route_rules
            if rule.get("outbound") == "direct-ru"
            for suffix in rule.get("domain_suffix", [])
        }
        self.assertTrue({"mtalk.google.com", "www.msftconnecttest.com"}.isdisjoint(direct_domains))
        self.assertNotIn(".gstatic.com", direct_suffixes)
        global_routes = [rule for rule in policy.route_rules if rule.get("outbound") == "to-foreign"]
        self.assertTrue(any("mtalk.google.com" in rule.get("domain", []) for rule in global_routes))
        self.assertTrue(any(".gstatic.com" in rule.get("domain_suffix", []) for rule in global_routes))

    def test_private_addresses_including_tun_dot_reject_without_dns_override(self) -> None:
        rules = build_ru_routing_policy(self.make_env()).route_rules
        private_index = next(i for i, rule in enumerate(rules) if rule.get("ip_is_private") is True)
        self.assertEqual(rules[private_index], {"ip_is_private": True, "action": "reject"})
        self.assertFalse(any(rule.get("port") == 853 for rule in rules))
        self.assertFalse(any("override_address" in rule for rule in rules))

    def test_legacy_knobs_are_reported_but_cannot_change_routes(self) -> None:
        env = self.make_env()
        baseline = build_ru_routing_policy(env)
        env.update({"RU_LITERAL_POLICY": "reject", "RU_IPV6_LITERAL_POLICY": "reject", "TO_FOREIGN_CONNECT_TIMEOUT": "5s", "RU_BLOCK_QUIC": "1"})
        legacy = build_ru_routing_policy(env)
        self.assertEqual(legacy.route_rules, baseline.route_rules)
        self.assertEqual(legacy.outbounds, baseline.outbounds)
        self.assertEqual(
            set(legacy.deprecated_overrides),
            {"RU_LITERAL_POLICY", "RU_IPV6_LITERAL_POLICY", "TO_FOREIGN_CONNECT_TIMEOUT", "RU_BLOCK_QUIC"},
        )


if __name__ == "__main__":
    unittest.main()
