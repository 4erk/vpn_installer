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
        self.assertEqual(policy.classes["resolved_ru_ip"].outbound, "direct-ru")
        self.assertNotIn("client_dns_dot", policy.classes)

    def test_policy_has_two_real_egress_outbounds_without_artificial_timeouts(self) -> None:
        parts = build_ru_routing_policy(self.make_env()).singbox_parts()
        outbounds = {outbound["tag"]: outbound for outbound in parts["outbounds"]}
        self.assertEqual(set(outbounds), {"direct-ru", "to-foreign"})
        self.assertFalse(any("connect_timeout" in outbound for outbound in outbounds.values()))

    def test_literal_routes_are_deterministic_and_precede_domain_resolution(self) -> None:
        rules = build_ru_routing_policy(self.make_env()).route_rules
        ipv6_index = next(i for i, rule in enumerate(rules) if rule.get("ip_version") == 6)
        ipv4_index = next(i for i, rule in enumerate(rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        resolve_index = next(i for i, rule in enumerate(rules) if rule.get("server") == "dns-global")
        self.assertEqual(rules[ipv6_index], {"ip_version": 6, "action": "route", "outbound": "to-foreign"})
        self.assertEqual(rules[ipv4_index], {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"})
        self.assertLess(ipv6_index, ipv4_index)
        self.assertLess(ipv4_index, resolve_index)

    def test_resolved_ru_geoip_rule_only_runs_after_global_resolution(self) -> None:
        rules = build_ru_routing_policy(self.make_env()).route_rules
        resolve_index = next(i for i, rule in enumerate(rules) if rule.get("server") == "dns-global")
        geoip_indexes = [i for i, rule in enumerate(rules) if rule.get("rule_set") == ["ru-geoip"]]
        self.assertEqual(len(geoip_indexes), 1)
        self.assertLess(resolve_index, geoip_indexes[0])

    def test_ipv6_only_probe_cannot_leak_from_legacy_direct_domains(self) -> None:
        env = self.make_env()
        env["RU_FORCE_DIRECT_DOMAIN"] += ",ipv6-internet.yandex.net"
        policy = build_ru_routing_policy(env)
        rejected = next(rule for rule in policy.dns_rules if rule.get("action") == "reject" and "domain" in rule)
        routed_domains = [domain for rule in policy.dns_rules if rule.get("action") == "route" for domain in rule.get("domain", [])]
        self.assertIn("ipv6-internet.yandex.net", rejected["domain"])
        self.assertNotIn("ipv6-internet.yandex.net", routed_domains)

    def test_private_addresses_including_tun_dot_reject_without_dns_override(self) -> None:
        rules = build_ru_routing_policy(self.make_env()).route_rules
        private_index = next(i for i, rule in enumerate(rules) if rule.get("ip_is_private") is True)
        self.assertEqual(rules[private_index], {"ip_is_private": True, "action": "reject"})
        self.assertFalse(any(rule.get("port") == 853 for rule in rules))
        self.assertFalse(any("override_address" in rule for rule in rules))

    def test_legacy_knobs_are_reported_but_cannot_change_routes(self) -> None:
        baseline = build_ru_routing_policy(self.make_env())
        env = self.make_env()
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
