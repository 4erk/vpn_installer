from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import Any, Iterable

from .dns_policy import CONNECTIVITY_CHECK_DIRECT_DOMAINS, CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS, merged_domains

POLICY_VERSION = "0.11.9"

TRAFFIC_CLASSES = (
    "ru_direct_domain",
    "ru_direct_ip",
    "private_or_fake",
    "connectivity_check",
    "connectivity_check_ipv6_only",
    "dns_global",
    "domain_foreign",
    "ipv4_literal_foreign",
    "ipv6_literal_foreign",
    "blocked",
)


def _env_list(env: dict[str, str], key: str) -> list[str]:
    return [item.strip() for item in textwrap.dedent(env.get(key, "")).replace("\n", ",").split(",") if item.strip()]


@dataclass(frozen=True)
class RouteClass:
    name: str
    outbound: str
    resolver: str
    timeout_policy: str
    log_category: str
    fallback: str
    dns_rules: tuple[dict[str, Any], ...] = ()
    route_rules: tuple[dict[str, Any], ...] = ()

    def metadata(self) -> dict[str, str]:
        return {
            "name": self.name,
            "outbound": self.outbound,
            "resolver": self.resolver,
            "timeout_policy": self.timeout_policy,
            "log_category": self.log_category,
            "fallback": self.fallback,
        }


@dataclass(frozen=True)
class RoutingPolicy:
    policy_version: str
    traffic: tuple[RouteClass, ...]
    control_route_rules: tuple[dict[str, Any], ...]
    outbounds: tuple[dict[str, Any], ...]
    final_outbound: str
    deprecated_overrides: tuple[str, ...] = field(default_factory=tuple)

    @property
    def classes(self) -> dict[str, RouteClass]:
        return {item.name: item for item in self.traffic}

    @property
    def dns_rules(self) -> list[dict[str, Any]]:
        return [rule for item in self.traffic for rule in item.dns_rules]

    @property
    def route_rules(self) -> list[dict[str, Any]]:
        return [*self.control_route_rules, *(rule for item in self.traffic for rule in item.route_rules)]

    def singbox_parts(self) -> dict[str, Any]:
        return {
            "dns_rules": self.dns_rules,
            "route_rules": self.route_rules,
            "outbounds": list(self.outbounds),
            "final_outbound": self.final_outbound,
            "policy_version": self.policy_version,
            "traffic_classes": {item.name: item.metadata() for item in self.traffic},
            "deprecated_overrides": list(self.deprecated_overrides),
        }


def _traffic_class(
    name: str,
    outbound: str,
    resolver: str,
    timeout_policy: str,
    log_category: str,
    fallback: str,
    *,
    dns: Iterable[dict[str, Any]] = (),
    routes: Iterable[dict[str, Any]] = (),
) -> RouteClass:
    return RouteClass(name, outbound, resolver, timeout_policy, log_category, fallback, tuple(dns), tuple(routes))


def build_ru_routing_policy(env: dict[str, str]) -> RoutingPolicy:
    sniff_timeout = env.get("RU_SNIFF_TIMEOUT", "250ms").strip() or "250ms"
    ipv6_only_domains = {domain.lower() for domain in CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS}
    direct_domains = [domain for domain in _env_list(env, "RU_FORCE_DIRECT_DOMAIN") if domain.lower() not in ipv6_only_domains]
    direct_domains = merged_domains(CONNECTIVITY_CHECK_DIRECT_DOMAINS, direct_domains)
    direct_suffixes = _env_list(env, "RU_FORCE_DIRECT_DOMAIN_SUFFIX")
    direct_cidrs = _env_list(env, "RU_FORCE_DIRECT_IP_CIDR")
    if env.get("RU_PUBLIC_IP", "").strip():
        public_cidr = f"{env['RU_PUBLIC_IP'].strip()}/32"
        if public_cidr not in direct_cidrs:
            direct_cidrs.append(public_cidr)
    blocked_cidrs = _env_list(env, "RU_BLOCK_IP_CIDR")
    raw_ru_geoip_route = {"rule_set": ["ru-geoip"], "action": "route", "outbound": "direct-ru"}

    control_rules: list[dict[str, Any]] = [
        {"inbound": ["router-in"], "action": "sniff", "timeout": sniff_timeout},
        {"action": "route-options", "udp_disable_domain_unmapping": True},
        {"protocol": "dns", "action": "hijack-dns"},
    ]

    traffic = (
        _traffic_class(
            "connectivity_check_ipv6_only", "reject", "none", "none", "blocked_private_fake", "none",
            dns=({"query_type": ["AAAA"], "action": "reject"}, {"domain": list(CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS), "action": "reject"}),
            routes=({"domain": list(CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS), "action": "reject"},),
        ),
        _traffic_class(
            "connectivity_check", "direct-ru", "dns-ru-direct", "none", "direct_ru", "dns-global",
            dns=({"domain": direct_domains, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"},) if direct_domains else (),
            routes=({"domain": direct_domains, "action": "route", "outbound": "direct-ru"},) if direct_domains else (),
        ),
        _traffic_class(
            "ru_direct_domain", "direct-ru", "dns-ru-direct", "none", "direct_ru", "blocked",
            dns=(
                *(({"domain_suffix": direct_suffixes, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"},) if direct_suffixes else ()),
                {"rule_set": ["ru-geosite"], "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"},
            ),
            routes=(
                *(({"domain_suffix": direct_suffixes, "action": "route", "outbound": "direct-ru"},) if direct_suffixes else ()),
                {"rule_set": ["ru-geosite"], "action": "route", "outbound": "direct-ru"},
            ),
        ),
        _traffic_class(
            "dns_global", "to-foreign", "dns-global", "system", "dns_failed", "none",
            dns=({"ip_is_private": True, "action": "reject", "server": "dns-global"},),
        ),
        _traffic_class(
            "domain_foreign", "to-foreign", "dns-global", "system", "domain_to_foreign_timeout", "none",
            routes=({"domain_regex": ["^[^:]*[A-Za-z][^:]*$"], "action": "route", "outbound": "to-foreign"},),
        ),
        _traffic_class(
            "blocked", "reject", "none", "none", "blocked_private_fake", "none",
            routes=({"ip_cidr": blocked_cidrs, "action": "reject"},) if blocked_cidrs else (),
        ),
        _traffic_class(
            "private_or_fake", "reject", "none", "none", "blocked_private_fake", "none",
            routes=({"ip_is_private": True, "action": "reject"},),
        ),
        _traffic_class(
            "ru_direct_ip", "direct-ru", "dns-ru-direct", "none", "direct_ru", "blocked",
            routes=(
                *(({"ip_cidr": direct_cidrs, "action": "route", "outbound": "direct-ru"},) if direct_cidrs else ()),
                raw_ru_geoip_route,
            ),
        ),
        _traffic_class(
            "ipv6_literal_foreign", "to-foreign", "none", "system", "ipv6_literal_timeout", "none",
            routes=({"ip_version": 6, "action": "route", "outbound": "to-foreign"},),
        ),
        _traffic_class(
            "ipv4_literal_foreign", "to-foreign", "none", "system", "ipv4_literal_timeout", "none",
            routes=({"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"},),
        ),
    )
    foreign_base = {
        "type": "direct",
        "bind_interface": env["WG_INTERFACE"],
        "routing_mark": int(env["APP_ROUTE_MARK"]),
        "domain_resolver": {"server": "dns-global", "strategy": "ipv4_only"},
    }
    outbounds = (
        {"type": "direct", "tag": "direct-ru", "domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"}},
        dict(foreign_base, tag="to-foreign"),
    )
    deprecated = tuple(
        key
        for key in (
            "RU_LITERAL_POLICY", "RU_IPV6_LITERAL_POLICY", "RU_IPV6_POLICY", "RU_GEOIP_DIRECT",
            "TO_FOREIGN_CONNECT_TIMEOUT", "TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT", "TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT",
            "RU_BLOCK_QUIC",
        )
        if key in env
    )
    policy = RoutingPolicy(POLICY_VERSION, traffic, tuple(control_rules), outbounds, "to-foreign", deprecated)
    missing = set(TRAFFIC_CLASSES) - set(policy.classes)
    if missing:
        raise ValueError(f"routing policy is incomplete: {', '.join(sorted(missing))}")
    return policy
