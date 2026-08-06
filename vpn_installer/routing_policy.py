from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import Any, Iterable

from .dns_policy import GLOBAL_FOREIGN_DOMAINS, GLOBAL_FOREIGN_DOMAIN_SUFFIXES, CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS
from .interserver_transport import (
    HY2_PORT,
    HY2_SERVER_NAME,
    TRANSPORT_CANDIDATE_TAGS,
    TRANSPORT_HEALTHCHECK_URL,
    TRANSPORT_HY2_TAG,
    TRANSPORT_SELECTOR_TAG,
    TRANSPORT_URLTEST_IDLE_TIMEOUT,
    TRANSPORT_URLTEST_INTERVAL,
    TRANSPORT_URLTEST_TOLERANCE_MS,
    TRANSPORT_WG_TAG,
    derive_transport_obfs_password,
    derive_transport_password,
)

POLICY_VERSION = "0.16.0"

TRAFFIC_CLASSES = (
    "ru_direct_domain",
    "ru_direct_ip",
    "private_or_fake",
    "connectivity_check_ipv6_only",
    "global_foreign",
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
    pre_route_rules: tuple[dict[str, Any], ...] = ()
    guard_rules: tuple[dict[str, Any], ...] = ()
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
        guards = [rule for item in self.traffic for rule in item.guard_rules]
        pre_only = [rule for item in self.traffic if not item.route_rules for rule in item.pre_route_rules]
        terminal_rules: list[dict[str, Any]] = []
        compiled = [*self.control_route_rules, *pre_only]
        for item in self.traffic:
            if item.pre_route_rules and item.route_rules:
                if len(item.pre_route_rules) != len(item.route_rules):
                    raise ValueError(f"routing class {item.name} has mismatched resolve and terminal rules")
                for pre_route, route in zip(item.pre_route_rules, item.route_rules):
                    compiled.extend((pre_route, *guards, route))
            elif item.route_rules:
                terminal_rules.extend(item.route_rules)
        return [*compiled, *guards, *terminal_rules]

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
    pre_routes: Iterable[dict[str, Any]] = (),
    guards: Iterable[dict[str, Any]] = (),
    routes: Iterable[dict[str, Any]] = (),
) -> RouteClass:
    return RouteClass(
        name,
        outbound,
        resolver,
        timeout_policy,
        log_category,
        fallback,
        tuple(dns),
        tuple(pre_routes),
        tuple(guards),
        tuple(routes),
    )


def build_ru_routing_policy(env: dict[str, str]) -> RoutingPolicy:
    sniff_timeout = env.get("RU_SNIFF_TIMEOUT", "250ms").strip() or "250ms"
    ipv6_only_domains = {domain.lower() for domain in CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS}
    foreign_domains = {domain.lower() for domain in GLOBAL_FOREIGN_DOMAINS}
    foreign_suffixes = {suffix.lower() for suffix in GLOBAL_FOREIGN_DOMAIN_SUFFIXES}
    direct_domains = [
        domain
        for domain in _env_list(env, "RU_FORCE_DIRECT_DOMAIN")
        if domain.lower() not in ipv6_only_domains | foreign_domains
    ]
    direct_suffixes = [
        suffix
        for suffix in _env_list(env, "RU_FORCE_DIRECT_DOMAIN_SUFFIX")
        if suffix.lower() not in foreign_suffixes
    ]
    direct_cidrs = _env_list(env, "RU_FORCE_DIRECT_IP_CIDR")
    if env.get("RU_PUBLIC_IP", "").strip():
        public_cidr = f"{env['RU_PUBLIC_IP'].strip()}/32"
        if public_cidr not in direct_cidrs:
            direct_cidrs.append(public_cidr)
    blocked_cidrs = _env_list(env, "RU_BLOCK_IP_CIDR")
    raw_ru_geoip_route = {"rule_set": ["ru-geoip"], "action": "route", "outbound": "direct-ru"}
    global_domains = list(GLOBAL_FOREIGN_DOMAINS)
    global_suffixes = list(GLOBAL_FOREIGN_DOMAIN_SUFFIXES)

    control_rules: list[dict[str, Any]] = [
        {"inbound": ["router-in"], "action": "sniff", "timeout": sniff_timeout},
        {"action": "route-options", "udp_disable_domain_unmapping": True},
        {"protocol": "dns", "action": "hijack-dns"},
    ]

    traffic = (
        _traffic_class(
            "connectivity_check_ipv6_only", "reject", "none", "none", "blocked_private_fake", "none",
            dns=({"query_type": ["AAAA"], "action": "reject"}, {"domain": list(CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS), "action": "reject"}),
            pre_routes=({"domain": list(CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS), "action": "reject"},),
        ),
        _traffic_class(
            "global_foreign", "to-foreign", "dns-global", "system", "domain_to_foreign_timeout", "none",
            dns=(
                {"domain": global_domains, "action": "route", "server": "dns-global", "strategy": "ipv4_only"},
                {"domain_suffix": global_suffixes, "action": "route", "server": "dns-global", "strategy": "ipv4_only"},
            ),
            pre_routes=(
                {"domain": global_domains, "action": "resolve", "server": "dns-global", "strategy": "ipv4_only"},
                {"domain_suffix": global_suffixes, "action": "resolve", "server": "dns-global", "strategy": "ipv4_only"},
            ),
            routes=(
                {"domain": global_domains, "action": "route", "outbound": "to-foreign"},
                {"domain_suffix": global_suffixes, "action": "route", "outbound": "to-foreign"},
            ),
        ),
        _traffic_class(
            "ru_direct_domain", "direct-ru", "dns-ru-direct", "none", "direct_ru", "blocked",
            dns=(
                *(({"domain": direct_domains, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"},) if direct_domains else ()),
                *(({"domain_suffix": direct_suffixes, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"},) if direct_suffixes else ()),
                {"rule_set": ["ru-geosite"], "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"},
            ),
            pre_routes=(
                *(({"domain": direct_domains, "action": "resolve", "server": "dns-ru-direct", "strategy": "ipv4_only"},) if direct_domains else ()),
                *(({"domain_suffix": direct_suffixes, "action": "resolve", "server": "dns-ru-direct", "strategy": "ipv4_only"},) if direct_suffixes else ()),
                {"rule_set": ["ru-geosite"], "action": "resolve", "server": "dns-ru-direct", "strategy": "ipv4_only"},
            ),
            routes=(
                *(({"domain": direct_domains, "action": "route", "outbound": "direct-ru"},) if direct_domains else ()),
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
            pre_routes=({"domain_regex": ["^[^:]*[A-Za-z][^:]*$"], "action": "resolve", "server": "dns-global", "strategy": "ipv4_only"},),
            routes=({"domain_regex": ["^[^:]*[A-Za-z][^:]*$"], "action": "route", "outbound": "to-foreign"},),
        ),
        _traffic_class(
            "blocked", "reject", "none", "none", "blocked_private_fake", "none",
            guards=({"ip_cidr": blocked_cidrs, "action": "reject"},) if blocked_cidrs else (),
        ),
        _traffic_class(
            "private_or_fake", "reject", "none", "none", "blocked_private_fake", "none",
            guards=({"ip_is_private": True, "action": "reject"},),
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
    wireguard = {
        "type": "direct",
        "tag": TRANSPORT_WG_TAG,
        "bind_interface": env["WG_INTERFACE"],
        "routing_mark": int(env["APP_ROUTE_MARK"]),
        "domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"},
    }
    hysteria = {
        "type": "hysteria2",
        "tag": TRANSPORT_HY2_TAG,
        "server": env["FOREIGN_PUBLIC_IP"],
        "server_port": HY2_PORT,
        "obfs": {"type": "salamander", "password": derive_transport_obfs_password(env["WG_PRESHARED_KEY"])},
        "password": derive_transport_password(env["WG_PRESHARED_KEY"]),
        "tls": {
            "enabled": True,
            "server_name": HY2_SERVER_NAME,
            "certificate_public_key_sha256": [env["INTERSERVER_HY2_PUBLIC_KEY_SHA256"]],
        },
    }
    adaptive_foreign = {
        "type": "urltest",
        "tag": TRANSPORT_SELECTOR_TAG,
        "outbounds": list(TRANSPORT_CANDIDATE_TAGS),
        "url": TRANSPORT_HEALTHCHECK_URL,
        "interval": TRANSPORT_URLTEST_INTERVAL,
        "tolerance": TRANSPORT_URLTEST_TOLERANCE_MS,
        "idle_timeout": TRANSPORT_URLTEST_IDLE_TIMEOUT,
        "interrupt_exist_connections": False,
    }
    outbounds = (
        {"type": "direct", "tag": "direct-ru", "domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"}},
        wireguard,
        hysteria,
        adaptive_foreign,
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
