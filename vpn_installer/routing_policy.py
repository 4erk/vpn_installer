from __future__ import annotations

import ipaddress
import textwrap
from dataclasses import dataclass, field
from typing import Any

from .dns_policy import CONNECTIVITY_CHECK_DIRECT_DOMAINS, CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS, merged_domains

POLICY_VERSION = "0.9.11"

TRAFFIC_CLASSES = (
    "ru_direct_domain",
    "ru_direct_ip",
    "client_dns_dot",
    "private_or_fake",
    "connectivity_check",
    "connectivity_check_ipv6_only",
    "dns_global",
    "domain_foreign",
    "ipv4_literal_foreign",
    "ipv6_literal_foreign",
    "blocked",
)

LITERAL_POLICIES = {"fail-fast", "route", "reject"}
IPV6_LITERAL_POLICIES = {"route-with-budget", "reject"}


def _env_list(env: dict[str, str], key: str) -> list[str]:
    raw_value = env.get(key, "")
    if not raw_value:
        return []
    values: list[str] = []
    for raw_item in textwrap.dedent(raw_value).replace("\n", ",").split(","):
        item = raw_item.strip()
        if item:
            values.append(item)
    return values


def _env_int(env: dict[str, str], key: str) -> int:
    return int(env[key])


def _enabled(raw_value: str) -> bool:
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _ip_network_or_raw(raw_value: str) -> str:
    try:
        return str(ipaddress.ip_network(raw_value, strict=False))
    except ValueError:
        return raw_value


def _normalize_literal_policy(raw_value: str) -> str:
    policy = (raw_value or "fail-fast").strip().lower()
    return policy if policy in LITERAL_POLICIES else "fail-fast"


def _normalize_ipv6_literal_policy(env: dict[str, str]) -> str:
    legacy = env.get("RU_IPV6_POLICY", "to-foreign").strip().lower()
    if legacy in {"block", "reject", "disabled", "off", "0", "false", "no"}:
        return "reject"
    policy = env.get("RU_IPV6_LITERAL_POLICY", "").strip().lower()
    if policy in IPV6_LITERAL_POLICIES:
        return policy
    return "reject"


def _client_dns_dot_networks(env: dict[str, str]) -> list[str]:
    networks: list[str] = []
    for key in ("CLIENT_TUN_ADDRESS_V4", "CLIENT_FAKEIP_V4"):
        raw_value = env.get(key, "").strip()
        if raw_value:
            networks.append(_ip_network_or_raw(raw_value))
    networks.append("fd00::/8")
    return networks


@dataclass(frozen=True)
class TrafficBudget:
    domain_foreign_connect_timeout: str = ""
    ipv4_literal_connect_timeout: str = "2s"
    ipv6_literal_connect_timeout: str = "2s"

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "TrafficBudget":
        return cls(
            domain_foreign_connect_timeout=env.get("TO_FOREIGN_CONNECT_TIMEOUT", "").strip(),
            ipv4_literal_connect_timeout=env.get("TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT", "2s").strip(),
            ipv6_literal_connect_timeout=env.get("TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT", "2s").strip(),
        )


@dataclass(frozen=True)
class RouteClass:
    name: str
    outbound: str
    resolver: str
    timeout_policy: str
    log_category: str
    fallback: str


@dataclass(frozen=True)
class RoutingPolicy:
    policy_version: str
    classes: dict[str, RouteClass]
    dns_rules: list[dict[str, Any]]
    route_rules: list[dict[str, Any]]
    outbounds: list[dict[str, Any]]
    final_outbound: str
    deprecated_overrides: list[str] = field(default_factory=list)

    def singbox_parts(self) -> dict[str, Any]:
        return {
            "dns_rules": self.dns_rules,
            "route_rules": self.route_rules,
            "outbounds": self.outbounds,
            "final_outbound": self.final_outbound,
            "policy_version": self.policy_version,
            "traffic_classes": {name: vars(route_class) for name, route_class in self.classes.items()},
            "deprecated_overrides": list(self.deprecated_overrides),
        }


def build_ru_routing_policy(env: dict[str, str]) -> RoutingPolicy:
    sniff_timeout = env.get("RU_SNIFF_TIMEOUT", "250ms").strip() or "250ms"
    literal_policy = _normalize_literal_policy(env.get("RU_LITERAL_POLICY", "fail-fast"))
    ipv6_literal_policy = _normalize_ipv6_literal_policy(env)
    budget = TrafficBudget.from_env(env)
    direct_domains = _env_list(env, "RU_FORCE_DIRECT_DOMAIN")
    direct_domain_suffixes = _env_list(env, "RU_FORCE_DIRECT_DOMAIN_SUFFIX")
    direct_ip_cidrs = _env_list(env, "RU_FORCE_DIRECT_IP_CIDR")
    client_dns_dot_networks = _client_dns_dot_networks(env)
    ru_public_ip = env.get("RU_PUBLIC_IP", "").strip()
    if ru_public_ip:
        ru_public_cidr = f"{ru_public_ip}/32"
        if ru_public_cidr not in direct_ip_cidrs:
            direct_ip_cidrs.append(ru_public_cidr)
    block_ip_cidrs = _env_list(env, "RU_BLOCK_IP_CIDR")
    block_quic = _enabled(env.get("RU_BLOCK_QUIC", "0"))
    geoip_direct = _enabled(env.get("RU_GEOIP_DIRECT", "0"))

    dns_rules: list[dict[str, Any]] = [{"query_type": ["AAAA"], "action": "reject"}]
    dns_rules.append({"domain": list(CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS), "action": "reject"})
    direct_dns_domains = merged_domains(CONNECTIVITY_CHECK_DIRECT_DOMAINS, direct_domains)
    if direct_dns_domains:
        dns_rules.append({"domain": direct_dns_domains, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})
    if direct_domain_suffixes:
        dns_rules.append({"domain_suffix": direct_domain_suffixes, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})
    dns_rules.append({"rule_set": ["ru-geosite"], "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})

    route_rules: list[dict[str, Any]] = [
        {"inbound": ["router-in"], "action": "sniff", "timeout": sniff_timeout},
        {"action": "route-options", "udp_disable_domain_unmapping": True},
        {"protocol": "dns", "action": "hijack-dns"},
    ]
    if block_quic:
        route_rules.append({"network": "udp", "port": 443, "action": "reject"})
    route_rules.append({"domain": list(CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS), "action": "reject"})
    if direct_dns_domains:
        route_rules.append({"domain": direct_dns_domains, "action": "resolve", "server": "dns-ru-direct", "strategy": "ipv4_only"})
        route_rules.append({"domain": direct_dns_domains, "action": "route", "outbound": "direct-ru"})
    if direct_domain_suffixes:
        route_rules.append({"domain_suffix": direct_domain_suffixes, "action": "resolve", "server": "dns-ru-direct", "strategy": "ipv4_only"})
        route_rules.append({"domain_suffix": direct_domain_suffixes, "action": "route", "outbound": "direct-ru"})
    route_rules.append({"rule_set": ["ru-geosite"], "action": "resolve", "server": "dns-ru-direct", "strategy": "ipv4_only"})
    route_rules.append({"rule_set": ["ru-geosite"], "action": "route", "outbound": "direct-ru"})
    if direct_ip_cidrs:
        route_rules.append({"ip_cidr": direct_ip_cidrs, "action": "route", "outbound": "direct-ru"})
    if block_ip_cidrs:
        route_rules.append({"ip_cidr": block_ip_cidrs, "action": "route", "outbound": "blocked"})
    route_rules.append(
        {
            "ip_cidr": client_dns_dot_networks,
            "port": 853,
            "action": "route",
            "outbound": "direct-ru",
            "override_address": env["GLOBAL_DOH_SERVER"],
            "override_port": 853,
        }
    )
    route_rules.append({"ip_is_private": True, "action": "route", "outbound": "blocked"})
    if ipv6_literal_policy == "reject":
        route_rules.append({"ip_version": 6, "action": "reject"})
    else:
        route_rules.append({"ip_version": 6, "port": 443, "action": "route", "outbound": "to-foreign-ipv6-literal"})
        route_rules.append({"ip_version": 6, "action": "reject"})
    if geoip_direct:
        route_rules.append({"rule_set": ["ru-geoip"], "action": "route", "outbound": "direct-ru"})
    if literal_policy == "reject":
        route_rules.append({"ip_cidr": ["0.0.0.0/0"], "action": "reject"})
    elif literal_policy == "route":
        route_rules.append({"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"})
    else:
        route_rules.append({"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign-ip-literal"})
    route_rules.append({"action": "resolve", "server": "dns-global", "strategy": "ipv4_only"})
    route_rules.append({"ip_is_private": True, "action": "route", "outbound": "blocked"})
    if geoip_direct:
        route_rules.append({"rule_set": ["ru-geoip"], "action": "route", "outbound": "direct-ru"})

    foreign_base = {
        "type": "direct",
        "bind_interface": env["WG_INTERFACE"],
        "routing_mark": _env_int(env, "APP_ROUTE_MARK"),
        "domain_resolver": {"server": "dns-global", "strategy": "ipv4_only"},
    }
    to_foreign = dict(foreign_base, tag="to-foreign")
    if budget.domain_foreign_connect_timeout:
        to_foreign["connect_timeout"] = budget.domain_foreign_connect_timeout
    to_foreign_ip_literal = dict(foreign_base, tag="to-foreign-ip-literal")
    if budget.ipv4_literal_connect_timeout:
        to_foreign_ip_literal["connect_timeout"] = budget.ipv4_literal_connect_timeout
    to_foreign_ipv6_literal = dict(foreign_base, tag="to-foreign-ipv6-literal")
    if budget.ipv6_literal_connect_timeout:
        to_foreign_ipv6_literal["connect_timeout"] = budget.ipv6_literal_connect_timeout

    outbounds = [
        {"type": "direct", "tag": "direct-ru", "domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"}},
        to_foreign,
        to_foreign_ip_literal,
        to_foreign_ipv6_literal,
        {"type": "block", "tag": "blocked"},
    ]
    classes = {
        "ru_direct_domain": RouteClass("ru_direct_domain", "direct-ru", "dns-ru-direct", "none", "direct_ru", "blocked"),
        "ru_direct_ip": RouteClass("ru_direct_ip", "direct-ru", "dns-ru-direct", "none", "direct_ru", "blocked"),
        "client_dns_dot": RouteClass("client_dns_dot", "direct-ru", "none", "fixed_budget", "client_dns_dot", "blocked"),
        "private_or_fake": RouteClass("private_or_fake", "blocked", "none", "none", "blocked_private_fake", "none"),
        "connectivity_check": RouteClass("connectivity_check", "direct-ru", "dns-ru-direct", "none", "direct_ru", "dns-global"),
        "connectivity_check_ipv6_only": RouteClass("connectivity_check_ipv6_only", "blocked", "none", "none", "blocked_private_fake", "none"),
        "dns_global": RouteClass("dns_global", "to-foreign", "dns-global", "domain_foreign", "dns_failed", "dns-ru-direct"),
        "domain_foreign": RouteClass("domain_foreign", "to-foreign", "dns-global", "operator_override", "domain_to_foreign_timeout", "none"),
        "ipv4_literal_foreign": RouteClass("ipv4_literal_foreign", "to-foreign-ip-literal", "dns-global", literal_policy, "ipv4_literal_timeout", "reject"),
        "ipv6_literal_foreign": RouteClass("ipv6_literal_foreign", "to-foreign-ipv6-literal", "dns-global", ipv6_literal_policy, "ipv6_literal_timeout", "reject"),
        "blocked": RouteClass("blocked", "blocked", "none", "none", "blocked_private_fake", "none"),
    }
    deprecated_overrides = [
        key
        for key, default_value in (
            ("TO_FOREIGN_CONNECT_TIMEOUT", ""),
            ("TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT", "2s"),
            ("TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT", "2s"),
            ("RU_IPV6_POLICY", "to-foreign"),
        )
        if key in env and env.get(key, "").strip() != default_value
    ]
    return RoutingPolicy(
        policy_version=POLICY_VERSION,
        classes=classes,
        dns_rules=dns_rules,
        route_rules=route_rules,
        outbounds=outbounds,
        final_outbound="to-foreign",
        deprecated_overrides=deprecated_overrides,
    )
