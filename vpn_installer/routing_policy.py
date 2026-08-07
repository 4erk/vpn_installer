from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import Any, Iterable

from .dns_policy import GLOBAL_FOREIGN_DOMAINS, GLOBAL_FOREIGN_DOMAIN_SUFFIXES, CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS
from .interserver_transport import TRANSPORT_OVERLAY_TAG

POLICY_VERSION = "0.18.0"

TRAFFIC_CLASSES = (
    "ru_direct_domain",
    "ru_direct_ip",
    "private_or_fake",
    "global_foreign",
    "dns_global",
    "domain_foreign",
    "ipv4_literal_foreign",
    "ipv6_literal_foreign",
    "blocked",
)

PRIVATE_OR_FAKE_DESTINATION_CIDRS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "2001:db8::/32",
)

_NO_TARGET = "none"
_NON_OUTBOUND_TARGETS = {_NO_TARGET, "reject"}
_SUPPORTED_TIMEOUT_POLICIES = {_NO_TARGET, "system"}
_SUPPORTED_FALLBACKS = {_NO_TARGET, "blocked"}


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

    def __post_init__(self) -> None:
        if self.timeout_policy not in _SUPPORTED_TIMEOUT_POLICIES:
            raise ValueError(f"routing class {self.name} has unsupported timeout policy {self.timeout_policy}")
        if self.fallback not in _SUPPORTED_FALLBACKS:
            raise ValueError(f"routing class {self.name} has unsupported fallback {self.fallback}")

    def metadata(self) -> dict[str, str]:
        return {
            "name": self.name,
            "outbound": self.outbound,
            "resolver": self.resolver,
            "timeout_policy": self.timeout_policy,
            "log_category": self.log_category,
            "fallback": self.fallback,
        }


def _bind_rule_target(
    rules: Iterable[dict[str, Any]],
    *,
    owner: str,
    action: str,
    target_key: str,
    target: str,
) -> tuple[dict[str, Any], ...]:
    compiled: list[dict[str, Any]] = []
    for source_rule in rules:
        rule = dict(source_rule)
        if rule.get("action") == action:
            if target in _NON_OUTBOUND_TARGETS:
                raise ValueError(f"routing class {owner} cannot compile {action} without {target_key}")
            configured_target = rule.setdefault(target_key, target)
            if configured_target != target:
                raise ValueError(f"routing class {owner} {target_key} conflicts with rule target {configured_target}")
        compiled.append(rule)
    return tuple(compiled)


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
                fallback_rules = guards if item.fallback == "blocked" else ()
                for pre_route, route in zip(item.pre_route_rules, item.route_rules):
                    compiled.extend((pre_route, *fallback_rules, route))
            elif item.route_rules:
                terminal_rules.extend(item.route_rules)
        return [*compiled, *guards, *terminal_rules]

    def validate_runtime_targets(self, *, dns_servers: Iterable[str], outbounds: Iterable[str]) -> None:
        dns_server_tags = set(dns_servers)
        outbound_tags = set(outbounds)
        missing_resolvers = {
            item.resolver
            for item in self.traffic
            if item.resolver != _NO_TARGET and item.resolver not in dns_server_tags
        }
        missing_outbounds = {
            item.outbound
            for item in self.traffic
            if item.outbound not in _NON_OUTBOUND_TARGETS and item.outbound not in outbound_tags
        }
        if self.final_outbound not in outbound_tags:
            missing_outbounds.add(self.final_outbound)
        if missing_resolvers:
            raise ValueError(f"routing policy references missing DNS servers: {', '.join(sorted(missing_resolvers))}")
        if missing_outbounds:
            raise ValueError(f"routing policy references missing outbounds: {', '.join(sorted(missing_outbounds))}")

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
        _bind_rule_target(dns, owner=name, action="route", target_key="server", target=resolver),
        _bind_rule_target(pre_routes, owner=name, action="resolve", target_key="server", target=resolver),
        _bind_rule_target(guards, owner=name, action="route", target_key="outbound", target=outbound),
        _bind_rule_target(routes, owner=name, action="route", target_key="outbound", target=outbound),
    )


def _reject_rule(**match: Any) -> dict[str, Any]:
    return {**match, "action": "reject", "method": "default", "no_drop": True}


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
    raw_ru_geoip_route = {"rule_set": ["ru-geoip"], "action": "route"}
    global_domains = list(dict.fromkeys((*GLOBAL_FOREIGN_DOMAINS, *CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS)))
    global_suffixes = list(GLOBAL_FOREIGN_DOMAIN_SUFFIXES)

    control_rules: list[dict[str, Any]] = [
        {"inbound": ["router-in"], "action": "sniff", "timeout": sniff_timeout},
        {"action": "route-options", "udp_disable_domain_unmapping": True},
        {
            "inbound": ["public-hy2-in"],
            "port": 53,
            "action": "route",
            "outbound": "to-foreign",
        },
    ]

    traffic = (
        _traffic_class(
            "global_foreign", "to-foreign", "dns-global", "system", "domain_to_foreign_timeout", "blocked",
            dns=(
                {"domain": global_domains, "action": "route", "strategy": "prefer_ipv4"},
                {"domain_suffix": global_suffixes, "action": "route", "strategy": "prefer_ipv4"},
            ),
            pre_routes=(
                {"domain": global_domains, "action": "resolve", "strategy": "prefer_ipv4"},
                {"domain_suffix": global_suffixes, "action": "resolve", "strategy": "prefer_ipv4"},
            ),
            routes=(
                {"domain": global_domains, "action": "route"},
                {"domain_suffix": global_suffixes, "action": "route"},
            ),
        ),
        _traffic_class(
            "ru_direct_domain", "direct-ru", "dns-ru-direct", "none", "direct_ru", "blocked",
            dns=(
                *(({"domain": direct_domains, "action": "route", "strategy": "ipv4_only"},) if direct_domains else ()),
                *(({"domain_suffix": direct_suffixes, "action": "route", "strategy": "ipv4_only"},) if direct_suffixes else ()),
                {"rule_set": ["ru-geosite"], "action": "route", "strategy": "ipv4_only"},
            ),
            pre_routes=(
                *(({"domain": direct_domains, "action": "resolve", "strategy": "ipv4_only"},) if direct_domains else ()),
                *(({"domain_suffix": direct_suffixes, "action": "resolve", "strategy": "ipv4_only"},) if direct_suffixes else ()),
                {"rule_set": ["ru-geosite"], "action": "resolve", "strategy": "ipv4_only"},
            ),
            routes=(
                *(({"domain": direct_domains, "action": "route"},) if direct_domains else ()),
                *(({"domain_suffix": direct_suffixes, "action": "route"},) if direct_suffixes else ()),
                {"rule_set": ["ru-geosite"], "action": "route"},
            ),
        ),
        _traffic_class(
            "dns_global", "to-foreign", "dns-global", "system", "dns_failed", "none",
            dns=(_reject_rule(ip_is_private=True, server="dns-global"),),
        ),
        _traffic_class(
            "domain_foreign", "to-foreign", "dns-global", "system", "domain_to_foreign_timeout", "blocked",
            pre_routes=({"domain_regex": ["^[^:]*[A-Za-z][^:]*$"], "action": "resolve", "strategy": "prefer_ipv4"},),
            routes=({"domain_regex": ["^[^:]*[A-Za-z][^:]*$"], "action": "route"},),
        ),
        _traffic_class(
            "blocked", "reject", "none", "none", "blocked_private_fake", "none",
            guards=(_reject_rule(ip_cidr=blocked_cidrs),) if blocked_cidrs else (),
        ),
        _traffic_class(
            "private_or_fake", "reject", "none", "none", "blocked_private_fake", "none",
            guards=(_reject_rule(ip_is_private=True),),
        ),
        _traffic_class(
            "ru_direct_ip", "direct-ru", "dns-ru-direct", "none", "direct_ru", "blocked",
            routes=(
                *(({"ip_cidr": direct_cidrs, "action": "route"},) if direct_cidrs else ()),
                raw_ru_geoip_route,
            ),
        ),
        _traffic_class(
            "ipv6_literal_foreign", "to-foreign", "none", "system", "ipv6_literal_timeout", "none",
            routes=({"ip_version": 6, "action": "route"},),
        ),
        _traffic_class(
            "ipv4_literal_foreign", "to-foreign", "none", "system", "ipv4_literal_timeout", "none",
            routes=({"ip_cidr": ["0.0.0.0/0"], "action": "route"},),
        ),
    )
    stable_overlay = {
        "type": "direct",
        "tag": TRANSPORT_OVERLAY_TAG,
        "bind_interface": env["WG_INTERFACE"],
        "routing_mark": int(env["APP_ROUTE_MARK"]),
        "domain_resolver": {"server": "dns-global", "strategy": "prefer_ipv4"},
    }
    outbounds = (
        {"type": "direct", "tag": "direct-ru", "domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"}},
        stable_overlay,
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
