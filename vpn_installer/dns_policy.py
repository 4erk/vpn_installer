from __future__ import annotations

CONNECTIVITY_CHECK_DIRECT_DOMAINS = (
    "www.msftconnecttest.com",
    "www.msftncsi.com",
)

CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS = (
    "ipv6.msftconnecttest.com",
    "ipv6.msftncsi.com",
)

CONNECTIVITY_CHECK_DOMAINS = CONNECTIVITY_CHECK_DIRECT_DOMAINS + CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS


def merged_domains(*groups: list[str] | tuple[str, ...]) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for domain in group:
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
    return domains
