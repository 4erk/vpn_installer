from __future__ import annotations

GLOBAL_FOREIGN_DOMAINS = (
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    "mtalk.google.com",
)

GLOBAL_FOREIGN_DOMAIN_SUFFIXES = (
    ".gstatic.com",
)

CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS = (
    "ipv6.msftconnecttest.com",
    "ipv6.msftncsi.com",
    "ipv6-internet.yandex.net",
)

CONNECTIVITY_CHECK_DOMAINS = GLOBAL_FOREIGN_DOMAINS[:2] + CONNECTIVITY_CHECK_IPV6_ONLY_DOMAINS
