from __future__ import annotations


HOST_DNS_SERVERS = ("1.1.1.1", "9.9.9.9", "8.8.8.8")
HOST_DNS_FALLBACK_SERVERS = ("1.0.0.1", "149.112.112.112", "8.8.4.4")
HOST_DNS_STALE_RETENTION = "1h"
RESOLVED_STUB_PATH = "/run/systemd/resolve/stub-resolv.conf"


def render_resolved_dropin() -> str:
    return "\n".join(
        [
            "[Resolve]",
            f"DNS={' '.join(HOST_DNS_SERVERS)}",
            f"FallbackDNS={' '.join(HOST_DNS_FALLBACK_SERVERS)}",
            "Domains=~.",
            "Cache=yes",
            f"StaleRetentionSec={HOST_DNS_STALE_RETENTION}",
            "DNSSEC=no",
            "DNSOverTLS=no",
            "LLMNR=no",
            "MulticastDNS=no",
            "",
        ]
    )
