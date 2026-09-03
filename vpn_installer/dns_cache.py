from __future__ import annotations


DNS_CACHE_ADDRESS = "127.0.0.1"
DNS_CACHE_PORT = 1054
DNS_CACHE_CAPACITY = 4096
DNS_CACHE_UPSTREAMS = ("1.1.1.1", "9.9.9.9", "8.8.8.8")


def render_dnsmasq_config() -> str:
    lines = [
        f"listen-address={DNS_CACHE_ADDRESS}",
        f"port={DNS_CACHE_PORT}",
        "bind-interfaces",
        "no-resolv",
        "no-hosts",
        "all-servers",
        f"cache-size={DNS_CACHE_CAPACITY}",
        "neg-ttl=60",
        "max-cache-ttl=3600",
        "log-facility=-",
    ]
    lines.extend(f"server={address}" for address in DNS_CACHE_UPSTREAMS)
    return "\n".join((*lines, ""))


def render_dnsmasq_service() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=vpn-stack private DNS cache",
            "After=network-online.target",
            "Wants=network-online.target",
            "Before=sing-box.service",
            "",
            "[Service]",
            "Type=simple",
            "DynamicUser=true",
            "ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/vpn-stack/dnsmasq.conf",
            "Restart=on-failure",
            "RestartSec=2s",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectHome=true",
            "ProtectSystem=strict",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
