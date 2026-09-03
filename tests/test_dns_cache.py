from __future__ import annotations

import unittest

from vpn_installer.dns_cache import (
    DNS_CACHE_ADDRESS,
    DNS_CACHE_CAPACITY,
    DNS_CACHE_PORT,
    DNS_CACHE_UPSTREAMS,
    render_dnsmasq_config,
    render_dnsmasq_service,
)


class DnsCacheTests(unittest.TestCase):
    def test_dnsmasq_config_is_private_cached_and_uses_all_upstreams(self) -> None:
        self.assertEqual(DNS_CACHE_ADDRESS, "127.0.0.1")
        self.assertEqual(DNS_CACHE_PORT, 1054)
        self.assertEqual(DNS_CACHE_CAPACITY, 4096)
        self.assertEqual(DNS_CACHE_UPSTREAMS, ("1.1.1.1", "9.9.9.9", "8.8.8.8"))
        self.assertEqual(
            render_dnsmasq_config(),
            "\n".join(
                [
                    "listen-address=127.0.0.1",
                    "port=1054",
                    "bind-interfaces",
                    "no-resolv",
                    "no-hosts",
                    "all-servers",
                    "cache-size=4096",
                    "neg-ttl=60",
                    "max-cache-ttl=3600",
                    "log-facility=-",
                    "server=1.1.1.1",
                    "server=9.9.9.9",
                    "server=8.8.8.8",
                    "",
                ]
            ),
        )

    def test_dnsmasq_service_is_managed_and_sandboxed(self) -> None:
        service = render_dnsmasq_service()

        self.assertIn("Before=sing-box.service", service)
        self.assertIn(
            "ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/vpn-stack/dnsmasq.conf",
            service,
        )
        self.assertIn("Restart=on-failure", service)
        self.assertIn("User=nobody", service)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", service)


if __name__ == "__main__":
    unittest.main()
