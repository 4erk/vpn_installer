from __future__ import annotations

import unittest

from vpn_installer.system_resolver import HOST_DNS_FALLBACK_SERVERS, HOST_DNS_SERVERS, render_resolved_dropin


class SystemResolverTests(unittest.TestCase):
    def test_policy_uses_independent_cached_upstreams(self) -> None:
        config = render_resolved_dropin()
        self.assertEqual(len(HOST_DNS_SERVERS), 3)
        self.assertEqual(len(HOST_DNS_FALLBACK_SERVERS), 3)
        self.assertEqual(len(set(HOST_DNS_SERVERS + HOST_DNS_FALLBACK_SERVERS)), 6)
        self.assertIn(f"DNS={' '.join(HOST_DNS_SERVERS)}", config)
        self.assertIn("Domains=~.", config)
        self.assertIn("Cache=yes", config)
        self.assertIn("StaleRetentionSec=1h", config)
        self.assertIn("DNSSEC=no", config)


if __name__ == "__main__":
    unittest.main()
