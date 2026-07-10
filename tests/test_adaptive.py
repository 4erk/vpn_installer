from __future__ import annotations

import unittest

from vpn_installer.adaptive import (
    ROUTE_FAIL_CLASSES,
    format_route_fail_cache,
    render_route_fail_cache_printf_shell,
    render_route_fail_cache_read_shell,
    render_route_fail_collector_shell,
    route_fail_cache_fields,
    route_fail_cache_has_data,
)


class AdaptiveTests(unittest.TestCase):
    def test_route_fail_classes_cover_domain_and_literal_buckets(self) -> None:
        self.assertEqual([route_class.name for route_class in ROUTE_FAIL_CLASSES], ["domain_foreign", "ipv4_literal", "ipv6_literal"])
        self.assertEqual([route_class.cache_prefix for route_class in ROUTE_FAIL_CLASSES], ["DOMAIN_FOREIGN", "IPV4_LITERAL", "IPV6_LITERAL"])

    def test_route_fail_cache_formats_all_classes_from_one_model(self) -> None:
        preflight = {
            "route_fail_cache_ttl_seconds": "300",
            "route_fail_domain_foreign_count": "3",
            "route_fail_domain_foreign_top_dest": "[173.194.160.162]:443=3",
            "route_fail_domain_foreign_age_s": "15",
            "route_fail_ipv4_literal_count": "4",
            "route_fail_ipv4_literal_top_dest": "91.108.56.103:443=4",
            "route_fail_ipv4_literal_age_s": "20",
            "route_fail_ipv6_literal_count": "0",
            "route_fail_ipv6_literal_age_s": "-1",
        }
        self.assertTrue(route_fail_cache_has_data(preflight))
        self.assertEqual(route_fail_cache_fields(preflight)["route_fail_domain_foreign_count"], "3")
        self.assertEqual(
            format_route_fail_cache(preflight),
            "ttl=300s, domain_foreign=3@15s [173.194.160.162]:443=3, ipv4_literal=4@20s 91.108.56.103:443=4, ipv6_literal=0@-1s",
        )

    def test_route_fail_cache_empty_when_all_counts_are_zero(self) -> None:
        self.assertFalse(route_fail_cache_has_data({"route_fail_domain_foreign_count": "0", "route_fail_ipv4_literal_count": "0"}))

    def test_shell_fragments_are_generated_from_route_fail_classes(self) -> None:
        collector = render_route_fail_collector_shell()
        reads = render_route_fail_cache_read_shell()
        prints = render_route_fail_cache_printf_shell()
        self.assertIn("route_fail_journal_since()", collector)
        self.assertIn("/etc/vpn-stack/installed_at", collector)
        self.assertIn("post_install_epoch=$((installed_epoch + 10))", collector)
        self.assertIn('journalctl -u sing-box --since "${journal_since}"', collector)
        self.assertNotIn('--since "-${ROUTE_FAIL_CACHE_TTL_SECONDS} seconds"', collector)
        for route_class in ROUTE_FAIL_CLASSES:
            self.assertIn(f'mark_route_fail_bucket "{route_class.cache_prefix}"', collector)
            self.assertIn(f"{route_class.name}_timeout_recent", collector)
            self.assertIn(f"route_fail_{route_class.name}_count", reads)
            self.assertIn(
                f'route_fail_{route_class.name}_age_s="$(age_from_epoch "${{route_fail_{route_class.name}_last_epoch}}")"',
                reads,
            )
            self.assertIn(f"route_fail_{route_class.name}_count", prints)


if __name__ == "__main__":
    unittest.main()
