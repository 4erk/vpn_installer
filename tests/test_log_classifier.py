from __future__ import annotations

import unittest

from vpn_installer.log_classifier import classify_line, summarize_lines


class LogClassifierTests(unittest.TestCase):
    def test_classifies_real_singbox_timeout_formats_into_exclusive_buckets(self) -> None:
        samples = {
            "domain_to_foreign_timeout": "open connection to github.com:443 using outbound/direct[to-foreign]: dial tcp: i/o timeout",
            "ipv4_literal_timeout": "open connection to 91.108.56.103:443 using outbound/direct[to-foreign-ip-literal]: dial tcp: i/o timeout",
            "ipv6_literal_timeout": "open connection to [2a00:1450:4001:82b::200e]:443 using outbound/direct[to-foreign-ip-literal]: dial tcp: i/o timeout",
            "dns_failed": "dns: lookup failed for example.com: context deadline exceeded",
            "dns_exchange_failed": "+0300 2026-07-08 12:51:50 ERROR [1484790583 28.98s] dns: exchange failed for ipv6.msftconnecttest.com. IN AAAA: context deadline exceeded",
            "client_front_connect_failed": "+0300 2026-07-08 18:43:36 ERROR [2412979623 5.0s] connection: open connection to 149.154.175.100:443 using outbound/vless[proxy]: dial tcp 94.232.248.35:443: i/o timeout",
            "blocked_private_fake": "open connection to 198.18.0.1:80 using outbound/block[blocked]",
            "client_reset_eof": "mux connection closed: EOF",
        }
        for bucket, line in samples.items():
            with self.subTest(bucket=bucket):
                classified = classify_line(line)
                self.assertIsNotNone(classified)
                self.assertEqual(classified.bucket, "dns_failed" if bucket == "dns_exchange_failed" else bucket)

    def test_client_front_connect_failed_keeps_public_endpoint(self) -> None:
        classified = classify_line(
            "+0300 2026-07-08 18:43:41 ERROR [3092694891 27.45s] connection: open connection to 8.8.4.4:443 using outbound/vless[proxy]: read tcp 192.168.0.101:6348->94.232.248.35:443: wsarecv: A connection attempt failed because the connected party did not properly respond after a period of time"
        )
        self.assertIsNotNone(classified)
        self.assertEqual(classified.bucket, "client_front_connect_failed")
        self.assertEqual(classified.destination, "94.232.248.35:443")

    def test_dns_exchange_failed_keeps_domain_and_query_type(self) -> None:
        classified = classify_line(
            "+0300 2026-07-08 12:52:11 ERROR [4186343754 30.0s] dns: exchange failed for www.msftconnecttest.com. IN A: context deadline exceeded"
        )
        self.assertIsNotNone(classified)
        self.assertEqual(classified.bucket, "dns_failed")
        self.assertEqual(classified.destination, "www.msftconnecttest.com:A")

    def test_classifies_xray_disabled_invalid_separately_from_invalid_reality(self) -> None:
        disabled = classify_line("from 203.0.113.4:456 accepted tcp:disabled.invalid:443")
        invalid = classify_line("REALITY: processed invalid connection from 203.0.113.5:1234")
        self.assertEqual(disabled.bucket, "disabled_invalid")
        self.assertEqual(invalid.bucket, "invalid_reality")

    def test_summary_counts_and_top_destinations(self) -> None:
        summary = summarize_lines(
            [
                "open connection to 91.108.56.103:443 using outbound/direct[to-foreign-ip-literal]: dial tcp: i/o timeout",
                "open connection to 91.108.56.103:443 using outbound/direct[to-foreign-ip-literal]: dial tcp: i/o timeout",
                "dns: exchange failed for ipv6.msftconnecttest.com. IN AAAA: context deadline exceeded",
                "connection: open connection to 149.154.175.100:443 using outbound/vless[proxy]: dial tcp 94.232.248.35:443: i/o timeout",
            ]
        )
        self.assertEqual(summary["counts"]["client_front_connect_failed"], 1)
        self.assertEqual(summary["counts"]["ipv4_literal_timeout"], 2)
        self.assertEqual(summary["counts"]["dns_failed"], 1)
        self.assertEqual(summary["top_destinations"]["client_front_connect_failed"]["94.232.248.35:443"], 1)
        self.assertEqual(summary["top_destinations"]["ipv4_literal_timeout"]["91.108.56.103:443"], 2)
        self.assertEqual(summary["top_destinations"]["dns_failed"]["ipv6.msftconnecttest.com:AAAA"], 1)


if __name__ == "__main__":
    unittest.main()
