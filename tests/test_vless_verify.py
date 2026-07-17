from __future__ import annotations

import json
import unittest

from vpn_installer.vless_verify import parse_vless_uri, render_ephemeral_singbox_client, render_socks5_udp_dns_probe, render_vless_runner


class VlessVerifyTests(unittest.TestCase):
    URI = "vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&fp=chrome&type=tcp&flow=xtls-rprx-vision#demo"

    def test_parses_primary_reality_uri(self) -> None:
        uri = parse_vless_uri(self.URI)
        self.assertEqual(uri.host, "203.0.113.10")
        self.assertEqual(uri.port, 443)
        self.assertEqual(uri.flow, "xtls-rprx-vision")

    def test_rendered_ephemeral_client_keeps_reality_contract(self) -> None:
        payload = json.loads(render_ephemeral_singbox_client(parse_vless_uri(self.URI), listen_port=18080))
        outbound = payload["outbounds"][0]
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["packet_encoding"], "xudp")
        self.assertEqual(outbound["tls"]["reality"]["short_id"], "0123456789abcdef")
        self.assertEqual(payload["inbounds"][0]["listen_port"], 18080)

    def test_udp_probe_is_stdlib_only_and_targets_the_ephemeral_proxy(self) -> None:
        probe = render_socks5_udp_dns_probe(listen_port=18080)
        compile(probe, "udp-probe.py", "exec")
        self.assertIn("socket.create_connection", probe)
        self.assertIn("127.0.0.1", probe)
        self.assertIn("1.1.1.1", probe)
        self.assertNotIn("requests", probe)

    def test_runner_measures_fixed_time_with_bounded_acceptance_load(self) -> None:
        runner = render_vless_runner(listen_port=18080)
        self.assertTrue(runner.startswith("#!/usr/bin/env bash\n"))
        self.assertNotIn("\r", runner)
        self.assertIn("throughput_deadline_ns", runner)
        self.assertIn("throughput_bytes", runner)
        self.assertIn("throughput-curl-exit", runner)
        self.assertIn("kill -KILL", runner)
        self.assertIn("--limit-rate 1875000", runner)
        self.assertIn("timeout --foreground --signal=TERM --kill-after=5s", runner)
        self.assertIn("wc -c", runner)
        self.assertNotIn("--max-time \"$remaining_seconds\"", runner)

    def test_rejects_non_reality_uri(self) -> None:
        with self.assertRaises(ValueError):
            parse_vless_uri("vless://id@example.com:443?security=tls&type=tcp")


if __name__ == "__main__":
    unittest.main()
