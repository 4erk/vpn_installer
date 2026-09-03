from __future__ import annotations

import contextlib
import io
import json
import socket
import struct
import threading
import unittest

from vpn_installer.vless_verify import parse_vless_uri, render_ephemeral_singbox_client, render_live_route_probe, render_vless_runner


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
        self.assertNotIn("packet_encoding", outbound)
        self.assertEqual(outbound["tls"]["reality"]["short_id"], "0123456789abcdef")
        self.assertEqual(payload["inbounds"][0]["listen_port"], 18080)
        self.assertEqual(payload["inbounds"][1]["listen_port"], 18081)
        self.assertEqual(payload["inbounds"][1]["network"], "udp")

    def test_rejects_unknown_or_duplicate_uri_parameters(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical contract"):
            parse_vless_uri(self.URI.replace("#demo", "&extra=1#demo"))
        with self.assertRaisesRegex(ValueError, "canonical contract"):
            parse_vless_uri(self.URI.replace("&type=tcp", "&type=tcp&type=tcp"))

    def test_udp_probe_is_stdlib_only_and_targets_the_ephemeral_proxy(self) -> None:
        probe = render_live_route_probe(listen_port=18080, dns_listen_port=18081)
        compile(probe, "udp-probe.py", "exec")
        self.assertIn("socket.create_connection", probe)
        self.assertIn("127.0.0.1", probe)
        self.assertIn("18081", probe)
        self.assertIn("10.0.0.1", probe)
        self.assertIn("172.19.0.2", probe)
        self.assertIn("private_reject", probe)
        self.assertIn("def socks_reply", probe)
        self.assertIn("HEAD / HTTP/1.0", probe)
        self.assertNotIn("requests", probe)

    @staticmethod
    def _dns_query(*, query_type: int = 1, transaction_id: int = 0x1122) -> bytes:
        question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in "example.com".split("."))
        return struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question + b"\x00" + struct.pack("!HH", query_type, 1)

    @staticmethod
    def _dns_response(
        *,
        flags: int = 0x8180,
        question_name: str = "example.com",
        include_answer: bool = True,
        query_type: int = 1,
        transaction_id: int = 0x1122,
    ) -> bytes:
        question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in question_name.split("."))
        question += b"\x00" + struct.pack("!HH", query_type, 1)
        answer_data = socket.inet_aton("93.184.216.34") if query_type == 1 else socket.inet_pton(socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", query_type, 1, 60, len(answer_data)) + answer_data
        return struct.pack("!HHHHHH", transaction_id, flags, 1, int(include_answer), 0, 0) + question + (answer if include_answer else b"")

    def _run_route_probe(
        self,
        dns_reply: bytes,
        *,
        private_statuses: tuple[int, ...] = (2, 2),
        expect_aaaa: bool = True,
        drop_first_dns: bool = False,
    ) -> dict[str, object]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(3)
        listener.settimeout(3)
        listen_port = listener.getsockname()[1]
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(3)
        udp_port = udp.getsockname()[1]
        errors: list[Exception] = []

        def receive_exact(connection: socket.socket, size: int) -> bytes:
            payload = b""
            while len(payload) < size:
                chunk = connection.recv(size - len(payload))
                if not chunk:
                    raise RuntimeError("unexpected test SOCKS EOF")
                payload += chunk
            return payload

        def receive_socks_request(connection: socket.socket) -> int:
            header = receive_exact(connection, 4)
            address_type = header[3]
            if address_type == 1:
                receive_exact(connection, 6)
            elif address_type == 4:
                receive_exact(connection, 18)
            elif address_type == 3:
                receive_exact(connection, receive_exact(connection, 1)[0] + 2)
            else:
                raise RuntimeError(f"unexpected address type: {address_type}")
            return header[1]

        def socks_reply(status: int, port: int) -> bytes:
            return b"\x05" + bytes([status]) + b"\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", port)

        def serve() -> None:
            try:
                dns_replies = [dns_reply]
                dns_requests = [self._dns_query()]
                if expect_aaaa:
                    dns_replies.append(self._dns_response(query_type=28, transaction_id=0x1123))
                    dns_requests.append(self._dns_query(query_type=28, transaction_id=0x1123))
                for index, (expected_request, reply) in enumerate(zip(dns_requests, dns_replies, strict=True)):
                    if drop_first_dns and index == 0:
                        dropped_packet, _peer = udp.recvfrom(4096)
                        if dropped_packet != expected_request:
                            raise RuntimeError("malformed retransmitted DNS request")
                    packet, peer = udp.recvfrom(4096)
                    if packet != expected_request:
                        raise RuntimeError("malformed DNS request")
                    udp.sendto(reply, peer)

                for status in private_statuses:
                    connection, _peer = listener.accept()
                    with connection:
                        connection.settimeout(3)
                        if receive_exact(connection, 3) != b"\x05\x01\x00":
                            raise RuntimeError("unexpected private SOCKS greeting")
                        connection.sendall(b"\x05\x00")
                        if receive_socks_request(connection) != 1:
                            raise RuntimeError("expected SOCKS connect")
                        connection.sendall(socks_reply(status, 80))
                        if status == 0 and receive_exact(connection, len(b"HEAD / HTTP/1.0\r\n\r\n")) != b"HEAD / HTTP/1.0\r\n\r\n":
                            raise RuntimeError("expected private probe request")
            except Exception as exc:  # noqa: BLE001 - surface server-thread failure in the test thread.
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        output = io.StringIO()
        probe_error: Exception | None = None
        try:
            with contextlib.redirect_stdout(output):
                exec(
                    compile(
                        render_live_route_probe(listen_port=listen_port, dns_listen_port=udp_port),
                        "route-probe.py",
                        "exec",
                    ),
                    {"__name__": "__main__"},
                )
        except Exception as exc:  # noqa: BLE001 - returned to the test after deterministic cleanup.
            probe_error = exc
        finally:
            listener.close()
            udp.close()
            thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        if probe_error is not None:
            raise probe_error
        return json.loads(output.getvalue())

    def test_route_probe_validates_dns_and_explicit_socks_reject(self) -> None:
        result = self._run_route_probe(self._dns_response(), private_statuses=(2, 2))
        self.assertTrue(result["ok"])
        self.assertEqual(result["dns"]["verdict"], "verified")
        self.assertEqual(result["dns"]["question"], {"name": "example.com", "type": 1, "class": 1})
        self.assertEqual(result["dns"]["matching_answers"], 1)
        self.assertEqual(result["dns"]["queries"]["AAAA"]["question"]["type"], 28)
        self.assertEqual(result["dns"]["queries"]["AAAA"]["matching_answers"], 1)
        self.assertTrue(result["private_reject"]["ok"])
        self.assertTrue(all(target["evidence"] == "socks-reply-reject" for target in result["private_reject"]["targets"]))

    def test_route_probe_retransmits_one_lost_dns_datagram(self) -> None:
        result = self._run_route_probe(self._dns_response(), drop_first_dns=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["dns"]["queries"]["AAAA"]["verdict"], "verified")

    def test_route_probe_does_not_treat_socks_success_then_eof_as_reject(self) -> None:
        result = self._run_route_probe(self._dns_response(), private_statuses=(0, 0))
        self.assertEqual(result["private_reject"]["verdict"], "inconclusive")
        self.assertFalse(result["private_reject"]["ok"])
        self.assertTrue(all(target["correlation_required"] for target in result["private_reject"]["targets"]))
        self.assertTrue(all(0 <= target["elapsed_seconds"] < 2 for target in result["private_reject"]["targets"]))

    def test_route_probe_rejects_invalid_dns_semantics(self) -> None:
        cases = {
            "QR": self._dns_response(flags=0x0180),
            "RCODE": self._dns_response(flags=0x8182),
            "question": self._dns_response(question_name="invalid.example"),
            "matching type 1 answer": self._dns_response(include_answer=False),
        }
        for expected_error, reply in cases.items():
            with self.subTest(expected_error=expected_error):
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    self._run_route_probe(reply, private_statuses=(), expect_aaaa=False)

    def test_runner_measures_sustained_goodput_and_transfer_gaps(self) -> None:
        runner = render_vless_runner(listen_port=18080)
        self.assertTrue(runner.startswith("#!/usr/bin/env bash\n"))
        self.assertNotIn("\r", runner)
        self.assertIn("throughput_deadline_ns", runner)
        self.assertIn("throughput_bytes", runner)
        self.assertIn("throughput-curl-exit", runner)
        self.assertIn("throughput_source_failures", runner)
        self.assertIn("capacity_bytes_per_second", runner)
        self.assertIn("sustained_bytes_per_second", runner)
        self.assertIn("max_gap_seconds", runner)
        self.assertIn("throughput_max_gap_ns", runner)
        self.assertIn("source_metrics", runner)
        self.assertIn("format_duration_ns()", runner)
        self.assertIn("attempt_budget_ns=$remaining_ns", runner)
        self.assertIn('attempt_seconds=$(format_duration_ns "$attempt_budget_ns")', runner)
        self.assertNotIn("phase_remaining_ns + 999999999", runner)
        self.assertIn("event private-reject", runner)
        self.assertIn("fail private-reject", runner)
        self.assertIn("https://ipv4-internet.yandex.net/api/v0/ip", runner)
        self.assertNotIn("https://api.ipify.org", runner)
        self.assertIn('cd "$work_dir"', runner)
        self.assertIn('sing_box_bin=$(command -v sing-box 2>/dev/null || true)', runner)
        self.assertIn("flock -n 9", runner)
        self.assertIn("controller-lease-expired", runner)
        self.assertIn("event first-load-reliability", runner)
        self.assertIn('reliability_attempts=0', runner)
        self.assertIn("%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{remote_ip}", runner)
        self.assertIn('probe["incomplete_phase"] = incomplete_phase(probe)', runner)
        self.assertIn('"error": error', runner)
        self.assertIn('"probes": reliability_probes', runner)
        self.assertIn('"required_targets": required_targets', runner)
        self.assertIn("https://vk.ru/", runner)
        self.assertIn("https://chatgpt.com/", runner)
        self.assertNotIn("https://github.com/favicon.ico", runner)
        self.assertIn('"$probe_code" =~ ^[1-5][0-9][0-9]$', runner)
        self.assertNotIn("200|204|301|302|403", runner)
        self.assertIn('"first_load_reliability": reliability', runner)
        self.assertIn("kill -KILL", runner)
        self.assertNotIn("phase=capacity", runner)
        self.assertNotIn("phase=stability", runner)
        self.assertNotIn("--limit-rate", runner)
        self.assertIn('"failures": failure_count', runner)
        self.assertIn("https://nbg1-speed.hetzner.com/100MB.bin", runner)
        self.assertIn("https://fsn1-speed.hetzner.com/100MB.bin", runner)
        self.assertIn("https://speed.cloudflare.com/__down?bytes=50000000", runner)
        self.assertNotIn("--range", runner)
        self.assertIn('"successful_sources": successful_sources', runner)
        self.assertIn('"required_successful_sources": min(2, len(sources))', runner)
        self.assertNotIn("speedtest.tele2.net", runner)
        self.assertIn("timeout --foreground --signal=TERM --kill-after=5s", runner)
        self.assertIn('stat -c %s -- "$throughput_payload_path"', runner)
        self.assertIn('kill "$curl_pid"', runner)
        self.assertIn('rm -f -- "$reliability_results_path" "$reliability_error_path" "$throughput_payload_path"', runner)
        self.assertNotIn("mktemp", runner)
        self.assertNotIn("--max-time \"$remaining_seconds\"", runner)

    def test_rejects_non_reality_uri(self) -> None:
        with self.assertRaises(ValueError):
            parse_vless_uri("vless://id@example.com:443?security=tls&type=tcp")


if __name__ == "__main__":
    unittest.main()
