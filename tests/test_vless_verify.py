from __future__ import annotations

import contextlib
import io
import json
import socket
import struct
import threading
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
        self.assertIn("10.0.0.1", probe)
        self.assertIn("172.19.0.2", probe)
        self.assertIn("private_reject", probe)
        self.assertIn("def socks_reply", probe)
        self.assertIn("HEAD / HTTP/1.0", probe)
        self.assertNotIn("requests", probe)

    def test_route_probe_accepts_immediate_eof_after_a_complete_socks_reply(self) -> None:
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

        def success_reply(port: int) -> bytes:
            return b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", port)

        def serve() -> None:
            try:
                connection, _peer = listener.accept()
                with connection:
                    connection.settimeout(3)
                    if receive_exact(connection, 3) != b"\x05\x01\x00":
                        raise RuntimeError("unexpected SOCKS greeting")
                    connection.sendall(b"\x05\x00")
                    if receive_socks_request(connection) != 3:
                        raise RuntimeError("expected UDP associate")
                    connection.sendall(success_reply(udp_port))

                _packet, peer = udp.recvfrom(4096)
                dns_reply = b"\x11\x22\x81\x80" + b"\x00" * 12
                udp.sendto(b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + dns_reply, peer)

                for _target in range(2):
                    connection, _peer = listener.accept()
                    with connection:
                        connection.settimeout(3)
                        if receive_exact(connection, 3) != b"\x05\x01\x00":
                            raise RuntimeError("unexpected private SOCKS greeting")
                        connection.sendall(b"\x05\x00")
                        if receive_socks_request(connection) != 1:
                            raise RuntimeError("expected SOCKS connect")
                        connection.sendall(success_reply(80))
                        if receive_exact(connection, len(b"HEAD / HTTP/1.0\r\n\r\n")) != b"HEAD / HTTP/1.0\r\n\r\n":
                            raise RuntimeError("expected private probe request")
            except Exception as exc:  # noqa: BLE001 - surface server-thread failure in the test thread.
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                exec(compile(render_socks5_udp_dns_probe(listen_port=listen_port), "route-probe.py", "exec"), {"__name__": "__main__"})
        finally:
            listener.close()
            udp.close()
            thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        result = json.loads(output.getvalue())
        self.assertTrue(result["ok"])
        self.assertTrue(result["private_reject"]["ok"])
        self.assertTrue(all(target["ok"] for target in result["private_reject"]["targets"]))

    def test_runner_measures_uncapped_capacity_for_explicit_throughput_run(self) -> None:
        runner = render_vless_runner(listen_port=18080)
        self.assertTrue(runner.startswith("#!/usr/bin/env bash\n"))
        self.assertNotIn("\r", runner)
        self.assertIn("throughput_deadline_ns", runner)
        self.assertIn("throughput_bytes", runner)
        self.assertIn("throughput-curl-exit", runner)
        self.assertIn("event private-reject", runner)
        self.assertIn("fail private-reject", runner)
        self.assertIn("kill -KILL", runner)
        self.assertNotIn("--limit-rate", runner)
        self.assertIn("timeout --foreground --signal=TERM --kill-after=5s", runner)
        self.assertIn("wc -c", runner)
        self.assertNotIn("--max-time \"$remaining_seconds\"", runner)

    def test_rejects_non_reality_uri(self) -> None:
        with self.assertRaises(ValueError):
            parse_vless_uri("vless://id@example.com:443?security=tls&type=tcp")


if __name__ == "__main__":
    unittest.main()
