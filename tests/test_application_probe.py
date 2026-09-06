from __future__ import annotations

import io
import json
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime
from unittest.mock import Mock, patch

from vpn_installer import application_probe as probe


# Telegram's published resPQ sample, independent of the production serializer.
SAMPLE = bytes.fromhex(
    "000000000000000001f4ccc26170466a5000000063241605"
    "51a1143fc7a3666be4be54d6890a02dc63248f6748214eab8a2f4cc876e11974"
    "082e9cdb98c80cda4b00000015c4b51c03000000"
    "85fd64de851d9dd0a5b7f709355fc30b216be86c022bb4c3"
)


def response(nonce: bytes) -> bytes:
    return SAMPLE[:24] + nonce + SAMPLE[40:]


def wire(frame: bytes) -> bytes:
    return struct.pack("<I", len(frame)) + frame


def receive(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError("probe closed before sending expected bytes")
        data.extend(chunk)
    return bytes(data)


@contextmanager
def loopback(handler, *, family=socket.AF_INET):
    failures = []
    stop = threading.Event()
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        listener.listen(1)
        listener.settimeout(2)

        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(2)
                    handler(connection, stop)
            except BaseException as exc:
                failures.append(exc)

        worker = threading.Thread(target=serve, name="mtproto-loopback", daemon=True)
        worker.start()
        address, port = listener.getsockname()[:2]
        try:
            yield f"{address}:{port}" if family == socket.AF_INET else f"[{address}]:{port}"
        finally:
            stop.set()
            worker.join(3)
            if worker.is_alive():
                raise AssertionError("loopback worker did not stop")
            if failures:
                raise failures[0]


class ApplicationProbeTests(unittest.TestCase):
    def read_request(self, connection):
        request = receive(connection, 48)
        self.assertEqual(request[:4], b"\xee" * 4)
        self.assertEqual(struct.unpack_from("<I", request, 4)[0], 40)
        auth_key, message_id, length, constructor = struct.unpack_from("<QQII", request, 8)
        self.assertEqual((auth_key, message_id % 4, length, constructor), (0, 0, 20, 0xBE7E8EF1))
        return request[32:48]

    def successful_server(self, connection, stop):
        nonce = self.read_request(connection)
        connection.sendall(wire(response(nonce)))
        self.assertEqual(connection.recv(1), b"", "probe must not proceed to key generation")

    def test_real_ipv4_response_and_no_dns_or_followup_key_exchange(self):
        with loopback(self.successful_server) as endpoint:
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                result = probe.probe_telegram(endpoint)
        self.assertTrue(result["tcp_connected"])
        self.assertIsNone(result["proxy_accepted"])
        self.assertTrue(result["protocol_response"])
        self.assertEqual(result["phase"], "mtproto")
        self.assertEqual(result["path"]["kind"], "direct")
        self.assertIsNone(result["error"])
        self.assertEqual(result["res_pq"]["pq"], "2e9cdb98c80cda4b")
        self.assertEqual(result["res_pq"]["fingerprints"], [
            "d09d1d85de64fd85", "0bc35f3509f7b7a5", "c3b42b026ce86b21",
        ])
        self.assertGreaterEqual(result["elapsed"], 0)
        self.assertLess(result["elapsed"], probe.PROBE_TIMEOUT)

    def test_real_ipv6_response(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 sockets unavailable")
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        with loopback(self.successful_server, family=socket.AF_INET6) as endpoint:
            result = probe.probe_telegram(endpoint)
        self.assertTrue(result["protocol_response"], result)
        self.assertEqual(result["address"], "::1")

    def test_each_exchange_uses_a_fresh_nonce(self):
        nonces = []

        def serve(connection, stop):
            nonce = self.read_request(connection)
            nonces.append(nonce)
            connection.sendall(wire(response(nonce)))

        for _ in range(2):
            with loopback(serve) as endpoint:
                self.assertTrue(probe.probe_telegram(endpoint)["protocol_response"])
        self.assertNotEqual(*nonces)

    def test_real_wrong_nonce_truncation_and_malformed_responses(self):
        def replace(frame, offset, value):
            return frame[:offset] + value + frame[offset + len(value):]

        cases = {
            "nonce": lambda frame: wire(replace(frame, 24, bytes(byte ^ 255 for byte in frame[24:40]))),
            "auth_key": lambda frame: wire(replace(frame, 0, struct.pack("<Q", 1))),
            "message_id": lambda frame: wire(replace(frame, 8, struct.pack("<Q", 4))),
            "message_length": lambda frame: wire(replace(frame, 16, struct.pack("<I", 4))),
            "constructor": lambda frame: wire(replace(frame, 20, b"\0" * 4)),
            "pq_zero_length": lambda frame: wire(replace(frame, 56, b"\0")),
            "pq_invalid_prefix": lambda frame: wire(replace(frame, 56, b"\xff")),
            "pq_noncanonical_length": lambda frame: wire(replace(frame, 56, b"\xfe\x01\0\0")),
            "pq_out_of_bounds": lambda frame: wire(replace(frame, 56, b"\xfe\xff\xff\xff")),
            "pq_even": lambda frame: wire(replace(frame, 64, b"\x02")),
            "pq_padding": lambda frame: wire(replace(frame, 65, b"\x01")),
            "vector_constructor": lambda frame: wire(replace(frame, 68, b"\0" * 4)),
            "vector_negative": lambda frame: wire(replace(frame, 72, struct.pack("<i", -1))),
            "vector_empty": lambda frame: wire(replace(frame, 72, b"\0" * 4)),
            "vector_overflow": lambda frame: wire(replace(frame, 72, struct.pack("<i", 0x7FFFFFFF))),
            "vector_trailing": lambda frame: wire(replace(frame, 72, struct.pack("<i", 2))),
            "truncated": lambda frame: wire(frame)[:-1],
            "transport_error": lambda frame: wire(struct.pack("<i", -429)),
            "short_frame": lambda frame: wire(b"\0" * 8),
        }
        for name, malformed in cases.items():
            with self.subTest(name=name):
                def serve(connection, stop):
                    frame = response(self.read_request(connection))
                    connection.sendall(malformed(frame))

                with loopback(serve) as endpoint:
                    result = probe.probe_telegram(endpoint)
                self.assertTrue(result["tcp_connected"])
                self.assertFalse(result["protocol_response"])
                self.assertNotIn("res_pq", result)
                self.assertEqual(result["phase"], "mtproto")
                self.assertTrue(result["error"])

    def test_invalid_frame_header_is_rejected_before_receiving_body(self):
        for size in (0, 3, 4097, 0xFFFFFFFF, 0x80000000):
            with self.subTest(size=size):
                def serve(connection, stop):
                    self.read_request(connection)
                    connection.sendall(struct.pack("<I", size))
                    self.assertEqual(connection.recv(1), b"")

                with loopback(serve) as endpoint:
                    result = probe.probe_telegram(endpoint)
                self.assertFalse(result["protocol_response"])
                self.assertIn("frame length", result["error"])

    def test_tl_long_pq_and_maximum_frame_are_bounded(self):
        # Maximum aligned frame: 20-byte envelope, 36-byte fixed fields,
        # four-byte TL length, 4020-byte pq, eight-byte vector header + one long.
        pq = b"\x01" * 4020
        body = SAMPLE[20:56] + b"\xfe" + len(pq).to_bytes(3, "little") + pq
        body += struct.pack("<IiQ", 0x1CB5C415, 1, 7)
        frame = SAMPLE[:16] + struct.pack("<I", len(body)) + body
        self.assertEqual(len(frame), 4096)
        self.assertEqual(probe._parse_res_pq(frame, SAMPLE[24:40])["fingerprints"], ["0000000000000007"])
        with self.assertRaisesRegex(ValueError, "frame length"):
            probe._parse_res_pq(frame + b"\0" * 4, SAMPLE[24:40])

    def test_slow_trickle_does_not_restart_total_budget(self):
        sent = []

        def serve(connection, stop):
            reply = wire(response(self.read_request(connection)))
            for byte in reply:
                try:
                    connection.sendall(bytes([byte]))
                except OSError:
                    break
                sent.append(byte)
                if stop.wait(0.025):
                    break

        with loopback(serve) as endpoint, patch.object(probe, "PROBE_TIMEOUT", 0.18):
            started = time.monotonic()
            result = probe.probe_telegram(endpoint)
            elapsed = time.monotonic() - started
        self.assertGreater(len(sent), 2)
        self.assertLess(elapsed, 0.7)
        self.assertFalse(result["protocol_response"])
        self.assertEqual(result["phase"], "mtproto")
        self.assertTrue(result["error"])

    def socks_handshake(self, connection, destination, *, reply=None):
        self.assertEqual(receive(connection, 3), b"\x05\x01\x00")
        connection.sendall(b"\x05\x00")
        version, command, reserved, atyp = receive(connection, 4)
        self.assertEqual((version, command, reserved), (5, 1, 0))
        self.assertIn(atyp, (1, 4), "SOCKS must never use remote DNS")
        address = socket.inet_ntop(socket.AF_INET if atyp == 1 else socket.AF_INET6,
                                  receive(connection, 4 if atyp == 1 else 16))
        port = struct.unpack("!H", receive(connection, 2))[0]
        self.assertEqual((address, port), probe.parse_endpoint(destination))
        connection.sendall(reply or b"\x05\x00\x00\x01\x7f\0\0\x01\0\0")

    def test_socks_numeric_ipv4_and_ipv6_destinations_with_actual_response(self):
        replies = (
            ("192.0.2.1:443", None),
            ("[2001:db8::1]:80", b"\x05\x00\x00\x04" + b"\0" * 16 + b"\0\0"),
            ("192.0.2.1:443", b"\x05\x00\x00\x03\x0bnot.invalid\0\0"),
        )
        for destination, reply in replies:
            with self.subTest(destination=destination):
                def serve(connection, stop):
                    self.socks_handshake(connection, destination, reply=reply)
                    self.successful_server(connection, stop)

                with loopback(serve) as endpoint:
                    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                        result = probe.probe_telegram(destination, proxy=endpoint)
                self.assertTrue(result["tcp_connected"])
                self.assertTrue(result["proxy_accepted"])
                self.assertTrue(result["protocol_response"])
                self.assertEqual(result["path"], {"kind": "socks5", "proxy": endpoint, "interface": None})

    def test_socks_auth_negotiation_failure_does_not_send_request_or_credentials(self):
        for greeting in (b"\x05\x02", b"\x05\xff", b"\x04\x00"):
            with self.subTest(greeting=greeting):
                def serve(connection, stop):
                    self.assertEqual(receive(connection, 3), b"\x05\x01\x00")
                    connection.sendall(greeting)
                    self.assertEqual(connection.recv(1), b"")

                with loopback(serve) as endpoint:
                    result = probe.probe_telegram("192.0.2.1:443", proxy=endpoint)
                self.assertFalse(result["proxy_accepted"])
                self.assertFalse(result["protocol_response"])
                self.assertEqual(result["phase"], "proxy")
                self.assertIn("unauthenticated", result["error"])

    def test_optimistic_socks_ack_is_not_protocol_success(self):
        def serve(connection, stop):
            self.socks_handshake(connection, "192.0.2.1:443")
            self.read_request(connection)
            self.assertEqual(connection.recv(1), b"")

        with loopback(serve) as endpoint, patch.object(probe, "PROBE_TIMEOUT", 0.15):
            result = probe.probe_telegram("192.0.2.1:443", proxy=endpoint)
        self.assertTrue(result["tcp_connected"])
        self.assertTrue(result["proxy_accepted"])
        self.assertFalse(result["protocol_response"])
        self.assertEqual(result["phase"], "mtproto")
        self.assertTrue(result["error"])
        self.assertLess(result["elapsed"], 0.7)

    def test_socks_setup_and_mtproto_share_one_budget(self):
        def serve(connection, stop):
            self.assertEqual(receive(connection, 3), b"\x05\x01\x00")
            stop.wait(0.10)
            connection.sendall(b"\x05\x00")
            self.assertEqual(receive(connection, 10)[:4], b"\x05\x01\x00\x01")
            connection.sendall(b"\x05\x00\x00\x01\x7f\0\0\x01\0\0")
            self.read_request(connection)
            self.assertEqual(connection.recv(1), b"")

        with loopback(serve) as endpoint, patch.object(probe, "PROBE_TIMEOUT", 0.22):
            result = probe.probe_telegram("192.0.2.1:443", proxy=endpoint)
        self.assertTrue(result["proxy_accepted"])
        self.assertFalse(result["protocol_response"])
        self.assertLess(result["elapsed"], 0.30)

    def test_socks_refused_malformed_and_truncated_ack_are_not_accepted(self):
        for reply in (b"\x05\x05\x00\x01", b"\x04\x00\x00\x01",
                      b"\x05\x00\x01\x01", b"\x05\x00\x00\x09",
                      b"\x05\x00\x00\x03\x00", b"\x05\x00\x00\x01\x7f"):
            with self.subTest(reply=reply):
                def serve(connection, stop):
                    self.socks_handshake(connection, "192.0.2.1:443", reply=reply)

                with loopback(serve) as endpoint:
                    result = probe.probe_telegram("192.0.2.1:443", proxy=endpoint)
                self.assertTrue(result["tcp_connected"])
                self.assertFalse(result["proxy_accepted"])
                self.assertFalse(result["protocol_response"])
                self.assertEqual(result["phase"], "proxy")

    def test_stalled_socks_greeting_has_same_total_budget(self):
        def serve(connection, stop):
            self.assertEqual(receive(connection, 3), b"\x05\x01\x00")
            self.assertEqual(connection.recv(1), b"")

        with loopback(serve) as endpoint, patch.object(probe, "PROBE_TIMEOUT", 0.15):
            result = probe.probe_telegram("192.0.2.1:443", proxy=endpoint)
        self.assertTrue(result["tcp_connected"])
        self.assertFalse(result["proxy_accepted"])
        self.assertEqual(result["phase"], "proxy")
        self.assertLess(result["elapsed"], 0.7)

    def test_endpoint_validation_and_no_default_incident_addresses(self):
        for value, expected in (("192.0.2.1", ("192.0.2.1", 443)),
                                ("[2001:db8::1]:80", ("2001:db8::1", 80)),
                                ("2001:db8::1", ("2001:db8::1", 443))):
            self.assertEqual(probe.parse_endpoint(value), expected)
        for value in ("", "telegram.org", "localhost:443", "1.1.1.1:0", "1.1.1.1:65536",
                      "[::1]suffix", "[::1", "[::1]:", "::1%lo", "1.2.3.999"):
            with self.subTest(value=value), patch.object(socket, "socket") as create:
                with self.assertRaises(ValueError):
                    probe.probe_telegram(value)
                create.assert_not_called()
        for kwargs in ({"proxy": "localhost:1080"}, {"proxy": "192.0.2.2:1080"},
                       {"proxy": "127.0.0.1"}, {"proxy": "127.0.0.1:1080", "interface": "lo"},
                       {"interface": ""}, {"interface": "bad\0name"}):
            with self.subTest(kwargs=kwargs), patch.object(socket, "socket") as create:
                with self.assertRaises(ValueError):
                    probe.probe_telegram("192.0.2.1", **kwargs)
                create.assert_not_called()

    def test_interface_binding_is_socket_only_and_fails_closed(self):
        connection = Mock()
        connection.setsockopt.side_effect = OSError("permission denied")
        context = Mock()
        context.__enter__ = Mock(return_value=connection)
        context.__exit__ = Mock(return_value=False)
        with patch.object(socket, "SO_BINDTODEVICE", 25, create=True):
            with patch.object(socket, "socket", return_value=context):
                result = probe.probe_telegram("192.0.2.1", interface="wg0")
        connection.setsockopt.assert_called_once_with(socket.SOL_SOCKET, 25, b"wg0\0")
        connection.connect.assert_not_called()
        context.__exit__.assert_called_once()
        self.assertFalse(result["tcp_connected"])
        self.assertEqual(result["path"]["kind"], "interface")
        self.assertIn("permission denied", result["error"])

    def test_tcp_connect_consumes_budget_and_socket_closes_on_expiry(self):
        connection = Mock()
        now = [0.0]
        connection.connect.side_effect = lambda address: now.__setitem__(0, 8.01)
        context = Mock()
        context.__enter__ = Mock(return_value=connection)
        context.__exit__ = Mock(return_value=False)
        with patch.object(socket, "socket", return_value=context):
            with patch.object(probe.time, "monotonic", side_effect=lambda: now[0]):
                result = probe.probe_telegram("192.0.2.1")
        connection.settimeout.assert_called_once_with(8.0)
        connection.sendall.assert_not_called()
        context.__exit__.assert_called_once()
        self.assertFalse(result["protocol_response"])
        self.assertEqual(result["phase"], "tcp")
        self.assertIn("budget", result["error"])

    def test_completed_io_after_deadline_is_not_accepted(self):
        for operation, argument in ((probe._send, b"test"), (probe._receive, 4)):
            with self.subTest(operation=operation.__name__):
                connection = Mock()
                connection.recv.return_value = b"test"
                with patch.object(probe.time, "monotonic", side_effect=[0.25, 1.01]):
                    with self.assertRaisesRegex(TimeoutError, "budget"):
                        operation(connection, argument, 1.0)
                connection.settimeout.assert_called_once_with(0.75)

    def test_io_after_expired_deadline_does_not_touch_socket(self):
        for operation, argument in ((probe._send, b"test"), (probe._receive, 4)):
            with self.subTest(operation=operation.__name__):
                connection = Mock()
                with patch.object(probe.time, "monotonic", return_value=1.01):
                    with self.assertRaises(TimeoutError):
                        operation(connection, argument, 1.0)
                self.assertEqual(connection.mock_calls, [])

    def test_pool_has_at_most_four_workers_preserves_order_and_partial_verdict(self):
        barrier = threading.Barrier(4)
        lock = threading.Lock()
        active = maximum = 0

        def fake(destination, **kwargs):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(active, maximum)
            barrier.wait(timeout=2)
            with lock:
                active -= 1
            return {"address": destination, "protocol_response": destination.endswith("1")}

        destinations = [f"192.0.2.{number}" for number in range(1, 9)]
        with patch.object(probe, "probe_telegram", side_effect=fake):
            result = probe.run_probes(destinations)
        self.assertEqual(maximum, 4)
        self.assertEqual([item["address"] for item in result["probes"]], destinations)
        self.assertEqual(result["verdict"], "degraded")
        self.assertEqual(result["application"], "telegram")
        self.assertEqual(result["scope"], "unauthenticated_req_pq_multi")
        self.assertIsNotNone(datetime.fromisoformat(result["generated_at"]).tzinfo)

    def test_batch_rejects_invalid_inputs_before_starting_any_worker(self):
        for destinations in ([], ["192.0.2.1"] * 9, ["192.0.2.1", "invalid"]):
            with self.subTest(destinations=destinations), patch.object(probe, "probe_telegram") as worker:
                with self.assertRaises(ValueError):
                    probe.run_probes(destinations)
                worker.assert_not_called()

    def test_cli_json_exit_codes_and_required_destinations(self):
        for success, verdict, code in ((True, "responsive", 0), (False, "failed", 0)):
            with self.subTest(success=success):
                output = io.StringIO()
                with patch.object(probe, "probe_telegram", return_value={"protocol_response": success}):
                    with redirect_stdout(output):
                        self.assertEqual(probe.main(["--destination", "192.0.2.1"]), code)
                self.assertEqual(json.loads(output.getvalue())["verdict"], verdict)
        for args in ([], ["--destination", "invalid"],
                     ["--destination", "192.0.2.1"] * 9,
                     ["--destination", "192.0.2.1", "--proxy", "127.0.0.1:1080", "--interface", "lo"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    probe.main(args)
                self.assertEqual(raised.exception.code, 1)

    def test_standalone_cli_preserves_negative_probe_json_with_exit_zero(self):
        def serve(connection, stop):
            self.read_request(connection)
            connection.sendall(wire(struct.pack("<i", -429)))

        with loopback(serve) as endpoint:
            result = subprocess.run(
                [sys.executable, "-B", probe.__file__, "--destination", endpoint],
                capture_output=True, text=True, timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["verdict"], "failed")
        self.assertTrue(report["probes"][0]["tcp_connected"])
        self.assertFalse(report["probes"][0]["protocol_response"])
        self.assertIn("-429", report["probes"][0]["error"])

    def test_standalone_cli_invalid_arguments_exit_one_without_report(self):
        result = subprocess.run(
            [sys.executable, "-B", probe.__file__],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("--destination", result.stderr)


if __name__ == "__main__":
    unittest.main()
