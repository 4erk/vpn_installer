"""Bounded, unauthenticated Telegram req_pq_multi/resPQ reachability probe.

A valid resPQ proves only a protocol response, not server authentication, account
access or encrypted message delivery. No key generation follows this exchange.
Wire formats: https://core.telegram.org/mtproto/samples-auth_key and
https://core.telegram.org/mtproto/mtproto-transports#intermediate
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import secrets
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

PROBE_TIMEOUT = 8.0
MAX_FRAME = 4096
MAX_DESTINATIONS = 8
MAX_WORKERS = 4
REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
VECTOR = 0x1CB5C415


def parse_endpoint(value: str, *, default_port: int | None = 443) -> tuple[str, int]:
    """Accept numeric IP[:port], with brackets required for an IPv6 port."""
    host, port = value, default_port
    if value.startswith("["):
        host, separator, suffix = value[1:].partition("]")
        if not separator or (suffix and not suffix.startswith(":")):
            raise ValueError("invalid bracketed IP endpoint")
        if suffix:
            port = int(suffix[1:])
    elif value.count(":") == 1:
        host, raw_port = value.split(":")
        port = int(raw_port)
    if "%" in host:
        raise ValueError("scoped IP literals are unsupported; use --interface")
    address = ipaddress.ip_address(host)
    if port is None or not 1 <= port <= 65535:
        raise ValueError("endpoint port must be between 1 and 65535")
    return str(address), port


def _proxy_endpoint(proxy: str | None, interface: str | None) -> tuple[str, int] | None:
    if interface is not None and (not interface or "\0" in interface):
        raise ValueError("interface must be a nonempty interface name")
    if proxy is None:
        return None
    if interface is not None:
        raise ValueError("--proxy and --interface select different paths; use only one")
    endpoint = parse_endpoint(proxy, default_port=None)
    if not ipaddress.ip_address(endpoint[0]).is_loopback:
        raise ValueError("SOCKS5 endpoint must be a local loopback IP and explicit port")
    return endpoint


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("total probe I/O budget exhausted")
    return remaining


def _receive(sock: socket.socket, size: int, deadline: float) -> bytes:
    payload = bytearray()
    while len(payload) < size:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(size - len(payload))
        _remaining(deadline)
        if not chunk:
            raise OSError("peer closed before the response was complete")
        payload.extend(chunk)
    return bytes(payload)


def _send(sock: socket.socket, payload: bytes, deadline: float) -> None:
    sock.settimeout(_remaining(deadline))
    sock.sendall(payload)
    _remaining(deadline)


def _socks_connect(sock: socket.socket, address: str, port: int, deadline: float) -> None:
    _send(sock, b"\x05\x01\x00", deadline)
    if _receive(sock, 2, deadline) != b"\x05\x00":
        raise ValueError("SOCKS5 proxy rejected unauthenticated probing")
    ip = ipaddress.ip_address(address)
    atyp = b"\x01" if ip.version == 4 else b"\x04"
    _send(sock, b"\x05\x01\x00" + atyp + ip.packed + struct.pack("!H", port), deadline)
    version, status, reserved, atyp = _receive(sock, 4, deadline)
    if version != 5 or reserved != 0:
        raise ValueError("malformed SOCKS5 reply")
    if status != 0:
        raise ValueError(f"SOCKS5 CONNECT rejected with status {status}")
    if atyp == 3:
        size = _receive(sock, 1, deadline)[0]
        if not size:
            raise ValueError("empty SOCKS5 bound address")
    elif atyp in (1, 4):
        size = 4 if atyp == 1 else 16
    else:
        raise ValueError("invalid SOCKS5 address type")
    # The bound address is consumed, never resolved or connected to.
    _receive(sock, size + 2, deadline)


def _parse_res_pq(frame: bytes, nonce: bytes) -> dict:
    if len(frame) == 4:
        raise ValueError(f"MTProto transport error {struct.unpack('<i', frame)[0]}")
    if len(frame) < 76 or len(frame) > MAX_FRAME or len(frame) % 4:
        raise ValueError("invalid resPQ frame length")
    auth_key, message_id, message_length = struct.unpack_from("<QQI", frame)
    if auth_key != 0:
        raise ValueError("resPQ auth_key_id must be zero")
    if message_id % 4 != 1:
        raise ValueError("invalid resPQ response message_id")
    if message_length != len(frame) - 20:
        raise ValueError("resPQ message length mismatch")
    if struct.unpack_from("<I", frame, 20)[0] != RES_PQ:
        raise ValueError("unexpected MTProto constructor, expected resPQ")
    if frame[24:40] != nonce:
        raise ValueError("resPQ nonce mismatch")
    size, offset = frame[56], 57
    if size == 254:
        size, offset = int.from_bytes(frame[57:60], "little"), 60
        if size < 254:
            raise ValueError("noncanonical resPQ pq length")
    elif size == 255:
        raise ValueError("invalid resPQ pq length prefix")
    end = offset + size
    padded_end = (end + 3) & ~3
    if size == 0 or padded_end + 8 > len(frame):
        raise ValueError("resPQ pq field exceeds frame bounds")
    pq = frame[offset:end]
    if int.from_bytes(pq, "big") <= 1 or pq[-1] % 2 == 0:
        raise ValueError("invalid resPQ pq value")
    if any(frame[end:padded_end]):
        raise ValueError("invalid resPQ pq padding")
    constructor, count = struct.unpack_from("<Ii", frame, padded_end)
    fingerprints = frame[padded_end + 8:]
    if constructor != VECTOR or count <= 0 or count * 8 != len(fingerprints):
        raise ValueError("invalid resPQ fingerprint vector bounds or constructor")
    return {
        "server_nonce": frame[40:56].hex(),
        "pq": pq.hex(),
        "fingerprints": [f"{value:016x}" for (value,) in struct.iter_unpack("<Q", fingerprints)],
    }


def probe_telegram(destination: str, *, proxy: str | None = None, interface: str | None = None) -> dict:
    """Probe one explicit destination. Invalid input raises before socket creation.

    All socket I/O shares eight monotonic seconds; OS scheduling is not a hard
    real-time guarantee. Interface binding fails closed where unsupported.
    """
    address, port = parse_endpoint(destination)
    proxy_endpoint = _proxy_endpoint(proxy, interface)
    result = {
        "address": address, "port": port,
        "path": {"kind": "socks5" if proxy else "interface" if interface else "direct",
                 "proxy": proxy, "interface": interface},
        "phase": "tcp", "tcp_connected": False,
        "proxy_accepted": False if proxy else None,
        "protocol_response": False, "error": None, "elapsed": 0.0,
    }
    started = time.monotonic()
    deadline = started + PROBE_TIMEOUT
    try:
        endpoint = proxy_endpoint or (address, port)
        ip = ipaddress.ip_address(endpoint[0])
        family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            if interface:
                if not hasattr(socket, "SO_BINDTODEVICE"):
                    raise OSError("interface binding is unsupported on this platform")
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
                if ip.version == 6 and ip.is_link_local:
                    endpoint = (*endpoint, 0, socket.if_nametoindex(interface))
            sock.settimeout(_remaining(deadline))
            sock.connect(endpoint)
            _remaining(deadline)
            result["tcp_connected"] = True
            if proxy_endpoint:
                result["phase"] = "proxy"
                _socks_connect(sock, address, port, deadline)
                result["proxy_accepted"] = True
            result["phase"] = "mtproto"
            nonce = secrets.token_bytes(16)
            message_id = (time.time_ns() * (1 << 32) // 1_000_000_000) & ~3
            body = struct.pack("<I", REQ_PQ_MULTI) + nonce
            frame = struct.pack("<QQI", 0, message_id, len(body)) + body
            _send(sock, b"\xee" * 4 + struct.pack("<I", len(frame)) + frame, deadline)
            size = struct.unpack("<I", _receive(sock, 4, deadline))[0]
            if size < 4 or size > MAX_FRAME or size % 4:
                raise ValueError("invalid intermediate frame length (maximum 4096)")
            result["res_pq"] = _parse_res_pq(_receive(sock, size, deadline), nonce)
            _remaining(deadline)
            result["protocol_response"] = True
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)
    result["elapsed"] = round(time.monotonic() - started, 6)
    return result


def run_probes(destinations: list[str], *, proxy: str | None = None, interface: str | None = None) -> dict:
    """One to eight probes, four workers; responsive means only valid resPQ."""
    if not 1 <= len(destinations) <= MAX_DESTINATIONS:
        raise ValueError("supply between 1 and 8 explicit destinations")
    for destination in destinations:
        parse_endpoint(destination)
    _proxy_endpoint(proxy, interface)
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(destinations))) as pool:
        probes = list(pool.map(lambda item: probe_telegram(item, proxy=proxy, interface=interface), destinations))
    successes = sum(item["protocol_response"] for item in probes)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": "telegram", "scope": "unauthenticated_req_pq_multi",
        "probes": probes,
        "verdict": "responsive" if successes == len(probes) else "degraded" if successes else "failed",
    }


class _ProbeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(1, f"{self.prog}: error: {message}\n")


def main(argv: list[str] | None = None) -> int:
    parser = _ProbeArgumentParser(description=__doc__)
    parser.add_argument("--destination", action="append", required=True,
                        help="IPv4[:port] or [IPv6]:port; bare IP uses 443; repeat at most 8 times")
    paths = parser.add_mutually_exclusive_group()
    paths.add_argument("--proxy", help="local SOCKS5 numeric loopback IP:port, no authentication")
    paths.add_argument("--interface", help="bind only this probe socket to a Linux interface")
    args = parser.parse_args(argv)
    try:
        report = run_probes(args.destination, proxy=args.proxy, interface=args.interface)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
