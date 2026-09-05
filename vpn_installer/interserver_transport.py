from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Any

HY2_PORT = 18443
HY2_SERVER_NAME = "vpn-stack.internal"
HY2_CLASH_API_LISTEN = "127.0.0.1:19090"
TRANSPORT_OVERLAY_TAG = "to-foreign"
TRANSPORT_WG_TAG = "interserver-underlay-wg"
TRANSPORT_HY2_TAG = "interserver-underlay-hy2"
TRANSPORT_SELECTOR_TAG = "interserver-underlay-select"
TRANSPORT_CANDIDATE_TAGS = (TRANSPORT_WG_TAG, TRANSPORT_HY2_TAG)
TRANSPORT_RELAY_INBOUND_TAG = "interserver-overlay-in"
TRANSPORT_RELAY_PORT = 19091
TRANSPORT_PROBE_INBOUND_TAGS = {
    TRANSPORT_WG_TAG: "interserver-probe-wg-in",
    TRANSPORT_HY2_TAG: "interserver-probe-hy2-in",
}
TRANSPORT_PROBE_PORTS = {
    TRANSPORT_WG_TAG: 19093,
    TRANSPORT_HY2_TAG: 19094,
}
FOREIGN_DNS_RELAY_PORT = 1053
TRANSPORT_CANDIDATE_PROBE_TIMEOUT_MS = 1200
TRANSPORT_OVERLAY_PROBE_ATTEMPTS = 2
TRANSPORT_PROBE_INTERVAL_SECONDS = 2
TRANSPORT_QUALITY_PROBE_INTERVAL_SECONDS = 15
TRANSPORT_QUALITY_PROBE_PACKETS = 20
TRANSPORT_QUALITY_PROBE_PAYLOAD_BYTES = 1200
TRANSPORT_FAILURE_CONFIRMATIONS = 2
TRANSPORT_ALTERNATE_HEALTH_CONFIRMATIONS = 2
TRANSPORT_EVIDENCE_MAX_GAP_SECONDS = TRANSPORT_PROBE_INTERVAL_SECONDS * 5
TRANSPORT_PREFERRED_TAG = TRANSPORT_WG_TAG
TRANSPORT_PREFERRED_RECOVERY_CONFIRMATIONS = 3
TRANSPORT_PREFERRED_RECOVERY_MIN_SECONDS = 300
TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS = 30
TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS = 8
TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS = 2400
TRANSPORT_PREFERRED_EVIDENCE_MAX_GAP_SECONDS = TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS * 3
TRANSPORT_PREFERRED_RETRY_BASE_SECONDS = 60
TRANSPORT_PREFERRED_RETRY_MAX_SECONDS = 300
TRANSPORT_PREFERRED_STABLE_RESET_SECONDS = 1800
TRANSPORT_SWITCH_RETRY_BASE_SECONDS = 30
TRANSPORT_SWITCH_RETRY_MAX_SECONDS = 300
TRANSPORT_SWITCH_PROOF_ATTEMPTS = 5
TRANSPORT_SWITCH_PROOF_TIMEOUT_MS = 1200
TRANSPORT_SWITCH_PROOF_RETRY_DELAY_SECONDS = 0.2
TRANSPORT_STATE_SCHEMA_VERSION = 16
UNDERLAY_WG_RU_ADDRESS = "10.75.0.1/32"
UNDERLAY_WG_FOREIGN_ADDRESS = "10.75.0.2/32"
UNDERLAY_WG_MTU = 1420
X25519_P = 2**255 - 19
X25519_A24 = 121665
def _interserver_exit_public_ip(env: dict[str, str]) -> str:
    try:
        from .topology import (
            CAP_INTERSERVER_CLIENT,
            CAP_INTERSERVER_SERVER,
            NODE_EXIT,
            NODE_GATEWAY,
            TopologySpec,
        )
    except ImportError:  # Installed policy module runs as a standalone script.
        from topology import (  # type: ignore[no-redef]
            CAP_INTERSERVER_CLIENT,
            CAP_INTERSERVER_SERVER,
            NODE_EXIT,
            NODE_GATEWAY,
            TopologySpec,
        )

    topology = TopologySpec.from_env(env)
    if not topology.is_dual:
        raise ValueError("interserver transport requires a dual topology")
    gateway_plan = topology.plan(NODE_GATEWAY)
    exit_plan = topology.plan(NODE_EXIT)
    if (
        CAP_INTERSERVER_CLIENT not in gateway_plan.capabilities
        or CAP_INTERSERVER_SERVER not in exit_plan.capabilities
    ):
        raise ValueError("topology does not provide interserver transport capabilities")
    return exit_plan.public_ip


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    while size:
        chunk = connection.recv(size)
        if not chunk:
            raise OSError("peer closed before the probe response was complete")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def _socks_address(address: str) -> tuple[bytes, bytes]:
    parsed = ipaddress.ip_address(address)
    return (b"\x01", parsed.packed) if parsed.version == 4 else (b"\x04", parsed.packed)


def _receive_socks_address(connection: socket.socket, address_type: int) -> tuple[str, int]:
    if address_type == 1:
        raw_address = _receive_exact(connection, 4)
        host = socket.inet_ntop(socket.AF_INET, raw_address)
    elif address_type == 4:
        raw_address = _receive_exact(connection, 16)
        host = socket.inet_ntop(socket.AF_INET6, raw_address)
    elif address_type == 3:
        raw_address = _receive_exact(connection, _receive_exact(connection, 1)[0])
        host = raw_address.decode("ascii")
    else:
        raise OSError("SOCKS5 proxy returned an invalid address type")
    return host, int.from_bytes(_receive_exact(connection, 2), "big")


def _dns_probe_query() -> tuple[int, bytes]:
    query_id = 0x5650
    question = b"\x09localhost\x00" + struct.pack("!HH", 1, 1)
    return query_id, struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question


def _skip_dns_name(payload: bytes, offset: int) -> int:
    while True:
        if offset >= len(payload):
            raise OSError("DNS probe returned a truncated name")
        size = payload[offset]
        offset += 1
        if size == 0:
            return offset
        if size & 0xC0 == 0xC0:
            if offset >= len(payload):
                raise OSError("DNS probe returned a truncated name pointer")
            return offset + 1
        if size & 0xC0 or offset + size > len(payload):
            raise OSError("DNS probe returned an invalid name")
        offset += size


def _dns_probe_response(payload: bytes, query_id: int) -> None:
    if len(payload) < 12:
        raise OSError("DNS probe returned a truncated response")
    response_id, flags, questions, answers, _authority, _additional = struct.unpack("!HHHHHH", payload[:12])
    if response_id != query_id or not flags & 0x8000:
        raise OSError("DNS probe returned an unrelated response")
    if flags & 0x0200:
        raise OSError("DNS probe returned a truncated response")
    if flags & 0x000F:
        raise OSError(f"DNS probe returned rcode {flags & 0x000F}")
    if questions != 1 or answers < 1:
        raise OSError("DNS probe returned no usable answer")
    offset = _skip_dns_name(payload, 12)
    if offset + 4 > len(payload):
        raise OSError("DNS probe returned a truncated question")
    offset += 4
    for _answer in range(answers):
        offset = _skip_dns_name(payload, offset)
        if offset + 10 > len(payload):
            raise OSError("DNS probe returned a truncated answer")
        record_type, record_class, _ttl, data_size = struct.unpack("!HHIH", payload[offset:offset + 10])
        offset += 10
        if offset + data_size > len(payload):
            raise OSError("DNS probe returned truncated answer data")
        if record_type == 1 and record_class == 1 and data_size == 4:
            return
        offset += data_size
    raise OSError("DNS probe returned no IPv4 answer")


def _socks_udp_dns_probe(proxy_port: int, target_host: str, target_port: int, timeout_seconds: float) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        datagram.bind(("127.0.0.1", 0))
        datagram.settimeout(timeout_seconds)
        local_host, local_port = datagram.getsockname()
        local_type, local_address = _socks_address(local_host)
        target_type, target_address = _socks_address(target_host)
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout_seconds) as control:
            control.settimeout(timeout_seconds)
            control.sendall(b"\x05\x01\x00")
            if _receive_exact(control, 2) != b"\x05\x00":
                raise OSError("SOCKS5 proxy rejected unauthenticated probing")
            control.sendall(
                b"\x05\x03\x00" + local_type + local_address + local_port.to_bytes(2, "big")
            )
            version, status, _reserved, reply_type = _receive_exact(control, 4)
            relay_host, relay_port = _receive_socks_address(control, reply_type)
            if version != 5 or status != 0:
                raise OSError(f"SOCKS5 UDP ASSOCIATE failed with status {status}")
            try:
                relay_address = ipaddress.ip_address(relay_host)
            except ValueError as exc:
                raise OSError("SOCKS5 UDP relay returned a non-IP address") from exc
            if relay_address.version != 4:
                raise OSError("SOCKS5 UDP relay returned an incompatible address family")
            if relay_address.is_unspecified:
                relay_host = "127.0.0.1"
            query_id, query = _dns_probe_query()
            request = b"\x00\x00\x00" + target_type + target_address + target_port.to_bytes(2, "big") + query
            datagram.sendto(request, (relay_host, relay_port))
            response, _source = datagram.recvfrom(4096)
            if len(response) < 7 or response[:3] != b"\x00\x00\x00":
                raise OSError("SOCKS5 UDP relay returned an invalid datagram")
            offset = 3
            response_type = response[offset]
            offset += 1
            if response_type == 1:
                offset += 4
            elif response_type == 4:
                offset += 16
            elif response_type == 3:
                if offset >= len(response):
                    raise OSError("SOCKS5 UDP relay returned a truncated domain")
                offset += 1 + response[offset]
            else:
                raise OSError("SOCKS5 UDP relay returned an invalid address type")
            offset += 2
            if offset > len(response):
                raise OSError("SOCKS5 UDP relay returned a truncated address")
            _dns_probe_response(response[offset:], query_id)


def _probe_result(
    scope: str,
    target: str,
    started: float,
    error: str = "",
    *,
    attempts: int = 1,
    health_confirmed: bool = False,
    failure_confirmed: bool = False,
) -> dict[str, Any]:
    elapsed_ms = max(1, round((time.monotonic() - started) * 1000))
    return {
        "checked": True,
        "ok": not error,
        "attempts": attempts,
        "delay_ms": 0 if error else elapsed_ms,
        "elapsed_ms": elapsed_ms,
        "scope": scope,
        "target": target,
        "error": error[:240],
        "health_confirmed": health_confirmed,
        "failure_confirmed": failure_confirmed,
    }


def transport_candidate_probe(
    tag: str,
    *,
    timeout_ms: int = TRANSPORT_CANDIDATE_PROBE_TIMEOUT_MS,
    attempts: int = 1,
) -> dict[str, Any]:
    """Prove UDP carriage and the controlled foreign DNS relay over one underlay."""

    started = time.monotonic()
    proxy_port = TRANSPORT_PROBE_PORTS.get(tag)
    target_host = UNDERLAY_WG_FOREIGN_ADDRESS.split("/", 1)[0]
    target = f"{target_host}:{FOREIGN_DNS_RELAY_PORT}"
    if proxy_port is None:
        return _probe_result("raw-underlay-udp", target, started, "unknown transport candidate")
    if attempts < 1:
        return _probe_result("raw-underlay-udp", target, started, "probe attempts must be positive")
    attempt_timeout = max(0.001, timeout_ms / 1000 / attempts)
    delays: list[int] = []
    last_error = "underlay DNS probe timed out"
    for _attempt in range(attempts):
        attempt_started = time.monotonic()
        try:
            _socks_udp_dns_probe(proxy_port, target_host, FOREIGN_DNS_RELAY_PORT, attempt_timeout)
        except (OSError, ValueError) as exc:
            last_error = str(exc) or last_error
            continue
        delays.append(max(1, round((time.monotonic() - attempt_started) * 1000)))
    if not delays:
        return _probe_result("raw-underlay-udp", target, started, last_error, attempts=attempts)
    result = _probe_result(
        "raw-underlay-udp",
        target,
        started,
        attempts=attempts,
        health_confirmed=True,
    )
    result["delay_ms"] = round(sum(delays) / len(delays))
    if attempts > 1:
        loss = round((attempts - len(delays)) * 100 / attempts, 3)
        result.update(
            {
                "quality_checked": True,
                "quality_ok": loss == 0,
                "quality_error": "" if loss == 0 else f"underlay probe packet loss {loss:g}%",
                "packet_loss_pct": loss,
            }
        )
    return result


def _bound_tcp_dns_probe(interface: str, target_host: str, target_port: int, timeout_seconds: float) -> None:
    query_id, query = _dns_probe_query()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.setsockopt(
            socket.SOL_SOCKET,
            getattr(socket, "SO_BINDTODEVICE", 25),
            interface.encode("utf-8") + b"\0",
        )
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        connection.settimeout(timeout_seconds)
        connection.connect((target_host, target_port))
        connection.sendall(len(query).to_bytes(2, "big") + query)
        response_size = int.from_bytes(_receive_exact(connection, 2), "big")
        _dns_probe_response(_receive_exact(connection, response_size), query_id)


def transport_overlay_dns_probe(
    interface: str,
    target_host: str,
    *,
    timeout_ms: int = TRANSPORT_CANDIDATE_PROBE_TIMEOUT_MS,
    attempts: int = TRANSPORT_OVERLAY_PROBE_ATTEMPTS,
) -> dict[str, Any]:
    """Prove the exact inner-WireGuard DNS dataplane without external dependencies."""

    started = time.monotonic()
    target = f"{target_host}:{FOREIGN_DNS_RELAY_PORT}"
    if not interface or not target_host or attempts < 1:
        return _probe_result("overlay-dns", target, started, "overlay probe identity is incomplete")
    try:
        address = ipaddress.ip_address(target_host)
    except ValueError:
        return _probe_result("overlay-dns", target, started, "overlay probe target is not an IP literal")
    if address.version != 4:
        return _probe_result("overlay-dns", target, started, "overlay probe target is not IPv4")

    attempt_timeout = max(0.001, timeout_ms / 1000 / attempts)
    last_error = "overlay DNS probe timed out"
    for attempt in range(1, attempts + 1):
        try:
            _bound_tcp_dns_probe(interface, target_host, FOREIGN_DNS_RELAY_PORT, attempt_timeout)
        except (OSError, ValueError) as exc:
            last_error = str(exc) or last_error
            continue
        return _probe_result(
            "overlay-dns",
            target,
            started,
            attempts=attempt,
            health_confirmed=True,
        )
    return _probe_result(
        "overlay-dns",
        target,
        started,
        last_error,
        attempts=attempts,
        failure_confirmed=True,
    )


def clamp_x25519_private(private_key: bytes) -> bytes:
    if len(private_key) != 32:
        raise ValueError("invalid X25519 private key length")
    data = bytearray(private_key)
    data[0] &= 248
    data[31] &= 127
    data[31] |= 64
    return bytes(data)


def x25519_public_from_private(private_key: bytes) -> bytes:
    scalar = int.from_bytes(clamp_x25519_private(private_key), "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for bit in range(254, -1, -1):
        current = (scalar >> bit) & 1
        swap ^= current
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = current
        a = (x2 + z2) % X25519_P
        aa = (a * a) % X25519_P
        b = (x2 - z2) % X25519_P
        bb = (b * b) % X25519_P
        e = (aa - bb) % X25519_P
        c = (x3 + z3) % X25519_P
        d = (x3 - z3) % X25519_P
        da = (d * a) % X25519_P
        cb = (c * b) % X25519_P
        x3 = pow((da + cb) % X25519_P, 2, X25519_P)
        z3 = (x1 * pow((da - cb) % X25519_P, 2, X25519_P)) % X25519_P
        x2 = (aa * bb) % X25519_P
        z2 = (e * ((aa + X25519_A24 * e) % X25519_P)) % X25519_P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = (x2 * pow(z2, X25519_P - 2, X25519_P)) % X25519_P
    return result.to_bytes(32, "little")


def generate_x25519_pair() -> tuple[bytes, bytes]:
    private_key = clamp_x25519_private(os.urandom(32))
    return private_key, x25519_public_from_private(private_key)


def generate_transport_identity() -> dict[str, str]:
    """Generate a pinned self-signed identity stored with the deployment."""

    from .runtime_deps import ensure_python_package

    ensure_python_package("cryptography", "cryptography>=41,<47")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    private_key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HY2_SERVER_NAME)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2049, 12, 31, tzinfo=timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HY2_SERVER_NAME)]), critical=False)
        .sign(private_key, algorithm=None)
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_key_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "INTERSERVER_HY2_CERTIFICATE_B64": base64.b64encode(certificate_pem).decode("ascii"),
        "INTERSERVER_HY2_PRIVATE_KEY_B64": base64.b64encode(private_key_pem).decode("ascii"),
        "INTERSERVER_HY2_PUBLIC_KEY_SHA256": base64.b64encode(hashlib.sha256(public_key_der).digest()).decode("ascii"),
    }


def validate_transport_identity(env: dict[str, str]) -> None:
    from .runtime_deps import ensure_python_package

    ensure_python_package("cryptography", "cryptography>=41,<47")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    certificate_pem = "\n".join(decode_transport_pem(env.get("INTERSERVER_HY2_CERTIFICATE_B64", ""), "certificate")) + "\n"
    private_key_pem = "\n".join(decode_transport_pem(env.get("INTERSERVER_HY2_PRIVATE_KEY_B64", ""), "private key")) + "\n"
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        certificate_public = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        private_public = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        expected_pin = base64.b64decode(env.get("INTERSERVER_HY2_PUBLIC_KEY_SHA256", ""), validate=True)
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except (TypeError, ValueError, x509.ExtensionNotFound) as exc:
        raise ValueError("invalid interserver transport identity") from exc
    if certificate_public != private_public:
        raise ValueError("interserver transport certificate and private key do not match")
    if not hmac.compare_digest(hashlib.sha256(certificate_public).digest(), expected_pin):
        raise ValueError("interserver transport certificate pin does not match")
    if HY2_SERVER_NAME not in names:
        raise ValueError("interserver transport certificate name does not match")
    not_before = getattr(certificate, "not_valid_before_utc", None)
    not_after = getattr(certificate, "not_valid_after_utc", None)
    if not_before is None or not_after is None:
        not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if not not_before <= now <= not_after:
        raise ValueError("interserver transport certificate is not currently valid")


def decode_transport_pem(value: str, label: str) -> list[str]:
    try:
        payload = base64.b64decode(value, validate=True).decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid {label} transport identity") from exc
    lines = payload.strip().splitlines()
    if not lines or not lines[0].startswith("-----BEGIN ") or not lines[-1].startswith("-----END "):
        raise ValueError(f"invalid {label} transport identity")
    return lines


def _transport_root_key(wireguard_preshared_key: str) -> bytes:
    try:
        root_key = base64.b64decode(wireguard_preshared_key, validate=True)
    except ValueError as exc:
        raise ValueError("invalid WireGuard preshared key") from exc
    if len(root_key) != 32:
        raise ValueError("invalid WireGuard preshared key length")
    return root_key


def _derive_transport_secret(wireguard_preshared_key: str, context: bytes) -> str:
    token = hmac.new(_transport_root_key(wireguard_preshared_key), context, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")


def _derive_transport_bytes(wireguard_preshared_key: str, context: bytes) -> bytes:
    return hmac.new(_transport_root_key(wireguard_preshared_key), context, hashlib.sha256).digest()


def derive_transport_password(wireguard_preshared_key: str) -> str:
    return _derive_transport_secret(wireguard_preshared_key, b"vpn-stack/interserver/hysteria2/auth/v1")


def derive_transport_obfs_password(wireguard_preshared_key: str) -> str:
    return _derive_transport_secret(wireguard_preshared_key, b"vpn-stack/interserver/hysteria2/obfs/v1")


def derive_underlay_wireguard_identity(wireguard_preshared_key: str) -> dict[str, str]:
    private_key = clamp_x25519_private(
        _derive_transport_bytes(wireguard_preshared_key, b"vpn-stack/interserver/wireguard/private/v1")
    )
    return {
        "private_key": base64.b64encode(private_key).decode("ascii"),
        "public_key": base64.b64encode(x25519_public_from_private(private_key)).decode("ascii"),
        "pre_shared_key": base64.b64encode(
            _derive_transport_bytes(wireguard_preshared_key, b"vpn-stack/interserver/wireguard/psk/v1")
        ).decode("ascii"),
    }


def _hysteria_outbound(env: dict[str, str], exit_public_ip: str) -> dict[str, Any]:
    return {
        "type": "hysteria2",
        "tag": TRANSPORT_HY2_TAG,
        "server": exit_public_ip,
        "server_port": HY2_PORT,
        "obfs": {"type": "salamander", "password": derive_transport_obfs_password(env["WG_PRESHARED_KEY"])},
        "password": derive_transport_password(env["WG_PRESHARED_KEY"]),
        "tls": {
            "enabled": True,
            "server_name": HY2_SERVER_NAME,
            "certificate_public_key_sha256": [env["INTERSERVER_HY2_PUBLIC_KEY_SHA256"]],
        },
        "routing_mark": int(env["WG_TUNNEL_FWMARK"]),
    }


def _relay_inbound() -> dict[str, Any]:
    return {
        "type": "direct",
        "tag": TRANSPORT_RELAY_INBOUND_TAG,
        "listen": "127.0.0.1",
        "listen_port": TRANSPORT_RELAY_PORT,
        "network": "udp",
    }


def _relay_rule(env: dict[str, str], exit_public_ip: str) -> dict[str, Any]:
    return {
        "inbound": [TRANSPORT_RELAY_INBOUND_TAG],
        "action": "route",
        "outbound": TRANSPORT_SELECTOR_TAG,
        "override_address": exit_public_ip,
        "override_port": int(env["WG_PORT"]),
    }


def _probe_inbounds() -> list[dict[str, Any]]:
    return [
        {
            "type": "mixed",
            "tag": TRANSPORT_PROBE_INBOUND_TAGS[tag],
            "listen": "127.0.0.1",
            "listen_port": TRANSPORT_PROBE_PORTS[tag],
        }
        for tag in TRANSPORT_CANDIDATE_TAGS
    ]


def _probe_rules() -> list[dict[str, Any]]:
    return [
        {
            "inbound": [TRANSPORT_PROBE_INBOUND_TAGS[tag]],
            "action": "route",
            "outbound": tag,
        }
        for tag in TRANSPORT_CANDIDATE_TAGS
    ]


def build_ru_transport_topology(env: dict[str, str]) -> dict[str, Any]:
    exit_public_ip = _interserver_exit_public_ip(env)
    identity = derive_underlay_wireguard_identity(env["WG_PRESHARED_KEY"])
    endpoint = {
        "type": "wireguard",
        "tag": TRANSPORT_WG_TAG,
        "system": False,
        "mtu": UNDERLAY_WG_MTU,
        "address": [UNDERLAY_WG_RU_ADDRESS],
        "private_key": identity["private_key"],
        "peers": [
            {
                "address": exit_public_ip,
                "port": int(env["WG_PORT"]),
                "public_key": env["WG_FOREIGN_PUBLIC_KEY"],
                "pre_shared_key": identity["pre_shared_key"],
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            }
        ],
        "routing_mark": int(env["WG_TUNNEL_FWMARK"]),
    }
    selector = {
        "type": "selector",
        "tag": TRANSPORT_SELECTOR_TAG,
        "outbounds": list(TRANSPORT_CANDIDATE_TAGS),
        "default": TRANSPORT_PREFERRED_TAG,
        "interrupt_exist_connections": True,
    }
    return {
        "endpoints": [endpoint],
        "inbounds": [_relay_inbound(), *_probe_inbounds()],
        "outbounds": [_hysteria_outbound(env, exit_public_ip), selector],
        "route_rules": [_relay_rule(env, exit_public_ip), *_probe_rules()],
    }


def foreign_underlay_wireguard_peer(wireguard_preshared_key: str) -> dict[str, str]:
    identity = derive_underlay_wireguard_identity(wireguard_preshared_key)
    return {
        "public_key": identity["public_key"],
        "pre_shared_key": identity["pre_shared_key"],
        "allowed_ip": UNDERLAY_WG_RU_ADDRESS,
    }


def transport_topology_configured(config: dict[str, Any], env: dict[str, str]) -> bool:
    """Validate the runtime topology without requiring renderer dependencies."""

    def by_tag(items: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(items, list):
            return {}
        return {
            str(item["tag"]): item
            for item in items
            if isinstance(item, dict) and item.get("tag")
        }

    try:
        exit_public_ip = _interserver_exit_public_ip(env)
        outbounds = by_tag(config.get("outbounds", []))
        stable_overlay = outbounds.get(TRANSPORT_OVERLAY_TAG, {})
        wireguard = by_tag(config.get("endpoints", [])).get(TRANSPORT_WG_TAG, {})
        expected_hysteria = _hysteria_outbound(env, exit_public_ip)
        expected_inbounds = [_relay_inbound(), *_probe_inbounds()]
        expected_rules = [_relay_rule(env, exit_public_ip), *_probe_rules()]
    except (ImportError, KeyError, TypeError, ValueError):
        return False
    if stable_overlay.get("type") != "direct" or stable_overlay.get("bind_interface") != env.get("WG_INTERFACE", "wg0"):
        return False
    if outbounds.get(TRANSPORT_HY2_TAG) != expected_hysteria:
        return False
    if outbounds.get(TRANSPORT_SELECTOR_TAG) != {
        "type": "selector",
        "tag": TRANSPORT_SELECTOR_TAG,
        "outbounds": list(TRANSPORT_CANDIDATE_TAGS),
        "default": TRANSPORT_PREFERRED_TAG,
        "interrupt_exist_connections": True,
    }:
        return False
    if any(by_tag(config.get("inbounds", [])).get(item["tag"]) != item for item in expected_inbounds):
        return False
    peers = wireguard.get("peers", [])
    peer = peers[0] if isinstance(peers, list) and len(peers) == 1 and isinstance(peers[0], dict) else {}
    if not (
        wireguard.get("type") == "wireguard"
        and wireguard.get("address") == [UNDERLAY_WG_RU_ADDRESS]
        and wireguard.get("mtu") == UNDERLAY_WG_MTU
        and bool(wireguard.get("private_key"))
        and peer.get("address") == exit_public_ip
        and peer.get("port") == int(env.get("WG_PORT", "0") or 0)
        and bool(peer.get("pre_shared_key"))
    ):
        return False
    rules = config.get("route", {}).get("rules", [])
    return isinstance(rules, list) and all(rule in rules for rule in expected_rules)


def _normalize_probe(probe: dict[str, Any] | None) -> dict[str, Any]:
    probe = probe or {}
    checked = probe.get("checked") is True if "checked" in probe else bool(probe)
    normalized = {
        "checked": checked,
        "ok": checked and probe.get("ok") is True,
        "attempts": max(0, int(probe.get("attempts", 1 if checked else 0) or 0)),
        "delay_ms": max(0, int(probe.get("delay_ms", 0) or 0)),
        "error": str(probe.get("error", ""))[:240],
    }
    for key in (
        "scope",
        "target",
        "elapsed_ms",
        "health_confirmed",
        "failure_confirmed",
        "quality_checked",
        "quality_sampled",
        "quality_ok",
        "quality_error",
        "packet_loss_pct",
        "rtt_avg_ms",
        "payload_bytes",
    ):
        if key in probe:
            normalized[key] = probe[key]
    return normalized


def _probe_failure_reason(probe: dict[str, Any]) -> str:
    error = " ".join(str(probe.get("error", "")).lower().split())
    categories = (
        ("packet_loss", ("packet loss",)),
        ("timeout", ("timed out", "timeout", "deadline")),
        ("connection_refused", ("connection refused",)),
        ("network_unreachable", ("network is unreachable", "no route to host")),
        ("host_unreachable", ("host is unreachable",)),
        ("tls_failure", ("certificate", "tls")),
        ("invalid_probe_response", ("dns probe returned", "socks5 proxy returned", "socks5 udp associate")),
    )
    return next((reason for reason, markers in categories if any(marker in error for marker in markers)), error[:120] or "probe_failed")


def _selected_quality(probe: dict[str, Any]) -> tuple[str, str]:
    if probe.get("quality_checked") is True and probe.get("quality_ok") is False:
        return "degraded", str(probe.get("quality_error") or "overlay quality sample is degraded")
    return "healthy", ""


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _cycle_relation(
    previous_at: Any,
    observed_at: str,
    *,
    max_gap_seconds: int = TRANSPORT_EVIDENCE_MAX_GAP_SECONDS,
) -> str:
    previous_time = _parse_timestamp(previous_at)
    current_time = _parse_timestamp(observed_at)
    if previous_time is None or current_time is None:
        return "reset"
    gap_seconds = (current_time - previous_time).total_seconds()
    if gap_seconds == 0:
        return "same"
    if 0 < gap_seconds <= max_gap_seconds:
        return "next"
    return "reset"


def _next_evidence(
    previous: dict[str, Any],
    *,
    key: str,
    path: str,
    reason: str,
    cycle_relation: str,
) -> dict[str, Any]:
    value = previous.get(key, {})
    prior = value if isinstance(value, dict) else {}
    same_evidence = prior.get("path") == path and prior.get("reason") == reason
    count = max(1, int(prior.get("confirmations", 0) or 0)) if same_evidence and cycle_relation != "reset" else 1
    if same_evidence and cycle_relation == "next":
        count += 1
    return {
        "path": path,
        "reason": reason,
        "confirmations": count,
    }


def _quality_switch_evidence(
    selected: str,
    selected_probe: dict[str, Any],
    alternate_probe: dict[str, Any],
    previous: dict[str, Any],
    observed_at: str,
) -> tuple[dict[str, Any], bool]:
    prior = previous.get("quality_failure", {})
    reason = _probe_failure_reason({"error": selected_probe.get("quality_error", "")})
    if not isinstance(prior, dict) or prior.get("path") != selected or prior.get("reason") != reason:
        prior = {}
    relation = _cycle_relation(
        prior.get("sampled_at"), observed_at,
        max_gap_seconds=TRANSPORT_QUALITY_PROBE_INTERVAL_SECONDS * 3,
    )
    if selected_probe.get("quality_sampled") is not True:
        return (dict(prior) if relation != "reset" else {}), False
    if not (
        alternate_probe.get("ok") is True
        and alternate_probe.get("health_confirmed") is True
        and alternate_probe.get("quality_checked") is True
        and alternate_probe.get("quality_ok") is True
    ):
        return {}, False
    sampled = _parse_timestamp(prior.get("sampled_at"))
    observed = _parse_timestamp(observed_at)
    if sampled and observed and 0 <= (observed - sampled).total_seconds() < TRANSPORT_QUALITY_PROBE_INTERVAL_SECONDS:
        return dict(prior), False

    # ICMP loss and candidate DNS success are not comparable rates. Require paired
    # observations at the quality cadence, never cached liveness cycles.
    evidence = _next_evidence(
        {"quality_failure": prior}, key="quality_failure", path=selected,
        reason=reason, cycle_relation=relation,
    )
    evidence.update({"sampled_at": observed_at, "packet_loss_pct": selected_probe.get("packet_loss_pct")})
    confirmed = evidence["confirmations"] >= max(
        TRANSPORT_FAILURE_CONFIRMATIONS, TRANSPORT_ALTERNATE_HEALTH_CONFIRMATIONS,
    )
    return evidence, confirmed


def _preferred_retry_active(previous: dict[str, Any], observed_at: str) -> bool:
    retry = previous.get("preferred_retry", {})
    if not isinstance(retry, dict) or retry.get("path") != TRANSPORT_PREFERRED_TAG:
        return False
    retry_at = _parse_timestamp(retry.get("retry_at"))
    observed = _parse_timestamp(observed_at)
    return retry_at is not None and observed is not None and observed < retry_at


def _next_preferred_retry(previous: dict[str, Any], reason: str, observed_at: str) -> dict[str, Any]:
    prior = previous.get("preferred_retry", {})
    observed = _parse_timestamp(observed_at) or datetime.now(timezone.utc)
    attempts = 1
    if isinstance(prior, dict) and prior.get("path") == TRANSPORT_PREFERRED_TAG:
        recovered_at = _parse_timestamp(prior.get("recovered_at"))
        if recovered_at is None or (observed - recovered_at).total_seconds() < TRANSPORT_PREFERRED_STABLE_RESET_SECONDS:
            attempts = max(0, int(prior.get("attempts", 0) or 0)) + 1
    delay = min(
        TRANSPORT_PREFERRED_RETRY_MAX_SECONDS,
        TRANSPORT_PREFERRED_RETRY_BASE_SECONDS * (2 ** min(attempts - 1, 8)),
    )
    return {
        "path": TRANSPORT_PREFERRED_TAG,
        "attempts": attempts,
        "failed_at": observed_at,
        "retry_at": (observed + timedelta(seconds=delay)).isoformat(),
        "reason": reason,
    }


def _preferred_recovery_details(
    previous: dict[str, Any],
    observed_at: str,
    *,
    mark_recovered: bool = False,
) -> dict[str, Any]:
    retry = previous.get("preferred_retry", {})
    if not isinstance(retry, dict) or retry.get("path") != TRANSPORT_PREFERRED_TAG:
        return {}
    recovered_at = _parse_timestamp(retry.get("recovered_at"))
    observed = _parse_timestamp(observed_at)
    if mark_recovered and recovered_at is None and observed is not None:
        retry = {**retry, "recovered_at": observed_at}
        recovered_at = observed
    if (
        recovered_at is not None
        and observed is not None
        and (observed - recovered_at).total_seconds() >= TRANSPORT_PREFERRED_STABLE_RESET_SECONDS
    ):
        return {}
    return {"preferred_retry": retry}


def _policy_state(
    selected: str,
    probes: dict[str, dict[str, Any]],
    observed_at: str,
    state: str,
    reason: str,
    recommended: str | None = None,
    hard_failure: bool = False,
    **details: Any,
) -> dict[str, Any]:
    target = selected if recommended is None else recommended
    return {
        "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
        "updated_at": observed_at,
        "state": state,
        "preferred": TRANSPORT_PREFERRED_TAG,
        "selected": selected,
        "recommended": target,
        "would_switch": target != selected,
        "hard_failure_evidence": hard_failure,
        "probes": probes,
        "reason": reason,
        **details,
    }


def evaluate_transport_policy(
    *,
    selected: str,
    probes: dict[str, dict[str, Any]],
    previous: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    previous = previous if isinstance(previous, dict) and previous.get("schema_version") == TRANSPORT_STATE_SCHEMA_VERSION else {}
    observed_at = observed_at or datetime.now(timezone.utc).isoformat()
    normalized = {tag: _normalize_probe(probes.get(tag)) for tag in TRANSPORT_CANDIDATE_TAGS}
    if selected not in TRANSPORT_CANDIDATE_TAGS:
        return _policy_state(selected, normalized, observed_at, "failed", "selected underlay is invalid")

    alternate = next(tag for tag in TRANSPORT_CANDIDATE_TAGS if tag != selected)
    selected_probe = normalized[selected]
    alternate_probe = normalized[alternate]
    failed_switch = previous.get("state") == "failed" and previous.get("would_switch") is True
    prior = previous if previous.get("selected") == selected and not failed_switch else {}
    cycle_relation = _cycle_relation(prior.get("updated_at"), observed_at)

    # Missing observations are not path failures. The selected observation covers
    # the real overlay, while the alternate observation covers only that raw underlay.
    if not selected_probe["checked"]:
        return _policy_state(selected, normalized, observed_at, "inconclusive", "selected underlay was not probed")
    if not selected_probe["ok"]:
        failure_reason = _probe_failure_reason(selected_probe)
        failure = _next_evidence(
            prior,
            key="failure",
            path=selected,
            reason=failure_reason,
            cycle_relation=cycle_relation,
        )
        if selected_probe.get("failure_confirmed") is True:
            failure["confirmations"] = max(TRANSPORT_FAILURE_CONFIRMATIONS, failure["confirmations"])
        confirmed_failure = failure["confirmations"] >= TRANSPORT_FAILURE_CONFIRMATIONS
        state = "failed" if confirmed_failure and not alternate_probe["ok"] else "suspect"
        reason = (
            f"{selected} {failure_reason} confirmation "
            f"{failure['confirmations']}/{TRANSPORT_FAILURE_CONFIRMATIONS}"
        )
        details: dict[str, Any] = {"failure": failure}
        details.update(_preferred_recovery_details(prior, observed_at))
        recommended: str | None = None
        if alternate_probe["ok"]:
            alternate_health = _next_evidence(
                prior,
                key="alternate_health",
                path=alternate,
                reason="healthy",
                cycle_relation=cycle_relation,
            )
            if alternate_probe.get("health_confirmed") is True:
                alternate_health["confirmations"] = max(
                    TRANSPORT_ALTERNATE_HEALTH_CONFIRMATIONS,
                    alternate_health["confirmations"],
                )
            details["alternate_health"] = alternate_health
            if (
                confirmed_failure
                and alternate_health["confirmations"] >= TRANSPORT_ALTERNATE_HEALTH_CONFIRMATIONS
            ):
                state = "recovering"
                recommended = alternate
                if selected == TRANSPORT_PREFERRED_TAG:
                    details["preferred_retry"] = _next_preferred_retry(prior, failure_reason, observed_at)
                reason = (
                    f"{selected} has confirmed {failure_reason}; "
                    f"{alternate} is confirmed healthy"
                )
        elif confirmed_failure:
            reason = f"{selected} has confirmed {failure_reason}; alternate is not proven healthy"
        return _policy_state(
            selected,
            normalized,
            observed_at,
            state,
            reason,
            recommended=recommended,
            hard_failure=confirmed_failure,
            **details,
        )

    state, quality_reason = _selected_quality(selected_probe)
    if state == "degraded":
        evidence, confirmed = _quality_switch_evidence(selected, selected_probe, alternate_probe, prior, observed_at)
        details = _preferred_recovery_details(prior, observed_at)
        if evidence:
            details["quality_failure"] = evidence
        retry_active = selected != TRANSPORT_PREFERRED_TAG and _preferred_retry_active(prior, observed_at)
        if confirmed and not retry_active:
            if selected == TRANSPORT_PREFERRED_TAG:
                details["preferred_retry"] = _next_preferred_retry(prior, evidence["reason"], observed_at)
            else:
                details.update(_preferred_recovery_details(prior, observed_at, mark_recovered=True))
            return _policy_state(
                selected, normalized, observed_at, "recovering",
                f"{selected} has confirmed {evidence['reason']}; alternate underlay is repeatedly healthy",
                recommended=alternate, **details,
            )
        if retry_active:
            quality_reason += f"; preferred retry is deferred until {prior['preferred_retry'].get('retry_at')}"
        return _policy_state(selected, normalized, observed_at, state, quality_reason, **details)

    if selected == TRANSPORT_PREFERRED_TAG:
        return _policy_state(
            selected,
            normalized,
            observed_at,
            state,
            quality_reason or "preferred overlay path is healthy",
            **_preferred_recovery_details(prior, observed_at, mark_recovered=True),
        )

    preferred_probe = normalized[TRANSPORT_PREFERRED_TAG]
    recovery_details: dict[str, Any] = _preferred_recovery_details(prior, observed_at)
    prior_recovery = prior.get("preferred_recovery")
    if isinstance(prior_recovery, dict):
        recovery_details["preferred_recovery"] = prior_recovery
    if prior.get("preferred_probe_at"):
        recovery_details["preferred_probe_at"] = prior["preferred_probe_at"]
    selected_state, selected_quality_reason = _selected_quality(selected_probe)
    if not preferred_probe["checked"]:
        deferred_reason = (
            f"fallback overlay path is healthy; preferred retry is deferred until "
            f"{recovery_details['preferred_retry'].get('retry_at')}"
            if _preferred_retry_active(prior, observed_at) and "preferred_retry" in recovery_details
            else "fallback overlay path is healthy; preferred probe is deferred"
        )
        return _policy_state(
            selected,
            normalized,
            observed_at,
            selected_state,
            selected_quality_reason or deferred_reason,
            **recovery_details,
        )
    if not preferred_probe["ok"]:
        retry = _next_preferred_retry(prior, _probe_failure_reason(preferred_probe), observed_at)
        return _policy_state(
            selected,
            normalized,
            observed_at,
            selected_state,
            selected_quality_reason
            or f"fallback overlay path is healthy; preferred underlay {_probe_failure_reason(preferred_probe)}",
            preferred_probe_at=observed_at,
            preferred_retry=retry,
        )
    if preferred_probe.get("quality_checked") is True and preferred_probe.get("quality_ok") is False:
        quality_reason = str(preferred_probe.get("quality_error") or "preferred underlay quality probe failed")
        retry = _next_preferred_retry(prior, _probe_failure_reason({"error": quality_reason}), observed_at)
        return _policy_state(
            selected,
            normalized,
            observed_at,
            selected_state,
            selected_quality_reason or f"fallback overlay is healthy; {quality_reason}",
            preferred_probe_at=observed_at,
            preferred_retry=retry,
        )

    recovery_relation = _cycle_relation(
        prior.get("preferred_probe_at"),
        observed_at,
        max_gap_seconds=TRANSPORT_PREFERRED_EVIDENCE_MAX_GAP_SECONDS,
    )
    recovery = _next_evidence(
        prior,
        key="preferred_recovery",
        path=TRANSPORT_PREFERRED_TAG,
        reason="healthy",
        cycle_relation=recovery_relation,
    )
    prior_recovery = prior.get("preferred_recovery", {})
    continuous_recovery = (
        recovery_relation != "reset"
        and isinstance(prior_recovery, dict)
        and prior_recovery.get("path") == TRANSPORT_PREFERRED_TAG
        and prior_recovery.get("reason") == "healthy"
    )
    recovery_started_at = (
        str(prior_recovery.get("started_at", ""))
        if continuous_recovery and prior_recovery.get("started_at")
        else observed_at
    )
    started = _parse_timestamp(recovery_started_at)
    observed = _parse_timestamp(observed_at)
    recovery_seconds = max(0, int((observed - started).total_seconds())) if started and observed else 0
    recovery.update({"started_at": recovery_started_at, "continuous_seconds": recovery_seconds})
    confirmed = (
        recovery["confirmations"] >= TRANSPORT_PREFERRED_RECOVERY_CONFIRMATIONS
        and recovery_seconds >= TRANSPORT_PREFERRED_RECOVERY_MIN_SECONDS
    )
    if confirmed and "preferred_retry" in recovery_details:
        recovery_details["preferred_retry"] = {
            **recovery_details["preferred_retry"],
            "recovered_at": observed_at,
        }
    recovery_details["preferred_recovery"] = recovery
    recovery_details["preferred_probe_at"] = observed_at
    return _policy_state(
        selected,
        normalized,
        observed_at,
        "recovering",
        (
            "preferred underlay is confirmed healthy"
            if confirmed
            else (
                f"preferred underlay recovery confirmation "
                f"{recovery['confirmations']}/{TRANSPORT_PREFERRED_RECOVERY_CONFIRMATIONS}, "
                f"stable {recovery_seconds}/{TRANSPORT_PREFERRED_RECOVERY_MIN_SECONDS}s"
            )
        ),
        recommended=TRANSPORT_PREFERRED_TAG if confirmed else None,
        **recovery_details,
    )
