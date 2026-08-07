from __future__ import annotations

import base64
import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Any

HY2_PORT = 18443
HY2_SERVER_NAME = "vpn-stack.internal"
HY2_CLASH_API_LISTEN = "127.0.0.1:19090"
TRANSPORT_OVERLAY_TAG = "to-foreign"
TRANSPORT_WG_TAG = "interserver-underlay-wg"
TRANSPORT_HY2_TAG = "interserver-underlay-hy2"
TRANSPORT_CANDIDATE_TAGS = (TRANSPORT_WG_TAG, TRANSPORT_HY2_TAG)
TRANSPORT_RELAY_INBOUND_TAGS = {
    TRANSPORT_WG_TAG: "interserver-overlay-wg-in",
    TRANSPORT_HY2_TAG: "interserver-overlay-hy2-in",
}
TRANSPORT_RELAY_PORTS = {
    TRANSPORT_WG_TAG: 19091,
    TRANSPORT_HY2_TAG: 19092,
}
TRANSPORT_PROBE_INBOUND_TAGS = {
    TRANSPORT_WG_TAG: "interserver-probe-wg-in",
    TRANSPORT_HY2_TAG: "interserver-probe-hy2-in",
}
TRANSPORT_PROBE_PORTS = {
    TRANSPORT_WG_TAG: 19093,
    TRANSPORT_HY2_TAG: 19094,
}
TRANSPORT_HEALTHCHECK_URL = "https://1.1.1.1/cdn-cgi/trace"
TRANSPORT_SELECTED_PROBE_TIMEOUT_MS = 800
TRANSPORT_PROBE_TIMEOUT_MS = 1200
TRANSPORT_PROBE_INTERVAL_SECONDS = 2
TRANSPORT_FAILURE_CONFIRMATIONS = 2
TRANSPORT_ALTERNATE_HEALTH_CONFIRMATIONS = 2
TRANSPORT_EVIDENCE_MAX_GAP_SECONDS = TRANSPORT_PROBE_INTERVAL_SECONDS * 5
TRANSPORT_PREFERRED_TAG = TRANSPORT_WG_TAG
TRANSPORT_STATE_SCHEMA_VERSION = 7
UNDERLAY_WG_RU_ADDRESS = "10.75.0.1/32"
UNDERLAY_WG_FOREIGN_ADDRESS = "10.75.0.2/32"
UNDERLAY_WG_MTU = 1420
X25519_P = 2**255 - 19
X25519_A24 = 121665


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


def _hysteria_outbound(env: dict[str, str]) -> dict[str, Any]:
    return {
        "type": "hysteria2",
        "tag": TRANSPORT_HY2_TAG,
        "server": env["FOREIGN_PUBLIC_IP"],
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


def _relay_inbounds() -> list[dict[str, Any]]:
    return [
        {
            "type": "direct",
            "tag": TRANSPORT_RELAY_INBOUND_TAGS[tag],
            "listen": "127.0.0.1",
            "listen_port": TRANSPORT_RELAY_PORTS[tag],
            "network": "udp",
        }
        for tag in TRANSPORT_CANDIDATE_TAGS
    ]


def _relay_rules(env: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "inbound": [TRANSPORT_RELAY_INBOUND_TAGS[tag]],
            "action": "route",
            "outbound": tag,
            "override_address": env["FOREIGN_PUBLIC_IP"],
            "override_port": int(env["WG_PORT"]),
        }
        for tag in TRANSPORT_CANDIDATE_TAGS
    ]


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
                "address": env["FOREIGN_PUBLIC_IP"],
                "port": int(env["WG_PORT"]),
                "public_key": env["WG_FOREIGN_PUBLIC_KEY"],
                "pre_shared_key": identity["pre_shared_key"],
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            }
        ],
        "routing_mark": int(env["WG_TUNNEL_FWMARK"]),
    }
    return {
        "endpoints": [endpoint],
        "inbounds": [*_relay_inbounds(), *_probe_inbounds()],
        "outbounds": [_hysteria_outbound(env)],
        "route_rules": [*_relay_rules(env), *_probe_rules()],
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
        outbounds = by_tag(config.get("outbounds", []))
        stable_overlay = outbounds.get(TRANSPORT_OVERLAY_TAG, {})
        wireguard = by_tag(config.get("endpoints", [])).get(TRANSPORT_WG_TAG, {})
        expected_hysteria = _hysteria_outbound(env)
        expected_inbounds = [*_relay_inbounds(), *_probe_inbounds()]
        expected_rules = [*_relay_rules(env), *_probe_rules()]
    except (KeyError, TypeError, ValueError):
        return False
    if stable_overlay.get("type") != "direct" or stable_overlay.get("bind_interface") != env.get("WG_INTERFACE", "wg0"):
        return False
    if outbounds.get(TRANSPORT_HY2_TAG) != expected_hysteria:
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
        and peer.get("address") == env.get("FOREIGN_PUBLIC_IP")
        and peer.get("port") == int(env.get("WG_PORT", "0") or 0)
        and bool(peer.get("pre_shared_key"))
    ):
        return False
    rules = config.get("route", {}).get("rules", [])
    return isinstance(rules, list) and all(rule in rules for rule in expected_rules)


def _normalize_probe(probe: dict[str, Any] | None) -> dict[str, Any]:
    probe = probe or {}
    checked = probe.get("checked") is True if "checked" in probe else bool(probe)
    return {
        "checked": checked,
        "ok": checked and probe.get("ok") is True,
        "attempts": max(0, int(probe.get("attempts", 1 if checked else 0) or 0)),
        "delay_ms": max(0, int(probe.get("delay_ms", 0) or 0)),
        "error": str(probe.get("error", ""))[:240],
    }


def _probe_failure_reason(probe: dict[str, Any]) -> str:
    error = " ".join(str(probe.get("error", "")).lower().split())
    categories = (
        ("timeout", ("timed out", "timeout", "deadline")),
        ("connection_refused", ("connection refused",)),
        ("network_unreachable", ("network is unreachable", "no route to host")),
        ("host_unreachable", ("host is unreachable",)),
        ("tls_failure", ("certificate", "tls")),
        ("invalid_probe_response", ("delay result is missing",)),
    )
    return next((reason for reason, markers in categories if any(marker in error for marker in markers)), error[:120] or "probe_failed")


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


def _cycle_relation(previous_at: Any, observed_at: str) -> str:
    previous_time = _parse_timestamp(previous_at)
    current_time = _parse_timestamp(observed_at)
    if previous_time is None or current_time is None:
        return "reset"
    gap_seconds = (current_time - previous_time).total_seconds()
    if gap_seconds == 0:
        return "same"
    if 0 < gap_seconds <= TRANSPORT_EVIDENCE_MAX_GAP_SECONDS:
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
        # Retained as inert fields for readers of schema 6 state.
        "latency_candidate": "",
        "latency_confirmations": 0,
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
    previous = previous if isinstance(previous, dict) and previous.get("schema_version") in {6, TRANSPORT_STATE_SCHEMA_VERSION} else {}
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

    # Missing observations are not path failures. Simultaneous failures against
    # the shared target cannot identify a bad underlay and must never trigger a switch.
    if not selected_probe["checked"]:
        return _policy_state(selected, normalized, observed_at, "inconclusive", "selected underlay was not probed")
    if not selected_probe["ok"] and alternate_probe["checked"] and not alternate_probe["ok"]:
        return _policy_state(
            selected,
            normalized,
            observed_at,
            "inconclusive",
            "both underlays failed against the shared probe target; path failure is not attributable",
        )
    if not selected_probe["ok"]:
        failure_reason = _probe_failure_reason(selected_probe)
        failure = _next_evidence(
            prior,
            key="failure",
            path=selected,
            reason=failure_reason,
            cycle_relation=cycle_relation,
        )
        confirmed_failure = failure["confirmations"] >= TRANSPORT_FAILURE_CONFIRMATIONS
        state = "failed" if confirmed_failure and not alternate_probe["ok"] else "suspect"
        reason = (
            f"{selected} {failure_reason} confirmation "
            f"{failure['confirmations']}/{TRANSPORT_FAILURE_CONFIRMATIONS}"
        )
        details: dict[str, Any] = {"failure": failure}
        recommended: str | None = None
        if alternate_probe["ok"]:
            alternate_health = _next_evidence(
                prior,
                key="alternate_health",
                path=alternate,
                reason="healthy",
                cycle_relation=cycle_relation,
            )
            details["alternate_health"] = alternate_health
            if (
                confirmed_failure
                and alternate_health["confirmations"] >= TRANSPORT_ALTERNATE_HEALTH_CONFIRMATIONS
            ):
                state = "recovering"
                recommended = alternate
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

    return _policy_state(selected, normalized, observed_at, "healthy", "selected underlay is healthy and remains sticky")
