from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any

HY2_PORT = 18443
HY2_SERVER_NAME = "vpn-stack.internal"
HY2_CLASH_API_LISTEN = "127.0.0.1:19090"
TRANSPORT_SELECTOR_TAG = "to-foreign"
TRANSPORT_PRIMARY_TAG = "to-foreign-wg"
TRANSPORT_FALLBACK_TAG = "to-foreign-hy2"
TRANSPORT_HEALTHCHECK_URL = "https://1.1.1.1/cdn-cgi/trace"
TRANSPORT_PROBE_TIMEOUT_MS = 1200
TRANSPORT_PROBE_INTERVAL_SECONDS = 2
TRANSPORT_FAILURE_CONFIRMATIONS = 2
TRANSPORT_PRIMARY_RECOVERY_SUCCESSES = 2
TRANSPORT_STATE_SCHEMA_VERSION = 4


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


def evaluate_transport_policy(
    *,
    selected: str,
    probes: dict[str, dict[str, Any]],
    previous: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic recommendation without changing the selector."""

    previous = previous or {}
    observed_at = observed_at or datetime.now(timezone.utc).isoformat()
    if selected not in {TRANSPORT_PRIMARY_TAG, TRANSPORT_FALLBACK_TAG}:
        return {
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": observed_at,
            "state": "failed",
            "selected": selected,
            "recommended": selected,
            "would_switch": False,
            "primary_recovery_successes": 0,
            "hard_failure_evidence": False,
            "probes": {},
            "reason": "selected transport is invalid",
        }

    normalized_probes = {
        tag: _normalize_probe(probes.get(tag))
        for tag in (TRANSPORT_PRIMARY_TAG, TRANSPORT_FALLBACK_TAG)
    }
    primary = normalized_probes[TRANSPORT_PRIMARY_TAG]
    fallback = normalized_probes[TRANSPORT_FALLBACK_TAG]
    selected_probe = normalized_probes[selected]
    alternate = TRANSPORT_FALLBACK_TAG if selected == TRANSPORT_PRIMARY_TAG else TRANSPORT_PRIMARY_TAG
    alternate_probe = normalized_probes[alternate]
    recovery_successes = 0
    recommended = selected
    state = "healthy" if selected == TRANSPORT_PRIMARY_TAG else "degraded"
    hard_failure = False
    evidence = "selected transport is healthy"

    if not selected_probe["checked"]:
        state = "failed"
        evidence = "selected transport was not probed"
    elif selected_probe["ok"]:
        if selected == TRANSPORT_FALLBACK_TAG:
            previous_successes = (
                int(previous.get("primary_recovery_successes", 0) or 0)
                if previous.get("selected") == selected
                else 0
            )
            if primary["checked"] and primary["ok"]:
                recovery_successes = previous_successes + 1
                state = "recovering"
                evidence = (
                    "primary recovery confirmed"
                    if recovery_successes >= TRANSPORT_PRIMARY_RECOVERY_SUCCESSES
                    else f"primary recovery confirmation {recovery_successes}/{TRANSPORT_PRIMARY_RECOVERY_SUCCESSES}"
                )
                if recovery_successes >= TRANSPORT_PRIMARY_RECOVERY_SUCCESSES:
                    recommended = TRANSPORT_PRIMARY_TAG
            else:
                evidence = "fallback transport remains healthy"
        elif selected_probe["attempts"] > 1:
            evidence = "primary recovered during immediate confirmation"
    elif selected_probe["attempts"] < TRANSPORT_FAILURE_CONFIRMATIONS:
        state = "suspect"
        evidence = f"{selected} failed once; immediate confirmation is required"
    elif alternate_probe["checked"] and alternate_probe["ok"]:
        hard_failure = True
        recommended = alternate
        state = "degraded" if alternate == TRANSPORT_FALLBACK_TAG else "recovering"
        evidence = f"{selected} failed twice while {alternate} is reachable"
    elif alternate_probe["checked"]:
        state = "failed"
        hard_failure = True
        evidence = "both interserver transports failed"
    else:
        state = "failed"
        hard_failure = True
        evidence = f"{selected} failed twice and alternate transport was not probed"

    return {
        "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
        "updated_at": observed_at,
        "state": state,
        "selected": selected,
        "recommended": recommended,
        "would_switch": recommended != selected,
        "primary_recovery_successes": recovery_successes,
        "hard_failure_evidence": hard_failure,
        "probes": normalized_probes,
        "reason": evidence,
    }


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


def _derive_transport_secret(wireguard_preshared_key: str, context: bytes) -> str:
    try:
        root_key = base64.b64decode(wireguard_preshared_key, validate=True)
    except ValueError as exc:
        raise ValueError("invalid WireGuard preshared key") from exc
    if len(root_key) != 32:
        raise ValueError("invalid WireGuard preshared key length")
    token = hmac.new(root_key, context, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")


def derive_transport_password(wireguard_preshared_key: str) -> str:
    return _derive_transport_secret(wireguard_preshared_key, b"vpn-stack/interserver/hysteria2/auth/v1")


def derive_transport_obfs_password(wireguard_preshared_key: str) -> str:
    return _derive_transport_secret(wireguard_preshared_key, b"vpn-stack/interserver/hysteria2/obfs/v1")
