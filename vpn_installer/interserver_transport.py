from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone

HY2_PORT = 18443
HY2_SERVER_NAME = "vpn-stack.internal"
HY2_CLASH_API_LISTEN = "127.0.0.1:19090"
TRANSPORT_SELECTOR_TAG = "to-foreign"
TRANSPORT_PRIMARY_TAG = "to-foreign-hy2"
TRANSPORT_FALLBACK_TAG = "to-foreign-wg"
TRANSPORT_HEALTHCHECK_URL = "https://1.1.1.1/cdn-cgi/trace"
TRANSPORT_PROBE_TIMEOUT_MS = 2500
TRANSPORT_PROBE_INTERVAL_SECONDS = 5
TRANSPORT_PRIMARY_FAILURES = 2
TRANSPORT_PRIMARY_RECOVERY_SUCCESSES = 2


def generate_transport_identity() -> dict[str, str]:
    """Generate a pinned self-signed identity stored with the deployment."""

    from .runtime_deps import ensure_python_package

    ensure_python_package("cryptography", "cryptography>=45,<47")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
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

    ensure_python_package("cryptography", "cryptography>=45,<47")
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
    now = datetime.now(timezone.utc)
    if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
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


def derive_transport_password(wireguard_preshared_key: str) -> str:
    try:
        root_key = base64.b64decode(wireguard_preshared_key, validate=True)
    except ValueError as exc:
        raise ValueError("invalid WireGuard preshared key") from exc
    if len(root_key) != 32:
        raise ValueError("invalid WireGuard preshared key length")
    token = hmac.new(root_key, b"vpn-stack/interserver/hysteria2/auth/v1", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")
