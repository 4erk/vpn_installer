from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone

HY2_PORT = 18443
HY2_SERVER_NAME = "vpn-stack.internal"
HY2_CLASH_API_LISTEN = "127.0.0.1:19090"
TRANSPORT_SELECTOR_TAG = "to-foreign"
TRANSPORT_WG_TAG = "to-foreign-wg"
TRANSPORT_HY2_TAG = "to-foreign-hy2"
TRANSPORT_CANDIDATE_TAGS = (TRANSPORT_HY2_TAG, TRANSPORT_WG_TAG)
TRANSPORT_HEALTHCHECK_URL = "https://1.1.1.1/cdn-cgi/trace"
TRANSPORT_PROBE_TIMEOUT_MS = 1200
TRANSPORT_URLTEST_INTERVAL = "10s"
TRANSPORT_URLTEST_INTERVAL_SECONDS = 10
TRANSPORT_URLTEST_TOLERANCE_MS = 30
TRANSPORT_URLTEST_IDLE_TIMEOUT = "30m"


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
