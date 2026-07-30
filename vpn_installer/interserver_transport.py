from __future__ import annotations

import base64
import hashlib
import hmac
import statistics
from datetime import datetime, timezone
from typing import Any

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
TRANSPORT_PRIMARY_RECOVERY_SUCCESSES = 3
TRANSPORT_QUALITY_CONFIRMATIONS = 3
TRANSPORT_DELAY_TOLERANCE_MS = 50
TRANSPORT_HISTORY_LIMIT = 12
TRANSPORT_STATE_SCHEMA_VERSION = 2


def _successful_delays(history: list[dict[str, Any]]) -> list[int]:
    return [
        int(sample["delay_ms"])
        for sample in history
        if sample.get("ok") is True and int(sample.get("delay_ms", 0) or 0) > 0
    ]


def _candidate_score(history: list[dict[str, Any]]) -> dict[str, Any]:
    delays = _successful_delays(history)
    if not delays:
        return {"available": False, "samples": 0, "delay_ms": None, "jitter_ms": None}
    median = float(statistics.median(delays))
    deviations = [abs(value - median) for value in delays]
    return {
        "available": True,
        "samples": len(delays),
        "delay_ms": round(median, 1),
        "jitter_ms": round(float(statistics.median(deviations)), 1),
    }


def _append_probe_history(
    previous: dict[str, Any],
    probes: dict[str, dict[str, Any]],
    observed_at: str,
) -> dict[str, list[dict[str, Any]]]:
    previous_history = previous.get("history", {}) if isinstance(previous, dict) else {}
    history: dict[str, list[dict[str, Any]]] = {}
    for tag in (TRANSPORT_PRIMARY_TAG, TRANSPORT_FALLBACK_TAG):
        prior = previous_history.get(tag, []) if isinstance(previous_history, dict) else []
        samples = [dict(sample) for sample in prior if isinstance(sample, dict)]
        probe = probes.get(tag, {})
        samples.append(
            {
                "observed_at": observed_at,
                "ok": probe.get("ok") is True,
                "delay_ms": int(probe.get("delay_ms", 0) or 0),
                "error": str(probe.get("error", ""))[:160],
            }
        )
        history[tag] = samples[-TRANSPORT_HISTORY_LIMIT:]
    return history


def evaluate_transport_policy(
    *,
    selected: str,
    probes: dict[str, dict[str, Any]],
    previous: dict[str, Any] | None = None,
    passive_deltas: dict[str, int] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic recommendation without changing the selector."""

    previous = previous or {}
    passive_deltas = passive_deltas or {}
    observed_at = observed_at or datetime.now(timezone.utc).isoformat()
    if selected not in {TRANSPORT_PRIMARY_TAG, TRANSPORT_FALLBACK_TAG}:
        return {
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": observed_at,
            "state": "failed",
            "selected": selected,
            "recommended": selected,
            "would_switch": False,
            "pending_target": "",
            "pending_cycles": 0,
            "hard_failure_evidence": False,
            "probes": {},
            "scores": {},
            "history": {},
            "passive_deltas": dict(passive_deltas),
            "reason": "selected transport is invalid",
        }

    normalized_probes = {
        tag: {
            "ok": probes.get(tag, {}).get("ok") is True,
            "delay_ms": int(probes.get(tag, {}).get("delay_ms", 0) or 0),
            "error": str(probes.get(tag, {}).get("error", ""))[:240],
        }
        for tag in (TRANSPORT_PRIMARY_TAG, TRANSPORT_FALLBACK_TAG)
    }
    history = _append_probe_history(previous, normalized_probes, observed_at)
    scores = {tag: _candidate_score(samples) for tag, samples in history.items()}
    primary = normalized_probes[TRANSPORT_PRIMARY_TAG]
    fallback = normalized_probes[TRANSPORT_FALLBACK_TAG]
    selected_probe = normalized_probes[selected]
    alternate = TRANSPORT_FALLBACK_TAG if selected == TRANSPORT_PRIMARY_TAG else TRANSPORT_PRIMARY_TAG
    alternate_probe = normalized_probes[alternate]
    hysteria_socket_drops = max(0, int(passive_deltas.get("hysteria_socket_drops", 0) or 0))

    desired = selected
    evidence = "selected transport is healthy"
    required_confirmations = TRANSPORT_QUALITY_CONFIRMATIONS
    hard_failure = False
    if not primary["ok"] and not fallback["ok"]:
        return {
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": observed_at,
            "state": "failed",
            "selected": selected,
            "recommended": selected,
            "would_switch": False,
            "pending_target": "",
            "pending_cycles": 0,
            "hard_failure_evidence": True,
            "probes": normalized_probes,
            "scores": scores,
            "history": history,
            "passive_deltas": dict(passive_deltas),
            "reason": "both interserver transports failed",
        }
    if not selected_probe["ok"] and alternate_probe["ok"]:
        desired = alternate
        hard_failure = True
        required_confirmations = TRANSPORT_PRIMARY_FAILURES
        evidence = f"{selected} failed while {alternate} is reachable"
    elif primary["ok"] and fallback["ok"]:
        primary_delay = float(scores[TRANSPORT_PRIMARY_TAG]["delay_ms"] or primary["delay_ms"])
        fallback_delay = float(scores[TRANSPORT_FALLBACK_TAG]["delay_ms"] or fallback["delay_ms"])
        if selected == TRANSPORT_PRIMARY_TAG:
            primary_slower = primary_delay > fallback_delay + TRANSPORT_DELAY_TOLERANCE_MS
            passive_loss_confirmed = hysteria_socket_drops > 0 and primary_delay > fallback_delay
            if primary_slower or passive_loss_confirmed:
                desired = TRANSPORT_FALLBACK_TAG
                if passive_loss_confirmed:
                    evidence = (
                        "primary socket loss and delay are worse than fallback "
                        f"(drops={hysteria_socket_drops})"
                    )
                else:
                    evidence = f"primary delay exceeds fallback by more than {TRANSPORT_DELAY_TOLERANCE_MS}ms"
        elif primary_delay <= fallback_delay + TRANSPORT_DELAY_TOLERANCE_MS:
            desired = TRANSPORT_PRIMARY_TAG
            required_confirmations = TRANSPORT_PRIMARY_RECOVERY_SUCCESSES
            evidence = "primary recovered within the preferred-path tolerance"

    same_selection = previous.get("selected") == selected
    previous_target = str(previous.get("pending_target", "")) if same_selection else ""
    previous_cycles = int(previous.get("pending_cycles", 0) or 0) if same_selection else 0
    pending_cycles = previous_cycles + 1 if previous_target == desired and desired != selected else 1
    pending_target = desired if desired != selected else ""
    if desired == selected:
        pending_cycles = 0
    confirmed = desired != selected and pending_cycles >= required_confirmations
    recommended = desired if confirmed else selected

    if confirmed:
        state = "degraded" if recommended == TRANSPORT_FALLBACK_TAG else "recovering"
    elif desired != selected:
        state = "suspect" if selected == TRANSPORT_PRIMARY_TAG else "recovering"
        evidence += f"; awaiting confirmation {pending_cycles}/{required_confirmations}"
    elif selected == TRANSPORT_FALLBACK_TAG:
        state = "degraded"
        evidence = "fallback transport remains selected"
    else:
        state = "healthy"

    return {
        "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
        "updated_at": observed_at,
        "state": state,
        "selected": selected,
        "recommended": recommended,
        "would_switch": recommended != selected,
        "pending_target": pending_target,
        "pending_cycles": pending_cycles,
        "hard_failure_evidence": hard_failure,
        "probes": normalized_probes,
        "scores": scores,
        "history": history,
        "passive_deltas": dict(passive_deltas),
        "reason": evidence,
    }


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
