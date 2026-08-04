from __future__ import annotations

import base64
import hashlib
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from vpn_installer.interserver_transport import (
    TRANSPORT_FALLBACK_TAG,
    TRANSPORT_PRIMARY_TAG,
    decode_transport_pem,
    derive_transport_obfs_password,
    derive_transport_password,
    evaluate_transport_policy,
    generate_transport_identity,
    validate_transport_identity,
)


def probes(primary_delay: int = 50, fallback_delay: int = 80) -> dict[str, dict[str, object]]:
    return {
        TRANSPORT_PRIMARY_TAG: {"ok": primary_delay > 0, "delay_ms": max(0, primary_delay), "error": ""},
        TRANSPORT_FALLBACK_TAG: {"ok": fallback_delay > 0, "delay_ms": max(0, fallback_delay), "error": ""},
    }


class InterserverTransportIdentityTests(unittest.TestCase):
    def test_generated_identity_has_matching_certificate_key_and_pin(self) -> None:
        identity = generate_transport_identity()
        certificate_pem = "\n".join(
            decode_transport_pem(identity["INTERSERVER_HY2_CERTIFICATE_B64"], "certificate")
        ) + "\n"
        private_key_pem = "\n".join(
            decode_transport_pem(identity["INTERSERVER_HY2_PRIVATE_KEY_B64"], "private key")
        ) + "\n"
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        certificate_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_public = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(certificate_public, private_public)
        self.assertEqual(
            base64.b64encode(hashlib.sha256(certificate_public).digest()).decode("ascii"),
            identity["INTERSERVER_HY2_PUBLIC_KEY_SHA256"],
        )
        validate_transport_identity(identity)

    def test_identity_validation_rejects_a_mismatched_pin(self) -> None:
        identity = generate_transport_identity()
        identity["INTERSERVER_HY2_PUBLIC_KEY_SHA256"] = base64.b64encode(bytes(32)).decode("ascii")
        with self.assertRaisesRegex(ValueError, "pin does not match"):
            validate_transport_identity(identity)

    def test_transport_password_is_stable_and_not_the_wireguard_key(self) -> None:
        preshared_key = base64.b64encode(bytes(range(32))).decode("ascii")
        first = derive_transport_password(preshared_key)
        self.assertEqual(first, derive_transport_password(preshared_key))
        self.assertNotEqual(first, preshared_key)
        self.assertNotIn("=", first)
        self.assertNotEqual(first, derive_transport_obfs_password(preshared_key))

    def test_transport_password_rejects_invalid_root_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "preshared key"):
            derive_transport_password("not-base64")


class InterserverTransportPolicyTests(unittest.TestCase):
    def test_rejects_an_unknown_selected_transport(self) -> None:
        result = evaluate_transport_policy(selected="unknown", probes=probes())
        self.assertEqual(result["state"], "failed")
        self.assertFalse(result["would_switch"])

    def test_primary_success_does_not_require_a_fallback_probe(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes={
                TRANSPORT_PRIMARY_TAG: {"checked": True, "ok": True, "delay_ms": 50},
                TRANSPORT_FALLBACK_TAG: {"checked": False, "ok": False, "attempts": 0},
            },
        )
        self.assertEqual(result["state"], "healthy")
        self.assertFalse(result["probes"][TRANSPORT_FALLBACK_TAG]["checked"])

    def test_one_failure_is_suspect_without_switching(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes=probes(primary_delay=0),
        )
        self.assertEqual(result["state"], "suspect")
        self.assertFalse(result["would_switch"])

    def test_two_failures_with_reachable_fallback_switch_immediately(self) -> None:
        failed_primary = {"ok": False, "attempts": 2, "delay_ms": 0, "error": "timeout"}
        result = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes={
                TRANSPORT_PRIMARY_TAG: failed_primary,
                TRANSPORT_FALLBACK_TAG: {"ok": True, "delay_ms": 70},
            },
        )
        self.assertTrue(result["would_switch"])
        self.assertEqual(result["recommended"], TRANSPORT_FALLBACK_TAG)
        self.assertTrue(result["hard_failure_evidence"])

    def test_latency_difference_alone_never_changes_transport(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes=probes(primary_delay=500, fallback_delay=50),
        )
        self.assertEqual(result["state"], "healthy")
        self.assertFalse(result["would_switch"])

    def test_primary_recovery_requires_two_confirmations(self) -> None:
        state: dict[str, object] = {}
        results = []
        for index in range(2):
            state = evaluate_transport_policy(
                selected=TRANSPORT_FALLBACK_TAG,
                probes=probes(primary_delay=70, fallback_delay=80),
                previous=state,
                observed_at=f"2026-07-30T20:00:{index * 5:02d}+00:00",
            )
            results.append(state)
        self.assertEqual([item["would_switch"] for item in results], [False, True])
        self.assertEqual(results[-1]["recommended"], TRANSPORT_PRIMARY_TAG)

    def test_fallback_failure_returns_to_reachable_primary_after_confirmation(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_FALLBACK_TAG,
            probes={
                TRANSPORT_PRIMARY_TAG: {"ok": True, "delay_ms": 60},
                TRANSPORT_FALLBACK_TAG: {"ok": False, "attempts": 2, "error": "timeout"},
            },
        )
        self.assertTrue(result["would_switch"])
        self.assertEqual(result["recommended"], TRANSPORT_PRIMARY_TAG)

    def test_both_failed_has_no_unsafe_recommendation(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes={
                TRANSPORT_PRIMARY_TAG: {"ok": False, "attempts": 2, "error": "timeout"},
                TRANSPORT_FALLBACK_TAG: {"ok": False, "error": "timeout"},
            },
        )
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["recommended"], TRANSPORT_PRIMARY_TAG)
        self.assertFalse(result["would_switch"])


if __name__ == "__main__":
    unittest.main()
