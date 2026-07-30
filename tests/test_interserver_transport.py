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

    def test_transport_password_rejects_invalid_root_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "preshared key"):
            derive_transport_password("not-base64")


class InterserverTransportPolicyTests(unittest.TestCase):
    def test_rejects_an_unknown_selected_transport(self) -> None:
        result = evaluate_transport_policy(selected="unknown", probes=probes())
        self.assertEqual(result["state"], "failed")
        self.assertFalse(result["would_switch"])

    def test_confirms_hard_failure_before_recommending_fallback(self) -> None:
        first = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes=probes(primary_delay=0),
            observed_at="2026-07-30T20:00:00+00:00",
        )
        second = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes=probes(primary_delay=0),
            previous=first,
            observed_at="2026-07-30T20:00:05+00:00",
        )
        self.assertEqual(first["state"], "suspect")
        self.assertFalse(first["would_switch"])
        self.assertTrue(second["would_switch"])
        self.assertEqual(second["recommended"], TRANSPORT_FALLBACK_TAG)

    def test_confirms_sustained_quality_difference_before_switching(self) -> None:
        state: dict[str, object] = {}
        results = []
        for index in range(3):
            state = evaluate_transport_policy(
                selected=TRANSPORT_PRIMARY_TAG,
                probes=probes(primary_delay=180, fallback_delay=70),
                previous=state,
                observed_at=f"2026-07-30T20:00:{index * 5:02d}+00:00",
            )
            results.append(state)
        self.assertEqual([item["would_switch"] for item in results], [False, False, True])
        self.assertEqual(results[-1]["recommended"], TRANSPORT_FALLBACK_TAG)

    def test_global_udp_errors_are_diagnostic_only(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes=probes(primary_delay=50, fallback_delay=80),
            passive_deltas={"udp_receive_drops": 10_000, "udp_send_drops": 10_000},
        )
        self.assertEqual(result["state"], "healthy")
        self.assertFalse(result["would_switch"])

    def test_external_selector_change_resets_pending_confirmation(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes=probes(primary_delay=180, fallback_delay=70),
            previous={
                "selected": TRANSPORT_FALLBACK_TAG,
                "pending_target": TRANSPORT_FALLBACK_TAG,
                "pending_cycles": 2,
            },
        )
        self.assertEqual(result["pending_cycles"], 1)
        self.assertFalse(result["would_switch"])

    def test_attributed_socket_loss_still_requires_quality_confirmation(self) -> None:
        state: dict[str, object] = {}
        for index in range(3):
            state = evaluate_transport_policy(
                selected=TRANSPORT_PRIMARY_TAG,
                probes=probes(primary_delay=90, fallback_delay=80),
                previous=state,
                passive_deltas={"hysteria_socket_drops": 2},
                observed_at=f"2026-07-30T20:00:{index * 5:02d}+00:00",
            )
        self.assertTrue(state["would_switch"])
        self.assertIn("primary socket loss", state["reason"])

    def test_primary_recovery_requires_three_confirmations(self) -> None:
        state: dict[str, object] = {}
        results = []
        for index in range(3):
            state = evaluate_transport_policy(
                selected=TRANSPORT_FALLBACK_TAG,
                probes=probes(primary_delay=70, fallback_delay=80),
                previous=state,
                observed_at=f"2026-07-30T20:00:{index * 5:02d}+00:00",
            )
            results.append(state)
        self.assertEqual([item["would_switch"] for item in results], [False, False, True])
        self.assertEqual(results[-1]["recommended"], TRANSPORT_PRIMARY_TAG)

    def test_both_failed_has_no_unsafe_recommendation(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_PRIMARY_TAG,
            probes=probes(primary_delay=0, fallback_delay=0),
        )
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["recommended"], TRANSPORT_PRIMARY_TAG)
        self.assertFalse(result["would_switch"])


if __name__ == "__main__":
    unittest.main()
