from __future__ import annotations

import base64
import hashlib
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from vpn_installer.config import generate_default_env
from vpn_installer.interserver_transport import (
    TRANSPORT_HY2_TAG,
    TRANSPORT_OVERLAY_TAG,
    TRANSPORT_RELAY_INBOUND_TAGS,
    TRANSPORT_RELAY_PORTS,
    TRANSPORT_WG_TAG,
    build_ru_transport_topology,
    decode_transport_pem,
    derive_underlay_wireguard_identity,
    derive_transport_obfs_password,
    derive_transport_password,
    evaluate_transport_policy,
    generate_transport_identity,
    transport_topology_configured,
    validate_transport_identity,
)


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

    def test_underlay_wireguard_identity_is_deterministic_and_separate(self) -> None:
        preshared_key = base64.b64encode(bytes(range(32))).decode("ascii")
        first = derive_underlay_wireguard_identity(preshared_key)
        self.assertEqual(first, derive_underlay_wireguard_identity(preshared_key))
        self.assertNotEqual(first["pre_shared_key"], preshared_key)
        self.assertEqual(len(base64.b64decode(first["private_key"])), 32)
        self.assertEqual(len(base64.b64decode(first["public_key"])), 32)

    def test_topology_compiles_two_static_relays_without_application_selector(self) -> None:
        env = generate_default_env("demo")
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        topology = build_ru_transport_topology(env)
        self.assertEqual(
            {item["tag"]: item["listen_port"] for item in topology["inbounds"]},
            {tag: TRANSPORT_RELAY_PORTS[candidate] for candidate, tag in TRANSPORT_RELAY_INBOUND_TAGS.items()},
        )
        self.assertEqual(
            [rule["outbound"] for rule in topology["route_rules"]],
            [TRANSPORT_WG_TAG, TRANSPORT_HY2_TAG],
        )
        self.assertFalse(any(item.get("type") == "selector" for item in topology["outbounds"]))

    def test_topology_validation_uses_the_compiled_model(self) -> None:
        env = generate_default_env("demo")
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        topology = build_ru_transport_topology(env)
        config = {
            "endpoints": topology["endpoints"],
            "inbounds": topology["inbounds"],
            "outbounds": [
                {"type": "direct", "tag": TRANSPORT_OVERLAY_TAG, "bind_interface": env["WG_INTERFACE"]},
                *topology["outbounds"],
            ],
            "route": {"rules": topology["route_rules"]},
        }
        self.assertTrue(transport_topology_configured(config, env))
        config["inbounds"][0]["listen_port"] += 1
        self.assertFalse(transport_topology_configured(config, env))

    def test_policy_switches_only_after_confirmed_failure(self) -> None:
        first = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 1},
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
            },
        )
        confirmed = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 2},
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
            },
        )
        self.assertEqual(first["state"], "suspect")
        self.assertFalse(first["would_switch"])
        self.assertTrue(confirmed["would_switch"])
        self.assertEqual(confirmed["recommended"], TRANSPORT_HY2_TAG)

    def test_policy_requires_stable_latency_advantage_and_resets_on_recovery(self) -> None:
        state: dict[str, object] = {}
        probes = {
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 100},
            TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 40},
        }
        for expected_confirmation in (1, 2, 3):
            state = evaluate_transport_policy(selected=TRANSPORT_HY2_TAG, probes=probes, previous=state)
            self.assertEqual(state["latency_confirmations"], expected_confirmation)
        self.assertTrue(state["would_switch"])
        self.assertEqual(state["recommended"], TRANSPORT_WG_TAG)

        recovered = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes={
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 60},
                TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 50},
            },
            previous=state,
        )
        self.assertFalse(recovered["would_switch"])
        self.assertEqual(recovered["latency_confirmations"], 0)

if __name__ == "__main__":
    unittest.main()
