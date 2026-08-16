from __future__ import annotations

import base64
import hashlib
import json
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from vpn_installer.config import generate_default_env
from vpn_installer.interserver_transport import (
    TRANSPORT_CANDIDATE_TAGS,
    TRANSPORT_HY2_TAG,
    TRANSPORT_OVERLAY_TAG,
    TRANSPORT_PREFERRED_TAG,
    TRANSPORT_PROBE_INBOUND_TAGS,
    TRANSPORT_PROBE_PORTS,
    TRANSPORT_RELAY_INBOUND_TAG,
    TRANSPORT_RELAY_PORT,
    TRANSPORT_SELECTOR_TAG,
    TRANSPORT_STATE_SCHEMA_VERSION,
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
    x25519_public_from_private,
)


def canonical_dual_env(name: str = "demo") -> dict[str, str]:
    env = generate_default_env(name)
    env.update(
        {
            "CONFIG_SCHEMA": "2",
            "TOPOLOGY": "dual",
            "GATEWAY_LOCATION": "ru",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "EXIT_PUBLIC_IP": "198.51.100.20",
        }
    )
    env.pop("RU_PUBLIC_IP", None)
    env.pop("FOREIGN_PUBLIC_IP", None)
    return env


class InterserverTransportIdentityTests(unittest.TestCase):
    def test_stdlib_x25519_matches_rfc_7748_vector(self) -> None:
        private_key = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        expected_public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

        self.assertEqual(x25519_public_from_private(private_key), expected_public)

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

    def test_topology_compiles_one_stable_relay_with_an_underlay_selector(self) -> None:
        env = canonical_dual_env()
        topology = build_ru_transport_topology(env)
        self.assertEqual(
            {item["tag"]: item["listen_port"] for item in topology["inbounds"]},
            {
                TRANSPORT_RELAY_INBOUND_TAG: TRANSPORT_RELAY_PORT,
                **{tag: TRANSPORT_PROBE_PORTS[candidate] for candidate, tag in TRANSPORT_PROBE_INBOUND_TAGS.items()},
            },
        )
        self.assertEqual(
            [rule["outbound"] for rule in topology["route_rules"]],
            [TRANSPORT_SELECTOR_TAG, TRANSPORT_WG_TAG, TRANSPORT_HY2_TAG],
        )
        selector = next(item for item in topology["outbounds"] if item.get("tag") == TRANSPORT_SELECTOR_TAG)
        self.assertEqual(
            selector,
            {
                "type": "selector",
                "tag": TRANSPORT_SELECTOR_TAG,
                "outbounds": list(TRANSPORT_CANDIDATE_TAGS),
                "default": TRANSPORT_PREFERRED_TAG,
                "interrupt_exist_connections": True,
            },
        )

    def test_topology_validation_uses_the_compiled_model(self) -> None:
        env = canonical_dual_env()
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

    def test_canonical_dual_transport_output_is_byte_stable(self) -> None:
        env = canonical_dual_env("transport-golden")
        env.update(
            {
                "WG_PRESHARED_KEY": base64.b64encode(bytes(range(32))).decode("ascii"),
                "WG_FOREIGN_PUBLIC_KEY": "foreign-public-key",
                "INTERSERVER_HY2_PUBLIC_KEY_SHA256": "transport-pin",
                "WG_TUNNEL_FWMARK": "51820",
                "WG_PORT": "51820",
            }
        )
        payload = json.dumps(build_ru_transport_topology(env), sort_keys=True, separators=(",", ":"))

        self.assertEqual(
            hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "25b3b25f46c98c59ca6425d474e92fef2862f316896bed29dfd890efaf8a37c5",
        )

    def test_interserver_transport_rejects_legacy_address_aliases(self) -> None:
        env = canonical_dual_env()
        env["FOREIGN_PUBLIC_IP"] = env["EXIT_PUBLIC_IP"]

        with self.assertRaisesRegex(ValueError, "legacy public IP aliases"):
            build_ru_transport_topology(env)

    def test_interserver_transport_rejects_single_topology(self) -> None:
        env = generate_default_env("single", topology="single", gateway_location="ru")
        env.update(
            {
                "CONFIG_SCHEMA": "2",
                "TOPOLOGY": "single",
                "GATEWAY_LOCATION": "ru",
                "GATEWAY_PUBLIC_IP": "203.0.113.10",
                "EXIT_PUBLIC_IP": "",
            }
        )
        env.pop("RU_PUBLIC_IP", None)
        env.pop("FOREIGN_PUBLIC_IP", None)

        with self.assertRaisesRegex(ValueError, "requires a dual topology"):
            build_ru_transport_topology(env)

    def test_policy_switches_only_after_confirmed_failure(self) -> None:
        first = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 2, "error": "timed out"},
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )
        confirmed = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 2, "error": "timed out"},
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
            },
            previous=first,
            observed_at="2026-08-06T12:00:02+00:00",
        )
        self.assertEqual(first["state"], "suspect")
        self.assertFalse(first["would_switch"])
        self.assertEqual(first["failure"]["confirmations"], 1)
        self.assertTrue(confirmed["would_switch"])
        self.assertEqual(confirmed["recommended"], TRANSPORT_HY2_TAG)
        self.assertEqual(confirmed["failure"]["confirmations"], 2)
        self.assertEqual(confirmed["alternate_health"]["confirmations"], 2)

    def test_policy_never_switches_for_latency_advantage(self) -> None:
        state: dict[str, object] = {
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": "2026-08-06T11:59:58+00:00",
            "selected": TRANSPORT_HY2_TAG,
            "latency_candidate": TRANSPORT_WG_TAG,
            "latency_confirmations": 999,
        }
        probes = {
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 800},
            TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 10},
        }
        for second in range(0, 20, 2):
            state = evaluate_transport_policy(
                selected=TRANSPORT_HY2_TAG,
                probes=probes,
                previous=state,
                observed_at=f"2026-08-06T12:00:{second:02d}+00:00",
            )
            self.assertFalse(state["would_switch"])
            self.assertEqual(state["recommended"], TRANSPORT_HY2_TAG)
            self.assertEqual(state["latency_confirmations"], 0)

    def test_unknown_state_schema_cannot_confirm_a_switch(self) -> None:
        stale = {
            "schema_version": 999,
            "updated_at": "2026-08-06T11:59:58+00:00",
            "selected": TRANSPORT_WG_TAG,
            "failure": {"path": TRANSPORT_WG_TAG, "reason": "timed out", "confirmations": 99},
            "alternate_health": {"path": TRANSPORT_HY2_TAG, "reason": "healthy", "confirmations": 99},
        }
        result = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 2, "error": "timed out"},
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
            },
            previous=stale,
            observed_at="2026-08-06T12:00:00+00:00",
        )
        self.assertEqual(result["failure"]["confirmations"], 1)
        self.assertFalse(result["would_switch"])

    def test_policy_requires_the_same_failure_reason_in_separate_cycles(self) -> None:
        probes = {
            TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 2, "error": "timed out"},
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
        }
        first = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            observed_at="2026-08-06T12:00:00+00:00",
        )
        same_cycle = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            previous=first,
            observed_at="2026-08-06T12:00:00+00:00",
        )
        changed_reason = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                **probes,
                TRANSPORT_WG_TAG: {
                    "checked": True,
                    "ok": False,
                    "attempts": 2,
                    "error": "connection refused",
                },
            },
            previous=same_cycle,
            observed_at="2026-08-06T12:00:02+00:00",
        )
        confirmed = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                **probes,
                TRANSPORT_WG_TAG: {
                    "checked": True,
                    "ok": False,
                    "attempts": 2,
                    "error": "connection refused",
                },
            },
            previous=changed_reason,
            observed_at="2026-08-06T12:00:04+00:00",
        )
        self.assertEqual(same_cycle["failure"]["confirmations"], 1)
        self.assertEqual(same_cycle["alternate_health"]["confirmations"], 1)
        self.assertEqual(changed_reason["failure"]["confirmations"], 1)
        self.assertFalse(changed_reason["would_switch"])
        self.assertTrue(confirmed["would_switch"])

    def test_stale_failure_evidence_does_not_confirm_a_new_incident(self) -> None:
        probes = {
            TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 2, "error": "timed out"},
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
        }
        stale = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            observed_at="2026-08-06T12:00:00+00:00",
        )
        fresh = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            previous=stale,
            observed_at="2026-08-06T12:01:00+00:00",
        )
        self.assertEqual(fresh["failure"]["confirmations"], 1)
        self.assertEqual(fresh["alternate_health"]["confirmations"], 1)
        self.assertFalse(fresh["would_switch"])

    def test_failed_switch_requires_fresh_evidence_before_retry(self) -> None:
        probes = {
            TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 2, "error": "timed out"},
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
        }
        first = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            observed_at="2026-08-06T12:00:00+00:00",
        )
        requested = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            previous=first,
            observed_at="2026-08-06T12:00:02+00:00",
        )
        failed_switch = {**requested, "state": "failed"}
        retry = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            previous=failed_switch,
            observed_at="2026-08-06T12:00:04+00:00",
        )
        self.assertTrue(requested["would_switch"])
        self.assertEqual(retry["failure"]["confirmations"], 1)
        self.assertEqual(retry["alternate_health"]["confirmations"], 1)
        self.assertFalse(retry["would_switch"])

    def test_failed_overlay_never_selects_an_unproven_alternate(self) -> None:
        failures = {
            TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 1, "scope": "overlay-dns", "error": "timed out"},
            TRANSPORT_HY2_TAG: {"checked": True, "ok": False, "attempts": 1, "scope": "raw-underlay", "error": "connection refused"},
        }
        first = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=failures,
            observed_at="2026-08-06T12:00:00+00:00",
        )
        second = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=failures,
            previous=first,
            observed_at="2026-08-06T12:00:02+00:00",
        )
        alternate_once = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 1, "scope": "overlay-dns", "error": "timed out"},
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
            },
            previous=second,
            observed_at="2026-08-06T12:00:04+00:00",
        )
        self.assertEqual(first["state"], "suspect")
        self.assertEqual(second["state"], "failed")
        self.assertEqual(second["failure"]["confirmations"], 2)
        self.assertFalse(second["would_switch"])
        self.assertEqual(alternate_once["failure"]["confirmations"], 3)
        self.assertEqual(alternate_once["alternate_health"]["confirmations"], 1)
        self.assertFalse(alternate_once["would_switch"])

    def test_healthy_fallback_returns_to_preferred_after_three_fresh_probes(self) -> None:
        failure = {
            TRANSPORT_HY2_TAG: {"checked": True, "ok": False, "attempts": 2, "error": "timed out"},
            TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 70},
        }
        first = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes=failure,
            observed_at="2026-08-06T12:00:00+00:00",
        )
        switch = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes=failure,
            previous=first,
            observed_at="2026-08-06T12:00:02+00:00",
        )
        self.assertTrue(switch["would_switch"])

        state: dict[str, object] = {
            **switch,
            "selected": TRANSPORT_WG_TAG,
            "would_switch": False,
            "changed": True,
        }
        healthy = {
            TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 40},
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 90},
        }
        for second in (4, 14, 24):
            state = evaluate_transport_policy(
                selected=TRANSPORT_WG_TAG,
                probes=healthy,
                previous=state,
                observed_at=f"2026-08-06T12:00:{second:02d}+00:00",
            )
        self.assertEqual(state["state"], "recovering")
        self.assertEqual(state["selected"], TRANSPORT_WG_TAG)
        self.assertEqual(state["recommended"], TRANSPORT_HY2_TAG)
        self.assertTrue(state["would_switch"])
        self.assertEqual(state["preferred_recovery"]["confirmations"], 3)
        json.dumps(state)

    def test_deferred_cycle_preserves_but_does_not_increment_recovery_evidence(self) -> None:
        first = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 20},
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 50},
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )
        deferred = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 20},
                TRANSPORT_HY2_TAG: {"checked": False, "ok": False},
            },
            previous=first,
            observed_at="2026-08-06T12:00:02+00:00",
        )

        self.assertEqual(first["preferred_recovery"]["confirmations"], 1)
        self.assertEqual(deferred["preferred_recovery"]["confirmations"], 1)
        self.assertEqual(deferred["preferred_probe_at"], first["preferred_probe_at"])
        self.assertFalse(deferred["would_switch"])

if __name__ == "__main__":
    unittest.main()
