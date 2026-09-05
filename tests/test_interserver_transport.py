from __future__ import annotations

import base64
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from vpn_installer.config import generate_default_env
from vpn_installer.interserver_transport import (
    TRANSPORT_CANDIDATE_TAGS,
    TRANSPORT_HY2_TAG,
    TRANSPORT_OVERLAY_TAG,
    TRANSPORT_PREFERRED_TAG,
    TRANSPORT_QUALITY_PROBE_INTERVAL_SECONDS,
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
            "CONFIG_SCHEMA": "3",
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
            "1e94653d45e803d6b61ae43d057a3a63717ea122dc5e1e434a1442adbe288aa9",
        )

    def test_interserver_transport_rejects_single_topology(self) -> None:
        env = generate_default_env("single", topology="single", gateway_location="ru")
        env.update(
            {
                "CONFIG_SCHEMA": "3",
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

    def test_policy_rejects_invalid_selection_and_missing_observation(self) -> None:
        invalid = evaluate_transport_policy(selected="unknown", probes={}, observed_at="2026-08-06T12:00:00+00:00")
        missing = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {"checked": False, "ok": False},
                TRANSPORT_HY2_TAG: {"checked": False, "ok": False},
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )

        self.assertEqual(invalid["state"], "failed")
        self.assertIn("invalid", invalid["reason"])
        self.assertEqual(missing["state"], "inconclusive")
        self.assertIn("not probed", missing["reason"])

    def test_dataplane_confirmations_switch_in_one_cycle(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {
                    "checked": True,
                    "ok": False,
                    "attempts": 2,
                    "failure_confirmed": True,
                    "scope": "overlay-dns",
                    "error": "timed out",
                },
                TRANSPORT_HY2_TAG: {
                    "checked": True,
                    "ok": True,
                    "attempts": 1,
                    "health_confirmed": True,
                    "scope": "raw-underlay-udp",
                },
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )

        self.assertEqual(result["state"], "recovering")
        self.assertTrue(result["hard_failure_evidence"])
        self.assertTrue(result["would_switch"])
        self.assertEqual(result["recommended"], TRANSPORT_HY2_TAG)
        self.assertEqual(result["failure"]["confirmations"], 2)
        self.assertEqual(result["alternate_health"]["confirmations"], 2)

    def test_policy_never_switches_for_latency_advantage(self) -> None:
        state: dict[str, object] = {
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": "2026-08-06T11:59:58+00:00",
            "selected": TRANSPORT_WG_TAG,
            "latency_candidate": TRANSPORT_HY2_TAG,
            "latency_confirmations": 999,
        }
        probes = {
            TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 800},
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 10},
        }
        for second in range(0, 20, 2):
            state = evaluate_transport_policy(
                selected=TRANSPORT_WG_TAG,
                probes=probes,
                previous=state,
                observed_at=f"2026-08-06T12:00:{second:02d}+00:00",
            )
            self.assertFalse(state["would_switch"])
            self.assertEqual(state["recommended"], TRANSPORT_WG_TAG)
            self.assertNotIn("latency_candidate", state)
            self.assertNotIn("latency_confirmations", state)

    def test_quality_loss_is_soft_degradation_without_a_switch(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {
                    "checked": True,
                    "ok": True,
                    "scope": "overlay-dns",
                    "quality_checked": True,
                    "quality_ok": False,
                    "quality_error": "WireGuard overlay packet loss 25%",
                    "packet_loss_pct": 25.0,
                },
                TRANSPORT_HY2_TAG: {"checked": False, "ok": False},
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )

        self.assertEqual(result["state"], "degraded")
        self.assertFalse(result["hard_failure_evidence"])
        self.assertFalse(result["would_switch"])
        self.assertIn("packet loss 25%", result["reason"])

    def test_preferred_quality_loss_requires_independent_fresh_pairs(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {
                    "checked": True,
                    "ok": True,
                    "scope": "overlay-dns",
                    "quality_checked": True,
                    "quality_sampled": True,
                    "quality_ok": False,
                    "quality_error": "WireGuard overlay packet loss 10%",
                    "packet_loss_pct": 10.0,
                },
                TRANSPORT_HY2_TAG: {
                    "checked": True,
                    "ok": True,
                    "health_confirmed": True,
                    "scope": "raw-underlay-udp",
                    "quality_checked": True,
                    "quality_ok": True,
                    "packet_loss_pct": 0.0,
                },
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )

        self.assertEqual(result["state"], "degraded")
        self.assertFalse(result["hard_failure_evidence"])
        self.assertFalse(result["would_switch"])
        self.assertEqual(result["quality_failure"]["confirmations"], 1)
        probes = result["probes"]
        for second, fresh in ((0, True), (2, True), (4, False), (14, False), (15, True)):
            with self.subTest(second=second, fresh=fresh):
                result = evaluate_transport_policy(
                    selected=TRANSPORT_WG_TAG,
                    probes={
                        TRANSPORT_WG_TAG: {**probes[TRANSPORT_WG_TAG], "quality_sampled": fresh},
                        TRANSPORT_HY2_TAG: probes[TRANSPORT_HY2_TAG] if fresh else {"checked": False},
                    },
                    previous=result,
                    observed_at=f"2026-08-06T12:00:{second:02d}+00:00",
                )
                self.assertEqual(result["would_switch"], second == 15)
                self.assertEqual(result["quality_failure"]["confirmations"], 2 if second == 15 else 1)
        self.assertEqual(result["quality_failure"]["reason"], "packet_loss")
        self.assertEqual(result["recommended"], TRANSPORT_HY2_TAG)
        self.assertEqual(result["preferred_retry"]["retry_at"], "2026-08-06T12:01:15+00:00")

    def test_quality_evidence_resets_after_clean_missing_lossy_or_stale_samples(self) -> None:
        loss = {
            "checked": True, "ok": True, "quality_checked": True, "quality_sampled": True,
            "quality_ok": False, "quality_error": "overlay packet loss 5%", "packet_loss_pct": 5.0,
        }
        clean = {
            "checked": True, "ok": True, "health_confirmed": True,
            "quality_checked": True, "quality_ok": True,
        }
        baseline = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={TRANSPORT_WG_TAG: loss, TRANSPORT_HY2_TAG: clean},
            observed_at="2026-08-06T12:00:00+00:00",
        )
        cases = (
            ({**loss, "quality_ok": True}, clean),
            (loss, {"checked": False}),
            (loss, {**clean, "quality_ok": False}),
            ({**loss, "quality_checked": False}, clean),
            ({"checked": False}, clean),
        )
        for selected_probe, alternate_probe in cases:
            with self.subTest(selected=selected_probe, alternate=alternate_probe):
                interrupted = evaluate_transport_policy(
                    selected=TRANSPORT_WG_TAG,
                    probes={TRANSPORT_WG_TAG: selected_probe, TRANSPORT_HY2_TAG: alternate_probe},
                    previous=baseline,
                    observed_at="2026-08-06T12:00:15+00:00",
                )
                result = evaluate_transport_policy(
                    selected=TRANSPORT_WG_TAG,
                    probes={TRANSPORT_WG_TAG: loss, TRANSPORT_HY2_TAG: clean},
                    previous=interrupted,
                    observed_at="2026-08-06T12:00:30+00:00",
                )
                self.assertFalse(result["would_switch"])
                self.assertEqual(result["quality_failure"]["confirmations"], 1)
        stale = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={TRANSPORT_WG_TAG: loss, TRANSPORT_HY2_TAG: clean},
            previous=baseline,
            observed_at="2026-08-06T12:01:00+00:00",
        )
        self.assertFalse(stale["would_switch"])
        self.assertEqual(stale["quality_failure"]["confirmations"], 1)

    def test_quality_evidence_cannot_cross_a_successful_path_switch(self) -> None:
        loss = {
            "checked": True, "ok": True, "quality_checked": True, "quality_sampled": True,
            "quality_ok": False, "quality_error": "overlay packet loss 5%",
        }
        clean = {
            "checked": True, "ok": True, "health_confirmed": True,
            "quality_checked": True, "quality_ok": True,
        }
        previous = {
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "selected": TRANSPORT_HY2_TAG,
            "quality_failure": {
                "path": TRANSPORT_WG_TAG, "reason": "packet_loss", "confirmations": 2,
                "sampled_at": "2026-08-06T12:00:00+00:00",
            },
        }
        result = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes={TRANSPORT_HY2_TAG: loss, TRANSPORT_WG_TAG: clean},
            previous=previous,
            observed_at="2026-08-06T12:00:15+00:00",
        )
        self.assertFalse(result["would_switch"])
        self.assertEqual(result["quality_failure"]["path"], TRANSPORT_HY2_TAG)
        self.assertEqual(result["quality_failure"]["confirmations"], 1)

    def test_preferred_quality_loss_does_not_switch_to_a_lossy_fallback(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes={
                TRANSPORT_WG_TAG: {
                    "checked": True,
                    "ok": True,
                    "quality_checked": True,
                    "quality_sampled": True,
                    "quality_ok": False,
                    "quality_error": "WireGuard overlay packet loss 10%",
                    "packet_loss_pct": 10.0,
                },
                TRANSPORT_HY2_TAG: {
                    "checked": True,
                    "ok": True,
                    "health_confirmed": True,
                    "quality_checked": True,
                    "quality_ok": False,
                    "quality_error": "underlay probe packet loss 12.5%",
                    "packet_loss_pct": 12.5,
                },
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )

        self.assertEqual(result["state"], "degraded")
        self.assertFalse(result["would_switch"])
        self.assertEqual(result["recommended"], TRANSPORT_WG_TAG)

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

    def test_healthy_fallback_returns_only_after_a_continuous_clean_window(self) -> None:
        failure = {
            TRANSPORT_WG_TAG: {"checked": True, "ok": False, "attempts": 2, "error": "timed out"},
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 70},
        }
        first = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=failure,
            observed_at="2026-08-06T12:00:00+00:00",
        )
        switch = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=failure,
            previous=first,
            observed_at="2026-08-06T12:00:02+00:00",
        )
        self.assertTrue(switch["would_switch"])
        self.assertEqual(switch["preferred_retry"]["retry_at"], "2026-08-06T12:01:02+00:00")

        state: dict[str, object] = {
            **switch,
            "selected": TRANSPORT_HY2_TAG,
            "would_switch": False,
            "changed": True,
        }
        healthy = {
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 90},
            TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 40},
        }
        deferred = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes={**healthy, TRANSPORT_WG_TAG: {"checked": False, "ok": False}},
            previous=state,
            observed_at="2026-08-06T12:00:04+00:00",
        )
        self.assertFalse(deferred["would_switch"])
        self.assertIn("deferred until", deferred["reason"])
        state = deferred
        for stamp in ("12:01:02", "12:02:02", "12:03:02", "12:04:02", "12:05:02"):
            state = evaluate_transport_policy(
                selected=TRANSPORT_HY2_TAG,
                probes=healthy,
                previous=state,
                observed_at=f"2026-08-06T{stamp}+00:00",
            )
        self.assertEqual(state["state"], "recovering")
        self.assertEqual(state["selected"], TRANSPORT_HY2_TAG)
        self.assertEqual(state["recommended"], TRANSPORT_HY2_TAG)
        self.assertFalse(state["would_switch"])
        self.assertEqual(state["preferred_recovery"]["continuous_seconds"], 240)

        state = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes=healthy,
            previous=state,
            observed_at="2026-08-06T12:06:02+00:00",
        )
        self.assertEqual(state["recommended"], TRANSPORT_WG_TAG)
        self.assertTrue(state["would_switch"])
        self.assertEqual(state["preferred_recovery"]["confirmations"], 6)
        self.assertEqual(state["preferred_recovery"]["continuous_seconds"], 300)
        self.assertEqual(state["preferred_retry"]["recovered_at"], "2026-08-06T12:06:02+00:00")
        json.dumps(state)

    def test_healthy_fallback_defers_after_a_failed_preferred_probe(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes={
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "scope": "overlay-dns"},
                TRANSPORT_WG_TAG: {"checked": True, "ok": False, "error": "timed out"},
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )

        self.assertEqual(result["state"], "healthy")
        self.assertFalse(result["would_switch"])
        self.assertIn("preferred underlay timeout", result["reason"])
        self.assertEqual(result["preferred_retry"]["attempts"], 1)

    def test_fallback_does_not_recover_to_a_lossy_preferred_path(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes={
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "scope": "overlay-dns"},
                TRANSPORT_WG_TAG: {
                    "checked": True,
                    "ok": True,
                    "quality_checked": True,
                    "quality_ok": False,
                    "quality_error": "underlay probe packet loss 12.5%",
                    "packet_loss_pct": 12.5,
                },
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )

        self.assertEqual(result["state"], "healthy")
        self.assertFalse(result["would_switch"])
        self.assertIn("packet loss 12.5%", result["reason"])
        self.assertEqual(result["preferred_retry"]["reason"], "packet_loss")

    def test_degraded_fallback_requires_fresh_pairs_and_honors_preferred_retry(self) -> None:
        result = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes={
                TRANSPORT_HY2_TAG: {
                    "checked": True,
                    "ok": True,
                    "quality_checked": True,
                    "quality_sampled": True,
                    "quality_ok": False,
                    "quality_error": "Hysteria overlay packet loss 15%",
                    "packet_loss_pct": 15.0,
                },
                TRANSPORT_WG_TAG: {
                    "checked": True,
                    "ok": True,
                    "health_confirmed": True,
                    "quality_checked": True,
                    "quality_ok": True,
                    "packet_loss_pct": 0.0,
                },
            },
            previous={
                "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
                "selected": TRANSPORT_HY2_TAG,
                "preferred_retry": {
                    "path": TRANSPORT_WG_TAG,
                    "attempts": 3,
                    "retry_at": "2026-08-06T12:01:00+00:00",
                    "reason": "packet_loss",
                },
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )

        self.assertFalse(result["would_switch"])
        probes = result["probes"]
        base = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
        for seconds in range(TRANSPORT_QUALITY_PROBE_INTERVAL_SECONDS, 61, TRANSPORT_QUALITY_PROBE_INTERVAL_SECONDS):
            result = evaluate_transport_policy(
                selected=TRANSPORT_HY2_TAG,
                probes=probes,
                previous=result,
                observed_at=(base + timedelta(seconds=seconds)).isoformat(),
            )
            self.assertEqual(result["would_switch"], seconds == 60)
        self.assertEqual(result["recommended"], TRANSPORT_WG_TAG)
        self.assertEqual(result["quality_failure"]["path"], TRANSPORT_HY2_TAG)
        self.assertEqual(result["preferred_retry"]["recovered_at"], "2026-08-06T12:01:00+00:00")

    def test_deferred_cycle_preserves_but_does_not_increment_recovery_evidence(self) -> None:
        first = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes={
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 50},
                TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 20},
            },
            observed_at="2026-08-06T12:00:00+00:00",
        )
        deferred = evaluate_transport_policy(
            selected=TRANSPORT_HY2_TAG,
            probes={
                TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 50},
                TRANSPORT_WG_TAG: {"checked": False, "ok": False},
            },
            previous=first,
            observed_at="2026-08-06T12:00:02+00:00",
        )

        self.assertEqual(first["preferred_recovery"]["confirmations"], 1)
        self.assertEqual(deferred["preferred_recovery"]["confirmations"], 1)
        self.assertEqual(deferred["preferred_probe_at"], first["preferred_probe_at"])
        self.assertFalse(deferred["would_switch"])

    def test_recurrent_preferred_failure_increases_retry_without_permanent_lockout(self) -> None:
        previous: dict[str, object] = {
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "updated_at": "2026-08-06T12:01:58+00:00",
            "selected": TRANSPORT_WG_TAG,
            "preferred_retry": {
                "path": TRANSPORT_WG_TAG,
                "attempts": 1,
                "failed_at": "2026-08-06T12:00:00+00:00",
                "retry_at": "2026-08-06T12:01:00+00:00",
                "recovered_at": "2026-08-06T12:01:00+00:00",
                "reason": "packet_loss",
            },
        }
        probes = {
            TRANSPORT_WG_TAG: {
                "checked": True,
                "ok": False,
                "attempts": 5,
                "error": "WireGuard overlay packet loss 20%",
            },
            TRANSPORT_HY2_TAG: {"checked": True, "ok": True, "delay_ms": 40},
        }
        first = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            previous=previous,
            observed_at="2026-08-06T12:02:00+00:00",
        )
        second = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            previous=first,
            observed_at="2026-08-06T12:02:02+00:00",
        )

        self.assertTrue(second["would_switch"])
        self.assertEqual(second["failure"]["reason"], "packet_loss")
        self.assertEqual(second["preferred_retry"]["attempts"], 2)
        self.assertEqual(second["preferred_retry"]["retry_at"], "2026-08-06T12:04:02+00:00")

    def test_healthy_preferred_path_closes_and_eventually_clears_retry_history(self) -> None:
        previous = {
            "schema_version": TRANSPORT_STATE_SCHEMA_VERSION,
            "selected": TRANSPORT_WG_TAG,
            "preferred_retry": {
                "path": TRANSPORT_WG_TAG,
                "attempts": 2,
                "failed_at": "2026-08-06T11:59:00+00:00",
                "retry_at": "2026-08-06T12:01:00+00:00",
                "reason": "timeout",
            },
        }
        probes = {
            TRANSPORT_WG_TAG: {"checked": True, "ok": True, "delay_ms": 20},
            TRANSPORT_HY2_TAG: {"checked": False, "ok": False},
        }

        recovered = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            previous=previous,
            observed_at="2026-08-06T12:02:00+00:00",
        )
        stable = evaluate_transport_policy(
            selected=TRANSPORT_WG_TAG,
            probes=probes,
            previous=recovered,
            observed_at="2026-08-06T12:32:00+00:00",
        )

        self.assertEqual(recovered["preferred_retry"]["recovered_at"], "2026-08-06T12:02:00+00:00")
        self.assertNotIn("preferred_retry", stable)

if __name__ == "__main__":
    unittest.main()
