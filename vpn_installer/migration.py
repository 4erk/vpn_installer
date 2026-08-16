from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .topology import (
    CONFIG_SCHEMA_VERSION,
    LOCATION_FOREIGN,
    LOCATION_RU,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
)


LEGACY_RU_PUBLIC_IP = "RU_PUBLIC_IP"
LEGACY_FOREIGN_PUBLIC_IP = "FOREIGN_PUBLIC_IP"
LEGACY_ADDRESS_KEYS = (LEGACY_RU_PUBLIC_IP, LEGACY_FOREIGN_PUBLIC_IP)


class EnvMigrationError(ValueError):
    """The input cannot be interpreted without guessing or losing intent."""


@dataclass(frozen=True)
class EnvMigrationResult:
    """Canonical env plus explicit evidence consumed at the migration boundary."""

    env: dict[str, str]
    legacy_inputs: tuple[str, ...]


def _copy_env(source: Mapping[str, str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in source.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise EnvMigrationError("deployment env keys and values must be strings")
        env[key] = value
    return env


def _clean(env: Mapping[str, str], key: str) -> str:
    return env.get(key, "").strip()


def _require(env: Mapping[str, str], key: str) -> str:
    value = _clean(env, key)
    if not value:
        raise EnvMigrationError(f"canonical CONFIG_SCHEMA=2 env requires {key}")
    return value


def _without_legacy_addresses(env: Mapping[str, str]) -> dict[str, str]:
    canonical = dict(env)
    for key in LEGACY_ADDRESS_KEYS:
        canonical.pop(key, None)
    return canonical


def _assert_optional_match(env: Mapping[str, str], canonical_key: str, expected: str) -> None:
    observed = _clean(env, canonical_key)
    if observed and observed != expected:
        raise EnvMigrationError(
            f"canonical/legacy conflict: {canonical_key} does not match the legacy dual endpoint"
        )


def _migrate_legacy_dual(env: Mapping[str, str]) -> EnvMigrationResult:
    ru_ip = _clean(env, LEGACY_RU_PUBLIC_IP)
    foreign_ip = _clean(env, LEGACY_FOREIGN_PUBLIC_IP)
    if not ru_ip or not foreign_ip:
        raise EnvMigrationError(
            "legacy env without CONFIG_SCHEMA must contain both RU_PUBLIC_IP and FOREIGN_PUBLIC_IP"
        )

    topology = _clean(env, "TOPOLOGY")
    if topology and topology != TOPOLOGY_DUAL:
        raise EnvMigrationError("legacy env without CONFIG_SCHEMA can only describe dual topology")
    gateway_location = _clean(env, "GATEWAY_LOCATION")
    if gateway_location and gateway_location != LOCATION_RU:
        raise EnvMigrationError("legacy dual env requires an RU gateway")

    _assert_optional_match(env, "GATEWAY_PUBLIC_IP", ru_ip)
    _assert_optional_match(env, "EXIT_PUBLIC_IP", foreign_ip)

    canonical = _without_legacy_addresses(env)
    canonical.update(
        {
            "CONFIG_SCHEMA": str(CONFIG_SCHEMA_VERSION),
            "TOPOLOGY": TOPOLOGY_DUAL,
            "GATEWAY_LOCATION": LOCATION_RU,
            "GATEWAY_PUBLIC_IP": ru_ip,
            "EXIT_PUBLIC_IP": foreign_ip,
        }
    )
    return EnvMigrationResult(canonical, LEGACY_ADDRESS_KEYS)


def _accept_canonical(env: Mapping[str, str]) -> EnvMigrationResult:
    topology = _require(env, "TOPOLOGY").lower()
    if topology not in {TOPOLOGY_SINGLE, TOPOLOGY_DUAL}:
        raise EnvMigrationError(f"unsupported topology for CONFIG_SCHEMA=2: {topology}")

    gateway_location = _require(env, "GATEWAY_LOCATION").lower()
    if gateway_location not in {LOCATION_RU, LOCATION_FOREIGN}:
        raise EnvMigrationError(f"unsupported gateway location for CONFIG_SCHEMA=2: {gateway_location}")
    if topology == TOPOLOGY_DUAL and gateway_location != LOCATION_RU:
        raise EnvMigrationError("dual topology requires an RU gateway")

    gateway_ip = _require(env, "GATEWAY_PUBLIC_IP")
    exit_ip = _clean(env, "EXIT_PUBLIC_IP")
    if topology == TOPOLOGY_DUAL and not exit_ip:
        raise EnvMigrationError("canonical CONFIG_SCHEMA=2 dual env requires EXIT_PUBLIC_IP")
    if topology == TOPOLOGY_SINGLE and exit_ip:
        raise EnvMigrationError("canonical CONFIG_SCHEMA=2 single env cannot contain EXIT_PUBLIC_IP")

    expected_legacy = {
        LEGACY_RU_PUBLIC_IP: gateway_ip if gateway_location == LOCATION_RU else "",
        LEGACY_FOREIGN_PUBLIC_IP: (
            exit_ip if topology == TOPOLOGY_DUAL else gateway_ip if gateway_location == LOCATION_FOREIGN else ""
        ),
    }
    legacy_inputs: list[str] = []
    for key in LEGACY_ADDRESS_KEYS:
        observed = _clean(env, key)
        if not observed:
            continue
        if not expected_legacy[key] or observed != expected_legacy[key]:
            raise EnvMigrationError(f"canonical/legacy conflict: {key} does not match canonical topology")
        legacy_inputs.append(key)

    canonical = _without_legacy_addresses(env)
    canonical.update(
        {
            "CONFIG_SCHEMA": str(CONFIG_SCHEMA_VERSION),
            "TOPOLOGY": topology,
            "GATEWAY_LOCATION": gateway_location,
            "GATEWAY_PUBLIC_IP": gateway_ip,
            "EXIT_PUBLIC_IP": exit_ip,
        }
    )
    return EnvMigrationResult(canonical, tuple(legacy_inputs))


def migrate_env(source: Mapping[str, str]) -> EnvMigrationResult:
    """Validate one env schema and return a detached canonical representation.

    This function performs no I/O and never mutates ``source``. Callers may only
    persist ``result.env`` after this boundary succeeds.
    """

    env = _copy_env(source)
    schema = _clean(env, "CONFIG_SCHEMA")
    if not schema:
        return _migrate_legacy_dual(env)
    if schema != str(CONFIG_SCHEMA_VERSION):
        raise EnvMigrationError(f"unsupported CONFIG_SCHEMA: {schema}")
    return _accept_canonical(env)
