from __future__ import annotations

from typing import Any, Mapping

from .compatibility import TRANSITION_REMOVE_IN, TRANSITION_SOURCE_VERSION
from .topology import (
    CAP_WEB_ADMIN,
    CONFIG_SCHEMA_VERSION,
    DUAL_ONLY_ENV_KEYS,
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
    NodePlan,
    TopologySpec,
)


SOURCE_CONFIG_SCHEMA = 2
SOURCE_STATE_SCHEMA = 2
SOURCE_MANIFEST_SCHEMA = 3
SOURCE_INSTALL_PLAN_SCHEMA = 3
SOURCE_DIAGNOSTICS_SCHEMA = 4

_REMOVED_ENV_KEYS = frozenset({"ADMIN_WEB_ENABLED"})
_FORBIDDEN_PRE_0200_ENV_KEYS = frozenset({"RU_PUBLIC_IP", "FOREIGN_PUBLIC_IP"})
_OLD_NODE_ROLES = {NODE_GATEWAY: "ru-gateway", NODE_EXIT: "foreign-exit"}


class Upgrade0200Error(ValueError):
    pass


def _strings(source: Mapping[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in source.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise Upgrade0200Error("0.20.0 env keys and values must be strings")
        result[key] = value
    return result


def upgrade_env(source: Mapping[str, str]) -> dict[str, str]:
    """Translate only the canonical 0.20.0 env into the current schema.

    This module is the complete 0.20.0 compatibility boundary and is removed
    in 0.20.2 when the minimum compatible installed release becomes 0.20.1.
    """

    env = _strings(source)
    if env.get("CONFIG_SCHEMA", "").strip() != str(SOURCE_CONFIG_SCHEMA):
        raise Upgrade0200Error(f"expected 0.20.0 CONFIG_SCHEMA={SOURCE_CONFIG_SCHEMA}")
    forbidden = sorted(_FORBIDDEN_PRE_0200_ENV_KEYS & env.keys())
    if forbidden:
        raise Upgrade0200Error(f"pre-0.20.0 env keys are not supported: {', '.join(forbidden)}")

    topology = env.get("TOPOLOGY", "").strip().lower()
    location = env.get("GATEWAY_LOCATION", "").strip().lower()
    if topology not in {TOPOLOGY_SINGLE, TOPOLOGY_DUAL}:
        raise Upgrade0200Error(f"invalid 0.20.0 topology: {topology or '<empty>'}")
    if location not in {LOCATION_RU, LOCATION_FOREIGN}:
        raise Upgrade0200Error(f"invalid 0.20.0 gateway location: {location or '<empty>'}")
    if topology == TOPOLOGY_DUAL and location != LOCATION_RU:
        raise Upgrade0200Error("0.20.0 dual topology requires an RU gateway")
    if not env.get("GATEWAY_PUBLIC_IP", "").strip():
        raise Upgrade0200Error("0.20.0 env is missing GATEWAY_PUBLIC_IP")
    if topology == TOPOLOGY_DUAL and not env.get("EXIT_PUBLIC_IP", "").strip():
        raise Upgrade0200Error("0.20.0 dual env is missing EXIT_PUBLIC_IP")
    if topology == TOPOLOGY_SINGLE and env.get("EXIT_PUBLIC_IP", "").strip():
        raise Upgrade0200Error("0.20.0 single env contains EXIT_PUBLIC_IP")

    upgraded = {key: value for key, value in env.items() if key not in _REMOVED_ENV_KEYS}
    if topology == TOPOLOGY_SINGLE:
        for key in DUAL_ONLY_ENV_KEYS:
            upgraded.pop(key, None)
    upgraded["CONFIG_SCHEMA"] = str(CONFIG_SCHEMA_VERSION)
    return upgraded


def upgrade_state(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != SOURCE_STATE_SCHEMA:
        raise Upgrade0200Error(f"expected 0.20.0 state schema {SOURCE_STATE_SCHEMA}")
    topology = payload.get("topology")
    if topology not in {TOPOLOGY_SINGLE, TOPOLOGY_DUAL}:
        raise Upgrade0200Error(f"invalid 0.20.0 state topology: {topology!r}")
    nodes = payload.get("nodes")
    if not isinstance(nodes, dict):
        raise Upgrade0200Error("0.20.0 state requires a nodes object")
    expected = {NODE_GATEWAY} if topology == TOPOLOGY_SINGLE else {NODE_GATEWAY, NODE_EXIT}
    if set(nodes) - expected or NODE_GATEWAY not in nodes:
        raise Upgrade0200Error("0.20.0 state nodes do not match its topology")
    for node_id, value in nodes.items():
        if not isinstance(value, dict):
            raise Upgrade0200Error(f"0.20.0 state node {node_id} must be an object")
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "topology": topology,
        "updated_at": str(payload.get("updated_at", "")),
        "nodes": {node_id: dict(value) for node_id, value in nodes.items()},
    }


def previous_node_plan(env: Mapping[str, str], node_id: str) -> NodePlan:
    """Compile the exact capability shape emitted by 0.20.0."""

    source = _strings(env)
    if source.get("CONFIG_SCHEMA", "").strip() != str(SOURCE_CONFIG_SCHEMA):
        raise Upgrade0200Error("previous bundle is not a 0.20.0 node env")
    topology = TopologySpec.from_env(source, require_addresses=False)
    plan = topology.plan(node_id)
    if plan.node_id != NODE_GATEWAY:
        return plan
    enabled = source.get("ADMIN_WEB_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}
    capabilities = set(plan.capabilities)
    if enabled:
        capabilities.add(CAP_WEB_ADMIN)
    elif topology.is_dual:
        capabilities.discard(CAP_WEB_ADMIN)
    return NodePlan(node=plan.node, topology=plan.topology, capabilities=frozenset(capabilities))


def previous_role(node_id: str) -> str:
    try:
        return _OLD_NODE_ROLES[node_id]
    except KeyError as exc:
        raise Upgrade0200Error(f"invalid 0.20.0 node id: {node_id}") from exc


def transition_metadata() -> dict[str, str]:
    return {
        "from": TRANSITION_SOURCE_VERSION,
        "to_schema": str(CONFIG_SCHEMA_VERSION),
        "remove_in": TRANSITION_REMOVE_IN,
    }


def upgrade_diagnostics_snapshot(payload: Mapping[str, Any], *, target_schema: int) -> dict[str, Any]:
    """Adapt only a native 0.20.0 agent snapshot for upgrade preflight."""

    if payload.get("schema_version") != SOURCE_DIAGNOSTICS_SCHEMA:
        raise Upgrade0200Error(
            f"expected 0.20.0 diagnostics schema {SOURCE_DIAGNOSTICS_SCHEMA}"
        )
    release = payload.get("release")
    if not isinstance(release, Mapping) or release.get("version") != TRANSITION_SOURCE_VERSION:
        raise Upgrade0200Error("diagnostics snapshot is not from release 0.20.0")
    upgraded = dict(payload)
    upgraded.pop("role", None)
    upgraded.pop("migration", None)
    upgraded["schema_version"] = target_schema
    return upgraded
