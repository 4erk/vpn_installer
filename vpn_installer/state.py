from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import STATE_DIR, utc_now, write_private_json
from .models import RemoteTarget
from .topology import CONFIG_SCHEMA_VERSION, NODE_EXIT, NODE_GATEWAY, TOPOLOGY_DUAL, TOPOLOGY_SINGLE


def _validate_native_state(payload: dict[str, Any]) -> dict[str, Any]:
    topology = payload.get("topology")
    if topology not in {TOPOLOGY_SINGLE, TOPOLOGY_DUAL}:
        raise ValueError(f"unsupported state topology: {topology}")
    nodes = payload.get("nodes")
    if not isinstance(nodes, dict):
        raise ValueError(f"state schema {CONFIG_SCHEMA_VERSION} requires a nodes object")
    allowed = {NODE_GATEWAY} if topology == TOPOLOGY_SINGLE else {NODE_GATEWAY, NODE_EXIT}
    unknown = set(nodes) - allowed
    if unknown:
        raise ValueError(f"state contains nodes outside topology={topology}: {', '.join(sorted(unknown))}")
    for node_id, node_state in nodes.items():
        if not isinstance(node_state, dict):
            raise ValueError(f"state node {node_id} must be an object")
    return payload


def state_json_path(deployment_name: str) -> Path:
    return STATE_DIR / f"{deployment_name}.json"


def load_state(deployment_name: str) -> dict[str, Any]:
    json_path = state_json_path(deployment_name)
    if json_path.exists():
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        schema = payload.get("schema_version")
        if payload.get("schema_version") != CONFIG_SCHEMA_VERSION:
            raise ValueError(f"unsupported state schema: {schema}")
        return _validate_native_state(payload)
    return {}


def write_state(
    deployment_name: str,
    targets: list[RemoteTarget],
    existing_state: dict[str, Any] | None = None,
    *,
    topology: str | None = None,
) -> None:
    target_nodes = {target.node_id for target in targets}
    existing_nodes_for_mode = (existing_state or {}).get("nodes", {}) if isinstance((existing_state or {}).get("nodes"), dict) else {}
    has_existing_exit = NODE_EXIT in existing_nodes_for_mode
    topology = topology or str((existing_state or {}).get("topology", "")) or (
        TOPOLOGY_DUAL if NODE_EXIT in target_nodes or has_existing_exit else TOPOLOGY_SINGLE
    )
    if topology not in {TOPOLOGY_SINGLE, TOPOLOGY_DUAL}:
        raise ValueError(f"unsupported state topology: {topology}")
    configured_nodes = {NODE_GATEWAY} if topology == TOPOLOGY_SINGLE else {NODE_GATEWAY, NODE_EXIT}
    payload = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "topology": topology,
        "updated_at": utc_now(),
        "nodes": {},
    }
    if existing_state:
        existing_nodes = existing_state.get("nodes", {}) if isinstance(existing_state.get("nodes"), dict) else {}
        for node_id in (NODE_GATEWAY, NODE_EXIT):
            node_state = existing_nodes.get(node_id, {})
            if node_id in configured_nodes and isinstance(node_state, dict) and node_state:
                payload["nodes"][node_id] = {
                    "location": str(node_state.get("location", "")),
                    "public_ip": str(node_state.get("public_ip", "")),
                    "ssh_host": str(node_state.get("ssh_host", "")),
                    "ssh_port": str(node_state.get("ssh_port", "")),
                    "ssh_user": str(node_state.get("ssh_user", "")),
                    "auth_mode": str(node_state.get("auth_mode", "key") or "key"),
                    "identity_path": str(node_state.get("identity_path", "")),
                }
    for target in targets:
        if target.node_id not in configured_nodes:
            raise ValueError(f"target {target.node_id} is not part of {topology} topology")
        payload["nodes"][target.node_id] = target.to_state()
    write_private_json(state_json_path(deployment_name), payload)
