from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import STATE_DIR, utc_now, write_private_json
from .config import load_env_file
from .models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from .topology import CONFIG_SCHEMA_VERSION, NODE_EXIT, NODE_GATEWAY, TOPOLOGY_DUAL, TOPOLOGY_SINGLE


def _validate_native_state(payload: dict[str, Any]) -> dict[str, Any]:
    topology = payload.get("topology")
    if topology not in {TOPOLOGY_SINGLE, TOPOLOGY_DUAL}:
        raise ValueError(f"unsupported state topology: {topology}")
    nodes = payload.get("nodes")
    if not isinstance(nodes, dict):
        raise ValueError("state schema 2 requires a nodes object")
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


def state_legacy_path(deployment_name: str) -> Path:
    return STATE_DIR / f"{deployment_name}.env"


def load_state(deployment_name: str) -> dict[str, Any]:
    json_path = state_json_path(deployment_name)
    if json_path.exists():
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        schema = payload.get("schema_version")
        if schema is not None:
            if schema != CONFIG_SCHEMA_VERSION:
                raise ValueError(f"unsupported state schema: {schema}")
            return _validate_native_state(payload)
        if NODE_GATEWAY in payload or NODE_EXIT in payload:
            nodes = {
                node_id: payload[node_id]
                for node_id in (NODE_GATEWAY, NODE_EXIT)
                if isinstance(payload.get(node_id), dict) and payload[node_id]
            }
            return {
                "schema_version": CONFIG_SCHEMA_VERSION,
                "topology": TOPOLOGY_DUAL if NODE_EXIT in nodes else TOPOLOGY_SINGLE,
                "updated_at": payload.get("updated_at", ""),
                "nodes": nodes,
                "migration": {"state": "deprecated", "legacy_inputs": [key for key in (NODE_GATEWAY, NODE_EXIT) if key in payload]},
            }
        nodes = {
            NODE_GATEWAY: payload.get(ROLE_RU, {}),
            NODE_EXIT: payload.get(ROLE_FOREIGN, {}),
        }
        nodes = {node_id: value for node_id, value in nodes.items() if isinstance(value, dict) and value}
        return {
            "schema_version": CONFIG_SCHEMA_VERSION,
            "topology": TOPOLOGY_DUAL if NODE_EXIT in nodes else TOPOLOGY_SINGLE,
            "updated_at": payload.get("updated_at", ""),
            "nodes": nodes,
            "migration": {"state": "deprecated", "legacy_inputs": [key for key in (ROLE_RU, ROLE_FOREIGN) if key in payload]},
        }
    legacy_path = state_legacy_path(deployment_name)
    if not legacy_path.exists():
        return {}
    legacy = load_env_file(legacy_path)
    def legacy_role(prefix: str) -> dict[str, str]:
        return {
            "public_ip": legacy.get(f"{prefix}_PUBLIC_IP", ""),
            "ssh_host": legacy.get(f"{prefix}_SSH_HOST", ""),
            "ssh_port": legacy.get(f"{prefix}_SSH_PORT", "22"),
            "ssh_user": legacy.get(f"{prefix}_SSH_USER", "root"),
            "auth_mode": legacy.get(f"{prefix}_AUTH_MODE", "") or legacy.get(f"{prefix}_SSH_AUTH_MODE", ""),
            "identity_path": legacy.get(f"{prefix}_IDENTITY_PATH", ""),
        }

    nodes = {
        NODE_GATEWAY: legacy_role("RU"),
        NODE_EXIT: legacy_role("FOREIGN"),
    }
    nodes = {node_id: value for node_id, value in nodes.items() if value.get("public_ip") or value.get("ssh_host")}
    return {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "topology": TOPOLOGY_DUAL if NODE_EXIT in nodes else TOPOLOGY_SINGLE,
        "nodes": nodes,
        "migration": {"state": "deprecated", "legacy_inputs": ["state-env"]},
    }


def write_state(
    deployment_name: str,
    targets: list[RemoteTarget],
    existing_state: dict[str, Any] | None = None,
    *,
    topology: str | None = None,
) -> None:
    target_nodes = {target.node_id for target in targets}
    existing_nodes_for_mode = (existing_state or {}).get("nodes", {}) if isinstance((existing_state or {}).get("nodes"), dict) else (existing_state or {})
    has_existing_exit = NODE_EXIT in existing_nodes_for_mode or ROLE_FOREIGN in existing_nodes_for_mode
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
        "migration": {"state": "native", "legacy_inputs": []},
    }
    if existing_state:
        existing_nodes = existing_state.get("nodes", {}) if isinstance(existing_state.get("nodes"), dict) else existing_state
        for node_id, legacy_role in ((NODE_GATEWAY, ROLE_RU), (NODE_EXIT, ROLE_FOREIGN)):
            role_state = existing_nodes.get(node_id, {}) or existing_nodes.get(legacy_role, {})
            if node_id in configured_nodes and isinstance(role_state, dict) and role_state:
                payload["nodes"][node_id] = {
                    "location": str(role_state.get("location", "")),
                    "public_ip": str(role_state.get("public_ip", "")),
                    "ssh_host": str(role_state.get("ssh_host", "")),
                    "ssh_port": str(role_state.get("ssh_port", "")),
                    "ssh_user": str(role_state.get("ssh_user", "")),
                    "auth_mode": str(role_state.get("auth_mode", "key") or "key"),
                    "identity_path": str(role_state.get("identity_path", "")),
                }
    for target in targets:
        if target.node_id not in configured_nodes:
            raise ValueError(f"target {target.node_id} is not part of {topology} topology")
        payload["nodes"][target.node_id] = target.to_state()
    write_private_json(state_json_path(deployment_name), payload)
