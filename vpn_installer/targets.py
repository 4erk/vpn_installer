from __future__ import annotations

import os
import ipaddress
from typing import Any

from .models import AppError, ROLE_META, ROLE_RU, RemoteTarget
from .prompts import has_saved_connection
from .topology import NODE_GATEWAY, TopologySpec, legacy_role_for_node, normalize_node_id


def build_target(role: str, env: dict[str, str], state: dict[str, Any]) -> RemoteTarget:
    node_id = normalize_node_id(role)
    legacy_role = legacy_role_for_node(node_id)
    nodes = state.get("nodes", {}) if isinstance(state.get("nodes"), dict) else state
    role_state = nodes.get(node_id, {}) or nodes.get(legacy_role, {})
    saved_connection = has_saved_connection(role_state)
    topology = TopologySpec.from_env(env, require_addresses=False)
    node = topology.node(node_id)
    ssh_port_raw = str((role_state.get("ssh_port") if saved_connection else None) or env.get("SSH_PORT", "22") or "22")
    ssh_port = int(ssh_port_raw)
    public_ip = str((role_state.get("public_ip") if saved_connection else None) or node.public_ip)
    return RemoteTarget(
        role=legacy_role,
        location=node.location,
        public_ip=public_ip,
        ssh_host=str((role_state.get("ssh_host") if saved_connection else None) or public_ip),
        ssh_port=ssh_port,
        ssh_user=str((role_state.get("ssh_user") if saved_connection else None) or "root"),
        auth_mode=str((role_state.get("auth_mode") if saved_connection else None) or "key"),
        identity_path=str((role_state.get("identity_path") if saved_connection else None) or ""),
        saved_connection=saved_connection,
    )


def role_env_prefix(role: str) -> str:
    return "VPN_GATEWAY" if normalize_node_id(role) == NODE_GATEWAY else "VPN_EXIT"


def legacy_role_env_prefix(role: str) -> str:
    """One-release process-env adapter. Remove in 0.20.1."""

    return "VPN_RU" if normalize_node_id(role) == NODE_GATEWAY else "VPN_FOREIGN"


def apply_env_connection_overrides(target: RemoteTarget) -> RemoteTarget:
    prefix = role_env_prefix(target.role)
    legacy_prefix = legacy_role_env_prefix(target.role)

    def setting(name: str) -> str:
        return os.environ.get(f"{prefix}_{name}", "").strip() or os.environ.get(f"{legacy_prefix}_{name}", "").strip()

    public_ip = setting("PUBLIC_IP")
    ssh_host = setting("SSH_HOST")
    ssh_port = setting("SSH_PORT")
    ssh_user = setting("SSH_USER")
    auth_mode = setting("SSH_AUTH_MODE")
    identity_path = setting("SSH_IDENTITY_PATH")
    bind_address = os.environ.get("VPN_SSH_BIND_ADDRESS", "").strip()
    password = (
        os.environ.get(f"{prefix}_SSH_PASSWORD", "")
        or os.environ.get(f"{legacy_prefix}_SSH_PASSWORD", "")
        or os.environ.get("VPN_SSH_PASSWORD", "")
    )

    if public_ip:
        target.public_ip = public_ip
    if ssh_host:
        target.ssh_host = ssh_host
    if ssh_port:
        try:
            target.ssh_port = int(ssh_port)
        except ValueError as exc:
            raise AppError(f"{target.label}: некорректный {prefix}_SSH_PORT={ssh_port}") from exc
    if ssh_user:
        target.ssh_user = ssh_user
    if auth_mode:
        target.auth_mode = auth_mode
    if identity_path:
        target.identity_path = identity_path
    if bind_address:
        try:
            target.ssh_bind_address = str(ipaddress.ip_address(bind_address))
        except ValueError as exc:
            raise AppError(f"Некорректный VPN_SSH_BIND_ADDRESS={bind_address}") from exc
    if password:
        target.auth_mode = "password"
        target.identity_path = ""
        target.ssh_password = password

    if target.public_ip and not target.ssh_host:
        target.ssh_host = target.public_ip
    if target.public_ip and target.ssh_host and target.ssh_user and target.ssh_port:
        target.saved_connection = True
    return target


def update_env_with_targets(env: dict[str, str], targets: list[RemoteTarget]) -> None:
    for target in targets:
        if target.node_id == NODE_GATEWAY:
            env["GATEWAY_PUBLIC_IP"] = target.public_ip
        else:
            env["EXIT_PUBLIC_IP"] = target.public_ip


def sync_targets_from_env(env: dict[str, str], targets: list[RemoteTarget]) -> None:
    topology = TopologySpec.from_env(env, require_addresses=False)
    for target in targets:
        public_ip = topology.node(target.node_id).public_ip
        if public_ip:
            target.public_ip = public_ip


def remote_env_matches_target(target: RemoteTarget, deployment_name: str, preflight: dict[str, str]) -> bool:
    observed_node = preflight.get("node", "").strip()
    observed_role = preflight.get("role", "").strip()
    return (
        preflight.get("installed") == "1"
        and preflight.get("deployment_name", "").strip() == deployment_name
        and (observed_node == target.node_id or observed_role == target.role)
    )


def can_fetch_remote_env(target: RemoteTarget) -> bool:
    return target.ssh_user == "root" or target.sudo_mode in {"root", "nopasswd", "password"}
