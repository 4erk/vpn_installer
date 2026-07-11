from __future__ import annotations

import os
from typing import Any

from .models import AppError, ROLE_META, ROLE_RU, RemoteTarget
from .prompts import has_saved_connection


def build_target(role: str, env: dict[str, str], state: dict[str, Any]) -> RemoteTarget:
    role_state = state.get(role, {})
    saved_connection = has_saved_connection(role_state)
    public_ip_key = ROLE_META[role]["public_ip_key"]
    ssh_port_raw = str((role_state.get("ssh_port") if saved_connection else None) or env.get("SSH_PORT", "22") or "22")
    ssh_port = int(ssh_port_raw)
    public_ip = str((role_state.get("public_ip") if saved_connection else None) or env.get(public_ip_key, ""))
    return RemoteTarget(
        role=role,
        public_ip=public_ip,
        ssh_host=str((role_state.get("ssh_host") if saved_connection else None) or public_ip),
        ssh_port=ssh_port,
        ssh_user=str((role_state.get("ssh_user") if saved_connection else None) or "root"),
        auth_mode=str((role_state.get("auth_mode") if saved_connection else None) or "key"),
        identity_path=str((role_state.get("identity_path") if saved_connection else None) or ""),
        saved_connection=saved_connection,
    )


def role_env_prefix(role: str) -> str:
    return "VPN_RU" if role == ROLE_RU else "VPN_FOREIGN"


def apply_env_connection_overrides(target: RemoteTarget) -> RemoteTarget:
    prefix = role_env_prefix(target.role)
    public_ip = os.environ.get(f"{prefix}_PUBLIC_IP", "").strip()
    ssh_host = os.environ.get(f"{prefix}_SSH_HOST", "").strip()
    ssh_port = os.environ.get(f"{prefix}_SSH_PORT", "").strip()
    ssh_user = os.environ.get(f"{prefix}_SSH_USER", "").strip()
    auth_mode = os.environ.get(f"{prefix}_SSH_AUTH_MODE", "").strip()
    identity_path = os.environ.get(f"{prefix}_SSH_IDENTITY_PATH", "").strip()
    password = os.environ.get(f"{prefix}_SSH_PASSWORD", "") or os.environ.get("VPN_SSH_PASSWORD", "")

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
        env[ROLE_META[target.role]["public_ip_key"]] = target.public_ip


def sync_targets_from_env(env: dict[str, str], targets: list[RemoteTarget]) -> None:
    for target in targets:
        public_ip = env.get(ROLE_META[target.role]["public_ip_key"], "").strip()
        if public_ip:
            target.public_ip = public_ip


def remote_env_matches_target(target: RemoteTarget, deployment_name: str, preflight: dict[str, str]) -> bool:
    return (
        preflight.get("installed") == "1"
        and preflight.get("deployment_name", "").strip() == deployment_name
        and preflight.get("role", "").strip() == target.role
    )


def can_fetch_remote_env(target: RemoteTarget) -> bool:
    return target.ssh_user == "root" or target.sudo_mode in {"root", "nopasswd", "password"}
