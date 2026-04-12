from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import STATE_DIR, utc_now, write_json
from .config import load_env_file
from .models import ROLE_FOREIGN, ROLE_RU, RemoteTarget


def state_json_path(deployment_name: str) -> Path:
    return STATE_DIR / f"{deployment_name}.json"


def state_legacy_path(deployment_name: str) -> Path:
    return STATE_DIR / f"{deployment_name}.env"


def load_state(deployment_name: str) -> dict[str, Any]:
    json_path = state_json_path(deployment_name)
    if json_path.exists():
        return json.loads(json_path.read_text(encoding="utf-8"))
    legacy_path = state_legacy_path(deployment_name)
    if not legacy_path.exists():
        return {}
    legacy = load_env_file(legacy_path)
    return {
        ROLE_RU: {
            "public_ip": legacy.get("RU_PUBLIC_IP", ""),
            "ssh_host": legacy.get("RU_SSH_HOST", ""),
            "ssh_port": legacy.get("RU_SSH_PORT", "22"),
            "ssh_user": legacy.get("RU_SSH_USER", "root"),
            "auth_mode": "key",
            "identity_path": legacy.get("RU_IDENTITY_PATH", ""),
        },
        ROLE_FOREIGN: {
            "public_ip": legacy.get("FOREIGN_PUBLIC_IP", ""),
            "ssh_host": legacy.get("FOREIGN_SSH_HOST", ""),
            "ssh_port": legacy.get("FOREIGN_SSH_PORT", "22"),
            "ssh_user": legacy.get("FOREIGN_SSH_USER", "root"),
            "auth_mode": "key",
            "identity_path": legacy.get("FOREIGN_IDENTITY_PATH", ""),
        },
    }


def write_state(deployment_name: str, targets: list[RemoteTarget], existing_state: dict[str, Any] | None = None) -> None:
    payload = {"updated_at": utc_now(), ROLE_RU: {}, ROLE_FOREIGN: {}}
    if existing_state:
        for role in (ROLE_RU, ROLE_FOREIGN):
            role_state = existing_state.get(role, {})
            if isinstance(role_state, dict):
                payload[role] = {
                    "public_ip": str(role_state.get("public_ip", "")),
                    "ssh_host": str(role_state.get("ssh_host", "")),
                    "ssh_port": str(role_state.get("ssh_port", "")),
                    "ssh_user": str(role_state.get("ssh_user", "")),
                    "auth_mode": str(role_state.get("auth_mode", "key") or "key"),
                    "identity_path": str(role_state.get("identity_path", "")),
                }
    for target in targets:
        payload[target.role] = target.to_state()
    write_json(state_json_path(deployment_name), payload)
