from __future__ import annotations

from .models import ROLE_FOREIGN, ROLE_RU
from .topology import legacy_role_for_node, normalize_node_id


def requested_roles(role_arg: str) -> list[str]:
    return [ROLE_RU, ROLE_FOREIGN] if role_arg == "all" else [legacy_role_for_node(normalize_node_id(role_arg))]


def execution_roles(action: str, roles: list[str]) -> list[str]:
    if action in {"install", "reinstall"}:
        preferred = [ROLE_FOREIGN, ROLE_RU]
    elif action in {"remove", "purge"}:
        preferred = [ROLE_RU, ROLE_FOREIGN]
    else:
        preferred = [ROLE_RU, ROLE_FOREIGN]
    return [role for role in preferred if role in roles]
