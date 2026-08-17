from __future__ import annotations

import webbrowser

from .common import print_header
from .config import load_existing_deployment_env
from .models import AppError
from .prompts import select_existing_deployment
from .topology import CAP_WEB_ADMIN, NODE_GATEWAY, TopologySpec


DEFAULT_ADMIN_PORT = 11333


def _valid_port(value: int) -> int:
    if not 1 <= value <= 65535:
        raise AppError("ADMIN_WEB_PORT должен быть в диапазоне 1..65535")
    return value


def admin_access_workflow(
    deployment: str | None,
    *,
    open_browser: bool = False,
) -> int:
    deployment_name = select_existing_deployment(deployment)
    _env_path, env = load_existing_deployment_env(deployment_name)
    topology = TopologySpec.from_env(env)
    if CAP_WEB_ADMIN not in topology.plan(NODE_GATEWAY).capabilities:
        raise AppError("Web-admin доступен только в dual topology.")
    try:
        port = _valid_port(int(env.get("ADMIN_WEB_PORT", str(DEFAULT_ADMIN_PORT))))
    except ValueError as exc:
        raise AppError("ADMIN_WEB_PORT должен быть целым числом") from exc
    url = f"http://{topology.gateway.public_ip}:{port}"
    print_header("Web-admin")
    print(f"deployment: {deployment_name}")
    print(f"Адрес: {url}")
    print("Доступ разрешается firewall только для источника активного подключения к публичному VPN-входу.")
    if open_browser:
        webbrowser.open(url, new=2)
    return 0
