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


def admin_url(env: dict[str, str]) -> str:
    topology = TopologySpec.from_env(env, require_addresses=False)
    if CAP_WEB_ADMIN not in topology.plan(NODE_GATEWAY).capabilities:
        raise AppError("Web-admin доступен только в dual topology.")
    if not topology.gateway.public_ip:
        raise AppError("Для web-admin не указан публичный IP gateway.")
    try:
        port = _valid_port(int(env.get("ADMIN_WEB_PORT", str(DEFAULT_ADMIN_PORT))))
    except ValueError as exc:
        raise AppError("ADMIN_WEB_PORT должен быть целым числом") from exc
    return f"http://{topology.gateway.public_ip}:{port}"


def admin_access_workflow(
    deployment: str | None,
    *,
    open_browser: bool = False,
) -> int:
    deployment_name = select_existing_deployment(deployment)
    env_path, env = load_existing_deployment_env(deployment_name)
    url = admin_url(env)
    print_header("Web-admin")
    print(f"deployment: {deployment_name}")
    print(f"Адрес: {url}")
    print(f"Начальные данные входа: ADMIN_WEB_USERNAME и ADMIN_WEB_PASSWORD в {env_path}")
    print("Если пароль менялся в панели, используй установленный там пароль.")
    print("Публичная панель использует HTTP. Допуск firewall по пакетам VPN не шифрует пароль; для защищённого доступа используй SSH-туннель (docs/ADMIN.md).")
    if open_browser:
        webbrowser.open(url, new=2)
    return 0
