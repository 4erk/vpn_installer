from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from dataclasses import dataclass

from .models import AppError, RemoteTarget


ALLOW_TUNNELED_ROUTE_ENV = "VPN_INSTALLER_ALLOW_TUNNELED_SERVER_ROUTE"


@dataclass(frozen=True)
class LocalRoute:
    target_ip: str
    interface_alias: str = ""
    next_hop: str = ""
    source_address: str = ""


def valid_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def windows_route_to_ip(target_ip: str) -> LocalRoute | None:
    try:
        ip = valid_ip(target_ip)
    except ValueError:
        return None
    script = rf"""
$ErrorActionPreference = 'SilentlyContinue'
$result = Find-NetRoute -RemoteIPAddress '{ip}'
$route = @($result | Where-Object {{ $_.DestinationPrefix }} | Select-Object -First 1)
$addr = @($result | Where-Object {{ $_.IPAddress }} | Select-Object -First 1)
if ($route.Count -gt 0) {{
  [pscustomobject]@{{
    interface_alias = [string]$route[0].InterfaceAlias
    next_hop = [string]$route[0].NextHop
    source_address = [string]$addr[0].IPAddress
  }} | ConvertTo-Json -Compress
}}
""".strip()
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return LocalRoute(
        target_ip=ip,
        interface_alias=str(payload.get("interface_alias", "")),
        next_hop=str(payload.get("next_hop", "")),
        source_address=str(payload.get("source_address", "")),
    )


def route_uses_self_tunnel(route: LocalRoute, *, client_tun_name: str) -> bool:
    alias = route.interface_alias.strip().lower()
    expected = client_tun_name.strip().lower()
    if not alias:
        return False
    if expected and alias == expected:
        return True
    markers = ("singbox", "hiddify", "wintun", "v2ray", "nekobox", "clash")
    return any(marker in alias for marker in markers)


def local_route_check_supported() -> bool:
    return os.name == "nt"


def local_route_to_server(target: RemoteTarget) -> LocalRoute | None:
    if not local_route_check_supported():
        return None
    address = target.public_ip or target.ssh_host
    return windows_route_to_ip(address)


def assert_server_route_not_self_tunneled(target: RemoteTarget, env: dict[str, str]) -> LocalRoute | None:
    route = local_route_to_server(target)
    if route is None:
        return None
    if route_uses_self_tunnel(route, client_tun_name=env.get("CLIENT_TUN_NAME", "")):
        if target.ssh_bind_address:
            # SSH validates this separately bound management path before mutation.
            return route
        if os.environ.get(ALLOW_TUNNELED_ROUTE_ENV) == "1":
            return route
        raise AppError(
            "\n".join(
                [
                    f"Локальный маршрут до {target.label} ({route.target_ip}) идёт через VPN-интерфейс {route.interface_alias}.",
                    "Так клиент заворачивает подключение к самому VPN-серверу внутрь VPN, из-за чего ломаются SSH, reinstall и Reality handshake.",
                    "Для независимого management-пути задай VPN_SSH_BIND_ADDRESS на адрес физического интерфейса; это не меняет клиент или серверный dataplane.",
                    "Либо отключи текущий VPN перед обслуживанием серверов.",
                    f"Экстренный override для опытной диагностики: {ALLOW_TUNNELED_ROUTE_ENV}=1",
                ]
            )
        )
    return route
