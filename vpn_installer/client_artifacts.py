from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path
from typing import Any

from .common import OUT_DIR, write_text
from .config import require_env
from .models import REQUIRED_ENV_VARS


def _env_int(env: dict[str, str], key: str) -> int:
    return int(env[key])


def _render_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def deployment_out_dir(env: dict[str, str], *, out_dir: Path | None = None) -> Path:
    return (out_dir or OUT_DIR) / env["DEPLOY_NAME"]


def client_route_excludes(env: dict[str, str]) -> list[str]:
    route_excludes: list[str] = []
    for auto_exclude in (env.get("RU_PUBLIC_IP", "").strip(), env.get("FOREIGN_PUBLIC_IP", "").strip()):
        if auto_exclude:
            cidr = auto_exclude if "/" in auto_exclude else f"{auto_exclude}/32"
            if cidr not in route_excludes:
                route_excludes.append(cidr)
    extra_excludes = [entry.strip() for entry in (env.get("CLIENT_ROUTE_EXCLUDE_V4", "") + "," + env.get("CLIENT_ROUTE_EXCLUDE_V6", "")).split(",") if entry.strip()]
    for entry in extra_excludes:
        if entry not in route_excludes:
            route_excludes.append(entry)
    return route_excludes


def render_client_profile(env: dict[str, str], auto_redirect: bool, *, android_safe: bool = False) -> str:
    tun_addresses = [env["CLIENT_TUN_ADDRESS_V4"]]
    if not android_safe:
        tun_addresses.append(env["CLIENT_TUN_ADDRESS_V6"])
    route_excludes = client_route_excludes(env)
    payload: dict[str, Any] = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "strategy": "ipv4_only",
            "servers": [
                {
                    "type": "https",
                    "tag": "dns-remote",
                    "server": env["GLOBAL_DOH_SERVER"],
                    "server_port": 443,
                    "path": env["GLOBAL_DOH_PATH"],
                    "detour": "ru-gateway",
                    "tls": {"enabled": True, "server_name": env["GLOBAL_DOH_SERVER_NAME"]},
                },
            ],
            "rules": [{"query_type": ["AAAA"], "action": "reject"}],
            "final": "dns-remote",
            "independent_cache": True,
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": env["CLIENT_TUN_NAME"],
                "address": tun_addresses,
                "auto_route": True,
                "strict_route": True,
                "auto_redirect": auto_redirect,
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "ru-gateway",
                "server": env["RU_PUBLIC_IP"],
                "server_port": _env_int(env, "RU_LISTEN_PORT"),
                "uuid": env["CLIENT_UUID"],
                "flow": env["CLIENT_FLOW"],
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True,
                    "server_name": env["RU_REALITY_SERVER_NAME"],
                    "utls": {"enabled": True, "fingerprint": env["UTLS_FINGERPRINT"]},
                    "reality": {"enabled": True, "public_key": env["RU_REALITY_PUBLIC_KEY"], "short_id": env["RU_REALITY_SHORT_ID"]},
                },
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-remote", "strategy": "ipv4_only"},
            "rules": [
                {"ip_version": 6, "action": "route", "outbound": "block"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
                {"domain_suffix": ["local"], "action": "route", "outbound": "direct"},
            ],
            "final": "ru-gateway",
        },
    }
    if android_safe:
        payload["route"]["override_android_vpn"] = True
    if route_excludes:
        payload["inbounds"][0]["route_exclude_address"] = route_excludes
    return _render_json(payload)


def render_xray_client_profile(env: dict[str, str]) -> str:
    route_rules: list[dict[str, Any]] = [{"type": "field", "ip": ["::/0"], "outboundTag": "block"}]
    route_excludes = client_route_excludes(env)
    if route_excludes:
        route_rules.append({"type": "field", "ip": route_excludes, "outboundTag": "direct"})
    payload = {
        "log": {"loglevel": "warning"},
        "dns": {"queryStrategy": "UseIPv4", "servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
            },
            {
                "tag": "http",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
            },
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": env["RU_PUBLIC_IP"],
                            "port": _env_int(env, "RU_LISTEN_PORT"),
                            "users": [{"id": env["CLIENT_UUID"], "encryption": "none", "flow": env["CLIENT_FLOW"]}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": env["RU_REALITY_SERVER_NAME"],
                        "fingerprint": env["UTLS_FINGERPRINT"],
                        "publicKey": env["RU_REALITY_PUBLIC_KEY"],
                        "shortId": env["RU_REALITY_SHORT_ID"],
                        "spiderX": "/",
                    },
                },
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": route_rules},
    }
    return _render_json(payload)


def render_windows_route_bypass_script(env: dict[str, str]) -> str:
    server_ips = [ip.split("/", 1)[0] for ip in client_route_excludes(env) if ip]
    server_ip_literal = "@(" + ", ".join(f'"{ip}"' for ip in server_ips) + ")"
    return textwrap.dedent(
        f"""\
        # Generated by vpn_installer. Run in elevated PowerShell when a TUN/full VPN client routes server IPs through itself.
        param(
          [switch]$Remove
        )

        $ErrorActionPreference = "Stop"
        $ServerIps = {server_ip_literal}
        $TunnelInterfacePattern = "(?i)(singbox|hiddify|wintun|v2ray|nekobox|clash|tun|vpn)"

        function Test-Admin {{
          $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
          $principal = [Security.Principal.WindowsPrincipal]::new($identity)
          return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }}

        function Get-PhysicalGatewayRoute {{
          $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Where-Object {{ $_.NextHop -and $_.NextHop -ne "0.0.0.0" -and $_.InterfaceAlias -notmatch $TunnelInterfacePattern }} |
            Sort-Object RouteMetric, InterfaceMetric |
            Select-Object -First 1
          if ($route) {{ return $route }}

          $gateway = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            Where-Object {{ $_.IPv4DefaultGateway -and $_.InterfaceAlias -notmatch $TunnelInterfacePattern }} |
            Select-Object -First 1
          if (-not $gateway) {{ return $null }}

          [pscustomobject]@{{
            InterfaceIndex = $gateway.InterfaceIndex
            InterfaceAlias = $gateway.InterfaceAlias
            NextHop = $gateway.IPv4DefaultGateway.NextHop
          }}
        }}

        if (-not (Test-Admin)) {{
          throw "Run this script from elevated PowerShell."
        }}

        foreach ($ip in $ServerIps) {{
          $prefix = "$ip/32"
          if ($Remove) {{
            Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
              Where-Object {{ $_.RouteMetric -eq 1 }} |
              Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Removed bypass route $prefix"
            continue
          }}

          $gatewayRoute = Get-PhysicalGatewayRoute
          if (-not $gatewayRoute) {{
            throw "Physical default gateway was not found. Disable the VPN client and run client-check again."
          }}

          Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Where-Object {{ $_.InterfaceIndex -ne $gatewayRoute.InterfaceIndex -or $_.NextHop -ne $gatewayRoute.NextHop }} |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

          if (-not (Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $gatewayRoute.InterfaceIndex -NextHop $gatewayRoute.NextHop -ErrorAction SilentlyContinue)) {{
            New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $gatewayRoute.InterfaceIndex -NextHop $gatewayRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
          }}
          Write-Host "Bypass route $prefix via $($gatewayRoute.InterfaceAlias) $($gatewayRoute.NextHop)"
        }}

        Write-Host "Done. Re-run: .\\vpn.cmd client-check --deployment {env['DEPLOY_NAME']}"
        """
    )


def render_vless_uri(env: dict[str, str]) -> str:
    return f"vless://{env['CLIENT_UUID']}@{env['RU_PUBLIC_IP']}:{env['RU_LISTEN_PORT']}?security=reality&sni={env['RU_REALITY_SERVER_NAME']}&pbk={env['RU_REALITY_PUBLIC_KEY']}&sid={env['RU_REALITY_SHORT_ID']}&fp={env['UTLS_FINGERPRINT']}&type=tcp&flow={env['CLIENT_FLOW']}#{env['DEPLOY_NAME']}-ru-gateway\n"


def client_artifact_paths(env: dict[str, str], *, out_dir: Path | None = None) -> dict[str, Path]:
    deployment_dir = deployment_out_dir(env, out_dir=out_dir)
    client_dir = deployment_dir / "client"
    return {
        "client_dir": client_dir,
        "vless_uri": client_dir / "vless-uri.txt",
        "hiddify_uri_compat": client_dir / "hiddify-uri.txt",
        "hiddify_json": client_dir / "hiddify-cross-platform.json",
        "android_hiddify_json": client_dir / "hiddify-android.json",
        "linux_json": client_dir / "linux-sing-box.json",
        "windows_xray_json": client_dir / "windows-xray.json",
        "android_xray_json": client_dir / "android-v2rayng-xray.json",
        "windows_route_bypass": client_dir / "windows-route-bypass.ps1",
        "next_steps": deployment_dir / "NEXT-STEPS.txt",
    }


STALE_CLIENT_ARTIFACT_NAMES = (
    "vless-uri-compatible.txt",
    "hiddify-subscription-url.txt",
    "hiddify-import-url.txt",
    "hiddify-android-subscription-url.txt",
)

GENERATED_CLIENT_FILE_NAMES = (
    "vless-uri.txt",
    "hiddify-uri.txt",
    "hiddify-cross-platform.json",
    "hiddify-android.json",
    "linux-sing-box.json",
    "windows-xray.json",
    "android-v2rayng-xray.json",
    "windows-route-bypass.ps1",
)


def prepare_client_artifact_dir(client_dir: Path) -> None:
    client_dir.mkdir(parents=True, exist_ok=True)
    for name in GENERATED_CLIENT_FILE_NAMES + STALE_CLIENT_ARTIFACT_NAMES:
        path = client_dir / name
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def render_next_steps(env: dict[str, str], *, out_dir: Path | None = None) -> str:
    paths = client_artifact_paths(env, out_dir=out_dir)
    return "\n".join(
        [
            f"Deployment: {env['DEPLOY_NAME']}",
            "",
            "Что уже готово:",
            f"- Быстрый VLESS URI fallback: {paths['vless_uri']}",
            f"- Стабильный Android/v2rayNG Xray JSON: {paths['android_xray_json']}",
            f"- JSON fallback для Hiddify: {paths['hiddify_json']}",
            f"- Android JSON fallback для Hiddify: {paths['android_hiddify_json']}",
            f"- Windows/v2rayN Xray JSON: {paths['windows_xray_json']}",
            f"- Windows route bypass helper: {paths['windows_route_bypass']}",
            f"- Совместимый Hiddify URI alias: {paths['hiddify_uri_compat']}",
            f"- JSON backup для Linux sing-box: {paths['linux_json']}",
            "",
            "Что делать дальше:",
            f"1. На Android/v2rayNG используй {paths['android_xray_json'].name}: полный Xray JSON включает sniffing и не зависит от локального IPv6 DNS клиента. NekoBox можно пробовать только если он импортирует тот же полный Xray JSON.",
            f"2. На Windows/v2rayN используй {paths['windows_xray_json'].name} с Xray core.",
            f"3. Прямой {paths['vless_uri'].name} оставлен как простой URI fallback. Если клиент сам резолвит домены в IPv6 literal, сервер быстро закроет такую попытку, чтобы не висеть на нестабильном IPv6 path.",
            f"4. Если нужен Hiddify на Android, используй локальный JSON {paths['android_hiddify_json'].name}. Этот путь считается совместимым, но не эталонным.",
            f"5. Файл {paths['hiddify_uri_compat'].name} оставлен как совместимый alias того же VLESS URI для старых сценариев.",
            f"6. Если включён TUN/full VPN и client-check показывает self-tunnel, запусти PowerShell от администратора: .\\{paths['windows_route_bypass'].name}",
            f"7. Для проверки серверов потом запусти: vpn status --deployment {env['DEPLOY_NAME']}",
        ]
    ) + "\n"


def render_client_profiles(env: dict[str, str], *, out_dir: Path | None = None) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    paths = client_artifact_paths(env, out_dir=out_dir)
    prepare_client_artifact_dir(paths["client_dir"])
    write_text(paths["hiddify_json"], render_client_profile(env, auto_redirect=False))
    write_text(paths["android_hiddify_json"], render_client_profile(env, auto_redirect=False, android_safe=True))
    write_text(paths["linux_json"], render_client_profile(env, auto_redirect=True))
    xray_profile = render_xray_client_profile(env)
    write_text(paths["windows_xray_json"], xray_profile)
    write_text(paths["android_xray_json"], xray_profile)
    write_text(paths["windows_route_bypass"], render_windows_route_bypass_script(env))
    uri_payload = render_vless_uri(env)
    write_text(paths["vless_uri"], uri_payload)
    write_text(paths["hiddify_uri_compat"], uri_payload)
    write_text(paths["next_steps"], render_next_steps(env, out_dir=out_dir))
    return paths["client_dir"]
