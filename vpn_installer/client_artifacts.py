from __future__ import annotations

import json
import os
import shutil
import tempfile
import textwrap
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote, urlencode, urlparse

from .common import OUT_DIR, cli_command, write_private_text
from .config import require_env
from .interserver_transport import HY2_SERVER_NAME
from .models import AppError, REQUIRED_ENV_VARS
from .topology import TopologySpec
from .public_transport import (
    derive_public_hy2_password,
    public_hy2_certificate_fingerprint,
)
from .vless_verify import parse_vless_uri

PUBLIC_VLESS_OUTBOUND_TAG = "ru-gateway-vless"


def _env_int(env: dict[str, str], key: str) -> int:
    return int(env[key])


def _render_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def deployment_out_dir(env: dict[str, str], *, out_dir: Path | None = None) -> Path:
    return (out_dir or OUT_DIR) / env["DEPLOY_NAME"]


def gateway_profile_name(env: dict[str, str]) -> str:
    topology = TopologySpec.from_env(env)
    return "ru-gateway" if topology.is_dual else f"{topology.gateway.location}-gateway"


def client_route_excludes(env: dict[str, str]) -> list[str]:
    route_excludes: list[str] = []
    topology = TopologySpec.from_env(env)
    for auto_exclude in (node.public_ip for node in topology.nodes):
        if auto_exclude:
            cidr = auto_exclude if "/" in auto_exclude else f"{auto_exclude}/32"
            if cidr not in route_excludes:
                route_excludes.append(cidr)
    extra_excludes = [entry.strip() for entry in (env.get("CLIENT_ROUTE_EXCLUDE_V4", "") + "," + env.get("CLIENT_ROUTE_EXCLUDE_V6", "")).split(",") if entry.strip()]
    for entry in extra_excludes:
        if entry not in route_excludes:
            route_excludes.append(entry)
    return route_excludes


def render_vless_client_outbound(env: dict[str, str]) -> dict[str, Any]:
    gateway = TopologySpec.from_env(env).gateway
    return {
        "type": "vless",
        "tag": PUBLIC_VLESS_OUTBOUND_TAG,
        "server": gateway.public_ip,
        "server_port": _env_int(env, "RU_LISTEN_PORT"),
        "uuid": env["CLIENT_UUID"],
        "flow": env["CLIENT_FLOW"],
        "packet_encoding": "xudp",
        "multiplex": {"enabled": False},
        "tls": {
            "enabled": True,
            "server_name": env["RU_REALITY_SERVER_NAME"],
            "utls": {"enabled": True, "fingerprint": env["UTLS_FINGERPRINT"]},
            "reality": {
                "enabled": True,
                "public_key": env["RU_REALITY_PUBLIC_KEY"],
                "short_id": env["RU_REALITY_SHORT_ID"],
            },
        },
    }


def render_client_profile(env: dict[str, str], auto_redirect: bool, *, android_safe: bool = False) -> str:
    tun_addresses = [env["CLIENT_TUN_ADDRESS_V4"]]
    enable_ipv6 = env.get("CLIENT_ENABLE_IPV6", "0").strip().lower() in {"1", "true", "yes", "on"}
    if enable_ipv6 and not android_safe:
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
                    "detour": PUBLIC_VLESS_OUTBOUND_TAG,
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
            render_vless_client_outbound(env),
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-remote", "strategy": "ipv4_only"},
            "rules": [
                {"inbound": ["tun-in"], "action": "sniff", "timeout": "1s"},
                {"ip_version": 6, "action": "route", "outbound": "block"},
                {"inbound": ["tun-in"], "port": 53, "action": "hijack-dns"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
                {"domain_suffix": ["local"], "action": "route", "outbound": "direct"},
            ],
            "final": PUBLIC_VLESS_OUTBOUND_TAG,
        },
    }
    if android_safe:
        payload["route"]["override_android_vpn"] = True
    if route_excludes:
        payload["inbounds"][0]["route_exclude_address"] = route_excludes
    return _render_json(payload)


def render_xray_client_profile(env: dict[str, str]) -> str:
    gateway = TopologySpec.from_env(env).gateway
    route_rules: list[dict[str, Any]] = [
        {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
    ]
    route_excludes = client_route_excludes(env)
    if route_excludes:
        route_rules.append({"type": "field", "ip": route_excludes, "outboundTag": "direct"})
    payload = {
        "log": {"loglevel": "warning"},
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
                            "address": gateway.public_ip,
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
                "mux": {"enabled": False},
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": route_rules},
    }
    return _render_json(payload)


def render_windows_route_bypass_script(env: dict[str, str]) -> str:
    server_ips = [node.public_ip for node in TopologySpec.from_env(env).nodes]
    server_ip_literal = "@(" + ", ".join(f'"{ip}"' for ip in server_ips) + ")"
    return textwrap.dedent(
        """\
        # Generated by vpn_installer. Run in elevated PowerShell when a TUN/full VPN client routes server IPs through itself.
        param(
          [switch]$Remove
        )

        $ErrorActionPreference = "Stop"
        $ServerIps = __SERVER_IPS__
        $ServerPrefixes = @($ServerIps | ForEach-Object {
          $bits = if ([Net.IPAddress]::Parse($_).AddressFamily -eq 'InterNetwork') { 32 } else { 128 }
          "$_/$bits"
        })
        $TunnelInterfacePattern = "(?i)(singbox|hiddify|wintun|v2ray|nekobox|clash|tun|vpn)"
        $RouteFields = @('DestinationPrefix', 'InterfaceIndex', 'InterfaceAlias', 'NextHop', 'RouteMetric', 'Protocol', 'Publish')
        $StatePath = Join-Path $PSScriptRoot 'windows-route-bypass.state.json'

        function Test-Admin {
          $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
          $principal = [Security.Principal.WindowsPrincipal]::new($identity)
          return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }

        function Get-PhysicalGatewayRoute($Prefix) {
          $default = if ($Prefix -match ':') { '::/0' } else { '0.0.0.0/0' }
          Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.DestinationPrefix -eq $default -and $_.NextHop -notin @('0.0.0.0', '::') -and $_.InterfaceAlias -notmatch $TunnelInterfacePattern } |
            Sort-Object { $_.RouteMetric + $_.InterfaceMetric } |
            Select-Object -First 1
        }

        function Test-OwnedRoute($Route, $Record) {
          foreach ($field in $RouteFields) {
            if ($null -eq $Record -or $null -eq $Record.$field -or $null -eq $Route.$field -or
                [string]$Record.$field -cne [string]$Route.$field) { return $false }
          }
          return $true
        }

        function Get-RouteRecord($Route) {
          $record = [ordered]@{}
          foreach ($field in $RouteFields) { $record[$field] = [string]$Route.$field }
          return [pscustomobject]$record
        }

        function Get-RouteAction($Existing, $Record, [bool]$Removing) {
          if ($Removing) {
            if (@($Existing | Where-Object { Test-OwnedRoute $_ $Record }).Count -eq 1) { return 'remove' }
            return 'preserve'
          }
          if (@($Existing).Count) { return 'preserve' }
          return 'create'
        }

        function Save-RouteState {
          $temporary = "$StatePath.$([guid]::NewGuid().ToString('N')).tmp"
          try {
            [IO.File]::WriteAllText($temporary, ($state | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
            if ([IO.File]::Exists($StatePath)) { [IO.File]::Replace($temporary, $StatePath, $null) }
            else { [IO.File]::Move($temporary, $StatePath) }
          } finally {
            if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
          }
        }

        if (-not (Test-Admin)) {
          throw "Run this script from elevated PowerShell."
        }
        $lock = [IO.File]::Open("$StatePath.lock", 'OpenOrCreate', 'ReadWrite', 'None')
        try {
          $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
          $state = [pscustomobject]@{ Schema = 1; Machine = $env:COMPUTERNAME; Boot = $boot; Routes = @() }
          if (Test-Path -LiteralPath $StatePath) {
            $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
            if ($saved.Schema -ne 1) { throw 'Unknown route ownership state; no routes changed.' }
            if ($saved.Machine -eq $state.Machine -and $saved.Boot -eq $boot) { $state.Routes = @($saved.Routes) }
          }
          # ActiveStore routes never survive a reboot. Do not adopt routes from another machine or boot.
          Save-RouteState
          foreach ($prefix in $ServerPrefixes) {
            $existing = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq $prefix })
            $records = @($state.Routes | Where-Object { $_.DestinationPrefix -eq $prefix })
            $record = if ($records.Count -eq 1) { $records[0] } else { $null }
            $action = Get-RouteAction $existing $record ([bool]$Remove)
            if ($action -eq 'remove') {
              $existing | Where-Object { Test-OwnedRoute $_ $record } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
              Write-Host "Removed owned server route $prefix"
            } elseif ($action -eq 'create') {
              $gatewayRoute = Get-PhysicalGatewayRoute $prefix
              if (-not $gatewayRoute) { throw "No physical default gateway for $prefix; no route added." }
              $created = New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $gatewayRoute.InterfaceIndex -NextHop $gatewayRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop
              $record = Get-RouteRecord $created
              $state.Routes = @($state.Routes | Where-Object { $_.DestinationPrefix -ne $prefix }) + @($record)
              try { Save-RouteState } catch {
                # A route without a durable ownership record must not be left behind.
                Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop |
                  Where-Object { Test-OwnedRoute $_ $record } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                throw
              }
              Write-Host "Added owned server route $prefix"
              continue
            } else {
              Write-Host "Preserved existing routes for $prefix"
              if (-not $Remove -and @($existing | Where-Object { Test-OwnedRoute $_ $record }).Count -eq 1) { continue }
            }
            $state.Routes = @($state.Routes | Where-Object { $_.DestinationPrefix -ne $prefix })
            Save-RouteState
          }
        } finally { $lock.Dispose() }

        Write-Host 'Done. Re-run: __CLIENT_CHECK__'
        """
    ).replace("__SERVER_IPS__", server_ip_literal).replace(
        "__CLIENT_CHECK__", cli_command(f"client-check --deployment {env['DEPLOY_NAME']}", platform_name="nt").replace("'", "''")
    )


def render_vless_uri(env: dict[str, str]) -> str:
    gateway = TopologySpec.from_env(env).gateway
    return f"vless://{env['CLIENT_UUID']}@{gateway.public_ip}:{env['RU_LISTEN_PORT']}?security=reality&sni={env['RU_REALITY_SERVER_NAME']}&pbk={env['RU_REALITY_PUBLIC_KEY']}&sid={env['RU_REALITY_SHORT_ID']}&fp={env['UTLS_FINGERPRINT']}&type=tcp&flow={env['CLIENT_FLOW']}#{env['DEPLOY_NAME']}-{gateway_profile_name(env)}\n"


def render_hysteria2_uri(env: dict[str, str]) -> str:
    gateway = TopologySpec.from_env(env).gateway
    password = quote(derive_public_hy2_password(env["CLIENT_UUID"]), safe="")
    query = urlencode(
        {
            "sni": HY2_SERVER_NAME,
            "insecure": "1",
            "pinSHA256": public_hy2_certificate_fingerprint(env),
        }
    )
    name = quote(f"{env['DEPLOY_NAME']}-{gateway_profile_name(env)}-quic", safe="")
    return f"hysteria2://{password}@{gateway.public_ip}:{env['RU_LISTEN_PORT']}/?{query}#{name}\n"


def client_artifact_paths(env: dict[str, str], *, out_dir: Path | None = None) -> dict[str, Path]:
    deployment_dir = deployment_out_dir(env, out_dir=out_dir)
    client_dir = deployment_dir / "client"
    return {
        "client_dir": client_dir,
        "vless_uri": client_dir / "vless-uri.txt",
        "hiddify_uri_compat": client_dir / "hiddify-uri.txt",
        "v2rayn_uri": client_dir / "v2rayn-uri.txt",
        "hysteria2_uri": client_dir / "hysteria2-uri.txt",
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
    "sing-box-adaptive.json",
    "live-xray-smoke.json",
)

GENERATED_CLIENT_FILE_NAMES = (
    "vless-uri.txt",
    "hiddify-uri.txt",
    "v2rayn-uri.txt",
    "hysteria2-uri.txt",
    "hiddify-cross-platform.json",
    "hiddify-android.json",
    "linux-sing-box.json",
    "windows-xray.json",
    "android-v2rayng-xray.json",
    "windows-route-bypass.ps1",
)


@contextmanager
def _client_artifact_lock(client_dir: Path) -> Iterator[None]:
    with (client_dir.parent / ".client-artifacts.lock").open("a+b") as lock:
        if lock.tell() == 0:
            lock.write(b"\0")
            lock.flush()
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise AppError("Client artifacts are being published by another process; retry later.") from exc
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _publish_client_artifacts(client_dir: Path, payloads: dict[Path, str]) -> None:
    if client_dir.is_symlink() or getattr(client_dir, "is_junction", lambda: False)():
        raise AppError(f"Client output directory must not be a link: {client_dir}")
    client_dir.mkdir(parents=True, exist_ok=True)
    with _client_artifact_lock(client_dir):
        _publish_locked_client_artifacts(client_dir, payloads)


def _publish_locked_client_artifacts(client_dir: Path, payloads: dict[Path, str]) -> None:
    stage = Path(tempfile.mkdtemp(prefix=".client-stage-", dir=client_dir.parent))
    changes: list[tuple[Path, Path]] = []
    keep_backup = False
    try:
        for destination, payload in payloads.items():
            staged = stage / "new" / destination.relative_to(client_dir.parent)
            write_private_text(staged, payload)
            if not payload.strip() or staged.read_text(encoding="utf-8") != payload:
                raise AppError(f"Client artifact is empty or incomplete: {destination.name}")
            if destination.suffix == ".json" and not isinstance(json.loads(payload), dict):
                raise AppError(f"Client profile must be a JSON object: {destination.name}")
            if destination.name in {"vless-uri.txt", "hiddify-uri.txt", "v2rayn-uri.txt"}:
                parse_vless_uri(payload)
            if destination.name == "hysteria2-uri.txt":
                uri = urlparse(payload.strip())
                if uri.scheme != "hysteria2" or not uri.username or not uri.hostname or not uri.port:
                    raise AppError("Invalid Hysteria2 client URI")
        # Nothing in the previous set is removed until every new file is rendered and validated.
        for destination in [*payloads, *(client_dir / name for name in STALE_CLIENT_ARTIFACT_NAMES)]:
            relative = destination.relative_to(client_dir.parent)
            backup = stage / "previous" / relative
            if destination.exists() or destination.is_symlink():
                backup.parent.mkdir(parents=True, exist_ok=True)
                if destination not in payloads or (destination.is_dir() and not destination.is_symlink()):
                    destination.replace(backup)
                else:
                    shutil.copy2(destination, backup, follow_symlinks=False)
            changes.append((destination, backup))
            if destination in payloads:
                (stage / "new" / relative).replace(destination)
    except BaseException:
        keep_backup = True
        rollback_failed = False
        for destination, backup in reversed(changes):
            try:
                if backup.exists() or backup.is_symlink():
                    if backup.is_dir() and not backup.is_symlink():
                        destination.unlink(missing_ok=True)
                    backup.replace(destination)
                else:
                    destination.unlink(missing_ok=True)
            except OSError:
                rollback_failed = True
        if rollback_failed:
            raise AppError(f"Client publication rollback incomplete; previous artifacts retained in {stage}")
        keep_backup = False
        raise
    finally:
        if not keep_backup:
            shutil.rmtree(stage, ignore_errors=True)


def render_next_steps(env: dict[str, str], *, out_dir: Path | None = None) -> str:
    paths = client_artifact_paths(env, out_dir=out_dir)
    status_command = cli_command(f"status --deployment {env['DEPLOY_NAME']} --node gateway")
    verify_command = cli_command(f"verify live --deployment {env['DEPLOY_NAME']}")
    client_diagnose_command = cli_command(
        f"diagnose client --deployment {env['DEPLOY_NAME']} --source <public-ip>"
    )
    return "\n".join(
        [
            f"Deployment: {env['DEPLOY_NAME']}",
            "",
            "Что уже готово:",
            f"- Основной VLESS URI: {paths['vless_uri']}",
            f"- Совместимый Hiddify URI alias: {paths['hiddify_uri_compat']}",
            f"- Нативный v2rayN URI alias: {paths['v2rayn_uri']}",
            f"- Дополнительный стандартный Hysteria2 URI для Hiddify/v2rayN: {paths['hysteria2_uri']}",
            f"- Дополнительный Windows/v2rayN Xray JSON: {paths['windows_xray_json']}",
            f"- Дополнительный Android/v2rayNG Xray JSON: {paths['android_xray_json']}",
            f"- Route-safe VLESS профиль без multiplex для Hiddify: {paths['hiddify_json']}",
            f"- Route-safe Android VLESS профиль без multiplex для Hiddify: {paths['android_hiddify_json']}",
            f"- Windows direct server route helper: {paths['windows_route_bypass']}",
            f"- JSON backup для Linux sing-box: {paths['linux_json']}",
            "",
            "Что делать дальше:",
            f"1. Сначала импортируй {paths['vless_uri'].name}. Это основной контракт: клиент делает обычный VLESS/Reality tunnel, а маршрутизация остаётся на сервере.",
            f"2. Для v2rayN скопируй строку из {paths['v2rayn_uri'].name} и выбери импорт share link из буфера; это тот же канонический VLESS URI без custom-config слоя.",
            f"3. Если клиенту нужен JSON-импорт, используй {paths['hiddify_json'].name}, {paths['windows_xray_json'].name} или {paths['android_xray_json'].name}. В них multiplex явно выключен: большие загрузки не делят один outer TCP stream.",
            f"4. Если клиентский JSON/TUN начинает отправлять на сервер private/fake IP вместо домена, `{cli_command('status')}` покажет это в отдельном bucket `blocked_private_fake`.",
            f"5. Если импортированный URI переиспользует один TCP socket для разных сайтов, `{client_diagnose_command}` покажет multiplex. Для VLESS используй mux-free JSON; не включай Mux в глобальных настройках клиента.",
            f"6. Для импорта QUIC как обычного узла в Hiddify/v2rayN используй {paths['hysteria2_uri'].name}; VLESS URI остаётся основным вариантом для сетей без UDP.",
            f"7. Ручная смена клиентского VLESS/Hysteria2 узла действует только на новые соединения. Серверный underlay failover сохраняет открытые потоки внутри WireGuard overlay, но не может восстановить уже оборванный участок клиент -> RU.",
            f"8. Если сайты висят, сначала смотри серверные группы ошибок: {status_command}",
            f"9. Если включён TUN/full VPN и client-check показывает self-tunnel, запусти PowerShell от администратора: .\\{paths['windows_route_bypass'].name}",
            f"10. После install/reinstall запусти live-приёмку: {verify_command}",
        ]
    ) + "\n"


def render_client_profiles(env: dict[str, str], *, out_dir: Path | None = None) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    paths = client_artifact_paths(env, out_dir=out_dir)
    xray_profile = render_xray_client_profile(env)
    uri_payload = render_vless_uri(env)
    payloads = {
        paths["hiddify_json"]: render_client_profile(env, auto_redirect=False),
        paths["android_hiddify_json"]: render_client_profile(env, auto_redirect=False, android_safe=True),
        paths["linux_json"]: render_client_profile(env, auto_redirect=True),
        paths["windows_xray_json"]: xray_profile,
        paths["android_xray_json"]: xray_profile,
        paths["windows_route_bypass"]: render_windows_route_bypass_script(env),
        paths["vless_uri"]: uri_payload,
        paths["hiddify_uri_compat"]: uri_payload,
        paths["v2rayn_uri"]: uri_payload,
        paths["hysteria2_uri"]: render_hysteria2_uri(env),
        paths["next_steps"]: render_next_steps(env, out_dir=out_dir),
    }
    _publish_client_artifacts(paths["client_dir"], payloads)
    return paths["client_dir"]
