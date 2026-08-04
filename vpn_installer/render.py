from __future__ import annotations

import base64
import json
import shutil
import tarfile
import textwrap
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

from . import client_artifacts as _client_artifacts
from .client_artifacts import (
    client_route_excludes,
    render_client_profile,
    render_vless_uri,
    render_windows_route_bypass_script,
    render_xray_client_profile,
)
from .common import INSTALL_SCRIPT_PATH, OUT_DIR, ROOT_DIR, ensure_file_parent, print_header, warn, write_text
from .config import apply_ru_direct_overlays, download_asset, parse_env_text, render_env_text, require_env, split_asset_sources
from .interserver_transport import (
    HY2_CLASH_API_LISTEN,
    HY2_PORT,
    decode_transport_pem,
    derive_transport_obfs_password,
    derive_transport_password,
)
from .manifest import render_manifest
from .models import (
    CONNTRACK_MAX,
    DEFAULT_ASSET_TIMEOUT,
    PUBLIC_FRONT_TCP_USER_TIMEOUT_MS,
    REQUIRED_ENV_VARS,
    ROLE_FOREIGN,
    ROLE_RU,
    TCP_MTU_PROBE_FLOOR,
    TCP_NO_METRICS_SAVE,
    UDP_RMEM_DEFAULT,
    UDP_RMEM_MAX,
    UDP_WMEM_MAX,
)
from .public_transport import render_public_hy2_inbound
from .routing_policy import build_ru_routing_policy
from .specs import DeploymentSpec
from .system_resolver import render_resolved_dropin


def find_cached_asset(asset_name: str, target_path: Path) -> Path | None:
    candidates: list[Path] = []
    try:
        target_resolved = target_path.resolve()
    except OSError:
        target_resolved = target_path
    for candidate in OUT_DIR.glob(f"*/assets/{asset_name}"):
        if not candidate.is_file():
            continue
        try:
            if candidate.resolve() == target_resolved:
                continue
        except OSError:
            pass
        if candidate.stat().st_size > 0:
            candidates.append(candidate)
    if not candidates:
        return None
    return max(candidates, key=lambda path: (path.stat().st_size, path.stat().st_mtime))


def allow_asset_cache_fallback(sources: list[str]) -> bool:
    for source in sources:
        host = urllib.parse.urlparse(source).hostname or ""
        if host in {"127.0.0.1", "::1", "localhost"}:
            return False
    return True


def fetch_assets(env: dict[str, str], assets_dir: Path) -> dict[str, Path]:
    assets_dir.mkdir(parents=True, exist_ok=True)
    targets = {
        "geosite-ru.srs": (split_asset_sources(env["RU_GEOSITE_URL"]), assets_dir / "geosite-ru.srs"),
        "geoip-ru.srs": (split_asset_sources(env["RU_GEOIP_URL"]), assets_dir / "geoip-ru.srs"),
    }
    required_assets = {"geosite-ru.srs", "geoip-ru.srs"}
    if env.get("FOREIGN_BLOCK_RU", "0") == "1":
        targets["ru-ipv4.zone"] = (split_asset_sources(env["FOREIGN_RU_IPV4_LIST_URL"]), assets_dir / "ru-ipv4.zone")
        targets["ru-ipv6.zone"] = (split_asset_sources(env["FOREIGN_RU_IPV6_LIST_URL"]), assets_dir / "ru-ipv6.zone")
        required_assets.update({"ru-ipv4.zone", "ru-ipv6.zone"})
    print_header("Подкачка rule-set и CIDR-ассетов")
    results: dict[str, Path] = {}
    missing_required: list[str] = []
    for name, (sources, path) in targets.items():
        errors: list[str] = []
        for source in sources:
            try:
                download_asset(source, path, name)
                print(f"{name}: OK")
                results[name] = path
                break
            except (urllib.error.URLError, OSError, RuntimeError) as exc:
                errors.append(f"{source}: {exc}")
        else:
            joined_errors = "; ".join(errors) if errors else "источники не заданы"
            if path.exists() and path.stat().st_size > 0:
                warn(f"{name}: не удалось обновить ни из одного источника, оставляю локальную копию ({joined_errors})")
                results[name] = path
            elif allow_asset_cache_fallback(sources):
                cached_asset = find_cached_asset(name, path)
                if cached_asset is not None:
                    shutil.copy2(cached_asset, path)
                    warn(f"{name}: не удалось обновить ни из одного источника, использую локальный cache {cached_asset} ({joined_errors})")
                    results[name] = path
                else:
                    warn(f"{name}: загрузка не удалась ни из одного источника ({joined_errors})")
                    if name in required_assets:
                        missing_required.append(name)
            else:
                warn(f"{name}: загрузка не удалась ни из одного источника ({joined_errors})")
                if name in required_assets:
                    missing_required.append(name)
    if missing_required:
        raise RuntimeError(f"Не удалось получить обязательные assets: {', '.join(sorted(missing_required))}")
    return results


def render_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def env_int(env: dict[str, str], key: str) -> int:
    return int(env[key])


def env_list(env: dict[str, str], key: str) -> list[str]:
    raw_value = env.get(key, "")
    if not raw_value:
        return []
    result: list[str] = []
    for raw_item in textwrap.dedent(raw_value).replace("\n", ",").split(","):
        item = raw_item.strip()
        if item:
            result.append(item)
    return result


def wg_host_address(cidr: str) -> str:
    return cidr.split("/", 1)[0]


def render_ru_singbox(env: dict[str, str]) -> str:
    log_level = env.get("SING_BOX_LOG_LEVEL", "info").strip() or "info"
    policy = build_ru_routing_policy(env)
    policy_parts = policy.singbox_parts()

    payload = {
        "log": {"level": log_level, "timestamp": True},
        "dns": {
            "strategy": "ipv4_only",
            "servers": [
                {"type": "local", "tag": "dns-ru-direct"},
                {"type": "https", "tag": "dns-global", "server": env["GLOBAL_DOH_SERVER"], "server_port": 443, "path": env["GLOBAL_DOH_PATH"], "detour": "to-foreign", "tls": {"enabled": True, "server_name": env["GLOBAL_DOH_SERVER_NAME"]}},
            ],
            "rules": policy_parts["dns_rules"],
            "final": "dns-global",
            "cache_capacity": 4096,
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "router-in",
                "listen": "127.0.0.1",
                "listen_port": env_int(env, "RU_ROUTER_LISTEN_PORT"),
            },
            render_public_hy2_inbound(env),
        ],
        "outbounds": policy_parts["outbounds"],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"},
            "rule_set": [
                {"tag": "ru-geosite", "type": "local", "format": "binary", "path": f"{env['RULESET_DIR']}/geosite-ru.srs"},
                {"tag": "ru-geoip", "type": "local", "format": "binary", "path": f"{env['RULESET_DIR']}/geoip-ru.srs"},
            ],
            "rules": policy_parts["route_rules"],
            "final": policy_parts["final_outbound"],
        },
        "experimental": {"clash_api": {"external_controller": HY2_CLASH_API_LISTEN}},
    }
    return render_json(payload)


def render_ru_xray(env: dict[str, str]) -> str:
    short_ids = [env["RU_REALITY_SHORT_ID"]]
    if env.get("RU_REALITY_ACCEPT_EMPTY_SHORT_ID", "1").strip().lower() not in {"0", "false", "no", "off"}:
        short_ids.append("")
    reality: dict[str, Any] = {
        "show": False,
        "dest": f"{env['RU_REALITY_HANDSHAKE_SERVER']}:{env_int(env, 'RU_REALITY_HANDSHAKE_PORT')}",
        "xver": 0,
        "serverNames": [env["RU_REALITY_SERVER_NAME"]],
        "privateKey": env["RU_REALITY_PRIVATE_KEY"],
        "shortIds": list(dict.fromkeys(short_ids)),
    }
    payload = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": env_int(env, "RU_LISTEN_PORT"),
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": env["CLIENT_UUID"], "flow": env["CLIENT_FLOW"], "email": f"{env['DEPLOY_NAME']}-client"}],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": reality,
                    "sockopt": {
                        "tcpKeepAliveIdle": 90,
                        "tcpKeepAliveInterval": 15,
                        "tcpUserTimeout": PUBLIC_FRONT_TCP_USER_TIMEOUT_MS,
                    },
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
            }
        ],
        "outbounds": [
            {
                "protocol": "socks",
                "tag": "split-router",
                "settings": {"servers": [{"address": "127.0.0.1", "port": env_int(env, "RU_ROUTER_LISTEN_PORT")}]},
            }
        ],
    }
    return render_json(payload)


def render_foreign_singbox(env: dict[str, str]) -> str:
    return render_json(
        {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "hysteria2",
                    "tag": "interserver-hy2-in",
                    "listen": "0.0.0.0",
                    "listen_port": HY2_PORT,
                    "obfs": {
                        "type": "salamander",
                        "password": derive_transport_obfs_password(env["WG_PRESHARED_KEY"]),
                    },
                    "users": [{"password": derive_transport_password(env["WG_PRESHARED_KEY"])}],
                    "tls": {
                        "enabled": True,
                        "certificate": decode_transport_pem(env["INTERSERVER_HY2_CERTIFICATE_B64"], "certificate"),
                        "key": decode_transport_pem(env["INTERSERVER_HY2_PRIVATE_KEY_B64"], "private key"),
                    },
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
    )


def render_ru_wg(env: dict[str, str]) -> str:
    foreign_v6_host = wg_host_address(env["WG_FOREIGN_ADDRESS_V6"])
    return "\n".join(
        [
            "[Interface]",
            f"Address = {env['WG_RU_ADDRESS']}, {env['WG_RU_ADDRESS_V6']}",
            f"PrivateKey = {env['WG_RU_PRIVATE_KEY']}",
            f"MTU = {env['WG_MTU']}",
            f"FwMark = {env['WG_TUNNEL_FWMARK']}",
            "Table = off",
            f"PostUp = ip -4 route replace {wg_host_address(env['WG_FOREIGN_ADDRESS'])}/32 dev {env['WG_INTERFACE']}",
            f"PostUp = ip -6 route replace {foreign_v6_host}/128 dev {env['WG_INTERFACE']}",
            f"PostUp = ip -4 route replace default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']}",
            f"PostUp = ip -6 route replace default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']}",
            f"PostUp = ip -4 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000 2>/dev/null || true",
            f"PostUp = ip -4 rule add fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000",
            f"PostUp = ip -6 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000 2>/dev/null || true",
            f"PostUp = ip -6 rule add fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000",
            f"PreDown = ip -6 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000 2>/dev/null || true",
            f"PreDown = ip -4 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000 2>/dev/null || true",
            f"PreDown = ip -6 route del default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']} 2>/dev/null || true",
            f"PreDown = ip -4 route del default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']} 2>/dev/null || true",
            f"PreDown = ip -6 route del {foreign_v6_host}/128 dev {env['WG_INTERFACE']} 2>/dev/null || true",
            f"PreDown = ip -4 route del {wg_host_address(env['WG_FOREIGN_ADDRESS'])}/32 dev {env['WG_INTERFACE']} 2>/dev/null || true",
            "",
            "[Peer]",
            f"PublicKey = {env['WG_FOREIGN_PUBLIC_KEY']}",
            f"PresharedKey = {env['WG_PRESHARED_KEY']}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"Endpoint = {env['FOREIGN_PUBLIC_IP']}:{env['WG_PORT']}",
            "",
        ]
    )


def render_foreign_wg(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "[Interface]",
            f"Address = {env['WG_FOREIGN_ADDRESS']}, {env['WG_FOREIGN_ADDRESS_V6']}",
            f"ListenPort = {env['WG_PORT']}",
            f"PrivateKey = {env['WG_FOREIGN_PRIVATE_KEY']}",
            f"MTU = {env['WG_MTU']}",
            "",
            "[Peer]",
            f"PublicKey = {env['WG_RU_PUBLIC_KEY']}",
            f"PresharedKey = {env['WG_PRESHARED_KEY']}",
            f"AllowedIPs = {wg_host_address(env['WG_RU_ADDRESS'])}/32, {wg_host_address(env['WG_RU_ADDRESS_V6'])}/128",
            "",
        ]
    )


def render_foreign_nftables(env: dict[str, str], wan_iface: str) -> str:
    block_ru = env.get("FOREIGN_BLOCK_RU", "0").strip() == "1"
    lines = [
        "flush ruleset",
        "",
        "table inet vpnstack {",
    ]
    if block_ru:
        lines.extend(
            [
                "  set ru_ipv4 {",
                "    type ipv4_addr",
                "    flags interval",
                "    auto-merge",
                "  }",
                "",
                "  set ru_ipv6 {",
                "    type ipv6_addr",
                "    flags interval",
                "    auto-merge",
                "  }",
                "",
            ]
        )
    lines.extend(
        [
            "  chain input {",
            "    type filter hook input priority 0;",
            "    policy drop;",
            "",
            '    iifname "lo" accept',
            "    ct state invalid drop",
            "    ip6 nexthdr icmpv6 accept",
            "    ip protocol icmp accept",
            "    ct state established,related accept",
        ]
    )
    lines.append(f"    tcp dport {env['SSH_PORT']} counter accept")
    forward_rules = [
        f"    ip saddr {env['RU_PUBLIC_IP']} udp dport {env['WG_PORT']} counter accept",
        f"    ip saddr {env['RU_PUBLIC_IP']} udp dport {HY2_PORT} counter accept",
        "  }",
        "",
        "  chain forward {",
        "    type filter hook forward priority 0;",
        "    policy drop;",
        "",
        "    ct state invalid drop",
        "    ct state established,related accept",
    ]
    if block_ru:
        forward_rules.extend(
            [
                f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" ip daddr @ru_ipv4 drop',
                f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" ip6 daddr @ru_ipv6 drop',
            ]
        )
    tcp_mss = max(env_int(env, "WG_MTU") - 40, 536)
    forward_rules.extend(
        [
            f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" tcp flags syn tcp option maxseg size set {tcp_mss} accept',
            f'    iifname "{wan_iface}" oifname "{env["WG_INTERFACE"]}" tcp flags syn tcp option maxseg size set {tcp_mss} accept',
            f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" accept',
            f'    iifname "{wan_iface}" oifname "{env["WG_INTERFACE"]}" ct state established,related accept',
            "  }",
            "}",
            "",
            "table ip nat {",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat;",
            f'    ip saddr {wg_host_address(env["WG_RU_ADDRESS"])} oifname "{wan_iface}" masquerade',
            "  }",
            "}",
            "",
            "table ip6 nat {",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat;",
            f'    ip6 saddr {env["WG_IPV6_PREFIX"]} oifname "{wan_iface}" masquerade',
            "  }",
            "}",
            "",
        ]
    )
    lines.extend(forward_rules)
    return "\n".join(lines)


def render_ru_firewall_nftables(env: dict[str, str]) -> str:
    admin_enabled = env.get("ADMIN_WEB_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
    admin_port = str(env_int(env, "ADMIN_WEB_PORT"))
    admin_active_client_required = env.get("ADMIN_WEB_ACTIVE_CLIENT_REQUIRED", "1").strip().lower() in {"1", "true", "yes", "on"}
    admin_allow_tunnel_clients = env.get("ADMIN_WEB_ALLOW_TUNNEL_CLIENTS", "1").strip().lower() in {"1", "true", "yes", "on"}
    admin_allowed_cidrs = env_list(env, "ADMIN_WEB_ALLOWED_CIDR")
    admin_allow_wg = env.get("ADMIN_WEB_ALLOW_WG", "0").strip().lower() in {"1", "true", "yes", "on"}
    admin_tunnel_sources: list[str] = []
    for key in ("RU_PUBLIC_IP", "FOREIGN_PUBLIC_IP"):
        value = env.get(key, "").strip()
        if value:
            admin_tunnel_sources.append(value)
    lines = [
        "flush ruleset",
        "",
        "table inet vpnstack {",
    ]
    if admin_enabled and admin_active_client_required:
        lines.extend(
            [
                "",
                "  set admin_clients_ipv4 {",
                "    type ipv4_addr",
                "    flags timeout",
                "  }",
            ]
        )
    lines.extend(
        [
            "",
            "  chain prerouting_raw {",
            "    type filter hook prerouting priority raw;",
            "    policy accept;",
            f'    tcp dport {env["RU_LISTEN_PORT"]} counter notrack comment "vpnstack-xray-in-notrack"',
            f'    udp dport {env["RU_LISTEN_PORT"]} counter notrack comment "vpnstack-hy2-in-notrack"',
            "  }",
            "",
            "  chain output_raw {",
            "    type filter hook output priority raw;",
            "    policy accept;",
            f'    tcp sport {env["RU_LISTEN_PORT"]} counter notrack comment "vpnstack-xray-out-notrack"',
            f'    udp sport {env["RU_LISTEN_PORT"]} counter notrack comment "vpnstack-hy2-out-notrack"',
            "  }",
            "",
            "  chain input {",
            "    type filter hook input priority 0;",
            "    policy drop;",
            "",
            '    iifname "lo" accept',
            "    ct state invalid drop",
            "    ip6 nexthdr icmpv6 accept",
            "    ip protocol icmp accept",
            "    ct state established,related accept",
        ]
    )
    if admin_enabled and admin_active_client_required:
        lines.append(f'    ip saddr @admin_clients_ipv4 tcp dport {admin_port} counter accept comment "vpnstack-admin-active-client"')
    if admin_enabled and admin_active_client_required and admin_allow_tunnel_clients and admin_tunnel_sources:
        lines.append(f'    ip saddr {{ {", ".join(admin_tunnel_sources)} }} tcp dport {admin_port} counter accept comment "vpnstack-admin-tunnel-client"')
    if admin_enabled and admin_allow_wg:
        lines.append(f'    iifname "{env["WG_INTERFACE"]}" tcp dport {admin_port} counter accept')
    if admin_enabled and admin_allowed_cidrs:
        lines.append(f"    ip saddr {{ {', '.join(admin_allowed_cidrs)} }} tcp dport {admin_port} counter accept")
    lines.append(f"    tcp dport {env['SSH_PORT']} counter accept")
    lines.append(f"    tcp dport {env['RU_LISTEN_PORT']} counter accept")
    lines.append(f"    udp dport {env['RU_LISTEN_PORT']} counter accept")
    lines.extend(["  }", "}", ""])
    return "\n".join(lines)


def render_admin_web_service() -> str:
    return textwrap.dedent(
        """
        [Unit]
        Description=vpn-stack web admin
        After=network-online.target sing-box.service
        Wants=network-online.target sing-box.service

        [Service]
        Type=simple
        ExecStart=/usr/bin/python3 /usr/local/lib/vpn-stack/admin_web.py
        Restart=on-failure
        RestartSec=3

        [Install]
        WantedBy=multi-user.target
        """
    ).strip() + "\n"


def render_xray_service() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=vpn-stack Xray public VLESS/Reality front",
            "After=network-online.target sing-box.service",
            "Wants=network-online.target sing-box.service",
            "",
            "[Service]",
            "Type=simple",
            "ExecStart=/usr/bin/env xray run -c /etc/xray/config.json",
            "Restart=on-failure",
            "RestartSec=3s",
            "LimitNOFILE=1048576",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def render_sshd_hardening(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "# Managed by vpn-stack",
            f"LoginGraceTime {env['SSH_LOGIN_GRACE_TIME']}",
            f"MaxAuthTries {env['SSH_MAX_AUTH_TRIES']}",
            f"MaxStartups {env['SSH_MAX_STARTUPS']}",
            f"PerSourceMaxStartups {env['SSH_PER_SOURCE_MAX_STARTUPS']}",
            f"PerSourceNetBlockSize {env['SSH_PER_SOURCE_NETBLOCK_SIZE']}",
            "UseDNS no",
            "KbdInteractiveAuthentication no",
            "PasswordAuthentication yes",
            "AllowTcpForwarding yes",
            "",
        ]
    )


def render_sysctl(role: str) -> str:
    lines = [
        "net.core.default_qdisc=fq",
        f"net.core.rmem_max={UDP_RMEM_MAX}",
        f"net.core.rmem_default={UDP_RMEM_DEFAULT}",
        f"net.core.wmem_max={UDP_WMEM_MAX}",
        f"net.netfilter.nf_conntrack_max={CONNTRACK_MAX}",
        "net.ipv4.tcp_syncookies=1",
        "net.ipv4.tcp_congestion_control=bbr",
        "net.ipv4.tcp_mtu_probing=1",
        f"net.ipv4.tcp_mtu_probe_floor={TCP_MTU_PROBE_FLOOR}",
        f"net.ipv4.tcp_no_metrics_save={TCP_NO_METRICS_SAVE}",
    ]
    if role == ROLE_RU:
        lines.append("net.ipv4.conf.all.src_valid_mark=1")
    else:
        lines.extend(("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"))
    return "\n".join((*lines, ""))


def render_modules_load() -> str:
    return "nf_conntrack\n"


def journal_limits_enabled(env: dict[str, str]) -> bool:
    return env["JOURNAL_LIMIT_ENABLED"].strip().lower() not in {"0", "false", "no", "off"}


def render_journald_dropin(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "[Journal]",
            f"SystemMaxUse={env['JOURNAL_SYSTEM_MAX_USE']}",
            f"MaxRetentionSec={env['JOURNAL_MAX_RETENTION_SEC']}",
            "",
        ]
    )


def render_apt_periodic_dropin() -> str:
    return 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'


def server_script_asset(name: str) -> str:
    return (ROOT_DIR / "vpn_installer" / name).read_text(encoding="utf-8")


def render_health_service() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Check vpn-stack runtime health",
            "After=network-online.target ssh.service",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=oneshot",
            "ExecStart=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py health",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def render_health_timer() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Periodic vpn-stack runtime health check",
            "",
            "[Timer]",
            "OnBootSec=1min",
            "OnUnitActiveSec=2min",
            "AccuracySec=15s",
            "Unit=vpn-stack-health.service",
            "",
            "[Install]",
            "WantedBy=timers.target",
            "",
        ]
    )


def render_transport_service() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Maintain the preferred vpn-stack interserver transport",
            "After=network-online.target sing-box.service",
            "Requires=sing-box.service",
            "PartOf=sing-box.service",
            "",
            "[Service]",
            "Type=simple",
            "ExecStart=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py transport-watch",
            "Restart=on-failure",
            "RestartSec=2s",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectHome=true",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/vpn-stack /run",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )

def deployment_out_dir(env: dict[str, str]) -> Path:
    return OUT_DIR / env["DEPLOY_NAME"]


def client_artifact_paths(env: dict[str, str]) -> dict[str, Path]:
    return _client_artifacts.client_artifact_paths(env, out_dir=OUT_DIR)


def render_next_steps(env: dict[str, str]) -> str:
    return _client_artifacts.render_next_steps(env, out_dir=OUT_DIR)


def render_client_profiles(env: dict[str, str]) -> Path:
    return _client_artifacts.render_client_profiles(env, out_dir=OUT_DIR)


def preview_dir_for_role(preview_root: Path, role: str) -> Path:
    return preview_root / ("ru" if role == ROLE_RU else "foreign")


def reset_generated_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def rendered_files_for_role(env: dict[str, str], role: str, *, assets: dict[str, Path] | None = None) -> dict[str, str]:
    env = DeploymentSpec.from_env(env).for_role(role).values
    if role == ROLE_RU:
        files = {
            "sing-box.json": render_ru_singbox(env),
            "xray.json": render_ru_xray(env),
            f"{env['WG_INTERFACE']}.conf": render_ru_wg(env),
            "nftables.conf": render_ru_firewall_nftables(env),
            "sshd-vpn-stack.conf": render_sshd_hardening(env),
            "sysctl-vpn-stack.conf": render_sysctl(role),
            "modules-vpn-stack.conf": render_modules_load(),
            "apt-vpn-stack-unattended.conf": render_apt_periodic_dropin(),
            "resolved-vpn-stack.conf": render_resolved_dropin(),
            "vpn-stack-agent.py": server_script_asset("server_agent.py"),
            "log_classifier.py": server_script_asset("log_classifier.py"),
            "interserver_transport.py": server_script_asset("interserver_transport.py"),
            "admin_apply.py": server_script_asset("admin_apply.py"),
            "admin_web.py": server_script_asset("admin_web.py"),
            "vpn-stack-health.service": render_health_service(),
            "vpn-stack-health.timer": render_health_timer(),
            "vpn-stack-transport.service": render_transport_service(),
            "vpn-stack-admin.service": render_admin_web_service(),
            "vpn-stack-xray.service": render_xray_service(),
        }
        if journal_limits_enabled(env):
            files["journald-vpn-stack.conf"] = render_journald_dropin(env)
        files["render-manifest.json"] = render_manifest(render_env_text(env), role, files, assets=assets)
        return files
    wan_iface = env.get("WAN_INTERFACE", "").strip() or "eth0"
    files = {
        "sing-box.json": render_foreign_singbox(env),
        f"{env['WG_INTERFACE']}.conf": render_foreign_wg(env),
        "nftables.conf": render_foreign_nftables(env, wan_iface),
        "sshd-vpn-stack.conf": render_sshd_hardening(env),
        "sysctl-vpn-stack.conf": render_sysctl(role),
        "modules-vpn-stack.conf": render_modules_load(),
        "apt-vpn-stack-unattended.conf": render_apt_periodic_dropin(),
        "resolved-vpn-stack.conf": render_resolved_dropin(),
        "vpn-stack-agent.py": server_script_asset("server_agent.py"),
        "log_classifier.py": server_script_asset("log_classifier.py"),
        "interserver_transport.py": server_script_asset("interserver_transport.py"),
        "vpn-stack-health.service": render_health_service(),
        "vpn-stack-health.timer": render_health_timer(),
    }
    if journal_limits_enabled(env):
        files["journald-vpn-stack.conf"] = render_journald_dropin(env)
    files["render-manifest.json"] = render_manifest(render_env_text(env), role, files, assets=assets)
    return files


def write_role_rendered_files(env: dict[str, str], role: str, output_dir: Path, *, assets: dict[str, Path] | None = None) -> Path:
    for name, content in rendered_files_for_role(env, role, assets=assets).items():
        write_text(output_dir / name, content)
    return output_dir


def copy_python_package(target_root: Path) -> Path:
    destination = target_root / "vpn_installer"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(ROOT_DIR / "vpn_installer", destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return destination


def render_preview_files(env: dict[str, str], preview_dir: Path, *, assets: dict[str, Path] | None = None) -> None:
    reset_generated_dir(preview_dir_for_role(preview_dir, ROLE_RU))
    reset_generated_dir(preview_dir_for_role(preview_dir, ROLE_FOREIGN))
    write_role_rendered_files(env, ROLE_RU, preview_dir_for_role(preview_dir, ROLE_RU), assets=assets)
    write_role_rendered_files(env, ROLE_FOREIGN, preview_dir_for_role(preview_dir, ROLE_FOREIGN), assets=assets)


def render_config_artifacts(env_path: Path, env: dict[str, str], *, fetch_assets_first: bool = True) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    out_dir = deployment_out_dir(env)
    assets_dir = out_dir / "assets"
    server_dir = out_dir / "server"
    preview_dir = out_dir / "preview"
    assets = fetch_assets(env, assets_dir) if fetch_assets_first else {path.name: path for path in assets_dir.glob("*") if path.is_file()}
    reset_generated_dir(server_dir)
    write_text(server_dir / "ru.env", render_env_text(env))
    write_text(server_dir / "foreign.env", render_env_text(env))
    render_preview_files(env, preview_dir, assets=assets)
    return out_dir


def emit_cloud_init_assets(assets_dir: Path) -> str:
    lines: list[str] = []
    for asset_name in ("geosite-ru.srs", "geoip-ru.srs", "ru-ipv4.zone", "ru-ipv6.zone"):
        asset_path = assets_dir / asset_name
        if asset_path.is_file():
            encoded = base64.b64encode(asset_path.read_bytes()).decode("ascii")
            lines.extend([f"  - path: /root/vpn-stack/assets/{asset_name}", "    permissions: '0644'", "    encoding: b64", f"    content: {encoded}"])
    return "\n".join(lines)


def emit_cloud_init_tree(source_dir: Path, destination_prefix: str) -> str:
    lines: list[str] = []
    executable_names = {"install.sh"}
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source_dir).as_posix()
        destination = f"{destination_prefix.rstrip('/')}/{relative}"
        permissions = "0755" if path.name in executable_names else "0644"
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        lines.extend([f"  - path: {destination}", f"    permissions: '{permissions}'", "    encoding: b64", f"    content: {encoded}"])
    return "\n".join(lines)


def render_cloud_init_role(role: str, env_text: str, assets_dir: Path) -> str:
    cloud_root = OUT_DIR / ".cloud-init-stage" / role
    if cloud_root.exists():
        shutil.rmtree(cloud_root)
    try:
        cloud_root.mkdir(parents=True, exist_ok=True)
        write_text(cloud_root / "install.sh", INSTALL_SCRIPT_PATH.read_text(encoding="utf-8"))
        write_text(cloud_root / "deployment.env", env_text)
        copy_python_package(cloud_root)
        assets = {path.name: path for path in assets_dir.glob("*") if path.is_file()}
        write_role_rendered_files(env=parse_env_text(env_text), role=role, output_dir=cloud_root / "rendered", assets=assets)
        lines = [
            "#cloud-config",
            "package_update: true",
            "write_files:",
        ]
        lines.append(emit_cloud_init_tree(cloud_root, "/root/vpn-stack"))
        asset_block = emit_cloud_init_assets(assets_dir)
        if asset_block:
            lines.append(asset_block)
        lines.extend(["runcmd:", f'  - [bash, -lc, "cd /root/vpn-stack && ./install.sh --role {role} --env-file /root/vpn-stack/deployment.env --assets-dir /root/vpn-stack/assets"]', ""])
        return "\n".join(lines)
    finally:
        if cloud_root.exists():
            shutil.rmtree(cloud_root, ignore_errors=True)


def render_cloud_init_artifacts(env: dict[str, str]) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    out_dir = deployment_out_dir(env)
    assets_dir = out_dir / "assets"
    cloud_dir = out_dir / "cloud-init"
    reset_generated_dir(cloud_dir)
    write_text(cloud_dir / "ru.yaml", render_cloud_init_role(ROLE_RU, render_env_text(env), assets_dir))
    write_text(cloud_dir / "foreign.yaml", render_cloud_init_role(ROLE_FOREIGN, render_env_text(env), assets_dir))
    return cloud_dir


def copy_asset_if_present(source: Path, destination: Path) -> None:
    if source.is_file():
        ensure_file_parent(destination)
        shutil.copy2(source, destination)


def create_tarball(source_dir: Path, destination_tarball: Path) -> None:
    ensure_file_parent(destination_tarball)
    with tarfile.open(destination_tarball, "w:gz") as archive:
        for item in sorted(source_dir.rglob("*")):
            archive.add(item, arcname=str(item.relative_to(source_dir)))


def package_bundle(env: dict[str, str]) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    out_dir = deployment_out_dir(env)
    assets_dir = out_dir / "assets"
    server_dir = out_dir / "server"
    bundle_dir = out_dir / "bundle"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    ru_bundle = bundle_dir / ROLE_RU
    foreign_bundle = bundle_dir / ROLE_FOREIGN
    write_text(bundle_dir / "README.txt", "\n".join(["ru-gateway:", "  tar -xzf ru-gateway.tar.gz", "  sudo ./install.sh --role ru-gateway --env-file ./deployment.env --assets-dir ./assets", "", "foreign-exit:", "  tar -xzf foreign-exit.tar.gz", "  sudo ./install.sh --role foreign-exit --env-file ./deployment.env --assets-dir ./assets", ""]))
    ensure_file_parent(ru_bundle / "assets" / ".keep")
    ensure_file_parent(foreign_bundle / "assets" / ".keep")
    shutil.copy2(INSTALL_SCRIPT_PATH, ru_bundle / "install.sh")
    shutil.copy2(INSTALL_SCRIPT_PATH, foreign_bundle / "install.sh")
    shutil.copy2(server_dir / "ru.env", ru_bundle / "deployment.env")
    shutil.copy2(server_dir / "foreign.env", foreign_bundle / "deployment.env")
    copy_python_package(ru_bundle)
    copy_python_package(foreign_bundle)
    shutil.copytree(preview_dir_for_role(out_dir / "preview", ROLE_RU), ru_bundle / "rendered", dirs_exist_ok=True)
    shutil.copytree(preview_dir_for_role(out_dir / "preview", ROLE_FOREIGN), foreign_bundle / "rendered", dirs_exist_ok=True)
    for asset_name in ("geosite-ru.srs", "geoip-ru.srs"):
        copy_asset_if_present(assets_dir / asset_name, ru_bundle / "assets" / asset_name)
    if env.get("FOREIGN_BLOCK_RU", "0") == "1":
        for asset_name in ("ru-ipv4.zone", "ru-ipv6.zone"):
            copy_asset_if_present(assets_dir / asset_name, foreign_bundle / "assets" / asset_name)
    create_tarball(ru_bundle, bundle_dir / f"{ROLE_RU}.tar.gz")
    create_tarball(foreign_bundle, bundle_dir / f"{ROLE_FOREIGN}.tar.gz")
    return bundle_dir


def render_all_artifacts(
    env_path: Path,
    env: dict[str, str],
    *,
    fetch_assets_first: bool = True,
) -> Path:
    effective_env = apply_ru_direct_overlays(env, env_path)
    out_dir = render_config_artifacts(
        env_path,
        effective_env,
        fetch_assets_first=fetch_assets_first,
    )
    render_client_profiles(effective_env)
    render_cloud_init_artifacts(effective_env)
    package_bundle(effective_env)
    return out_dir
