from __future__ import annotations

import base64
import json
import os
import shutil
import tarfile
import tempfile
import textwrap
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any, Iterable

from .common import INSTALL_SCRIPT_PATH, OUT_DIR, ROOT_DIR, ensure_file_parent, print_header, warn, write_private_text, write_text
from .config import apply_ru_direct_overlays, download_asset, parse_env_text, render_env_text, require_env, split_asset_sources
from .interserver_transport import (
    FOREIGN_DNS_RELAY_PORT,
    HY2_CLASH_API_LISTEN,
    HY2_PORT,
    TRANSPORT_RELAY_PORT,
    UNDERLAY_WG_FOREIGN_ADDRESS,
    UNDERLAY_WG_RU_ADDRESS,
    build_ru_transport_topology,
    decode_transport_pem,
    derive_transport_obfs_password,
    derive_transport_password,
    foreign_underlay_wireguard_peer,
)
from .manifest import finalize_node_files, render_manifest, render_node_env_text, required_asset_names
from .models import (
    DEFAULT_ASSET_TIMEOUT,
    REQUIRED_ENV_VARS,
)
from .network_profile import (
    CONNTRACK_MAX,
    FQ_KIND,
    TCP_MTU_PROBE_FLOOR,
    TCP_NO_METRICS_SAVE,
    UDP_RMEM_DEFAULT,
    UDP_RMEM_MAX,
    UDP_WMEM_DEFAULT,
    UDP_WMEM_MAX,
    wireguard_policy_spec,
)
from .public_transport import render_public_hy2_inbound
from .routing_policy import PRIVATE_OR_FAKE_DESTINATION_CIDRS, build_gateway_routing_policy
from .specs import DeploymentSpec, reality_handshake_target
from .system_resolver import render_resolved_dropin
from .topology import CAP_WEB_ADMIN, NODE_EXIT, NODE_GATEWAY, TopologySpec, normalize_node_id


SERVER_RENDER_MODULES = (
    "__init__.py",
    "admin_apply.py",
    "admin_web.py",
    "common.py",
    "compatibility.py",
    "config.py",
    "diagnostics.py",
    "dns_policy.py",
    "install_contract.py",
    "install_support.py",
    "interserver_transport.py",
    "log_classifier.py",
    "manifest.py",
    "models.py",
    "network_profile.py",
    "public_transport.py",
    "release_integrity.py",
    "resource_control.py",
    "render.py",
    "routing_policy.py",
    "server_agent.py",
    "specs.py",
    "system_resolver.py",
    "topology.py",
)

SERVER_AGENT_BASE_MODULES = (
    "diagnostics.py",
    "log_classifier.py",
    "network_profile.py",
    "release_integrity.py",
    "resource_control.py",
)
SERVER_AGENT_INTERSERVER_MODULES = (
    "interserver_transport.py",
    "topology.py",
)


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
    topology = TopologySpec.from_env(env, require_addresses=False)
    targets: dict[str, tuple[list[str], Path]] = {}
    required_assets: set[str] = set()
    if topology.is_dual:
        targets.update(
            {
                "geosite-ru.srs": (split_asset_sources(env["RU_GEOSITE_URL"]), assets_dir / "geosite-ru.srs"),
                "geoip-ru.srs": (split_asset_sources(env["RU_GEOIP_URL"]), assets_dir / "geoip-ru.srs"),
            }
        )
        required_assets.update({"geosite-ru.srs", "geoip-ru.srs"})
    if topology.is_dual and env.get("FOREIGN_BLOCK_RU", "0") == "1":
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


def render_gateway_singbox(env: dict[str, str]) -> str:
    log_level = env.get("SING_BOX_LOG_LEVEL", "warn").strip() or "warn"
    topology = TopologySpec.from_env(env)
    policy = build_gateway_routing_policy(env)
    policy_parts = policy.singbox_parts()
    transport = build_ru_transport_topology(env) if topology.is_dual else {
        "inbounds": [],
        "endpoints": [],
        "outbounds": [],
        "route_rules": [],
    }
    if topology.is_dual:
        dns_servers = [
            {"type": "local", "tag": "dns-ru-direct"},
            {
                "type": "tcp",
                "tag": "dns-global",
                "server": wg_host_address(env["WG_FOREIGN_ADDRESS"]),
                "server_port": FOREIGN_DNS_RELAY_PORT,
                "detour": "to-foreign",
            },
        ]
        dns_final = "dns-global"
        rule_set = [
            {"tag": "ru-geosite", "type": "local", "format": "binary", "path": f"{env['RULESET_DIR']}/geosite-ru.srs"},
            {"tag": "ru-geoip", "type": "local", "format": "binary", "path": f"{env['RULESET_DIR']}/geoip-ru.srs"},
        ]
    else:
        dns_servers = [{"type": "local", "tag": "dns-local"}]
        dns_final = "dns-local"
        rule_set = []
    outbounds = [*policy_parts["outbounds"], *transport["outbounds"]]
    policy.validate_runtime_targets(
        dns_servers=(server["tag"] for server in dns_servers),
        outbounds=(outbound["tag"] for outbound in outbounds),
    )

    payload = {
        "log": {"level": log_level, "timestamp": True},
        "dns": {
            "strategy": "prefer_ipv4",
            "servers": dns_servers,
            "rules": policy_parts["dns_rules"],
            "final": dns_final,
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
            *transport["inbounds"],
        ],
        "endpoints": transport["endpoints"],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": dns_final, "strategy": "prefer_ipv4"},
            "rules": [*transport["route_rules"], *policy_parts["route_rules"]],
            "final": policy_parts["final_outbound"],
        },
        "experimental": {"cache_file": {"enabled": True, "path": "/var/lib/vpn-stack/cache.db"}},
    }
    if rule_set:
        payload["route"]["rule_set"] = rule_set
    if topology.is_dual:
        payload["experimental"]["clash_api"] = {"external_controller": HY2_CLASH_API_LISTEN}
    return render_json(payload)


def render_gateway_xray(env: dict[str, str]) -> str:
    topology = TopologySpec.from_env(env)
    short_ids = [env["RU_REALITY_SHORT_ID"]]
    if env.get("RU_REALITY_ACCEPT_EMPTY_SHORT_ID", "1").strip().lower() not in {"0", "false", "no", "off"}:
        short_ids.append("")
    reality: dict[str, Any] = {
        "show": False,
        "target": reality_handshake_target(env["RU_REALITY_SERVER_NAME"]),
        "xver": 0,
        "serverNames": [env["RU_REALITY_SERVER_NAME"]],
        "privateKey": env["RU_REALITY_PRIVATE_KEY"],
        "shortIds": list(dict.fromkeys(short_ids)),
    }
    outbounds: list[dict[str, Any]] = [
        {
            "protocol": "socks",
            "tag": "split-router",
            "settings": {"servers": [{"address": "127.0.0.1", "port": env_int(env, "RU_ROUTER_LISTEN_PORT")}]},
        },
    ]
    routing_rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "network": "udp",
            "ip": list(PRIVATE_OR_FAKE_DESTINATION_CIDRS),
            "outboundTag": "blocked",
        },
    ]
    dns: dict[str, Any] | None = None
    if topology.is_dual:
        dns = {
            "servers": [
                {
                    "address": f"tcp://{wg_host_address(env['WG_FOREIGN_ADDRESS'])}",
                    "port": FOREIGN_DNS_RELAY_PORT,
                    "tag": "xray-global-dns",
                    "queryStrategy": "UseIP",
                    "skipFallback": True,
                }
            ],
            "queryStrategy": "UseIP",
            "disableCache": False,
        }
        outbounds.append(
            {
                "protocol": "freedom",
                "tag": "foreign-overlay",
                "settings": {"domainStrategy": "UseIP"},
                "streamSettings": {
                    "sockopt": {
                        "interface": env["WG_INTERFACE"],
                        "mark": env_int(env, "APP_ROUTE_MARK"),
                    }
                },
            }
        )
        routing_rules.insert(0, {"type": "field", "inboundTag": ["xray-global-dns"], "outboundTag": "foreign-overlay"})
        routing_rules.append({"type": "field", "network": "udp", "outboundTag": "foreign-overlay"})
    else:
        routing_rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "split-router"})
    outbounds.append({"protocol": "blackhole", "tag": "blocked"})
    payload: dict[str, Any] = {
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
                    },
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
            }
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules,
        },
    }
    if dns is not None:
        payload["dns"] = dns
    return render_json(payload)


def render_foreign_singbox(env: dict[str, str]) -> str:
    return render_json(
        {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "direct",
                    "tag": "dns-relay-in",
                    "listen": "0.0.0.0",
                    "listen_port": FOREIGN_DNS_RELAY_PORT,
                    "override_address": "127.0.0.53",
                    "override_port": 53,
                },
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
    policy = wireguard_policy_spec(env)
    interface = str(policy["interface"])
    route_table = int(policy["table"])
    route_mark = int(policy["mark"])
    priority = int(policy["priority"])
    foreign_v4_host = str(policy["ipv4_peer"])
    foreign_v6_host = str(policy["ipv6_peer"])
    return "\n".join(
        [
            "[Interface]",
            f"Address = {env['WG_RU_ADDRESS']}, {env['WG_RU_ADDRESS_V6']}",
            f"PrivateKey = {env['WG_RU_PRIVATE_KEY']}",
            f"MTU = {env['WG_MTU']}",
            f"FwMark = {env['WG_TUNNEL_FWMARK']}",
            "Table = off",
            f"PostUp = ip -4 route replace {foreign_v4_host}/32 dev {interface}",
            f"PostUp = ip -6 route replace {foreign_v6_host}/128 dev {interface}",
            f"PostUp = ip -4 route replace default dev {interface} table {route_table}",
            f"PostUp = ip -6 route replace default dev {interface} table {route_table}",
            f"PostUp = ip -4 rule del fwmark {route_mark} table {route_table} priority {priority} 2>/dev/null || true",
            f"PostUp = ip -4 rule add fwmark {route_mark} table {route_table} priority {priority}",
            f"PostUp = ip -6 rule del fwmark {route_mark} table {route_table} priority {priority} 2>/dev/null || true",
            f"PostUp = ip -6 rule add fwmark {route_mark} table {route_table} priority {priority}",
            f"PreDown = ip -6 rule del fwmark {route_mark} table {route_table} priority {priority} 2>/dev/null || true",
            f"PreDown = ip -4 rule del fwmark {route_mark} table {route_table} priority {priority} 2>/dev/null || true",
            f"PreDown = ip -6 route del default dev {interface} table {route_table} 2>/dev/null || true",
            f"PreDown = ip -4 route del default dev {interface} table {route_table} 2>/dev/null || true",
            f"PreDown = ip -6 route del {foreign_v6_host}/128 dev {interface} 2>/dev/null || true",
            f"PreDown = ip -4 route del {foreign_v4_host}/32 dev {interface} 2>/dev/null || true",
            "",
            "[Peer]",
            f"PublicKey = {env['WG_FOREIGN_PUBLIC_KEY']}",
            f"PresharedKey = {env['WG_PRESHARED_KEY']}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"Endpoint = 127.0.0.1:{TRANSPORT_RELAY_PORT}",
            "PersistentKeepalive = 1",
            "",
        ]
    )


def render_foreign_wg(env: dict[str, str]) -> str:
    underlay_peer = foreign_underlay_wireguard_peer(env["WG_PRESHARED_KEY"])
    return "\n".join(
        [
            "[Interface]",
            f"Address = {env['WG_FOREIGN_ADDRESS']}, {env['WG_FOREIGN_ADDRESS_V6']}, {UNDERLAY_WG_FOREIGN_ADDRESS}",
            f"ListenPort = {env['WG_PORT']}",
            f"PrivateKey = {env['WG_FOREIGN_PRIVATE_KEY']}",
            f"MTU = {env['WG_MTU']}",
            "",
            "[Peer]",
            f"PublicKey = {env['WG_RU_PUBLIC_KEY']}",
            f"PresharedKey = {env['WG_PRESHARED_KEY']}",
            f"AllowedIPs = {wg_host_address(env['WG_RU_ADDRESS'])}/32, {wg_host_address(env['WG_RU_ADDRESS_V6'])}/128",
            "",
            "[Peer]",
            f"PublicKey = {underlay_peer['public_key']}",
            f"PresharedKey = {underlay_peer['pre_shared_key']}",
            f"AllowedIPs = {underlay_peer['allowed_ip']}",
            "",
        ]
    )


def render_foreign_nftables(env: dict[str, str], wan_iface: str) -> str:
    block_ru = env.get("FOREIGN_BLOCK_RU", "0").strip() == "1"
    lines = [
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
    lines.append(
        f'    iifname "{env["WG_INTERFACE"]}" ip saddr {wg_host_address(env["WG_RU_ADDRESS"])} tcp dport {FOREIGN_DNS_RELAY_PORT} counter accept'
    )
    lines.append(
        f'    iifname "{env["WG_INTERFACE"]}" ip saddr {wg_host_address(UNDERLAY_WG_RU_ADDRESS)} udp dport {FOREIGN_DNS_RELAY_PORT} counter accept'
    )
    forward_rules = [
        f'    iifname "{env["WG_INTERFACE"]}" ip saddr {wg_host_address(UNDERLAY_WG_RU_ADDRESS)} udp dport {env["WG_PORT"]} counter accept',
        f"    ip saddr {env['GATEWAY_PUBLIC_IP']} udp dport {env['WG_PORT']} counter accept",
        f"    ip saddr {env['GATEWAY_PUBLIC_IP']} udp dport {HY2_PORT} counter accept",
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
            "table ip vpnstack_nat4 {",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat;",
            f'    ip saddr {{ {wg_host_address(env["WG_RU_ADDRESS"])}, {wg_host_address(UNDERLAY_WG_RU_ADDRESS)} }} oifname "{wan_iface}" masquerade',
            "  }",
            "}",
            "",
            "table ip6 vpnstack_nat6 {",
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


def render_ru_firewall_nftables(env: dict[str, str], *, web_admin: bool = False) -> str:
    lines = [
        "table inet vpnstack {",
    ]
    if web_admin:
        lines.extend(
            [
                "",
                "  set admin_clients_ipv4 {",
                "    type ipv4_addr",
                "    flags dynamic,timeout",
                "    timeout 3m",
                "  }",
                "",
                "  set admin_clients_ipv6 {",
                "    type ipv6_addr",
                "    flags dynamic,timeout",
                "    timeout 3m",
                "  }",
            ]
        )
    lines.extend(
        [
            "",
            "  chain prerouting_raw {",
            "    type filter hook prerouting priority raw;",
            "    policy accept;",
            *(
                [
                    f'    meta nfproto ipv4 tcp dport {env["RU_LISTEN_PORT"]} update @admin_clients_ipv4 {{ ip saddr timeout 3m }}',
                    f'    meta nfproto ipv6 tcp dport {env["RU_LISTEN_PORT"]} update @admin_clients_ipv6 {{ ip6 saddr timeout 3m }}',
                    f'    meta nfproto ipv4 udp dport {env["RU_LISTEN_PORT"]} update @admin_clients_ipv4 {{ ip saddr timeout 3m }}',
                    f'    meta nfproto ipv6 udp dport {env["RU_LISTEN_PORT"]} update @admin_clients_ipv6 {{ ip6 saddr timeout 3m }}',
                ]
                if web_admin
                else []
            ),
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
    lines.append(f"    tcp dport {env['SSH_PORT']} counter accept")
    lines.append(f"    tcp dport {env['RU_LISTEN_PORT']} counter accept")
    lines.append(f"    udp dport {env['RU_LISTEN_PORT']} counter accept")
    if web_admin:
        lines.append(f"    tcp dport {env['ADMIN_WEB_PORT']} ip saddr @admin_clients_ipv4 counter accept")
        lines.append(f"    tcp dport {env['ADMIN_WEB_PORT']} ip6 saddr @admin_clients_ipv6 counter accept")
    lines.extend(["  }", "}", ""])
    return "\n".join(lines)


def render_nft_apply_script() -> str:
    return textwrap.dedent(
        """
        #!/bin/sh
        set -eu

        mode=apply
        if [ "${1:-}" = "--check" ] || [ "${1:-}" = "--delete" ]; then
          mode=${1#--}
          shift
        fi
        config=${1:-/etc/vpn-stack/nftables.conf}
        batch=$(mktemp)
        trap 'rm -f "$batch"' EXIT HUP INT TERM

        owned_tables="inet:vpnstack ip:vpnstack_nat4 ip6:vpnstack_nat6"
        for owned_table in $owned_tables; do
          family=${owned_table%%:*}
          table=${owned_table#*:}
          if nft list table "$family" "$table" >/dev/null 2>&1; then
            printf 'delete table %s %s\n' "$family" "$table" >>"$batch"
          fi
        done
        if [ "$mode" != delete ]; then
          cat "$config" >>"$batch"
        fi
        [ -s "$batch" ] || exit 0
        nft --check --file "$batch"
        [ "$mode" != check ] || exit 0
        nft --file "$batch"
        """
    ).strip() + "\n"


def render_nftables_service() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Apply vpn-stack-owned nftables tables",
            "DefaultDependencies=no",
            "After=systemd-modules-load.service",
            "Before=network-pre.target",
            "Wants=network-pre.target",
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            "ExecStart=/bin/sh /usr/local/lib/vpn-stack/nft-apply.sh /etc/vpn-stack/nftables.conf",
            "ExecReload=/bin/sh /usr/local/lib/vpn-stack/nft-apply.sh /etc/vpn-stack/nftables.conf",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


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
            "ExecStart=/etc/vpn-stack/current/bin/xray run -c /etc/xray/config.json",
            "Restart=on-failure",
            "RestartSec=3s",
            "LimitNOFILE=1048576",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def render_singbox_service(node_id: str, *, operator_routing: bool = True) -> str:
    service_lines = [
            "[Unit]",
            "Description=vpn-stack sing-box router",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=simple",
    ]
    if normalize_node_id(node_id) == NODE_GATEWAY and operator_routing:
        service_lines.append(
            "ExecStartPre=/usr/bin/python3 /etc/vpn-stack/current/admin_apply.py --base /etc/vpn-stack/current/sing-box.json --config /etc/sing-box/config.json --rules /etc/vpn-stack/admin-routing-rules.json --no-restart"
        )
    service_lines.extend(
        [
            "ExecStartPre=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py memory-prepare",
            "ExecStart=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py exec-router /etc/vpn-stack/current/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run",
            "Restart=on-failure",
            "RestartSec=3s",
            "LimitNOFILE=1048576",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    return "\n".join(service_lines)


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


def render_sysctl(node_id: str) -> str:
    lines = [
        f"net.core.default_qdisc={FQ_KIND}",
        f"net.core.rmem_max={UDP_RMEM_MAX}",
        f"net.core.rmem_default={UDP_RMEM_DEFAULT}",
        f"net.core.wmem_default={UDP_WMEM_DEFAULT}",
        f"net.core.wmem_max={UDP_WMEM_MAX}",
        f"net.netfilter.nf_conntrack_max={CONNTRACK_MAX}",
        "net.ipv4.tcp_syncookies=1",
        "net.ipv4.tcp_congestion_control=bbr",
        "net.ipv4.tcp_mtu_probing=1",
        f"net.ipv4.tcp_mtu_probe_floor={TCP_MTU_PROBE_FLOOR}",
        f"net.ipv4.tcp_no_metrics_save={TCP_NO_METRICS_SAVE}",
        "vm.swappiness=10",
    ]
    if normalize_node_id(node_id) == NODE_GATEWAY:
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
    return (
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::AutocleanInterval "7";\n'
    )


def render_btmp_logrotate_config() -> str:
    return "\n".join(
        [
            "/var/log/btmp {",
            "    missingok",
            "    rotate 2",
            "    size 64M",
            "    compress",
            "    nodelaycompress",
            "    create 0660 root utmp",
            "}",
            "",
        ]
    )


def server_script_asset(name: str) -> str:
    return (ROOT_DIR / "vpn_installer" / name).read_text(encoding="utf-8")


def server_agent_artifacts(*, interserver: bool) -> dict[str, str]:
    modules = SERVER_AGENT_BASE_MODULES + (SERVER_AGENT_INTERSERVER_MODULES if interserver else ())
    return {
        "vpn-stack-agent.py": server_script_asset("server_agent.py"),
        **{name: server_script_asset(name) for name in modules},
    }


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
            "ExecStartPre=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py network-apply",
            "ExecStart=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py health",
            "ExecStartPost=-/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py storage-maintain",
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


def render_transport_service(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Maintain vpn-stack interserver underlay",
            f"After=network-online.target sing-box.service wg-quick@{env['WG_INTERFACE']}.service",
            f"Requires=sing-box.service wg-quick@{env['WG_INTERFACE']}.service",
            "PartOf=sing-box.service",
            "",
            "[Service]",
            "Type=simple",
            "ExecStartPre=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py transport-reconcile",
            "ExecStart=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py transport-watch",
            "Restart=on-failure",
            "RestartSec=1s",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectHome=true",
            "ProtectSystem=strict",
            "ReadWritePaths=/var/lib/vpn-stack /run",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def deployment_out_dir(env: dict[str, str]) -> Path:
    return OUT_DIR / env["DEPLOY_NAME"]


def client_route_excludes(env: dict[str, str]) -> list[str]:
    from .client_artifacts import client_route_excludes as implementation

    return implementation(env)


def render_client_profile(env: dict[str, str], auto_redirect: bool, *, android_safe: bool = False) -> str:
    from .client_artifacts import render_client_profile as implementation

    return implementation(env, auto_redirect, android_safe=android_safe)


def render_xray_client_profile(env: dict[str, str]) -> str:
    from .client_artifacts import render_xray_client_profile as implementation

    return implementation(env)


def render_windows_route_bypass_script(env: dict[str, str]) -> str:
    from .client_artifacts import render_windows_route_bypass_script as implementation

    return implementation(env)


def render_vless_uri(env: dict[str, str]) -> str:
    from .client_artifacts import render_vless_uri as implementation

    return implementation(env)


def client_artifact_paths(env: dict[str, str]) -> dict[str, Path]:
    from . import client_artifacts as _client_artifacts

    return _client_artifacts.client_artifact_paths(env, out_dir=OUT_DIR)


def render_next_steps(env: dict[str, str]) -> str:
    from . import client_artifacts as _client_artifacts

    return _client_artifacts.render_next_steps(env, out_dir=OUT_DIR)


def render_client_profiles(env: dict[str, str]) -> Path:
    from . import client_artifacts as _client_artifacts

    return _client_artifacts.render_client_profiles(env, out_dir=OUT_DIR)


def preview_dir_for_node(preview_root: Path, node_id: str) -> Path:
    return preview_root / normalize_node_id(node_id)


def reset_generated_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def rendered_files_for_node(env: dict[str, str], node_id: str, *, assets: dict[str, Path] | None = None) -> dict[str, str]:
    normalized_node_id = normalize_node_id(node_id)
    if env.get("NODE_ID", "").strip():
        configured_node_id = normalize_node_id(env["NODE_ID"])
        if configured_node_id != normalized_node_id:
            raise ValueError(
                f"projected node env belongs to {configured_node_id}, not {normalized_node_id}"
            )
        topology = TopologySpec.from_env(env)
        plan = topology.plan(configured_node_id)
        env = env.copy()
    else:
        deployment = DeploymentSpec.from_env(env)
        node = deployment.for_node(normalized_node_id)
        env = node.values
        plan = node.plan
    if plan.node_id == NODE_GATEWAY:
        files = {
            "sing-box.json": render_gateway_singbox(env),
            "sing-box.service": render_singbox_service(NODE_GATEWAY),
            "admin_apply.py": server_script_asset("admin_apply.py"),
            "xray.json": render_gateway_xray(env),
            "nftables.conf": render_ru_firewall_nftables(env, web_admin=CAP_WEB_ADMIN in plan.capabilities),
            "vpn-stack-nft-apply.sh": render_nft_apply_script(),
            "vpn-stack-nftables.service": render_nftables_service(),
            "sshd-vpn-stack.conf": render_sshd_hardening(env),
            "sysctl-vpn-stack.conf": render_sysctl(NODE_GATEWAY),
            "modules-vpn-stack.conf": render_modules_load(),
            "apt-vpn-stack-unattended.conf": render_apt_periodic_dropin(),
            "resolved-vpn-stack.conf": render_resolved_dropin(),
            "btmp-vpn-stack.conf": render_btmp_logrotate_config(),
            **server_agent_artifacts(interserver=plan.requires_wireguard),
            "vpn-stack-health.service": render_health_service(),
            "vpn-stack-health.timer": render_health_timer(),
            "vpn-stack-xray.service": render_xray_service(),
        }
        if CAP_WEB_ADMIN in plan.capabilities:
            files.update(
                {
                    "admin_web.py": server_script_asset("admin_web.py"),
                    "vpn-stack-admin.service": render_admin_web_service(),
                }
            )
        if plan.requires_wireguard:
            files[f"{env['WG_INTERFACE']}.conf"] = render_ru_wg(env)
            files["vpn-stack-transport.service"] = render_transport_service(env)
        if journal_limits_enabled(env):
            files["journald-vpn-stack.conf"] = render_journald_dropin(env)
        return finalize_node_files(env, plan, files, assets=assets)
    if plan.node_id != NODE_EXIT:
        raise ValueError(f"unsupported node: {plan.node_id}")
    wan_iface = env.get("WAN_INTERFACE", "").strip() or "eth0"
    files = {
        "sing-box.json": render_foreign_singbox(env),
        "sing-box.service": render_singbox_service(NODE_EXIT),
        f"{env['WG_INTERFACE']}.conf": render_foreign_wg(env),
        "nftables.conf": render_foreign_nftables(env, wan_iface),
        "vpn-stack-nft-apply.sh": render_nft_apply_script(),
        "vpn-stack-nftables.service": render_nftables_service(),
        "sshd-vpn-stack.conf": render_sshd_hardening(env),
        "sysctl-vpn-stack.conf": render_sysctl(NODE_EXIT),
        "modules-vpn-stack.conf": render_modules_load(),
        "apt-vpn-stack-unattended.conf": render_apt_periodic_dropin(),
        "resolved-vpn-stack.conf": render_resolved_dropin(),
        "btmp-vpn-stack.conf": render_btmp_logrotate_config(),
        **server_agent_artifacts(interserver=True),
        "vpn-stack-health.service": render_health_service(),
        "vpn-stack-health.timer": render_health_timer(),
    }
    if journal_limits_enabled(env):
        files["journald-vpn-stack.conf"] = render_journald_dropin(env)
    return finalize_node_files(
        env,
        plan,
        files,
        assets=assets,
        foreign_block_ru=env.get("FOREIGN_BLOCK_RU", "0").strip() == "1",
    )


def write_node_rendered_files(env: dict[str, str], node_id: str, output_dir: Path, *, assets: dict[str, Path] | None = None) -> Path:
    for name, content in rendered_files_for_node(env, node_id, assets=assets).items():
        write_private_text(output_dir / name, content)
    return output_dir


def copy_python_package(target_root: Path) -> Path:
    destination = target_root / "vpn_installer"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name in SERVER_RENDER_MODULES:
        shutil.copy2(ROOT_DIR / "vpn_installer" / name, destination / name)
    return destination


def render_preview_files(env: dict[str, str], preview_dir: Path, *, assets: dict[str, Path] | None = None) -> None:
    topology = TopologySpec.from_env(env)
    reset_generated_dir(preview_dir)
    for node in topology.nodes:
        write_node_rendered_files(env, node.node_id, preview_dir_for_node(preview_dir, node.node_id), assets=assets)


def render_config_artifacts(env_path: Path, env: dict[str, str], *, fetch_assets_first: bool = True) -> Path:
    require_env(env)
    topology = TopologySpec.from_env(env)
    out_dir = deployment_out_dir(env)
    assets_dir = out_dir / "assets"
    server_dir = out_dir / "server"
    preview_dir = out_dir / "preview"
    assets = fetch_assets(env, assets_dir) if fetch_assets_first else {path.name: path for path in assets_dir.glob("*") if path.is_file()}
    reset_generated_dir(server_dir)
    for node in topology.nodes:
        node_env_path = server_dir / f"{node.node_id}.env"
        write_private_text(node_env_path, render_node_env_text(env, topology.plan(node.node_id)))
    render_preview_files(env, preview_dir, assets=assets)
    return out_dir


def emit_cloud_init_assets(assets_dir: Path, asset_names: Iterable[str]) -> str:
    lines: list[str] = []
    for asset_name in sorted(asset_names):
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
        permissions = "0600" if relative == "deployment.env" else "0755" if path.name in executable_names else "0644"
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        lines.extend([f"  - path: {destination}", f"    permissions: '{permissions}'", "    encoding: b64", f"    content: {encoded}"])
    return "\n".join(lines)


def render_cloud_init_node(node_id: str, env_text: str, assets_dir: Path, asset_names: Iterable[str]) -> str:
    node_id = normalize_node_id(node_id)
    required_assets = tuple(sorted(set(asset_names)))
    cloud_root = OUT_DIR / ".cloud-init-stage" / node_id
    if cloud_root.exists():
        shutil.rmtree(cloud_root)
    try:
        cloud_root.mkdir(parents=True, exist_ok=True)
        write_text(cloud_root / "install.sh", INSTALL_SCRIPT_PATH.read_text(encoding="utf-8"))
        write_private_text(cloud_root / "deployment.env", env_text)
        copy_python_package(cloud_root)
        lines = [
            "#cloud-config",
            "package_update: true",
            "write_files:",
        ]
        lines.append(emit_cloud_init_tree(cloud_root, "/root/vpn-stack"))
        asset_block = emit_cloud_init_assets(assets_dir, required_assets)
        if asset_block:
            lines.append(asset_block)
        assets_argument = " --assets-dir /root/vpn-stack/assets" if required_assets else ""
        lines.extend(
            [
                "runcmd:",
                f'  - [bash, -lc, "cd /root/vpn-stack && ./install.sh --node {node_id} --env-file /root/vpn-stack/deployment.env{assets_argument}"]',
                "",
            ]
        )
        return "\n".join(lines)
    finally:
        if cloud_root.exists():
            shutil.rmtree(cloud_root, ignore_errors=True)


def render_cloud_init_artifacts(env: dict[str, str]) -> Path:
    require_env(env)
    topology = TopologySpec.from_env(env)
    out_dir = deployment_out_dir(env)
    assets_dir = out_dir / "assets"
    cloud_dir = out_dir / "cloud-init"
    reset_generated_dir(cloud_dir)
    for node in topology.nodes:
        plan = topology.plan(node.node_id)
        cloud_path = cloud_dir / f"{node.node_id}.yaml"
        write_private_text(
            cloud_path,
            render_cloud_init_node(
                node.node_id,
                render_node_env_text(env, plan),
                assets_dir,
                required_asset_names(plan, foreign_block_ru=env.get("FOREIGN_BLOCK_RU", "0") == "1"),
            ),
        )
    return cloud_dir


def copy_asset_if_present(source: Path, destination: Path) -> None:
    if source.is_file():
        ensure_file_parent(destination)
        shutil.copy2(source, destination)


def create_tarball(source_dir: Path, destination_tarball: Path) -> None:
    def normalized_metadata(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        relative = Path(info.name)
        if info.isdir():
            info.mode = 0o755
        elif relative.name == "deployment.env":
            info.mode = 0o600
        elif relative.name == "install.sh":
            info.mode = 0o700
        else:
            info.mode = 0o644
        return info

    ensure_file_parent(destination_tarball)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_tarball.name}.",
        dir=destination_tarball.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            for item in sorted(source_dir.rglob("*")):
                archive.add(
                    item,
                    arcname=str(item.relative_to(source_dir)),
                    recursive=False,
                    filter=normalized_metadata,
                )
        os.replace(temporary, destination_tarball)
        if os.name != "nt":
            destination_tarball.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def package_bundle(env: dict[str, str]) -> Path:
    require_env(env)
    topology = TopologySpec.from_env(env)
    out_dir = deployment_out_dir(env)
    assets_dir = out_dir / "assets"
    server_dir = out_dir / "server"
    bundle_dir = out_dir / "bundle"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    readme: list[str] = []
    for node in topology.nodes:
        plan = topology.plan(node.node_id)
        node_bundle = bundle_dir / node.node_id
        ensure_file_parent(node_bundle / "assets" / ".keep")
        shutil.copy2(INSTALL_SCRIPT_PATH, node_bundle / "install.sh")
        shutil.copy2(server_dir / f"{node.node_id}.env", node_bundle / "deployment.env")
        copy_python_package(node_bundle)
        for asset_name in required_asset_names(plan, foreign_block_ru=env.get("FOREIGN_BLOCK_RU", "0") == "1"):
            copy_asset_if_present(assets_dir / asset_name, node_bundle / "assets" / asset_name)
        create_tarball(node_bundle, bundle_dir / f"{node.node_id}.tar.gz")
        shutil.rmtree(node_bundle)
        readme.extend(
            [
                f"{node.node_id}:",
                f"  tar -xzf {node.node_id}.tar.gz",
                f"  sudo ./install.sh --node {node.node_id} --env-file ./deployment.env --assets-dir ./assets",
                "",
            ]
        )
    write_text(bundle_dir / "README.txt", "\n".join(readme))
    return bundle_dir


def package_control_bundle() -> Path:
    """Build the self-contained installer used by rollback/remove operations."""

    control_dir = OUT_DIR / "control"
    control_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vpn-stack-control-", dir=control_dir) as temporary:
        stage = Path(temporary)
        shutil.copy2(INSTALL_SCRIPT_PATH, stage / "install.sh")
        copy_python_package(stage)
        destination = control_dir / "installer-support.tar.gz"
        create_tarball(stage, destination)
    return destination


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
