from __future__ import annotations

import base64
import json
import shutil
import tarfile
import textwrap
import urllib.error
from pathlib import Path
from typing import Any

from .common import INSTALL_SCRIPT_PATH, OUT_DIR, ROOT_DIR, ensure_file_parent, parse_env_value, print_header, warn, write_text
from .config import download_asset, render_env_text, require_env, split_asset_sources
from .models import DEFAULT_ASSET_TIMEOUT, REQUIRED_ENV_VARS, ROLE_FOREIGN, ROLE_RU


def fetch_assets(env: dict[str, str], assets_dir: Path) -> dict[str, Path]:
    assets_dir.mkdir(parents=True, exist_ok=True)
    targets = {
        "geosite-ru.srs": (split_asset_sources(env["RU_GEOSITE_URL"]), assets_dir / "geosite-ru.srs"),
        "geoip-ru.srs": (split_asset_sources(env["RU_GEOIP_URL"]), assets_dir / "geoip-ru.srs"),
    }
    required_assets = {"geosite-ru.srs", "geoip-ru.srs"}
    if env.get("FOREIGN_BLOCK_RU", "1") == "1":
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


def load_env_file_from_text(env_text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw_line in env_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        env[key.strip()] = parse_env_value(raw_value)
    return env


def wg_host_address(cidr: str) -> str:
    return cidr.split("/", 1)[0]


def render_ru_singbox(env: dict[str, str]) -> str:
    direct_domains = env_list(env, "RU_FORCE_DIRECT_DOMAIN")
    direct_domain_suffixes = env_list(env, "RU_FORCE_DIRECT_DOMAIN_SUFFIX")
    direct_ip_cidrs = env_list(env, "RU_FORCE_DIRECT_IP_CIDR")

    dns_rules: list[dict[str, Any]] = [{"query_type": ["AAAA"], "action": "reject"}]
    if direct_domains:
        dns_rules.append({"domain": direct_domains, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})
    if direct_domain_suffixes:
        dns_rules.append({"domain_suffix": direct_domain_suffixes, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})
    dns_rules.append({"rule_set": ["ru-geosite"], "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})

    route_rules: list[dict[str, Any]] = [
        {"ip_version": 6, "action": "route", "outbound": "blocked"},
        {"inbound": ["vless-in"], "action": "resolve", "strategy": "ipv4_only"},
        {"inbound": ["vless-in"], "action": "sniff"},
    ]
    if direct_domains:
        route_rules.append({"domain": direct_domains, "action": "route", "outbound": "direct-ru"})
    if direct_domain_suffixes:
        route_rules.append({"domain_suffix": direct_domain_suffixes, "action": "route", "outbound": "direct-ru"})
    if direct_ip_cidrs:
        route_rules.append({"ip_cidr": direct_ip_cidrs, "action": "route", "outbound": "direct-ru"})
    route_rules.extend(
        [
            {"ip_is_private": True, "action": "route", "outbound": "direct-ru"},
            {"rule_set": ["ru-geosite"], "action": "route", "outbound": "direct-ru"},
            {"rule_set": ["ru-geoip"], "action": "route", "outbound": "direct-ru"},
        ]
    )

    payload = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "strategy": "ipv4_only",
            "servers": [
                {"type": "udp", "tag": "dns-ru-direct", "server": env["RU_DIRECT_DNS_SERVER"], "server_port": env_int(env, "RU_DIRECT_DNS_PORT")},
                {"type": "https", "tag": "dns-global", "server": env["GLOBAL_DOH_SERVER"], "server_port": 443, "path": env["GLOBAL_DOH_PATH"], "detour": "to-foreign", "tls": {"enabled": True, "server_name": env["GLOBAL_DOH_SERVER_NAME"]}},
            ],
            "rules": dns_rules,
            "final": "dns-global",
            "independent_cache": True,
        },
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-in",
                "listen": "::",
                "listen_port": env_int(env, "RU_LISTEN_PORT"),
                "users": [{"name": f"{env['DEPLOY_NAME']}-client", "uuid": env["CLIENT_UUID"], "flow": env["CLIENT_FLOW"]}],
                "tls": {
                    "enabled": True,
                    "server_name": env["RU_REALITY_SERVER_NAME"],
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": env["RU_REALITY_HANDSHAKE_SERVER"], "server_port": env_int(env, "RU_REALITY_HANDSHAKE_PORT")},
                        "private_key": env["RU_REALITY_PRIVATE_KEY"],
                        "short_id": [env["RU_REALITY_SHORT_ID"]],
                    },
                },
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-ru"},
            {"type": "direct", "tag": "to-foreign", "bind_interface": env["WG_INTERFACE"], "routing_mark": env_int(env, "APP_ROUTE_MARK")},
            {"type": "block", "tag": "blocked"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"},
            "rule_set": [
                {"tag": "ru-geosite", "type": "local", "format": "binary", "path": f"{env['RULESET_DIR']}/geosite-ru.srs"},
                {"tag": "ru-geoip", "type": "local", "format": "binary", "path": f"{env['RULESET_DIR']}/geoip-ru.srs"},
            ],
            "rules": route_rules,
            "final": "to-foreign",
        },
    }
    return render_json(payload)


def render_foreign_singbox() -> str:
    return render_json({"log": {"level": "warn", "timestamp": True}, "outbounds": [{"type": "direct", "tag": "direct"}]})


def render_ru_wg(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "[Interface]",
            f"Address = {env['WG_RU_ADDRESS']}",
            f"PrivateKey = {env['WG_RU_PRIVATE_KEY']}",
            f"MTU = {env['WG_MTU']}",
            f"FwMark = {env['WG_TUNNEL_FWMARK']}",
            "Table = off",
            f"PostUp = ip -4 route add default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']}",
            f"PostUp = ip -4 rule add fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000",
            f"PreDown = ip -4 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000",
            f"PreDown = ip -4 route del default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']}",
            "",
            "[Peer]",
            f"PublicKey = {env['WG_FOREIGN_PUBLIC_KEY']}",
            f"PresharedKey = {env['WG_PRESHARED_KEY']}",
            "AllowedIPs = 0.0.0.0/0",
            f"Endpoint = {env['FOREIGN_PUBLIC_IP']}:{env['WG_PORT']}",
            f"PersistentKeepalive = {env['WG_KEEPALIVE']}",
            "",
        ]
    )


def render_foreign_wg(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "[Interface]",
            f"Address = {env['WG_FOREIGN_ADDRESS']}",
            f"ListenPort = {env['WG_PORT']}",
            f"PrivateKey = {env['WG_FOREIGN_PRIVATE_KEY']}",
            f"MTU = {env['WG_MTU']}",
            "",
            "[Peer]",
            f"PublicKey = {env['WG_RU_PUBLIC_KEY']}",
            f"PresharedKey = {env['WG_PRESHARED_KEY']}",
            f"AllowedIPs = {wg_host_address(env['WG_RU_ADDRESS'])}/32",
            "",
        ]
    )


def render_foreign_nftables(env: dict[str, str], wan_iface: str) -> str:
    return "\n".join(
        [
            "flush ruleset",
            "",
            "table inet vpnstack {",
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
            "  chain input {",
            "    type filter hook input priority 0;",
            "    policy drop;",
            "",
            '    iifname "lo" accept',
            "    ip6 nexthdr icmpv6 accept",
            "    ip protocol icmp accept",
            "    ct state established,related accept",
            f"    tcp dport {env['SSH_PORT']} accept",
            f"    udp dport {env['WG_PORT']} accept",
            "  }",
            "",
            "  chain forward {",
            "    type filter hook forward priority 0;",
            "    policy drop;",
            "",
            "    ct state established,related accept",
            f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" ip daddr @ru_ipv4 drop',
            f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" ip6 daddr @ru_ipv6 drop',
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
        ]
    )


def render_ru_firewall_nftables(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "flush ruleset",
            "",
            "table inet vpnstack {",
            "  chain input {",
            "    type filter hook input priority 0;",
            "    policy drop;",
            "",
            '    iifname "lo" accept',
            "    ip6 nexthdr icmpv6 accept",
            "    ip protocol icmp accept",
            "    ct state established,related accept",
            f"    tcp dport {env['SSH_PORT']} accept",
            f"    tcp dport {env['RU_LISTEN_PORT']} accept",
            "  }",
            "}",
            "",
        ]
    )


def render_sync_script(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            'ROLE="${1:-}"',
            f'RULESET_DIR="${{2:-{env["RULESET_DIR"]}}}"',
            f'RU_GEOSITE_URL="${{3:-{env["RU_GEOSITE_URL"]}}}"',
            f'RU_GEOIP_URL="${{4:-{env["RU_GEOIP_URL"]}}}"',
            f'FOREIGN_BLOCK_RU="${{5:-{env["FOREIGN_BLOCK_RU"]}}}"',
            f'FOREIGN_RU_IPV4_LIST_URL="${{6:-{env["FOREIGN_RU_IPV4_LIST_URL"]}}}"',
            f'FOREIGN_RU_IPV6_LIST_URL="${{7:-{env["FOREIGN_RU_IPV6_LIST_URL"]}}}"',
            "",
            'mkdir -p "$RULESET_DIR"',
            "",
            "download_from_source() {",
            '  local source="$1"',
            '  local output="$2"',
            '  local asset_kind="$3"',
            '  local response_tmp="$output.response.tmp"',
            '  local render_tmp="$output.render.tmp"',
            '  rm -f "$response_tmp" "$render_tmp"',
            '  curl -fsSL "$source" -o "$response_tmp"',
            '  if [[ "$source" == *"stat.ripe.net/data/country-resource-list/"* ]]; then',
            '    python3 - "$asset_kind" "$response_tmp" "$render_tmp" <<\'PY\'',
            "import json",
            "import sys",
            "from pathlib import Path",
            "",
            "asset_kind = sys.argv[1]",
            "response_path = Path(sys.argv[2])",
            "output_path = Path(sys.argv[3])",
            "payload = json.loads(response_path.read_text(encoding='utf-8'))",
            "resources = payload.get('data', {}).get('resources', {})",
            "family = 'ipv6' if asset_kind == 'ipv6' else 'ipv4'",
            "prefixes = resources.get(family, [])",
            "if not isinstance(prefixes, list) or not prefixes:",
            "    raise SystemExit(1)",
            "output_path.write_text(''.join(f'{entry}\\n' for entry in prefixes if str(entry).strip()), encoding='utf-8')",
            "PY",
            '    mv "$render_tmp" "$output"',
            "  else",
            '    mv "$response_tmp" "$output"',
            "  fi",
            '  rm -f "$response_tmp" "$render_tmp"',
            "}",
            "",
            "download_any() {",
            '  local sources="$1"',
            '  local output="$2"',
            '  local asset_kind="$3"',
            "  local source",
            "  local errors=()",
            '  for source in $sources; do',
            '    if download_from_source "$source" "$output.tmp" "$asset_kind"; then',
            '      if [[ -s "$output.tmp" ]]; then',
            '        mv "$output.tmp" "$output"',
            "        return 0",
            "      fi",
            '      rm -f "$output.tmp"',
            '      errors+=("$source: empty payload")',
            "      continue",
            "    fi",
            '    rm -f "$output.tmp"',
            '    errors+=("$source")',
            "  done",
            '  if [[ -s "$output" ]]; then',
            '    echo "vpn-stack-sync: оставляю старую копию $(basename "$output"), все источники недоступны: ${errors[*]}" >&2',
            "    return 0",
            "  fi",
            '  echo "vpn-stack-sync: не удалось получить $(basename "$output") ни из одного источника: ${errors[*]}" >&2',
            "  return 1",
            "}",
            "",
            'if [[ "$ROLE" == "ru-gateway" ]]; then',
            '  download_any "$RU_GEOSITE_URL" "$RULESET_DIR/geosite-ru.srs" binary',
            '  download_any "$RU_GEOIP_URL" "$RULESET_DIR/geoip-ru.srs" binary',
            "  exit 0",
            "fi",
            "",
            'if [[ "$ROLE" == "foreign-exit" && "$FOREIGN_BLOCK_RU" == "1" ]]; then',
            '  local_v4="$RULESET_DIR/ru-ipv4.zone"',
            '  local_v6="$RULESET_DIR/ru-ipv6.zone"',
            '  download_any "$FOREIGN_RU_IPV4_LIST_URL" "$local_v4" ipv4',
            '  download_any "$FOREIGN_RU_IPV6_LIST_URL" "$local_v6" ipv6',
            "  {",
            '    echo "flush set inet vpnstack ru_ipv4"',
            '    if [[ -s "$local_v4" ]]; then',
            "      printf 'add element inet vpnstack ru_ipv4 { '",
            '      paste -sd, "$local_v4"',
            "      echo ' }'",
            "    fi",
            '    echo "flush set inet vpnstack ru_ipv6"',
            '    if [[ -s "$local_v6" ]]; then',
            "      printf 'add element inet vpnstack ru_ipv6 { '",
            '      paste -sd, "$local_v6"',
            "      echo ' }'",
            "    fi",
            '  } > "$RULESET_DIR/nft-ru-block.nft"',
            '  nft -f "$RULESET_DIR/nft-ru-block.nft"',
            "fi",
            "",
        ]
    )


def render_sync_service(role: str) -> str:
    return "\n".join(
        [
            "[Unit]",
            f"Description=Sync vpn-stack state for {role}",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart=/usr/local/lib/vpn-stack/sync-state.sh {role}",
            "",
        ]
    )


def render_sync_timer() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Run vpn-stack state sync daily",
            "",
            "[Timer]",
            "OnBootSec=2m",
            "OnUnitActiveSec=1d",
            "RandomizedDelaySec=20m",
            "Persistent=true",
            "",
            "[Install]",
            "WantedBy=timers.target",
            "",
        ]
    )


def render_client_profile(env: dict[str, str], auto_redirect: bool) -> str:
    payload: dict[str, Any] = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "strategy": "ipv4_only",
            "servers": [
                {"type": "fakeip", "tag": "dns-fakeip", "inet4_range": env["CLIENT_FAKEIP_V4"], "inet6_range": env["CLIENT_FAKEIP_V6"]},
                {"type": "https", "tag": "dns-remote", "server": env["GLOBAL_DOH_SERVER"], "server_port": 443, "path": env["GLOBAL_DOH_PATH"], "detour": "ru-gateway", "tls": {"enabled": True, "server_name": env["GLOBAL_DOH_SERVER_NAME"]}},
            ],
            "rules": [{"query_type": ["AAAA"], "action": "reject"}, {"query_type": ["A"], "action": "route", "server": "dns-fakeip"}],
            "final": "dns-remote",
            "reverse_mapping": True,
            "independent_cache": True,
        },
        "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": env["CLIENT_TUN_NAME"], "address": [env["CLIENT_TUN_ADDRESS_V4"], env["CLIENT_TUN_ADDRESS_V6"]], "auto_route": True, "strict_route": True, "auto_redirect": auto_redirect}],
        "outbounds": [
            {"type": "vless", "tag": "ru-gateway", "server": env["RU_PUBLIC_IP"], "server_port": env_int(env, "RU_LISTEN_PORT"), "uuid": env["CLIENT_UUID"], "flow": env["CLIENT_FLOW"], "packet_encoding": "xudp", "tls": {"enabled": True, "server_name": env["RU_REALITY_SERVER_NAME"], "utls": {"enabled": True, "fingerprint": env["UTLS_FINGERPRINT"]}, "reality": {"enabled": True, "public_key": env["RU_REALITY_PUBLIC_KEY"], "short_id": env["RU_REALITY_SHORT_ID"]}}},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-remote", "strategy": "ipv4_only"},
            "rules": [{"ip_version": 6, "action": "route", "outbound": "block"}, {"protocol": "dns", "action": "hijack-dns"}, {"ip_is_private": True, "action": "route", "outbound": "direct"}, {"domain_suffix": ["local"], "action": "route", "outbound": "direct"}],
            "final": "ru-gateway",
        },
    }
    excludes = [entry.strip() for entry in (env.get("CLIENT_ROUTE_EXCLUDE_V4", "") + "," + env.get("CLIENT_ROUTE_EXCLUDE_V6", "")).split(",") if entry.strip()]
    if excludes:
        payload["inbounds"][0]["route_exclude_address"] = excludes
    return render_json(payload)


def render_vless_uri(env: dict[str, str]) -> str:
    return f"vless://{env['CLIENT_UUID']}@{env['RU_PUBLIC_IP']}:{env['RU_LISTEN_PORT']}?security=reality&sni={env['RU_REALITY_SERVER_NAME']}&pbk={env['RU_REALITY_PUBLIC_KEY']}&sid={env['RU_REALITY_SHORT_ID']}&fp={env['UTLS_FINGERPRINT']}&type=tcp&flow={env['CLIENT_FLOW']}#{env['DEPLOY_NAME']}-ru-gateway\n"


def deployment_out_dir(env: dict[str, str]) -> Path:
    return OUT_DIR / env["DEPLOY_NAME"]


def preview_dir_for_role(preview_root: Path, role: str) -> Path:
    return preview_root / ("ru" if role == ROLE_RU else "foreign")


def rendered_files_for_role(env: dict[str, str], role: str) -> dict[str, str]:
    if role == ROLE_RU:
        return {
            "sing-box.json": render_ru_singbox(env),
            f"{env['WG_INTERFACE']}.conf": render_ru_wg(env),
            "nftables.conf": render_ru_firewall_nftables(env),
            "sync-state.sh": render_sync_script(env),
            "vpn-stack-sync.service": render_sync_service(ROLE_RU),
            "vpn-stack-sync.timer": render_sync_timer(),
        }
    wan_iface = env.get("WAN_INTERFACE", "").strip() or "eth0"
    return {
        "sing-box.json": render_foreign_singbox(),
        f"{env['WG_INTERFACE']}.conf": render_foreign_wg(env),
        "nftables.conf": render_foreign_nftables(env, wan_iface),
        "sync-state.sh": render_sync_script(env),
        "vpn-stack-sync.service": render_sync_service(ROLE_FOREIGN),
        "vpn-stack-sync.timer": render_sync_timer(),
    }


def write_role_rendered_files(env: dict[str, str], role: str, output_dir: Path) -> Path:
    for name, content in rendered_files_for_role(env, role).items():
        write_text(output_dir / name, content)
    return output_dir


def copy_python_package(target_root: Path) -> Path:
    destination = target_root / "vpn_installer"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(ROOT_DIR / "vpn_installer", destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return destination


def client_artifact_paths(env: dict[str, str]) -> dict[str, Path]:
    client_dir = deployment_out_dir(env) / "client"
    return {
        "client_dir": client_dir,
        "hiddify_json": client_dir / "hiddify-cross-platform.json",
        "linux_json": client_dir / "linux-sing-box.json",
        "uri": client_dir / "hiddify-uri.txt",
        "legacy_uri": client_dir / "vless-uri.txt",
        "next_steps": deployment_out_dir(env) / "NEXT-STEPS.txt",
    }


def render_next_steps(env: dict[str, str]) -> str:
    paths = client_artifact_paths(env)
    return "\n".join(
        [
            f"Deployment: {env['DEPLOY_NAME']}",
            "",
            "Что уже готово:",
            f"- Hiddify URI: {paths['uri']}",
            f"- JSON backup для Hiddify: {paths['hiddify_json']}",
            f"- JSON backup для Linux sing-box: {paths['linux_json']}",
            "",
            "Что делать дальше:",
            "1. Открой Hiddify на Windows, Linux или Android.",
            "2. Выбери добавление профиля из буфера обмена.",
            f"3. Если буфер обмена недоступен, открой файл {paths['uri'].name} и вставь его вручную.",
            f"4. Если URI не подходит, импортируй JSON-файл {paths['hiddify_json'].name}.",
            f"5. Для проверки серверов запусти: vpn status --deployment {env['DEPLOY_NAME']}",
        ]
    ) + "\n"


def render_preview_files(env: dict[str, str], preview_dir: Path) -> None:
    write_role_rendered_files(env, ROLE_RU, preview_dir_for_role(preview_dir, ROLE_RU))
    write_role_rendered_files(env, ROLE_FOREIGN, preview_dir_for_role(preview_dir, ROLE_FOREIGN))


def render_config_artifacts(env_path: Path, env: dict[str, str], *, fetch_assets_first: bool = True) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    out_dir = deployment_out_dir(env)
    assets_dir = out_dir / "assets"
    server_dir = out_dir / "server"
    preview_dir = out_dir / "preview"
    if fetch_assets_first:
        fetch_assets(env, assets_dir)
    write_text(server_dir / "ru.env", render_env_text(env))
    write_text(server_dir / "foreign.env", render_env_text(env))
    render_preview_files(env, preview_dir)
    return out_dir


def render_client_profiles(env: dict[str, str]) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    paths = client_artifact_paths(env)
    write_text(paths["hiddify_json"], render_client_profile(env, auto_redirect=False))
    write_text(paths["linux_json"], render_client_profile(env, auto_redirect=True))
    uri_payload = render_vless_uri(env)
    write_text(paths["uri"], uri_payload)
    write_text(paths["legacy_uri"], uri_payload)
    write_text(paths["next_steps"], render_next_steps(env))
    return paths["client_dir"]


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
    executable_names = {"install.sh", "sync-state.sh"}
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
        write_role_rendered_files(env=load_env_file_from_text(env_text), role=role, output_dir=cloud_root / "rendered")
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
    cloud_dir.mkdir(parents=True, exist_ok=True)
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
    for asset_name in ("ru-ipv4.zone", "ru-ipv6.zone"):
        copy_asset_if_present(assets_dir / asset_name, foreign_bundle / "assets" / asset_name)
    create_tarball(ru_bundle, bundle_dir / f"{ROLE_RU}.tar.gz")
    create_tarball(foreign_bundle, bundle_dir / f"{ROLE_FOREIGN}.tar.gz")
    return bundle_dir


def render_all_artifacts(env_path: Path, env: dict[str, str]) -> Path:
    out_dir = render_config_artifacts(env_path, env, fetch_assets_first=True)
    render_client_profiles(env)
    render_cloud_init_artifacts(env)
    package_bundle(env)
    return out_dir
