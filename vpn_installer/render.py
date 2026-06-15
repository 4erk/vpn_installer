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
from .models import DEFAULT_ASSET_TIMEOUT, REQUIRED_ENV_VARS, ROLE_FOREIGN, ROLE_RU


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
    direct_domains = env_list(env, "RU_FORCE_DIRECT_DOMAIN")
    direct_domain_suffixes = env_list(env, "RU_FORCE_DIRECT_DOMAIN_SUFFIX")
    direct_ip_cidrs = env_list(env, "RU_FORCE_DIRECT_IP_CIDR")
    reality_short_ids = [env["RU_REALITY_SHORT_ID"]]
    if env.get("RU_REALITY_ACCEPT_EMPTY_SHORT_ID", "1").strip().lower() not in {"0", "false", "no", "off"}:
        reality_short_ids.append("")
    reality_settings: dict[str, Any] = {
        "enabled": True,
        "handshake": {"server": env["RU_REALITY_HANDSHAKE_SERVER"], "server_port": env_int(env, "RU_REALITY_HANDSHAKE_PORT")},
        "private_key": env["RU_REALITY_PRIVATE_KEY"],
        "short_id": list(dict.fromkeys(reality_short_ids)),
    }
    reality_max_time_difference = env.get("RU_REALITY_MAX_TIME_DIFFERENCE", "").strip()
    if reality_max_time_difference:
        reality_settings["max_time_difference"] = reality_max_time_difference

    dns_rules: list[dict[str, Any]] = [{"query_type": ["AAAA"], "action": "reject"}]
    if direct_domains:
        dns_rules.append({"domain": direct_domains, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})
    if direct_domain_suffixes:
        dns_rules.append({"domain_suffix": direct_domain_suffixes, "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})
    dns_rules.append({"rule_set": ["ru-geosite"], "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"})

    route_rules: list[dict[str, Any]] = [
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
            {"ip_version": 6, "action": "route", "outbound": "to-foreign"},
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
                "multiplex": {"enabled": True},
                "tls": {
                    "enabled": True,
                    "server_name": env["RU_REALITY_SERVER_NAME"],
                    "reality": reality_settings,
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
            f"PersistentKeepalive = {env['WG_KEEPALIVE']}",
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


def render_rate_limited_tcp_accept(service_tag: str, port: str, rate: str, burst: str) -> list[str]:
    return [
        f'    tcp dport {port} ct state new meter {service_tag} {{ ip saddr limit rate {rate} burst {burst} packets }} counter accept',
        f"    tcp dport {port} counter drop",
    ]


def render_foreign_nftables(env: dict[str, str], wan_iface: str) -> str:
    lines = [
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
        "  set abuse_ipv4 {",
        "    type ipv4_addr",
        "    flags timeout",
        "  }",
        "",
        "  chain input {",
        "    type filter hook input priority 0;",
        "    policy drop;",
        "",
        '    iifname "lo" accept',
        "    ct state invalid drop",
        '    ip saddr @abuse_ipv4 counter drop comment "vpnstack-abuse-block"',
        "    ip6 nexthdr icmpv6 accept",
        "    ip protocol icmp accept",
        "    ct state established,related accept",
    ]
    lines.extend(render_rate_limited_tcp_accept("ssh_guard", env["SSH_PORT"], env["SSH_INPUT_RATE"], env["SSH_INPUT_BURST"]))
    lines.extend(
        [
            f"    udp dport {env['WG_PORT']} accept",
            "  }",
            "",
            "  chain forward {",
            "    type filter hook forward priority 0;",
            "    policy drop;",
            "",
            "    ct state invalid drop",
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
            "table ip6 nat {",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat;",
            f'    ip6 saddr {env["WG_IPV6_PREFIX"]} oifname "{wan_iface}" masquerade',
            "  }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def render_ru_firewall_nftables(env: dict[str, str]) -> str:
    lines = [
        "flush ruleset",
        "",
        "table inet vpnstack {",
        "  set abuse_ipv4 {",
        "    type ipv4_addr",
        "    flags timeout",
        "  }",
        "",
        "  chain input {",
        "    type filter hook input priority 0;",
        "    policy drop;",
        "",
        '    iifname "lo" accept',
        "    ct state invalid drop",
        '    ip saddr @abuse_ipv4 counter drop comment "vpnstack-abuse-block"',
        "    ip6 nexthdr icmpv6 accept",
        "    ip protocol icmp accept",
        "    ct state established,related accept",
    ]
    lines.extend(render_rate_limited_tcp_accept("ssh_guard", env["SSH_PORT"], env["SSH_INPUT_RATE"], env["SSH_INPUT_BURST"]))
    lines.append(f"    tcp dport {env['RU_LISTEN_PORT']} counter accept")
    lines.extend(["  }", "}", ""])
    return "\n".join(lines)


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


def render_health_script(env: dict[str, str], role: str) -> str:
    role_specific_wg_probe = (
        "\n".join(
            [
                'route_to_foreign_wg_ipv4_ok() {',
                '  ip -4 route get "${WG_FOREIGN_ADDRESS_HOST}" 2>/dev/null | grep -Eq "(^| )dev ${WG_INTERFACE}( |$)"',
                '}',
                "",
                'route_to_foreign_wg_ipv6_ok() {',
                f'  ip -6 route get 2606:4700:4700::1111 mark {env["APP_ROUTE_MARK"]} 2>/dev/null | grep -Eq "(^| )dev ${{WG_INTERFACE}}( |$)"',
                '}',
                "",
                'route_to_foreign_wg_ok() {',
                '  route_to_foreign_wg_ipv4_ok && route_to_foreign_wg_ipv6_ok',
                '}',
                "",
                'probe_wireguard_path() {',
                '  route_to_foreign_wg_ok && probe_http_ipv4 "${WG_INTERFACE}"',
                '}',
                "",
                "append_wireguard_path_reason() {",
                '  if ! route_to_foreign_wg_ok; then',
                '    reasons+=("ru_wg_peer_route_missing")',
                "    return 0",
                "  fi",
                '  reasons+=("ru_wg_egress")',
                "}",
            ]
        )
        if role == ROLE_RU
        else "\n".join(
            [
                'probe_wireguard_path() {',
                '  ping -4 -I "${WG_INTERFACE}" -c 1 -W 2 "${WG_RU_ADDRESS_HOST}" >/dev/null 2>&1',
                '}',
                "",
                "append_wireguard_path_reason() {",
                '  reasons+=("foreign_wg_peer_unreachable")',
                "}",
            ]
        )
    )
    role_specific_direct_probe = (
        ""
        if role == ROLE_RU
        else "\n".join(
            [
                'if ! probe_http_ipv4 ""; then',
                '  reasons+=("foreign_direct_egress")',
                "fi",
            ]
        )
    )
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail

        ROLE="{role}"
        WG_INTERFACE="{env['WG_INTERFACE']}"
        WG_RU_ADDRESS_HOST="{wg_host_address(env['WG_RU_ADDRESS'])}"
        WG_FOREIGN_ADDRESS_HOST="{wg_host_address(env['WG_FOREIGN_ADDRESS'])}"
        WG_FOREIGN_ADDRESS_V6_HOST="{wg_host_address(env['WG_FOREIGN_ADDRESS_V6'])}"
        WAN_INTERFACE="{env.get('WAN_INTERFACE', '')}"
        RU_PUBLIC_IP="{env['RU_PUBLIC_IP']}"
        FOREIGN_PUBLIC_IP="{env['FOREIGN_PUBLIC_IP']}"
        SSH_PORT="{env['SSH_PORT']}"
        HEALTHCHECK_URL="{env['HEALTHCHECK_URL']}"
        HEALTH_THROUGHPUT_URLS="{env['HEALTH_THROUGHPUT_URLS']}"
        HEALTH_UPLOAD_URL="{env['HEALTH_UPLOAD_URL']}"
        HEALTH_UPLOAD_BYTES="{env['HEALTH_UPLOAD_BYTES']}"
        RUNTIME_QDISC="{env.get('RUNTIME_QDISC', 'fq')}"
        DEEP_PROBE_INTERVAL_MINUTES="{env['HEALTH_DEEP_PROBE_INTERVAL_MINUTES']}"
        MIN_FOREIGN_DIRECT_DOWNLOAD_BPS="{env['HEALTH_MIN_FOREIGN_DIRECT_DOWNLOAD_BPS']}"
        MIN_RU_WG_DOWNLOAD_BPS="{env['HEALTH_MIN_RU_WG_DOWNLOAD_BPS']}"
        MIN_FOREIGN_DIRECT_UPLOAD_BPS="{env['HEALTH_MIN_FOREIGN_DIRECT_UPLOAD_BPS']}"
        MIN_RU_WG_UPLOAD_BPS="{env['HEALTH_MIN_RU_WG_UPLOAD_BPS']}"
        MAX_FOREIGN_RU_PING_LOSS_PCT="{env['HEALTH_MAX_FOREIGN_RU_PING_LOSS_PCT']}"
        MAX_FOREIGN_INTERNET_PING_LOSS_PCT="{env['HEALTH_MAX_FOREIGN_INTERNET_PING_LOSS_PCT']}"
        HANDSHAKE_GRACE="{env['HEALTH_HANDSHAKE_GRACE_SECONDS']}"
        DISABLE_NIC_OFFLOADS="{env.get('DISABLE_NIC_OFFLOADS', '1')}"
        SELF_HEAL_ENABLED="{env.get('HEALTH_SELF_HEAL', '1')}"
        SELF_HEAL_COOLDOWN_MINUTES="{env.get('HEALTH_SELF_HEAL_COOLDOWN_MINUTES', '15')}"
        SELF_HEAL_MAX_ACTIONS_PER_HOUR="{env.get('HEALTH_SELF_HEAL_MAX_ACTIONS_PER_HOUR', '2')}"
        SELF_HEAL_CONFIRMATIONS="{env.get('HEALTH_SELF_HEAL_CONFIRMATIONS', '2')}"
        HEALTH_STATE_PATH="/var/lib/vpn-stack/health-state.env"

        log() {{
          echo "vpn-stack-health[$ROLE]: $*" >&2
        }}

        number_or_default() {{
          local value="$1"
          local fallback="$2"
          if [[ "${{value}}" =~ ^[0-9]+$ ]]; then
            printf '%s' "${{value}}"
          else
            printf '%s' "${{fallback}}"
          fi
        }}

        DEEP_PROBE_INTERVAL_MINUTES="$(number_or_default "${{DEEP_PROBE_INTERVAL_MINUTES}}" 30)"
        MIN_FOREIGN_DIRECT_DOWNLOAD_BPS="$(number_or_default "${{MIN_FOREIGN_DIRECT_DOWNLOAD_BPS}}" 300000)"
        MIN_RU_WG_DOWNLOAD_BPS="$(number_or_default "${{MIN_RU_WG_DOWNLOAD_BPS}}" 300000)"
        MIN_FOREIGN_DIRECT_UPLOAD_BPS="$(number_or_default "${{MIN_FOREIGN_DIRECT_UPLOAD_BPS}}" 1000000)"
        MIN_RU_WG_UPLOAD_BPS="$(number_or_default "${{MIN_RU_WG_UPLOAD_BPS}}" 1000000)"
        MAX_FOREIGN_RU_PING_LOSS_PCT="$(number_or_default "${{MAX_FOREIGN_RU_PING_LOSS_PCT}}" 5)"
        MAX_FOREIGN_INTERNET_PING_LOSS_PCT="$(number_or_default "${{MAX_FOREIGN_INTERNET_PING_LOSS_PCT}}" 5)"
        HEALTH_UPLOAD_BYTES="$(number_or_default "${{HEALTH_UPLOAD_BYTES}}" 1048576)"
        SELF_HEAL_COOLDOWN_MINUTES="$(number_or_default "${{SELF_HEAL_COOLDOWN_MINUTES}}" 15)"
        SELF_HEAL_MAX_ACTIONS_PER_HOUR="$(number_or_default "${{SELF_HEAL_MAX_ACTIONS_PER_HOUR}}" 2)"
        SELF_HEAL_CONFIRMATIONS="$(number_or_default "${{SELF_HEAL_CONFIRMATIONS}}" 2)"

        detect_default_iface() {{
          ip route show default 2>/dev/null | awk '/default/ {{print $5; exit}}'
        }}

        apply_qdisc() {{
          local iface="$1"
          [[ -n "${{iface}}" ]] || return 0
          command -v tc >/dev/null 2>&1 || return 0
          case "${{RUNTIME_QDISC:-fq}}" in
            fq)
              tc qdisc replace dev "${{iface}}" root fq >/dev/null 2>&1 ||
                tc qdisc replace dev "${{iface}}" root fq_codel >/dev/null 2>&1 ||
                true
              ;;
            fq_codel)
              tc qdisc replace dev "${{iface}}" root fq_codel >/dev/null 2>&1 || true
              ;;
            none|off|disabled)
              return 0
              ;;
            *)
              tc qdisc replace dev "${{iface}}" root fq >/dev/null 2>&1 ||
                tc qdisc replace dev "${{iface}}" root fq_codel >/dev/null 2>&1 ||
                true
              ;;
          esac
        }}

        disable_offloads() {{
          local iface="$1"
          [[ -n "${{iface}}" ]] || return 0
          [[ "${{DISABLE_NIC_OFFLOADS}}" == "1" ]] || return 0
          command -v ethtool >/dev/null 2>&1 || return 0
          ethtool -K "${{iface}}" gro off >/dev/null 2>&1 || true
          ethtool -K "${{iface}}" gso off >/dev/null 2>&1 || true
          ethtool -K "${{iface}}" tso off >/dev/null 2>&1 || true
        }}

        harden_interface() {{
          local iface="$1"
          [[ -n "${{iface}}" ]] || return 0
          apply_qdisc "${{iface}}"
          disable_offloads "${{iface}}"
        }}

        harden_runtime() {{
          local default_iface=""
          default_iface="$(detect_default_iface)"
          harden_interface "${{default_iface}}"
          if [[ -n "${{WAN_INTERFACE}}" && "${{WAN_INTERFACE}}" != "${{default_iface}}" ]]; then
            harden_interface "${{WAN_INTERFACE}}"
          fi
          apply_qdisc "${{WG_INTERFACE}}"
        }}

        probe_http_ipv4() {{
          local bind_iface="$1"
          local curl_args=(-4fsS --max-time 8 -o /dev/null)
          local url=""
          if [[ -n "${{bind_iface}}" ]]; then
            curl_args+=(--interface "${{bind_iface}}")
          fi
          for url in "${{HEALTHCHECK_URL}}" "https://cloudflare.com/cdn-cgi/trace" "https://connectivitycheck.gstatic.com/generate_204"; do
            if curl "${{curl_args[@]}}" "${{url}}" >/dev/null 2>&1; then
              return 0
            fi
          done
          return 1
        }}

        {textwrap.indent(role_specific_wg_probe, '        ')}

        state_value() {{
          local key="$1"
          if [[ -r "${{HEALTH_STATE_PATH}}" ]]; then
            awk -F= -v key="${{key}}" '$1 == key {{ sub(/^[^=]*=/, ""); gsub(/^"/, ""); gsub(/"$/, ""); print; exit }}' "${{HEALTH_STATE_PATH}}"
          fi
        }}

        state_escape() {{
          sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g' <<<"$1"
        }}

        set_state_value() {{
          local key="$1"
          local value="$2"
          local tmp=""
          mkdir -p "$(dirname "${{HEALTH_STATE_PATH}}")"
          tmp="${{HEALTH_STATE_PATH}}.tmp.$$"
          if [[ -r "${{HEALTH_STATE_PATH}}" ]]; then
            awk -F= -v key="${{key}}" '$1 != key {{ print }}' "${{HEALTH_STATE_PATH}}" > "${{tmp}}"
          else
            : > "${{tmp}}"
          fi
          printf '%s="%s"\\n' "${{key}}" "$(state_escape "${{value}}")" >> "${{tmp}}"
          mv "${{tmp}}" "${{HEALTH_STATE_PATH}}"
        }}

        reset_self_heal_observation() {{
          if [[ -n "$(state_value SELF_HEAL_LAST_REASON)" || -n "$(state_value SELF_HEAL_CONSECUTIVE)" ]]; then
            set_state_value SELF_HEAL_LAST_REASON ""
            set_state_value SELF_HEAL_CONSECUTIVE "0"
          fi
        }}

        probe_download_bps() {{
          local bind_iface="$1"
          local url="$2"
          if ! command -v curl >/dev/null 2>&1 || [[ -z "${{url}}" ]]; then
            printf -- '-1'
            return 0
          fi
          local speed
          if [[ -n "${{bind_iface}}" ]]; then
            speed="$(curl -4fsS --interface "${{bind_iface}}" --max-time 15 -o /dev/null -w '%{{speed_download}}' "${{url}}" 2>/dev/null || true)"
          else
            speed="$(curl -4fsS --max-time 15 -o /dev/null -w '%{{speed_download}}' "${{url}}" 2>/dev/null || true)"
          fi
          if [[ "${{speed}}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            awk -v speed="${{speed}}" 'BEGIN {{ printf "%.0f", speed }}'
          else
            printf -- '-1'
          fi
        }}

        probe_upload_bps() {{
          local bind_iface="$1"
          local url="$2"
          local bytes="$3"
          if ! command -v curl >/dev/null 2>&1 || [[ -z "${{url}}" ]] || [[ ! "${{bytes}}" =~ ^[0-9]+$ ]]; then
            printf -- '-1'
            return 0
          fi
          local speed
          if [[ -n "${{bind_iface}}" ]]; then
            speed="$(head -c "${{bytes}}" /dev/zero | curl -4fsS --interface "${{bind_iface}}" --max-time 20 -o /dev/null -w '%{{speed_upload}}' --data-binary @- "${{url}}" 2>/dev/null || true)"
          else
            speed="$(head -c "${{bytes}}" /dev/zero | curl -4fsS --max-time 20 -o /dev/null -w '%{{speed_upload}}' --data-binary @- "${{url}}" 2>/dev/null || true)"
          fi
          if [[ "${{speed}}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            awk -v speed="${{speed}}" 'BEGIN {{ printf "%.0f", speed }}'
          else
            printf -- '-1'
          fi
        }}

        probe_ping_loss_pct() {{
          local host="$1"
          if ! command -v ping >/dev/null 2>&1 || [[ -z "${{host}}" ]]; then
            printf -- '-1'
            return 0
          fi
          local output loss
          output="$(ping -4 -c 10 -W 1 "${{host}}" 2>/dev/null || true)"
          loss="$(awk -F', ' '/packets transmitted/ {{ gsub(/% packet loss/, "", $3); print $3; exit }}' <<<"${{output}}")"
          if [[ "${{loss}}" =~ ^[0-9]+$ ]]; then
            printf '%s' "${{loss}}"
          else
            printf -- '-1'
          fi
        }}

        probe_ping_loss_pct_fast() {{
          local host="$1"
          if ! command -v ping >/dev/null 2>&1 || [[ -z "${{host}}" ]]; then
            printf -- '-1'
            return 0
          fi
          local output loss
          output="$(ping -4 -c 4 -W 1 "${{host}}" 2>/dev/null || true)"
          loss="$(awk -F', ' '/packets transmitted/ {{ gsub(/% packet loss/, "", $3); print $3; exit }}' <<<"${{output}}")"
          if [[ "${{loss}}" =~ ^[0-9]+$ ]]; then
            printf '%s' "${{loss}}"
          else
            printf -- '-1'
          fi
        }}

        probe_multi_download_summary() {{
          local bind_iface="$1"
          local min_speed="-1"
          local detail=""
          local url="" label="" speed=""
          for url in ${{HEALTH_THROUGHPUT_URLS}}; do
            speed="$(probe_download_bps "${{bind_iface}}" "${{url}}")"
            label="${{url#*://}}"
            label="${{label%%/*}}"
            if [[ -n "${{detail}}" ]]; then
              detail="${{detail}},"
            fi
            detail="${{detail}}${{label}}:${{speed}}"
            if [[ "${{speed}}" =~ ^[0-9]+$ && "${{speed}}" -ge 0 ]]; then
              if [[ "${{min_speed}}" == "-1" || "${{speed}}" -lt "${{min_speed}}" ]]; then
                min_speed="${{speed}}"
              fi
            fi
          done
          printf '%s|%s' "${{min_speed}}" "${{detail}}"
        }}

        should_run_deep_probe() {{
          local last_epoch="" now="" interval_s=""
          local last_verdict=""
          last_verdict="$(state_value DEEP_PROBE_VERDICT)"
          if [[ -n "${{last_verdict}}" && "${{last_verdict}}" != "ok" ]]; then
            return 0
          fi
          last_epoch="$(state_value DEEP_PROBE_AT_EPOCH)"
          if [[ ! "${{last_epoch}}" =~ ^[0-9]+$ ]]; then
            return 0
          fi
          now="$(date +%s)"
          interval_s="$((DEEP_PROBE_INTERVAL_MINUTES * 60))"
          if [[ ! "${{now}}" =~ ^[0-9]+$ ]]; then
            return 0
          fi
          [[ $((now - last_epoch)) -ge $interval_s ]]
        }}

        ssh_banner_ok() {{
          timeout 5 bash -lc 'exec 3<>/dev/tcp/127.0.0.1/'"${{SSH_PORT}}"'; head -c 4 <&3' 2>/dev/null | grep -q '^SSH-'
        }}

        wg_handshake_age() {{
          local value=""
          local now=""
          value="$(wg show "${{WG_INTERFACE}}" latest-handshakes 2>/dev/null | awk 'NR==1 {{print $2}}')"
          if [[ -z "${{value}}" || "${{value}}" == "0" ]]; then
            printf '999999'
            return 0
          fi
          now="$(date +%s)"
          if [[ "${{value}}" =~ ^[0-9]+$ && "${{now}}" =~ ^[0-9]+$ && "${{now}}" -ge "${{value}}" ]]; then
            printf '%s' "$((now - value))"
            return 0
          fi
          printf '999999'
        }}

        run_deep_probe() {{
          local probe_at="" probe_epoch="" verdict="ok" reasons_joined=""
          local direct_summary="" direct_min="-1" direct_detail="" direct_upload="-1"
          local wg_summary="" wg_min="-1" wg_detail="" wg_upload="-1"
          local gateway_ping_loss="-1" peer_ping_loss="-1" internet_ping_loss="-1"
          local self_heal_last_reason="" self_heal_consecutive="0" self_heal_last_action_epoch="0"
          local self_heal_action_window_epoch="0" self_heal_action_window_count="0"
          local self_heal_last_action="" self_heal_last_action_result=""
          local fast_foreign_ru_ping_loss="-1" fast_ru_foreign_ping_loss="-1"
          local -a reasons=()

          probe_at="$(date -Is)"
          probe_epoch="$(date +%s)"
          self_heal_last_reason="$(state_value SELF_HEAL_LAST_REASON)"
          self_heal_consecutive="$(state_value SELF_HEAL_CONSECUTIVE)"
          self_heal_last_action_epoch="$(state_value SELF_HEAL_LAST_ACTION_EPOCH)"
          self_heal_action_window_epoch="$(state_value SELF_HEAL_ACTION_WINDOW_EPOCH)"
          self_heal_action_window_count="$(state_value SELF_HEAL_ACTION_WINDOW_COUNT)"
          self_heal_last_action="$(state_value SELF_HEAL_LAST_ACTION)"
          self_heal_last_action_result="$(state_value SELF_HEAL_LAST_ACTION_RESULT)"
          fast_foreign_ru_ping_loss="$(state_value FAST_FOREIGN_RU_PING_LOSS_PCT)"
          fast_ru_foreign_ping_loss="$(state_value FAST_RU_FOREIGN_PING_LOSS_PCT)"

          if [[ "${{ROLE}}" == "foreign-exit" ]]; then
            direct_summary="$(probe_multi_download_summary "")"
            direct_min="${{direct_summary%%|*}}"
            direct_detail="${{direct_summary#*|}}"
            direct_upload="$(probe_upload_bps "" "${{HEALTH_UPLOAD_URL}}" "${{HEALTH_UPLOAD_BYTES}}")"
            gateway_ping_loss="$(probe_ping_loss_pct "$(ip route show default 2>/dev/null | awk '/default/ {{print $3; exit}}')")"
            peer_ping_loss="$(probe_ping_loss_pct "${{RU_PUBLIC_IP}}")"
            internet_ping_loss="$(probe_ping_loss_pct "1.1.1.1")"
            if [[ "${{direct_min}}" =~ ^[0-9]+$ && "${{direct_min}}" -ge 0 && "${{direct_min}}" -lt "${{MIN_FOREIGN_DIRECT_DOWNLOAD_BPS}}" ]]; then
              reasons+=("foreign_direct_download=${{direct_min}}")
            fi
            if [[ "${{direct_upload}}" =~ ^[0-9]+$ && "${{direct_upload}}" -ge 0 && "${{direct_upload}}" -lt "${{MIN_FOREIGN_DIRECT_UPLOAD_BPS}}" ]]; then
              reasons+=("foreign_direct_upload=${{direct_upload}}")
            fi
            if [[ "${{gateway_ping_loss}}" =~ ^[0-9]+$ && "${{gateway_ping_loss}}" -gt "${{MAX_FOREIGN_INTERNET_PING_LOSS_PCT}}" ]]; then
              reasons+=("foreign_gateway_ping_loss=${{gateway_ping_loss}}")
            fi
            if [[ "${{peer_ping_loss}}" =~ ^[0-9]+$ && "${{peer_ping_loss}}" -gt "${{MAX_FOREIGN_RU_PING_LOSS_PCT}}" ]]; then
              reasons+=("foreign_ru_ping_loss=${{peer_ping_loss}}")
            fi
            if [[ "${{internet_ping_loss}}" =~ ^[0-9]+$ && "${{internet_ping_loss}}" -gt "${{MAX_FOREIGN_INTERNET_PING_LOSS_PCT}}" ]]; then
              reasons+=("foreign_internet_ping_loss=${{internet_ping_loss}}")
            fi
          else
            wg_summary="$(probe_multi_download_summary "${{WG_INTERFACE}}")"
            wg_min="${{wg_summary%%|*}}"
            wg_detail="${{wg_summary#*|}}"
            wg_upload="$(probe_upload_bps "${{WG_INTERFACE}}" "${{HEALTH_UPLOAD_URL}}" "${{HEALTH_UPLOAD_BYTES}}")"
            if [[ "${{wg_min}}" =~ ^[0-9]+$ && "${{wg_min}}" -ge 0 && "${{wg_min}}" -lt "${{MIN_RU_WG_DOWNLOAD_BPS}}" ]]; then
              reasons+=("ru_wg_download=${{wg_min}}")
            fi
            if [[ "${{wg_upload}}" =~ ^[0-9]+$ && "${{wg_upload}}" -ge 0 && "${{wg_upload}}" -lt "${{MIN_RU_WG_UPLOAD_BPS}}" ]]; then
              reasons+=("ru_wg_upload=${{wg_upload}}")
            fi
          fi

          if [[ "${{#reasons[@]}}" -gt 0 ]]; then
            verdict="degraded"
            reasons_joined="$(IFS=,; echo "${{reasons[*]}}")"
          fi

          cat > "${{HEALTH_STATE_PATH}}.tmp" <<EOF
DEEP_PROBE_AT="${{probe_at}}"
DEEP_PROBE_AT_EPOCH="${{probe_epoch}}"
DEEP_PROBE_VERDICT="${{verdict}}"
DEEP_PROBE_REASONS="${{reasons_joined}}"
DEEP_FOREIGN_DIRECT_DOWNLOAD_MIN_BPS="${{direct_min}}"
DEEP_FOREIGN_DIRECT_DOWNLOAD_DETAIL="${{direct_detail}}"
DEEP_FOREIGN_DIRECT_UPLOAD_BPS="${{direct_upload}}"
DEEP_FOREIGN_GATEWAY_PING_LOSS_PCT="${{gateway_ping_loss}}"
DEEP_FOREIGN_RU_PING_LOSS_PCT="${{peer_ping_loss}}"
DEEP_FOREIGN_INTERNET_PING_LOSS_PCT="${{internet_ping_loss}}"
DEEP_RU_WG_DOWNLOAD_MIN_BPS="${{wg_min}}"
DEEP_RU_WG_DOWNLOAD_DETAIL="${{wg_detail}}"
DEEP_RU_WG_UPLOAD_BPS="${{wg_upload}}"
FAST_FOREIGN_RU_PING_LOSS_PCT="${{fast_foreign_ru_ping_loss:-1}}"
FAST_RU_FOREIGN_PING_LOSS_PCT="${{fast_ru_foreign_ping_loss:-1}}"
SELF_HEAL_LAST_REASON="${{self_heal_last_reason}}"
SELF_HEAL_CONSECUTIVE="${{self_heal_consecutive:-0}}"
SELF_HEAL_LAST_ACTION_EPOCH="${{self_heal_last_action_epoch:-0}}"
SELF_HEAL_ACTION_WINDOW_EPOCH="${{self_heal_action_window_epoch:-0}}"
SELF_HEAL_ACTION_WINDOW_COUNT="${{self_heal_action_window_count:-0}}"
SELF_HEAL_LAST_ACTION="${{self_heal_last_action}}"
SELF_HEAL_LAST_ACTION_RESULT="${{self_heal_last_action_result}}"
EOF
          mv "${{HEALTH_STATE_PATH}}.tmp" "${{HEALTH_STATE_PATH}}"

          if [[ "${{#reasons[@]}}" -gt 0 ]]; then
            printf '%s\\n' "${{reasons[@]}}"
          fi
        }}

        self_heal_reason_key() {{
          local reason=""
          local key=""
          for reason in "$@"; do
            case "${{reason}}" in
              ru_wg_peer_route_missing)
                if [[ "${{key}}" != *ru_wireguard_route* ]]; then
                  key="${{key}},ru_wireguard_route"
                fi
                ;;
              wg_handshake_stale=*|ru_wg_egress|foreign_wg_peer_unreachable|foreign_ru_ping_loss=*|foreign_ru_ping_loss_fast=*|ru_foreign_ping_loss_fast=*|ru_wg_download=*|ru_wg_upload=*)
                if [[ "${{key}}" != *wireguard_path* ]]; then
                  key="${{key}},wireguard_path"
                fi
                ;;
              foreign_direct_egress|foreign_direct_download=*|foreign_direct_upload=*)
                if [[ "${{key}}" != *foreign_nftables* ]]; then
                  key="${{key}},foreign_nftables"
                fi
                ;;
            esac
          done
          key="${{key#,}}"
          printf '%s' "${{key}}"
        }}

        self_heal_action_for_key() {{
          local key="$1"
          if [[ "${{ROLE}}" == "ru-gateway" && "${{key}}" == *ru_wireguard_route* ]]; then
            printf 'repair-ru-wireguard-route'
          elif [[ "${{key}}" == *wireguard_path* ]]; then
            printf 'restart-wireguard'
          elif [[ "${{ROLE}}" == "foreign-exit" && "${{key}}" == *foreign_nftables* ]]; then
            printf 'restart-foreign-nftables'
          else
            printf 'none'
          fi
        }}

        perform_self_heal_action() {{
          local action="$1"
          case "${{action}}" in
            restart-wireguard)
              systemctl restart --no-block "wg-quick@${{WG_INTERFACE}}"
              ;;
            repair-ru-wireguard-route)
              ip -4 route replace "${{WG_FOREIGN_ADDRESS_HOST}}/32" dev "${{WG_INTERFACE}}"
              ip -6 route replace "${{WG_FOREIGN_ADDRESS_V6_HOST}}/128" dev "${{WG_INTERFACE}}"
              ip -4 route replace default dev "${{WG_INTERFACE}}" table "{env['WG_ROUTE_TABLE']}"
              ip -6 route replace default dev "${{WG_INTERFACE}}" table "{env['WG_ROUTE_TABLE']}"
              ip -4 rule del fwmark "{env['APP_ROUTE_MARK']}" table "{env['WG_ROUTE_TABLE']}" priority 10000 >/dev/null 2>&1 || true
              ip -4 rule add fwmark "{env['APP_ROUTE_MARK']}" table "{env['WG_ROUTE_TABLE']}" priority 10000
              ip -6 rule del fwmark "{env['APP_ROUTE_MARK']}" table "{env['WG_ROUTE_TABLE']}" priority 10000 >/dev/null 2>&1 || true
              ip -6 rule add fwmark "{env['APP_ROUTE_MARK']}" table "{env['WG_ROUTE_TABLE']}" priority 10000
              ;;
            restart-foreign-nftables)
              systemctl restart --no-block nftables vpn-stack-sync.service
              ;;
            *)
              return 1
              ;;
          esac
        }}

        maybe_self_heal() {{
          local severity="$1"
          shift || true
          local reason_key="" action="" now="" last_reason="" consecutive="0"
          local last_action_epoch="0" cooldown_s="0" window_epoch="0" window_count="0"
          local result="scheduled"

          [[ "${{SELF_HEAL_ENABLED}}" == "1" ]] || return 0
          [[ "$#" -gt 0 ]] || return 0

          reason_key="$(self_heal_reason_key "$@")"
          [[ -n "${{reason_key}}" ]] || return 0

          action="$(self_heal_action_for_key "${{reason_key}}")"
          [[ "${{action}}" != "none" ]] || return 0

          now="$(date +%s)"
          [[ "${{now}}" =~ ^[0-9]+$ ]] || return 0

          last_reason="$(state_value SELF_HEAL_LAST_REASON)"
          consecutive="$(number_or_default "$(state_value SELF_HEAL_CONSECUTIVE)" 0)"
          if [[ "${{last_reason}}" == "${{severity}}:${{reason_key}}" ]]; then
            consecutive="$((consecutive + 1))"
          else
            consecutive="1"
          fi
          set_state_value SELF_HEAL_LAST_REASON "${{severity}}:${{reason_key}}"
          set_state_value SELF_HEAL_CONSECUTIVE "${{consecutive}}"
          set_state_value SELF_HEAL_LAST_SEEN_EPOCH "${{now}}"

          if [[ "${{consecutive}}" -lt "${{SELF_HEAL_CONFIRMATIONS}}" ]]; then
            log "self-heal pending confirmation ${{consecutive}}/${{SELF_HEAL_CONFIRMATIONS}} for ${{reason_key}}"
            return 0
          fi

          last_action_epoch="$(number_or_default "$(state_value SELF_HEAL_LAST_ACTION_EPOCH)" 0)"
          cooldown_s="$((SELF_HEAL_COOLDOWN_MINUTES * 60))"
          if [[ "${{last_action_epoch}}" -gt 0 && "$((now - last_action_epoch))" -lt "${{cooldown_s}}" ]]; then
            log "self-heal cooldown active for ${{reason_key}}"
            return 0
          fi

          window_epoch="$(number_or_default "$(state_value SELF_HEAL_ACTION_WINDOW_EPOCH)" 0)"
          window_count="$(number_or_default "$(state_value SELF_HEAL_ACTION_WINDOW_COUNT)" 0)"
          if [[ "${{window_epoch}}" -le 0 || "$((now - window_epoch))" -ge 3600 ]]; then
            window_epoch="${{now}}"
            window_count="0"
          fi
          if [[ "${{window_count}}" -ge "${{SELF_HEAL_MAX_ACTIONS_PER_HOUR}}" ]]; then
            log "self-heal hourly limit reached for ${{reason_key}}"
            return 0
          fi

          log "self-heal action=${{action}} reason=${{reason_key}}"
          if perform_self_heal_action "${{action}}"; then
            result="scheduled"
          else
            result="failed"
          fi
          set_state_value SELF_HEAL_LAST_ACTION_EPOCH "${{now}}"
          set_state_value SELF_HEAL_ACTION_WINDOW_EPOCH "${{window_epoch}}"
          set_state_value SELF_HEAL_ACTION_WINDOW_COUNT "$((window_count + 1))"
          set_state_value SELF_HEAL_LAST_ACTION "${{action}}"
          set_state_value SELF_HEAL_LAST_ACTION_REASON "${{severity}}:${{reason_key}}"
          set_state_value SELF_HEAL_LAST_ACTION_RESULT "${{result}}"
        }}

        collect_hard_reasons() {{
          local reasons=()
          local age=""
          if ! ssh_banner_ok; then
            reasons+=("ssh_banner")
          fi
          if ! probe_wireguard_path; then
            append_wireguard_path_reason
          fi
          age="$(wg_handshake_age)"
          if [[ "${{age}}" =~ ^[0-9]+$ && "${{age}}" -gt "${{HANDSHAKE_GRACE}}" ]]; then
            reasons+=("wg_handshake_stale=${{age}}")
          fi
        {textwrap.indent(role_specific_direct_probe, '  ')}
          if [[ "${{#reasons[@]}}" -gt 0 ]]; then
            printf '%s\\n' "${{reasons[@]}}"
          fi
        }}

        collect_soft_reasons() {{
          local deep_reasons=()
          local fast_loss="-1"
          if [[ "${{ROLE}}" == "foreign-exit" ]]; then
            fast_loss="$(probe_ping_loss_pct_fast "${{RU_PUBLIC_IP}}")"
            set_state_value FAST_FOREIGN_RU_PING_LOSS_PCT "${{fast_loss}}"
            if [[ "${{fast_loss}}" =~ ^[0-9]+$ && "${{fast_loss}}" -gt "${{MAX_FOREIGN_RU_PING_LOSS_PCT}}" ]]; then
              printf '%s\\n' "foreign_ru_ping_loss_fast=${{fast_loss}}"
            fi
          else
            fast_loss="$(probe_ping_loss_pct_fast "${{FOREIGN_PUBLIC_IP}}")"
            set_state_value FAST_RU_FOREIGN_PING_LOSS_PCT "${{fast_loss}}"
            if [[ "${{fast_loss}}" =~ ^[0-9]+$ && "${{fast_loss}}" -gt "${{MAX_FOREIGN_RU_PING_LOSS_PCT}}" ]]; then
              printf '%s\\n' "ru_foreign_ping_loss_fast=${{fast_loss}}"
            fi
          fi
          if should_run_deep_probe; then
            mapfile -t deep_reasons < <(run_deep_probe)
          fi
          if [[ "${{#deep_reasons[@]}}" -gt 0 ]]; then
            printf '%s\\n' "${{deep_reasons[@]}}"
          fi
        }}

        harden_runtime
        mapfile -t hard_reasons < <(collect_hard_reasons)
        mapfile -t soft_reasons < <(collect_soft_reasons)
        if [[ "${{#hard_reasons[@]}}" -eq 0 && "${{#soft_reasons[@]}}" -eq 0 ]]; then
          reset_self_heal_observation
          exit 0
        fi
        if [[ "${{#hard_reasons[@]}}" -eq 0 ]]; then
          log "runtime degraded without hard failure: ${{soft_reasons[*]}}"
          exit 0
        fi

        log "runtime hard failure: ${{hard_reasons[*]}}"
        if [[ "${{#soft_reasons[@]}}" -gt 0 ]]; then
          log "latest deep degradation snapshot: ${{soft_reasons[*]}}"
        fi
        maybe_self_heal "hard" "${{hard_reasons[@]}}"
        exit 1
        """
    ).strip() + "\n"


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
            "ExecStart=/usr/local/lib/vpn-stack/health-check.sh",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def render_health_timer(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Periodic vpn-stack runtime health repair",
            "",
            "[Timer]",
            "OnBootSec=1min",
            f"OnUnitActiveSec={env['HEALTH_CHECK_INTERVAL_MINUTES']}min",
            "AccuracySec=15s",
            "Unit=vpn-stack-health.service",
            "",
            "[Install]",
            "WantedBy=timers.target",
            "",
        ]
    )


def render_guard_script(env: dict[str, str], role: str) -> str:
    return textwrap.dedent(
        f"""
        #!/usr/bin/env bash
        set -euo pipefail

        ROLE="{role}"
        GUARD_ENABLED="{env['GUARD_ENABLED']}"
        LOOKBACK_MINUTES="{env['GUARD_LOOKBACK_MINUTES']}"
        BLOCK_TIMEOUT="{env['GUARD_BLOCK_TIMEOUT']}"
        SSH_FAILURE_THRESHOLD="{env['GUARD_SSH_FAILURE_THRESHOLD']}"
        REALITY_INVALID_THRESHOLD="{env['GUARD_REALITY_INVALID_THRESHOLD']}"
        STATE_PATH="/var/lib/vpn-stack/guard-state.env"

        log() {{
          echo "vpn-stack-guard[$ROLE]: $*" >&2
        }}

        is_ipv4() {{
          local ip="$1"
          local a b c d octet
          [[ "$ip" =~ ^([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}$ ]] || return 1
          IFS=. read -r a b c d <<<"$ip"
          for octet in "$a" "$b" "$c" "$d"; do
            [[ "$octet" =~ ^[0-9]+$ ]] || return 1
            (( octet >= 0 && octet <= 255 )) || return 1
          done
        }}

        ensure_abuse_set() {{
          command -v nft >/dev/null 2>&1 || return 1
          nft list table inet vpnstack >/dev/null 2>&1 || return 1
          nft list set inet vpnstack abuse_ipv4 >/dev/null 2>&1 && return 0
          nft add set inet vpnstack abuse_ipv4 '{{ type ipv4_addr; flags timeout; }}' >/dev/null 2>&1
        }}

        add_block() {{
          local ip="$1"
          local reason="$2"
          is_ipv4 "$ip" || return 0
          nft add element inet vpnstack abuse_ipv4 "{{ $ip timeout $BLOCK_TIMEOUT }}" >/dev/null 2>&1 || true
          log "temporary block $ip ($reason, timeout=$BLOCK_TIMEOUT)"
        }}

        extract_ipv4() {{
          grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' || true
        }}

        ssh_noise_ips() {{
          journalctl -u ssh.service -u ssh.socket --since "-${{LOOKBACK_MINUTES}} minutes" --no-pager 2>/dev/null \\
            | grep -E 'Failed password|Invalid user|maximum authentication attempts|Timeout before authentication|kex_exchange_identification|banner exchange' \\
            | extract_ipv4
        }}

        reality_noise_ips() {{
          journalctl -u sing-box.service --since "-${{LOOKBACK_MINUTES}} minutes" --no-pager 2>/dev/null \\
            | grep -F 'REALITY: processed invalid connection' \\
            | extract_ipv4
        }}

        block_repeated_ips() {{
          local threshold="$1"
          local reason="$2"
          local tmp
          local blocked=0
          tmp="$(mktemp)"
          cat >"$tmp"
          while read -r count ip; do
            [[ -n "${{ip:-}}" ]] || continue
            if (( count >= threshold )); then
              add_block "$ip" "$reason:$count"
              blocked=$((blocked + 1))
            fi
          done < <(sort "$tmp" | uniq -c)
          rm -f "$tmp"
          printf '%s' "$blocked"
        }}

        write_state() {{
          local ssh_blocked="$1"
          local reality_blocked="$2"
          mkdir -p "$(dirname "$STATE_PATH")"
          cat >"$STATE_PATH" <<EOF
        GUARD_LAST_RUN_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        GUARD_ROLE="$ROLE"
        GUARD_ENABLED="$GUARD_ENABLED"
        GUARD_LOOKBACK_MINUTES="$LOOKBACK_MINUTES"
        GUARD_BLOCK_TIMEOUT="$BLOCK_TIMEOUT"
        GUARD_SSH_BLOCKED_COUNT="$ssh_blocked"
        GUARD_REALITY_BLOCKED_COUNT="$reality_blocked"
        EOF
        }}

        if [[ "$GUARD_ENABLED" != "1" ]]; then
          write_state 0 0
          exit 0
        fi

        if ! ensure_abuse_set; then
          log "nftables set inet vpnstack abuse_ipv4 is unavailable, skipping"
          write_state 0 0
          exit 0
        fi

        ssh_blocked="$(ssh_noise_ips | block_repeated_ips "$SSH_FAILURE_THRESHOLD" ssh)"
        reality_blocked="0"
        if [[ "$ROLE" == "ru-gateway" ]]; then
          reality_blocked="$(reality_noise_ips | block_repeated_ips "$REALITY_INVALID_THRESHOLD" reality)"
        fi
        write_state "$ssh_blocked" "$reality_blocked"
        """
    ).strip() + "\n"


def render_guard_service() -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Update vpn-stack abuse guard",
            "After=nftables.service",
            "Wants=nftables.service",
            "",
            "[Service]",
            "Type=oneshot",
            "ExecStart=/usr/local/lib/vpn-stack/guard.sh",
            "",
        ]
    )


def render_guard_timer(env: dict[str, str]) -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=Run vpn-stack abuse guard",
            "",
            "[Timer]",
            "OnBootSec=2min",
            f"OnUnitActiveSec={env['GUARD_INTERVAL_MINUTES']}min",
            "AccuracySec=30s",
            "Unit=vpn-stack-guard.service",
            "",
            "[Install]",
            "WantedBy=timers.target",
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


def rendered_files_for_role(env: dict[str, str], role: str) -> dict[str, str]:
    if role == ROLE_RU:
        return {
            "sing-box.json": render_ru_singbox(env),
            f"{env['WG_INTERFACE']}.conf": render_ru_wg(env),
            "nftables.conf": render_ru_firewall_nftables(env),
            "sshd-vpn-stack.conf": render_sshd_hardening(env),
            "sync-state.sh": render_sync_script(env),
            "health-check.sh": render_health_script(env, ROLE_RU),
            "guard.sh": render_guard_script(env, ROLE_RU),
            "vpn-stack-sync.service": render_sync_service(ROLE_RU),
            "vpn-stack-sync.timer": render_sync_timer(),
            "vpn-stack-health.service": render_health_service(),
            "vpn-stack-health.timer": render_health_timer(env),
            "vpn-stack-guard.service": render_guard_service(),
            "vpn-stack-guard.timer": render_guard_timer(env),
        }
    wan_iface = env.get("WAN_INTERFACE", "").strip() or "eth0"
    return {
        "sing-box.json": render_foreign_singbox(),
        f"{env['WG_INTERFACE']}.conf": render_foreign_wg(env),
        "nftables.conf": render_foreign_nftables(env, wan_iface),
        "sshd-vpn-stack.conf": render_sshd_hardening(env),
        "sync-state.sh": render_sync_script(env),
        "health-check.sh": render_health_script(env, ROLE_FOREIGN),
        "guard.sh": render_guard_script(env, ROLE_FOREIGN),
        "vpn-stack-sync.service": render_sync_service(ROLE_FOREIGN),
        "vpn-stack-sync.timer": render_sync_timer(),
        "vpn-stack-health.service": render_health_service(),
        "vpn-stack-health.timer": render_health_timer(env),
        "vpn-stack-guard.service": render_guard_service(),
        "vpn-stack-guard.timer": render_guard_timer(env),
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


def render_preview_files(env: dict[str, str], preview_dir: Path) -> None:
    reset_generated_dir(preview_dir_for_role(preview_dir, ROLE_RU))
    reset_generated_dir(preview_dir_for_role(preview_dir, ROLE_FOREIGN))
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
    reset_generated_dir(server_dir)
    write_text(server_dir / "ru.env", render_env_text(env))
    write_text(server_dir / "foreign.env", render_env_text(env))
    render_preview_files(env, preview_dir)
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
        write_role_rendered_files(env=parse_env_text(env_text), role=role, output_dir=cloud_root / "rendered")
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
    for asset_name in ("ru-ipv4.zone", "ru-ipv6.zone"):
        copy_asset_if_present(assets_dir / asset_name, foreign_bundle / "assets" / asset_name)
    create_tarball(ru_bundle, bundle_dir / f"{ROLE_RU}.tar.gz")
    create_tarball(foreign_bundle, bundle_dir / f"{ROLE_FOREIGN}.tar.gz")
    return bundle_dir


def render_all_artifacts(env_path: Path, env: dict[str, str]) -> Path:
    effective_env = apply_ru_direct_overlays(env, env_path)
    out_dir = render_config_artifacts(env_path, effective_env, fetch_assets_first=True)
    render_client_profiles(effective_env)
    render_cloud_init_artifacts(effective_env)
    package_bundle(effective_env)
    return out_dir
