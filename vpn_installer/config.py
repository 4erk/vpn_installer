from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .common import DEPLOYMENTS_DIR, env_line, fail, parse_env_value, read_text, sanitize_name, write_text
from .models import (
    ALLOW_EMPTY_OVERRIDE,
    DEFAULT_ASSET_TIMEOUT,
    ENV_SECTIONS,
    REQUIRED_ENV_VARS,
    X25519_A24,
    X25519_P,
    AppError,
)

MERGED_CSV_DEFAULT_KEYS = {
    "RU_FORCE_DIRECT_DOMAIN",
    "RU_FORCE_DIRECT_DOMAIN_SUFFIX",
    "RU_FORCE_DIRECT_IP_CIDR",
    "RU_BLOCK_IP_CIDR",
}

MERGED_SOURCE_DEFAULT_KEYS = {
    "RU_GEOSITE_URL",
    "RU_GEOIP_URL",
    "FOREIGN_RU_IPV4_LIST_URL",
    "FOREIGN_RU_IPV6_LIST_URL",
    "HEALTH_TARGET_PROBE_URLS",
    "HEALTH_RU_DIRECT_TARGET_PROBE_URLS",
}

DEPRECATED_ENV_KEYS = {
    "CLIENT_COMPAT_UUID",
    "RU_COMPAT_LISTEN_PORTS",
}

REMOTE_ENV_CRITICAL_KEYS = {
    "DEPLOY_NAME",
    "CLIENT_UUID",
    "RU_LISTEN_PORT",
    "RU_ROUTER_LISTEN_PORT",
    "RU_REALITY_PUBLIC_KEY",
    "RU_REALITY_SHORT_ID",
    "RU_REALITY_ACCEPT_EMPTY_SHORT_ID",
    "SING_BOX_LOG_LEVEL",
    "RU_SNIFF_TIMEOUT",
    "TO_FOREIGN_CONNECT_TIMEOUT",
    "TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT",
    "GUARD_ENABLED",
    "GUARD_INTERVAL_MINUTES",
    "GUARD_LOOKBACK_MINUTES",
    "GUARD_BLOCK_TIMEOUT",
    "GUARD_SSH_FAILURE_THRESHOLD",
    "GUARD_REALITY_INVALID_THRESHOLD",
    "GUARD_REALITY_BLOCK_ENABLED",
    "WAN_INTERFACE",
    "DISABLE_NIC_OFFLOADS",
    "RUNTIME_QDISC",
    "JOURNAL_LIMIT_ENABLED",
    "JOURNAL_SYSTEM_MAX_USE",
    "JOURNAL_MAX_RETENTION_SEC",
    "WG_MTU",
    "HEALTH_THROUGHPUT_URLS",
    "HEALTH_UPLOAD_URL",
    "HEALTH_UPLOAD_BYTES",
    "HEALTH_DEEP_PROBE_INTERVAL_MINUTES",
    "HEALTH_MIN_FOREIGN_DIRECT_DOWNLOAD_BPS",
    "HEALTH_MIN_RU_WG_DOWNLOAD_BPS",
    "HEALTH_MIN_FOREIGN_DIRECT_UPLOAD_BPS",
    "HEALTH_MIN_RU_WG_UPLOAD_BPS",
    "HEALTH_MAX_FOREIGN_RU_PING_LOSS_PCT",
    "HEALTH_MAX_FOREIGN_INTERNET_PING_LOSS_PCT",
    "HEALTH_HANDSHAKE_GRACE_SECONDS",
    "HEALTH_HANDSHAKE_MIN_GRACE_SECONDS",
    "HEALTH_HANDSHAKE_GRACE_MULTIPLIER",
    "HEALTH_SELF_HEAL",
    "HEALTH_SELF_HEAL_COOLDOWN_MINUTES",
    "HEALTH_SELF_HEAL_MAX_ACTIONS_PER_HOUR",
    "HEALTH_SELF_HEAL_CONFIRMATIONS",
    "HEALTH_TARGET_PROBE_URLS",
    "HEALTH_RU_DIRECT_TARGET_PROBE_URLS",
    "HEALTH_TARGET_CONNECT_TIMEOUT_SECONDS",
    "HEALTH_TARGET_MAX_TIME_SECONDS",
    "RU_FORCE_DIRECT_DOMAIN",
    "RU_FORCE_DIRECT_DOMAIN_SUFFIX",
    "RU_FORCE_DIRECT_IP_CIDR",
    "RU_BLOCK_IP_CIDR",
    "RU_IPV6_POLICY",
    "RU_BLOCK_QUIC",
    "RU_GEOIP_DIRECT",
    "RU_GEOSITE_URL",
    "RU_GEOIP_URL",
    "FOREIGN_BLOCK_RU",
    "FOREIGN_RU_IPV4_LIST_URL",
    "FOREIGN_RU_IPV6_LIST_URL",
}

RU_DIRECT_OVERLAY_FILES = {
    "RU_FORCE_DIRECT_DOMAIN": "ru-direct-domains.txt",
    "RU_FORCE_DIRECT_DOMAIN_SUFFIX": "ru-direct-suffixes.txt",
    "RU_FORCE_DIRECT_IP_CIDR": "ru-direct-cidrs.txt",
}


def validate_deployment_name(raw_name: str) -> str:
    cleaned = sanitize_name(raw_name)
    if not cleaned:
        fail("Имя deployment пустое или состоит только из недопустимых символов.")
    return cleaned


def parse_env_text(env_text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw_line in env_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        env[key.strip()] = parse_env_value(raw_value)
    return env


def load_env_file(path: Path) -> dict[str, str]:
    return parse_env_text(read_text(path))


def render_env_text(env: dict[str, str]) -> str:
    lines: list[str] = []
    seen_keys: set[str] = set()
    for comment, keys in ENV_SECTIONS:
        if comment:
            if lines:
                lines.append("")
            lines.append(comment)
        for key in keys:
            lines.append(env_line(key, env.get(key, "")))
            seen_keys.add(key)
    extra_keys = sorted(key for key in env if key not in seen_keys)
    if extra_keys:
        lines.extend(["", "# Extra values"])
        for key in extra_keys:
            lines.append(env_line(key, env[key]))
    return "\n".join(lines) + "\n"


def clamp_x25519_private(private_key: bytes) -> bytes:
    data = bytearray(private_key)
    data[0] &= 248
    data[31] &= 127
    data[31] |= 64
    return bytes(data)


def x25519_public_from_private(private_key: bytes) -> bytes:
    scalar = int.from_bytes(clamp_x25519_private(private_key), "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for bit in range(254, -1, -1):
        current = (scalar >> bit) & 1
        swap ^= current
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = current
        a = (x2 + z2) % X25519_P
        aa = (a * a) % X25519_P
        b = (x2 - z2) % X25519_P
        bb = (b * b) % X25519_P
        e = (aa - bb) % X25519_P
        c = (x3 + z3) % X25519_P
        d = (x3 - z3) % X25519_P
        da = (d * a) % X25519_P
        cb = (c * b) % X25519_P
        x3 = pow((da + cb) % X25519_P, 2, X25519_P)
        z3 = (x1 * pow((da - cb) % X25519_P, 2, X25519_P)) % X25519_P
        x2 = (aa * bb) % X25519_P
        z2 = (e * ((aa + (X25519_A24 * e)) % X25519_P)) % X25519_P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = (x2 * pow(z2, X25519_P - 2, X25519_P)) % X25519_P
    return result.to_bytes(32, "little")


def generate_x25519_pair() -> tuple[bytes, bytes]:
    private_key = clamp_x25519_private(os.urandom(32))
    return private_key, x25519_public_from_private(private_key)


def generate_default_env(deploy_name: str) -> dict[str, str]:
    reality_private, reality_public = generate_x25519_pair()
    ru_wg_private, ru_wg_public = generate_x25519_pair()
    foreign_wg_private, foreign_wg_public = generate_x25519_pair()
    return {
        "DEPLOY_NAME": deploy_name,
        "RU_PUBLIC_IP": "",
        "FOREIGN_PUBLIC_IP": "",
        "SSH_PORT": "22",
        "SSH_LOGIN_GRACE_TIME": "20",
        "SSH_MAX_AUTH_TRIES": "3",
        "SSH_MAX_STARTUPS": "5:30:20",
        "SSH_PER_SOURCE_MAX_STARTUPS": "2",
        "SSH_PER_SOURCE_NETBLOCK_SIZE": "24:64",
        "SSH_INPUT_RATE": "6/minute",
        "SSH_INPUT_BURST": "3",
        "RU_HTTPS_INPUT_RATE": "120/minute",
        "RU_HTTPS_INPUT_BURST": "60",
        "GUARD_ENABLED": "1",
        "GUARD_INTERVAL_MINUTES": "5",
        "GUARD_LOOKBACK_MINUTES": "30",
        "GUARD_BLOCK_TIMEOUT": "6h",
        "GUARD_SSH_FAILURE_THRESHOLD": "6",
        "GUARD_REALITY_INVALID_THRESHOLD": "8",
        "GUARD_REALITY_BLOCK_ENABLED": "0",
        "WAN_INTERFACE": "",
        "DISABLE_NIC_OFFLOADS": "1",
        "RUNTIME_QDISC": "fq",
        "CLIENT_UUID": str(uuid.uuid4()),
        "CLIENT_FLOW": "xtls-rprx-vision",
        "RU_LISTEN_PORT": "443",
        "RU_ROUTER_LISTEN_PORT": "2080",
        "RU_REALITY_SERVER_NAME": "www.bing.com",
        "RU_REALITY_HANDSHAKE_SERVER": "www.bing.com",
        "RU_REALITY_HANDSHAKE_PORT": "443",
        "RU_REALITY_PRIVATE_KEY": base64_url_nopad(reality_private),
        "RU_REALITY_PUBLIC_KEY": base64_url_nopad(reality_public),
        "RU_REALITY_SHORT_ID": "0123456789abcdef",
        "RU_REALITY_ACCEPT_EMPTY_SHORT_ID": "1",
        "RU_REALITY_MAX_TIME_DIFFERENCE": "24h",
        "UTLS_FINGERPRINT": "chrome",
        "SING_BOX_LOG_LEVEL": "info",
        "RU_SNIFF_TIMEOUT": "250ms",
        "TO_FOREIGN_CONNECT_TIMEOUT": "",
        "TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT": "2s",
        "WG_INTERFACE": "wg0",
        "WG_PORT": "51820",
        "WG_MTU": "1360",
        "WG_KEEPALIVE": "25",
        "WG_ROUTE_TABLE": "51820",
        "APP_ROUTE_MARK": "48",
        "WG_TUNNEL_FWMARK": "51820",
        "WG_RU_ADDRESS": "10.74.0.1/32",
        "WG_FOREIGN_ADDRESS": "10.74.0.2/32",
        "WG_RU_ADDRESS_V6": "fd74:7670:6e73::1/128",
        "WG_FOREIGN_ADDRESS_V6": "fd74:7670:6e73::2/128",
        "WG_IPV6_PREFIX": "fd74:7670:6e73::/64",
        "WG_RU_PRIVATE_KEY": base64_std(ru_wg_private),
        "WG_RU_PUBLIC_KEY": base64_std(ru_wg_public),
        "WG_FOREIGN_PRIVATE_KEY": base64_std(foreign_wg_private),
        "WG_FOREIGN_PUBLIC_KEY": base64_std(foreign_wg_public),
        "WG_PRESHARED_KEY": base64_std(os.urandom(32)),
        "RU_DIRECT_DNS_SERVER": "77.88.8.8",
        "RU_DIRECT_DNS_PORT": "53",
        "GLOBAL_DOH_SERVER": "8.8.8.8",
        "GLOBAL_DOH_SERVER_NAME": "dns.google",
        "GLOBAL_DOH_PATH": "/dns-query",
        "RU_FORCE_DIRECT_DOMAIN": "api.oneme.ru,mtalk.google.com,calls.okcdn.ru,gosuslugi.ru,api.ok.ru,ifconfig.me,ifconfig.co,checkip.amazonaws.com,ipapi.co,ipinfo.io,ident.me,tnedi.me,icanhazip.com,ip.mail.ru,ipv4-internet.yandex.net,ipv6-internet.yandex.net,2ip.ru",
        "RU_FORCE_DIRECT_DOMAIN_SUFFIX": ".gstatic.com,.gosuslugi.ru,.ipify.org,.ipinfo.io,.ident.me,.tnedi.me,.icanhazip.com",
        "RU_FORCE_DIRECT_IP_CIDR": "",
        "RU_BLOCK_IP_CIDR": "",
        "RU_IPV6_POLICY": "fast-fail",
        "RU_BLOCK_QUIC": "0",
        "RU_GEOIP_DIRECT": "0",
        "RULESET_DIR": "/var/lib/vpn-stack/rules",
        "RU_GEOSITE_URL": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-ru.srs",
        "RU_GEOIP_URL": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-ru.srs https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-ru.srs",
        "FOREIGN_BLOCK_RU": "0",
        "FOREIGN_RU_IPV4_LIST_URL": "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone https://stat.ripe.net/data/country-resource-list/data.json?resource=ru&v4_format=prefix",
        "FOREIGN_RU_IPV6_LIST_URL": "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone https://stat.ripe.net/data/country-resource-list/data.json?resource=ru",
        "HEALTHCHECK_URL": "https://api.ipify.org",
        "JOURNAL_LIMIT_ENABLED": "1",
        "JOURNAL_SYSTEM_MAX_USE": "256M",
        "JOURNAL_MAX_RETENTION_SEC": "14day",
        "HEALTH_THROUGHPUT_URLS": "https://cachefly.cachefly.net/1mb.test https://proof.ovh.net/files/1Mb.dat",
        "HEALTH_UPLOAD_URL": "https://speed.cloudflare.com/__up",
        "HEALTH_UPLOAD_BYTES": "1048576",
        "HEALTH_DEEP_PROBE_INTERVAL_MINUTES": "15",
        "HEALTH_MIN_FOREIGN_DIRECT_DOWNLOAD_BPS": "300000",
        "HEALTH_MIN_RU_WG_DOWNLOAD_BPS": "300000",
        "HEALTH_MIN_FOREIGN_DIRECT_UPLOAD_BPS": "1000000",
        "HEALTH_MIN_RU_WG_UPLOAD_BPS": "1000000",
        "HEALTH_MAX_FOREIGN_RU_PING_LOSS_PCT": "5",
        "HEALTH_MAX_FOREIGN_INTERNET_PING_LOSS_PCT": "5",
        "HEALTH_HANDSHAKE_GRACE_SECONDS": "180",
        "HEALTH_HANDSHAKE_MIN_GRACE_SECONDS": "180",
        "HEALTH_HANDSHAKE_GRACE_MULTIPLIER": "8",
        "HEALTH_CHECK_INTERVAL_MINUTES": "2",
        "HEALTH_SELF_HEAL": "1",
        "HEALTH_SELF_HEAL_COOLDOWN_MINUTES": "15",
        "HEALTH_SELF_HEAL_MAX_ACTIONS_PER_HOUR": "2",
        "HEALTH_SELF_HEAL_CONFIRMATIONS": "2",
        "HEALTH_TARGET_PROBE_URLS": "https://chatgpt.com/ https://discord.com/ https://github.com/ https://www.google.com/generate_204 https://telegram.org/ https://api.telegram.org/ https://t.me/",
        "HEALTH_RU_DIRECT_TARGET_PROBE_URLS": "https://api.ipify.org/ https://2ip.ru/",
        "HEALTH_TARGET_CONNECT_TIMEOUT_SECONDS": "2",
        "HEALTH_TARGET_MAX_TIME_SECONDS": "4",
        "ADMIN_WEB_ENABLED": "1",
        "ADMIN_WEB_BIND": "0.0.0.0",
        "ADMIN_WEB_PORT": "11333",
        "ADMIN_WEB_ACTIVE_CLIENT_REQUIRED": "1",
        "ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS": "5",
        "ADMIN_WEB_ALLOW_TUNNEL_CLIENTS": "1",
        "ADMIN_WEB_ALLOWED_CIDR": "",
        "ADMIN_WEB_ALLOW_WG": "0",
        "ADMIN_WEB_USERNAME": "user",
        "ADMIN_WEB_PASSWORD": "password",
        "CLIENT_TUN_NAME": "tun0",
        "CLIENT_TUN_ADDRESS_V4": "172.19.0.1/30",
        "CLIENT_TUN_ADDRESS_V6": "fdfe:dcba:9876::1/126",
        "CLIENT_FAKEIP_V4": "198.18.0.0/15",
        "CLIENT_FAKEIP_V6": "fc00::/18",
        "CLIENT_ENABLE_IPV6": "0",
        "CLIENT_ROUTE_EXCLUDE_V4": "",
        "CLIENT_ROUTE_EXCLUDE_V6": "",
    }


def base64_std(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def base64_url_nopad(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _split_csv_values(raw_value: str) -> list[str]:
    return [item.strip() for item in raw_value.replace("\n", ",").split(",") if item.strip()]


def _split_overlay_values(raw_value: str) -> list[str]:
    values: list[str] = []
    for raw_line in raw_value.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        values.extend(_split_csv_values(line))
    return values


def _merge_csv_defaults(existing_value: str, default_value: str) -> str:
    merged: list[str] = []
    seen: set[str] = set()
    for item in _split_csv_values(existing_value) + _split_csv_values(default_value):
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    return ",".join(merged)


def _merge_source_defaults(existing_value: str, default_value: str) -> str:
    merged: list[str] = []
    seen: set[str] = set()
    for item in split_asset_sources(existing_value) + split_asset_sources(default_value):
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    return " ".join(merged)


def merge_env_with_defaults(existing: dict[str, str], deploy_name: str) -> dict[str, str]:
    defaults = generate_default_env(deploy_name)
    merged = defaults.copy()
    for key, value in existing.items():
        if key in DEPRECATED_ENV_KEYS:
            continue
        if value or key in ALLOW_EMPTY_OVERRIDE:
            merged[key] = value
    for key in MERGED_CSV_DEFAULT_KEYS:
        if existing.get(key):
            merged[key] = _merge_csv_defaults(existing[key], defaults[key])
    for key in MERGED_SOURCE_DEFAULT_KEYS:
        if existing.get(key):
            merged[key] = _merge_source_defaults(existing[key], defaults[key])
    if merged.get("UTLS_FINGERPRINT") == "randomized":
        merged["UTLS_FINGERPRINT"] = defaults["UTLS_FINGERPRINT"]
    if merged.get("RU_LISTEN_PORT") == "8443":
        merged["RU_LISTEN_PORT"] = defaults["RU_LISTEN_PORT"]
    if merged.get("RU_REALITY_SERVER_NAME") == "www.cloudflare.com":
        merged["RU_REALITY_SERVER_NAME"] = defaults["RU_REALITY_SERVER_NAME"]
    if merged.get("RU_REALITY_HANDSHAKE_SERVER") == "www.cloudflare.com":
        merged["RU_REALITY_HANDSHAKE_SERVER"] = defaults["RU_REALITY_HANDSHAKE_SERVER"]
    if merged.get("SSH_INPUT_RATE") == "12/minute":
        merged["SSH_INPUT_RATE"] = defaults["SSH_INPUT_RATE"]
    if merged.get("SSH_INPUT_BURST") == "6":
        merged["SSH_INPUT_BURST"] = defaults["SSH_INPUT_BURST"]
    if merged.get("WG_MTU") == "1380":
        merged["WG_MTU"] = defaults["WG_MTU"]
    if merged.get("RUNTIME_QDISC", "") == "":
        merged["RUNTIME_QDISC"] = defaults["RUNTIME_QDISC"]
    if merged.get("HEALTH_HANDSHAKE_GRACE_SECONDS") == "120":
        merged["HEALTH_HANDSHAKE_GRACE_SECONDS"] = defaults["HEALTH_HANDSHAKE_GRACE_SECONDS"]
    if merged.get("HEALTH_DEEP_PROBE_INTERVAL_MINUTES") == "30":
        merged["HEALTH_DEEP_PROBE_INTERVAL_MINUTES"] = defaults["HEALTH_DEEP_PROBE_INTERVAL_MINUTES"]
    if merged.get("RU_BLOCK_IP_CIDR") == "91.108.56.0/22":
        merged["RU_BLOCK_IP_CIDR"] = defaults["RU_BLOCK_IP_CIDR"]
    if merged.get("RU_IPV6_POLICY") in {"block", "to-foreign"}:
        merged["RU_IPV6_POLICY"] = defaults["RU_IPV6_POLICY"]
    if merged.get("RU_SNIFF_TIMEOUT") == "1s":
        merged["RU_SNIFF_TIMEOUT"] = defaults["RU_SNIFF_TIMEOUT"]
    if merged.get("TO_FOREIGN_CONNECT_TIMEOUT") in {"1s", "2s"}:
        merged["TO_FOREIGN_CONNECT_TIMEOUT"] = defaults["TO_FOREIGN_CONNECT_TIMEOUT"]
    if merged.get("SING_BOX_LOG_LEVEL") == "warn":
        merged["SING_BOX_LOG_LEVEL"] = defaults["SING_BOX_LOG_LEVEL"]
    if merged.get("GLOBAL_DOH_SERVER") == "1.1.1.1" and merged.get("GLOBAL_DOH_SERVER_NAME") == "cloudflare-dns.com":
        merged["GLOBAL_DOH_SERVER"] = defaults["GLOBAL_DOH_SERVER"]
        merged["GLOBAL_DOH_SERVER_NAME"] = defaults["GLOBAL_DOH_SERVER_NAME"]
    if (
        existing.get("ADMIN_WEB_BIND") in {"127.0.0.1", "localhost"}
        and merged.get("ADMIN_WEB_ACTIVE_CLIENT_REQUIRED", "1").strip().lower() in {"1", "true", "yes", "on"}
        and not existing.get("ADMIN_WEB_ALLOWED_CIDR", "").strip()
        and existing.get("ADMIN_WEB_ALLOW_WG", "0").strip().lower() in {"", "0", "false", "no", "off"}
    ):
        merged["ADMIN_WEB_BIND"] = defaults["ADMIN_WEB_BIND"]
    merged["DEPLOY_NAME"] = deploy_name
    return merged


def overlay_file_path(env_path: Path, deploy_name: str, overlay_name: str) -> Path:
    return env_path.with_name(f"{deploy_name}.{overlay_name}")


def apply_ru_direct_overlays(env: dict[str, str], env_path: Path | None) -> dict[str, str]:
    if env_path is None:
        return env.copy()
    deploy_name = env.get("DEPLOY_NAME", "").strip() or sanitize_name(env_path.stem)
    effective = env.copy()
    for env_key, overlay_name in RU_DIRECT_OVERLAY_FILES.items():
        path = overlay_file_path(env_path, deploy_name, overlay_name)
        if not path.is_file():
            continue
        overlay_items = _split_overlay_values(read_text(path))
        if not overlay_items:
            continue
        effective[env_key] = _merge_csv_defaults(effective.get(env_key, ""), ",".join(overlay_items))
    return effective


def critical_env_view(env: dict[str, str]) -> dict[str, str]:
    relevant_keys = set(REMOTE_ENV_CRITICAL_KEYS)
    relevant_keys.update(key for key in env if key.startswith("WG_"))
    return {key: env.get(key, "") for key in sorted(relevant_keys)}


def generate_example_env() -> dict[str, str]:
    env = generate_default_env("my-stack")
    env.update(
        {
            "RU_PUBLIC_IP": "203.0.113.10",
            "FOREIGN_PUBLIC_IP": "198.51.100.20",
            "CLIENT_UUID": "00000000-0000-0000-0000-000000000000",
            "RU_REALITY_PRIVATE_KEY": "",
            "RU_REALITY_PUBLIC_KEY": "",
            "WG_RU_PRIVATE_KEY": "",
            "WG_RU_PUBLIC_KEY": "",
            "WG_FOREIGN_PRIVATE_KEY": "",
            "WG_FOREIGN_PUBLIC_KEY": "",
            "WG_PRESHARED_KEY": "",
        }
    )
    return env


def render_example_env_text() -> str:
    return render_env_text(generate_example_env())


def ensure_deployment_env(env_path: Path, deployment_name: str) -> dict[str, str]:
    if env_path.exists():
        env = merge_env_with_defaults(load_env_file(env_path), deployment_name)
    else:
        env = generate_default_env(deployment_name)
    write_text(env_path, render_env_text(env))
    return env


def load_existing_deployment_env(deployment_name: str) -> tuple[Path, dict[str, str]]:
    env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
    if not env_path.exists():
        fail(f"Не найден deployment env: {env_path}")
    return env_path, merge_env_with_defaults(load_env_file(env_path), deployment_name)


def validate_ip_literal(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        fail("IP не может быть пустым.")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise AppError(f"Некорректный IP-адрес: {raw_value}") from exc
    return value


def validate_ssh_host(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        fail("SSH host не может быть пустым.")
    if any(char.isspace() for char in value):
        fail(f"SSH host не должен содержать пробелы: {raw_value}")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253:
        fail("SSH host слишком длинный.")
    labels = value.split(".")
    host_pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if not all(label and host_pattern.fullmatch(label) for label in labels):
        fail(f"Некорректное имя хоста: {raw_value}")
    return value


def validate_ssh_port(raw_value: str) -> str:
    value = raw_value.strip()
    try:
        port = int(value)
    except ValueError as exc:
        raise AppError(f"SSH port должен быть числом: {raw_value}") from exc
    if not 1 <= port <= 65535:
        fail(f"SSH port вне диапазона 1..65535: {raw_value}")
    return str(port)


def validate_ssh_user(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        fail("SSH user не может быть пустым.")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        fail(f"Некорректный SSH user: {raw_value}")
    return value


def normalize_identity_path(raw_path: str) -> str:
    raw_path = raw_path.strip()
    if not raw_path:
        return ""
    path = Path(raw_path).expanduser()
    path = (Path.cwd() / path).resolve() if not path.is_absolute() else path.resolve()
    return str(path)


def validate_identity_path(raw_path: str) -> str:
    normalized = normalize_identity_path(raw_path)
    if normalized and not Path(normalized).is_file():
        fail(f"Не найден SSH key: {normalized}")
    return normalized


def validate_auth_mode(raw_value: str) -> str:
    value = raw_value.strip().lower()
    if value not in {"key", "password"}:
        fail(f"Некорректный способ входа: {raw_value}")
    return value


def require_env(env: dict[str, str], required: list[str] | None = None) -> None:
    required_names = required or REQUIRED_ENV_VARS
    missing = [name for name in required_names if not env.get(name, "").strip()]
    if missing:
        fail(f"В deployment env не хватает обязательных значений: {', '.join(missing)}")


def find_existing_deployments() -> list[str]:
    names: list[str] = []
    for env_path in sorted(DEPLOYMENTS_DIR.glob("*.env")):
        if env_path.name != "deployment.env.example":
            names.append(env_path.stem)
    return names


def split_asset_sources(raw_value: str) -> list[str]:
    return [entry for entry in re.split(r"[\s|]+", raw_value.strip()) if entry]


def _country_resource_key(asset_name: str) -> str:
    return "ipv6" if asset_name.endswith(".ipv6") or "ipv6" in asset_name else "ipv4"


def _write_prefix_lines(destination: Path, prefixes: list[str]) -> None:
    if not prefixes:
        fail("Источник не вернул ни одного префикса.")
    tmp_path = destination.with_suffix(destination.suffix + ".tmp")
    tmp_path.write_text("\n".join(prefixes) + "\n", encoding="utf-8")
    tmp_path.replace(destination)


def _download_ripe_country_resource(url: str, destination: Path, asset_name: str) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "vpn-installer/1.0"})
    with urllib.request.urlopen(request, timeout=DEFAULT_ASSET_TIMEOUT) as response:
        payload = json.loads(response.read().decode("utf-8"))
    resources = payload.get("data", {}).get("resources", {})
    family_key = _country_resource_key(asset_name)
    prefixes = resources.get(family_key, [])
    if not isinstance(prefixes, list):
        fail(f"RIPE country-resource-list вернул неожиданный формат для {asset_name}.")
    normalized = [str(prefix).strip() for prefix in prefixes if str(prefix).strip()]
    _write_prefix_lines(destination, normalized)


def download_asset(url: str, destination: Path, asset_name: str) -> None:
    if "stat.ripe.net/data/country-resource-list/" in url:
        _download_ripe_country_resource(url, destination, asset_name)
        return
    download_file(url, destination)


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "vpn-installer/1.0"})
    tmp_path = destination.with_suffix(destination.suffix + ".tmp")
    with urllib.request.urlopen(request, timeout=DEFAULT_ASSET_TIMEOUT) as response:
        tmp_path.write_bytes(response.read())
    tmp_path.replace(destination)
