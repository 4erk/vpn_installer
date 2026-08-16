from __future__ import annotations

import ipaddress
import json
import os
import re
import http.client
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .common import DEPLOYMENTS_DIR, env_line, fail, parse_env_value, read_text, sanitize_name, write_text
from .interserver_transport import generate_transport_identity, generate_x25519_pair, validate_transport_identity
from .migration import migrate_env
from .models import (
    ALLOW_EMPTY_OVERRIDE,
    DEFAULT_ASSET_TIMEOUT,
    ENV_SECTIONS,
    REQUIRED_ENV_VARS,
    AppError,
)
from .topology import (
    CONFIG_SCHEMA_VERSION,
    LOCATION_RU,
    TOPOLOGY_DUAL,
    TopologySpec,
    normalize_node_id,
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
}

DEPRECATED_ENV_KEYS = {
    # Public web-admin access was replaced by the loopback-only SSH tunnel.
    # Compatibility boundary: remove in 0.20.1.
    "ADMIN_WEB_BIND",
    "ADMIN_WEB_ACTIVE_CLIENT_REQUIRED",
    "ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS",
    "ADMIN_WEB_ALLOW_TUNNEL_CLIENTS",
    "ADMIN_WEB_ALLOWED_CIDR",
    "ADMIN_WEB_ALLOW_WG",
    "CLIENT_COMPAT_UUID",
    "RU_COMPAT_LISTEN_PORTS",
    "RU_REALITY_HANDSHAKE_SERVER",
    "RU_REALITY_HANDSHAKE_PORT",
    "RU_LITERAL_POLICY",
    "RU_IPV6_LITERAL_POLICY",
    "RU_IPV6_POLICY",
    "RU_GEOIP_DIRECT",
    "TO_FOREIGN_CONNECT_TIMEOUT",
    "TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT",
    "TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT",
    "HEALTH_ROUTE_FAIL_CACHE_TTL_SECONDS",
    "HEALTH_ROUTE_FAIL_THRESHOLD",
    "HEALTH_GOOD_CACHE_TTL_SECONDS",
    "HEALTH_THROUGHPUT_URL",
    "SUBSCRIPTION_PORT",
    "SUBSCRIPTION_TOKEN",
    "SSH_INPUT_RATE",
    "SSH_INPUT_BURST",
    "RU_HTTPS_INPUT_RATE",
    "RU_HTTPS_INPUT_BURST",
    "RU_DIRECT_DNS_SERVER",
    "RU_DIRECT_DNS_PORT",
    "GUARD_ENABLED",
    "GUARD_INTERVAL_MINUTES",
    "GUARD_LOOKBACK_MINUTES",
    "GUARD_BLOCK_TIMEOUT",
    "GUARD_SSH_FAILURE_THRESHOLD",
    "GUARD_REALITY_INVALID_THRESHOLD",
    "GUARD_REALITY_BLOCK_ENABLED",
    "DISABLE_NIC_OFFLOADS",
    "RUNTIME_QDISC",
    "WG_KEEPALIVE",
    "HEALTHCHECK_URL",
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
    "HEALTH_CHECK_INTERVAL_MINUTES",
    "RU_BLOCK_QUIC",
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
    "WAN_INTERFACE",
    "JOURNAL_LIMIT_ENABLED",
    "JOURNAL_SYSTEM_MAX_USE",
    "JOURNAL_MAX_RETENTION_SEC",
    "WG_MTU",
    "INTERSERVER_HY2_CERTIFICATE_B64",
    "INTERSERVER_HY2_PRIVATE_KEY_B64",
    "INTERSERVER_HY2_PUBLIC_KEY_SHA256",
    "RU_FORCE_DIRECT_DOMAIN",
    "RU_FORCE_DIRECT_DOMAIN_SUFFIX",
    "RU_FORCE_DIRECT_IP_CIDR",
    "RU_BLOCK_IP_CIDR",
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

RETIRED_DIRECT_POLICY_VALUES = {
    "RU_FORCE_DIRECT_DOMAIN": frozenset(
        {
            "mtalk.google.com",
            "ifconfig.me",
            "ifconfig.co",
            "checkip.amazonaws.com",
            "ipapi.co",
            "ipinfo.io",
            "ident.me",
            "tnedi.me",
            "icanhazip.com",
        }
    ),
    "RU_FORCE_DIRECT_DOMAIN_SUFFIX": frozenset(
        {".gstatic.com", ".ipify.org", ".ipinfo.io", ".ident.me", ".tnedi.me", ".icanhazip.com"}
    ),
}

TRANSPORT_IDENTITY_KEYS = (
    "INTERSERVER_HY2_CERTIFICATE_B64",
    "INTERSERVER_HY2_PRIVATE_KEY_B64",
    "INTERSERVER_HY2_PUBLIC_KEY_SHA256",
)

PUBLIC_TRANSPORT_IDENTITY_KEYS = (
    "PUBLIC_HY2_CERTIFICATE_B64",
    "PUBLIC_HY2_PRIVATE_KEY_B64",
    "PUBLIC_HY2_PUBLIC_KEY_SHA256",
)

DUAL_REQUIRED_ENV_VARS = (
    "EXIT_PUBLIC_IP",
    "WG_RU_ADDRESS",
    "WG_FOREIGN_ADDRESS",
    "WG_RU_ADDRESS_V6",
    "WG_FOREIGN_ADDRESS_V6",
    "WG_IPV6_PREFIX",
    "WG_RU_PRIVATE_KEY",
    "WG_RU_PUBLIC_KEY",
    "WG_FOREIGN_PRIVATE_KEY",
    "WG_FOREIGN_PUBLIC_KEY",
    "WG_PRESHARED_KEY",
    *TRANSPORT_IDENTITY_KEYS,
)

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
    normalized = env.copy()
    normalized.update(TopologySpec.from_env(normalized, require_addresses=False).canonical_env_values())
    lines: list[str] = []
    seen_keys: set[str] = set()
    for comment, keys in ENV_SECTIONS:
        if comment:
            if lines:
                lines.append("")
            lines.append(comment)
        for key in keys:
            if key in DEPRECATED_ENV_KEYS:
                continue
            lines.append(env_line(key, normalized.get(key, "")))
            seen_keys.add(key)
    extra_keys = sorted(
        key
        for key in normalized
        if key not in seen_keys and key not in DEPRECATED_ENV_KEYS
    )
    if extra_keys:
        lines.extend(["", "# Extra values"])
        for key in extra_keys:
            lines.append(env_line(key, normalized[key]))
    return "\n".join(lines) + "\n"


def generate_default_env(
    deploy_name: str,
    *,
    transport_identity: dict[str, str] | None = None,
    public_transport_identity: dict[str, str] | None = None,
    topology: str = TOPOLOGY_DUAL,
    gateway_location: str = LOCATION_RU,
) -> dict[str, str]:
    reality_private, reality_public = generate_x25519_pair()
    dual = topology == TOPOLOGY_DUAL
    ru_wg_private, ru_wg_public = generate_x25519_pair() if dual else (b"", b"")
    foreign_wg_private, foreign_wg_public = generate_x25519_pair() if dual else (b"", b"")
    if transport_identity is not None and not all(transport_identity.get(key, "").strip() for key in TRANSPORT_IDENTITY_KEYS):
        raise ValueError("transport identity must be complete")
    if public_transport_identity is not None and not all(public_transport_identity.get(key, "").strip() for key in PUBLIC_TRANSPORT_IDENTITY_KEYS):
        raise ValueError("public transport identity must be complete")
    transport_identity = transport_identity or (generate_transport_identity() if dual else {key: "" for key in TRANSPORT_IDENTITY_KEYS})
    if public_transport_identity is None:
        generated_public_identity = generate_transport_identity()
        public_transport_identity = {
            public_key: generated_public_identity[interserver_key]
            for public_key, interserver_key in zip(PUBLIC_TRANSPORT_IDENTITY_KEYS, TRANSPORT_IDENTITY_KEYS)
        }
    return {
        "CONFIG_SCHEMA": str(CONFIG_SCHEMA_VERSION),
        "DEPLOY_NAME": deploy_name,
        "TOPOLOGY": topology,
        "GATEWAY_LOCATION": gateway_location,
        "GATEWAY_PUBLIC_IP": "",
        "EXIT_PUBLIC_IP": "",
        "SSH_PORT": "22",
        "SSH_LOGIN_GRACE_TIME": "20",
        "SSH_MAX_AUTH_TRIES": "3",
        "SSH_MAX_STARTUPS": "10:30:60",
        "SSH_PER_SOURCE_MAX_STARTUPS": "6",
        "SSH_PER_SOURCE_NETBLOCK_SIZE": "24:64",
        "WAN_INTERFACE": "",
        "CLIENT_UUID": str(uuid.uuid4()),
        "CLIENT_FLOW": "xtls-rprx-vision",
        "RU_LISTEN_PORT": "443",
        "RU_ROUTER_LISTEN_PORT": "2080",
        "RU_REALITY_SERVER_NAME": "www.bing.com",
        "RU_REALITY_PRIVATE_KEY": base64_url_nopad(reality_private),
        "RU_REALITY_PUBLIC_KEY": base64_url_nopad(reality_public),
        "RU_REALITY_SHORT_ID": "0123456789abcdef",
        "RU_REALITY_ACCEPT_EMPTY_SHORT_ID": "1",
        "RU_REALITY_MAX_TIME_DIFFERENCE": "24h",
        "UTLS_FINGERPRINT": "chrome",
        "SING_BOX_LOG_LEVEL": "info",
        "RU_SNIFF_TIMEOUT": "250ms",
        "WG_INTERFACE": "wg0",
        "WG_PORT": "51820",
        "WG_MTU": "1360",
        "WG_ROUTE_TABLE": "51820",
        "APP_ROUTE_MARK": "48",
        "WG_TUNNEL_FWMARK": "51820",
        "WG_RU_ADDRESS": "10.74.0.1/32",
        "WG_FOREIGN_ADDRESS": "10.74.0.2/32",
        "WG_RU_ADDRESS_V6": "fd74:7670:6e73::1/128",
        "WG_FOREIGN_ADDRESS_V6": "fd74:7670:6e73::2/128",
        "WG_IPV6_PREFIX": "fd74:7670:6e73::/64",
        "WG_RU_PRIVATE_KEY": base64_std(ru_wg_private) if dual else "",
        "WG_RU_PUBLIC_KEY": base64_std(ru_wg_public) if dual else "",
        "WG_FOREIGN_PRIVATE_KEY": base64_std(foreign_wg_private) if dual else "",
        "WG_FOREIGN_PUBLIC_KEY": base64_std(foreign_wg_public) if dual else "",
        "WG_PRESHARED_KEY": base64_std(os.urandom(32)) if dual else "",
        **public_transport_identity,
        **transport_identity,
        "GLOBAL_DOH_SERVER": "8.8.8.8",
        "GLOBAL_DOH_SERVER_NAME": "dns.google",
        "GLOBAL_DOH_PATH": "/dns-query",
        "RU_FORCE_DIRECT_DOMAIN": "api.oneme.ru,calls.okcdn.ru,gosuslugi.ru,api.ok.ru,ip.mail.ru,ipv4-internet.yandex.net,2ip.ru",
        "RU_FORCE_DIRECT_DOMAIN_SUFFIX": ".gosuslugi.ru",
        "RU_FORCE_DIRECT_IP_CIDR": "",
        "RU_BLOCK_IP_CIDR": "",
        "RULESET_DIR": "/var/lib/vpn-stack/rules",
        "RU_GEOSITE_URL": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ru.srs https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-ru.srs",
        "RU_GEOIP_URL": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-ru.srs https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-ru.srs",
        "FOREIGN_BLOCK_RU": "0",
        "FOREIGN_RU_IPV4_LIST_URL": "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone https://stat.ripe.net/data/country-resource-list/data.json?resource=ru&v4_format=prefix",
        "FOREIGN_RU_IPV6_LIST_URL": "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone https://stat.ripe.net/data/country-resource-list/data.json?resource=ru",
        "JOURNAL_LIMIT_ENABLED": "1",
        "JOURNAL_SYSTEM_MAX_USE": "256M",
        "JOURNAL_MAX_RETENTION_SEC": "14day",
        "ADMIN_WEB_ENABLED": "1",
        "ADMIN_WEB_PORT": "11333",
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


def _normalize_policy_csv(key: str, value: str) -> str:
    retired = RETIRED_DIRECT_POLICY_VALUES.get(key, frozenset())
    return ",".join(item for item in _split_csv_values(value) if item.lower() not in retired)


def _merge_source_defaults(existing_value: str, default_value: str) -> str:
    merged: list[str] = []
    seen: set[str] = set()
    for item in split_asset_sources(existing_value) + split_asset_sources(default_value):
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    return " ".join(merged)


def merge_env_with_defaults(
    existing: dict[str, str],
    deploy_name: str,
    *,
    fallback_defaults: dict[str, str] | None = None,
) -> dict[str, str]:
    topology_mode = existing.get("TOPOLOGY", "").strip() or (fallback_defaults or {}).get("TOPOLOGY", "").strip() or TOPOLOGY_DUAL
    gateway_location = existing.get("GATEWAY_LOCATION", "").strip() or (fallback_defaults or {}).get("GATEWAY_LOCATION", "").strip() or LOCATION_RU
    existing_transport_identity = (
        {key: existing[key] for key in TRANSPORT_IDENTITY_KEYS}
        if all(existing.get(key, "").strip() for key in TRANSPORT_IDENTITY_KEYS)
        else None
    )
    fallback_transport_identity = (
        {key: fallback_defaults[key] for key in TRANSPORT_IDENTITY_KEYS}
        if fallback_defaults and all(fallback_defaults.get(key, "").strip() for key in TRANSPORT_IDENTITY_KEYS)
        else None
    )
    existing_public_identity = (
        {key: existing[key] for key in PUBLIC_TRANSPORT_IDENTITY_KEYS}
        if all(existing.get(key, "").strip() for key in PUBLIC_TRANSPORT_IDENTITY_KEYS)
        else None
    )
    fallback_public_identity = (
        {key: fallback_defaults[key] for key in PUBLIC_TRANSPORT_IDENTITY_KEYS}
        if fallback_defaults and all(fallback_defaults.get(key, "").strip() for key in PUBLIC_TRANSPORT_IDENTITY_KEYS)
        else None
    )
    if existing_public_identity is None and existing_transport_identity is not None:
        # One release migration boundary: old deployments used the same TLS
        # identity for public and interserver Hysteria2. Persisting explicit
        # public keys keeps existing client artifacts stable while allowing the
        # two identities to rotate independently afterwards.
        existing_public_identity = {
            public_key: existing_transport_identity[interserver_key]
            for public_key, interserver_key in zip(PUBLIC_TRANSPORT_IDENTITY_KEYS, TRANSPORT_IDENTITY_KEYS)
        }
    defaults = generate_default_env(
        deploy_name,
        transport_identity=existing_transport_identity or fallback_transport_identity,
        public_transport_identity=existing_public_identity or fallback_public_identity,
        topology=topology_mode,
        gateway_location=gateway_location,
    )
    if fallback_defaults:
        defaults.update(
            {
                key: value
                for key, value in fallback_defaults.items()
                if key in defaults and key not in (*TRANSPORT_IDENTITY_KEYS, *PUBLIC_TRANSPORT_IDENTITY_KEYS)
            }
        )
    merged = defaults.copy()
    for key, value in existing.items():
        if key in DEPRECATED_ENV_KEYS:
            continue
        if key in TRANSPORT_IDENTITY_KEYS and existing_transport_identity is None:
            continue
        if key in PUBLIC_TRANSPORT_IDENTITY_KEYS and existing_public_identity is None:
            continue
        if value or key in ALLOW_EMPTY_OVERRIDE:
            merged[key] = value
    for key in MERGED_CSV_DEFAULT_KEYS:
        if existing.get(key):
            merged[key] = _merge_csv_defaults(existing[key], defaults[key])
        merged[key] = _normalize_policy_csv(key, merged[key])
    for key in MERGED_SOURCE_DEFAULT_KEYS:
        if existing.get(key):
            merged[key] = _merge_source_defaults(existing[key], defaults[key])
    merged["DEPLOY_NAME"] = deploy_name
    merged["GATEWAY_PUBLIC_IP"] = (
        existing.get("GATEWAY_PUBLIC_IP", "").strip()
        or merged.get("GATEWAY_PUBLIC_IP", "").strip()
        or (fallback_defaults or {}).get("GATEWAY_PUBLIC_IP", "").strip()
    )
    if topology_mode == TOPOLOGY_DUAL:
        merged["EXIT_PUBLIC_IP"] = (
            existing.get("EXIT_PUBLIC_IP", "").strip()
            or merged.get("EXIT_PUBLIC_IP", "").strip()
            or (fallback_defaults or {}).get("EXIT_PUBLIC_IP", "").strip()
        )
    else:
        merged["EXIT_PUBLIC_IP"] = ""
        for key in DUAL_REQUIRED_ENV_VARS:
            merged[key] = ""
    merged["CONFIG_SCHEMA"] = str(CONFIG_SCHEMA_VERSION)
    merged["TOPOLOGY"] = topology_mode
    merged["GATEWAY_LOCATION"] = gateway_location
    return merged


def merge_node_env_with_defaults(existing: dict[str, str], deploy_name: str) -> dict[str, str]:
    """Validate a projected node env without inventing values on the target."""

    node_id = normalize_node_id(existing.get("NODE_ID", ""))
    topology = TopologySpec.from_env(existing)
    node = topology.node(node_id)
    if existing.get("DEPLOY_NAME", "").strip() != deploy_name:
        raise ValueError("node env deployment name does not match its canonical descriptor")
    if existing.get("NODE_LOCATION", "").strip() != node.location:
        raise ValueError("node env location does not match canonical topology")
    if existing.get("NODE_PUBLIC_IP", "").strip() != node.public_ip:
        raise ValueError("node env public IP does not match canonical topology")

    # Import locally to keep the configuration/model dependency one-way.
    from .manifest import project_node_env

    projected = project_node_env(existing, topology.plan(node_id))
    if projected != existing:
        unexpected = sorted(set(existing) - set(projected))
        missing = sorted(set(projected) - set(existing))
        changed = sorted(
            key
            for key in set(existing) & set(projected)
            if existing[key] != projected[key]
        )
        raise ValueError(
            "node env is not a canonical capability projection "
            f"(unexpected={unexpected}, missing={missing}, changed={changed})"
        )
    return projected


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
        effective[env_key] = _normalize_policy_csv(
            env_key,
            _merge_csv_defaults(effective.get(env_key, ""), ",".join(overlay_items)),
        )
    return effective


def critical_env_view(env: dict[str, str]) -> dict[str, str]:
    relevant_keys = set(REMOTE_ENV_CRITICAL_KEYS)
    relevant_keys.update(key for key in env if key.startswith("WG_"))
    return {key: env.get(key, "") for key in sorted(relevant_keys)}


def generate_example_env() -> dict[str, str]:
    env = generate_default_env("my-stack")
    env.update(
        {
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "EXIT_PUBLIC_IP": "198.51.100.20",
            "CLIENT_UUID": "00000000-0000-0000-0000-000000000000",
            "RU_REALITY_PRIVATE_KEY": "",
            "RU_REALITY_PUBLIC_KEY": "",
            "WG_RU_PRIVATE_KEY": "",
            "WG_RU_PUBLIC_KEY": "",
            "WG_FOREIGN_PRIVATE_KEY": "",
            "WG_FOREIGN_PUBLIC_KEY": "",
            "WG_PRESHARED_KEY": "",
            "PUBLIC_HY2_CERTIFICATE_B64": "",
            "PUBLIC_HY2_PRIVATE_KEY_B64": "",
            "PUBLIC_HY2_PUBLIC_KEY_SHA256": "",
            "INTERSERVER_HY2_CERTIFICATE_B64": "",
            "INTERSERVER_HY2_PRIVATE_KEY_B64": "",
            "INTERSERVER_HY2_PUBLIC_KEY_SHA256": "",
        }
    )
    return env


def render_example_env_text() -> str:
    return render_env_text(generate_example_env())


def ensure_deployment_env(
    env_path: Path,
    deployment_name: str,
    *,
    topology: str | None = None,
    gateway_location: str | None = None,
) -> dict[str, str]:
    if env_path.exists():
        source = migrate_env(load_env_file(env_path)).env
        if topology is not None:
            source["TOPOLOGY"] = topology
        if gateway_location is not None:
            source["GATEWAY_LOCATION"] = gateway_location
        env = merge_env_with_defaults(source, deployment_name)
    else:
        env = generate_default_env(
            deployment_name,
            topology=topology or TOPOLOGY_DUAL,
            gateway_location=gateway_location or LOCATION_RU,
        )
    return env


def load_existing_deployment_env(deployment_name: str) -> tuple[Path, dict[str, str]]:
    env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
    if not env_path.exists():
        fail(f"Не найден deployment env: {env_path}")
    return env_path, merge_env_with_defaults(migrate_env(load_env_file(env_path)).env, deployment_name)


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
    if not path.is_absolute() and len(path.parts) == 1:
        path = Path.home() / ".ssh" / path
    elif not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
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
    topology = TopologySpec.from_env(env, require_addresses=False)
    env.update(topology.canonical_env_values())
    required_names = list(required) if required is not None else [
        *REQUIRED_ENV_VARS,
        *(DUAL_REQUIRED_ENV_VARS if topology.is_dual else ()),
    ]
    missing = [name for name in required_names if not env.get(name, "").strip()]
    if missing:
        fail(f"В deployment env не хватает обязательных значений: {', '.join(missing)}")
    if all(env.get(name, "").strip() for name in PUBLIC_TRANSPORT_IDENTITY_KEYS):
        public_identity = {
            interserver_key: env[public_key]
            for public_key, interserver_key in zip(PUBLIC_TRANSPORT_IDENTITY_KEYS, TRANSPORT_IDENTITY_KEYS)
        }
        try:
            validate_transport_identity(public_identity)
        except ValueError as exc:
            fail(f"Некорректная identity публичного Hysteria2: {exc}")
    if topology.is_dual and all(env.get(name, "").strip() for name in TRANSPORT_IDENTITY_KEYS):
        try:
            validate_transport_identity(env)
        except ValueError as exc:
            fail(f"Некорректная identity межсерверного транспорта: {exc}")


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
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_ASSET_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except http.client.IncompleteRead as exc:
        raise RuntimeError(f"incomplete download for {asset_name}: {exc}") from exc
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
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_ASSET_TIMEOUT) as response:
            tmp_path.write_bytes(response.read())
    except http.client.IncompleteRead as exc:
        raise RuntimeError(f"incomplete download: {exc}") from exc
    tmp_path.replace(destination)
