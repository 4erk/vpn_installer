from __future__ import annotations

import ipaddress
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


def validate_deployment_name(raw_name: str) -> str:
    cleaned = sanitize_name(raw_name)
    if not cleaned:
        fail("Имя deployment пустое или состоит только из недопустимых символов.")
    return cleaned


def load_env_file(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        env[key.strip()] = parse_env_value(raw_value)
    return env


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
        "WAN_INTERFACE": "",
        "CLIENT_UUID": str(uuid.uuid4()),
        "CLIENT_FLOW": "xtls-rprx-vision",
        "RU_LISTEN_PORT": "443",
        "RU_REALITY_SERVER_NAME": "www.cloudflare.com",
        "RU_REALITY_HANDSHAKE_SERVER": "www.cloudflare.com",
        "RU_REALITY_HANDSHAKE_PORT": "443",
        "RU_REALITY_PRIVATE_KEY": base64_url_nopad(reality_private),
        "RU_REALITY_PUBLIC_KEY": base64_url_nopad(reality_public),
        "RU_REALITY_SHORT_ID": "0123456789abcdef",
        "UTLS_FINGERPRINT": "chrome",
        "WG_INTERFACE": "wg0",
        "WG_PORT": "51820",
        "WG_MTU": "1380",
        "WG_KEEPALIVE": "25",
        "WG_ROUTE_TABLE": "51820",
        "APP_ROUTE_MARK": "48",
        "WG_TUNNEL_FWMARK": "51820",
        "WG_RU_ADDRESS": "10.74.0.1/32",
        "WG_FOREIGN_ADDRESS": "10.74.0.2/32",
        "WG_RU_PRIVATE_KEY": base64_std(ru_wg_private),
        "WG_RU_PUBLIC_KEY": base64_std(ru_wg_public),
        "WG_FOREIGN_PRIVATE_KEY": base64_std(foreign_wg_private),
        "WG_FOREIGN_PUBLIC_KEY": base64_std(foreign_wg_public),
        "WG_PRESHARED_KEY": base64_std(os.urandom(32)),
        "RU_DIRECT_DNS_SERVER": "77.88.8.8",
        "RU_DIRECT_DNS_PORT": "53",
        "GLOBAL_DOH_SERVER": "1.1.1.1",
        "GLOBAL_DOH_SERVER_NAME": "cloudflare-dns.com",
        "GLOBAL_DOH_PATH": "/dns-query",
        "RULESET_DIR": "/var/lib/vpn-stack/rules",
        "RU_GEOSITE_URL": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs",
        "RU_GEOIP_URL": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
        "FOREIGN_BLOCK_RU": "1",
        "FOREIGN_RU_IPV4_LIST_URL": "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone",
        "FOREIGN_RU_IPV6_LIST_URL": "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone",
        "CLIENT_TUN_NAME": "tun0",
        "CLIENT_TUN_ADDRESS_V4": "172.19.0.1/30",
        "CLIENT_TUN_ADDRESS_V6": "fdfe:dcba:9876::1/126",
        "CLIENT_FAKEIP_V4": "198.18.0.0/15",
        "CLIENT_FAKEIP_V6": "fc00::/18",
        "CLIENT_ROUTE_EXCLUDE_V4": "",
        "CLIENT_ROUTE_EXCLUDE_V6": "",
    }


def base64_std(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def base64_url_nopad(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def merge_env_with_defaults(existing: dict[str, str], deploy_name: str) -> dict[str, str]:
    merged = generate_default_env(deploy_name)
    for key, value in existing.items():
        if value or key in ALLOW_EMPTY_OVERRIDE:
            merged[key] = value
    merged["DEPLOY_NAME"] = deploy_name
    return merged


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


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "vpn-installer/1.0"})
    tmp_path = destination.with_suffix(destination.suffix + ".tmp")
    with urllib.request.urlopen(request, timeout=DEFAULT_ASSET_TIMEOUT) as response:
        tmp_path.write_bytes(response.read())
    tmp_path.replace(destination)
