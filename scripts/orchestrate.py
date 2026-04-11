#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import base64
import getpass
import importlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import textwrap
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if sys.version_info < (3, 9):
    print("Требуется Python 3.9 или новее.", file=sys.stderr)
    sys.exit(1)

ROOT_DIR = Path(__file__).resolve().parents[1]
DEPLOYMENTS_DIR = ROOT_DIR / "deployments"
STATE_DIR = ROOT_DIR / "state"
OUT_DIR = ROOT_DIR / "out"
RUNTIME_DIR = ROOT_DIR / ".runtime"
INSTALL_SCRIPT_PATH = ROOT_DIR / "install.sh"
RUNTIME_SITE_PACKAGES = RUNTIME_DIR / "python-packages"

if str(RUNTIME_SITE_PACKAGES) not in sys.path:
    sys.path.insert(0, str(RUNTIME_SITE_PACKAGES))

ROLE_RU = "ru-gateway"
ROLE_FOREIGN = "foreign-exit"
ROLE_META = {
    ROLE_RU: {"label": "RU gateway", "prefix": "RU", "public_ip_key": "RU_PUBLIC_IP"},
    ROLE_FOREIGN: {"label": "Foreign exit", "prefix": "FOREIGN", "public_ip_key": "FOREIGN_PUBLIC_IP"},
}
ALLOW_EMPTY_OVERRIDE = {
    "RU_PUBLIC_IP",
    "FOREIGN_PUBLIC_IP",
    "WAN_INTERFACE",
    "CLIENT_ROUTE_EXCLUDE_V4",
    "CLIENT_ROUTE_EXCLUDE_V6",
}
ENV_SECTIONS = [
    ("", ["DEPLOY_NAME"]),
    ("# Public addresses", ["RU_PUBLIC_IP", "FOREIGN_PUBLIC_IP"]),
    ("# SSH hardening and firewall", ["SSH_PORT"]),
    ("# Foreign egress NIC override. Leave empty to auto-detect on the foreign host.", ["WAN_INTERFACE"]),
    ("# sing-box / VLESS + REALITY", ["CLIENT_UUID", "CLIENT_FLOW", "RU_LISTEN_PORT", "RU_REALITY_SERVER_NAME", "RU_REALITY_HANDSHAKE_SERVER", "RU_REALITY_HANDSHAKE_PORT", "RU_REALITY_PRIVATE_KEY", "RU_REALITY_PUBLIC_KEY", "RU_REALITY_SHORT_ID", "UTLS_FINGERPRINT"]),
    ("# WireGuard between RU and foreign", ["WG_INTERFACE", "WG_PORT", "WG_MTU", "WG_KEEPALIVE", "WG_ROUTE_TABLE", "APP_ROUTE_MARK", "WG_TUNNEL_FWMARK", "WG_RU_ADDRESS", "WG_FOREIGN_ADDRESS", "WG_RU_PRIVATE_KEY", "WG_RU_PUBLIC_KEY", "WG_FOREIGN_PRIVATE_KEY", "WG_FOREIGN_PUBLIC_KEY", "WG_PRESHARED_KEY"]),
    ("# RU DNS policy", ["RU_DIRECT_DNS_SERVER", "RU_DIRECT_DNS_PORT", "GLOBAL_DOH_SERVER", "GLOBAL_DOH_SERVER_NAME", "GLOBAL_DOH_PATH"]),
    ("# Rule assets for the RU server", ["RULESET_DIR", "RU_GEOSITE_URL", "RU_GEOIP_URL"]),
    ("# Optional RU egress deny list on the foreign server", ["FOREIGN_BLOCK_RU", "FOREIGN_RU_IPV4_LIST_URL", "FOREIGN_RU_IPV6_LIST_URL"]),
    ("# Client tun profile", ["CLIENT_TUN_NAME", "CLIENT_TUN_ADDRESS_V4", "CLIENT_TUN_ADDRESS_V6", "CLIENT_FAKEIP_V4", "CLIENT_FAKEIP_V6"]),
    ("# Optional extra route exclusions on the client profile", ["CLIENT_ROUTE_EXCLUDE_V4", "CLIENT_ROUTE_EXCLUDE_V6"]),
]
REQUIRED_ENV_VARS = [
    "DEPLOY_NAME", "RU_PUBLIC_IP", "FOREIGN_PUBLIC_IP", "CLIENT_UUID",
    "RU_REALITY_SERVER_NAME", "RU_REALITY_HANDSHAKE_SERVER",
    "RU_REALITY_PRIVATE_KEY", "RU_REALITY_PUBLIC_KEY", "RU_REALITY_SHORT_ID",
    "WG_RU_ADDRESS", "WG_FOREIGN_ADDRESS", "WG_RU_PRIVATE_KEY", "WG_RU_PUBLIC_KEY",
    "WG_FOREIGN_PRIVATE_KEY", "WG_FOREIGN_PUBLIC_KEY", "WG_PRESHARED_KEY",
]
DEFAULT_ASSET_TIMEOUT = 30
X25519_P = 2**255 - 19
X25519_A24 = 121665


class AppError(RuntimeError):
    pass


@dataclass
class RemoteTarget:
    role: str
    public_ip: str = ""
    ssh_host: str = ""
    ssh_port: int = 22
    ssh_user: str = "root"
    auth_mode: str = "key"
    identity_path: str = ""
    ssh_password: str = ""
    sudo_mode: str = "unknown"
    sudo_password: str = ""
    saved_connection: bool = False

    @property
    def label(self) -> str:
        return ROLE_META[self.role]["label"]

    def to_state(self) -> dict[str, str]:
        return {
            "public_ip": self.public_ip,
            "ssh_host": self.ssh_host,
            "ssh_port": str(self.ssh_port),
            "ssh_user": self.ssh_user,
            "auth_mode": self.auth_mode,
            "identity_path": self.identity_path,
        }


def print_header(title: str) -> None:
    print(f"\n== {title} ==")


def warn(message: str) -> None:
    print(f"Предупреждение: {message}", file=sys.stderr)


def fail(message: str) -> None:
    raise AppError(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sanitize_name(raw_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", raw_name).strip("-")


def validate_deployment_name(raw_name: str) -> str:
    cleaned = sanitize_name(raw_name)
    if not cleaned:
        fail("Имя deployment пустое или состоит только из недопустимых символов.")
    return cleaned


def ensure_directories() -> None:
    for path in (DEPLOYMENTS_DIR, STATE_DIR, OUT_DIR, RUNTIME_DIR):
        path.mkdir(parents=True, exist_ok=True)


def ensure_file_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    ensure_file_parent(path)
    path.write_text(content, encoding="utf-8", newline="\n")


def write_json(path: Path, payload: Any) -> None:
    write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def shell_env_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def env_line(key: str, value: str) -> str:
    return f"{key}={shell_env_quote(value)}"


def parse_env_value(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw[0] in ('"', "'"):
        try:
            return str(ast.literal_eval(raw))
        except (SyntaxError, ValueError) as exc:
            raise AppError(f"Не удалось разобрать значение env: {raw}") from exc
    return raw


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


def base64_std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64_url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


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
        "DEPLOY_NAME": deploy_name, "RU_PUBLIC_IP": "", "FOREIGN_PUBLIC_IP": "", "SSH_PORT": "22", "WAN_INTERFACE": "",
        "CLIENT_UUID": str(uuid.uuid4()), "CLIENT_FLOW": "xtls-rprx-vision", "RU_LISTEN_PORT": "443",
        "RU_REALITY_SERVER_NAME": "www.cloudflare.com", "RU_REALITY_HANDSHAKE_SERVER": "www.cloudflare.com",
        "RU_REALITY_HANDSHAKE_PORT": "443", "RU_REALITY_PRIVATE_KEY": base64_url_nopad(reality_private),
        "RU_REALITY_PUBLIC_KEY": base64_url_nopad(reality_public), "RU_REALITY_SHORT_ID": os.urandom(8).hex(),
        "UTLS_FINGERPRINT": "chrome", "WG_INTERFACE": "wg0", "WG_PORT": "51820", "WG_MTU": "1380",
        "WG_KEEPALIVE": "25", "WG_ROUTE_TABLE": "51820", "APP_ROUTE_MARK": "48", "WG_TUNNEL_FWMARK": "51820",
        "WG_RU_ADDRESS": "10.74.0.1/32", "WG_FOREIGN_ADDRESS": "10.74.0.2/32",
        "WG_RU_PRIVATE_KEY": base64_std(ru_wg_private), "WG_RU_PUBLIC_KEY": base64_std(ru_wg_public),
        "WG_FOREIGN_PRIVATE_KEY": base64_std(foreign_wg_private), "WG_FOREIGN_PUBLIC_KEY": base64_std(foreign_wg_public),
        "WG_PRESHARED_KEY": base64_std(os.urandom(32)), "RU_DIRECT_DNS_SERVER": "77.88.8.8", "RU_DIRECT_DNS_PORT": "53",
        "GLOBAL_DOH_SERVER": "1.1.1.1", "GLOBAL_DOH_SERVER_NAME": "cloudflare-dns.com", "GLOBAL_DOH_PATH": "/dns-query",
        "RULESET_DIR": "/var/lib/vpn-stack/rules",
        "RU_GEOSITE_URL": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs",
        "RU_GEOIP_URL": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
        "FOREIGN_BLOCK_RU": "1",
        "FOREIGN_RU_IPV4_LIST_URL": "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone",
        "FOREIGN_RU_IPV6_LIST_URL": "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone",
        "CLIENT_TUN_NAME": "tun0", "CLIENT_TUN_ADDRESS_V4": "172.19.0.1/30",
        "CLIENT_TUN_ADDRESS_V6": "fdfe:dcba:9876::1/126", "CLIENT_FAKEIP_V4": "198.18.0.0/15",
        "CLIENT_FAKEIP_V6": "fc00::/18", "CLIENT_ROUTE_EXCLUDE_V4": "", "CLIENT_ROUTE_EXCLUDE_V6": "",
    }


def merge_env_with_defaults(existing: dict[str, str], deploy_name: str) -> dict[str, str]:
    merged = generate_default_env(deploy_name)
    merged["DEPLOY_NAME"] = deploy_name
    for key, value in existing.items():
        if key == "DEPLOY_NAME":
            continue
        if key in ALLOW_EMPTY_OVERRIDE or value != "":
            merged[key] = value
    return merged


def ensure_deployment_env(env_path: Path, deployment_name: str) -> dict[str, str]:
    env = merge_env_with_defaults(load_env_file(env_path), deployment_name) if env_path.exists() else generate_default_env(deployment_name)
    write_text(env_path, render_env_text(env))
    return env


def load_existing_deployment_env(deployment_name: str) -> tuple[Path, dict[str, str]]:
    env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
    if not env_path.exists():
        fail(f"Не найден deployment env: {env_path}")
    return env_path, merge_env_with_defaults(load_env_file(env_path), deployment_name)


def state_json_path(deployment_name: str) -> Path:
    return STATE_DIR / f"{deployment_name}.json"


def state_legacy_path(deployment_name: str) -> Path:
    return STATE_DIR / f"{deployment_name}.env"


def load_state(deployment_name: str) -> dict[str, Any]:
    json_path = state_json_path(deployment_name)
    if json_path.exists():
        return json.loads(read_text(json_path))
    legacy_path = state_legacy_path(deployment_name)
    if not legacy_path.exists():
        return {}
    legacy = load_env_file(legacy_path)
    return {
        ROLE_RU: {"public_ip": legacy.get("RU_PUBLIC_IP", ""), "ssh_host": legacy.get("RU_SSH_HOST", ""), "ssh_port": legacy.get("RU_SSH_PORT", "22"), "ssh_user": legacy.get("RU_SSH_USER", "root"), "auth_mode": "key", "identity_path": legacy.get("RU_IDENTITY_PATH", "")},
        ROLE_FOREIGN: {"public_ip": legacy.get("FOREIGN_PUBLIC_IP", ""), "ssh_host": legacy.get("FOREIGN_SSH_HOST", ""), "ssh_port": legacy.get("FOREIGN_SSH_PORT", "22"), "ssh_user": legacy.get("FOREIGN_SSH_USER", "root"), "auth_mode": "key", "identity_path": legacy.get("FOREIGN_IDENTITY_PATH", "")},
    }


def write_state(deployment_name: str, targets: list[RemoteTarget], existing_state: dict[str, Any] | None = None) -> None:
    payload = {"updated_at": utc_now(), ROLE_RU: {}, ROLE_FOREIGN: {}}
    if existing_state:
        for role in (ROLE_RU, ROLE_FOREIGN):
            role_state = existing_state.get(role, {})
            if isinstance(role_state, dict):
                payload[role] = {
                    "public_ip": str(role_state.get("public_ip", "")),
                    "ssh_host": str(role_state.get("ssh_host", "")),
                    "ssh_port": str(role_state.get("ssh_port", "")),
                    "ssh_user": str(role_state.get("ssh_user", "")),
                    "auth_mode": str(role_state.get("auth_mode", "key") or "key"),
                    "identity_path": str(role_state.get("identity_path", "")),
                }
    for target in targets:
        payload[target.role] = target.to_state()
    write_json(state_json_path(deployment_name), payload)


def build_target(role: str, env: dict[str, str], state: dict[str, Any]) -> RemoteTarget:
    role_state = state.get(role, {})
    saved_connection = has_saved_connection(role_state)
    public_ip_key = ROLE_META[role]["public_ip_key"]
    ssh_port_raw = str((role_state.get("ssh_port") if saved_connection else None) or env.get("SSH_PORT", "22") or "22")
    try:
        ssh_port = int(ssh_port_raw)
    except ValueError as exc:
        raise AppError(f"Некорректный SSH port для {ROLE_META[role]['label']}: {ssh_port_raw}") from exc
    public_ip = str((role_state.get("public_ip") if saved_connection else None) or env.get(public_ip_key, ""))
    return RemoteTarget(
        role=role,
        public_ip=public_ip,
        ssh_host=str((role_state.get("ssh_host") if saved_connection else None) or public_ip),
        ssh_port=ssh_port,
        ssh_user=str((role_state.get("ssh_user") if saved_connection else None) or "root"),
        auth_mode=str((role_state.get("auth_mode") if saved_connection else None) or "key"),
        identity_path=str((role_state.get("identity_path") if saved_connection else None) or ""),
        saved_connection=saved_connection,
    )


def prompt_value(label: str, default: str | None = None, allow_empty: bool = False) -> str:
    while True:
        suffix = f" (Enter = {default})" if default not in (None, "") else ""
        value = input(f"{label}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        if allow_empty:
            return ""


def prompt_validated_value(
    label: str,
    *,
    default: str | None = None,
    allow_empty: bool = False,
    validator: Any | None = None,
) -> str:
    while True:
        value = prompt_value(label, default=default, allow_empty=allow_empty)
        if not value and allow_empty:
            return value
        if validator is None:
            return value
        try:
            return validator(value)
        except AppError as exc:
            warn(str(exc))


def prompt_secret(label: str) -> str:
    return getpass.getpass(f"{label}: ")


def prompt_yes_no(label: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{label} [{suffix}]: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes", "д", "да"}:
            return True
        if answer in {"n", "no", "н", "нет"}:
            return False


def prompt_choice(label: str, options: list[tuple[str, str]], default: str) -> str:
    if default not in {value for value, _ in options}:
        raise AppError(f"Некорректный default для prompt_choice: {default}")
    print(label)
    default_index = 1
    option_map: dict[str, str] = {}
    for index, (value, description) in enumerate(options, start=1):
        if value == default:
            default_index = index
        option_map[str(index)] = value
        print(f"{index}. {description} [{value}]")
    while True:
        raw = input(f"Выберите вариант [{default_index}]: ").strip().lower()
        if not raw:
            return default
        if raw in option_map:
            return option_map[raw]
        for value, _ in options:
            if raw == value:
                return value


def normalize_identity_path(raw_path: str) -> str:
    raw_path = raw_path.strip()
    if not raw_path:
        return ""
    path = Path(raw_path).expanduser()
    path = (Path.cwd() / path).resolve() if not path.is_absolute() else path.resolve()
    return str(path)


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


def validate_auth_mode(raw_value: str) -> str:
    value = raw_value.strip().lower()
    if value not in {"key", "password"}:
        fail(f"Некорректный способ входа: {raw_value}")
    return value


def validate_identity_path(raw_path: str) -> str:
    normalized = normalize_identity_path(raw_path)
    if normalized and not Path(normalized).is_file():
        fail(f"Не найден SSH key: {normalized}")
    return normalized


def has_saved_connection(role_state: dict[str, Any]) -> bool:
    return bool(
        str(role_state.get("public_ip", "")).strip()
        and str(role_state.get("ssh_host", "")).strip()
        and str(role_state.get("ssh_user", "")).strip()
        and str(role_state.get("ssh_port", "")).strip()
    )


def validate_target_settings(target: RemoteTarget) -> None:
    target.public_ip = validate_ip_literal(target.public_ip)
    target.ssh_host = validate_ssh_host(target.ssh_host)
    target.ssh_port = int(validate_ssh_port(str(target.ssh_port)))
    target.ssh_user = validate_ssh_user(target.ssh_user)
    target.auth_mode = validate_auth_mode(target.auth_mode)
    if target.auth_mode == "key":
        target.identity_path = validate_identity_path(target.identity_path)
    else:
        target.identity_path = ""


def auth_mode_label(auth_mode: str) -> str:
    return "SSH key" if auth_mode == "key" else "SSH password"


def display_target_connection(target: RemoteTarget) -> None:
    print(f"Public IP: {target.public_ip}")
    print(f"SSH: {target.ssh_user}@{target.ssh_host}:{target.ssh_port}")
    print(f"Вход: {auth_mode_label(target.auth_mode)}")
    if target.auth_mode == "key":
        print(f"SSH key: {target.identity_path or 'ssh-agent / стандартный ключ'}")
    elif target.saved_connection:
        print("SSH password: будет запрошен заново перед подключением")


def hydrate_runtime_auth(target: RemoteTarget) -> RemoteTarget:
    target.ssh_password = ""
    if target.auth_mode == "password":
        while True:
            password = prompt_secret(f"{target.label}: SSH пароль")
            if password:
                target.ssh_password = password
                return target
            warn("SSH пароль не может быть пустым.")
    return target


def prompt_server_connection(target: RemoteTarget, *, force_prompt: bool = False, confirm_existing: bool = True) -> RemoteTarget:
    print_header(f"Подключение: {target.label}")
    if target.saved_connection:
        try:
            validate_target_settings(target)
        except AppError as exc:
            warn(f"{target.label}: сохранённые SSH-данные повреждены или неполны, нужно ввести заново ({exc})")
            force_prompt = True
        else:
            print("Найдены сохранённые SSH-данные:")
            display_target_connection(target)
            if not force_prompt and not confirm_existing:
                print("Использую сохранённое подключение.")
                return hydrate_runtime_auth(target)
            if not force_prompt:
                action = prompt_choice(
                    f"Что делать с подключением для {target.label}?",
                    [
                        ("reuse", "Использовать сохранённые SSH-данные"),
                        ("edit", "Изменить SSH-данные"),
                    ],
                    default="reuse",
                )
                if action == "reuse":
                    print(f"{target.label}: использую сохранённое подключение, дальше будет реальная SSH-проверка.")
                    return hydrate_runtime_auth(target)
    elif target.public_ip:
        print(f"Подставлен public IP из deployment env: {target.public_ip}")

    target.public_ip = prompt_validated_value(
        f"{target.label}: Public IP (пример 203.0.113.10)",
        default=target.public_ip or None,
        validator=validate_ip_literal,
    )
    ssh_port_raw = prompt_validated_value(
        f"{target.label}: SSH port (пример 22)",
        default=str(target.ssh_port or 22),
        validator=validate_ssh_port,
    )
    target.ssh_user = prompt_validated_value(
        f"{target.label}: SSH user (пример root или ubuntu)",
        default=target.ssh_user or "root",
        validator=validate_ssh_user,
    )
    auth_default = target.auth_mode or "key"
    target.auth_mode = prompt_choice(
        f"{target.label}: способ входа",
        [
            ("key", "SSH key"),
            ("password", "SSH password"),
        ],
        default=auth_default,
    )
    use_custom_host_default = bool(target.ssh_host and target.ssh_host != target.public_ip)
    if prompt_yes_no(f"{target.label}: SSH адрес отличается от Public IP?", default=use_custom_host_default):
        target.ssh_host = prompt_validated_value(
            f"{target.label}: SSH host/IP (пример ssh.example.com)",
            default=(target.ssh_host if use_custom_host_default else None),
            validator=validate_ssh_host,
        )
    else:
        target.ssh_host = target.public_ip
    if target.auth_mode == "key":
        identity_raw = prompt_validated_value(
            f"{target.label}: путь к SSH key (пусто = ssh-agent / стандартный ключ)",
            default=target.identity_path or None,
            allow_empty=True,
            validator=validate_identity_path,
        )
        target.identity_path = identity_raw
        target.ssh_password = ""
    else:
        target.identity_path = ""
        target = hydrate_runtime_auth(target)
    target.ssh_port = int(ssh_port_raw)
    target.saved_connection = False
    validate_target_settings(target)
    print("Будет использовано подключение:")
    display_target_connection(target)
    return target


def find_existing_deployments() -> list[str]:
    names: list[str] = []
    for env_path in sorted(DEPLOYMENTS_DIR.glob("*.env")):
        if env_path.name != "deployment.env.example":
            names.append(env_path.stem)
    return names


def select_deployment(cli_name: str | None) -> str:
    if cli_name:
        return validate_deployment_name(cli_name)

    existing = find_existing_deployments()
    if not existing:
        return validate_deployment_name(prompt_value("Имя нового deployment"))

    print_header("Выбор deployment")
    for index, name in enumerate(existing, start=1):
        print(f"{index}. {name}")
    create_index = len(existing) + 1
    print(f"{create_index}. Создать новый deployment")

    while True:
        selection_raw = input(f"Выберите deployment [{create_index}]: ").strip() or str(create_index)
        if not selection_raw.isdigit():
            continue
        selection = int(selection_raw)
        if 1 <= selection <= len(existing):
            print(f"Выбран существующий deployment: {existing[selection - 1]}")
            return existing[selection - 1]
        if selection == create_index:
            return validate_deployment_name(prompt_value("Имя нового deployment"))


def select_existing_deployment(cli_name: str | None) -> str:
    if cli_name:
        deployment_name = validate_deployment_name(cli_name)
        env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
        if not env_path.exists():
            fail(f"Не найден deployment env: {env_path}")
        return deployment_name

    existing = find_existing_deployments()
    if not existing:
        fail("Не найдено ни одного deployment env.")

    print_header("Выбор deployment")
    for index, name in enumerate(existing, start=1):
        print(f"{index}. {name}")

    while True:
        selection_raw = input("Выберите deployment [1]: ").strip() or "1"
        if not selection_raw.isdigit():
            continue
        selection = int(selection_raw)
        if 1 <= selection <= len(existing):
            return existing[selection - 1]


def require_env(env: dict[str, str], required: list[str]) -> None:
    missing = [name for name in required if not env.get(name, "").strip()]
    if missing:
        fail(f"В deployment env не хватает обязательных значений: {', '.join(missing)}")


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def require_local_commands(commands: list[str]) -> None:
    missing = [command for command in commands if not command_exists(command)]
    if missing:
        fail(f"Не найдены локальные команды: {', '.join(missing)}")


def run_command(args: list[str], *, capture_output: bool = False, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(args, input=input_text, text=True, capture_output=capture_output, check=False)
    except FileNotFoundError as exc:
        raise AppError(f"Не найдена команда: {args[0]}") from exc
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip() if capture_output else ""
        if detail:
            raise AppError(f"Команда завершилась с ошибкой: {' '.join(args)}\n{detail}")
        raise AppError(f"Команда завершилась с ошибкой (код {completed.returncode}): {' '.join(args)}")
    return completed


def ensure_pip_available() -> None:
    if run_command([sys.executable, "-m", "pip", "--version"], capture_output=True, check=False).returncode == 0:
        return
    ensure_directories()
    if run_command([sys.executable, "-m", "ensurepip", "--upgrade"], capture_output=True, check=False).returncode == 0:
        if run_command([sys.executable, "-m", "pip", "--version"], capture_output=True, check=False).returncode == 0:
            return
    downloads_dir = RUNTIME_DIR / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    get_pip_path = downloads_dir / "get-pip.py"
    get_pip_url = os.environ.get("VPN_GET_PIP_URL", "https://bootstrap.pypa.io/get-pip.py")
    try:
        urllib.request.urlretrieve(get_pip_url, get_pip_path)
    except (urllib.error.URLError, OSError) as exc:
        raise AppError(f"Не удалось скачать get-pip.py: {exc}") from exc
    completed = run_command([sys.executable, str(get_pip_path)], capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise AppError(f"Не удалось установить pip для Python runtime.\n{detail}")


def ensure_paramiko_installed():
    try:
        return importlib.import_module("paramiko")
    except ImportError:
        ensure_directories()
        ensure_pip_available()
        target_dir = str(RUNTIME_SITE_PACKAGES)
        completed = run_command(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--target",
                target_dir,
                os.environ.get("VPN_PARAMIKO_PACKAGE", "paramiko>=3.5,<4"),
            ],
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise AppError(f"Не удалось подготовить Python SSH backend (paramiko).\n{detail}")
        importlib.invalidate_caches()
        try:
            return importlib.import_module("paramiko")
        except ImportError as exc:  # pragma: no cover - defensive
            raise AppError("Python SSH backend не загрузился даже после установки paramiko.") from exc


def use_python_ssh_backend(target: RemoteTarget) -> bool:
    return target.auth_mode == "password" or not (command_exists("ssh") and command_exists("scp"))


def ssh_base_args(target: RemoteTarget) -> list[str]:
    args = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-p", str(target.ssh_port)]
    if target.identity_path:
        args.extend(["-i", target.identity_path])
    args.append(f"{target.ssh_user}@{target.ssh_host}")
    return args


def scp_base_args(target: RemoteTarget) -> list[str]:
    args = ["scp", "-o", "StrictHostKeyChecking=accept-new", "-P", str(target.ssh_port)]
    if target.identity_path:
        args.extend(["-i", target.identity_path])
    return args


def build_remote_command(command_body: str, target: RemoteTarget, as_root: bool) -> tuple[str, str | None]:
    input_text: str | None = None
    shell_command = f"bash -lc {shlex.quote(command_body)}"
    if as_root and target.ssh_user != "root":
        if target.sudo_mode == "nopasswd":
            shell_command = f"sudo -n {shell_command}"
        elif target.sudo_mode == "password":
            shell_command = f"sudo -S -p '' {shell_command}"
            input_text = f"{target.sudo_password}\n"
        else:
            fail(f"Для {target.label} не подтверждён root/sudo доступ.")
    return shell_command, input_text


def paramiko_connect(target: RemoteTarget):
    paramiko = ensure_paramiko_installed()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict[str, Any] = {
        "hostname": target.ssh_host,
        "port": int(target.ssh_port),
        "username": target.ssh_user,
        "timeout": 20,
        "banner_timeout": 20,
        "auth_timeout": 20,
    }
    if target.auth_mode == "password":
        if not target.ssh_password:
            fail(f"Для {target.label} не задан SSH password.")
        connect_kwargs["password"] = target.ssh_password
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    else:
        connect_kwargs["look_for_keys"] = not bool(target.identity_path)
        connect_kwargs["allow_agent"] = not bool(target.identity_path)
        if target.identity_path:
            connect_kwargs["key_filename"] = target.identity_path
    try:
        client.connect(**connect_kwargs)
    except Exception as exc:  # noqa: BLE001
        raise AppError(f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}") from exc
    return client


def paramiko_exec(target: RemoteTarget, remote_command: str, *, input_text: str | None = None) -> tuple[int, str, str]:
    client = paramiko_connect(target)
    try:
        stdin, stdout, stderr = client.exec_command(remote_command, get_pty=bool(input_text))
        if input_text:
            stdin.write(input_text)
            stdin.flush()
            try:
                stdin.channel.shutdown_write()
            except Exception:  # noqa: BLE001
                pass
        channel = stdout.channel
        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        while True:
            if channel.recv_ready():
                out_chunks.append(channel.recv(4096))
            if channel.recv_stderr_ready():
                err_chunks.append(channel.recv_stderr(4096))
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.05)
        exit_status = channel.recv_exit_status()
        out_text = b"".join(out_chunks).decode("utf-8", errors="replace")
        err_text = b"".join(err_chunks).decode("utf-8", errors="replace")
        return exit_status, out_text, err_text
    finally:
        client.close()


def paramiko_upload(target: RemoteTarget, local_path: Path, remote_path: str) -> None:
    client = paramiko_connect(target)
    try:
        sftp = client.open_sftp()
        try:
            sftp.put(str(local_path), remote_path)
        finally:
            sftp.close()
    except Exception as exc:  # noqa: BLE001
        raise AppError(f"Не удалось загрузить {local_path} на {target.label}: {exc}") from exc
    finally:
        client.close()


def ssh_capture(target: RemoteTarget, command_body: str, *, as_root: bool = False) -> str:
    remote_command, input_text = build_remote_command(command_body, target, as_root)
    if use_python_ssh_backend(target):
        exit_status, stdout, stderr = paramiko_exec(target, remote_command, input_text=input_text)
        if exit_status != 0:
            detail = (stderr or stdout).strip()
            if detail:
                raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{detail}")
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label} (код {exit_status}).")
        return stdout
    completed = run_command(ssh_base_args(target) + [remote_command], capture_output=True, input_text=input_text)
    return completed.stdout


def ssh_stream(target: RemoteTarget, command_body: str, *, as_root: bool = False) -> None:
    remote_command, input_text = build_remote_command(command_body, target, as_root)
    if use_python_ssh_backend(target):
        exit_status, stdout, stderr = paramiko_exec(target, remote_command, input_text=input_text)
        if stdout.strip():
            print(stdout.rstrip())
        if stderr.strip():
            print(stderr.rstrip(), file=sys.stderr)
        if exit_status != 0:
            detail = (stderr or stdout).strip()
            if detail:
                raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{detail}")
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label} (код {exit_status}).")
        return
    run_command(ssh_base_args(target) + [remote_command], input_text=input_text)


def scp_upload(target: RemoteTarget, local_path: Path, remote_path: str) -> None:
    if use_python_ssh_backend(target):
        paramiko_upload(target, local_path, remote_path)
        return
    run_command(scp_base_args(target) + [str(local_path), f"{target.ssh_user}@{target.ssh_host}:{remote_path}"])


def parse_kv_output(payload: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in payload.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def preflight_script(wg_interface: str) -> str:
    return textwrap.dedent(
        """\
        set -euo pipefail

        service_state() {
          if command -v systemctl >/dev/null 2>&1; then
            systemctl is-active "$1" 2>/dev/null || true
          else
            printf 'unavailable'
          fi
        }

        login_user="$(id -un)"
        uid="$(id -u)"
        is_root="0"
        if [[ "${uid}" -eq 0 ]]; then is_root="1"; fi

        has_sudo="0"
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then has_sudo="1"; fi

        os_id=""
        os_version=""
        if [[ -r /etc/os-release ]]; then
          source /etc/os-release
          os_id="${ID:-}"
          os_version="${VERSION_ID:-}"
        fi

        installed="0"
        deployment_name=""
        role=""
        installed_at=""
        if [[ -r /etc/vpn-stack/deployment.env ]]; then
          installed="1"
          deployment_name="$(grep -E '^DEPLOY_NAME=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
        fi
        if [[ -r /etc/vpn-stack/role ]]; then role="$(tr -d '\\r\\n' </etc/vpn-stack/role)"; fi
        if [[ -r /etc/vpn-stack/installed_at ]]; then installed_at="$(tr -d '\\r\\n' </etc/vpn-stack/installed_at)"; fi

        default_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
        hostname_value="$(hostname -f 2>/dev/null || hostname)"

        printf 'login_user=%s\\n' "${login_user}"
        printf 'is_root=%s\\n' "${is_root}"
        printf 'has_sudo=%s\\n' "${has_sudo}"
        printf 'os_id=%s\\n' "${os_id}"
        printf 'os_version=%s\\n' "${os_version}"
        printf 'hostname=%s\\n' "${hostname_value}"
        printf 'default_iface=%s\\n' "${default_iface}"
        printf 'installed=%s\\n' "${installed}"
        printf 'deployment_name=%s\\n' "${deployment_name}"
        printf 'role=%s\\n' "${role}"
        printf 'installed_at=%s\\n' "${installed_at}"
        printf 'sing_box=%s\\n' "$(service_state sing-box)"
        printf 'nftables=%s\\n' "$(service_state nftables)"
        printf 'wireguard=%s\\n' "$(service_state wg-quick@__WG_INTERFACE__)"
        printf 'sync_timer=%s\\n' "$(service_state vpn-stack-sync.timer)"
        """
    ).replace("__WG_INTERFACE__", wg_interface).strip()


def remote_preflight(target: RemoteTarget, wg_interface: str) -> dict[str, str]:
    return parse_kv_output(ssh_capture(target, preflight_script(wg_interface)))


def print_preflight(target: RemoteTarget, preflight: dict[str, str]) -> None:
    print_header(f"Проверка {target.label}")
    print(f"host: {preflight.get('hostname', '-')}")
    print(f"login user: {preflight.get('login_user', '-')}")
    print(f"os: {preflight.get('os_id', '-')} {preflight.get('os_version', '-')}")
    print(f"default iface: {preflight.get('default_iface', '-')}")
    print(f"installed: {preflight.get('installed', '0')}")
    print(f"role: {preflight.get('role', '-')}")
    print(f"deployment: {preflight.get('deployment_name', '-')}")
    print(f"sing-box: {preflight.get('sing_box', '-')}")
    print(f"nftables: {preflight.get('nftables', '-')}")
    print(f"wireguard: {preflight.get('wireguard', '-')}")
    print(f"sync timer: {preflight.get('sync_timer', '-')}")


def verify_target_interactively(
    target: RemoteTarget,
    *,
    wg_interface: str,
    require_privilege: bool,
    validate_os: bool,
    confirm_existing_connection: bool,
) -> tuple[RemoteTarget, dict[str, str]]:
    force_prompt = not target.saved_connection
    while True:
        target = prompt_server_connection(target, force_prompt=force_prompt, confirm_existing=confirm_existing_connection)
        print(f"Проверяю подключение к {target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port}")
        try:
            preflight = remote_preflight(target, wg_interface)
            print_preflight(target, preflight)
            if validate_os:
                if preflight.get("os_id") != "ubuntu":
                    fail(f"{target.label} должен быть Ubuntu.")
                if preflight.get("os_version") and preflight["os_version"] != "24.04":
                    warn(f"{target.label} не на Ubuntu 24.04: {preflight['os_version']}")
            if require_privilege:
                ensure_remote_privilege(target, preflight)
            return target, preflight
        except AppError as exc:
            warn(str(exc))
            action = prompt_choice(
                f"{target.label}: подключение или preflight не прошли. Что делать?",
                [
                    ("edit", "Исправить параметры сервера"),
                    ("retry", "Повторить с теми же параметрами"),
                    ("cancel", "Отменить операцию"),
                ],
                default="edit",
            )
            if action == "cancel":
                raise
            if action == "retry":
                target.saved_connection = True
                if target.auth_mode == "password":
                    target.ssh_password = ""
                force_prompt = False
            else:
                target.saved_connection = False
                force_prompt = True


def ensure_remote_privilege(target: RemoteTarget, preflight: dict[str, str]) -> None:
    if preflight.get("is_root") == "1":
        target.sudo_mode = "root"
        print(f"{target.label}: удалённый вход уже под root.")
        return
    if preflight.get("has_sudo") == "1":
        target.sudo_mode = "nopasswd"
        print(f"{target.label}: найден passwordless sudo.")
        return
    if not prompt_yes_no(f"Пользователь {preflight.get('login_user', 'unknown')} на {preflight.get('hostname', 'unknown')} не root и без passwordless sudo. Попробовать sudo по паролю?", default=True):
        fail(f"Для {target.label} нужен root или sudo.")
    target.sudo_mode = "password"
    target.sudo_password = prompt_secret(f"Введите sudo-пароль для {target.label}")


def ask_install_action(role: str, deployment_name: str, preflight: dict[str, str]) -> str:
    if preflight.get("installed") != "1":
        print(f"На {ROLE_META[role]['label']} стек не найден.")
        return prompt_choice(
            f"Что делать с {ROLE_META[role]['label']}?",
            [
                ("install", "Установить роль"),
                ("skip", "Пока ничего не делать"),
            ],
            default="install",
        )
    existing_role = preflight.get("role", "")
    existing_deployment = preflight.get("deployment_name", "")
    if existing_role and existing_role != role:
        print(f"На {ROLE_META[role]['label']} уже стоит роль {existing_role} (deployment: {existing_deployment or '-'})")
        return prompt_choice(
            f"Что делать с {ROLE_META[role]['label']}?",
            [
                ("reinstall", "Переустановить и обновить роль"),
                ("skip", "Пока ничего не делать"),
            ],
            default="skip",
        )
    if existing_deployment and existing_deployment != deployment_name:
        print(f"На сервере уже найден другой deployment: {existing_deployment}")
    return prompt_choice(
        f"Что делать с {ROLE_META[role]['label']}?",
        [
            ("reinstall", "Обновить / переустановить роль"),
            ("skip", "Пока ничего не делать"),
        ],
        default="reinstall",
    )


def download_file(url: str, destination: Path) -> None:
    ensure_file_parent(destination)
    request = urllib.request.Request(url, headers={"User-Agent": "vpn-installer/1.0"})
    tmp_path = destination.with_suffix(destination.suffix + ".tmp")
    with urllib.request.urlopen(request, timeout=DEFAULT_ASSET_TIMEOUT) as response:
        tmp_path.write_bytes(response.read())
    tmp_path.replace(destination)


def fetch_assets(env: dict[str, str], assets_dir: Path) -> dict[str, Path]:
    assets_dir.mkdir(parents=True, exist_ok=True)
    targets = {
        "geosite-ru.srs": (env["RU_GEOSITE_URL"], assets_dir / "geosite-ru.srs"),
        "geoip-ru.srs": (env["RU_GEOIP_URL"], assets_dir / "geoip-ru.srs"),
    }
    required_assets = {"geosite-ru.srs", "geoip-ru.srs"}
    if env.get("FOREIGN_BLOCK_RU", "1") == "1":
        targets["ru-ipv4.zone"] = (env["FOREIGN_RU_IPV4_LIST_URL"], assets_dir / "ru-ipv4.zone")
        targets["ru-ipv6.zone"] = (env["FOREIGN_RU_IPV6_LIST_URL"], assets_dir / "ru-ipv6.zone")
        required_assets.update({"ru-ipv4.zone", "ru-ipv6.zone"})
    fetched: dict[str, Path] = {}
    missing_required: list[str] = []
    print_header("Подкачка rule-set и CIDR-ассетов")
    for asset_name, (url, path) in targets.items():
        try:
            download_file(url, path)
            fetched[asset_name] = path
            print(f"{asset_name}: OK")
        except (urllib.error.URLError, OSError) as exc:
            if path.exists() and path.stat().st_size > 0:
                warn(f"{asset_name}: не удалось обновить, оставляю локальную копию ({exc})")
                fetched[asset_name] = path
            else:
                if asset_name in required_assets:
                    missing_required.append(f"{asset_name} ({exc})")
                else:
                    warn(f"{asset_name}: не удалось скачать ({exc})")
    if missing_required:
        fail("Не удалось получить обязательные assets: " + ", ".join(missing_required))
    return fetched


def render_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def env_int(env: dict[str, str], key: str) -> int:
    try:
        return int(env[key])
    except ValueError as exc:
        raise AppError(f"Переменная {key} должна быть числом, сейчас: {env[key]}") from exc


def wg_host_address(cidr: str) -> str:
    return cidr.split("/", 1)[0]


def render_ru_singbox(env: dict[str, str]) -> str:
    payload = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "strategy": "ipv4_only",
            "servers": [
                {"type": "udp", "tag": "dns-ru-direct", "server": env["RU_DIRECT_DNS_SERVER"], "server_port": env_int(env, "RU_DIRECT_DNS_PORT")},
                {"type": "https", "tag": "dns-global", "server": env["GLOBAL_DOH_SERVER"], "server_port": 443, "path": env["GLOBAL_DOH_PATH"], "routing_mark": env_int(env, "APP_ROUTE_MARK"), "tls": {"enabled": True, "server_name": env["GLOBAL_DOH_SERVER_NAME"]}},
            ],
            "rules": [
                {"query_type": ["AAAA"], "action": "reject"},
                {"rule_set": ["geosite-ru"], "action": "route", "server": "dns-ru-direct", "strategy": "ipv4_only"},
            ],
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
                        "max_time_difference": "1m",
                    },
                },
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-ru"},
            {"type": "direct", "tag": "to-foreign", "routing_mark": env_int(env, "APP_ROUTE_MARK")},
            {"type": "block", "tag": "blocked"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"},
            "rule_set": [
                {"type": "local", "tag": "geosite-ru", "format": "binary", "path": f"{env['RULESET_DIR']}/geosite-ru.srs"},
                {"type": "local", "tag": "geoip-ru", "format": "binary", "path": f"{env['RULESET_DIR']}/geoip-ru.srs"},
            ],
            "rules": [
                {"ip_version": 6, "action": "route", "outbound": "blocked"},
                {"inbound": ["vless-in"], "action": "resolve", "strategy": "ipv4_only"},
                {"inbound": ["vless-in"], "action": "sniff"},
                {"ip_is_private": True, "action": "route", "outbound": "direct-ru"},
                {"rule_set": ["geosite-ru"], "action": "route", "outbound": "direct-ru"},
                {"rule_set": ["geoip-ru"], "action": "route", "outbound": "direct-ru"},
            ],
            "final": "to-foreign",
        },
    }
    return render_json(payload)


def render_foreign_singbox() -> str:
    return render_json({"log": {"level": "warn", "timestamp": True}, "outbounds": [{"type": "direct", "tag": "direct"}]})


def render_ru_wg(env: dict[str, str]) -> str:
    return "\n".join(["[Interface]", f"Address = {env['WG_RU_ADDRESS']}", f"PrivateKey = {env['WG_RU_PRIVATE_KEY']}", f"MTU = {env['WG_MTU']}", f"FwMark = {env['WG_TUNNEL_FWMARK']}", "Table = off", f"PostUp = ip -4 route add default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']}", f"PostUp = ip -4 rule add fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000", f"PreDown = ip -4 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000", f"PreDown = ip -4 route del default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']}", "", "[Peer]", f"PublicKey = {env['WG_FOREIGN_PUBLIC_KEY']}", f"PresharedKey = {env['WG_PRESHARED_KEY']}", "AllowedIPs = 0.0.0.0/0", f"Endpoint = {env['FOREIGN_PUBLIC_IP']}:{env['WG_PORT']}", f"PersistentKeepalive = {env['WG_KEEPALIVE']}", ""]) 


def render_foreign_wg(env: dict[str, str]) -> str:
    return "\n".join(["[Interface]", f"Address = {env['WG_FOREIGN_ADDRESS']}", f"ListenPort = {env['WG_PORT']}", f"PrivateKey = {env['WG_FOREIGN_PRIVATE_KEY']}", f"MTU = {env['WG_MTU']}", "", "[Peer]", f"PublicKey = {env['WG_RU_PUBLIC_KEY']}", f"PresharedKey = {env['WG_PRESHARED_KEY']}", f"AllowedIPs = {wg_host_address(env['WG_RU_ADDRESS'])}/32", ""])


def render_foreign_nftables(env: dict[str, str], wan_iface: str) -> str:
    return "\n".join([
        "flush ruleset", "", "table inet vpnstack {", "  set ru_ipv4 {", "    type ipv4_addr", "    flags interval", "    auto-merge", "  }", "", "  set ru_ipv6 {", "    type ipv6_addr", "    flags interval", "    auto-merge", "  }", "", "  chain input {", "    type filter hook input priority 0;", "    policy drop;", "", '    iifname "lo" accept', "    ip6 nexthdr icmpv6 accept", "    ip protocol icmp accept", "    ct state established,related accept", f"    tcp dport {env['SSH_PORT']} accept", f"    udp dport {env['WG_PORT']} accept", "  }", "", "  chain forward {", "    type filter hook forward priority 0;", "    policy drop;", "", "    ct state established,related accept", f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" ip daddr @ru_ipv4 drop', f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" ip6 daddr @ru_ipv6 drop', f'    iifname "{env["WG_INTERFACE"]}" oifname "{wan_iface}" accept', f'    iifname "{wan_iface}" oifname "{env["WG_INTERFACE"]}" ct state established,related accept', "  }", "}", "", "table ip nat {", "  chain postrouting {", "    type nat hook postrouting priority srcnat;", f'    ip saddr {wg_host_address(env["WG_RU_ADDRESS"])} oifname "{wan_iface}" masquerade', "  }", "}", ""])


def render_ru_firewall_nftables(env: dict[str, str]) -> str:
    return "\n".join(["flush ruleset", "", "table inet vpnstack {", "  chain input {", "    type filter hook input priority 0;", "    policy drop;", "", '    iifname "lo" accept', "    ip6 nexthdr icmpv6 accept", "    ip protocol icmp accept", "    ct state established,related accept", f"    tcp dport {env['SSH_PORT']} accept", f"    tcp dport {env['RU_LISTEN_PORT']} accept", "  }", "}", ""])


def render_sync_script(env: dict[str, str]) -> str:
    return "\n".join([
        "#!/usr/bin/env bash", "set -euo pipefail", "", 'ROLE="${1:-}"', f'RULESET_DIR="${{2:-{env["RULESET_DIR"]}}}"', f'RU_GEOSITE_URL="${{3:-{env["RU_GEOSITE_URL"]}}}"', f'RU_GEOIP_URL="${{4:-{env["RU_GEOIP_URL"]}}}"', f'FOREIGN_BLOCK_RU="${{5:-{env["FOREIGN_BLOCK_RU"]}}}"', f'FOREIGN_RU_IPV4_LIST_URL="${{6:-{env["FOREIGN_RU_IPV4_LIST_URL"]}}}"', f'FOREIGN_RU_IPV6_LIST_URL="${{7:-{env["FOREIGN_RU_IPV6_LIST_URL"]}}}"', "", 'mkdir -p "$RULESET_DIR"', "", "download() {", '  local url="$1"', '  local output="$2"', '  curl -fsSL "$url" -o "$output.tmp"', '  mv "$output.tmp" "$output"', "}", "", 'if [[ "$ROLE" == "ru-gateway" ]]; then', '  download "$RU_GEOSITE_URL" "$RULESET_DIR/geosite-ru.srs"', '  download "$RU_GEOIP_URL" "$RULESET_DIR/geoip-ru.srs"', "  exit 0", "fi", "", 'if [[ "$ROLE" == "foreign-exit" && "$FOREIGN_BLOCK_RU" == "1" ]]; then', '  local_v4="$RULESET_DIR/ru-ipv4.zone"', '  local_v6="$RULESET_DIR/ru-ipv6.zone"', '  download "$FOREIGN_RU_IPV4_LIST_URL" "$local_v4"', '  download "$FOREIGN_RU_IPV6_LIST_URL" "$local_v6"', "  {", '    echo "flush set inet vpnstack ru_ipv4"', '    if [[ -s "$local_v4" ]]; then', "      printf 'add element inet vpnstack ru_ipv4 { '", '      paste -sd, "$local_v4"', "      echo ' }'", "    fi", '    echo "flush set inet vpnstack ru_ipv6"', '    if [[ -s "$local_v6" ]]; then', "      printf 'add element inet vpnstack ru_ipv6 { '", '      paste -sd, "$local_v6"', "      echo ' }'", "    fi", '  } > "$RULESET_DIR/nft-ru-block.nft"', '  nft -f "$RULESET_DIR/nft-ru-block.nft"', "fi", ""])


def render_sync_service(role: str) -> str:
    return "\n".join(["[Unit]", f"Description=Sync vpn-stack state for {role}", "After=network-online.target", "Wants=network-online.target", "", "[Service]", "Type=oneshot", f"ExecStart=/usr/local/lib/vpn-stack/sync-state.sh {role}", ""])


def render_sync_timer() -> str:
    return "\n".join(["[Unit]", "Description=Run vpn-stack state sync daily", "", "[Timer]", "OnBootSec=2m", "OnUnitActiveSec=1d", "RandomizedDelaySec=20m", "Persistent=true", "", "[Install]", "WantedBy=timers.target", ""])


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


def copy_to_clipboard(payload: str) -> tuple[bool, str]:
    payload = payload.rstrip("\n")
    if os.name == "nt":
        if command_exists("powershell"):
            completed = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Set-Clipboard -Value ([Console]::In.ReadToEnd())",
                ],
                input_text=payload,
                capture_output=True,
                check=False,
            )
            if completed.returncode == 0:
                return True, "URI скопирована в буфер обмена Windows."
            return False, (completed.stderr or completed.stdout or "Не удалось использовать Set-Clipboard.").strip()
        return False, "PowerShell не найден, буфер обмена недоступен."
    clipboard_tools = [
        (["wl-copy"], "URI скопирована через wl-copy."),
        (["xclip", "-selection", "clipboard"], "URI скопирована через xclip."),
        (["xsel", "--clipboard", "--input"], "URI скопирована через xsel."),
    ]
    for command, ok_message in clipboard_tools:
        if not command_exists(command[0]):
            continue
        completed = run_command(command, input_text=payload, capture_output=True, check=False)
        if completed.returncode == 0:
            return True, ok_message
    return False, "Буфер обмена недоступен, используй локальный файл с URI."


def render_preview_files(env: dict[str, str], preview_dir: Path) -> None:
    ru_dir = preview_dir / "ru"
    foreign_dir = preview_dir / "foreign"
    wan_iface = env.get("WAN_INTERFACE", "").strip() or "eth0"
    write_text(ru_dir / "sing-box.json", render_ru_singbox(env))
    write_text(ru_dir / f"{env['WG_INTERFACE']}.conf", render_ru_wg(env))
    write_text(ru_dir / "nftables.conf", render_ru_firewall_nftables(env))
    write_text(ru_dir / "sync-state.sh", render_sync_script(env))
    write_text(ru_dir / "vpn-stack-sync.service", render_sync_service(ROLE_RU))
    write_text(ru_dir / "vpn-stack-sync.timer", render_sync_timer())
    write_text(foreign_dir / "sing-box.json", render_foreign_singbox())
    write_text(foreign_dir / f"{env['WG_INTERFACE']}.conf", render_foreign_wg(env))
    write_text(foreign_dir / "nftables.conf", render_foreign_nftables(env, wan_iface))
    write_text(foreign_dir / "sync-state.sh", render_sync_script(env))
    write_text(foreign_dir / "vpn-stack-sync.service", render_sync_service(ROLE_FOREIGN))
    write_text(foreign_dir / "vpn-stack-sync.timer", render_sync_timer())


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


def render_cloud_init_role(role: str, env_text: str, assets_dir: Path) -> str:
    install_b64 = base64.b64encode(INSTALL_SCRIPT_PATH.read_bytes()).decode("ascii")
    env_b64 = base64.b64encode(env_text.encode("utf-8")).decode("ascii")
    lines = [
        "#cloud-config", "package_update: true", "write_files:",
        "  - path: /root/vpn-stack/install.sh", "    permissions: '0755'", "    encoding: b64", f"    content: {install_b64}",
        "  - path: /root/vpn-stack/deployment.env", "    permissions: '0600'", "    encoding: b64", f"    content: {env_b64}",
    ]
    asset_block = emit_cloud_init_assets(assets_dir)
    if asset_block:
        lines.append(asset_block)
    lines.extend(["runcmd:", f'  - [bash, -lc, "cd /root/vpn-stack && ./install.sh --role {role} --env-file /root/vpn-stack/deployment.env --assets-dir /root/vpn-stack/assets"]', ""])
    return "\n".join(lines)


def render_cloud_init_artifacts(env: dict[str, str]) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    out_dir = deployment_out_dir(env)
    server_dir = out_dir / "server"
    assets_dir = out_dir / "assets"
    cloud_init_dir = out_dir / "cloud-init"
    if not (server_dir / "ru.env").exists() or not (server_dir / "foreign.env").exists():
        render_config_artifacts(DEPLOYMENTS_DIR / f"{env['DEPLOY_NAME']}.env", env, fetch_assets_first=True)
    write_text(cloud_init_dir / "ru.yaml", render_cloud_init_role(ROLE_RU, read_text(server_dir / "ru.env"), assets_dir))
    write_text(cloud_init_dir / "foreign.yaml", render_cloud_init_role(ROLE_FOREIGN, read_text(server_dir / "foreign.env"), assets_dir))
    return cloud_init_dir


def copy_asset_if_present(source: Path, destination: Path) -> None:
    if source.is_file():
        ensure_file_parent(destination)
        shutil.copy2(source, destination)


def create_tarball(source_dir: Path, destination_tarball: Path) -> None:
    ensure_file_parent(destination_tarball)
    with tarfile.open(destination_tarball, "w:gz") as archive:
        for item in sorted(source_dir.rglob("*")):
            archive.add(item, arcname=item.relative_to(source_dir))


def package_bundle(env: dict[str, str]) -> Path:
    require_env(env, REQUIRED_ENV_VARS)
    out_dir = deployment_out_dir(env)
    server_dir = out_dir / "server"
    assets_dir = out_dir / "assets"
    bundle_dir = out_dir / "bundle"
    if not (server_dir / "ru.env").exists() or not (server_dir / "foreign.env").exists():
        render_config_artifacts(DEPLOYMENTS_DIR / f"{env['DEPLOY_NAME']}.env", env, fetch_assets_first=True)
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


def update_env_with_targets(env: dict[str, str], targets: list[RemoteTarget]) -> None:
    for target in targets:
        env[ROLE_META[target.role]["public_ip_key"]] = target.public_ip


def postcheck_command(wg_interface: str) -> str:
    return textwrap.dedent(
        """\
        set -euo pipefail
        systemctl is-active nftables >/dev/null
        systemctl is-active vpn-stack-sync.timer >/dev/null
        systemctl is-active wg-quick@__WG_INTERFACE__ >/dev/null
        if systemctl list-unit-files sing-box.service >/dev/null 2>&1; then
          systemctl is-active sing-box >/dev/null || true
        fi
        printf 'role='
        cat /etc/vpn-stack/role
        printf 'installed_at='
        cat /etc/vpn-stack/installed_at
        deployment_name="$(grep -E '^DEPLOY_NAME=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
        printf 'deployment=%s\\n' "${deployment_name}"
        """
    ).replace("__WG_INTERFACE__", wg_interface).strip()


def cleanup_remote_workdir(target: RemoteTarget, remote_root: str) -> None:
    try:
        ssh_stream(target, f"rm -rf {shlex.quote(remote_root)}")
    except AppError as exc:
        warn(f"Не удалось очистить временную папку на {target.label}: {exc}")


def install_remote_role(target: RemoteTarget, deployment_name: str, env: dict[str, str], action: str) -> None:
    remote_root = f"vpn-installer/{deployment_name}/{target.role}"
    archive_name = f"{target.role}.tar.gz"
    print_header(f"Подготовка {target.label}")
    ssh_stream(target, f"rm -rf {shlex.quote(remote_root)} && mkdir -p {shlex.quote(remote_root)}")
    try:
        if action in {"install", "reinstall"}:
            bundle_path = deployment_out_dir(env) / "bundle" / f"{target.role}.tar.gz"
            if not bundle_path.is_file():
                fail(f"Не найден bundle для {target.label}: {bundle_path}")
            print_header(f"Загрузка bundle на {target.label}")
            scp_upload(target, bundle_path, f"{remote_root}/{archive_name}")
            remote_command = (
                f"cd {shlex.quote(remote_root)} && "
                f"tar -xzf {shlex.quote(archive_name)} && "
                "chmod +x ./install.sh && "
                f"./install.sh --role {shlex.quote(target.role)} --action {shlex.quote(action)} --env-file ./deployment.env --assets-dir ./assets"
            )
        else:
            scp_upload(target, INSTALL_SCRIPT_PATH, f"{remote_root}/install.sh")
            remote_command = (
                f"cd {shlex.quote(remote_root)} && "
                "chmod +x ./install.sh && "
                f"./install.sh --role {shlex.quote(target.role)} --action {shlex.quote(action)}"
            )
        print_header(f"Действие {action} для {target.label}")
        ssh_stream(target, remote_command, as_root=True)
    finally:
        cleanup_remote_workdir(target, remote_root)


def postcheck_remote_role(target: RemoteTarget, wg_interface: str) -> None:
    print_header(f"Пост-проверка {target.label}")
    ssh_stream(target, postcheck_command(wg_interface), as_root=True)


def print_summary(deployment_name: str, env: dict[str, str], targets: list[RemoteTarget]) -> None:
    print_header("Сводка deployment")
    print(f"deployment: {deployment_name}")
    print(f"RU public IP: {env.get('RU_PUBLIC_IP', '-')}")
    print(f"Foreign public IP: {env.get('FOREIGN_PUBLIC_IP', '-')}")
    for target in targets:
        print(f"{target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port} ({auth_mode_label(target.auth_mode)})")
    print(f"WAN_INTERFACE: {env.get('WAN_INTERFACE') or '-'}")


def print_step(step: int, total: int, message: str) -> None:
    print(f"[{step}/{total}] {message}")


def ensure_foreign_wan_interface(env: dict[str, str], foreign_preflight: dict[str, str]) -> None:
    if env.get("WAN_INTERFACE", "").strip():
        return
    detected = foreign_preflight.get("default_iface", "").strip()
    if detected:
        env["WAN_INTERFACE"] = detected
        print(f"Автоматически выбран WAN_INTERFACE={detected}")
        return
    env["WAN_INTERFACE"] = prompt_value("Не удалось определить WAN interface автоматически. Укажите его вручную")


def load_env_for_render(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        fail(f"Не найден deployment env: {env_path}")
    env = merge_env_with_defaults(load_env_file(env_path), sanitize_name(env_path.stem))
    write_text(env_path, render_env_text(env))
    return env


def current_wg_interface(env: dict[str, str]) -> str:
    return env.get("WG_INTERFACE", "").strip() or "wg0"


def requested_roles(role_arg: str) -> list[str]:
    if role_arg == "all":
        return [ROLE_RU, ROLE_FOREIGN]
    return [role_arg]


def execution_roles(action: str, roles: list[str]) -> list[str]:
    if action in {"install", "reinstall"}:
        preferred = [ROLE_FOREIGN, ROLE_RU]
    elif action in {"remove", "purge"}:
        preferred = [ROLE_RU, ROLE_FOREIGN]
    else:
        preferred = [ROLE_RU, ROLE_FOREIGN]
    return [role for role in preferred if role in roles]


def prepare_remote_session(
    deployment_arg: str | None,
    *,
    roles: list[str],
    require_privilege: bool,
    validate_os: bool = True,
    allow_create: bool = False,
    persist_local: bool = True,
    confirm_existing_connections: bool = True,
) -> tuple[str, Path, dict[str, str], dict[str, Any], list[RemoteTarget], dict[str, dict[str, str]]]:
    if allow_create or persist_local:
        ensure_directories()

    if allow_create:
        deployment_name = select_deployment(deployment_arg)
        env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
        env = ensure_deployment_env(env_path, deployment_name)
    else:
        deployment_name = select_existing_deployment(deployment_arg)
        env_path, env = load_existing_deployment_env(deployment_name)

    state = load_state(deployment_name)

    print_header("Параметры deployment")
    print(f"deployment: {deployment_name}")
    targets: list[RemoteTarget] = []
    preflights: dict[str, dict[str, str]] = {}
    wg_interface = current_wg_interface(env)
    for role in roles:
        target = build_target(role, env, state)
        target, preflight = verify_target_interactively(
            target,
            wg_interface=wg_interface,
            require_privilege=require_privilege,
            validate_os=validate_os,
            confirm_existing_connection=confirm_existing_connections,
        )
        targets.append(target)
        preflights[role] = preflight

    update_env_with_targets(env, targets)
    if persist_local:
        write_text(env_path, render_env_text(env))
        write_state(deployment_name, targets, existing_state=state)

    return deployment_name, env_path, env, state, targets, preflights


def finalize_install_output(env: dict[str, str], deployment_name: str) -> None:
    paths = client_artifact_paths(env)
    uri_payload = render_vless_uri(env)
    clipboard_ok, clipboard_message = copy_to_clipboard(uri_payload)
    print_header("Готово")
    print(f"Deployment: {deployment_name}")
    print(f"Hiddify URI: {paths['uri']}")
    print(f"JSON backup для Hiddify: {paths['hiddify_json']}")
    print(f"JSON backup для Linux: {paths['linux_json']}")
    print(f"Следующие шаги: {paths['next_steps']}")
    print(clipboard_message)
    print("Что делать дальше:")
    print("1. Открой Hiddify.")
    print("2. Выбери импорт из буфера обмена.")
    print(f"3. Если буфер обмена не сработал, открой {paths['uri'].name} и вставь URI вручную.")
    print(f"4. Для проверки серверов потом запусти: vpn status --deployment {deployment_name}")


def cmd_init_env(args: argparse.Namespace) -> int:
    env_path = Path(args.output_env).expanduser()
    deployment_name = sanitize_name(env_path.stem)
    if not deployment_name:
        fail("Не удалось определить имя deployment из пути env-файла.")
    env = ensure_deployment_env(env_path, deployment_name)
    print(f"Wrote {env_path}")
    print(f"DEPLOY_NAME={env['DEPLOY_NAME']}")
    return 0


def cmd_fetch_assets(args: argparse.Namespace) -> int:
    env = load_env_for_render(Path(args.env_file).expanduser())
    assets_dir = deployment_out_dir(env) / "assets"
    fetch_assets(env, assets_dir)
    print(f"Assets dir: {assets_dir}")
    return 0


def cmd_render_config(args: argparse.Namespace) -> int:
    env_path = Path(args.env_file).expanduser()
    env = load_env_for_render(env_path)
    print(f"Rendered server previews to {render_config_artifacts(env_path, env, fetch_assets_first=True)}")
    return 0


def cmd_gen_client_profiles(args: argparse.Namespace) -> int:
    env = load_env_for_render(Path(args.env_file).expanduser())
    print(f"Generated client profiles in {render_client_profiles(env)}")
    return 0


def cmd_render_cloud_init(args: argparse.Namespace) -> int:
    env_path = Path(args.env_file).expanduser()
    env = load_env_for_render(env_path)
    render_config_artifacts(env_path, env, fetch_assets_first=True)
    print(f"Generated cloud-init files in {render_cloud_init_artifacts(env)}")
    return 0


def cmd_package_bundle(args: argparse.Namespace) -> int:
    env_path = Path(args.env_file).expanduser()
    env = load_env_for_render(env_path)
    render_config_artifacts(env_path, env, fetch_assets_first=True)
    print(f"Packaged bundles in {package_bundle(env)}")
    return 0


def cmd_render_all(args: argparse.Namespace) -> int:
    env_path = Path(args.env_file).expanduser()
    env = load_env_for_render(env_path)
    print(f"Rendered all artifacts to {render_all_artifacts(env_path, env)}")
    return 0


def run_selected_remote_action(
    action: str,
    deployment_name: str,
    env_path: Path,
    env: dict[str, str],
    targets: list[RemoteTarget],
    preflights: dict[str, dict[str, str]],
    *,
    role_arg: str = "all",
) -> None:
    target_map = {target.role: target for target in targets}
    roles = requested_roles(role_arg)
    wg_interface = current_wg_interface(env)
    if action in {"install", "reinstall"}:
        print_header("Локальная сборка артефактов")
        render_all_artifacts(env_path, env)
    for role in execution_roles(action, roles):
        target = target_map[role]
        install_remote_role(target, deployment_name, env, action)
        if action in {"install", "reinstall"}:
            postcheck_remote_role(target, wg_interface)
        else:
            print_preflight(target, remote_preflight(target, wg_interface))


def cmd_install(args: argparse.Namespace) -> int:
    print_header("Установка / обновление VPN")
    print("Сценарий:")
    print("1. Выбор или создание deployment")
    print("2. Проверка RU сервера")
    print("3. Проверка Foreign сервера")
    print("4. Локальная сборка артефактов")
    print("5. Установка сначала на Foreign, затем на RU")
    roles = requested_roles("all")
    deployment_name, env_path, env, state, targets, preflights = prepare_remote_session(
        args.deployment,
        roles=roles,
        require_privilege=True,
        allow_create=True,
        persist_local=True,
        confirm_existing_connections=True,
    )
    ensure_foreign_wan_interface(env, preflights[ROLE_FOREIGN])
    write_text(env_path, render_env_text(env))
    write_state(deployment_name, targets, existing_state=state)
    print_summary(deployment_name, env, targets)
    actions = {
        ROLE_RU: ask_install_action(ROLE_RU, deployment_name, preflights[ROLE_RU]),
        ROLE_FOREIGN: ask_install_action(ROLE_FOREIGN, deployment_name, preflights[ROLE_FOREIGN]),
    }
    if all(action == "skip" for action in actions.values()):
        print("Обе роли пропущены.")
        return 0
    if not prompt_yes_no("Продолжить установку / обновление?", default=True):
        print("Остановлено пользователем.")
        return 0
    total_steps = 1 + 2 * sum(1 for action in actions.values() if action != "skip")
    step = 1
    print_step(step, total_steps, "Локальная сборка артефактов")
    render_all_artifacts(env_path, env)
    step += 1
    target_map = {target.role: target for target in targets}
    for role in execution_roles("install", roles):
        action = actions[role]
        if action == "skip":
            continue
        print_step(step, total_steps, f"{ROLE_META[role]['label']}: {action}")
        install_remote_role(target_map[role], deployment_name, env, action)
        step += 1
        print_step(step, total_steps, f"{ROLE_META[role]['label']}: пост-проверка")
        postcheck_remote_role(target_map[role], current_wg_interface(env))
        step += 1
    finalize_install_output(env, deployment_name)
    print(f"Deployment env: {env_path}")
    print(f"Локальное состояние: {state_json_path(deployment_name)}")
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    return cmd_install(args)


def cmd_status(args: argparse.Namespace) -> int:
    roles = requested_roles(args.role)
    deployment_name, env_path, env, state, targets, preflights = prepare_remote_session(
        args.deployment,
        roles=roles,
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
    )
    print_summary(deployment_name, env, targets)
    print(f"Deployment env: {env_path}")
    return 0


def cmd_remote_action(args: argparse.Namespace) -> int:
    roles = requested_roles(args.role)
    deployment_name, env_path, env, state, targets, preflights = prepare_remote_session(
        args.deployment,
        roles=roles,
        require_privilege=True,
        allow_create=False,
        persist_local=True,
        confirm_existing_connections=True,
    )
    if args.action in {"install", "reinstall"} and ROLE_FOREIGN in roles:
        ensure_foreign_wan_interface(env, preflights[ROLE_FOREIGN])
        write_text(env_path, render_env_text(env))
    print_summary(deployment_name, env, targets)
    if not prompt_yes_no(f"Продолжить действие {args.action}?", default=False):
        print("Остановлено пользователем.")
        return 0
    run_selected_remote_action(args.action, deployment_name, env_path, env, targets, preflights, role_arg=args.role)
    if args.action in {"install", "reinstall"}:
        finalize_install_output(env, deployment_name)
    else:
        print_header("Готово")
        print(f"Deployment env: {env_path}")
        print(f"Локальное состояние: {state_json_path(deployment_name)}")
    return 0


def select_role_for_menu(command_name: str) -> str:
    if command_name not in {"status", "reinstall", "remove", "purge"}:
        return "all"
    return prompt_choice(
        "Какую часть контура нужно затронуть?",
        [
            ("all", "Обе роли: RU и Foreign"),
            (ROLE_RU, "Только RU сервер"),
            (ROLE_FOREIGN, "Только Foreign сервер"),
        ],
        default="all",
    )


def cmd_menu(_args: argparse.Namespace) -> int:
    print_header("VPN Installer")
    choice = prompt_choice(
        "Выбери действие",
        [
            ("install", "Установить или обновить VPN"),
            ("status", "Проверить текущее состояние"),
            ("reinstall", "Переустановить"),
            ("remove", "Удалить с серверов"),
            ("purge", "Полностью очистить состояние"),
            ("cleanup-local", "Удалить локальные файлы"),
            ("audit", "Запустить самопроверку"),
            ("exit", "Выход"),
        ],
        default="install",
    )
    if choice == "exit":
        print("Завершено.")
        return 0
    if choice == "audit":
        audit_mode = prompt_choice(
            "Какой режим самопроверки нужен?",
            [
                ("quick", "Быстрая локальная проверка"),
                ("docker", "Docker regression"),
                ("lab", "Глубокий Docker lab"),
                ("all", "Полный прогон"),
            ],
            default="quick",
        )
        return run_command([sys.executable, str(ROOT_DIR / "scripts" / "audit.py"), audit_mode], check=False).returncode
    if choice == "cleanup-local":
        ns = argparse.Namespace(deployment=None, drop_env=False, drop_runtime=False)
        return cmd_cleanup_local(ns)
    role = select_role_for_menu(choice)
    ns = argparse.Namespace(deployment=None, role=role)
    if choice == "install":
        return cmd_install(argparse.Namespace(deployment=None))
    if choice == "status":
        return cmd_status(ns)
    return cmd_remote_action(argparse.Namespace(deployment=None, role=role, action=choice))


def cmd_cleanup_local(args: argparse.Namespace) -> int:
    ensure_directories()
    deployment_name = select_deployment(args.deployment)
    removed: list[str] = []
    out_dir = OUT_DIR / deployment_name
    env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
    for path in (out_dir,):
        if path.is_dir():
            shutil.rmtree(path)
            removed.append(str(path))
    for path in (state_json_path(deployment_name), state_legacy_path(deployment_name)):
        if path.is_file():
            path.unlink()
            removed.append(str(path))
    if args.drop_env and env_path.is_file():
        env_path.unlink()
        removed.append(str(env_path))
    if args.drop_runtime and RUNTIME_DIR.is_dir():
        shutil.rmtree(RUNTIME_DIR)
        removed.append(str(RUNTIME_DIR))
    if removed:
        print("Удалено:")
        for item in removed:
            print(item)
    else:
        print("Локальные артефакты для этого deployment не найдены.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Локальный orchestration-слой для portable VPN stack.")
    subparsers = parser.add_subparsers(dest="command")
    menu = subparsers.add_parser("menu", help="Показать интерактивное меню.")
    menu.set_defaults(func=cmd_menu)
    install = subparsers.add_parser("install", help="Интерактивная установка или обновление.")
    install.add_argument("--deployment", help="Имя deployment.")
    install.set_defaults(func=cmd_install)
    bootstrap = subparsers.add_parser("bootstrap", help="Совместимость: вызывает install.")
    bootstrap.add_argument("--deployment", help="Имя deployment.")
    bootstrap.set_defaults(func=cmd_bootstrap)
    status = subparsers.add_parser("status", help="Проверить состояние серверов без изменений.")
    status.add_argument("--deployment", help="Имя deployment.")
    status.add_argument("--role", choices=["all", ROLE_RU, ROLE_FOREIGN], default="all", help="Какую роль проверять.")
    status.set_defaults(func=cmd_status)
    reinstall = subparsers.add_parser("reinstall", help="Переустановить одну роль или обе.")
    reinstall.add_argument("--deployment", help="Имя deployment.")
    reinstall.add_argument("--role", choices=["all", ROLE_RU, ROLE_FOREIGN], default="all", help="Какую роль затронуть.")
    reinstall.set_defaults(func=cmd_remote_action, action="reinstall")
    remove = subparsers.add_parser("remove", help="Удалить стек с сервера и восстановить baseline.")
    remove.add_argument("--deployment", help="Имя deployment.")
    remove.add_argument("--role", choices=["all", ROLE_RU, ROLE_FOREIGN], default="all", help="Какую роль затронуть.")
    remove.set_defaults(func=cmd_remote_action, action="remove")
    purge = subparsers.add_parser("purge", help="Удалить стек и вычистить его серверное состояние.")
    purge.add_argument("--deployment", help="Имя deployment.")
    purge.add_argument("--role", choices=["all", ROLE_RU, ROLE_FOREIGN], default="all", help="Какую роль затронуть.")
    purge.set_defaults(func=cmd_remote_action, action="purge")
    cleanup_local = subparsers.add_parser("cleanup-local", help="Удалить локальные артефакты deployment.")
    cleanup_local.add_argument("--deployment", help="Имя deployment.")
    cleanup_local.add_argument("--drop-env", action="store_true", help="Удалить и deployment env.")
    cleanup_local.add_argument("--drop-runtime", action="store_true", help="Удалить общий portable Python runtime.")
    cleanup_local.set_defaults(func=cmd_cleanup_local)
    init_env = subparsers.add_parser("init-env", help="Создать или обновить deployment env.")
    init_env.add_argument("output_env", help="Путь к env-файлу.")
    init_env.set_defaults(func=cmd_init_env)
    fetch_assets_parser = subparsers.add_parser("fetch-assets", help="Скачать rule-set и CIDR-ассеты.")
    fetch_assets_parser.add_argument("env_file", help="Путь к deployment env.")
    fetch_assets_parser.set_defaults(func=cmd_fetch_assets)
    render_config = subparsers.add_parser("render-config", help="Собрать preview серверных конфигов.")
    render_config.add_argument("env_file", help="Путь к deployment env.")
    render_config.set_defaults(func=cmd_render_config)
    clients = subparsers.add_parser("gen-client-profiles", help="Сгенерировать клиентские профили.")
    clients.add_argument("env_file", help="Путь к deployment env.")
    clients.set_defaults(func=cmd_gen_client_profiles)
    cloud_init = subparsers.add_parser("render-cloud-init", help="Сгенерировать cloud-init.")
    cloud_init.add_argument("env_file", help="Путь к deployment env.")
    cloud_init.set_defaults(func=cmd_render_cloud_init)
    bundle = subparsers.add_parser("package-bundle", help="Собрать переносимые tar.gz bundle.")
    bundle.add_argument("env_file", help="Путь к deployment env.")
    bundle.set_defaults(func=cmd_package_bundle)
    render_all = subparsers.add_parser("render-all", help="Собрать все локальные артефакты.")
    render_all.add_argument("env_file", help="Путь к deployment env.")
    render_all.set_defaults(func=cmd_render_all)
    parser.set_defaults(func=cmd_install, command="install")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        args = parser.parse_args(["install", *(argv or [])])
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.", file=sys.stderr)
        sys.exit(130)
    except AppError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)
