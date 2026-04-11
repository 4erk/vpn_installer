#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import base64
import getpass
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
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
    identity_path: str = ""
    sudo_mode: str = "unknown"
    sudo_password: str = ""

    @property
    def label(self) -> str:
        return ROLE_META[self.role]["label"]

    def to_state(self) -> dict[str, str]:
        return {
            "public_ip": self.public_ip,
            "ssh_host": self.ssh_host,
            "ssh_port": str(self.ssh_port),
            "ssh_user": self.ssh_user,
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
        ROLE_RU: {"public_ip": legacy.get("RU_PUBLIC_IP", ""), "ssh_host": legacy.get("RU_SSH_HOST", ""), "ssh_port": legacy.get("RU_SSH_PORT", "22"), "ssh_user": legacy.get("RU_SSH_USER", "root"), "identity_path": legacy.get("RU_IDENTITY_PATH", "")},
        ROLE_FOREIGN: {"public_ip": legacy.get("FOREIGN_PUBLIC_IP", ""), "ssh_host": legacy.get("FOREIGN_SSH_HOST", ""), "ssh_port": legacy.get("FOREIGN_SSH_PORT", "22"), "ssh_user": legacy.get("FOREIGN_SSH_USER", "root"), "identity_path": legacy.get("FOREIGN_IDENTITY_PATH", "")},
    }


def write_state(deployment_name: str, targets: list[RemoteTarget]) -> None:
    payload = {"updated_at": utc_now(), ROLE_RU: {}, ROLE_FOREIGN: {}}
    for target in targets:
        payload[target.role] = target.to_state()
    write_json(state_json_path(deployment_name), payload)


def build_target(role: str, env: dict[str, str], state: dict[str, Any]) -> RemoteTarget:
    role_state = state.get(role, {})
    public_ip_key = ROLE_META[role]["public_ip_key"]
    ssh_port_raw = str(role_state.get("ssh_port") or env.get("SSH_PORT", "22") or "22")
    try:
        ssh_port = int(ssh_port_raw)
    except ValueError as exc:
        raise AppError(f"Некорректный SSH port для {ROLE_META[role]['label']}: {ssh_port_raw}") from exc
    public_ip = str(role_state.get("public_ip") or env.get(public_ip_key, ""))
    return RemoteTarget(
        role=role,
        public_ip=public_ip,
        ssh_host=str(role_state.get("ssh_host") or public_ip),
        ssh_port=ssh_port,
        ssh_user=str(role_state.get("ssh_user") or "root"),
        identity_path=str(role_state.get("identity_path") or ""),
    )


def prompt_value(label: str, default: str | None = None, allow_empty: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default not in (None, "") else ""
        value = input(f"{label}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        if allow_empty:
            return ""


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


def normalize_identity_path(raw_path: str) -> str:
    raw_path = raw_path.strip()
    if not raw_path:
        return ""
    path = Path(raw_path).expanduser()
    path = (Path.cwd() / path).resolve() if not path.is_absolute() else path.resolve()
    return str(path)


def prompt_server_connection(target: RemoteTarget) -> RemoteTarget:
    target.public_ip = prompt_value(f"{target.label}: публичный IP", target.public_ip or None)
    target.ssh_host = prompt_value(f"{target.label}: SSH host/IP", target.ssh_host or target.public_ip or None)
    ssh_port_raw = prompt_value(f"{target.label}: SSH port", str(target.ssh_port))
    target.ssh_user = prompt_value(f"{target.label}: SSH user", target.ssh_user or "root")
    identity_raw = prompt_value(f"{target.label}: путь к SSH key (пусто = ssh-agent / стандартный ключ)", target.identity_path or None, allow_empty=True)
    target.identity_path = normalize_identity_path(identity_raw)
    if target.identity_path and not Path(target.identity_path).is_file():
        fail(f"Не найден SSH key: {target.identity_path}")
    try:
        target.ssh_port = int(ssh_port_raw)
    except ValueError as exc:
        raise AppError(f"Некорректный SSH port: {ssh_port_raw}") from exc
    return target


def find_existing_deployments() -> list[str]:
    names: list[str] = []
    for env_path in sorted(DEPLOYMENTS_DIR.glob("*.env")):
        if env_path.name != "deployment.env.example":
            names.append(env_path.stem)
    return names


def select_deployment(cli_name: str | None) -> str:
    if cli_name:
        deployment_name = sanitize_name(cli_name)
        if not deployment_name:
            fail("Пустое имя deployment.")
        return deployment_name

    existing = find_existing_deployments()
    if not existing:
        deployment_name = sanitize_name(prompt_value("Имя нового deployment"))
        if not deployment_name:
            fail("Пустое имя deployment.")
        return deployment_name

    print_header("Выбор deployment")
    for index, name in enumerate(existing, start=1):
        print(f"{index}. {name}")
    print(f"{len(existing) + 1}. Создать новый deployment")

    while True:
        selection_raw = input("Выберите deployment [1]: ").strip() or "1"
        if not selection_raw.isdigit():
            continue
        selection = int(selection_raw)
        if 1 <= selection <= len(existing):
            return existing[selection - 1]
        if selection == len(existing) + 1:
            deployment_name = sanitize_name(prompt_value("Имя нового deployment"))
            if not deployment_name:
                fail("Пустое имя deployment.")
            return deployment_name


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


def ssh_capture(target: RemoteTarget, command_body: str, *, as_root: bool = False) -> str:
    remote_command, input_text = build_remote_command(command_body, target, as_root)
    completed = run_command(ssh_base_args(target) + [remote_command], capture_output=True, input_text=input_text)
    return completed.stdout


def ssh_stream(target: RemoteTarget, command_body: str, *, as_root: bool = False) -> None:
    remote_command, input_text = build_remote_command(command_body, target, as_root)
    run_command(ssh_base_args(target) + [remote_command], input_text=input_text)


def scp_upload(target: RemoteTarget, local_path: Path, remote_path: str) -> None:
    run_command(scp_base_args(target) + [str(local_path), f"{target.ssh_user}@{target.ssh_host}:{remote_path}"])


def parse_kv_output(payload: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in payload.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def preflight_script() -> str:
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
        printf 'wireguard=%s\\n' "$(service_state wg-quick@wg0)"
        printf 'sync_timer=%s\\n' "$(service_state vpn-stack-sync.timer)"
        """
    ).strip()


def remote_preflight(target: RemoteTarget) -> dict[str, str]:
    return parse_kv_output(ssh_capture(target, preflight_script()))


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


def ensure_remote_privilege(target: RemoteTarget, preflight: dict[str, str]) -> None:
    if preflight.get("is_root") == "1":
        target.sudo_mode = "root"
        return
    if preflight.get("has_sudo") == "1":
        target.sudo_mode = "nopasswd"
        return
    if not prompt_yes_no(f"Пользователь {preflight.get('login_user', 'unknown')} на {preflight.get('hostname', 'unknown')} не root и без passwordless sudo. Попробовать sudo по паролю?", default=True):
        fail(f"Для {target.label} нужен root или sudo.")
    target.sudo_mode = "password"
    target.sudo_password = prompt_secret(f"Введите sudo-пароль для {target.label}")


def ask_install_action(role: str, deployment_name: str, preflight: dict[str, str]) -> str:
    if preflight.get("installed") != "1":
        return "install"
    existing_role = preflight.get("role", "")
    existing_deployment = preflight.get("deployment_name", "")
    if existing_role and existing_role != role:
        print(f"На {ROLE_META[role]['label']} уже стоит роль {existing_role} (deployment: {existing_deployment or '-'})")
        return "reinstall" if prompt_yes_no("Переустановить эту роль?", default=False) else "skip"
    if existing_deployment and existing_deployment != deployment_name:
        print(f"На сервере уже найден другой deployment: {existing_deployment}")
    return "update" if prompt_yes_no(f"Обновить {ROLE_META[role]['label']}?", default=True) else "skip"


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
    if env.get("FOREIGN_BLOCK_RU", "1") == "1":
        targets["ru-ipv4.zone"] = (env["FOREIGN_RU_IPV4_LIST_URL"], assets_dir / "ru-ipv4.zone")
        targets["ru-ipv6.zone"] = (env["FOREIGN_RU_IPV6_LIST_URL"], assets_dir / "ru-ipv6.zone")
    fetched: dict[str, Path] = {}
    print_header("Подкачка rule-set и CIDR-ассетов")
    for asset_name, (url, path) in targets.items():
        try:
            download_file(url, path)
            fetched[asset_name] = path
            print(f"{asset_name}: OK")
        except (urllib.error.URLError, OSError) as exc:
            if path.exists():
                warn(f"{asset_name}: не удалось обновить, оставляю локальную копию ({exc})")
                fetched[asset_name] = path
            else:
                warn(f"{asset_name}: не удалось скачать ({exc})")
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
                "sniff": True,
                "sniff_override_destination": True,
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
            "rule_set": [
                {"type": "local", "tag": "geosite-ru", "format": "binary", "path": f"{env['RULESET_DIR']}/geosite-ru.srs"},
                {"type": "local", "tag": "geoip-ru", "format": "binary", "path": f"{env['RULESET_DIR']}/geoip-ru.srs"},
            ],
            "rules": [
                {"ip_version": 6, "action": "route", "outbound": "blocked"},
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
    client_dir = deployment_out_dir(env) / "client"
    write_text(client_dir / "hiddify-cross-platform.json", render_client_profile(env, auto_redirect=False))
    write_text(client_dir / "linux-sing-box.json", render_client_profile(env, auto_redirect=True))
    write_text(client_dir / "vless-uri.txt", render_vless_uri(env))
    return client_dir


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


def postcheck_command() -> str:
    return textwrap.dedent(
        """\
        set -euo pipefail
        systemctl is-active nftables >/dev/null
        systemctl is-active vpn-stack-sync.timer >/dev/null
        systemctl is-active wg-quick@wg0 >/dev/null
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
    ).strip()


def install_remote_role(target: RemoteTarget, deployment_name: str, env: dict[str, str]) -> None:
    bundle_path = deployment_out_dir(env) / "bundle" / f"{target.role}.tar.gz"
    if not bundle_path.is_file():
        fail(f"Не найден bundle для {target.label}: {bundle_path}")
    remote_root = f"~/vpn-installer/{deployment_name}/{target.role}"
    archive_name = f"{target.role}.tar.gz"
    print_header(f"Загрузка bundle на {target.label}")
    ssh_stream(target, f"rm -rf {shlex.quote(remote_root)} && mkdir -p {shlex.quote(remote_root)}")
    scp_upload(target, bundle_path, f"{remote_root}/{archive_name}")
    print_header(f"Установка {target.label}")
    install_command = f"cd {shlex.quote(remote_root)} && tar -xzf {shlex.quote(f'{remote_root}/{archive_name}')} && chmod +x ./install.sh && ./install.sh --role {shlex.quote(target.role)} --env-file ./deployment.env --assets-dir ./assets"
    ssh_stream(target, install_command, as_root=True)


def postcheck_remote_role(target: RemoteTarget) -> None:
    print_header(f"Пост-проверка {target.label}")
    ssh_stream(target, postcheck_command(), as_root=True)


def print_summary(deployment_name: str, env: dict[str, str], targets: list[RemoteTarget]) -> None:
    print_header("Сводка deployment")
    print(f"deployment: {deployment_name}")
    print(f"RU public IP: {env.get('RU_PUBLIC_IP', '-')}")
    print(f"Foreign public IP: {env.get('FOREIGN_PUBLIC_IP', '-')}")
    for target in targets:
        print(f"{target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port}")
    print(f"WAN_INTERFACE: {env.get('WAN_INTERFACE') or '-'}")


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


def cmd_bootstrap(args: argparse.Namespace) -> int:
    require_local_commands(["ssh", "scp"])
    ensure_directories()
    deployment_name = select_deployment(args.deployment)
    env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
    env = ensure_deployment_env(env_path, deployment_name)
    state = load_state(deployment_name)
    print_header("Параметры deployment")
    ru_target = prompt_server_connection(build_target(ROLE_RU, env, state))
    foreign_target = prompt_server_connection(build_target(ROLE_FOREIGN, env, state))
    targets = [ru_target, foreign_target]
    update_env_with_targets(env, targets)
    write_text(env_path, render_env_text(env))
    write_state(deployment_name, targets)
    ru_preflight = remote_preflight(ru_target)
    foreign_preflight = remote_preflight(foreign_target)
    print_preflight(ru_target, ru_preflight)
    print_preflight(foreign_target, foreign_preflight)
    if ru_preflight.get("os_id") != "ubuntu":
        fail("RU gateway должен быть Ubuntu.")
    if foreign_preflight.get("os_id") != "ubuntu":
        fail("Foreign exit должен быть Ubuntu.")
    if ru_preflight.get("os_version") and ru_preflight["os_version"] != "24.04":
        warn(f"RU gateway не на Ubuntu 24.04: {ru_preflight['os_version']}")
    if foreign_preflight.get("os_version") and foreign_preflight["os_version"] != "24.04":
        warn(f"Foreign exit не на Ubuntu 24.04: {foreign_preflight['os_version']}")
    ensure_remote_privilege(ru_target, ru_preflight)
    ensure_remote_privilege(foreign_target, foreign_preflight)
    ensure_foreign_wan_interface(env, foreign_preflight)
    write_text(env_path, render_env_text(env))
    write_state(deployment_name, targets)
    print_summary(deployment_name, env, targets)
    if not prompt_yes_no("Продолжить сборку и установку?", default=True):
        print("Остановлено пользователем.")
        return 0
    print_header("Локальная сборка артефактов")
    out_dir = render_all_artifacts(env_path, env)
    foreign_action = ask_install_action(ROLE_FOREIGN, deployment_name, foreign_preflight)
    ru_action = ask_install_action(ROLE_RU, deployment_name, ru_preflight)
    if foreign_action != "skip":
        install_remote_role(foreign_target, deployment_name, env)
        postcheck_remote_role(foreign_target)
    else:
        print("Foreign exit: пропуск установки.")
    if ru_action != "skip":
        install_remote_role(ru_target, deployment_name, env)
        postcheck_remote_role(ru_target)
    else:
        print("RU gateway: пропуск установки.")
    print_header("Готово")
    print(f"Локальные артефакты: {out_dir}")
    print(f"Deployment env: {env_path}")
    print(f"Локальное состояние: {state_json_path(deployment_name)}")
    print(f"Клиентские профили: {out_dir / 'client'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Локальный orchestration-слой для portable VPN stack.")
    subparsers = parser.add_subparsers(dest="command")
    bootstrap = subparsers.add_parser("bootstrap", help="Интерактивный полный сценарий.")
    bootstrap.add_argument("--deployment", help="Имя deployment.")
    bootstrap.set_defaults(func=cmd_bootstrap)
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
    parser.set_defaults(func=cmd_bootstrap, command="bootstrap")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        args = parser.parse_args(["bootstrap", *(argv or [])])
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
