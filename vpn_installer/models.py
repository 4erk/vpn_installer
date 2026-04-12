from __future__ import annotations

from dataclasses import dataclass


class AppError(RuntimeError):
    pass


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
    "DEPLOY_NAME",
    "RU_PUBLIC_IP",
    "FOREIGN_PUBLIC_IP",
    "CLIENT_UUID",
    "RU_REALITY_SERVER_NAME",
    "RU_REALITY_HANDSHAKE_SERVER",
    "RU_REALITY_PRIVATE_KEY",
    "RU_REALITY_PUBLIC_KEY",
    "RU_REALITY_SHORT_ID",
    "WG_RU_ADDRESS",
    "WG_FOREIGN_ADDRESS",
    "WG_RU_PRIVATE_KEY",
    "WG_RU_PUBLIC_KEY",
    "WG_FOREIGN_PRIVATE_KEY",
    "WG_FOREIGN_PUBLIC_KEY",
    "WG_PRESHARED_KEY",
]

DEFAULT_ASSET_TIMEOUT = 30
X25519_P = 2**255 - 19
X25519_A24 = 121665


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
