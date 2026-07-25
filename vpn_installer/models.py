from __future__ import annotations

from dataclasses import dataclass


class AppError(RuntimeError):
    pass


class UserCancelled(AppError):
    pass


ROLE_RU = "ru-gateway"
ROLE_FOREIGN = "foreign-exit"
ROLE_META = {
    ROLE_RU: {"label": "Российский сервер", "prefix": "RU", "public_ip_key": "RU_PUBLIC_IP"},
    ROLE_FOREIGN: {"label": "Зарубежный сервер", "prefix": "FOREIGN", "public_ip_key": "FOREIGN_PUBLIC_IP"},
}

ALLOW_EMPTY_OVERRIDE = {
    "RU_PUBLIC_IP",
    "FOREIGN_PUBLIC_IP",
    "WAN_INTERFACE",
    "CLIENT_ROUTE_EXCLUDE_V4",
    "CLIENT_ROUTE_EXCLUDE_V6",
    "RU_FORCE_DIRECT_DOMAIN",
    "RU_FORCE_DIRECT_DOMAIN_SUFFIX",
    "RU_FORCE_DIRECT_IP_CIDR",
    "RU_BLOCK_IP_CIDR",
}

ENV_SECTIONS = [
    ("", ["DEPLOY_NAME"]),
    ("# Public addresses", ["RU_PUBLIC_IP", "FOREIGN_PUBLIC_IP"]),
    ("# SSH access and daemon hardening", ["SSH_PORT", "SSH_LOGIN_GRACE_TIME", "SSH_MAX_AUTH_TRIES", "SSH_MAX_STARTUPS", "SSH_PER_SOURCE_MAX_STARTUPS", "SSH_PER_SOURCE_NETBLOCK_SIZE"]),
    ("# Foreign egress NIC override. Leave empty to auto-detect on the foreign host.", ["WAN_INTERFACE"]),
    ("# Xray public VLESS/REALITY front + sing-box local router", ["CLIENT_UUID", "CLIENT_FLOW", "RU_LISTEN_PORT", "RU_ROUTER_LISTEN_PORT", "RU_REALITY_SERVER_NAME", "RU_REALITY_HANDSHAKE_SERVER", "RU_REALITY_HANDSHAKE_PORT", "RU_REALITY_PRIVATE_KEY", "RU_REALITY_PUBLIC_KEY", "RU_REALITY_SHORT_ID", "RU_REALITY_ACCEPT_EMPTY_SHORT_ID", "RU_REALITY_MAX_TIME_DIFFERENCE", "UTLS_FINGERPRINT", "SING_BOX_LOG_LEVEL", "RU_SNIFF_TIMEOUT"]),
    ("# WireGuard between RU and foreign", ["WG_INTERFACE", "WG_PORT", "WG_MTU", "WG_KEEPALIVE", "WG_ROUTE_TABLE", "APP_ROUTE_MARK", "WG_TUNNEL_FWMARK", "WG_RU_ADDRESS", "WG_FOREIGN_ADDRESS", "WG_RU_ADDRESS_V6", "WG_FOREIGN_ADDRESS_V6", "WG_IPV6_PREFIX", "WG_RU_PRIVATE_KEY", "WG_RU_PUBLIC_KEY", "WG_FOREIGN_PRIVATE_KEY", "WG_FOREIGN_PUBLIC_KEY", "WG_PRESHARED_KEY"]),
    ("# Generated identity for the resilient interserver transport", ["INTERSERVER_HY2_CERTIFICATE_B64", "INTERSERVER_HY2_PRIVATE_KEY_B64", "INTERSERVER_HY2_PUBLIC_KEY_SHA256"]),
    ("# DNS policy", ["GLOBAL_DOH_SERVER", "GLOBAL_DOH_SERVER_NAME", "GLOBAL_DOH_PATH"]),
    ("# Forced policy rules for the Russian server: Russian APIs, reachability checks, IP-check services", ["RU_FORCE_DIRECT_DOMAIN", "RU_FORCE_DIRECT_DOMAIN_SUFFIX", "RU_FORCE_DIRECT_IP_CIDR", "RU_BLOCK_IP_CIDR"]),
    ("# Rule assets for the RU server. Several source URLs can be listed through spaces.", ["RULESET_DIR", "RU_GEOSITE_URL", "RU_GEOIP_URL"]),
    ("# Optional RU egress deny list on the foreign server. Several source URLs can be listed through spaces.", ["FOREIGN_BLOCK_RU", "FOREIGN_RU_IPV4_LIST_URL", "FOREIGN_RU_IPV6_LIST_URL"]),
    (
        "# Managed diagnostics, recovery and maintenance",
        [
            "JOURNAL_LIMIT_ENABLED",
            "JOURNAL_SYSTEM_MAX_USE",
            "JOURNAL_MAX_RETENTION_SEC",
        ],
    ),
    (
        "# Optional web admin for server-side routing exceptions",
        [
            "ADMIN_WEB_ENABLED",
            "ADMIN_WEB_BIND",
            "ADMIN_WEB_PORT",
            "ADMIN_WEB_ACTIVE_CLIENT_REQUIRED",
            "ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS",
            "ADMIN_WEB_ALLOW_TUNNEL_CLIENTS",
            "ADMIN_WEB_ALLOWED_CIDR",
            "ADMIN_WEB_ALLOW_WG",
            "ADMIN_WEB_USERNAME",
            "ADMIN_WEB_PASSWORD",
        ],
    ),
    ("# Client tun profile", ["CLIENT_TUN_NAME", "CLIENT_TUN_ADDRESS_V4", "CLIENT_TUN_ADDRESS_V6", "CLIENT_FAKEIP_V4", "CLIENT_FAKEIP_V6", "CLIENT_ENABLE_IPV6"]),
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
    "WG_RU_ADDRESS_V6",
    "WG_FOREIGN_ADDRESS_V6",
    "WG_IPV6_PREFIX",
    "WG_RU_PRIVATE_KEY",
    "WG_RU_PUBLIC_KEY",
    "WG_FOREIGN_PRIVATE_KEY",
    "WG_FOREIGN_PUBLIC_KEY",
    "WG_PRESHARED_KEY",
    "INTERSERVER_HY2_CERTIFICATE_B64",
    "INTERSERVER_HY2_PRIVATE_KEY_B64",
    "INTERSERVER_HY2_PUBLIC_KEY_SHA256",
]

DEFAULT_ASSET_TIMEOUT = 30
CONNTRACK_MAX = 32_768
UDP_RMEM_DEFAULT = 8_388_608
UDP_RMEM_MAX = 16_777_216
UDP_WMEM_MAX = 16_777_216
TCP_MTU_PROBE_FLOOR = 536
TCP_NO_METRICS_SAVE = 1
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
    ssh_bind_address: str = ""
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
