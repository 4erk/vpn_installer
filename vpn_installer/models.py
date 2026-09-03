from __future__ import annotations

from dataclasses import dataclass, field

from .topology import LOCATION_FOREIGN, NODE_EXIT, NODE_GATEWAY, normalize_node_id


class AppError(RuntimeError):
    pass


class UserCancelled(AppError):
    pass


NODE_META = {
    NODE_GATEWAY: {"label": "Сервер входа", "prefix": "GATEWAY", "public_ip_key": "GATEWAY_PUBLIC_IP"},
    NODE_EXIT: {"label": "Сервер выхода", "prefix": "EXIT", "public_ip_key": "EXIT_PUBLIC_IP"},
}

ALLOW_EMPTY_OVERRIDE = {
    "GATEWAY_PUBLIC_IP",
    "EXIT_PUBLIC_IP",
    "WAN_INTERFACE",
    "CLIENT_ROUTE_EXCLUDE_V4",
    "CLIENT_ROUTE_EXCLUDE_V6",
    "RU_FORCE_DIRECT_DOMAIN",
    "RU_FORCE_DIRECT_DOMAIN_SUFFIX",
    "RU_FORCE_DIRECT_IP_CIDR",
    "RU_BLOCK_IP_CIDR",
}

ENV_SECTIONS = [
    ("", ["CONFIG_SCHEMA", "DEPLOY_NAME"]),
    ("# Deployment topology", ["TOPOLOGY", "GATEWAY_LOCATION", "GATEWAY_PUBLIC_IP", "EXIT_PUBLIC_IP"]),
    ("# SSH access", ["SSH_PORT"]),
    ("# Foreign egress NIC override. Leave empty to auto-detect on the foreign host.", ["WAN_INTERFACE"]),
    ("# Xray public VLESS/REALITY front + sing-box local router", ["CLIENT_UUID", "CLIENT_FLOW", "RU_LISTEN_PORT", "RU_ROUTER_LISTEN_PORT", "RU_REALITY_SERVER_NAME", "RU_REALITY_PRIVATE_KEY", "RU_REALITY_PUBLIC_KEY", "RU_REALITY_SHORT_ID", "RU_REALITY_ACCEPT_EMPTY_SHORT_ID", "RU_REALITY_MAX_TIME_DIFFERENCE", "UTLS_FINGERPRINT", "SING_BOX_LOG_LEVEL", "RU_SNIFF_TIMEOUT"]),
    ("# WireGuard between RU and foreign", ["WG_INTERFACE", "WG_PORT", "WG_MTU", "WG_ROUTE_TABLE", "APP_ROUTE_MARK", "WG_TUNNEL_FWMARK", "WG_RU_ADDRESS", "WG_FOREIGN_ADDRESS", "WG_RU_ADDRESS_V6", "WG_FOREIGN_ADDRESS_V6", "WG_IPV6_PREFIX", "WG_RU_PRIVATE_KEY", "WG_RU_PUBLIC_KEY", "WG_FOREIGN_PRIVATE_KEY", "WG_FOREIGN_PUBLIC_KEY", "WG_PRESHARED_KEY"]),
    ("# Generated identity for the public Hysteria2 gateway", ["PUBLIC_HY2_CERTIFICATE_B64", "PUBLIC_HY2_PRIVATE_KEY_B64", "PUBLIC_HY2_PUBLIC_KEY_SHA256"]),
    ("# Generated identity for the resilient interserver transport", ["INTERSERVER_HY2_CERTIFICATE_B64", "INTERSERVER_HY2_PRIVATE_KEY_B64", "INTERSERVER_HY2_PUBLIC_KEY_SHA256"]),
    ("# DNS policy", ["GLOBAL_DOH_SERVER", "GLOBAL_DOH_SERVER_NAME", "GLOBAL_DOH_PATH"]),
    ("# Explicit Russian routing policy; diagnostics must not add production route exceptions", ["RU_FORCE_DIRECT_DOMAIN", "RU_FORCE_DIRECT_DOMAIN_SUFFIX", "RU_FORCE_DIRECT_IP_CIDR", "RU_BLOCK_IP_CIDR"]),
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
            "ADMIN_WEB_PORT",
            "ADMIN_WEB_USERNAME",
            "ADMIN_WEB_PASSWORD",
        ],
    ),
    ("# Client tun profile", ["CLIENT_TUN_NAME", "CLIENT_TUN_ADDRESS_V4", "CLIENT_TUN_ADDRESS_V6", "CLIENT_FAKEIP_V4", "CLIENT_FAKEIP_V6", "CLIENT_ENABLE_IPV6"]),
    ("# Optional extra route exclusions on the client profile", ["CLIENT_ROUTE_EXCLUDE_V4", "CLIENT_ROUTE_EXCLUDE_V6"]),
]

REQUIRED_ENV_VARS = [
    "DEPLOY_NAME",
    "GATEWAY_PUBLIC_IP",
    "CLIENT_UUID",
    "RU_REALITY_SERVER_NAME",
    "RU_REALITY_PRIVATE_KEY",
    "RU_REALITY_PUBLIC_KEY",
    "RU_REALITY_SHORT_ID",
    "PUBLIC_HY2_CERTIFICATE_B64",
    "PUBLIC_HY2_PRIVATE_KEY_B64",
    "PUBLIC_HY2_PUBLIC_KEY_SHA256",
]

DEFAULT_ASSET_TIMEOUT = 30


@dataclass
class RemoteTarget:
    node_id: str
    location: str = ""
    public_ip: str = ""
    ssh_host: str = ""
    ssh_port: int = 22
    ssh_user: str = "root"
    auth_mode: str = "key"
    identity_path: str = ""
    ssh_bind_address: str = ""
    ssh_password: str = field(default="", repr=False)
    sudo_mode: str = "unknown"
    sudo_password: str = field(default="", repr=False)
    save_ssh_password: bool = field(default=False, repr=False)
    saved_connection: bool = False

    def __post_init__(self) -> None:
        self.node_id = normalize_node_id(self.node_id)

    @property
    def label(self) -> str:
        if self.node_id == NODE_GATEWAY and self.location == LOCATION_FOREIGN:
            return "VPN-шлюз (зарубежный сервер)"
        return NODE_META[self.node_id]["label"]

    def to_state(self) -> dict[str, str]:
        return {
            "location": self.location,
            "public_ip": self.public_ip,
            "ssh_host": self.ssh_host,
            "ssh_port": str(self.ssh_port),
            "ssh_user": self.ssh_user,
            "auth_mode": self.auth_mode,
            "identity_path": self.identity_path,
        }
