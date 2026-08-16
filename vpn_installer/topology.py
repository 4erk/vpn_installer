from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Mapping


CONFIG_SCHEMA_VERSION = 2

TOPOLOGY_SINGLE = "single"
TOPOLOGY_DUAL = "dual"
TOPOLOGIES = frozenset({TOPOLOGY_SINGLE, TOPOLOGY_DUAL})

LOCATION_RU = "ru"
LOCATION_FOREIGN = "foreign"
LOCATIONS = frozenset({LOCATION_RU, LOCATION_FOREIGN})

NODE_GATEWAY = "gateway"
NODE_EXIT = "exit"
NODE_IDS = frozenset({NODE_GATEWAY, NODE_EXIT})

LEGACY_ROLE_RU = "ru-gateway"
LEGACY_ROLE_FOREIGN = "foreign-exit"
LEGACY_ROLE_TO_NODE = {
    LEGACY_ROLE_RU: NODE_GATEWAY,
    LEGACY_ROLE_FOREIGN: NODE_EXIT,
}
NODE_TO_LEGACY_ROLE = {value: key for key, value in LEGACY_ROLE_TO_NODE.items()}

CAP_PUBLIC_FRONT = "public-front"
CAP_ROUTER = "router"
CAP_WEB_ADMIN = "web-admin"
CAP_LOCAL_EGRESS = "local-egress"
CAP_RU_SPLIT_ROUTING = "ru-split-routing"
CAP_INTERSERVER_CLIENT = "interserver-client"
CAP_INTERSERVER_SERVER = "interserver-server"
CAP_NAT_EXIT = "nat-exit"

SINGLE_EGRESS_TAGS = ("local-egress",)
DUAL_EGRESS_TAGS = ("direct-ru", "to-foreign")

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def normalize_node_id(value: str) -> str:
    normalized = str(value).strip().lower()
    normalized = LEGACY_ROLE_TO_NODE.get(normalized, normalized)
    if normalized not in NODE_IDS:
        raise ValueError(f"unsupported node: {value}")
    return normalized


def legacy_role_for_node(node_id: str) -> str:
    return NODE_TO_LEGACY_ROLE[normalize_node_id(node_id)]


@dataclass(frozen=True)
class NodeSpec:
    node_id: str
    location: str
    public_ip: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", normalize_node_id(self.node_id))
        location = self.location.strip().lower()
        if location not in LOCATIONS:
            raise ValueError(f"unsupported node location: {self.location}")
        object.__setattr__(self, "location", location)
        public_ip = self.public_ip.strip()
        if public_ip:
            try:
                public_ip = str(ipaddress.ip_address(public_ip))
            except ValueError as exc:
                raise ValueError(f"invalid public IP for {self.node_id}: {self.public_ip}") from exc
        object.__setattr__(self, "public_ip", public_ip)


@dataclass(frozen=True)
class NodePlan:
    node: NodeSpec
    topology: str
    capabilities: frozenset[str]

    @property
    def node_id(self) -> str:
        return self.node.node_id

    @property
    def location(self) -> str:
        return self.node.location

    @property
    def public_ip(self) -> str:
        return self.node.public_ip

    @property
    def has_interserver(self) -> bool:
        return bool(self.capabilities & {CAP_INTERSERVER_CLIENT, CAP_INTERSERVER_SERVER})

    @property
    def requires_wireguard(self) -> bool:
        return self.has_interserver

    @property
    def requires_xray(self) -> bool:
        return CAP_PUBLIC_FRONT in self.capabilities

    @property
    def required_services(self) -> tuple[str, ...]:
        services = ["nftables", "sing-box", "resolver", "health_timer"]
        if self.requires_xray:
            services.append("xray")
        if CAP_WEB_ADMIN in self.capabilities:
            services.append("admin")
        if self.requires_wireguard:
            services.append("wireguard")
        if CAP_INTERSERVER_CLIENT in self.capabilities:
            services.append("transport")
        return tuple(services)


@dataclass(frozen=True)
class TopologySpec:
    mode: str
    gateway: NodeSpec
    exit: NodeSpec | None = None
    admin_web_enabled: bool = True

    def __post_init__(self) -> None:
        mode = self.mode.strip().lower()
        if mode not in TOPOLOGIES:
            raise ValueError(f"unsupported topology: {self.mode}")
        object.__setattr__(self, "mode", mode)
        if self.gateway.node_id != NODE_GATEWAY:
            raise ValueError("topology gateway must use the gateway node id")
        if mode == TOPOLOGY_SINGLE and self.exit is not None:
            raise ValueError("single topology cannot contain an exit node")
        if mode == TOPOLOGY_DUAL:
            if self.exit is None or self.exit.node_id != NODE_EXIT:
                raise ValueError("dual topology requires an exit node")
            if self.gateway.location != LOCATION_RU or self.exit.location != LOCATION_FOREIGN:
                raise ValueError("dual topology requires an RU gateway and a foreign exit")
            if self.gateway.public_ip and self.gateway.public_ip == self.exit.public_ip:
                raise ValueError("dual topology requires distinct gateway and exit public IPs")

    @property
    def is_dual(self) -> bool:
        return self.mode == TOPOLOGY_DUAL

    @property
    def nodes(self) -> tuple[NodeSpec, ...]:
        return (self.gateway,) if self.exit is None else (self.gateway, self.exit)

    @property
    def route_egresses(self) -> tuple[str, ...]:
        return DUAL_EGRESS_TAGS if self.is_dual else SINGLE_EGRESS_TAGS

    def node(self, node_id: str) -> NodeSpec:
        normalized = normalize_node_id(node_id)
        for node in self.nodes:
            if node.node_id == normalized:
                return node
        raise ValueError(f"node {normalized} is not configured for {self.mode} topology")

    def plan(self, node_id: str) -> NodePlan:
        node = self.node(node_id)
        if node.node_id == NODE_GATEWAY:
            capabilities = {
                CAP_PUBLIC_FRONT,
                CAP_ROUTER,
                CAP_LOCAL_EGRESS,
            }
            if self.admin_web_enabled:
                capabilities.add(CAP_WEB_ADMIN)
            if self.is_dual:
                capabilities.update({CAP_RU_SPLIT_ROUTING, CAP_INTERSERVER_CLIENT})
        else:
            capabilities = {CAP_INTERSERVER_SERVER, CAP_NAT_EXIT}
        return NodePlan(node=node, topology=self.mode, capabilities=frozenset(capabilities))

    @classmethod
    def from_env(cls, env: Mapping[str, str], *, require_addresses: bool = True) -> "TopologySpec":
        mode = str(env.get("TOPOLOGY", "")).strip().lower()
        if not mode:
            raise ValueError("TOPOLOGY is required in canonical env")
        gateway_location = str(env.get("GATEWAY_LOCATION", "")).strip().lower()
        if not gateway_location:
            raise ValueError("GATEWAY_LOCATION is required in canonical env")
        gateway_ip = str(env.get("GATEWAY_PUBLIC_IP", "")).strip()
        if require_addresses and not gateway_ip:
            raise ValueError("gateway public IP is required")
        gateway = NodeSpec(NODE_GATEWAY, gateway_location, gateway_ip)
        admin_web_enabled = str(env.get("ADMIN_WEB_ENABLED", "1")).strip().lower() in _TRUE_VALUES
        if mode == TOPOLOGY_SINGLE:
            if str(env.get("EXIT_PUBLIC_IP", "")).strip():
                raise ValueError("single topology cannot contain EXIT_PUBLIC_IP")
            return cls(mode=mode, gateway=gateway, admin_web_enabled=admin_web_enabled)
        exit_ip = str(env.get("EXIT_PUBLIC_IP", "")).strip()
        if require_addresses and not exit_ip:
            raise ValueError("exit public IP is required for dual topology")
        return cls(
            mode=mode,
            gateway=gateway,
            exit=NodeSpec(NODE_EXIT, LOCATION_FOREIGN, exit_ip),
            admin_web_enabled=admin_web_enabled,
        )

    def canonical_env_values(self) -> dict[str, str]:
        return {
            "CONFIG_SCHEMA": str(CONFIG_SCHEMA_VERSION),
            "TOPOLOGY": self.mode,
            "GATEWAY_LOCATION": self.gateway.location,
            "GATEWAY_PUBLIC_IP": self.gateway.public_ip,
            "EXIT_PUBLIC_IP": self.exit.public_ip if self.exit else "",
            "ADMIN_WEB_ENABLED": "1" if self.admin_web_enabled else "0",
        }


def execution_node_ids(action: str, topology: TopologySpec, selected: tuple[str, ...] | None = None) -> list[str]:
    available = {node.node_id for node in topology.nodes}
    requested = available if selected is None else {normalize_node_id(node_id) for node_id in selected}
    unknown = requested - available
    if unknown:
        raise ValueError(f"nodes are not configured for {topology.mode}: {', '.join(sorted(unknown))}")
    preferred = [NODE_EXIT, NODE_GATEWAY] if action in {"install", "reinstall"} else [NODE_GATEWAY, NODE_EXIT]
    return [node_id for node_id in preferred if node_id in requested]
