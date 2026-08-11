from __future__ import annotations

import ipaddress
from typing import Mapping

CONNTRACK_MAX = 32_768
FQ_KIND = "fq"
FQ_PACKET_LIMIT = 10_000
FQ_FLOW_LIMIT = 512
UDP_RMEM_DEFAULT = 8_388_608
UDP_RMEM_MAX = 16_777_216
UDP_WMEM_DEFAULT = 8_388_608
UDP_WMEM_MAX = 16_777_216
TCP_MTU_PROBE_FLOOR = 536
TCP_NO_METRICS_SAVE = 0
WIREGUARD_POLICY_PRIORITY = 10_000


def wireguard_policy_spec(env: Mapping[str, str]) -> dict[str, str | int]:
    """Normalize the RU policy-routing state shared by the renderer and agent."""

    return {
        "interface": env.get("WG_INTERFACE", "wg0") or "wg0",
        "table": int(env["WG_ROUTE_TABLE"], 0),
        "mark": int(env["APP_ROUTE_MARK"], 0),
        "priority": WIREGUARD_POLICY_PRIORITY,
        "ipv4_peer": str(ipaddress.ip_interface(env["WG_FOREIGN_ADDRESS"]).ip),
        "ipv6_peer": str(ipaddress.ip_interface(env["WG_FOREIGN_ADDRESS_V6"]).ip),
    }
