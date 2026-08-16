from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .config import DUAL_REQUIRED_ENV_VARS
from .models import REQUIRED_ENV_VARS
from .topology import TopologySpec, normalize_node_id


# The public SNI stays in client state; server-side target exceptions are versioned.
REALITY_HANDSHAKE_TARGETS = {"www.bing.com": "r.bing.com:443"}


def reality_handshake_target(server_name: str) -> str:
    normalized = server_name.strip().lower()
    if not normalized:
        raise ValueError("Reality server name must not be empty")
    return REALITY_HANDSHAKE_TARGETS.get(normalized, f"{normalized}:443")


@dataclass(frozen=True)
class DeploymentSpec:
    """Normalized deployment input consumed by rendering and install support."""

    values: dict[str, str]

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "DeploymentSpec":
        values = {str(key): str(value) for key, value in env.items()}
        topology = TopologySpec.from_env(values)
        values.update(topology.canonical_env_values())
        missing = [
            key
            for key in (*REQUIRED_ENV_VARS, *(DUAL_REQUIRED_ENV_VARS if topology.is_dual else ()))
            if not values.get(key, "").strip()
        ]
        if missing:
            raise ValueError(f"missing required deployment values: {', '.join(missing)}")
        return cls(values)

    @property
    def name(self) -> str:
        return self.values["DEPLOY_NAME"]

    @property
    def topology(self) -> TopologySpec:
        return TopologySpec.from_env(self.values)

    def for_role(self, role: str) -> "NodeDeploymentSpec":
        """One-release compatibility adapter; new code must use for_node()."""

        return self.for_node(role)

    def for_node(self, node_id: str) -> "NodeDeploymentSpec":
        return NodeDeploymentSpec(deployment=self, node_id=normalize_node_id(node_id))


@dataclass(frozen=True)
class NodeDeploymentSpec:
    deployment: DeploymentSpec
    node_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", normalize_node_id(self.node_id))
        self.deployment.topology.node(self.node_id)

    @property
    def values(self) -> dict[str, str]:
        return self.deployment.values

    @property
    def requires_xray(self) -> bool:
        return self.plan.requires_xray

    @property
    def plan(self):
        return self.deployment.topology.plan(self.node_id)

    @property
    def required_services(self) -> tuple[str, ...]:
        return self.plan.required_services
