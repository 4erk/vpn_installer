from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .models import REQUIRED_ENV_VARS, ROLE_FOREIGN, ROLE_RU


@dataclass(frozen=True)
class DeploymentSpec:
    """Normalized deployment input consumed by rendering and install support."""

    values: dict[str, str]

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "DeploymentSpec":
        values = {str(key): str(value) for key, value in env.items()}
        missing = [key for key in REQUIRED_ENV_VARS if not values.get(key, "").strip()]
        if missing:
            raise ValueError(f"missing required deployment values: {', '.join(missing)}")
        return cls(values)

    @property
    def name(self) -> str:
        return self.values["DEPLOY_NAME"]

    def for_role(self, role: str) -> "RoleSpec":
        return RoleSpec(deployment=self, role=role)


@dataclass(frozen=True)
class RoleSpec:
    deployment: DeploymentSpec
    role: str

    def __post_init__(self) -> None:
        if self.role not in {ROLE_RU, ROLE_FOREIGN}:
            raise ValueError(f"unsupported role: {self.role}")

    @property
    def values(self) -> dict[str, str]:
        return self.deployment.values

    @property
    def requires_xray(self) -> bool:
        return self.role == ROLE_RU

    @property
    def required_services(self) -> tuple[str, ...]:
        base = ("wireguard", "nftables")
        return ("sing-box", "xray", *base) if self.requires_xray else base
