from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class DiagnosticsSnapshot:
    schema_version: int = 2
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    deployment: str = ""
    role: str = ""
    services: dict[str, str] = field(default_factory=dict)
    installed_env_hash: str = ""
    installed_config_hash: str = ""
    rendered_config_hash: str = ""
    render_manifest: dict[str, Any] = field(default_factory=dict)
    drift: str = "unknown"
    wg_state: dict[str, str] = field(default_factory=dict)
    route_probes: dict[str, str] = field(default_factory=dict)
    runtime_overrides: dict[str, str] = field(default_factory=dict)
    log_buckets: dict[str, int] = field(default_factory=dict)
    historical_log_buckets: dict[str, int] = field(default_factory=dict)
    top_destinations: dict[str, str] = field(default_factory=dict)
    fresh_since: str = ""
    fresh_window_minutes: int = 30
    historical_window_hours: int = 4
    verdict: str = "inconclusive"
    reasons: list[str] = field(default_factory=list)
    release: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    front: dict[str, Any] = field(default_factory=dict)
    transport: dict[str, Any] = field(default_factory=dict)
    maintenance: dict[str, Any] = field(default_factory=dict)
    component_verdicts: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json(cls, payload: str) -> "DiagnosticsSnapshot":
        data = json.loads(payload)
        if int(data.get("schema_version", 0)) != 2:
            raise ValueError("unsupported diagnostics snapshot schema")
        return cls(**data)

    @classmethod
    def from_agent(cls, payload: dict[str, Any]) -> "DiagnosticsSnapshot":
        if int(payload.get("schema_version", 0)) != 2:
            raise ValueError("unsupported vpn-stack-agent snapshot schema")
        logs = payload.get("logs", {})
        windows = logs.get("windows_minutes", {})
        recent = logs.get("fresh", windows.get("30", {}))
        historical = windows.get("1440", {})
        artifacts = payload.get("artifacts", {})
        verdicts = payload.get("verdicts", {})
        return cls(
            schema_version=2,
            generated_at=str(payload.get("generated_at", "")),
            deployment=str(payload.get("deployment", "")),
            role=str(payload.get("role", "")),
            services={str(key): str(value) for key, value in payload.get("services", {}).items()},
            installed_env_hash=str(artifacts.get("installed_env_sha256", "")),
            installed_config_hash=str(artifacts.get("files", {}).get("sing-box.json", {}).get("actual_sha256", "")),
            rendered_config_hash=str(artifacts.get("files", {}).get("sing-box.json", {}).get("expected_sha256", "")),
            render_manifest=artifacts.get("manifest", {}),
            drift=str(artifacts.get("drift", "unknown")),
            wg_state=payload.get("wireguard", {}),
            route_probes=payload.get("probes", {}),
            runtime_overrides={},
            log_buckets={str(key): int(value) for key, value in recent.get("counts", {}).items()},
            historical_log_buckets={str(key): int(value) for key, value in historical.get("counts", {}).items()},
            top_destinations={str(key): json.dumps(value, ensure_ascii=False, sort_keys=True) for key, value in recent.get("top_destinations", {}).items()},
            fresh_since=str(recent.get("since", "")),
            fresh_window_minutes=int(recent.get("window_minutes", 30)),
            historical_window_hours=24 if "1440" in windows else 0,
            verdict=str(verdicts.get("overall", "inconclusive")),
            reasons=[str(value) for value in verdicts.get("reasons", [])],
            release=payload.get("release", {}),
            artifacts=artifacts,
            network=payload.get("network", {}),
            front=payload.get("front", {}),
            transport=payload.get("transport", {}),
            maintenance=payload.get("maintenance", {}),
            component_verdicts={key: str(value) for key, value in verdicts.items() if key != "reasons"},
        )
