from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Mapping

try:
    from .log_classifier import BUCKETS
except ImportError:  # Installed beside vpn-stack-agent.py as a standalone module.
    from log_classifier import BUCKETS  # type: ignore[no-redef]


SCHEMA_VERSION = 3
COLLECTOR_STATUSES = frozenset({"ok", "error", "stale", "skipped"})
LOG_WINDOW_KEYS = ("5m", "30m", "24h", "since_release")
COLLECTOR_NAMES = (
    "services",
    "artifacts",
    "wireguard",
    "route_probes",
    "logs",
    "storage",
    "network",
    "front",
    "transport",
    "maintenance",
)


def classify_interserver_adaptation(state: Mapping[str, Any]) -> tuple[str, str]:
    """Return mutually exclusive hard-failure and degradation reasons."""

    adaptation_state = str(state.get("state", ""))
    if not adaptation_state:
        return "interserver_adaptation=missing", ""
    if adaptation_state == "failed":
        return f"interserver_adaptation={state.get('reason') or 'failed'}", ""
    if state.get("fresh") is not True:
        return "", "interserver_adaptation=stale"
    if adaptation_state in {"degraded", "recovering", "suspect", "inconclusive", "maintenance"}:
        return "", f"interserver_adaptation={adaptation_state}"
    return "", ""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _mapping(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


@dataclass(frozen=True)
class CollectorState:
    status: str
    observed_at: str | None = None
    message: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, str) or self.status not in COLLECTOR_STATUSES:
            raise ValueError(f"invalid collector status: {self.status!r}")
        if self.observed_at is not None and not isinstance(self.observed_at, str):
            raise TypeError("collector observed_at must be a string or null")
        if not isinstance(self.message, str):
            raise TypeError("collector message must be a string")
        if self.status in {"error", "skipped"} and not self.message:
            raise ValueError(f"{self.status} collector status requires a message")
        if self.status in {"ok", "stale"} and not self.observed_at:
            raise ValueError(f"{self.status} collector status requires observed_at")

    @classmethod
    def ok(cls, observed_at: str | None = None) -> "CollectorState":
        return cls("ok", observed_at)

    @classmethod
    def error(cls, message: str) -> "CollectorState":
        return cls("error", message=message)

    @classmethod
    def stale(cls, observed_at: str, message: str = "") -> "CollectorState":
        return cls("stale", observed_at=observed_at, message=message)

    @classmethod
    def skipped(cls, message: str) -> "CollectorState":
        return cls("skipped", message=message)

    @classmethod
    def from_dict(cls, value: object) -> "CollectorState":
        if not isinstance(value, Mapping):
            raise TypeError("collector state must be an object")
        unknown = set(value) - {"status", "observed_at", "message"}
        if unknown:
            raise ValueError(f"unknown collector state fields: {sorted(unknown)}")
        if "status" not in value:
            raise ValueError("collector state is missing status")
        return cls(
            status=value["status"],
            observed_at=value.get("observed_at"),
            message=value.get("message", ""),
        )


def _missing_collector() -> CollectorState:
    return CollectorState.error("not collected")


@dataclass(frozen=True)
class LogWindowSnapshot:
    collector: CollectorState = field(default_factory=_missing_collector)
    since: str | None = None
    until: str | None = None
    counts: dict[str, int | None] | None = None
    top_destinations: dict[str, dict[str, int]] | None = None
    top_sources: dict[str, dict[str, int]] | None = None
    samples: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.collector, CollectorState):
            raise TypeError("log window collector must be CollectorState")
        for name, value in (("since", self.since), ("until", self.until)):
            if value is not None and not isinstance(value, str):
                raise TypeError(f"log window {name} must be a string or null")
        if self.collector.status in {"ok", "stale"} and self.counts is None:
            raise ValueError(f"{self.collector.status} log window requires counts")
        if self.collector.status in {"error", "skipped"} and self.counts is not None:
            raise ValueError(f"{self.collector.status} log window cannot contain counts")
        if self.counts is not None:
            if set(self.counts) != set(BUCKETS):
                missing = sorted(set(BUCKETS) - set(self.counts))
                unknown = sorted(set(self.counts) - set(BUCKETS))
                raise ValueError(f"log bucket keys must be exact; missing={missing}, unknown={unknown}")
            for bucket, count in self.counts.items():
                if count is not None and not _is_count(count):
                    raise ValueError(f"invalid count for {bucket}: {count!r}")
            if self.collector.status == "ok" and any(value is None for value in self.counts.values()):
                raise ValueError("ok log window cannot contain unknown counts")
        self._validate_ranked_counts("top_destinations", self.top_destinations)
        self._validate_ranked_counts("top_sources", self.top_sources)
        if self.samples is not None:
            if not isinstance(self.samples, dict) or not set(self.samples).issubset(BUCKETS):
                raise ValueError("log samples must use known bucket names")
            if not all(isinstance(value, str) for value in self.samples.values()):
                raise TypeError("log samples must contain strings")

    @staticmethod
    def _validate_ranked_counts(name: str, values: dict[str, dict[str, int]] | None) -> None:
        if values is None:
            return
        if not isinstance(values, dict) or not set(values).issubset(BUCKETS):
            raise ValueError(f"{name} must use known bucket names")
        for bucket, ranked in values.items():
            if not isinstance(ranked, dict) or not all(isinstance(key, str) and _is_count(count) for key, count in ranked.items()):
                raise ValueError(f"invalid {name} values for {bucket}")

    @classmethod
    def collected(
        cls,
        counts: Mapping[str, int],
        *,
        observed_at: str,
        since: str | None = None,
        until: str | None = None,
        top_destinations: Mapping[str, Mapping[str, int]] | None = None,
        top_sources: Mapping[str, Mapping[str, int]] | None = None,
        samples: Mapping[str, str] | None = None,
    ) -> "LogWindowSnapshot":
        missing = set(BUCKETS) - set(counts)
        unknown = set(counts) - set(BUCKETS)
        if missing or unknown:
            raise ValueError(f"log bucket keys must be exact; missing={sorted(missing)}, unknown={sorted(unknown)}")
        normalized = {bucket: counts[bucket] for bucket in BUCKETS}
        return cls(
            collector=CollectorState.ok(observed_at),
            since=since,
            until=until,
            counts=normalized,
            top_destinations={key: dict(value) for key, value in (top_destinations or {}).items()},
            top_sources={key: dict(value) for key, value in (top_sources or {}).items()},
            samples=dict(samples or {}),
        )

    @classmethod
    def empty(cls, *, observed_at: str, since: str | None = None, until: str | None = None) -> "LogWindowSnapshot":
        return cls.collected({bucket: 0 for bucket in BUCKETS}, observed_at=observed_at, since=since, until=until)

    @classmethod
    def unavailable(cls, message: str) -> "LogWindowSnapshot":
        return cls(collector=CollectorState.error(message))

    @classmethod
    def skipped(cls, message: str) -> "LogWindowSnapshot":
        return cls(collector=CollectorState.skipped(message))

    @classmethod
    def from_dict(cls, value: object) -> "LogWindowSnapshot":
        if not isinstance(value, Mapping):
            raise TypeError("log window must be an object")
        allowed = {item.name for item in fields(cls)}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown log window fields: {sorted(unknown)}")
        if "collector" not in value:
            raise ValueError("log window is missing collector state")
        counts_value = value.get("counts")
        ranked_destinations = value.get("top_destinations")
        ranked_sources = value.get("top_sources")
        samples = value.get("samples")
        return cls(
            collector=CollectorState.from_dict(value["collector"]),
            since=value.get("since"),
            until=value.get("until"),
            counts=dict(counts_value) if isinstance(counts_value, Mapping) else counts_value,
            top_destinations={str(key): dict(ranked) for key, ranked in ranked_destinations.items()}
            if isinstance(ranked_destinations, Mapping)
            else ranked_destinations,
            top_sources={str(key): dict(ranked) for key, ranked in ranked_sources.items()}
            if isinstance(ranked_sources, Mapping)
            else ranked_sources,
            samples=dict(samples) if isinstance(samples, Mapping) else samples,
        )


def _default_collectors() -> dict[str, CollectorState]:
    return {name: _missing_collector() for name in COLLECTOR_NAMES}


def _default_log_windows() -> dict[str, LogWindowSnapshot]:
    return {name: LogWindowSnapshot.unavailable("not collected") for name in LOG_WINDOW_KEYS}


@dataclass
class DiagnosticsSnapshot:
    schema_version: int = SCHEMA_VERSION
    generated_at: str = field(default_factory=_utc_now)
    deployment: str = ""
    role: str = ""
    host: dict[str, Any] = field(default_factory=dict)
    collectors: dict[str, CollectorState] = field(default_factory=_default_collectors)
    log_windows: dict[str, LogWindowSnapshot] = field(default_factory=_default_log_windows)
    services: dict[str, str] = field(default_factory=dict)
    installed_env_hash: str = ""
    installed_config_hash: str = ""
    rendered_config_hash: str = ""
    render_manifest: dict[str, Any] = field(default_factory=dict)
    drift: str = "unknown"
    wg_state: dict[str, Any] = field(default_factory=dict)
    route_probes: dict[str, Any] = field(default_factory=dict)
    runtime_overrides: dict[str, str] = field(default_factory=dict)
    verdict: str = "inconclusive"
    reasons: list[str] = field(default_factory=list)
    release: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)
    storage: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    front: dict[str, Any] = field(default_factory=dict)
    transport: dict[str, Any] = field(default_factory=dict)
    maintenance: dict[str, Any] = field(default_factory=dict)
    redundancy: dict[str, Any] = field(default_factory=dict)
    component_verdicts: dict[str, str] = field(default_factory=dict)
    migration: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported diagnostics snapshot schema")
        if not isinstance(self.generated_at, str) or not self.generated_at:
            raise ValueError("generated_at must be a non-empty string")
        if set(self.collectors) != set(COLLECTOR_NAMES):
            raise ValueError("collector names must match the V3 contract")
        if not all(isinstance(value, CollectorState) for value in self.collectors.values()):
            raise TypeError("collectors must contain CollectorState values")
        self.collectors = {name: self.collectors[name] for name in COLLECTOR_NAMES}
        if set(self.log_windows) != set(LOG_WINDOW_KEYS):
            raise ValueError(f"log windows must match {LOG_WINDOW_KEYS}")
        self.log_windows = {name: self.log_windows[name] for name in LOG_WINDOW_KEYS}
        if not all(isinstance(value, LogWindowSnapshot) for value in self.log_windows.values()):
            raise TypeError("log_windows must contain LogWindowSnapshot values")
        if not isinstance(self.reasons, list) or not all(isinstance(value, str) for value in self.reasons):
            raise TypeError("reasons must be a list of strings")
        if self.verdict not in {"verified", "degraded", "failed", "inconclusive"}:
            raise ValueError(f"invalid diagnostics verdict: {self.verdict!r}")
        for name in (
            "host",
            "services",
            "render_manifest",
            "wg_state",
            "route_probes",
            "runtime_overrides",
            "release",
            "artifacts",
            "storage",
            "network",
            "front",
            "transport",
            "maintenance",
            "redundancy",
            "component_verdicts",
            "migration",
        ):
            if not isinstance(getattr(self, name), dict):
                raise TypeError(f"{name} must be an object")

    @property
    def collector_status(self) -> str:
        statuses = {state.status for state in self.collectors.values()}
        if "error" in statuses:
            return "error"
        if "stale" in statuses:
            return "stale"
        if "skipped" in statuses:
            return "skipped"
        return "ok"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_dict(cls, value: object) -> "DiagnosticsSnapshot":
        if not isinstance(value, Mapping):
            raise TypeError("diagnostics snapshot must be an object")
        allowed = {item.name for item in fields(cls)}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown diagnostics snapshot fields: {sorted(unknown)}")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported diagnostics snapshot schema")
        missing = allowed - set(value)
        if missing:
            raise ValueError(f"missing diagnostics snapshot fields: {sorted(missing)}")
        collectors_value = value.get("collectors")
        windows_value = value.get("log_windows")
        if not isinstance(collectors_value, Mapping):
            raise TypeError("collectors must be an object")
        if not isinstance(windows_value, Mapping):
            raise TypeError("log_windows must be an object")
        payload = dict(value)
        payload["collectors"] = {str(name): CollectorState.from_dict(state) for name, state in collectors_value.items()}
        payload["log_windows"] = {str(name): LogWindowSnapshot.from_dict(window) for name, window in windows_value.items()}
        return cls(**payload)

    @classmethod
    def from_json(cls, payload: str) -> "DiagnosticsSnapshot":
        return cls.from_dict(json.loads(payload))

    @classmethod
    def from_agent(cls, payload: dict[str, Any]) -> "DiagnosticsSnapshot":
        """Parse the agent protocol at its single schema/migration boundary."""
        schema_version = payload.get("schema_version")
        if schema_version == SCHEMA_VERSION:
            return cls.from_dict(payload)
        if schema_version == 2:
            return cls.migrate_agent_v2(payload)
        raise ValueError("unsupported vpn-stack-agent snapshot schema")

    @classmethod
    def migrate_agent_v2(cls, payload: Mapping[str, Any]) -> "DiagnosticsSnapshot":
        """Convert deployed V2 agent output without treating inferred data as fresh."""
        if payload.get("schema_version") != 2:
            raise ValueError("migration boundary accepts only agent schema 2")
        generated_at = payload.get("generated_at")
        if not isinstance(generated_at, str) or not generated_at:
            raise ValueError("legacy agent snapshot is missing generated_at")

        source_keys = {
            "services": "services",
            "artifacts": "artifacts",
            "wireguard": "wireguard",
            "route_probes": "probes",
            "logs": "logs",
            "storage": "storage",
            "network": "network",
            "front": "front",
            "transport": "transport",
            "maintenance": "maintenance",
        }
        collectors: dict[str, CollectorState] = {}
        for collector, source_key in source_keys.items():
            if source_key not in payload or not isinstance(payload[source_key], Mapping):
                collectors[collector] = CollectorState.error(f"schema 2 payload has no valid {source_key} section")
            else:
                collectors[collector] = CollectorState.stale(
                    generated_at,
                    "migrated from schema 2; collector success was not encoded",
                )

        logs = _mapping(payload.get("logs"))
        minute_windows = _mapping(logs.get("windows_minutes"))
        legacy_sources = {
            "5m": minute_windows.get("5"),
            "30m": minute_windows.get("30"),
            "24h": minute_windows.get("1440"),
            "since_release": logs.get("fresh"),
        }
        log_windows: dict[str, LogWindowSnapshot] = {}
        migration_warnings: list[str] = []
        legacy_dns_failed: dict[str, int] = {}
        for window_name in LOG_WINDOW_KEYS:
            source = legacy_sources[window_name]
            if not isinstance(source, Mapping) or not isinstance(source.get("counts"), Mapping):
                log_windows[window_name] = LogWindowSnapshot.unavailable(
                    f"schema 2 payload has no {window_name} log data"
                )
                continue
            old_counts = source["counts"]
            counts: dict[str, int | None] = {}
            for bucket in BUCKETS:
                value = old_counts.get(bucket)
                counts[bucket] = value if _is_count(value) else None
            generic_dns_count = old_counts.get("dns_failed")
            if _is_count(generic_dns_count):
                legacy_dns_failed[window_name] = generic_dns_count
                for bucket in ("dns_nodata", "dns_refused", "dns_servfail"):
                    if bucket not in old_counts:
                        counts[bucket] = 0 if generic_dns_count == 0 else None
                if generic_dns_count:
                    migration_warnings.append(
                        f"{window_name}: dns_failed={generic_dns_count} cannot be split into V3 DNS buckets"
                    )
            top_destinations = {
                str(bucket): {str(destination): count for destination, count in ranked.items() if _is_count(count)}
                for bucket, ranked in _mapping(source.get("top_destinations")).items()
                if bucket in BUCKETS and isinstance(ranked, Mapping)
            }
            top_sources = {
                str(bucket): {str(source_name): count for source_name, count in ranked.items() if _is_count(count)}
                for bucket, ranked in _mapping(source.get("top_sources")).items()
                if bucket in BUCKETS and isinstance(ranked, Mapping)
            }
            samples = {
                str(bucket): str(sample)
                for bucket, sample in _mapping(source.get("samples")).items()
                if bucket in BUCKETS
            }
            since = source.get("since") if isinstance(source.get("since"), str) else {
                "5m": "5 minutes ago",
                "30m": "30 minutes ago",
                "24h": "1440 minutes ago",
            }.get(window_name)
            log_windows[window_name] = LogWindowSnapshot(
                collector=CollectorState.stale(
                    generated_at,
                    "migrated from schema 2; collection errors were not distinguishable from empty logs",
                ),
                since=since,
                until=generated_at,
                counts=counts,
                top_destinations=top_destinations,
                top_sources=top_sources,
                samples=samples,
            )

        artifacts = _mapping(payload.get("artifacts"))
        artifact_files = _mapping(artifacts.get("files"))
        sing_box_artifact = _mapping(artifact_files.get("sing-box.json"))
        verdicts = _mapping(payload.get("verdicts"))
        legacy_verdict = str(verdicts.get("overall", "inconclusive"))
        reasons = [str(value) for value in verdicts.get("reasons", [])] if isinstance(verdicts.get("reasons", []), list) else []
        if legacy_verdict == "verified":
            legacy_verdict = "inconclusive"
            reasons.append("schema 2 collector state is unknown; migrated evidence is stale")
        return cls(
            generated_at=generated_at,
            deployment=str(payload.get("deployment", "")),
            role=str(payload.get("role", "")),
            host=_mapping(payload.get("host")),
            collectors=collectors,
            log_windows=log_windows,
            services={str(key): str(value) for key, value in _mapping(payload.get("services")).items()},
            installed_env_hash=str(artifacts.get("installed_env_sha256", "")),
            installed_config_hash=str(sing_box_artifact.get("actual_sha256", "")),
            rendered_config_hash=str(sing_box_artifact.get("expected_sha256", "")),
            render_manifest=_mapping(artifacts.get("manifest")),
            drift=str(artifacts.get("drift", "unknown")),
            wg_state=_mapping(payload.get("wireguard")),
            route_probes=_mapping(payload.get("probes")),
            runtime_overrides={str(key): str(value) for key, value in _mapping(payload.get("runtime_overrides")).items()},
            verdict=legacy_verdict,
            reasons=reasons,
            release=_mapping(payload.get("release")),
            artifacts=artifacts,
            storage=_mapping(payload.get("storage")),
            network=_mapping(payload.get("network")),
            front=_mapping(payload.get("front")),
            transport=_mapping(payload.get("transport")),
            maintenance=_mapping(payload.get("maintenance")),
            redundancy=_mapping(payload.get("redundancy")),
            component_verdicts={str(key): str(value) for key, value in verdicts.items() if key not in {"overall", "reasons"}},
            migration={
                "source_schema_version": 2,
                "boundary": "DiagnosticsSnapshot.migrate_agent_v2",
                "warnings": migration_warnings,
                "legacy_dns_failed": legacy_dns_failed,
            },
        )
