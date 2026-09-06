from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Mapping

try:
    from .log_classifier import BUCKETS
except ImportError:  # Installed beside vpn-stack-agent.py as a standalone module.
    from log_classifier import BUCKETS  # type: ignore[no-redef]


SCHEMA_VERSION = 6
COLLECTOR_STATUSES = frozenset({"ok", "error", "stale", "skipped", "not_applicable"})
TOPOLOGIES = frozenset({"single", "dual"})
NODE_IDS = frozenset({"gateway", "exit"})
LOCATIONS = frozenset({"ru", "foreign"})
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


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("timezone is missing")
        return parsed.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be a timezone-aware timestamp") from exc


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


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
        if self.status in {"error", "skipped", "not_applicable"} and not self.message:
            raise ValueError(f"{self.status} collector status requires a message")
        if self.status in {"ok", "stale"} and not self.observed_at:
            raise ValueError(f"{self.status} collector status requires observed_at")
        if self.observed_at is not None:
            _timestamp(self.observed_at, "collector observed_at")

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
    def not_applicable(cls, message: str) -> "CollectorState":
        return cls("not_applicable", message=message)

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
        if self.until is not None:
            _timestamp(self.until, "log window until")
        self._validate_bounds()
        if self.collector.status in {"ok", "stale"} and self.counts is None:
            raise ValueError(f"{self.collector.status} log window requires counts")
        if self.collector.status in {"error", "skipped", "not_applicable"} and self.counts is not None:
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

    def _validate_bounds(self) -> None:
        if self.since is None:
            return
        try:
            datetime.fromisoformat(self.since.replace("Z", "+00:00"))
        except ValueError:
            return  # Schema 6 also carries legacy relative journal expressions.
        since = _timestamp(self.since, "log window since")
        if self.until is not None and since > _timestamp(self.until, "log window until"):
            raise ValueError("log window since must be <= until")

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
    def not_applicable(cls, message: str) -> "LogWindowSnapshot":
        return cls(collector=CollectorState.not_applicable(message))

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
    topology: str = ""
    node_id: str = ""
    location: str = ""
    capabilities: tuple[str, ...] = ()
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

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported diagnostics snapshot schema")
        if not isinstance(self.generated_at, str) or not self.generated_at:
            raise ValueError("generated_at must be a non-empty string")
        _timestamp(self.generated_at, "generated_at")
        for name, value, supported in (
            ("topology", self.topology, TOPOLOGIES),
            ("node_id", self.node_id, NODE_IDS),
            ("location", self.location, LOCATIONS),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if value and value not in supported:
                raise ValueError(f"unsupported diagnostics {name}: {value!r}")
        if not isinstance(self.capabilities, (list, tuple, set, frozenset)):
            raise TypeError("capabilities must be an array of strings")
        if not all(isinstance(value, str) and value for value in self.capabilities):
            raise ValueError("capabilities must contain non-empty strings")
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("capabilities must be unique")
        self.capabilities = tuple(sorted(self.capabilities))
        contract_values = (self.topology, self.node_id, self.location, self.capabilities)
        if any(bool(value) for value in contract_values) and not all(bool(value) for value in contract_values):
            raise ValueError("canonical diagnostics contract must include topology, node_id, location, and capabilities")
        if self.topology == "single" and self.node_id == "exit":
            raise ValueError("single topology cannot contain an exit node")
        if set(self.collectors) != set(COLLECTOR_NAMES):
            raise ValueError("collector names must match the V6 contract")
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
        ):
            if not isinstance(getattr(self, name), dict):
                raise TypeError(f"{name} must be an object")

    @property
    def collector_status(self) -> str:
        statuses = {state.status for state in self.collectors.values()}
        applicable = statuses - {"not_applicable"}
        if not applicable:
            return "not_applicable"
        if "error" in applicable:
            return "error"
        if "stale" in applicable:
            return "stale"
        if "skipped" in applicable:
            return "skipped"
        return "ok"

    @property
    def has_capability_contract(self) -> bool:
        return bool(self.topology and self.node_id and self.location and self.capabilities)

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def freshness_issues(
        self,
        *,
        now: datetime,
        max_age_seconds: float = 180,
        future_skew_seconds: float = 30,
    ) -> list[str]:
        """Validate claimed observations without rewriting historical evidence.

        Availability and required-capability checks remain the caller's responsibility.
        """
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise ValueError("now must be a timezone-aware datetime")
        for name, budget in (("max_age_seconds", max_age_seconds), ("future_skew_seconds", future_skew_seconds)):
            if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not math.isfinite(budget) or budget < 0:
                raise ValueError(f"{name} must be a finite non-negative number")
        issues: list[str] = []

        def check(name: str, value: str | None) -> None:
            if value is None:
                issues.append(f"{name} is missing")
                return
            try:
                observed = _timestamp(value, name)
            except ValueError as exc:
                issues.append(str(exc))
                return
            age = (now - observed).total_seconds()
            if age > max_age_seconds:
                issues.append(f"{name} is stale: age={age:.3f}s")
            elif age < -future_skew_seconds:
                issues.append(f"{name} is from the future: age={age:.3f}s")

        check("snapshot generated_at", self.generated_at)
        for name, state in self.collectors.items():
            if state.status in {"ok", "stale"}:
                check(f"collector {name} observed_at", state.observed_at)
                if state.status == "stale":
                    issues.append(f"collector {name} is marked stale")
        for name, window in self.log_windows.items():
            if window.collector.status in {"ok", "stale"}:
                check(f"log window {name} observed_at", window.collector.observed_at)
                check(f"log window {name} until", window.until)
                try:
                    window._validate_bounds()
                except ValueError as exc:
                    issues.append(f"log window {name}: {exc}")
                if window.collector.status == "stale":
                    issues.append(f"log window {name} is marked stale")
        return issues

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["capabilities"] = list(self.capabilities)
        return payload

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
        capabilities = value.get("capabilities")
        if not isinstance(capabilities, list):
            raise TypeError("capabilities must be an array")
        payload["capabilities"] = tuple(capabilities)
        return cls(**payload)

    @classmethod
    def from_json(cls, payload: str) -> "DiagnosticsSnapshot":
        return cls.from_dict(json.loads(payload))

    @classmethod
    def from_agent(cls, payload: dict[str, Any]) -> "DiagnosticsSnapshot":
        """Parse only the native agent protocol installed with this release."""

        return cls.from_dict(payload)
