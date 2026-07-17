from __future__ import annotations

from .diagnostics import DiagnosticsSnapshot


def format_snapshot_summary(snapshot: DiagnosticsSnapshot) -> list[str]:
    lines = [
        f"role: {snapshot.role or '-'}",
        f"drift: {snapshot.drift}",
        f"verdict: {snapshot.verdict}",
        f"fresh window: {snapshot.fresh_window_minutes}m",
        f"historical window: {snapshot.historical_window_hours}h",
    ]
    if snapshot.verdict == "inconclusive" and snapshot.route_probes.get("profile") == "none":
        lines.append("live probes: not run by read-only status; use vpn verify live for route acceptance")
    if snapshot.log_buckets:
        fresh = ", ".join(f"{key}={value}" for key, value in sorted(snapshot.log_buckets.items()))
        lines.append(f"log buckets: {fresh}")
    if snapshot.historical_log_buckets:
        historical = ", ".join(f"{key}={value}" for key, value in sorted(snapshot.historical_log_buckets.items()))
        lines.append(f"historical log buckets: {historical}")
    if snapshot.top_destinations:
        destinations = ", ".join(f"{key}: {value}" for key, value in sorted(snapshot.top_destinations.items()))
        lines.append(f"top destinations: {destinations}")
    if snapshot.runtime_overrides:
        overrides = ", ".join(f"{key}={value}" for key, value in sorted(snapshot.runtime_overrides.items()) if value)
        if overrides:
            lines.append(f"runtime overrides: {overrides}")
    if snapshot.reasons:
        lines.append("reasons: " + "; ".join(snapshot.reasons))
    return lines
