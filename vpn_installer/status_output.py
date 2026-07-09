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
    if snapshot.log_buckets:
        fresh = ", ".join(f"{key}={value}" for key, value in sorted(snapshot.log_buckets.items()))
        lines.append(f"log buckets: {fresh}")
    if snapshot.historical_log_buckets:
        historical = ", ".join(f"{key}={value}" for key, value in sorted(snapshot.historical_log_buckets.items()))
        lines.append(f"historical log buckets: {historical}")
    if snapshot.top_destinations:
        destinations = ", ".join(f"{key}: {value}" for key, value in sorted(snapshot.top_destinations.items()))
        lines.append(f"top destinations: {destinations}")
    if snapshot.dataplane_cache:
        cache = ", ".join(f"{key}={value}" for key, value in sorted(snapshot.dataplane_cache.items()) if value)
        if cache:
            lines.append(f"dataplane cache: {cache}")
    if snapshot.reasons:
        lines.append("reasons: " + "; ".join(snapshot.reasons))
    return lines
