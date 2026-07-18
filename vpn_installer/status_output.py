from __future__ import annotations

from .diagnostics import DiagnosticsSnapshot


def format_snapshot_summary(snapshot: DiagnosticsSnapshot) -> list[str]:
    lines = [
        f"role: {snapshot.role or '-'}",
        f"drift: {snapshot.drift}",
        f"verdict: {snapshot.verdict}",
        f"fresh window: {snapshot.fresh_window_minutes}m",
    ]
    if snapshot.historical_window_hours:
        lines.append(f"historical window: {snapshot.historical_window_hours}h")
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
    tcp_adaptation = snapshot.network.get("tcp_adaptation", {})
    if tcp_adaptation:
        lines.append(
            "tcp adaptation: "
            f"cc={tcp_adaptation.get('congestion_control', '-')}, qdisc={tcp_adaptation.get('qdisc', '-')}, "
            f"mtu_probing={tcp_adaptation.get('mtu_probing', '-')}, probe_interval_s={tcp_adaptation.get('probe_interval_seconds', '-')}, "
            f"udp_rmem={tcp_adaptation.get('udp_rmem_default', '-')}/{tcp_adaptation.get('udp_rmem_max', '-')}"
        )
    protocol = snapshot.network.get("protocol_counters", {})
    protocol_errors = {key: value for key, value in protocol.items() if value and ("Error" in key or "Drop" in key or "Discard" in key)}
    if protocol_errors:
        lines.append("protocol counters (lifetime): " + ", ".join(f"{key}={value}" for key, value in sorted(protocol_errors.items())))
    recent_deltas = snapshot.network.get("recent_health_deltas", {})
    recent_protocol = recent_deltas.get("protocol", {}) if isinstance(recent_deltas, dict) else {}
    recent_errors = {key: value for key, value in recent_protocol.items() if value and ("Error" in key or "Drop" in key or "Discard" in key)}
    if recent_errors:
        lines.append("protocol deltas (last health cycle): " + ", ".join(f"{key}=+{value}" for key, value in sorted(recent_errors.items())))
    if snapshot.reasons:
        lines.append("reasons: " + "; ".join(snapshot.reasons))
    return lines
