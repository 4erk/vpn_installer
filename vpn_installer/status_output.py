from __future__ import annotations

from .diagnostics import DiagnosticsSnapshot


def format_snapshot_summary(snapshot: DiagnosticsSnapshot) -> list[str]:
    lines = [
        f"role: {snapshot.role or '-'}",
        f"drift: {snapshot.drift}",
        f"verdict: {snapshot.verdict}",
        f"current log window: since={snapshot.fresh_since or '-'}, duration={snapshot.fresh_window_minutes}m",
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
            f"mtu_probing={tcp_adaptation.get('mtu_probing', '-')}, mtu_floor={tcp_adaptation.get('mtu_probe_floor', '-')}, "
            f"metrics_cache={'disabled' if tcp_adaptation.get('metrics_save_disabled') == 1 else 'enabled'}, "
            f"probe_interval_s={tcp_adaptation.get('probe_interval_seconds', '-')}, "
            f"udp_rmem={tcp_adaptation.get('udp_rmem_default', '-')}/{tcp_adaptation.get('udp_rmem_max', '-')}, "
            f"udp_wmem_max={tcp_adaptation.get('udp_wmem_max', '-')}"
        )
    conntrack = snapshot.network.get("conntrack", {})
    if conntrack:
        details = [f"{conntrack.get('count', '-')}/{conntrack.get('max', '-')} ({conntrack.get('percent', '-')}%)"]
        bypass = conntrack.get("front_bypass", {})
        if bypass:
            details.append(f"xray_front_bypass={'active' if bypass.get('active') else 'inactive'}")
        events = conntrack.get("table_full_events", {})
        labels = {"5": "5m", "30": "30m", "1440": "24h"}
        if events:
            details.append("table_full=" + ",".join(f"{labels.get(str(window), str(window))}:{count}" for window, count in events.items()))
        lines.append("conntrack: " + ", ".join(details))
    resolver = snapshot.network.get("resolver", {})
    if resolver:
        lines.append(
            "resolver: "
            f"stub={'active' if resolver.get('managed_stub') else 'inactive'}, "
            f"cache={'on' if resolver.get('cache_enabled') else 'off'}, "
            f"stale={resolver.get('stale_retention') or '-'}, "
            f"upstreams={','.join(str(value) for value in resolver.get('upstreams', [])) or '-'}"
        )
    interserver = snapshot.transport.get("interserver", {})
    if interserver:
        selection = interserver.get("selection", {})
        candidates = selection.get("candidates", {})
        delays = ",".join(
            f"{tag}={details.get('delay_ms')}ms" if details.get("delay_ms") is not None else f"{tag}=not-probed"
            for tag, details in candidates.items()
            if isinstance(details, dict)
        ) or "-"
        details = [
            f"mode={interserver.get('mode', '-')}",
            f"selected={selection.get('selected') or '-'}",
            f"candidates={delays}",
        ]
        if snapshot.role == "ru-gateway":
            adaptive = interserver.get("adaptive_state", {})
            details.append(f"adaptation={adaptive.get('state') or '-'}")
            details.append(f"hy2_session={'active' if interserver.get('hysteria_session_active') else 'inactive'}")
            if adaptive.get("reason"):
                details.append(f"reason={adaptive['reason']}")
        elif snapshot.role == "foreign-exit":
            details.append(f"listener={'active' if interserver.get('listening') else 'inactive'}")
            details.append(f"source={interserver.get('source_restricted_to') or '-'}")
        lines.append("interserver transport: " + ", ".join(details))
    health_state = snapshot.network.get("health_state", "")
    if health_state:
        health = f"health: {health_state}"
        if snapshot.network.get("health_updated_at"):
            health += f", updated={snapshot.network['health_updated_at']}"
        soft_reasons = snapshot.network.get("health_soft_reasons", [])
        if soft_reasons:
            health += ", soft=" + ",".join(str(reason) for reason in soft_reasons)
        lines.append(health)
    protocol = snapshot.network.get("protocol_counters", {})
    protocol_errors = {key: value for key, value in protocol.items() if value and ("Error" in key or "Drop" in key or "Discard" in key)}
    if protocol_errors:
        lines.append("protocol counters (lifetime): " + ", ".join(f"{key}={value}" for key, value in sorted(protocol_errors.items())))
    recent_deltas = snapshot.network.get("recent_health_deltas", {})
    recent_protocol = recent_deltas.get("protocol", {}) if isinstance(recent_deltas, dict) else {}
    recent_errors = {key: value for key, value in recent_protocol.items() if value and ("Error" in key or "Drop" in key or "Discard" in key)}
    if recent_errors:
        lines.append("protocol deltas (last health cycle): " + ", ".join(f"{key}=+{value}" for key, value in sorted(recent_errors.items())))
    retrans = int(recent_protocol.get("TcpRetransSegs", 0) or 0)
    outgoing = int(recent_protocol.get("TcpOutSegs", 0) or 0)
    if outgoing:
        ratio = retrans * 100 / outgoing
        lines.append(f"tcp deltas (last health cycle): out={outgoing}, retrans={retrans} ({ratio:.3f}%)")
    elif retrans:
        lines.append(f"tcp deltas (last health cycle): out=unavailable, retrans={retrans}")
    recovery_signals = {
        key: int(recent_protocol.get(key, 0) or 0)
        for key in ("TcpExtTCPSACKReorder", "TcpExtTCPDSACKRecv", "TcpExtTCPTimeouts", "TcpExtTCPSpuriousRTOs")
        if recent_protocol.get(key)
    }
    if recovery_signals:
        lines.append("tcp recovery deltas: " + ", ".join(f"{key}=+{value}" for key, value in recovery_signals.items()))
    front_degradation = snapshot.network.get("last_front_degradation", {})
    if front_degradation:
        aggregate = front_degradation.get("aggregate", {})
        sources = ",".join(str(source) for source in front_degradation.get("degraded_sources", [])) or "-"
        lines.append(
            "last front degradation: "
            f"at={front_degradation.get('observed_at', '-')}, sources={sources}, "
            f"retrans={aggregate.get('bytes_retrans', 0)}/{aggregate.get('bytes_sent', 0)} "
            f"({aggregate.get('retransmit_ratio_pct', 0)}%)"
        )
    if snapshot.reasons:
        lines.append("reasons: " + "; ".join(snapshot.reasons))
    return lines
