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
    root_filesystem = snapshot.storage.get("root_filesystem", {})
    if root_filesystem:
        lines.append(
            "root filesystem: "
            f"source={root_filesystem.get('source') or '-'}, fs={root_filesystem.get('filesystem') or '-'}, "
            f"state={root_filesystem.get('state') or 'unknown'}, errors={root_filesystem.get('errors_count', '-')}, "
            f"boot_fsck={'enabled' if root_filesystem.get('boot_check_enabled') else 'disabled'}, "
            f"verdict={root_filesystem.get('verdict', 'inconclusive')}"
        )
    if snapshot.role == "ru-gateway" and snapshot.front:
        lines.append(
            "public front liveness: "
            f"keepalive_idle_s={snapshot.front.get('tcp_keepalive_idle_seconds', '-')}, "
            f"keepalive_interval_s={snapshot.front.get('tcp_keepalive_interval_seconds', '-')}"
        )
        loss_sources = snapshot.front.get("loss_observed_sources", [])
        if loss_sources:
            lines.append("public front lifetime loss sources: " + ",".join(str(source) for source in loss_sources))
        lines.append(
            "public TCP sockets: "
            f"active={snapshot.front.get('active_connections', 0)}, "
            f"closing={snapshot.front.get('closing_connections', 0)}"
        )
        closing_sources = snapshot.front.get("closing_churn_sources", [])
        if closing_sources:
            lines.append("public front closing churn sources: " + ",".join(str(source) for source in closing_sources))
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
        rendered_delays: list[str] = []
        for tag, candidate in candidates.items():
            if not isinstance(candidate, dict) or candidate.get("delay_ms") is None:
                rendered_delays.append(f"{tag}=not-probed")
            elif candidate.get("fresh") is False:
                rendered_delays.append(
                    f"{tag}=stale({candidate.get('delay_ms')}ms,age={candidate.get('age_seconds', '-')}s)"
                )
            else:
                rendered_delays.append(f"{tag}={candidate.get('delay_ms')}ms")
        delays = ",".join(rendered_delays) or "-"
        details = [
            f"mode={interserver.get('mode', '-')}",
            f"selected={selection.get('selected') or '-'}",
            f"candidates={delays}",
        ]
        if snapshot.role == "ru-gateway":
            adaptive = interserver.get("adaptive_state", {})
            adaptive_label = adaptive.get("state") or "-"
            if adaptive.get("fresh") is False:
                adaptive_label = f"stale({adaptive_label},age={adaptive.get('age_seconds', '-')}s)"
            details.append(f"adaptation={adaptive_label}")
            details.append(f"hy2_session={'active' if interserver.get('hysteria_session_active') else 'inactive'}")
            if adaptive.get("reason"):
                details.append(f"reason={adaptive['reason']}")
        elif snapshot.role == "foreign-exit":
            details.append(f"listener={'active' if interserver.get('listening') else 'inactive'}")
            details.append(f"source={interserver.get('source_restricted_to') or '-'}")
        lines.append("interserver transport: " + ", ".join(details))
    public_client = snapshot.transport.get("public_client", {})
    if public_client:
        lines.append(
            "public QUIC transport: "
            f"configured={public_client.get('configured', False)}, "
            f"listener={public_client.get('listening', False)}, "
            f"firewall={public_client.get('firewall', False)}, "
            f"port={public_client.get('port', '-')}"
        )
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
    recent_interfaces = recent_deltas.get("interfaces", {}) if isinstance(recent_deltas, dict) else {}
    interface_drops = {
        f"{interface}.{counter}": value
        for interface, counters in recent_interfaces.items()
        if isinstance(counters, dict)
        for counter, value in counters.items()
        if value and counter in {"rx_dropped", "tx_dropped", "rx_errors", "tx_errors", "rx_missed_errors"}
    }
    if interface_drops:
        lines.append(
            "interface counters (unscoped, informational; last health cycle): "
            + ", ".join(f"{key}=+{value}" for key, value in sorted(interface_drops.items()))
        )
    recent_protocol = recent_deltas.get("protocol", {}) if isinstance(recent_deltas, dict) else {}
    recent_errors = {key: value for key, value in recent_protocol.items() if value and ("Error" in key or "Drop" in key or "Discard" in key)}
    if recent_errors:
        lines.append("protocol deltas (last health cycle): " + ", ".join(f"{key}=+{value}" for key, value in sorted(recent_errors.items())))
    retrans = int(recent_protocol.get("TcpRetransSegs", 0) or 0)
    outgoing = int(recent_protocol.get("TcpOutSegs", 0) or 0)
    if outgoing:
        ratio = retrans * 100 / outgoing
        lines.append(f"host-wide tcp counters (informational; last health cycle): out={outgoing}, retrans={retrans} ({ratio:.3f}%)")
    elif retrans:
        lines.append(f"host-wide tcp counters (informational; last health cycle): out=unavailable, retrans={retrans}")
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
    front_interval = snapshot.network.get("recent_front_interval", {})
    if front_interval:
        aggregate = front_interval.get("aggregate", {})
        sources = ",".join(str(source) for source in front_interval.get("degraded_sources", [])) or "-"
        lines.append(
            "front interval: "
            f"at={front_interval.get('observed_at', '-')}, observation={front_interval.get('observation', '-')}, "
            f"flows={front_interval.get('sampled_flows', 0)}, sources={sources}, "
            f"retrans={aggregate.get('bytes_retrans', 0)}/{aggregate.get('activity_bytes', 0)} "
            f"({aggregate.get('retransmit_ratio_pct', 0)}%)"
        )
    if snapshot.reasons:
        lines.append("reasons: " + "; ".join(snapshot.reasons))
    return lines
