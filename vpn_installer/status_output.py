from __future__ import annotations

from .diagnostics import LOG_WINDOW_KEYS, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot


def _collector_label(state: CollectorState) -> str:
    details: list[str] = []
    if state.observed_at:
        details.append(f"observed={state.observed_at}")
    if state.message:
        details.append(state.message)
    return state.status + (f" ({'; '.join(details)})" if details else "")


def _format_log_window(name: str, window: LogWindowSnapshot) -> list[str]:
    boundaries = []
    if window.since:
        boundaries.append(f"since={window.since}")
    if window.until:
        boundaries.append(f"until={window.until}")
    prefix = f"log window {name}: status={_collector_label(window.collector)}"
    if boundaries:
        prefix += ", " + ", ".join(boundaries)
    if window.counts is None:
        lines = [prefix + ", counts=unavailable"]
    else:
        nonzero = [f"{bucket}={count}" for bucket, count in window.counts.items() if isinstance(count, int) and count > 0]
        unknown = [bucket for bucket, count in window.counts.items() if count is None]
        if nonzero or unknown:
            rendered = [*nonzero, *(f"{bucket}=?" for bucket in unknown)]
            lines = [prefix + ", counts=" + ", ".join(rendered)]
        else:
            lines = [prefix + ", counts=no classified events"]
    if window.top_destinations:
        destinations = ", ".join(
            f"{bucket}:{destination}={count}"
            for bucket, ranked in sorted(window.top_destinations.items())
            for destination, count in ranked.items()
        )
        if destinations:
            lines.append(f"top destinations [{name}]: {destinations}")
    return lines


def format_snapshot_summary(snapshot: DiagnosticsSnapshot) -> list[str]:
    lines = [
        f"snapshot schema: {snapshot.schema_version}",
        f"role: {snapshot.role or '-'}",
        f"drift: {snapshot.drift}",
        f"verdict: {snapshot.verdict}",
        f"collector status: {snapshot.collector_status}",
        "collectors: " + ", ".join(
            f"{name}={_collector_label(snapshot.collectors[name])}" for name in snapshot.collectors
        ),
    ]
    if snapshot.verdict == "inconclusive" and snapshot.route_probes.get("profile") == "none":
        lines.append("live probes: not run by read-only status; use vpn verify live for route acceptance")
    for window_name in LOG_WINDOW_KEYS:
        lines.extend(_format_log_window(window_name, snapshot.log_windows[window_name]))
    if snapshot.migration:
        warnings = snapshot.migration.get("warnings", [])
        details = [
            f"source_schema={snapshot.migration.get('source_schema_version', '-')}",
            f"boundary={snapshot.migration.get('boundary', '-')}",
        ]
        if warnings:
            details.append("warnings=" + " | ".join(str(value) for value in warnings))
        lines.append("migration: " + ", ".join(details))
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
            "Reality target: "
            f"target={snapshot.front.get('reality_target') or '-'}, "
            f"config_key={snapshot.front.get('reality_target_config_key') or '-'}, "
            f"server_names={','.join(str(value) for value in snapshot.front.get('reality_server_names', [])) or '-'}, "
            f"pending_handshakes={snapshot.front.get('reality_pending_handshakes', 'unknown')}"
        )
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
            f"active={snapshot.front.get('active_connections', 'unknown')}, "
            f"closing={snapshot.front.get('closing_connections', 'unknown')}"
        )
        closing_sources = snapshot.front.get("closing_churn_sources", [])
        if closing_sources:
            lines.append("public front closing churn sources: " + ",".join(str(source) for source in closing_sources))
    tcp_adaptation = snapshot.network.get("tcp_adaptation", {})
    if tcp_adaptation:
        metrics_state = tcp_adaptation.get("metrics_save_disabled")
        metrics_label = "disabled" if metrics_state == 1 else "enabled" if metrics_state == 0 else "unknown"
        lines.append(
            "tcp adaptation: "
            f"cc={tcp_adaptation.get('congestion_control', '-')}, "
            f"qdisc={tcp_adaptation.get('qdisc', '-')}"
            f"(limit={tcp_adaptation.get('qdisc_limit', '-')},flow_limit={tcp_adaptation.get('qdisc_flow_limit', '-')},"
            f"drops={tcp_adaptation.get('qdisc_drops', '-')},flow_limit_drops={tcp_adaptation.get('qdisc_flow_limit_drops', '-')}), "
            f"mtu_probing={tcp_adaptation.get('mtu_probing', '-')}, mtu_floor={tcp_adaptation.get('mtu_probe_floor', '-')}, "
            f"metrics_cache={metrics_label}, "
            f"probe_interval_s={tcp_adaptation.get('probe_interval_seconds', '-')}, "
            f"udp_rmem={tcp_adaptation.get('udp_rmem_default', '-')}/{tcp_adaptation.get('udp_rmem_max', '-')}, "
            f"udp_wmem={tcp_adaptation.get('udp_wmem_default', '-')}/{tcp_adaptation.get('udp_wmem_max', '-')}"
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
        details = [f"mode={interserver.get('mode', '-')}"]
        if selection:
            details.append(f"selected={selection.get('selected') or '-'}")
        configured_candidates = [
            str(tag)
            for tag, candidate in candidates.items()
            if isinstance(candidate, dict) and candidate.get("configured") is True
        ]
        if configured_candidates:
            details.append(f"configured_candidates={','.join(configured_candidates)}")
        if snapshot.role == "ru-gateway":
            adaptive = interserver.get("adaptive_state", {})
            overlay_probe = adaptive.get("overlay_probe", {})
            if isinstance(overlay_probe, dict) and overlay_probe.get("checked") is True:
                if overlay_probe.get("ok") is True:
                    details.append(
                        f"overlay_probe=ok({overlay_probe.get('delay_ms', '-')}ms,target={overlay_probe.get('target') or '-'})"
                    )
                else:
                    details.append(f"overlay_probe=failed({overlay_probe.get('error') or 'unknown'})")
            probes = adaptive.get("probes", {})
            probes = probes if isinstance(probes, dict) else {}
            raw_probe = next(
                (
                    (tag, probe)
                    for tag, probe in probes.items()
                    if isinstance(probe, dict)
                    and probe.get("checked") is True
                    and probe.get("scope") == "raw-underlay"
                ),
                None,
            )
            if raw_probe:
                tag, probe = raw_probe
                outcome = (
                    f"ok({probe.get('delay_ms', '-')}ms)"
                    if probe.get("ok") is True
                    else f"failed({probe.get('error') or 'unknown'})"
                )
                details.append(f"cold_probe={tag}:{outcome}")
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
            f"configured={public_client.get('configured', 'unknown')}, "
            f"listener={public_client.get('listening', 'unknown')}, "
            f"firewall={public_client.get('firewall', 'unknown')}, "
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
            f"retrans={aggregate.get('bytes_retrans', 'unknown')}/{aggregate.get('bytes_sent', 'unknown')} "
            f"({aggregate.get('retransmit_ratio_pct', 'unknown')}%)"
        )
    front_interval = snapshot.network.get("recent_front_interval", {})
    if front_interval:
        aggregate = front_interval.get("aggregate", {})
        sources = ",".join(str(source) for source in front_interval.get("degraded_sources", [])) or "-"
        lines.append(
            "front interval: "
            f"at={front_interval.get('observed_at', '-')}, observation={front_interval.get('observation', '-')}, "
            f"flows={front_interval.get('sampled_flows', 'unknown')}, sources={sources}, "
            f"retrans={aggregate.get('bytes_retrans', 'unknown')}/{aggregate.get('activity_bytes', 'unknown')} "
            f"({aggregate.get('retransmit_ratio_pct', 'unknown')}%)"
        )
    if snapshot.reasons:
        lines.append("reasons: " + "; ".join(snapshot.reasons))
    return lines
