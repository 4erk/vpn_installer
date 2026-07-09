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
    schema_version: int = 1
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
    dataplane_cache: dict[str, str] = field(default_factory=dict)
    log_buckets: dict[str, int] = field(default_factory=dict)
    historical_log_buckets: dict[str, int] = field(default_factory=dict)
    top_destinations: dict[str, str] = field(default_factory=dict)
    fresh_window_minutes: int = 30
    historical_window_hours: int = 4
    verdict: str = "inconclusive"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_json(cls, payload: str) -> "DiagnosticsSnapshot":
        return cls(**json.loads(payload))

    @classmethod
    def from_preflight(cls, preflight: dict[str, str], *, deployment: str = "") -> "DiagnosticsSnapshot":
        services = {
            "sing-box": preflight.get("sing_box", ""),
            "xray": preflight.get("xray", ""),
            "wireguard": preflight.get("wireguard", ""),
            "nftables": preflight.get("nftables", ""),
        }
        log_buckets = {
            "dns_failed": int(preflight.get("singbox_recent_dns_failed_count") or 0),
            "domain_to_foreign_timeout": int(preflight.get("singbox_recent_to_foreign_timeout_count") or 0),
            "ipv4_literal_timeout": int(preflight.get("singbox_recent_to_foreign_ip_literal_timeout_count") or 0),
            "ipv6_literal_timeout": int(preflight.get("singbox_recent_to_foreign_ipv6_literal_timeout_count") or 0),
            "blocked_private_fake": int(preflight.get("singbox_recent_blocked_count") or 0),
            "client_reset_eof": int(preflight.get("singbox_recent_eof_count") or 0) + int(preflight.get("singbox_recent_mux_closed_count") or 0),
            "invalid_reality": int(preflight.get("xray_recent_invalid_reality_count") or 0),
            "disabled_invalid": int(preflight.get("xray_recent_disabled_invalid_count") or 0),
            "private_dns_leak": int(preflight.get("singbox_recent_private_dns_leak_count") or 0),
        }
        historical_log_buckets = {
            "dns_failed": int(preflight.get("singbox_dns_timeout_count") or 0),
            "domain_to_foreign_timeout": int(preflight.get("singbox_to_foreign_timeout_count") or 0),
            "ipv4_literal_timeout": int(preflight.get("singbox_to_foreign_ip_literal_timeout_count") or 0),
            "ipv6_literal_timeout": int(preflight.get("singbox_to_foreign_ipv6_literal_timeout_count") or 0),
        }
        top_destinations = {
            "timeout": preflight.get("singbox_fresh_timeout_destinations", ""),
            "domain_to_foreign_timeout": preflight.get("singbox_fresh_domain_timeout_destinations", ""),
            "ipv4_literal_timeout": preflight.get("singbox_fresh_ip_literal_timeout_destinations", ""),
            "ipv6_literal_timeout": preflight.get("singbox_fresh_ipv6_literal_timeout_destinations", ""),
            "blocked_private_fake": preflight.get("singbox_recent_blocked_destinations", ""),
            "private_dns_leak": preflight.get("singbox_recent_private_dns_leak_destinations", ""),
        }
        return cls(
            deployment=deployment or preflight.get("deployment_name", ""),
            role=preflight.get("role", ""),
            services=services,
            installed_env_hash=preflight.get("installed_env_sha256", ""),
            installed_config_hash=preflight.get("installed_singbox_sha256", ""),
            rendered_config_hash=preflight.get("render_manifest_singbox_sha256", ""),
            drift=preflight.get("drift", "unknown") or "unknown",
            wg_state={
                "latest_handshake": preflight.get("wg_latest_handshake", ""),
                "latest_handshake_age_s": preflight.get("wg_latest_handshake_age_s", ""),
                "transfer_rx": preflight.get("wg_transfer_rx", ""),
                "transfer_tx": preflight.get("wg_transfer_tx", ""),
            },
            route_probes={
                "direct": preflight.get("target_probe_direct", ""),
                "wg": preflight.get("target_probe_wg", ""),
                "ipv6_literal_tcp": preflight.get("ipv6_literal_tcp_probe", ""),
                "observed_ipv4": preflight.get("observed_ipv4", ""),
                "wg_observed_ipv4": preflight.get("wg_observed_ipv4", ""),
                "deep_probe_verdict": preflight.get("deep_probe_verdict", ""),
                "deep_probe_reasons": preflight.get("deep_probe_reasons", ""),
            },
            dataplane_cache={
                "good_wg_path_at": preflight.get("good_wg_path_at", ""),
                "good_wg_path_age_s": preflight.get("good_wg_path_age_s", ""),
                "good_wg_path_source": preflight.get("good_wg_path_source", ""),
                "good_wg_path_handshake_age_s": preflight.get("good_wg_path_handshake_age_s", ""),
                "good_cache_ttl_seconds": preflight.get("good_cache_ttl_seconds", ""),
                "route_fail_cache_ttl_seconds": preflight.get("route_fail_cache_ttl_seconds", ""),
                "route_fail_ipv4_literal_count": preflight.get("route_fail_ipv4_literal_count", ""),
                "route_fail_ipv4_literal_top_dest": preflight.get("route_fail_ipv4_literal_top_dest", ""),
                "route_fail_ipv4_literal_age_s": preflight.get("route_fail_ipv4_literal_age_s", ""),
                "route_fail_ipv6_literal_count": preflight.get("route_fail_ipv6_literal_count", ""),
                "route_fail_ipv6_literal_top_dest": preflight.get("route_fail_ipv6_literal_top_dest", ""),
                "route_fail_ipv6_literal_age_s": preflight.get("route_fail_ipv6_literal_age_s", ""),
                "singbox_runtime_overlay": preflight.get("singbox_runtime_overlay", ""),
                "admin_routing_rules_count": preflight.get("admin_routing_rules_count", ""),
                "admin_routing_rules_summary": preflight.get("admin_routing_rules_summary", ""),
            },
            log_buckets=log_buckets,
            historical_log_buckets=historical_log_buckets,
            top_destinations={key: value for key, value in top_destinations.items() if value},
            fresh_window_minutes=int(preflight.get("singbox_log_window_minutes") or 30),
        )
