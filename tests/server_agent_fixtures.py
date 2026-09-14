from __future__ import annotations

from datetime import datetime, timedelta
from vpn_installer import server_agent, server_runtime
from vpn_installer.platforms import default_build_platform


class AgentFixtures:
    @staticmethod
    def gateway_contract(*, topology: str = "dual") -> dict[str, object]:
        capabilities = {"public-front", "router", "local-egress"}
        required_services = ["nftables", "sing-box", "resolver", "health_timer", "xray"]
        if topology == "dual":
            capabilities.update({"ru-split-routing", "interserver-client", "web-admin"})
            required_services.extend(["admin", "wireguard", "transport"])
        return {
            "topology": topology,
            "node_id": "gateway",
            "location": "ru" if topology == "dual" else "foreign",
            "capabilities": frozenset(capabilities),
            "required_services": required_services,
            "service_units": {
                name: server_runtime.SERVICE_UNIT_DEFAULTS[name].format(wg_interface="wg0")
                for name in required_services
            },
        }

    @staticmethod
    def exit_contract() -> dict[str, object]:
        required_services = ["nftables", "sing-box", "resolver", "health_timer", "wireguard"]
        return {
            "topology": "dual",
            "node_id": "exit",
            "location": "foreign",
            "capabilities": frozenset({"interserver-server", "nat-exit"}),
            "required_services": required_services,
            "service_units": {
                name: server_runtime.SERVICE_UNIT_DEFAULTS[name].format(wg_interface="wg0")
                for name in required_services
            },
        }

    @staticmethod
    def single_manifest() -> dict[str, object]:
        capabilities = ["local-egress", "public-front", "router"]
        required = ["nftables", "sing-box", "resolver", "health_timer", "xray"]
        services = [
            {"name": name, "unit": server_runtime.SERVICE_UNIT_DEFAULTS[name].format(wg_interface="wg0")}
            for name in required
        ]
        node = {
            "id": "gateway",
            "location": "foreign",
            "capabilities": capabilities,
            "required_services": required,
        }
        platform = default_build_platform().to_dict()
        return {
            "schema_version": 5,
            "topology": "single",
            "node_id": "gateway",
            "location": "foreign",
            "capabilities": capabilities,
            "required_services": required,
            "node": node,
            "platform": platform,
            "install_plan": {
                "schema_version": 5,
                "topology": "single",
                "node_id": "gateway",
                "location": "foreign",
                "capabilities": capabilities,
                "required_services": required,
                "services": services,
                "platform": platform,
            },
        }

    def diagnostics_facts(self) -> dict[str, object]:
        generated_at = "2026-08-06T18:00:00+00:00"
        installed_at = "2026-08-06T17:59:00+00:00"
        observed = "2026-08-06T17:59:30+00:00"
        empty_logs = {**server_agent.summarize_lines([]), "observed_at": observed, "until": observed, "coverage": {}, "coverage_error": ""}
        return {
            **self.gateway_contract(),
            "generated_at": generated_at,
            "collector_observed_at": {
                name: (datetime.fromisoformat(generated_at) - timedelta(seconds=120 - index)).isoformat()
                for index, name in enumerate(server_agent.COLLECTOR_NAMES)
            },
            "deployment": "demo",
            "host": {"hostname": "ru", "login_user": "root", "is_root": True},
            "release": {"release_id": "release-1", "installed_at": installed_at},
            "services": {name: "active" for name in ("wireguard", "nftables", "sing-box", "resolver", "xray", "admin", "health_timer", "transport")},
            "artifacts": {"manifest": {"schema_version": 5, "release_id": "release-1"}, "drift": "none", "files": {"sing-box.json": {"actual_sha256": "a", "expected_sha256": "a"}}},
            "wireguard": {"interface": "wg0", "state": "up", "peers": []},
            "probes": {"profile": "acceptance", "ok": True},
            "storage": {
                "root_filesystem": {"source": "/dev/vda1", "verdict": "verified"},
                "runtime_events": {"oom_kills": {"counts": {"5m": 0}, "collector_error": ""}},
            },
            "network": {"tcp_adaptation": {"qdisc": "fq"}, "resolver": {"managed_config": True}, "conntrack": {
                "count": 1, "journal_evidence": {"counts": {"5": 0}, "collector_error": ""},
            }},
            "front": {"listening": True},
            "transport": {"interserver": {"configured": True}},
            "maintenance": {"upgradable": 0, "security_upgradable": 0, "reboot_required": False},
            "redundancy": {"egress": {"available": False}},
            "logs": {
                "collector_error": "",
                "windows_minutes": {key: dict(empty_logs) for key in ("5", "30", "1440")},
                "fresh": {"since": installed_at, "window_minutes": 1, **empty_logs},
            },
            "verdicts": {"overall": "verified", "server_path": "verified", "reasons": []},
        }
