from __future__ import annotations

import ast
import contextlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.config import generate_default_env
from vpn_installer import render
from vpn_installer.client_artifacts import PUBLIC_VLESS_OUTBOUND_TAG
from vpn_installer.common import cli_command
import json


def preferred_bash() -> str | None:
    candidates = [
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return shutil.which("bash")


class RenderTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        env["WAN_INTERFACE"] = "eth1"
        return env

    def make_single_env(self, location: str) -> dict[str, str]:
        env = generate_default_env("demo", topology="single", gateway_location=location)
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        return env

    def test_single_gateway_router_has_no_interserver_runtime(self) -> None:
        for location in ("ru", "foreign"):
            with self.subTest(location=location):
                payload = json.loads(render.render_gateway_singbox(self.make_single_env(location)))
                self.assertEqual(payload["dns"]["servers"], [{"type": "local", "tag": "dns-local"}])
                self.assertEqual(payload["dns"]["final"], "dns-local")
                self.assertEqual([item["tag"] for item in payload["inbounds"]], ["router-in", "public-hy2-in"])
                self.assertEqual(payload["endpoints"], [])
                self.assertEqual([item["tag"] for item in payload["outbounds"]], ["local-egress"])
                self.assertEqual(payload["route"]["final"], "local-egress")
                self.assertNotIn("rule_set", payload["route"])
                self.assertNotIn("clash_api", payload["experimental"])
                self.assertNotIn("wg0", json.dumps(payload))
                self.assertNotIn("interserver", json.dumps(payload))

    def test_single_gateway_xray_routes_every_public_flow_through_router(self) -> None:
        payload = json.loads(render.render_gateway_xray(self.make_single_env("foreign")))
        self.assertNotIn("dns", payload)
        self.assertEqual([item["tag"] for item in payload["outbounds"]], ["split-router", "blocked"])
        self.assertEqual(
            payload["routing"]["rules"][-1],
            {"type": "field", "network": "tcp,udp", "outboundTag": "split-router"},
        )
        self.assertNotIn("foreign-overlay", json.dumps(payload))
        self.assertNotIn("wg0", json.dumps(payload))

    def test_single_gateway_firewall_never_references_wireguard(self) -> None:
        env = self.make_single_env("ru")
        rules = render.render_ru_firewall_nftables(env)
        self.assertNotIn("wg0", rules)
        self.assertNotIn("11333", rules)

    def test_single_gateway_artifacts_omit_wireguard_and_transport_service(self) -> None:
        for location in ("ru", "foreign"):
            with self.subTest(location=location):
                files = render.rendered_files_for_node(self.make_single_env(location), "gateway")
                self.assertNotIn("wg0.conf", files)
                self.assertNotIn("vpn-stack-transport.service", files)
                self.assertIn("xray.json", files)
                self.assertNotIn("admin_web.py", files)
                self.assertNotIn("vpn-stack-admin.service", files)

    def test_web_admin_is_compiled_only_for_dual_gateway(self) -> None:
        single_files = render.rendered_files_for_node(self.make_single_env("foreign"), "gateway")
        dual_files = render.rendered_files_for_node(self.make_env(), "gateway")
        single_manifest = json.loads(single_files["render-manifest.json"])
        dual_manifest = json.loads(dual_files["render-manifest.json"])
        self.assertNotIn("admin_web.py", single_files)
        self.assertNotIn("vpn-stack-admin.service", single_files)
        self.assertNotIn("admin", single_manifest["required_services"])
        self.assertIn("admin_web.py", dual_files)
        self.assertIn("vpn-stack-admin.service", dual_files)
        self.assertIn("admin", dual_manifest["required_services"])

    def test_enabled_admin_gateway_keeps_operator_rules_hook(self) -> None:
        files = render.rendered_files_for_node(self.make_env(), "gateway")

        self.assertIn("admin_apply.py", files)
        self.assertIn("/etc/vpn-stack/current/admin_apply.py", files["sing-box.service"])

    def test_render_vless_uri(self) -> None:
        env = self.make_env()
        uri = render.render_vless_uri(env)
        self.assertTrue(uri.startswith("vless://"))
        self.assertTrue(uri.startswith(f"vless://{env['CLIENT_UUID']}@"))
        self.assertIn(f"@{env['GATEWAY_PUBLIC_IP']}:443?", uri)
        self.assertIn("?security=reality&", uri)
        self.assertNotIn("encryption=none", uri)
        self.assertIn("&sni=www.bing.com&", uri)
        self.assertIn("&fp=chrome&", uri)
        self.assertIn(f"&flow={env['CLIENT_FLOW']}", uri)

    def test_render_xray_client_profile_uses_reality_vless(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_xray_client_profile(env))
        self.assertNotIn("dns", payload)
        self.assertEqual(payload["routing"]["domainStrategy"], "AsIs")
        self.assertEqual(payload["inbounds"][0]["protocol"], "socks")
        self.assertEqual(payload["inbounds"][0]["sniffing"], {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False})
        outbound = payload["outbounds"][0]
        self.assertEqual(outbound["protocol"], "vless")
        self.assertEqual(outbound["settings"]["vnext"][0]["address"], env["GATEWAY_PUBLIC_IP"])
        self.assertEqual(outbound["settings"]["vnext"][0]["port"], int(env["RU_LISTEN_PORT"]))
        self.assertEqual(outbound["settings"]["vnext"][0]["users"][0]["id"], env["CLIENT_UUID"])
        self.assertEqual(outbound["streamSettings"]["security"], "reality")
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["fingerprint"], "chrome")
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["publicKey"], env["RU_REALITY_PUBLIC_KEY"])
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["shortId"], env["RU_REALITY_SHORT_ID"])
        self.assertEqual(outbound["mux"], {"enabled": False})
        self.assertEqual(
            payload["routing"]["rules"][0],
            {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
        )
        self.assertEqual(
            payload["routing"]["rules"][1],
            {"type": "field", "ip": [f"{env['GATEWAY_PUBLIC_IP']}/32", f"{env['EXIT_PUBLIC_IP']}/32"], "outboundTag": "direct"},
        )
        self.assertFalse(any(rule.get("network") == "udp" and rule.get("port") == 443 for rule in payload["routing"]["rules"]))

    def test_client_profile_is_simple_ru_tunnel(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_client_profile(env, auto_redirect=False))
        servers = {server["tag"]: server for server in payload["dns"]["servers"]}
        self.assertEqual(set(servers), {"dns-remote"})
        self.assertNotIn("reverse_mapping", payload["dns"])
        self.assertEqual(payload["dns"]["rules"], [{"query_type": ["AAAA"], "action": "reject"}])
        self.assertEqual(payload["route"]["final"], PUBLIC_VLESS_OUTBOUND_TAG)
        outbound = payload["outbounds"][0]
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["tag"], PUBLIC_VLESS_OUTBOUND_TAG)
        self.assertEqual(outbound["server"], env["GATEWAY_PUBLIC_IP"])
        self.assertEqual(outbound["server_port"], int(env["RU_LISTEN_PORT"]))
        self.assertEqual(outbound["multiplex"], {"enabled": False})
        self.assertNotIn("network", outbound)
        self.assertEqual(servers["dns-remote"]["detour"], PUBLIC_VLESS_OUTBOUND_TAG)
        self.assertEqual(payload["route"]["default_domain_resolver"]["server"], "dns-remote")
        self.assertEqual(payload["route"]["rules"][0], {"inbound": ["tun-in"], "action": "sniff", "timeout": "1s"})
        self.assertEqual(payload["route"]["rules"][1]["ip_version"], 6)
        self.assertEqual(
            payload["route"]["rules"][2],
            {"inbound": ["tun-in"], "port": 53, "action": "hijack-dns"},
        )
        self.assertFalse(any(rule.get("network") == "udp" and rule.get("port") == 443 for rule in payload["route"]["rules"]))
        self.assertEqual(payload["inbounds"][0]["address"], [env["CLIENT_TUN_ADDRESS_V4"]])
        self.assertNotIn("sniff", payload["inbounds"][0])
        self.assertNotIn("sniff_override_destination", payload["inbounds"][0])
        self.assertEqual(
            payload["inbounds"][0]["route_exclude_address"][:2],
            [f"{env['GATEWAY_PUBLIC_IP']}/32", f"{env['EXIT_PUBLIC_IP']}/32"],
        )

    def test_android_client_profile_is_ipv4_only_and_sets_android_override(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_client_profile(env, auto_redirect=False, android_safe=True))
        self.assertEqual(payload["inbounds"][0]["address"], [env["CLIENT_TUN_ADDRESS_V4"]])
        self.assertTrue(payload["route"]["override_android_vpn"])
        self.assertEqual(payload["route"]["final"], PUBLIC_VLESS_OUTBOUND_TAG)
        self.assertEqual(
            payload["inbounds"][0]["route_exclude_address"][:2],
            [f"{env['GATEWAY_PUBLIC_IP']}/32", f"{env['EXIT_PUBLIC_IP']}/32"],
        )

    def test_client_profile_preserves_manual_route_excludes_after_server_ips(self) -> None:
        env = self.make_env()
        env["CLIENT_ROUTE_EXCLUDE_V4"] = "198.51.100.10/32,198.51.100.11/32"
        env["CLIENT_ROUTE_EXCLUDE_V6"] = "2001:db8::/32"
        payload = json.loads(render.render_client_profile(env, auto_redirect=False))
        self.assertEqual(
            payload["inbounds"][0]["route_exclude_address"],
            [
                f"{env['GATEWAY_PUBLIC_IP']}/32",
                f"{env['EXIT_PUBLIC_IP']}/32",
                "198.51.100.10/32",
                "198.51.100.11/32",
                "2001:db8::/32",
            ],
        )

    def test_ru_server_config_sets_default_domain_resolver(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_singbox(env))
        self.assertEqual(payload["route"]["default_domain_resolver"]["server"], "dns-global")

    def test_ru_server_config_accepts_single_primary_vless_user(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_xray(env))
        clients = payload["inbounds"][0]["settings"]["clients"]
        self.assertEqual(clients, [{"id": env["CLIENT_UUID"], "flow": env["CLIENT_FLOW"], "email": "demo-client"}])

    def test_ru_server_config_uses_plain_vless_inbound_without_multiplex(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_xray(env))
        self.assertNotIn("multiplex", payload["inbounds"][0])
        self.assertEqual(
            payload["inbounds"][0]["streamSettings"]["sockopt"],
            {"tcpKeepAliveIdle": 90, "tcpKeepAliveInterval": 15},
        )

    def test_ru_server_config_uses_configured_log_level(self) -> None:
        env = self.make_env()
        env["SING_BOX_LOG_LEVEL"] = "info"
        payload = json.loads(render.render_gateway_singbox(env))
        self.assertEqual(payload["log"], {"level": "info", "timestamp": True})

    def test_ru_server_config_renders_xray_public_443_and_local_singbox_router(self) -> None:
        env = self.make_env()
        router_payload = json.loads(render.render_gateway_singbox(env))
        xray_payload = json.loads(render.render_gateway_xray(env))
        self.assertEqual([inbound["listen_port"] for inbound in router_payload["inbounds"]], [2080, 443, 19091, 19093, 19094])
        self.assertEqual(
            [inbound["tag"] for inbound in router_payload["inbounds"]],
            [
                "router-in",
                "public-hy2-in",
                "interserver-overlay-in",
                "interserver-probe-wg-in",
                "interserver-probe-hy2-in",
            ],
        )
        inbound_rules = [rule for rule in router_payload["route"]["rules"] if rule.get("inbound")]
        self.assertEqual(
            next(rule for rule in inbound_rules if rule.get("action") == "sniff"),
            {"inbound": ["router-in"], "action": "sniff", "timeout": "250ms"},
        )
        self.assertEqual(xray_payload["inbounds"][0]["port"], 443)
        self.assertEqual(xray_payload["outbounds"][0]["protocol"], "socks")
        self.assertEqual(xray_payload["outbounds"][0]["settings"]["servers"][0], {"address": "127.0.0.1", "port": 2080})
        foreign_overlay = xray_payload["outbounds"][1]
        self.assertEqual(foreign_overlay["protocol"], "freedom")
        self.assertEqual(foreign_overlay["tag"], "foreign-overlay")
        self.assertEqual(
            foreign_overlay["streamSettings"]["sockopt"],
            {"interface": env["WG_INTERFACE"], "mark": int(env["APP_ROUTE_MARK"])},
        )
        self.assertEqual(
            xray_payload["routing"]["rules"],
            [
                {"type": "field", "inboundTag": ["xray-global-dns"], "outboundTag": "foreign-overlay"},
                {
                    "type": "field",
                    "network": "udp",
                    "ip": list(render.PRIVATE_OR_FAKE_DESTINATION_CIDRS),
                    "outboundTag": "blocked",
                },
                {"type": "field", "network": "udp", "outboundTag": "foreign-overlay"},
            ],
        )
        self.assertEqual(xray_payload["outbounds"][2], {"protocol": "blackhole", "tag": "blocked"})
        self.assertEqual(xray_payload["dns"]["servers"][0]["address"], f"tcp://{env['WG_FOREIGN_ADDRESS'].split('/', 1)[0]}")
        self.assertIn(
            {
                "inbound": ["public-hy2-in"],
                "port": 53,
                "action": "route",
                "outbound": "to-foreign",
            },
            router_payload["route"]["rules"],
        )

    def test_ru_server_reality_sets_explicit_time_tolerance_by_default(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_xray(env))
        reality = payload["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(payload["inbounds"][0]["port"], 443)
        self.assertEqual(reality["target"], "r.bing.com:443")
        self.assertNotIn("dest", reality)
        self.assertNotIn("maxTimeDiff", reality)

    def test_ru_server_reality_accepts_primary_and_empty_short_id_by_default(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_xray(env))
        reality = payload["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["shortIds"], [env["RU_REALITY_SHORT_ID"], ""])

    def test_ru_server_reality_keeps_custom_sni_and_target_consistent(self) -> None:
        env = self.make_env()
        env["RU_REALITY_SERVER_NAME"] = "www.cloudflare.com"
        payload = json.loads(render.render_gateway_xray(env))
        reality = payload["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["serverNames"], ["www.cloudflare.com"])
        self.assertEqual(reality["target"], "www.cloudflare.com:443")

    def test_ru_server_reality_can_disable_empty_short_id_compat(self) -> None:
        env = self.make_env()
        env["RU_REALITY_ACCEPT_EMPTY_SHORT_ID"] = "0"
        payload = json.loads(render.render_gateway_xray(env))
        reality = payload["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["shortIds"], [env["RU_REALITY_SHORT_ID"]])

    def test_ru_server_reality_can_render_explicit_time_tolerance(self) -> None:
        env = self.make_env()
        env["RU_REALITY_MAX_TIME_DIFFERENCE"] = "30s"
        payload = json.loads(render.render_gateway_xray(env))
        reality = payload["inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertNotIn("maxTimeDiff", reality)

    def test_ru_server_dns_servers_keep_global_detour_but_not_direct_detour(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_singbox(env))
        servers = {server["tag"]: server for server in payload["dns"]["servers"]}
        self.assertIn("dns-ru-direct", servers)
        self.assertEqual(servers["dns-ru-direct"], {"type": "local", "tag": "dns-ru-direct"})
        self.assertNotIn("detour", servers["dns-ru-direct"])
        self.assertEqual(servers["dns-global"]["detour"], "to-foreign")

    def test_ru_server_does_not_suppress_or_reject_aaaa(self) -> None:
        payload = json.loads(render.render_gateway_singbox(self.make_env()))
        self.assertFalse(
            any(
                "AAAA" in rule.get("query_type", []) and rule.get("action") in {"reject", "predefined"}
                for rule in payload["dns"]["rules"]
            )
        )
        self.assertEqual(payload["dns"]["strategy"], "prefer_ipv4")

    def test_health_service_delegates_to_agent(self) -> None:
        service = render.render_health_service()
        self.assertIn("ExecStartPre=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py network-apply", service)
        self.assertIn("ExecStart=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py health", service)
        self.assertNotIn("sync-state.sh", service)

    def test_transport_service_reconciles_before_starting_the_watcher(self) -> None:
        service = render.render_transport_service(self.make_env())
        self.assertIn("ExecStartPre=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py transport-reconcile", service)
        self.assertIn("ExecStart=/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py transport-watch", service)
        self.assertIn("AF_NETLINK", service)

    def test_ru_server_uses_one_stable_overlay_for_domains_and_literals(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_singbox(env))
        route_rules = payload["route"]["rules"]
        outbounds = {outbound["tag"]: outbound for outbound in payload["outbounds"]}
        domain_foreign_index = next(
            index
            for index, rule in enumerate(route_rules)
            if rule.get("domain_regex") == ["^[^:]*[A-Za-z][^:]*$"]
            and rule.get("action") == "route"
            and rule.get("outbound") == "to-foreign"
        )
        ipv6_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_version") == 6)
        ipv4_literal_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        raw_ru_geoip_index = next(index for index, rule in enumerate(route_rules) if rule.get("rule_set") == ["ru-geoip"])
        self.assertEqual(
            set(outbounds),
            {"direct-ru", "to-foreign", "interserver-underlay-hy2", "interserver-underlay-select"},
        )
        self.assertEqual(outbounds["to-foreign"]["type"], "direct")
        self.assertEqual(outbounds["to-foreign"]["bind_interface"], env["WG_INTERFACE"])
        self.assertEqual(outbounds["interserver-underlay-hy2"]["server"], env["EXIT_PUBLIC_IP"])
        self.assertEqual(outbounds["interserver-underlay-hy2"]["obfs"]["type"], "salamander")
        self.assertNotIn("up_mbps", outbounds["interserver-underlay-hy2"])
        self.assertNotIn("down_mbps", outbounds["interserver-underlay-hy2"])
        self.assertEqual(
            outbounds["interserver-underlay-select"],
            {
                "type": "selector",
                "tag": "interserver-underlay-select",
                "outbounds": ["interserver-underlay-wg", "interserver-underlay-hy2"],
                "default": "interserver-underlay-wg",
                "interrupt_exist_connections": True,
            },
        )
        endpoints = {endpoint["tag"]: endpoint for endpoint in payload["endpoints"]}
        self.assertEqual(endpoints["interserver-underlay-wg"]["type"], "wireguard")
        relay_routes = route_rules[:3]
        self.assertEqual(
            [rule["outbound"] for rule in relay_routes],
            ["interserver-underlay-select", "interserver-underlay-wg", "interserver-underlay-hy2"],
        )
        self.assertEqual(payload["experimental"]["clash_api"]["external_controller"], "127.0.0.1:19090")
        self.assertEqual(
            payload["experimental"]["cache_file"],
            {"enabled": True, "path": "/var/lib/vpn-stack/cache.db"},
        )
        self.assertEqual(route_rules[ipv6_index], {"ip_version": 6, "action": "route", "outbound": "to-foreign"})
        self.assertEqual(route_rules[ipv4_literal_index], {"ip_cidr": ["0.0.0.0/0"], "action": "route", "outbound": "to-foreign"})
        self.assertEqual(payload["route"]["final"], "to-foreign")
        self.assertEqual(route_rules[domain_foreign_index]["outbound"], "to-foreign")
        self.assertLess(domain_foreign_index, raw_ru_geoip_index)
        self.assertLess(raw_ru_geoip_index, ipv6_index)
        self.assertLess(ipv6_index, ipv4_literal_index)
        self.assertTrue(any(rule.get("action") == "resolve" and rule.get("server") == "dns-global" for rule in route_rules))
        self.assertNotIn("connect_timeout", outbounds["to-foreign"])
        self.assertEqual(payload["dns"]["cache_capacity"], 4096)
        self.assertNotIn("independent_cache", payload["dns"])

    def test_ru_server_allows_configurable_sniff_timeout(self) -> None:
        env = self.make_env()
        env["RU_SNIFF_TIMEOUT"] = "1500ms"
        payload = json.loads(render.render_gateway_singbox(env))
        sniff = next(rule for rule in payload["route"]["rules"] if rule.get("action") == "sniff")
        self.assertEqual(sniff["timeout"], "1500ms")

    def test_ru_server_rejects_client_tun_dot_without_dns_override(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_singbox(env))
        route_rules = payload["route"]["rules"]
        self.assertIn({"ip_is_private": True, "action": "reject", "method": "default", "no_drop": True}, route_rules)
        self.assertFalse(any(rule.get("port") == 853 for rule in route_rules))
        client_rules = [rule for rule in route_rules if rule.get("inbound") == ["router-in"] or not rule.get("inbound")]
        self.assertFalse(any("override_address" in rule for rule in client_rules))

    def test_ru_server_routes_own_public_ip_direct_before_foreign_catchall(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_singbox(env))
        route_rules = payload["route"]["rules"]
        own_ip_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == [f"{env['GATEWAY_PUBLIC_IP']}/32"])
        ipv4_literal_index = next(index for index, rule in enumerate(route_rules) if rule.get("ip_cidr") == ["0.0.0.0/0"])
        self.assertEqual(route_rules[own_ip_index]["outbound"], "direct-ru")
        self.assertLess(own_ip_index, ipv4_literal_index)

    def test_ru_server_resolves_direct_domains_at_the_selected_outbound(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_singbox(env))
        route_rules = payload["route"]["rules"]
        direct_outbound = next(item for item in payload["outbounds"] if item["tag"] == "direct-ru")
        self.assertTrue(any(rule.get("outbound") == "direct-ru" and "domain" in rule for rule in route_rules))
        self.assertTrue(any(rule.get("outbound") == "direct-ru" and rule.get("rule_set") == ["ru-geosite"] for rule in route_rules))
        self.assertTrue(any(rule.get("action") == "resolve" and rule.get("server") == "dns-ru-direct" for rule in route_rules))
        self.assertEqual(direct_outbound["domain_resolver"], {"server": "dns-ru-direct", "strategy": "ipv4_only"})

    def test_ru_server_config_forces_selected_domains_and_suffixes_direct(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_gateway_singbox(env))
        dns_rules = payload["dns"]["rules"]
        route_rules = payload["route"]["rules"]

        direct_domain_dns_rule = next(rule for rule in dns_rules if rule.get("action") == "route" and rule.get("server") == "dns-ru-direct" and "domain" in rule)
        self.assertIn("api.oneme.ru", direct_domain_dns_rule["domain"])
        self.assertIn("api.ok.ru", direct_domain_dns_rule["domain"])
        self.assertNotIn("checkip.amazonaws.com", direct_domain_dns_rule["domain"])
        self.assertNotIn("ident.me", direct_domain_dns_rule["domain"])
        self.assertIn("ip.mail.ru", direct_domain_dns_rule["domain"])
        self.assertIn("ipv4-internet.yandex.net", direct_domain_dns_rule["domain"])
        self.assertNotIn("ipv6-internet.yandex.net", direct_domain_dns_rule["domain"])
        self.assertIn("2ip.ru", direct_domain_dns_rule["domain"])
        self.assertNotIn("www.msftconnecttest.com", direct_domain_dns_rule["domain"])
        self.assertNotIn("mtalk.google.com", direct_domain_dns_rule["domain"])
        ipv6_probe_rule = next(rule for rule in dns_rules if "ipv6.msftconnecttest.com" in rule.get("domain", []))
        self.assertEqual(ipv6_probe_rule["action"], "route")
        self.assertEqual(ipv6_probe_rule["server"], "dns-global")
        self.assertEqual(ipv6_probe_rule["strategy"], "prefer_ipv4")
        self.assertIn("ipv6-internet.yandex.net", ipv6_probe_rule["domain"])

        direct_suffix_dns_rule = next(
            rule
            for rule in dns_rules
            if "domain_suffix" in rule and rule.get("server") == "dns-ru-direct"
        )
        self.assertNotIn(".gstatic.com", direct_suffix_dns_rule["domain_suffix"])
        self.assertNotIn(".ipify.org", direct_suffix_dns_rule["domain_suffix"])
        self.assertNotIn(".ipinfo.io", direct_suffix_dns_rule["domain_suffix"])
        self.assertEqual(direct_suffix_dns_rule["domain_suffix"], [".gosuslugi.ru"])

        direct_domain_route_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain" in rule)
        self.assertIn("gosuslugi.ru", direct_domain_route_rule["domain"])
        self.assertNotIn("ipapi.co", direct_domain_route_rule["domain"])
        self.assertNotIn("www.msftncsi.com", direct_domain_route_rule["domain"])
        self.assertNotIn("icanhazip.com", direct_domain_route_rule["domain"])
        self.assertIn("ip.mail.ru", direct_domain_route_rule["domain"])
        self.assertIn("ipv4-internet.yandex.net", direct_domain_route_rule["domain"])
        self.assertNotIn("ipv6-internet.yandex.net", direct_domain_route_rule["domain"])
        self.assertIn("2ip.ru", direct_domain_route_rule["domain"])

        direct_suffix_route_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain_suffix" in rule)
        self.assertNotIn(".ident.me", direct_suffix_route_rule["domain_suffix"])
        self.assertNotIn(".icanhazip.com", direct_suffix_route_rule["domain_suffix"])
        self.assertEqual(direct_suffix_route_rule["domain_suffix"], [".gosuslugi.ru"])
        self.assertNotIn(".gstatic.com", direct_suffix_route_rule["domain_suffix"])

        self.assertFalse(any(rule.get("domain") == ["api.ok.ru"] and rule.get("outbound") == "block" for rule in route_rules))

    def test_ru_server_can_block_explicit_ip_cidr(self) -> None:
        env = self.make_env()
        env["RU_BLOCK_IP_CIDR"] = "203.0.113.0/24,198.51.100.4/32"
        payload = json.loads(render.render_gateway_singbox(env))
        block_cidr_route_rule = next(rule for rule in payload["route"]["rules"] if rule.get("action") == "reject" and "ip_cidr" in rule)
        self.assertEqual(block_cidr_route_rule["ip_cidr"], ["203.0.113.0/24", "198.51.100.4/32"])

    def test_ru_server_config_supports_forced_direct_ip_cidr(self) -> None:
        env = self.make_env()
        env["RU_FORCE_DIRECT_IP_CIDR"] = "203.0.113.0/24,198.51.100.4/32"
        payload = json.loads(render.render_gateway_singbox(env))
        cidr_rule = next(rule for rule in payload["route"]["rules"] if rule.get("outbound") == "direct-ru" and "ip_cidr" in rule)
        self.assertEqual(cidr_rule["ip_cidr"], ["203.0.113.0/24", "198.51.100.4/32", f"{env['GATEWAY_PUBLIC_IP']}/32"])

    def test_render_next_steps_mentions_uri_first_contract(self) -> None:
        env = self.make_env()
        text = render.render_next_steps(env)
        self.assertIn("VLESS URI", text)
        self.assertIn("Основной простой VLESS URI", text)
        self.assertIn("android-v2rayng-xray.json", text)
        self.assertIn("multiplex", text)
        self.assertIn("fake IP", text)
        self.assertIn("v2rayNG", text)
        self.assertIn("Hiddify", text)
        self.assertIn("windows-xray.json", text)
        self.assertIn(cli_command("status"), text)
        self.assertIn("vless-uri.txt", text)
        self.assertIn("hiddify-cross-platform.json", text)
        self.assertIn("hiddify-android.json", text)
        self.assertIn("windows-route-bypass.ps1", text)
        self.assertIn("Совместимый Hiddify URI alias", text)

    def test_render_client_profiles_writes_user_artifacts(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                render.render_client_profiles(env)
                client_dir = Path(tmp) / "demo" / "client"
                self.assertTrue((client_dir / "vless-uri.txt").is_file())
                self.assertTrue((client_dir / "windows-xray.json").is_file())
                self.assertTrue((client_dir / "android-v2rayng-xray.json").is_file())
                self.assertTrue((client_dir / "hiddify-cross-platform.json").is_file())
                self.assertTrue((client_dir / "hiddify-android.json").is_file())
                self.assertTrue((client_dir / "hiddify-uri.txt").is_file())
                self.assertTrue((client_dir / "windows-route-bypass.ps1").is_file())
                self.assertTrue((client_dir.parent / "NEXT-STEPS.txt").is_file())

    def test_cloud_init_artifacts_embed_renderer_without_stale_role_files(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                out_dir = Path(tmp) / "demo"
                assets_dir = out_dir / "assets"
                assets_dir.mkdir(parents=True, exist_ok=True)
                for asset_name in ("geosite-ru.srs", "geoip-ru.srs", "ru-ipv4.zone", "ru-ipv6.zone"):
                    (assets_dir / asset_name).write_text("dummy\n", encoding="utf-8")
                cloud_dir = render.render_cloud_init_artifacts(env)
                gateway_yaml = (cloud_dir / "gateway.yaml").read_text(encoding="utf-8")
                exit_yaml = (cloud_dir / "exit.yaml").read_text(encoding="utf-8")
                self.assertIn("/root/vpn-stack/vpn_installer/install_support.py", gateway_yaml)
                self.assertIn("./install.sh --node gateway", gateway_yaml)
                self.assertIn("--assets-dir /root/vpn-stack/assets", gateway_yaml)
                self.assertNotIn("--assets-dir /root/vpn-stack/assets", exit_yaml)
                self.assertNotIn("/root/vpn-stack/rendered/", gateway_yaml)

    def test_server_render_package_closes_module_level_dependencies(self) -> None:
        package_dir = Path(render.__file__).parent
        selected = {Path(name).stem for name in render.SERVER_RENDER_MODULES}
        available = {path.stem for path in package_dir.glob("*.py")}
        missing: dict[str, list[str]] = {}

        for filename in render.SERVER_RENDER_MODULES:
            module_name = Path(filename).stem
            tree = ast.parse((package_dir / filename).read_text(encoding="utf-8"))
            dependencies = {
                node.module.split(".", 1)[0]
                for node in tree.body
                if isinstance(node, ast.ImportFrom)
                and node.level == 1
                and node.module
                and node.module.split(".", 1)[0] in available
                and node.module.split(".", 1)[0] not in selected
            }
            if dependencies:
                missing[module_name] = sorted(dependencies)

        self.assertEqual(missing, {})

    def test_fetch_assets_fail_fast_without_cache(self) -> None:
        env = self.make_env()
        env["FOREIGN_BLOCK_RU"] = "1"
        env["RU_GEOSITE_URL"] = "http://127.0.0.1:9/geosite-ru.srs"
        env["RU_GEOIP_URL"] = "http://127.0.0.1:9/geoip-ru.srs"
        env["FOREIGN_RU_IPV4_LIST_URL"] = "http://127.0.0.1:9/ru-ipv4.zone"
        env["FOREIGN_RU_IPV6_LIST_URL"] = "http://127.0.0.1:9/ru-ipv6.zone"
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp) / "out"), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(Exception):
                    render.fetch_assets(env, Path(tmp))

    def test_fetch_assets_uses_global_cache_after_source_failures(self) -> None:
        env = self.make_env()
        env["FOREIGN_BLOCK_RU"] = "1"
        env["RU_GEOSITE_URL"] = "https://cache-fail.example/geosite-ru.srs"
        env["RU_GEOIP_URL"] = "https://cache-fail.example/geoip-ru.srs"
        env["FOREIGN_RU_IPV4_LIST_URL"] = "https://cache-fail.example/ru-ipv4.zone"
        env["FOREIGN_RU_IPV6_LIST_URL"] = "https://cache-fail.example/ru-ipv6.zone"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cache_dir = tmp_path / "out" / "cached" / "assets"
            cache_dir.mkdir(parents=True)
            for asset_name in ("geosite-ru.srs", "geoip-ru.srs", "ru-ipv4.zone", "ru-ipv6.zone"):
                (cache_dir / asset_name).write_text(f"cached {asset_name}\n", encoding="utf-8")

            with patch.object(render, "OUT_DIR", tmp_path / "out"), patch.object(render, "download_asset", side_effect=OSError("boom")), contextlib.redirect_stderr(io.StringIO()):
                result = render.fetch_assets(env, tmp_path / "out" / "new" / "assets")

            for asset_name in ("geosite-ru.srs", "geoip-ru.srs", "ru-ipv4.zone", "ru-ipv6.zone"):
                self.assertEqual(result[asset_name].read_text(encoding="utf-8"), f"cached {asset_name}\n")

    def test_fetch_assets_tries_next_source_after_failure(self) -> None:
        env = self.make_env()
        env["FOREIGN_BLOCK_RU"] = "1"
        env["RU_GEOSITE_URL"] = "https://bad.example/geosite-ru.srs https://good.example/geosite-ru.srs"
        env["RU_GEOIP_URL"] = "https://good.example/geoip-ru.srs"
        env["FOREIGN_RU_IPV4_LIST_URL"] = "https://good.example/ru-ipv4.zone"
        env["FOREIGN_RU_IPV6_LIST_URL"] = "https://good.example/ru-ipv6.zone"

        calls: list[str] = []

        def fake_download(source: str, destination: Path, asset_name: str) -> None:
            calls.append(source)
            if source.startswith("https://bad.example/"):
                raise OSError("boom")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(f"{asset_name}\n", encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "download_asset", side_effect=fake_download):
                result = render.fetch_assets(env, Path(tmp))
                self.assertTrue(result["geosite-ru.srs"].is_file())
        self.assertIn("https://bad.example/geosite-ru.srs", calls)
        self.assertIn("https://good.example/geosite-ru.srs", calls)

    def test_client_artifact_paths_contract(self) -> None:
        env = self.make_env()
        paths = render.client_artifact_paths(env)
        self.assertEqual(paths["vless_uri"].name, "vless-uri.txt")
        self.assertEqual(paths["hiddify_uri_compat"].name, "hiddify-uri.txt")
        self.assertEqual(paths["hiddify_json"].name, "hiddify-cross-platform.json")
        self.assertEqual(paths["android_hiddify_json"].name, "hiddify-android.json")
        self.assertEqual(paths["linux_json"].name, "linux-sing-box.json")
        self.assertEqual(paths["windows_xray_json"].name, "windows-xray.json")
        self.assertEqual(paths["android_xray_json"].name, "android-v2rayng-xray.json")
        self.assertEqual(paths["windows_route_bypass"].name, "windows-route-bypass.ps1")
        self.assertEqual(paths["next_steps"].name, "NEXT-STEPS.txt")

    def test_render_windows_route_bypass_script_contains_server_ips_and_active_store(self) -> None:
        env = self.make_env()
        script = render.render_windows_route_bypass_script(env)
        self.assertIn(env["GATEWAY_PUBLIC_IP"], script)
        self.assertIn(env["EXIT_PUBLIC_IP"], script)
        self.assertIn("PolicyStore ActiveStore", script)
        self.assertIn("Get-PhysicalGatewayRoute", script)
        self.assertIn("TunnelInterfacePattern", script)

    def test_render_client_profiles_keeps_hiddify_uri_alias_equal_to_primary_uri(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                render.render_client_profiles(env)
                client_dir = Path(tmp) / "demo" / "client"
                self.assertEqual(
                    (client_dir / "vless-uri.txt").read_text(encoding="utf-8"),
                    (client_dir / "hiddify-uri.txt").read_text(encoding="utf-8"),
                )

    def test_render_client_profiles_removes_stale_subscription_artifacts(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                client_dir = Path(tmp) / "demo" / "client"
                client_dir.mkdir(parents=True)
                stale_files = [
                    client_dir / "vless-uri-compatible.txt",
                    client_dir / "hiddify-subscription-url.txt",
                    client_dir / "hiddify-import-url.txt",
                    client_dir / "hiddify-android-subscription-url.txt",
                ]
                for path in stale_files:
                    path.write_text("stale\n", encoding="utf-8")

                render.render_client_profiles(env)

                for path in stale_files:
                    self.assertFalse(path.exists(), f"stale client artifact survived render: {path.name}")
                self.assertTrue((client_dir / "vless-uri.txt").is_file())

    def test_render_client_profiles_does_not_delete_client_directory(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                client_dir = Path(tmp) / "demo" / "client"
                client_dir.mkdir(parents=True)
                marker = client_dir / "operator-notes.txt"
                marker.write_text("keep\n", encoding="utf-8")

                with patch.object(render.shutil, "rmtree", side_effect=AssertionError("client directory must not be reset")):
                    render.render_client_profiles(env)

                self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
                self.assertTrue((client_dir / "vless-uri.txt").is_file())

    def test_rendered_files_for_node_contains_core_contract(self) -> None:
        env = self.make_env()
        files = render.rendered_files_for_node(env, render.NODE_GATEWAY)
        self.assertIn("sing-box.json", files)
        self.assertIn("xray.json", files)
        self.assertIn(f"{env['WG_INTERFACE']}.conf", files)
        self.assertIn("sshd-vpn-stack.conf", files)
        self.assertIn("sysctl-vpn-stack.conf", files)
        self.assertIn("journald-vpn-stack.conf", files)
        self.assertIn("apt-vpn-stack-unattended.conf", files)
        self.assertIn("resolved-vpn-stack.conf", files)
        self.assertIn("vpn-stack-agent.py", files)
        self.assertIn("log_classifier.py", files)
        self.assertIn("release_integrity.py", files)
        self.assertNotIn("guard.sh", files)
        self.assertNotIn("sync-state.sh", files)
        self.assertNotIn("vpn-stack-sync.service", files)
        self.assertIn("vpn-stack-health.service", files)
        self.assertIn("vpn-stack-health.timer", files)
        self.assertIn("vpn-stack-transport.service", files)
        self.assertIn("interserver_transport.py", files)
        self.assertIn("network_profile.py", files)
        self.assertNotIn("vpn-stack-guard.service", files)
        self.assertNotIn("vpn-stack-guard.timer", files)
        self.assertIn("admin_apply.py", files)
        self.assertIn("admin_web.py", files)
        self.assertIn("vpn-stack-admin.service", files)
        self.assertIn("vpn-stack-xray.service", files)
        foreign_files = render.rendered_files_for_node(env, render.NODE_EXIT)
        self.assertIn("interserver_transport.py", foreign_files)
        self.assertIn("network_profile.py", foreign_files)
        self.assertNotIn("vpn-stack-transport.service", foreign_files)
        self.assertNotIn("admin_apply.py", foreign_files)
        self.assertNotIn("admin_web.py", foreign_files)
        self.assertNotIn("vpn-stack-admin.service", foreign_files)

    def test_runtime_dropins_are_renderer_owned_and_role_specific(self) -> None:
        env = self.make_env()
        ru_files = render.rendered_files_for_node(env, render.NODE_GATEWAY)
        foreign_files = render.rendered_files_for_node(env, render.NODE_EXIT)
        self.assertIn("net.ipv4.tcp_mtu_probing=1", ru_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.ipv4.tcp_mtu_probing=1", foreign_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.ipv4.tcp_mtu_probe_floor=536", ru_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.ipv4.tcp_no_metrics_save=0", ru_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.core.rmem_default=8388608", ru_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.core.rmem_max=16777216", foreign_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.core.wmem_default=8388608", foreign_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.core.wmem_max=16777216", foreign_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.ipv4.conf.all.src_valid_mark=1", ru_files["sysctl-vpn-stack.conf"])
        self.assertIn("net.ipv4.ip_forward=1", foreign_files["sysctl-vpn-stack.conf"])
        self.assertIn('APT::Periodic::Unattended-Upgrade "1";', ru_files["apt-vpn-stack-unattended.conf"])
        self.assertIn("DNS=1.1.1.1 9.9.9.9 8.8.8.8", ru_files["resolved-vpn-stack.conf"])
        self.assertIn("Cache=yes", foreign_files["resolved-vpn-stack.conf"])
        self.assertIn("StaleRetentionSec=1h", foreign_files["resolved-vpn-stack.conf"])
        self.assertIn(f"SystemMaxUse={env['JOURNAL_SYSTEM_MAX_USE']}", ru_files["journald-vpn-stack.conf"])
        env["JOURNAL_LIMIT_ENABLED"] = "0"
        self.assertNotIn("journald-vpn-stack.conf", render.rendered_files_for_node(env, render.NODE_GATEWAY))

    def test_ru_wireguard_hooks_are_restart_safe(self) -> None:
        env = self.make_env()
        config = render.render_ru_wg(env)
        foreign_wg_host = render.wg_host_address(env["WG_FOREIGN_ADDRESS"])
        foreign_wg_v6_host = render.wg_host_address(env["WG_FOREIGN_ADDRESS_V6"])
        self.assertIn(f"Address = {env['WG_RU_ADDRESS']}, {env['WG_RU_ADDRESS_V6']}", config)
        self.assertIn(f"PostUp = ip -4 route replace {foreign_wg_host}/32 dev {env['WG_INTERFACE']}", config)
        self.assertIn(f"PostUp = ip -6 route replace {foreign_wg_v6_host}/128 dev {env['WG_INTERFACE']}", config)
        self.assertIn(f"PostUp = ip -4 route replace default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']}", config)
        self.assertIn(f"PostUp = ip -6 route replace default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']}", config)
        self.assertIn(
            f"PostUp = ip -4 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000 2>/dev/null || true",
            config,
        )
        self.assertIn(
            f"PostUp = ip -6 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000 2>/dev/null || true",
            config,
        )
        self.assertIn(
            f"PreDown = ip -4 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000 2>/dev/null || true",
            config,
        )
        self.assertIn(
            f"PreDown = ip -6 rule del fwmark {env['APP_ROUTE_MARK']} table {env['WG_ROUTE_TABLE']} priority 10000 2>/dev/null || true",
            config,
        )
        self.assertIn(f"PreDown = ip -4 route del default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']} 2>/dev/null || true", config)
        self.assertIn(f"PreDown = ip -6 route del default dev {env['WG_INTERFACE']} table {env['WG_ROUTE_TABLE']} 2>/dev/null || true", config)
        self.assertIn(f"PreDown = ip -4 route del {foreign_wg_host}/32 dev {env['WG_INTERFACE']} 2>/dev/null || true", config)
        self.assertIn(f"PreDown = ip -6 route del {foreign_wg_v6_host}/128 dev {env['WG_INTERFACE']} 2>/dev/null || true", config)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", config)
        self.assertIn("Endpoint = 127.0.0.1:19091", config)
        self.assertIn("PersistentKeepalive = 1", config)
        self.assertNotIn("PostUp = ip -4 route add default", config)

    def test_foreign_wireguard_accepts_ru_ipv4_and_ipv6_peer_addresses(self) -> None:
        env = self.make_env()
        config = render.render_foreign_wg(env)
        self.assertIn(f"Address = {env['WG_FOREIGN_ADDRESS']}, {env['WG_FOREIGN_ADDRESS_V6']}", config)
        self.assertIn(
            f"AllowedIPs = {render.wg_host_address(env['WG_RU_ADDRESS'])}/32, {render.wg_host_address(env['WG_RU_ADDRESS_V6'])}/128",
            config,
        )

    def test_foreign_singbox_terminates_pinned_hysteria2_without_fixed_bandwidth(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_foreign_singbox(env))
        inbound = next(item for item in payload["inbounds"] if item["tag"] == "interserver-hy2-in")
        self.assertEqual(inbound["type"], "hysteria2")
        self.assertEqual(inbound["tag"], "interserver-hy2-in")
        self.assertNotIn("up_mbps", inbound)
        self.assertNotIn("down_mbps", inbound)
        self.assertEqual(inbound["obfs"]["type"], "salamander")
        self.assertTrue(inbound["tls"]["certificate"][0].startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(inbound["tls"]["key"][0].startswith("-----BEGIN PRIVATE KEY-----"))

    def test_foreign_dns_relay_accepts_inner_tcp_and_underlay_udp(self) -> None:
        env = self.make_env()
        payload = json.loads(render.render_foreign_singbox(env))
        inbound = next(item for item in payload["inbounds"] if item["tag"] == "dns-relay-in")
        self.assertEqual(inbound["listen"], "0.0.0.0")
        self.assertNotIn("network", inbound)
        self.assertEqual((inbound["override_address"], inbound["override_port"]), ("127.0.0.53", 53))
        nftables = render.render_foreign_nftables(env, "eth0")
        self.assertIn(
            f'iifname "{env["WG_INTERFACE"]}" ip saddr 10.75.0.1 udp dport 1053 counter accept',
            nftables,
        )

    def test_render_sshd_hardening_uses_expected_limits(self) -> None:
        env = self.make_env()
        config = render.render_sshd_hardening(env)
        self.assertIn("LoginGraceTime 20", config)
        self.assertIn("MaxAuthTries 3", config)
        self.assertIn("MaxStartups 10:30:60", config)
        self.assertIn("PerSourceMaxStartups 6", config)

    def test_render_ru_nftables_admits_ssh_and_vless_without_log_driven_blocks(self) -> None:
        env = self.make_env()
        rules = render.render_ru_firewall_nftables(env)
        self.assertIn("type filter hook prerouting priority raw", rules)
        self.assertIn(f'tcp dport {env["RU_LISTEN_PORT"]} counter notrack comment "vpnstack-xray-in-notrack"', rules)
        self.assertIn("type filter hook output priority raw", rules)
        self.assertIn(f'tcp sport {env["RU_LISTEN_PORT"]} counter notrack comment "vpnstack-xray-out-notrack"', rules)
        self.assertIn("ct state invalid drop", rules)
        self.assertNotIn("abuse_ipv4", rules)
        self.assertIn(f"tcp dport {env['SSH_PORT']} counter accept", rules)
        self.assertNotIn("ssh_guard", rules)
        self.assertNotIn(f"tcp dport {env['SSH_PORT']} counter drop", rules)
        self.assertIn(f"tcp dport {env['RU_LISTEN_PORT']} counter accept", rules)
        self.assertNotIn("tcp dport 8443 counter accept", rules)
        self.assertNotIn("vless_guard", rules)
        self.assertNotIn(f"tcp dport {env['RU_LISTEN_PORT']} counter drop", rules)
        self.assertNotIn("subscription_guard", rules)
        self.assertNotIn("admin_clients_ipv4", rules)
        self.assertNotIn("tcp dport 11333", rules)
        self.assertNotIn("flush ruleset", rules)
        self.assertNotIn("table ip nat", rules)
        self.assertNotIn("table ip6 nat", rules)

    def test_render_ru_nftables_gates_dual_admin_by_recent_public_vpn_source(self) -> None:
        env = self.make_env()
        rules = render.render_ru_firewall_nftables(env, web_admin=True)
        self.assertIn("set admin_clients_ipv4", rules)
        self.assertIn("set admin_clients_ipv6", rules)
        self.assertIn("timeout 3m", rules)
        self.assertIn(f"tcp dport {env['ADMIN_WEB_PORT']} ip saddr @admin_clients_ipv4", rules)
        self.assertNotIn("0.0.0.0/0", rules)

    def test_render_foreign_nftables_admits_ssh_without_log_driven_blocks(self) -> None:
        env = self.make_env()
        rules = render.render_foreign_nftables(env, "eth0")
        self.assertIn("ct state invalid drop", rules)
        self.assertNotIn("abuse_ipv4", rules)
        self.assertNotIn("set ru_ipv4", rules)
        self.assertNotIn("ip daddr @ru_ipv4 drop", rules)
        self.assertIn(f"tcp dport {env['SSH_PORT']} counter accept", rules)
        self.assertNotIn("ssh_guard", rules)
        self.assertNotIn(f"tcp dport {env['SSH_PORT']} counter drop", rules)
        self.assertIn(f"ip saddr {env['GATEWAY_PUBLIC_IP']} udp dport {env['WG_PORT']} counter accept", rules)
        self.assertNotIn(f"    udp dport {env['WG_PORT']} accept", rules)
        self.assertIn(f"ip saddr {env['GATEWAY_PUBLIC_IP']} udp dport 18443 counter accept", rules)
        self.assertIn(f'iifname "{env["WG_INTERFACE"]}" oifname "eth0" tcp flags syn tcp option maxseg size set 1320 accept', rules)
        self.assertIn(f'iifname "eth0" oifname "{env["WG_INTERFACE"]}" tcp flags syn tcp option maxseg size set 1320 accept', rules)
        self.assertIn("table ip vpnstack_nat4", rules)
        self.assertIn("table ip6 vpnstack_nat6", rules)
        self.assertNotIn("table ip nat", rules)
        self.assertNotIn("table ip6 nat", rules)
        self.assertNotIn("flush ruleset", rules)
        self.assertIn(f'ip6 saddr {env["WG_IPV6_PREFIX"]} oifname "eth0" masquerade', rules)
        self.assertNotIn("notrack", rules)

    def test_nft_apply_owns_only_vpn_stack_tables_and_is_reloadable(self) -> None:
        rendered = render.rendered_files_for_node(self.make_env(), render.NODE_GATEWAY)
        script = render.render_nft_apply_script()
        service = render.render_nftables_service()
        self.assertIn("vpn-stack-nft-apply.sh", rendered)
        self.assertIn("vpn-stack-nftables.service", rendered)
        self.assertIn("inet:vpnstack", script)
        self.assertIn("ip:vpnstack_nat4", script)
        self.assertIn("ip6:vpnstack_nat6", script)
        self.assertNotIn("ip:nat", script)
        self.assertNotIn("ip6:nat", script)
        self.assertIn("nft --check --file", script)
        self.assertEqual(script.count("nft --file"), 1)
        self.assertIn('mode=${1#--}', script)
        self.assertIn('[ "$mode" != delete ]', script)
        self.assertNotIn("flush ruleset", script)
        self.assertNotIn("delete table ip nat", script)
        self.assertNotIn("delete table ip6 nat", script)
        self.assertIn("ExecStart=/bin/sh /usr/local/lib/vpn-stack/nft-apply.sh /etc/vpn-stack/nftables.conf", service)
        self.assertIn("ExecReload=/bin/sh /usr/local/lib/vpn-stack/nft-apply.sh /etc/vpn-stack/nftables.conf", service)
        self.assertIn("RemainAfterExit=yes", service)

    @unittest.skipIf(os.name == "nt", "POSIX shell behavior is exercised on Linux CI")
    def test_nft_apply_is_idempotent_and_uses_one_apply_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            state = root / "state"
            log = root / "nft.log"
            config = root / "nftables.conf"
            apply_script = root / "nft-apply.sh"
            config.write_text(
                "table inet vpnstack {}\n"
                "table ip vpnstack_nat4 {}\n"
                "table ip6 vpnstack_nat6 {}\n",
                encoding="utf-8",
            )
            apply_script.write_text(render.render_nft_apply_script(), encoding="utf-8")
            apply_script.chmod(0o755)
            fake_nft = fake_bin / "nft"
            fake_nft.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "echo \"$*\" >>\"$NFT_TEST_LOG\"\n"
                "if [ \"$1\" = list ]; then grep -Fx \"$3 $4\" \"$NFT_TEST_STATE\" >/dev/null 2>&1; exit $?; fi\n"
                "if [ \"$1\" = --check ]; then exit 0; fi\n"
                "cat \"$2\" >>\"$NFT_TEST_LOG\"\n"
                "printf 'inet vpnstack\\nip vpnstack_nat4\\nip6 vpnstack_nat6\\n' >\"$NFT_TEST_STATE\"\n",
                encoding="utf-8",
            )
            fake_nft.chmod(0o755)
            state.write_text("", encoding="utf-8")
            env = {
                **os.environ,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                "NFT_TEST_LOG": str(log),
                "NFT_TEST_STATE": str(state),
            }
            subprocess.run(["sh", str(apply_script), str(config)], check=True, env=env)
            subprocess.run(["sh", str(apply_script), str(config)], check=True, env=env)
            with state.open("a", encoding="utf-8") as handle:
                handle.write("ip nat\nip6 nat\n")
            subprocess.run(["sh", str(apply_script), str(config)], check=True, env=env)
            calls = log.read_text(encoding="utf-8")
            call_lines = calls.splitlines()
            self.assertEqual(sum(line.startswith("--file ") for line in call_lines), 3, calls)
            self.assertEqual(sum(line.startswith("--check --file ") for line in call_lines), 3, calls)
            self.assertIn("delete table inet vpnstack", calls)
            self.assertIn("delete table ip vpnstack_nat4", calls)
            self.assertIn("delete table ip6 vpnstack_nat6", calls)
            self.assertNotIn("delete table ip nat", calls)
            self.assertNotIn("delete table ip6 nat", calls)

    def test_render_sysctl_reserves_conntrack_capacity_without_timeout_tuning(self) -> None:
        for node_id in (render.NODE_GATEWAY, render.NODE_EXIT):
            config = render.render_sysctl(node_id)
            self.assertIn("net.netfilter.nf_conntrack_max=32768", config)
            self.assertNotIn("nf_conntrack_tcp_timeout", config)
        self.assertEqual(render.render_modules_load(), "nf_conntrack\n")

    def test_render_foreign_nftables_can_enable_ru_block_explicitly(self) -> None:
        env = self.make_env()
        env["FOREIGN_BLOCK_RU"] = "1"
        rules = render.render_foreign_nftables(env, "eth0")
        self.assertIn("set ru_ipv4", rules)
        self.assertIn("set ru_ipv6", rules)
        self.assertIn(f'    iifname "{env["WG_INTERFACE"]}" oifname "eth0" ip daddr @ru_ipv4 drop', rules)
        self.assertIn(f'    iifname "{env["WG_INTERFACE"]}" oifname "eth0" ip6 daddr @ru_ipv6 drop', rules)

    def test_write_node_rendered_files_and_package_bundle(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(render, "OUT_DIR", Path(tmp)):
                out_dir = render.deployment_out_dir(env)
                assets_dir = out_dir / "assets"
                assets_dir.mkdir(parents=True, exist_ok=True)
                for asset_name in ("geosite-ru.srs", "geoip-ru.srs", "ru-ipv4.zone", "ru-ipv6.zone"):
                    (assets_dir / asset_name).write_text("dummy\n", encoding="utf-8")
                render.write_node_rendered_files(env, render.NODE_GATEWAY, out_dir / "preview" / "ru")
                render.write_node_rendered_files(env, render.NODE_EXIT, out_dir / "preview" / "foreign")
                server_dir = out_dir / "server"
                server_dir.mkdir(parents=True, exist_ok=True)
                (server_dir / "gateway.env").write_text(render.render_node_env_text(env, "gateway"), encoding="utf-8")
                (server_dir / "exit.env").write_text(render.render_node_env_text(env, "exit"), encoding="utf-8")
                bundle_dir = render.package_bundle(env)
                self.assertTrue((bundle_dir / "gateway.tar.gz").is_file())
                self.assertTrue((bundle_dir / "exit.tar.gz").is_file())
                self.assertFalse((bundle_dir / "gateway").exists())
                self.assertFalse((bundle_dir / "exit").exists())
                with tarfile.open(bundle_dir / "gateway.tar.gz", "r:gz") as archive:
                    self.assertEqual(archive.getmember("deployment.env").mode & 0o777, 0o600)
                    self.assertEqual(archive.getmember("install.sh").mode & 0o777, 0o700)

    def test_single_artifact_tree_contains_only_gateway_node_and_minimal_env(self) -> None:
        env = self.make_single_env("foreign")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            with patch.object(render, "OUT_DIR", tmp_path / "out"):
                out_dir = render.render_config_artifacts(env_path, env, fetch_assets_first=False)
                cloud_dir = render.render_cloud_init_artifacts(env)
                bundle_dir = render.package_bundle(env)

            node_env = (out_dir / "server" / "gateway.env").read_text(encoding="utf-8")
            self.assertTrue((bundle_dir / "gateway.tar.gz").is_file())
            self.assertFalse((bundle_dir / "exit.tar.gz").exists())
            self.assertTrue((cloud_dir / "gateway.yaml").is_file())
            self.assertFalse((cloud_dir / "exit.yaml").exists())
            self.assertFalse((out_dir / "server" / "exit.env").exists())
            self.assertNotIn("WG_RU_PRIVATE_KEY", node_env)
            self.assertNotIn("EXIT_PUBLIC_IP", node_env)

    def test_render_all_artifacts_merges_local_ru_direct_overlay_files(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            env_path.write_text(render.render_env_text(env), encoding="utf-8")
            (tmp_path / "demo.ru-direct-domains.txt").write_text("overlay.example\n", encoding="utf-8")
            with patch.object(render, "OUT_DIR", tmp_path / "out"), patch.object(render, "fetch_assets", return_value={}):
                render.render_all_artifacts(env_path, env)
                payload = json.loads((tmp_path / "out" / "demo" / "preview" / "gateway" / "sing-box.json").read_text(encoding="utf-8"))
        direct_domain_rule = next(rule for rule in payload["route"]["rules"] if rule.get("outbound") == "direct-ru" and "domain" in rule)
        self.assertIn("overlay.example", direct_domain_rule["domain"])

    def test_render_config_artifacts_removes_stale_preview_subscription_tree(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            env_path.write_text(render.render_env_text(env), encoding="utf-8")
            with patch.object(render, "OUT_DIR", tmp_path / "out"):
                stale_file = tmp_path / "out" / "demo" / "preview" / "gateway" / "subscription" / "old-token" / "vless.txt"
                stale_file.parent.mkdir(parents=True)
                stale_file.write_text("stale\n", encoding="utf-8")

                render.render_config_artifacts(env_path, env, fetch_assets_first=False)

                self.assertFalse(stale_file.exists())
                self.assertTrue((tmp_path / "out" / "demo" / "preview" / "gateway" / "sing-box.json").is_file())

    def test_role_manifest_requires_only_role_assets(self) -> None:
        env = self.make_env()
        env["FOREIGN_BLOCK_RU"] = "1"
        with tempfile.TemporaryDirectory() as tmp:
            assets = {}
            for name in ("geosite-ru.srs", "geoip-ru.srs", "ru-ipv4.zone", "ru-ipv6.zone"):
                path = Path(tmp) / name
                path.write_text(name, encoding="utf-8")
                assets[name] = path
            ru_manifest = json.loads(render.rendered_files_for_node(env, render.NODE_GATEWAY, assets=assets)["render-manifest.json"])
            foreign_manifest = json.loads(render.rendered_files_for_node(env, render.NODE_EXIT, assets=assets)["render-manifest.json"])
        self.assertEqual(set(ru_manifest["assets"]), {"geoip-ru.srs", "geosite-ru.srs"})
        self.assertEqual(set(foreign_manifest["assets"]), {"ru-ipv4.zone", "ru-ipv6.zone"})

    def test_role_manifest_tracks_modules_load_at_installed_path(self) -> None:
        env = self.make_env()
        manifest = json.loads(render.rendered_files_for_node(env, render.NODE_GATEWAY)["render-manifest.json"])
        modules = manifest["artifacts"]["modules-vpn-stack.conf"]
        self.assertEqual(modules["install_path"], "/etc/modules-load.d/90-vpn-stack.conf")
        self.assertTrue(modules["required"])

    def test_manifest_rejects_unmapped_rendered_artifact(self) -> None:
        env = self.make_env()
        with self.assertRaisesRegex(ValueError, "missing installed artifact path: unknown.conf"):
            render.render_manifest(render.render_env_text(env), render.NODE_GATEWAY, {"unknown.conf": "value\n"})

    def test_manifest_recognizes_dynamic_wireguard_config_by_structure(self) -> None:
        env = self.make_env()
        manifest = json.loads(
            render.render_manifest(
                render.render_env_text(env),
                render.NODE_GATEWAY,
                {"tunnel42.conf": "[Interface]\nPrivateKey = test\n"},
            )
        )
        self.assertEqual(manifest["artifacts"]["tunnel42.conf"]["install_path"], "/etc/wireguard/tunnel42.conf")

    def test_role_manifest_is_deterministic(self) -> None:
        env = self.make_env()
        first = render.rendered_files_for_node(env, render.NODE_GATEWAY)["render-manifest.json"]
        second = render.rendered_files_for_node(env, render.NODE_GATEWAY)["render-manifest.json"]
        self.assertEqual(first, second)
        self.assertNotIn("generated_at", json.loads(first))

    @unittest.skipUnless(preferred_bash(), "bash is required for install.sh render-only test")
    def test_install_sh_render_only_contains_forced_direct_rules(self) -> None:
        env = self.make_env()
        env["RU_FORCE_DIRECT_IP_CIDR"] = "203.0.113.0/24"
        repo_root = Path(__file__).resolve().parents[1]
        install_sh = repo_root / "install.sh"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_file = tmp_path / "demo.env"
            output_dir = tmp_path / "preview"
            env_file.write_text(render.render_env_text(env), encoding="utf-8")
            command = [
                preferred_bash() or "bash",
                str(install_sh),
                "--node",
                "gateway",
                "--env-file",
                str(env_file),
                "--render-only",
                "--output-dir",
                str(output_dir),
            ]
            completed = subprocess.run(
                command,
                cwd=repo_root,
                capture_output=True,
                text=True,
                env={**os.environ, "LC_ALL": "C.UTF-8"},
                check=False,
            )
            self.assertEqual(completed.returncode, 0, msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}")
            payload = json.loads((output_dir / "sing-box.json").read_text(encoding="utf-8"))
            xray_payload = json.loads((output_dir / "xray.json").read_text(encoding="utf-8"))
        dns_rules = payload["dns"]["rules"]
        route_rules = payload["route"]["rules"]
        servers = {server["tag"]: server for server in payload["dns"]["servers"]}
        self.assertNotIn("maxTimeDiff", xray_payload["inbounds"][0]["streamSettings"]["realitySettings"])
        direct_domain_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain" in rule)
        self.assertIn("api.ok.ru", direct_domain_rule["domain"])
        self.assertNotIn("checkip.amazonaws.com", direct_domain_rule["domain"])
        self.assertIn("2ip.ru", direct_domain_rule["domain"])
        direct_suffix_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "domain_suffix" in rule)
        self.assertEqual(direct_suffix_rule["domain_suffix"], [".gosuslugi.ru"])
        cidr_rule = next(rule for rule in route_rules if rule.get("outbound") == "direct-ru" and "ip_cidr" in rule)
        self.assertEqual(cidr_rule["ip_cidr"], ["203.0.113.0/24", "203.0.113.10/32"])
        dns_direct_rule = next(rule for rule in dns_rules if rule.get("action") == "route" and rule.get("server") == "dns-ru-direct" and "domain" in rule)
        self.assertIn("api.oneme.ru", dns_direct_rule["domain"])
        self.assertIn("ip.mail.ru", dns_direct_rule["domain"])
        self.assertNotIn("detour", servers["dns-ru-direct"])
        self.assertEqual(servers["dns-global"]["detour"], "to-foreign")


if __name__ == "__main__":
    unittest.main()
