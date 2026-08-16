from __future__ import annotations

import json
import shutil
import textwrap
import time

from ..common import OUT_DIR
from ..config import load_env_file
from ..interserver_transport import HY2_PORT, TRANSPORT_CANDIDATE_TAGS, TRANSPORT_HY2_TAG, TRANSPORT_PREFERRED_TAG
from ..network_profile import FQ_FLOW_LIMIT, FQ_KIND, FQ_PACKET_LIMIT
from ..render import (
    render_all_artifacts,
    render_foreign_nftables,
    render_foreign_singbox,
    render_foreign_wg,
    render_ru_firewall_nftables,
    render_ru_singbox,
    render_ru_wg,
)
from .runner import AUDIT_IMAGE, AuditFailure, AuditRunner, write_text
from .quick import seed_quick_asset_cache

LAB_FRONT_SUBNET = "198.18.0.0/24"
LAB_RU_SUBNET = "203.0.113.0/24"
LAB_GLOBAL_SUBNET = "198.51.100.0/24"
LAB_FRONT_GATEWAY = "198.18.0.1"
LAB_RU_GATEWAY = "203.0.113.1"
LAB_GLOBAL_GATEWAY = "198.51.100.1"
LAB_IPS = {
    "ru": "198.18.0.10",
    "foreign": "198.18.0.20",
    "client": "198.18.0.30",
    "dns": "198.18.0.53",
    "ru_web": "203.0.113.80",
    "global_web": "198.51.100.80",
    "foreign_wan": "198.51.100.20",
    "ru_lan": "203.0.113.10",
}
LAB_STREAM_CHUNK_BYTES = 65_536
LAB_STREAM_CHUNKS = 120
LAB_STREAM_BYTES = LAB_STREAM_CHUNK_BYTES * LAB_STREAM_CHUNKS


def run(runner: AuditRunner) -> None:
    runner.ensure_audit_image()
    runner.record("lab-dataplane", lambda: test_lab_dataplane(runner))


def validate_network_apply_result(result: dict[str, object]) -> None:
    qdisc = result.get("qdisc")
    policy = result.get("wireguard_policy")
    if not isinstance(qdisc, dict) or (
        qdisc.get("overlay_qdisc") != FQ_KIND
        or qdisc.get("overlay_qdisc_limit") != FQ_PACKET_LIMIT
        or qdisc.get("overlay_qdisc_flow_limit") != FQ_FLOW_LIMIT
    ):
        raise AuditFailure(f"Managed WireGuard qdisc was not applied: {result}")
    if not isinstance(policy, dict) or policy.get("managed") is not True or policy.get("ok") is not True:
        raise AuditFailure(f"Managed WireGuard policy was not applied: {result}")


def build_lab_client_config(env: dict[str, str]) -> str:
    payload = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "0.0.0.0", "listen_port": 1080}],
        "outbounds": [
            {
                "type": "socks",
                "tag": "ru-gateway",
                "server": LAB_IPS["ru"],
                "server_port": int(env.get("RU_ROUTER_LISTEN_PORT", "2080")),
            },
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [{"ip_version": 6, "action": "route", "outbound": "block"}],
            "final": "ru-gateway",
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def build_lab_ru_config(env: dict[str, str]) -> str:
    payload = json.loads(render_ru_singbox(env))
    direct_dns = next(server for server in payload["dns"]["servers"] if server.get("tag") == "dns-ru-direct")
    direct_dns.clear()
    direct_dns.update({"type": "udp", "tag": "dns-ru-direct", "server": LAB_IPS["dns"], "server_port": 53})
    payload["dns"]["final"] = "dns-global"
    payload["inbounds"][0]["listen"] = "0.0.0.0"
    payload["inbounds"][0]["listen_port"] = int(env.get("RU_ROUTER_LISTEN_PORT", "2080"))
    for rule_set in payload["route"]["rule_set"]:
        if rule_set.get("tag") == "ru-geoip":
            rule_set.update({"format": "source", "path": "/opt/geoip-ru.json"})
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def build_lab_foreign_config(env: dict[str, str]) -> str:
    payload = json.loads(render_foreign_singbox(env))
    dns_relay = next(inbound for inbound in payload["inbounds"] if inbound.get("tag") == "dns-relay-in")
    dns_relay.update({"override_address": LAB_IPS["dns"], "override_port": 53})
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def build_lab_web_server(name: str) -> str:
    return textwrap.dedent(
        f"""\
        import http.server
        import socketserver
        import time

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                with open("/opt/requests.log", "a", encoding="utf-8") as log:
                    log.write(f"{{self.path}}\\n")
                if self.path == "/stream":
                    chunk = b"x" * {LAB_STREAM_CHUNK_BYTES}
                    chunks = {LAB_STREAM_CHUNKS}
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(chunk) * chunks))
                    self.end_headers()
                    for _ in range(chunks):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        time.sleep(0.05)
                    return
                body = f"server={name}\\nsource={{self.client_address[0]}}\\nip={LAB_IPS['foreign_wan']}\\npath={{self.path}}\\n".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        with socketserver.ThreadingTCPServer(("0.0.0.0", 80), Handler) as server:
            server.daemon_threads = True
            server.serve_forever()
        """
    )


def build_lab_dnsmasq() -> str:
    return textwrap.dedent(
        f"""\
        no-daemon
        log-queries
        log-facility=-
        port=53
        bind-interfaces
        address=/localhost/127.0.0.1
        address=/ya.ru/{LAB_IPS["ru_web"]}
        address=/example.com/{LAB_IPS["global_web"]}
        address=/blocked-ru.example/{LAB_IPS["ru_web"]}
        address=/private.invalid/10.0.0.20
        address=/gosuslugi.ru/10.0.0.20
        """
    )


def test_lab_dataplane(runner: AuditRunner) -> dict[str, str]:
    runner.cleanup_stale_lab_resources()
    env_path, env = runner.create_env(
        "lab",
        {
            "RU_PUBLIC_IP": LAB_IPS["ru"],
            "FOREIGN_PUBLIC_IP": LAB_IPS["foreign"],
            "WAN_INTERFACE": "eth1",
            "WG_INTERFACE": "wg0",
            "FOREIGN_BLOCK_RU": "1",
        },
    )
    out_dir = OUT_DIR / env["DEPLOY_NAME"]
    runner.seed_foreign_block_cache(env["DEPLOY_NAME"])
    seed_quick_asset_cache(env, out_dir)
    render_all_artifacts(env_path, env, fetch_assets_first=False)
    env = load_env_file(env_path)

    front = f"audit-front-{runner.run_id}"
    ru_lan = f"audit-ru-{runner.run_id}"
    global_lan = f"audit-global-{runner.run_id}"

    with runner.docker_network(front, LAB_FRONT_SUBNET, LAB_FRONT_GATEWAY), runner.docker_network(ru_lan, LAB_RU_SUBNET, LAB_RU_GATEWAY), runner.docker_network(global_lan, LAB_GLOBAL_SUBNET, LAB_GLOBAL_GATEWAY):
        with runner.docker_container(f"ru-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["ru"]) as ru_container, runner.docker_container(f"foreign-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["foreign"]) as foreign_container, runner.docker_container(f"client-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["client"]) as client_container, runner.docker_container(f"dns-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["dns"]) as dns_container, runner.docker_container(f"ruweb-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=ru_lan, ip=LAB_IPS["ru_web"]) as ru_web_container, runner.docker_container(f"globalweb-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=global_lan, ip=LAB_IPS["global_web"]) as global_web_container:
            runner.docker_network_connect(ru_lan, ru_container, LAB_IPS["ru_lan"])
            runner.docker_network_connect(global_lan, foreign_container, LAB_IPS["foreign_wan"])
            runner.docker_exec(foreign_container, f"ip route replace default via {LAB_GLOBAL_GATEWAY} dev eth1")

            lab_dir = runner.work_dir / "lab"
            ru_wg = lab_dir / "wg0-ru.conf"
            foreign_wg = lab_dir / "wg0-foreign.conf"
            ru_nft = lab_dir / "ru.nft"
            foreign_nft = lab_dir / "foreign.nft"
            ru_cfg = lab_dir / "ru-singbox.json"
            foreign_cfg = lab_dir / "foreign-singbox.json"
            client_cfg = lab_dir / "client-singbox.json"
            ru_assets = lab_dir / "ru-assets"
            dns_conf = lab_dir / "dnsmasq.conf"
            ru_web = lab_dir / "ru-web.py"
            global_web = lab_dir / "global-web.py"
            geoip_source = lab_dir / "geoip-ru.json"
            lab_transport_policy = lab_dir / "interserver_transport.py"
            agent_dir = out_dir / "preview" / "ru"
            ru_manifest = agent_dir / "render-manifest.json"
            ru_assets.mkdir(parents=True, exist_ok=True)
            shutil.copy2(out_dir / "assets" / "geosite-ru.srs", ru_assets / "geosite-ru.srs")
            shutil.copy2(out_dir / "assets" / "geoip-ru.srs", ru_assets / "geoip-ru.srs")
            write_text(ru_wg, render_ru_wg(env))
            write_text(foreign_wg, render_foreign_wg(env))
            write_text(ru_nft, render_ru_firewall_nftables(env))
            write_text(foreign_nft, render_foreign_nftables(env, "eth1"))
            write_text(ru_cfg, build_lab_ru_config(env))
            write_text(foreign_cfg, build_lab_foreign_config(env))
            write_text(client_cfg, build_lab_client_config(env))
            write_text(dns_conf, build_lab_dnsmasq())
            write_text(ru_web, build_lab_web_server("ru-web"))
            write_text(global_web, build_lab_web_server("global-web"))
            write_text(geoip_source, json.dumps({"version": 3, "rules": [{"ip_cidr": [LAB_RU_SUBNET]}]}, indent=2) + "\n")
            transport_source = (agent_dir / "interserver_transport.py").read_text(encoding="utf-8")
            write_text(lab_transport_policy, transport_source)

            runner.docker_exec(ru_container, "mkdir -p /opt/agent /etc/vpn-stack /etc/sing-box /var/lib/vpn-stack")
            for container, local, remote in [
                (ru_container, ru_wg, "/opt/wg0.conf"),
                (foreign_container, foreign_wg, "/opt/wg0.conf"),
                (ru_container, ru_nft, "/opt/nftables.conf"),
                (foreign_container, foreign_nft, "/opt/nftables.conf"),
                (ru_container, ru_cfg, "/opt/ru-singbox.json"),
                (ru_container, ru_cfg, "/etc/sing-box/config.json"),
                (ru_container, ru_manifest, "/etc/vpn-stack/render-manifest.json"),
                (foreign_container, foreign_cfg, "/opt/foreign-singbox.json"),
                (client_container, client_cfg, "/opt/client-singbox.json"),
                (dns_container, dns_conf, "/opt/dnsmasq.conf"),
                (ru_web_container, ru_web, "/opt/web.py"),
                (global_web_container, global_web, "/opt/web.py"),
                (ru_container, geoip_source, "/opt/geoip-ru.json"),
                (ru_container, env_path, "/etc/vpn-stack/deployment.env"),
            ]:
                runner.docker_copy(container, local, remote)

            for name in ("vpn-stack-agent.py", "diagnostics.py", "log_classifier.py", "interserver_transport.py", "network_profile.py"):
                source = lab_transport_policy if name == "interserver_transport.py" else agent_dir / name
                runner.docker_copy(ru_container, source, f"/opt/agent/{name}")

            runner.docker_exec(ru_container, "mkdir -p /var/lib/vpn-stack/rules")
            for asset_name in ("geosite-ru.srs", "geoip-ru.srs"):
                runner.docker_copy(ru_container, ru_assets / asset_name, f"/var/lib/vpn-stack/rules/{asset_name}")

            runner.docker_exec(dns_container, "nohup dnsmasq --conf-file=/opt/dnsmasq.conf >/opt/dns.log 2>&1 &")
            runner.docker_exec(ru_web_container, "nohup python3 /opt/web.py >/opt/web.log 2>&1 &")
            runner.docker_exec(global_web_container, "nohup python3 /opt/web.py >/opt/web.log 2>&1 &")
            runner.docker_exec(
                dns_container,
                "for i in $(seq 1 50); do grep -q 'started, version' /opt/dns.log && exit 0; sleep 0.1; done; cat /opt/dns.log; exit 1",
            )
            for web_container in (ru_web_container, global_web_container):
                runner.docker_exec(
                    web_container,
                    "for i in $(seq 1 50); do curl -fsS --max-time 1 http://127.0.0.1/ready >/dev/null && exit 0; sleep 0.1; done; cat /opt/web.log; exit 1",
                )
            runner.docker_exec(foreign_container, "sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 >/dev/null")
            runner.docker_exec(ru_container, "sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null")
            runner.docker_exec(ru_container, "ip address add 10.0.0.20/32 dev lo && nohup python3 -m http.server 80 --bind 10.0.0.20 >/opt/private-direct-web.log 2>&1 &")
            runner.docker_exec(foreign_container, "wg-quick up /opt/wg0.conf")
            runner.docker_exec(foreign_container, "nohup sing-box run -c /opt/foreign-singbox.json >/opt/foreign-singbox.log 2>&1 &")
            runner.docker_exec(ru_container, "wg-quick up /opt/wg0.conf")
            network_profile = json.loads(
                runner.docker_exec(ru_container, "python3 /opt/agent/vpn-stack-agent.py network-apply").stdout
            )
            validate_network_apply_result(network_profile)
            runner.docker_exec(foreign_container, "ip address add 10.0.0.20/32 dev lo && nohup python3 -m http.server 80 --bind 10.0.0.20 >/opt/private-web.log 2>&1 &")
            runner.docker_exec(foreign_container, "nft -f /opt/nftables.conf && nft add element inet vpnstack ru_ipv4 { 203.0.113.0/24 }")
            runner.docker_exec(ru_container, "nft -f /opt/nftables.conf")
            runner.docker_exec(ru_container, f"nft insert rule inet vpnstack input tcp dport {env['RU_ROUTER_LISTEN_PORT']} counter accept")
            runner.docker_exec(ru_container, "nohup sing-box run -c /opt/ru-singbox.json >/opt/ru-singbox.log 2>&1 &")
            runner.docker_exec(client_container, "nohup sing-box run -c /opt/client-singbox.json >/opt/client-singbox.log 2>&1 &")
            runner.docker_exec(client_container, "for i in $(seq 1 20); do nc -z 127.0.0.1 1080 && exit 0; sleep 1; done; exit 1")

            ru_resp = runner.lab_curl(client_container, "http://ya.ru/").stdout
            if "server=ru-web" not in ru_resp or f"source={LAB_IPS['ru_lan']}" not in ru_resp:
                raise AuditFailure(f"RU dataplane не подтверждён:\n{ru_resp}")

            raw_ru_resp = runner.lab_curl(client_container, f"http://{LAB_IPS['ru_web']}/").stdout
            if "server=ru-web" not in raw_ru_resp or f"source={LAB_IPS['ru_lan']}" not in raw_ru_resp:
                raise AuditFailure(f"Raw RU GeoIP ушёл не через direct-ru:\n{raw_ru_resp}")

            global_resp = runner.lab_curl(client_container, "http://example.com/").stdout
            if "server=global-web" not in global_resp or f"source={LAB_IPS['foreign_wan']}" not in global_resp:
                raise AuditFailure(f"Global dataplane через foreign не подтверждён:\n{global_resp}")
            wg_qdisc = next(
                item
                for item in json.loads(runner.docker_exec(ru_container, "tc -j -s qdisc show dev wg0").stdout)
                if item.get("root") is True
            )
            if wg_qdisc.get("kind") != "fq" or int(wg_qdisc.get("packets", 0)) < 1:
                raise AuditFailure(f"WireGuard traffic bypassed the managed qdisc: {wg_qdisc}")

            raw_global_resp = runner.lab_curl(client_container, f"http://{LAB_IPS['global_web']}/").stdout
            if "server=global-web" not in raw_global_resp or f"source={LAB_IPS['foreign_wan']}" not in raw_global_resp:
                raise AuditFailure(f"Raw global IP ушёл не через foreign:\n{raw_global_resp}")

            runner.docker_exec(
                client_container,
                "rm -f /opt/stream.out /opt/stream.rc /opt/stream.time; "
                "(curl --silent --show-error --fail --socks5-hostname 127.0.0.1:1080 "
                "--write-out '%{time_total}' --output /opt/stream.out http://example.com/stream "
                ">/opt/stream.time; echo $? >/opt/stream.rc) &",
            )
            time.sleep(1)
            fallback_tag = next(tag for tag in TRANSPORT_CANDIDATE_TAGS if tag != TRANSPORT_PREFERRED_TAG)
            fault_port = HY2_PORT if TRANSPORT_PREFERRED_TAG == TRANSPORT_HY2_TAG else int(env["WG_PORT"])
            runner.docker_exec(
                ru_container,
                f"nft add table inet underlay_fault; nft 'add chain inet underlay_fault output {{ type filter hook output priority -10; policy accept; }}'; nft add rule inet underlay_fault output ip daddr {LAB_IPS['foreign']} udp dport {fault_port} drop",
            )
            switch_started = time.monotonic()
            suspicion = json.loads(
                runner.docker_exec(ru_container, "python3 /opt/agent/vpn-stack-agent.py transport-reconcile").stdout
            )
            if not (
                suspicion.get("changed") is not True
                and suspicion.get("selected") == TRANSPORT_PREFERRED_TAG
                and suspicion.get("state") == "suspect"
            ):
                raise AuditFailure(f"Transport agent did not retain the selected path for the first failure cycle: {suspicion}")
            transition = json.loads(
                runner.docker_exec(ru_container, "python3 /opt/agent/vpn-stack-agent.py transport-reconcile").stdout
            )
            if not (
                transition.get("changed") is True
                and transition.get("selected") == fallback_tag
            ):
                raise AuditFailure(f"Transport agent did not perform the expected failover: {transition}")
            switch_seconds = time.monotonic() - switch_started
            if switch_seconds > 4.0:
                raise AuditFailure(f"Confirmed underlay failover exceeded 4 seconds: {switch_seconds:.3f}s")
            runner.docker_exec(
                client_container,
                "for i in $(seq 1 200); do test -s /opt/stream.rc && exit 0; sleep 0.1; done; exit 1",
            )
            stream_result = runner.docker_exec(
                client_container,
                f'test "$(cat /opt/stream.rc)" = 0 && test "$(stat -c %s /opt/stream.out)" = {LAB_STREAM_BYTES}',
            )
            if stream_result.returncode != 0:
                raise AuditFailure("Existing TCP stream did not survive the underlay switch")
            stream_seconds = float(runner.docker_exec(client_container, "cat /opt/stream.time").stdout.strip())
            if stream_seconds > 14.0:
                raise AuditFailure(f"Underlay switch stalled an existing TCP stream for too long: {stream_seconds:.3f}s")
            request_count = runner.docker_exec(global_web_container, "grep -Fxc /stream /opt/requests.log")
            if request_count.stdout.strip() != "1":
                raise AuditFailure("Continuity check retried HTTP instead of preserving one TCP stream")
            runner.docker_exec(ru_container, "nft delete table inet underlay_fault")
            time.sleep(0.5)
            recovery: list[dict[str, object]] = []
            for attempt in range(3):
                if attempt:
                    time.sleep(10.1)
                recovery.append(
                    json.loads(
                        runner.docker_exec(ru_container, "python3 /opt/agent/vpn-stack-agent.py transport-reconcile").stdout
                    )
                )
            if not (
                all(state.get("changed") is not True and state.get("selected") == fallback_tag for state in recovery[:2])
                and recovery[-1].get("changed") is True
                and recovery[-1].get("selected") == TRANSPORT_PREFERRED_TAG
            ):
                raise AuditFailure(f"Transport agent did not return to the recovered preferred underlay: {recovery}")
            continuity_report = lab_dir / "transport-continuity.json"
            write_text(
                continuity_report,
                json.dumps(
                    {
                        "suspicion": suspicion,
                        "transition": transition,
                        "switch_seconds": switch_seconds,
                        "stream_bytes": LAB_STREAM_BYTES,
                        "stream_seconds": stream_seconds,
                        "server_request_count": 1,
                        "preferred_recovery": recovery,
                    },
                    indent=2,
                    sort_keys=True,
                ) + "\n",
            )

            private_dns = runner.lab_curl(client_container, "http://private.invalid/", expect_codes={5, 7, 22, 28, 52, 56, 97})
            if private_dns.returncode == 0:
                raise AuditFailure("Global DNS private answer открыл внутренний адрес foreign")

            private_direct_dns = runner.lab_curl(client_container, "http://gosuslugi.ru/", expect_codes={5, 7, 22, 28, 52, 56, 97})
            if private_direct_dns.returncode == 0:
                raise AuditFailure("RU direct DNS private answer открыл внутренний адрес RU")

            blocked = runner.lab_curl(client_container, "http://blocked-ru.example/", expect_codes={7, 22, 28, 52, 56, 97})
            if blocked.returncode == 0:
                raise AuditFailure("foreign RU-block не сработал для blocked-ru.example")

            runner.docker("stop-foreign", ["stop", foreign_container])

            failed_global = runner.lab_curl(client_container, "http://example.com/", expect_codes={7, 22, 28, 52, 56, 97})
            if failed_global.returncode == 0:
                raise AuditFailure("При падении foreign global трафик не упал fail-closed")

            ru_after = runner.lab_curl(client_container, "http://ya.ru/").stdout
            if "server=ru-web" not in ru_after or f"source={LAB_IPS['ru_lan']}" not in ru_after:
                raise AuditFailure("После падения foreign RU трафик перестал ходить напрямую")

            raw_ru_after = runner.lab_curl(client_container, f"http://{LAB_IPS['ru_web']}/").stdout
            if "server=ru-web" not in raw_ru_after or f"source={LAB_IPS['ru_lan']}" not in raw_ru_after:
                raise AuditFailure("После падения foreign raw RU GeoIP не остался на direct-ru")
    return {"lab_env": str(env_path), "transport_continuity": str(continuity_report)}
