from __future__ import annotations

import json
import shutil
import textwrap

from ..common import OUT_DIR
from ..config import load_env_file
from ..render import (
    render_all_artifacts,
    render_foreign_nftables,
    render_foreign_wg,
    render_ru_firewall_nftables,
    render_ru_singbox,
    render_ru_wg,
)
from .runner import AUDIT_IMAGE, AuditFailure, AuditRunner, write_text

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


def run(runner: AuditRunner) -> None:
    runner.ensure_audit_image()
    runner.record("lab-dataplane", lambda: test_lab_dataplane(runner))


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
    payload["dns"]["servers"] = [
        {"type": "udp", "tag": "dns-ru-direct", "server": LAB_IPS["dns"], "server_port": 53},
        {"type": "udp", "tag": "dns-global", "server": LAB_IPS["dns"], "server_port": 53},
    ]
    payload["dns"]["final"] = "dns-global"
    payload["inbounds"][0]["listen"] = "0.0.0.0"
    payload["inbounds"][0]["listen_port"] = int(env.get("RU_ROUTER_LISTEN_PORT", "2080"))
    for outbound in payload.get("outbounds", []):
        if outbound.get("tag") == "to-foreign":
            outbound["bind_interface"] = env["WG_INTERFACE"]
            outbound.pop("routing_mark", None)
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def build_lab_web_server(name: str) -> str:
    return textwrap.dedent(
        f"""\
        import http.server
        import socketserver

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = f"server={name}\\nsource={{self.client_address[0]}}\\npath={{self.path}}\\n".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        with socketserver.TCPServer(("0.0.0.0", 80), Handler) as server:
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
        address=/ya.ru/{LAB_IPS["ru_web"]}
        address=/example.com/{LAB_IPS["global_web"]}
        address=/blocked-ru.example/{LAB_IPS["ru_web"]}
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
        },
    )
    runner.seed_foreign_block_cache(env["DEPLOY_NAME"])
    render_all_artifacts(env_path, env)
    env = load_env_file(env_path)
    out_dir = OUT_DIR / env["DEPLOY_NAME"]

    front = f"audit-front-{runner.run_id}"
    ru_lan = f"audit-ru-{runner.run_id}"
    global_lan = f"audit-global-{runner.run_id}"

    with runner.docker_network(front, LAB_FRONT_SUBNET, LAB_FRONT_GATEWAY), runner.docker_network(ru_lan, LAB_RU_SUBNET, LAB_RU_GATEWAY), runner.docker_network(global_lan, LAB_GLOBAL_SUBNET, LAB_GLOBAL_GATEWAY):
        with runner.docker_container(f"ru-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["ru"]) as ru_container, runner.docker_container(f"foreign-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["foreign"]) as foreign_container, runner.docker_container(f"client-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["client"]) as client_container, runner.docker_container(f"dns-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["dns"]) as dns_container, runner.docker_container(f"ruweb-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=ru_lan, ip=LAB_IPS["ru_web"]) as ru_web_container, runner.docker_container(f"globalweb-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=global_lan, ip=LAB_IPS["global_web"]) as global_web_container:
            runner.docker_network_connect(ru_lan, ru_container, LAB_IPS["ru_lan"])
            runner.docker_network_connect(global_lan, foreign_container, LAB_IPS["foreign_wan"])

            lab_dir = runner.work_dir / "lab"
            ru_wg = lab_dir / "wg0-ru.conf"
            foreign_wg = lab_dir / "wg0-foreign.conf"
            ru_nft = lab_dir / "ru.nft"
            foreign_nft = lab_dir / "foreign.nft"
            ru_cfg = lab_dir / "ru-singbox.json"
            client_cfg = lab_dir / "client-singbox.json"
            ru_assets = lab_dir / "ru-assets"
            dns_conf = lab_dir / "dnsmasq.conf"
            ru_web = lab_dir / "ru-web.py"
            global_web = lab_dir / "global-web.py"
            ru_assets.mkdir(parents=True, exist_ok=True)
            shutil.copy2(out_dir / "assets" / "geosite-ru.srs", ru_assets / "geosite-ru.srs")
            shutil.copy2(out_dir / "assets" / "geoip-ru.srs", ru_assets / "geoip-ru.srs")
            write_text(ru_wg, render_ru_wg(env))
            write_text(foreign_wg, render_foreign_wg(env))
            write_text(ru_nft, render_ru_firewall_nftables(env))
            write_text(foreign_nft, render_foreign_nftables(env, "eth1"))
            write_text(ru_cfg, build_lab_ru_config(env))
            write_text(client_cfg, build_lab_client_config(env))
            write_text(dns_conf, build_lab_dnsmasq())
            write_text(ru_web, build_lab_web_server("ru-web"))
            write_text(global_web, build_lab_web_server("global-web"))

            for container, local, remote in [
                (ru_container, ru_wg, "/opt/wg0.conf"),
                (foreign_container, foreign_wg, "/opt/wg0.conf"),
                (ru_container, ru_nft, "/opt/nftables.conf"),
                (foreign_container, foreign_nft, "/opt/nftables.conf"),
                (ru_container, ru_cfg, "/opt/ru-singbox.json"),
                (client_container, client_cfg, "/opt/client-singbox.json"),
                (dns_container, dns_conf, "/opt/dnsmasq.conf"),
                (ru_web_container, ru_web, "/opt/web.py"),
                (global_web_container, global_web, "/opt/web.py"),
            ]:
                runner.docker_copy(container, local, remote)

            runner.docker_exec(ru_container, "mkdir -p /var/lib/vpn-stack/rules")
            for asset_name in ("geosite-ru.srs", "geoip-ru.srs"):
                runner.docker_copy(ru_container, ru_assets / asset_name, f"/var/lib/vpn-stack/rules/{asset_name}")

            runner.docker_exec(dns_container, "nohup dnsmasq --conf-file=/opt/dnsmasq.conf >/opt/dns.log 2>&1 &")
            runner.docker_exec(ru_web_container, "nohup python3 /opt/web.py >/opt/web.log 2>&1 &")
            runner.docker_exec(global_web_container, "nohup python3 /opt/web.py >/opt/web.log 2>&1 &")
            runner.docker_exec(foreign_container, "sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 >/dev/null")
            runner.docker_exec(ru_container, "sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null")
            runner.docker_exec(foreign_container, "wg-quick up /opt/wg0.conf")
            runner.docker_exec(ru_container, "wg-quick up /opt/wg0.conf")
            runner.docker_exec(foreign_container, "nft -f /opt/nftables.conf && nft add element inet vpnstack ru_ipv4 { 203.0.113.0/24 }")
            runner.docker_exec(ru_container, "nft -f /opt/nftables.conf")
            runner.docker_exec(ru_container, f"nft insert rule inet vpnstack input tcp dport {env['RU_ROUTER_LISTEN_PORT']} counter accept")
            runner.docker_exec(ru_container, "nohup sing-box run -c /opt/ru-singbox.json >/opt/ru-singbox.log 2>&1 &")
            runner.docker_exec(client_container, "nohup sing-box run -c /opt/client-singbox.json >/opt/client-singbox.log 2>&1 &")
            runner.docker_exec(client_container, "for i in $(seq 1 20); do nc -z 127.0.0.1 1080 && exit 0; sleep 1; done; exit 1")

            ru_resp = runner.lab_curl(client_container, "http://ya.ru/").stdout
            if "server=ru-web" not in ru_resp or f"source={LAB_IPS['ru_lan']}" not in ru_resp:
                raise AuditFailure(f"RU dataplane не подтверждён:\n{ru_resp}")

            global_resp = runner.lab_curl(client_container, "http://example.com/").stdout
            if "server=global-web" not in global_resp or f"source={LAB_IPS['foreign_wan']}" not in global_resp:
                raise AuditFailure(f"Global dataplane через foreign не подтверждён:\n{global_resp}")

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
    return {"lab_env": str(env_path)}
