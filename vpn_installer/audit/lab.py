from __future__ import annotations

import hashlib
from contextlib import contextmanager
from datetime import datetime
import json
import shlex
import shutil
import textwrap
import time

from ..common import OUT_DIR
from ..config import load_env_file
from ..interserver_transport import (
    HY2_PORT,
    TRANSPORT_CANDIDATE_PROBE_TIMEOUT_MS,
    TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS,
    TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
    TRANSPORT_CANDIDATE_TAGS,
    TRANSPORT_EVIDENCE_MAX_GAP_SECONDS,
    TRANSPORT_HY2_TAG,
    TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS,
    TRANSPORT_PREFERRED_RECOVERY_MIN_SECONDS,
    TRANSPORT_PREFERRED_TAG,
    TRANSPORT_PROBE_INTERVAL_SECONDS,
)
from ..network_profile import FQ_FLOW_LIMIT, FQ_KIND, FQ_PACKET_LIMIT
from ..render import (
    SERVER_AGENT_BASE_MODULES,
    SERVER_AGENT_INTERSERVER_MODULES,
    render_all_artifacts,
    render_foreign_nftables,
    render_foreign_singbox,
    render_foreign_wg,
    render_ru_firewall_nftables,
    render_gateway_singbox,
    render_ru_wg,
)
from ..topology import NODE_GATEWAY
from .runner import AUDIT_IMAGE, AuditFailure, AuditRunner, write_text
from .quick import seed_quick_asset_cache

LAB_FRONT_SUBNET = "198.18.0.0/24"
LAB_RU_SUBNET = "203.0.113.0/24"
LAB_GLOBAL_SUBNET = "198.51.100.0/24"
LAB_FRONT_GATEWAY = "198.18.0.1"
LAB_RU_GATEWAY = "203.0.113.1"
LAB_GLOBAL_GATEWAY = "198.51.100.1"
LAB_IPS = {
    "gateway": "198.18.0.10",
    "exit": "198.18.0.20",
    "client": "198.18.0.30",
    "dns": "198.18.0.53",
    "ru_web": "203.0.113.80",
    "global_web": "198.51.100.80",
    "exit_wan": "198.51.100.20",
    "ru_lan": "203.0.113.10",
}
LAB_STREAM_CHUNK_BYTES = 65_536
LAB_STREAM_CHUNKS = 320
LAB_STREAM_BYTES = LAB_STREAM_CHUNK_BYTES * LAB_STREAM_CHUNKS
LAB_STREAM_MAX_SECONDS = 30
# Two cycles (overlay + candidate), activation proof, and bounded Docker overhead.
LAB_FAILOVER_MAX_SECONDS = TRANSPORT_PROBE_INTERVAL_SECONDS + 5 * TRANSPORT_CANDIDATE_PROBE_TIMEOUT_MS / 1000 + 2


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
                "tag": "gateway",
                "server": LAB_IPS["gateway"],
                "server_port": int(env.get("RU_ROUTER_LISTEN_PORT", "2080")),
            },
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [{"ip_version": 6, "action": "route", "outbound": "block"}],
            "final": "gateway",
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def build_lab_ru_config(env: dict[str, str]) -> str:
    payload = json.loads(render_gateway_singbox(env))
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
                    for index in range(chunks):
                        self.wfile.write(bytes([index % 256]) * len(chunk))
                        self.wfile.flush()
                        time.sleep(0.05)
                    return
                body = f"server={name}\\nsource={{self.client_address[0]}}\\nip={LAB_IPS['exit_wan']}\\npath={{self.path}}\\n".encode("utf-8")
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


def _lab_overlay_probe(runner: AuditRunner, container: str, env: dict[str, str], *, convergence: bool = False) -> dict[str, object]:
    identity = {key: env[key] for key in ("WG_INTERFACE", "WG_FOREIGN_ADDRESS")}
    script = textwrap.dedent(f"""\
        import json, sys
        sys.dont_write_bytecode = True
        sys.path.insert(0, '/opt/agent')
        import server_transport
        env = {identity!r}
        try:
            result = server_transport.{'prove_wireguard_overlay' if convergence else 'transport_overlay_path_probe'}(env)
        except server_transport.TransportSwitchError as exc:
            result = exc.evidence
        print(json.dumps(result))
        """)
    return json.loads(runner.docker_exec(container, f"python3 -c {shlex.quote(script)}").stdout)


def _lab_overlay_deadlines(runner: AuditRunner, gateway: str, dns: str, env: dict[str, str]) -> dict[str, object]:
    # This IPv4 fixture delays DNS data (PSH), not SYN/ACK or UDP candidate probes.
    runner.docker_exec(dns, "tc qdisc replace dev eth0 root handle 1: prio; "
                       "tc qdisc add dev eth0 parent 1:3 handle 30: netem delay 800ms; "
                       "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 "
                       "match ip protocol 6 0xff match ip sport 53 0xffff "
                       "match u8 0x08 0x08 at 33 flowid 1:3")
    try:
        live = _lab_overlay_probe(runner, gateway, env)
        activation = _lab_overlay_probe(runner, gateway, env, convergence=True)
        if live.get("ok") is not False or activation.get("ok") is not False:
            raise AuditFailure(f"Delayed DNS activation/liveness disagree: {live}, {activation}")
        runner.docker_exec(dns, f"(sleep {TRANSPORT_PROBE_INTERVAL_SECONDS}; tc qdisc del dev eth0 root) "
                           ">/opt/dns-delay-clear.log 2>&1 &")
        converged = _lab_overlay_probe(runner, gateway, env, convergence=True)
        recovered = _lab_overlay_probe(runner, gateway, env)
        if not (converged.get("ok") is True and len(converged.get("rounds", [])) > 1 and recovered.get("ok") is True):
            raise AuditFailure(f"DNS convergence did not survive the next liveness probe: {converged}, {recovered}")
        return {"delayed_liveness": live, "delayed_activation": activation, "convergence": converged, "recovery": recovered}
    finally:
        runner.docker_exec(dns, "tc qdisc del dev eth0 root", expected_codes={0, 2})


def _lab_transport_cycle(runner: AuditRunner, gateway: str, *, next_cycle: bool = False) -> dict[str, object]:
    if next_cycle:
        time.sleep(TRANSPORT_PROBE_INTERVAL_SECONDS)
    return json.loads(runner.docker_exec(gateway, "python3 /opt/agent/vpn-stack-agent.py transport-reconcile").stdout)


def _lab_require_suspect(state: dict[str, object], selected: str) -> None:
    if not (
        state.get("state") == "suspect" and state.get("selected") == selected
        and state.get("changed") is not True and state.get("would_switch") is not True
        and state.get("hard_failure_evidence") is not True
        and state.get("failure", {}).get("path") == selected
        and state.get("failure", {}).get("confirmations") == 1
        and state.get("probes", {}).get(selected, {}).get("checked") is True
        and state.get("probes", {}).get(selected, {}).get("ok") is False
    ):
        raise AuditFailure(f"One failed cycle must not confirm failure or switch: {state}")


def _lab_confirmed_loss(runner: AuditRunner, gateway: str, selected: str, target: str | None) -> list[dict[str, object]]:
    first = _lab_transport_cycle(runner, gateway)
    _lab_require_suspect(first, selected)
    second = _lab_transport_cycle(runner, gateway, next_cycle=True)
    try:
        gap = (datetime.fromisoformat(second["updated_at"]) - datetime.fromisoformat(first["updated_at"])).total_seconds()
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditFailure("Loss confirmation has no valid cycle timestamps") from exc
    if not (
        first.get("cycle_id") and second.get("cycle_id") and first["cycle_id"] != second["cycle_id"]
        and TRANSPORT_PROBE_INTERVAL_SECONDS <= gap <= TRANSPORT_EVIDENCE_MAX_GAP_SECONDS
        and second.get("hard_failure_evidence") is True
        and second.get("probes", {}).get(selected, {}).get("checked") is True
        and second.get("probes", {}).get(selected, {}).get("ok") is False
    ):
        raise AuditFailure(f"Failure was not confirmed by two distinct fresh cycles: {first}, {second}")
    evidence = second if target is None else second.get("last_transition", {}).get("decision_evidence", {})
    paths = {"failure": selected}
    if target is not None:
        paths["alternate_health"] = target
    for key, path in paths.items():
        item = evidence.get(key, {})
        if item.get("path") != path or item.get("confirmations") != 2 or item.get("cycle_ids") != [first["cycle_id"], second["cycle_id"]]:
            raise AuditFailure(f"Missing matching two-cycle {key} evidence: {second}")
    if target is None:
        if second.get("state") != "failed" or second.get("changed") is True or second.get("selected") != selected:
            raise AuditFailure(f"Both-path loss was reported as usable or changed selector: {second}")
    elif not (
        second.get("changed") is True and second.get("selected") == target
        and second.get("selector_before") == selected and second.get("selector_after") == target
        and second.get("overlay_probe", {}).get("phase") == "activation"
        and second.get("overlay_probe", {}).get("ok") is True
        and second.get("overlay_probe", {}).get("path") == target
        and second.get("overlay_probe", {}).get("cycle_id") == second["cycle_id"]
        and second.get("last_transition", {}).get("cycle_id") == second["cycle_id"]
        and second.get("last_transition", {}).get("activation_proof", {}).get("ok") is True
    ):
        raise AuditFailure(f"Confirmed loss did not activate a proven fallback: {second}")
    return [first, second]


def _lab_require_udp_quality(state: dict[str, object], selected: str) -> None:
    probes = state.get("probes", {})
    active = probes.get(selected, {})
    if active.get("quality_sampled") is not True:
        raise AuditFailure(f"Recovery did not collect a fresh selected-path quality sample: {state}")
    for tag in TRANSPORT_CANDIDATE_TAGS:
        probe = active.get("quality_probe", {}) if tag == selected else probes.get(tag, {})
        if not (
            probe.get("scope") == "raw-underlay-udp" and probe.get("quality_ok") is True
            and probe.get("budget_ms") == TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS
            and all(probe.get(key) == TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS
                    for key in ("attempts", "attempts_limit", "transmitted", "received", "valid_responses"))
        ):
            raise AuditFailure(f"Recovered {tag} lacks comparable successful UDP quality evidence: {probe}")


@contextmanager
def _lab_underlay_loss(runner: AuditRunner, gateway: str, exit_node: str, ports: tuple[int, ...], *, reverse: bool = False):
    # Drop at the receiver: local OUTPUT drops return EPERM to the sending socket.
    container = gateway if reverse else exit_node
    peer = LAB_IPS["exit"] if reverse else LAB_IPS["gateway"]

    def add_port(port: int) -> None:
        runner.docker_exec(container, f"nft add rule inet underlay_fault input ip saddr {peer} "
                           f"udp {'sport' if reverse else 'dport'} {port} drop")

    runner.docker_exec(container, "nft add table inet underlay_fault")
    try:
        runner.docker_exec(container, "nft 'add chain inet underlay_fault input { type filter hook input priority -10; policy accept; }'")
        for port in ports:
            add_port(port)
        yield add_port
    finally:
        runner.docker_exec(container, "nft delete table inet underlay_fault")


def _lab_processes(runner: AuditRunner, containers: dict[str, str]) -> dict[str, object]:
    script = textwrap.dedent("""\
        import json
        from pathlib import Path
        processes = {}
        for path in Path('/proc').glob('[0-9]*/stat'):
            try:
                stat = path.read_text()
            except FileNotFoundError:
                continue
            name = stat[stat.index('(') + 1:stat.rindex(')')]
            fields = stat[stat.rindex(')') + 2:].split()
            if name == 'sing-box' and fields[0] != 'Z':
                processes[path.parent.name] = fields[19]
        print(json.dumps(processes))
        """)
    result = {role: json.loads(runner.docker_exec(container, f"python3 -c {shlex.quote(script)}").stdout)
              for role, container in containers.items()}
    if any(len(processes) != 1 for processes in result.values()) or not result:
        raise AuditFailure(f"Expected one live sing-box process per lab node: {result}")
    return result


def validate_process_continuity(before: dict[str, object], after: dict[str, object]) -> None:
    if not before or before != after:
        raise AuditFailure(f"sing-box restarted during underlay fault tests: {before} -> {after}")


def _lab_require_stream_active(runner: AuditRunner, client: str) -> None:
    runner.docker_exec(client, "test ! -e /opt/stream.rc && test -s /opt/stream.out && "
                       f"test $(stat -c %s /opt/stream.out) -lt {LAB_STREAM_BYTES}")


@contextmanager
def _lab_logs(runner: AuditRunner):
    try:
        yield
    finally:
        destination = runner.work_dir / "lab" / "runtime-logs"
        destination.mkdir(parents=True, exist_ok=True)
        errors = []
        for role, path in (("gateway", "/opt/ru-singbox.log"), ("exit", "/opt/foreign-singbox.log"),
                           ("client", "/opt/client-singbox.log"), ("dns", "/opt/dns.log")):
            try:
                runner.docker_cp_from(f"{role}-{runner.run_id}", path, destination / f"{role}.log")
            except AuditFailure as exc:
                errors.append(f"{role}: {exc}")
        if errors:
            write_text(destination / "collection-errors.txt", "\n".join(errors))


def test_lab_dataplane(runner: AuditRunner) -> dict[str, str]:
    runner.cleanup_stale_lab_resources()
    env_path, env = runner.create_env(
        "lab",
        {
            "GATEWAY_PUBLIC_IP": LAB_IPS["gateway"],
            "EXIT_PUBLIC_IP": LAB_IPS["exit"],
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
        with (
            runner.docker_container(f"gateway-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["gateway"]) as ru_container,
            runner.docker_container(f"exit-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["exit"]) as foreign_container,
            runner.docker_container(f"client-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["client"]) as client_container,
            runner.docker_container(f"dns-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["dns"]) as dns_container,
            runner.docker_container(f"ruweb-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=ru_lan, ip=LAB_IPS["ru_web"]) as ru_web_container,
            runner.docker_container(f"globalweb-{runner.run_id}", AUDIT_IMAGE, privileged=True, network=global_lan, ip=LAB_IPS["global_web"]) as global_web_container,
            _lab_logs(runner),
        ):
            runner.docker_network_connect(ru_lan, ru_container, LAB_IPS["ru_lan"])
            runner.docker_network_connect(global_lan, foreign_container, LAB_IPS["exit_wan"])
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
            agent_dir = out_dir / "preview" / NODE_GATEWAY
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

            for name in ("vpn-stack-agent.py", *SERVER_AGENT_BASE_MODULES, *SERVER_AGENT_INTERSERVER_MODULES):
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
                    "for i in $(seq 1 50); do curl -fsS --noproxy '*' --max-time 1 http://127.0.0.1/ready >/dev/null && exit 0; sleep 0.1; done; cat /opt/web.log; exit 1",
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
            process_containers = {"gateway": ru_container, "exit": foreign_container, "client": client_container}
            processes_before = _lab_processes(runner, process_containers)

            ru_resp = runner.lab_curl(client_container, "http://ya.ru/").stdout
            if "server=ru-web" not in ru_resp or f"source={LAB_IPS['ru_lan']}" not in ru_resp:
                raise AuditFailure(f"RU dataplane не подтверждён:\n{ru_resp}")

            raw_ru_resp = runner.lab_curl(client_container, f"http://{LAB_IPS['ru_web']}/").stdout
            if "server=ru-web" not in raw_ru_resp or f"source={LAB_IPS['ru_lan']}" not in raw_ru_resp:
                raise AuditFailure(f"Raw RU GeoIP ушёл не через direct-ru:\n{raw_ru_resp}")

            global_resp = runner.lab_curl(client_container, "http://example.com/").stdout
            if "server=global-web" not in global_resp or f"source={LAB_IPS['exit_wan']}" not in global_resp:
                raise AuditFailure(f"Global dataplane через foreign не подтверждён:\n{global_resp}")
            wg_qdisc = next(
                item
                for item in json.loads(runner.docker_exec(ru_container, "tc -j -s qdisc show dev wg0").stdout)
                if item.get("root") is True
            )
            if wg_qdisc.get("kind") != "fq" or int(wg_qdisc.get("packets", 0)) < 1:
                raise AuditFailure(f"WireGuard traffic bypassed the managed qdisc: {wg_qdisc}")

            raw_global_resp = runner.lab_curl(client_container, f"http://{LAB_IPS['global_web']}/").stdout
            if "server=global-web" not in raw_global_resp or f"source={LAB_IPS['exit_wan']}" not in raw_global_resp:
                raise AuditFailure(f"Raw global IP ушёл не через foreign:\n{raw_global_resp}")

            deadline_report = _lab_overlay_deadlines(runner, ru_container, dns_container, env)
            runner.docker_exec(
                client_container,
                "rm -f /opt/stream.out /opt/stream.rc /opt/stream.time; "
                "(curl --silent --show-error --fail --noproxy '' --socks5-hostname 127.0.0.1:1080 "
                f"--max-time {LAB_STREAM_MAX_SECONDS} "
                "--write-out '%{time_total}' --output /opt/stream.out http://example.com/stream "
                ">/opt/stream.time; echo $? >/opt/stream.rc) &",
            )
            runner.docker_exec(client_container,
                               "for i in $(seq 1 100); do test ! -e /opt/stream.rc || exit 1; "
                               f"test -s /opt/stream.out && test $(stat -c %s /opt/stream.out) -ge {LAB_STREAM_CHUNK_BYTES} "
                               "&& exit 0; sleep 0.05; done; exit 1")
            fallback_tag = next(tag for tag in TRANSPORT_CANDIDATE_TAGS if tag != TRANSPORT_PREFERRED_TAG)
            fault_port = HY2_PORT if TRANSPORT_PREFERRED_TAG == TRANSPORT_HY2_TAG else int(env["WG_PORT"])
            fallback_port = int(env["WG_PORT"]) if fallback_tag != TRANSPORT_HY2_TAG else HY2_PORT
            with _lab_underlay_loss(runner, ru_container, foreign_container, (fault_port,)):
                _lab_require_stream_active(runner, client_container)
                switch_started = time.monotonic()
                forward_loss = _lab_confirmed_loss(runner, ru_container, TRANSPORT_PREFERRED_TAG, fallback_tag)
                switch_seconds = time.monotonic() - switch_started
            transition = forward_loss[-1]
            if switch_seconds > LAB_FAILOVER_MAX_SECONDS:
                raise AuditFailure(f"Two-cycle failover exceeded {LAB_FAILOVER_MAX_SECONDS:g}s: {switch_seconds:.3f}s")
            # The first observation after activation must not inherit the old path's failure count.
            with _lab_underlay_loss(runner, ru_container, foreign_container, (fallback_port,), reverse=True):
                _lab_require_stream_active(runner, client_container)
                activation_transient = _lab_transport_cycle(runner, ru_container, next_cycle=True)
                _lab_require_suspect(activation_transient, fallback_tag)
            fallback_stability = _lab_transport_cycle(runner, ru_container, next_cycle=True)
            if not (
                fallback_stability.get("changed") is not True
                and fallback_stability.get("selected") == fallback_tag
                and fallback_stability.get("overlay_probe", {}).get("ok") is True
                and not fallback_stability.get("failure")
            ):
                raise AuditFailure(f"A brief post-activation loss did not recover on the same path: {fallback_stability}")
            runner.docker_exec(
                client_container,
                f"for i in $(seq 1 {LAB_STREAM_MAX_SECONDS * 10}); do test -s /opt/stream.rc && exit 0; sleep 0.1; done; exit 1",
            )
            stream_result = runner.docker_exec(
                client_container,
                f'test "$(cat /opt/stream.rc)" = 0 && test "$(stat -c %s /opt/stream.out)" = {LAB_STREAM_BYTES}',
            )
            if stream_result.returncode != 0:
                raise AuditFailure("Existing TCP stream did not survive the underlay switch")
            digest = hashlib.sha256()
            for index in range(LAB_STREAM_CHUNKS):
                digest.update(bytes([index % 256]) * LAB_STREAM_CHUNK_BYTES)
            stream_sha256 = runner.docker_exec(client_container, "sha256sum /opt/stream.out").stdout.split()[0]
            if stream_sha256 != digest.hexdigest():
                raise AuditFailure("Existing TCP stream checksum changed across the underlay switch")
            stream_seconds = float(runner.docker_exec(client_container, "cat /opt/stream.time").stdout.strip())
            if stream_seconds > LAB_STREAM_MAX_SECONDS:
                raise AuditFailure(f"Underlay switch stalled an existing TCP stream for too long: {stream_seconds:.3f}s")
            request_count = runner.docker_exec(global_web_container, "grep -Fxc /stream /opt/requests.log")
            if request_count.stdout.strip() != "1":
                raise AuditFailure("Continuity check retried HTTP instead of preserving one TCP stream")
            runner.docker_exec(
                ru_container,
                "python3 -c \"import json; p='/var/lib/vpn-stack/transport-state.json'; "
                "s=json.load(open(p)); s['preferred_retry']['retry_at']='1970-01-01T00:00:00+00:00'; "
                "s.pop('quality_probe_at',None); "
                "open(p,'w').write(json.dumps(s))\"",
            )
            recovery: list[dict[str, object]] = []
            for attempt in range(3):
                if attempt:
                    start_adjustment = (
                        f"s['preferred_recovery']['started_at']=(t-timedelta(seconds={TRANSPORT_PREFERRED_RECOVERY_MIN_SECONDS + 1})).isoformat(); "
                        if attempt == 1
                        else ""
                    )
                    runner.docker_exec(
                        ru_container,
                        "python3 -c \"import json; from datetime import datetime,timedelta; "
                        "p='/var/lib/vpn-stack/transport-state.json'; s=json.load(open(p)); "
                        "t=datetime.fromisoformat(s['updated_at']); "
                        f"s['preferred_probe_at']=(t-timedelta(seconds={TRANSPORT_PREFERRED_PROBE_INTERVAL_SECONDS + 1})).isoformat(); "
                        f"{start_adjustment}open(p,'w').write(json.dumps(s))\"",
                    )
                recovery.append(_lab_transport_cycle(runner, ru_container, next_cycle=True))
                if attempt == 0:
                    _lab_require_udp_quality(recovery[0], fallback_tag)
            if not (
                all(state.get("changed") is not True and state.get("selected") == fallback_tag for state in recovery[:2])
                and recovery[-1].get("changed") is True
                and recovery[-1].get("selected") == TRANSPORT_PREFERRED_TAG
            ):
                raise AuditFailure(f"Transport agent did not return to the recovered preferred underlay: {recovery}")
            with _lab_underlay_loss(runner, ru_container, foreign_container, (fault_port,), reverse=True) as add_loss:
                reverse_loss = _lab_confirmed_loss(runner, ru_container, TRANSPORT_PREFERRED_TAG, fallback_tag)
                add_loss(fallback_port)
                both_loss = _lab_confirmed_loss(runner, ru_container, fallback_tag, None)
                failed_both = runner.lab_curl(client_container, "http://example.com/", expect_codes={7, 22, 28, 52, 56, 97})
                if failed_both.returncode == 0:
                    raise AuditFailure("Both-path loss allowed global traffic instead of failing closed")
            restored = _lab_transport_cycle(runner, ru_container, next_cycle=True)
            if restored.get("overlay_probe", {}).get("ok") is not True or restored.get("selected") not in {fallback_tag, TRANSPORT_PREFERRED_TAG}:
                raise AuditFailure(f"No proven overlay recovered after both-path loss: {restored}")
            if restored.get("changed") is True and restored.get("last_transition", {}).get("activation_proof", {}).get("ok") is not True:
                raise AuditFailure(f"Recovery switched without a matching activation proof: {restored}")
            restored_stability = _lab_transport_cycle(runner, ru_container, next_cycle=True)
            if restored_stability.get("overlay_probe", {}).get("ok") is not True or restored_stability.get("selected") != restored.get("selected"):
                raise AuditFailure(f"Recovered overlay failed its next liveness cycle: {restored_stability}")
            recovered_response = runner.lab_curl(client_container, "http://example.com/recovered").stdout
            if "server=global-web" not in recovered_response or f"source={LAB_IPS['exit_wan']}" not in recovered_response:
                raise AuditFailure(f"Recovered overlay did not restore application traffic: {recovered_response}")
            processes_after = _lab_processes(runner, process_containers)
            validate_process_continuity(processes_before, processes_after)
            continuity_report = lab_dir / "transport-continuity.json"
            write_text(
                continuity_report,
                json.dumps(
                    {
                        "transition": transition,
                        "forward_one_way_loss": forward_loss,
                        "overlay_deadlines": deadline_report,
                        "post_activation_transient": activation_transient,
                        "fallback_stability": fallback_stability,
                        "switch_seconds": switch_seconds,
                        "stream_bytes": LAB_STREAM_BYTES,
                        "stream_sha256": stream_sha256,
                        "stream_seconds": stream_seconds,
                        "server_request_count": 1,
                        "preferred_recovery": recovery,
                        "reverse_one_way_loss": reverse_loss,
                        "both_path_loss": both_loss,
                        "restored_path": restored,
                        "restored_stability": restored_stability,
                        "processes_before": processes_before,
                        "processes_after": processes_after,
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
