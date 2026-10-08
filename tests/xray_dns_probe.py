"""Local-only runtime probe, executed inside the Docker audit container."""
from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import tempfile
import threading
import time
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from vpn_installer.config import generate_default_env
from vpn_installer.manifest import XRAY_LINUX_AMD64_BINARY_SHA256, XRAY_VERSION
from vpn_installer.render import render_gateway_xray

DOMAIN = "xray-dns.audit.invalid"
BODY = b"xray-dns-port-1053-ok\n"


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def ready(process: subprocess.Popen, port: int) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process exited before listening on {port}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"listener {port} did not become ready")


def probe(xray: Path) -> dict:
    digest = hashlib.sha256(xray.read_bytes()).hexdigest()
    if digest != XRAY_LINUX_AMD64_BINARY_SHA256:
        raise RuntimeError(f"Xray binary hash mismatch: {digest}")
    version = subprocess.run([str(xray), "version"], capture_output=True, text=True, check=True, timeout=2).stdout.splitlines()[0]
    if not version.startswith(f"Xray {XRAY_VERSION} "):
        raise RuntimeError(f"Xray version mismatch: {version}")
    env = generate_default_env("audit-xray-dns")
    env.update(GATEWAY_PUBLIC_IP="203.0.113.10", EXIT_PUBLIC_IP="198.51.100.20", WG_FOREIGN_ADDRESS="127.0.0.1/32")
    rendered = json.loads(render_gateway_xray(env))
    outbound = next(item for item in rendered["outbounds"] if item["tag"] == "foreign-overlay")
    # Keep the rendered resolver and freedom domain strategy; only remove the
    # unavailable production WireGuard binding and replace the public ingress.
    outbound.pop("streamSettings")
    config = {
        "log": {"loglevel": "debug"},
        "dns": rendered["dns"],
        "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth"}}],
        "outbounds": [outbound],
        "routing": {"domainStrategy": "AsIs", "rules": [rendered["routing"]["rules"][0]]},
    }
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append({"path": self.path, "host": self.headers.get("Host")})
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

        def log_message(self, *_args):
            pass

    results = {}
    with tempfile.TemporaryDirectory() as temporary, ThreadingHTTPServer(("127.0.0.1", 0), Handler) as http:
        directory = Path(temporary)
        worker = threading.Thread(target=http.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        try:
            dns_log = directory / "dns.log"
            with dns_log.open("w") as dns_output:
                dns = subprocess.Popen([
                    "dnsmasq", "--no-daemon", "--conf-file=/dev/null", "--no-resolv", "--no-hosts",
                    "--listen-address=127.0.0.1", "--bind-interfaces", "--port=1053", "--user=root", "--group=root",
                    "--pid-file=", "--log-queries", "--log-facility=-", f"--local=/{DOMAIN}/",
                    f"--address=/{DOMAIN}/127.0.0.1",
                ], stdout=dns_output, stderr=subprocess.STDOUT)
                try:
                    try:
                        ready(dns, 1053)
                    except RuntimeError as exc:
                        raise RuntimeError(f"DNS fixture startup failed: {dns_log.read_text()}") from exc
                    for case in ("legacy_separate_port", "rendered"):
                        payload = deepcopy(config)
                        if case == "legacy_separate_port":
                            payload["dns"]["servers"][0].update(address="tcp://127.0.0.1", port=1053)
                        path = directory / f"{case}.json"
                        path.write_text(json.dumps(payload), encoding="utf-8")
                        log_path = directory / f"{case}.log"
                        before = dns_log.read_text()
                        with log_path.open("w") as log:
                            process = subprocess.Popen([str(xray), "run", "-c", str(path)], stdout=log, stderr=subprocess.STDOUT)
                            try:
                                ready(process, 10808)
                                request = subprocess.run([
                                    "curl", "--disable", "--silent", "--show-error", "--fail", "--noproxy", "",
                                    "--socks5-hostname", "127.0.0.1:10808", "--max-time", "4", "--retry", "0",
                                    f"http://{DOMAIN}:{http.server_port}/dns-port-probe",
                                ], capture_output=True, timeout=5)
                            finally:
                                stop(process)
                        log_text = log_path.read_text()
                        queries = [line for line in dns_log.read_text()[len(before):].splitlines() if "query[" in line and DOMAIN in line]
                        results[case] = {
                            "curl_exit": request.returncode, "dns_listener_port": 1053, "queries": queries,
                            "xray_dns_dials": [line for line in log_text.splitlines() if "127.0.0.1:53" in line or "127.0.0.1:1053" in line],
                        }
                        if case == "legacy_separate_port":
                            if request.returncode == 0 or queries or requests or "127.0.0.1:53" not in log_text:
                                raise RuntimeError(f"negative control did not expose the wrong DNS port: {results}")
                        elif request.returncode != 0 or request.stdout != BODY or not queries or "127.0.0.1:53" in log_text:
                            raise RuntimeError(f"rendered DNS runtime failed: {results}; stderr={request.stderr.decode(errors='replace')}; xray={log_text}")
                    expected = [{"path": "/dns-port-probe", "host": f"{DOMAIN}:{http.server_port}"}]
                    if requests != expected:
                        raise RuntimeError(f"unexpected origin requests: {requests}")
                finally:
                    stop(dns)
        finally:
            http.shutdown()
            worker.join(timeout=1)
    return {"status": "passed", "xray_version": version, "xray_sha256": digest, "cases": results, "origin_requests": requests}


if __name__ == "__main__":
    print(json.dumps(probe(Path("/work/xray")), sort_keys=True))
