from __future__ import annotations

import json
import shlex
import textwrap
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse


RUNNER_HTTP_PROBE_COUNT = 5
RUNNER_HTTP_TIMEOUT_SECONDS = 15
RUNNER_UDP_TIMEOUT_SECONDS = 18
RUNNER_STARTUP_SECONDS = 1
RUNNER_THROUGHPUT_CLOCK_SKEW_SECONDS = 1
RUNNER_CURL_WATCHDOG_KILL_SECONDS = 5
RUNNER_SHUTDOWN_SECONDS = 5
RUNNER_REPORT_SECONDS = 1
RUNNER_TRANSPORT_DRAIN_SECONDS = 10
THROUGHPUT_SOURCE_URL = "https://download.thinkbroadband.com/1GB.zip"
THROUGHPUT_RANGE_END = 1_073_741_823
# Keep acceptance load above the 10 Mbit/s floor without saturating production.
THROUGHPUT_ACCEPTANCE_LOAD_BYTES_PER_SECOND = 1_875_000


@dataclass(frozen=True)
class VlessUri:
    uuid: str
    host: str
    port: int
    server_name: str
    public_key: str
    short_id: str
    fingerprint: str
    flow: str


def parse_vless_uri(raw_value: str) -> VlessUri:
    parsed = urlparse(raw_value.strip())
    if parsed.scheme != "vless" or not parsed.username or not parsed.hostname or not parsed.port:
        raise ValueError("invalid VLESS URI")
    query = parse_qs(parsed.query)
    if query.get("security", [""])[0] != "reality" or query.get("type", [""])[0] != "tcp":
        raise ValueError("VLESS URI must use Reality over TCP")
    required = {key: query.get(key, [""])[0] for key in ("sni", "pbk", "sid", "fp", "flow")}
    if not all(required.values()):
        raise ValueError("VLESS URI has incomplete Reality parameters")
    return VlessUri(
        uuid=unquote(parsed.username),
        host=parsed.hostname,
        port=parsed.port,
        server_name=required["sni"],
        public_key=required["pbk"],
        short_id=required["sid"],
        fingerprint=required["fp"],
        flow=required["flow"],
    )


def render_ephemeral_singbox_client(uri: VlessUri, *, listen_port: int) -> str:
    payload = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": listen_port, "tag": "verify-in"}],
        "outbounds": [
            {
                "type": "vless",
                "tag": "ru-gateway",
                "server": uri.host,
                "server_port": uri.port,
                "uuid": uri.uuid,
                "flow": uri.flow,
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True,
                    "server_name": uri.server_name,
                    "utls": {"enabled": True, "fingerprint": uri.fingerprint},
                    "reality": {"enabled": True, "public_key": uri.public_key, "short_id": uri.short_id},
                },
            }
        ],
        "route": {"final": "ru-gateway"},
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def render_socks5_udp_dns_probe(*, listen_port: int) -> str:
    """Return a stdlib-only SOCKS5 UDP-associate probe for the ephemeral verifier."""
    return textwrap.dedent(
        f"""\
        import json
        import socket
        import struct

        def receive_exact(sock, size):
            data = b""
            while len(data) < size:
                chunk = sock.recv(size - len(data))
                if not chunk:
                    raise RuntimeError("unexpected SOCKS EOF")
                data += chunk
            return data

        def dns_query(name):
            labels = name.split(".")
            question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels)
            return b"\\x11\\x22\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00" + question + b"\\x00\\x00\\x01\\x00\\x01"

        control = socket.create_connection(("127.0.0.1", {listen_port}), timeout=8)
        control.sendall(b"\\x05\\x01\\x00")
        if receive_exact(control, 2) != b"\\x05\\x00":
            raise RuntimeError("SOCKS authentication failed")
        control.sendall(b"\\x05\\x03\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        response = receive_exact(control, 4)
        if response[:2] != b"\\x05\\x00":
            raise RuntimeError(f"SOCKS UDP associate rejected: {{response!r}}")
        address_type = response[3]
        if address_type == 1:
            relay_address = socket.inet_ntoa(receive_exact(control, 4))
        elif address_type == 4:
            relay_address = socket.inet_ntop(socket.AF_INET6, receive_exact(control, 16))
        elif address_type == 3:
            relay_address = receive_exact(control, receive_exact(control, 1)[0]).decode("ascii")
        else:
            raise RuntimeError("unknown SOCKS relay address type")
        relay_port = struct.unpack("!H", receive_exact(control, 2))[0]
        if relay_address in {{"0.0.0.0", "::"}}:
            relay_address = "127.0.0.1"

        request = b"\\x00\\x00\\x00\\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + dns_query("example.com")
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(10)
        udp.sendto(request, (relay_address, relay_port))
        reply, _peer = udp.recvfrom(4096)
        if len(reply) < 14 or reply[:3] != b"\\x00\\x00\\x00":
            raise RuntimeError("invalid SOCKS UDP reply")
        if reply[3] == 1:
            payload_offset = 10
        elif reply[3] == 4:
            payload_offset = 22
        elif reply[3] == 3:
            payload_offset = 5 + reply[4]
        else:
            raise RuntimeError("invalid SOCKS reply address type")
        if reply[payload_offset:payload_offset + 2] != b"\\x11\\x22":
            raise RuntimeError("DNS transaction mismatch")
        print(json.dumps({{"ok": True, "answer_bytes": len(reply) - payload_offset}}))
        """
    )


def render_vless_runner(*, listen_port: int, throughput_url: str = THROUGHPUT_SOURCE_URL) -> str:
    """Render the external, full-path VLESS acceptance runner.

    The throughput phase measures aggregate transferred bytes over a fixed wall
    clock window. A completed range is requested again until the deadline, so
    fast paths do not turn a ten-minute check into a short burst. Its controlled
    15 Mbit/s load stays above the 10 Mbit/s acceptance floor without saturating
    production traffic.
    """

    template = r'''
#!/usr/bin/env bash
set -uo pipefail

config_path=${1:?missing sing-box config path}
udp_probe_path=${2:?missing UDP probe path}
throughput_seconds=${3:-0}
proxy="socks5h://127.0.0.1:__LISTEN_PORT__"
throughput_url=__THROUGHPUT_URL__
runner_started_ns=$(date +%s%N)
pid=""

event() {
    printf 'vpn-vless-runner phase=%s elapsed_s=%s\n' "$1" "$(( ($(date +%s%N) - runner_started_ns) / 1000000000 ))" >&2
}

fail() {
    event "failed:$1"
    tail -n 20 runner-curl.log >&2 2>/dev/null || true
    tail -n 20 sing-box.log >&2 2>/dev/null || true
    exit 1
}

cleanup() {
    if [[ -z "${pid:-}" ]] || ! kill -0 "$pid" 2>/dev/null; then
        return
    fi
    kill "$pid" >/dev/null 2>&1 || true
    for ((attempt = 0; attempt < __SHUTDOWN_POLLS__; attempt++)); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
    wait "$pid" >/dev/null 2>&1 || true
}

trap cleanup EXIT
event sing-box-check
if ! sing-box check -c "$config_path" >sing-box.log 2>&1; then
    fail sing-box-check
fi
sing-box run -c "$config_path" >sing-box.log 2>&1 &
pid=$!
sleep __STARTUP_SECONDS__
if ! kill -0 "$pid" 2>/dev/null; then
    fail sing-box-start
fi

event ru-identity
if ! ru_ip=$(curl -4fsS --proxy "$proxy" --connect-timeout 5 --max-time __HTTP_TIMEOUT_SECONDS__ https://api.ipify.org 2>>runner-curl.log); then
    fail ru-identity
fi
event foreign-identity
if ! foreign_ip=$(curl -4fsS --proxy "$proxy" --connect-timeout 5 --max-time __HTTP_TIMEOUT_SECONDS__ https://www.cloudflare.com/cdn-cgi/trace 2>>runner-curl.log | awk -F= '/^ip=/{print $2; exit}'); then
    fail foreign-identity
fi
event github
if ! github=$(curl -4sS -o /dev/null -w '%{http_code}' --proxy "$proxy" --connect-timeout 5 --max-time __HTTP_TIMEOUT_SECONDS__ https://github.com/ 2>>runner-curl.log); then
    fail github
fi
event google
if ! google=$(curl -4sS -o /dev/null -w '%{http_code}' --proxy "$proxy" --connect-timeout 5 --max-time __HTTP_TIMEOUT_SECONDS__ https://www.google.com/generate_204 2>>runner-curl.log); then
    fail google
fi
event udp-dns
if ! udp_dns=$(python3 "$udp_probe_path" 2>>runner-curl.log); then
    fail udp-dns
fi
event ipv6-literal
if ! ipv6_literal=$(curl -ksS -o /dev/null -w '%{http_code}' --proxy "$proxy" --connect-timeout 5 --max-time __HTTP_TIMEOUT_SECONDS__ https://[2606:4700:4700::1111]/cdn-cgi/trace 2>>runner-curl.log); then
    fail ipv6-literal
fi

throughput_bytes=0
throughput_attempts=0
throughput_failures=0
throughput_start_ns=0
throughput_end_ns=0
if (( throughput_seconds > 0 )); then
    event throughput-start
    throughput_start_ns=$(date +%s%N)
    throughput_deadline_ns=$((throughput_start_ns + throughput_seconds * 1000000000))
    while :; do
        now_ns=$(date +%s%N)
        remaining_ns=$((throughput_deadline_ns - now_ns))
        (( remaining_ns > 0 )) || break
        remaining_seconds=$(((remaining_ns + 999999999) / 1000000000))
        event "throughput-attempt-$throughput_attempts-remaining-$remaining_seconds"
        throughput_count_file=$(mktemp)
        timeout --foreground --signal=TERM --kill-after=__CURL_WATCHDOG_KILL_SECONDS__s "${remaining_seconds}s" curl -4fsS --proxy "$proxy" --connect-timeout 5 --limit-rate __THROUGHPUT_ACCEPTANCE_LOAD_BYTES_PER_SECOND__ --range 0-__THROUGHPUT_RANGE_END__ -o - "$throughput_url" 2>>runner-curl.log | wc -c >"$throughput_count_file"
        pipeline_status=("${PIPESTATUS[@]}")
        curl_status=${pipeline_status[0]}
        counter_status=${pipeline_status[1]}
        curl_output=$(tr -d '[:space:]' <"$throughput_count_file")
        rm -f "$throughput_count_file"
        if (( counter_status != 0 )) || [[ ! "$curl_output" =~ ^[0-9]+$ ]]; then
            throughput_failures=$((throughput_failures + 1))
            event throughput-invalid-metrics
            break
        fi
        throughput_bytes=$((throughput_bytes + curl_output))
        throughput_attempts=$((throughput_attempts + 1))
        now_ns=$(date +%s%N)
        if (( curl_status == 0 )); then
            if (( curl_output == 0 )); then
                throughput_failures=$((throughput_failures + 1))
                event throughput-empty-response
                break
            fi
            continue
        fi
        if (( (curl_status == 28 || curl_status == 124 || curl_status == 137) && now_ns >= throughput_deadline_ns && curl_output > 0 )); then
            break
        fi
        throughput_failures=$((throughput_failures + 1))
        event "throughput-curl-exit-$curl_status"
        break
    done
    throughput_end_ns=$(date +%s%N)
    event throughput-complete
fi

python3 - "$ru_ip" "$foreign_ip" "$github" "$google" "$throughput_bytes" "$throughput_start_ns" "$throughput_end_ns" "$throughput_attempts" "$throughput_failures" "$udp_dns" "$ipv6_literal" <<'PY'
import json
import sys

bytes_downloaded = int(sys.argv[5])
started_ns = int(sys.argv[6])
ended_ns = int(sys.argv[7])
duration_seconds = max(0.0, (ended_ns - started_ns) / 1_000_000_000) if started_ns else 0.0
throughput = {
    "bytes_per_second": bytes_downloaded / duration_seconds if duration_seconds else 0.0,
    "duration_seconds": duration_seconds,
    "bytes_downloaded": bytes_downloaded,
    "attempts": int(sys.argv[8]),
    "failures": int(sys.argv[9]),
}
print(json.dumps({
    "ru_egress_ip": sys.argv[1],
    "foreign_egress_ip": sys.argv[2],
    "github_status": sys.argv[3],
    "google_status": sys.argv[4],
    "throughput": throughput,
    "udp_dns": json.loads(sys.argv[10]),
    "ipv6_literal_status": sys.argv[11],
}))
PY
'''
    return textwrap.dedent(template).lstrip().replace("__LISTEN_PORT__", str(listen_port)).replace(
        "__THROUGHPUT_URL__", shlex.quote(throughput_url)
    ).replace("__HTTP_TIMEOUT_SECONDS__", str(RUNNER_HTTP_TIMEOUT_SECONDS)).replace(
        "__STARTUP_SECONDS__", str(RUNNER_STARTUP_SECONDS)
    ).replace("__THROUGHPUT_RANGE_END__", str(THROUGHPUT_RANGE_END)).replace(
        "__SHUTDOWN_POLLS__", str(RUNNER_SHUTDOWN_SECONDS * 10)
    ).replace(
        "__THROUGHPUT_ACCEPTANCE_LOAD_BYTES_PER_SECOND__", str(THROUGHPUT_ACCEPTANCE_LOAD_BYTES_PER_SECOND)
    ).replace(
        "__CURL_WATCHDOG_KILL_SECONDS__", str(RUNNER_CURL_WATCHDOG_KILL_SECONDS)
    )
