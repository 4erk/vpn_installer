from __future__ import annotations

import json
import shlex
import textwrap
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse


RUNNER_HTTP_PROBE_COUNT = 5
RUNNER_HTTP_TIMEOUT_SECONDS = 15
RUNNER_RELIABILITY_ATTEMPTS = 9
RUNNER_RELIABILITY_FAILURE_LIMIT = 2
RUNNER_RELIABILITY_TIMEOUT_SECONDS = 8
RUNNER_RELIABILITY_MAX_TOTAL_SECONDS = 5.0
RUNNER_ROUTE_PROBE_TIMEOUT_SECONDS = 24
RUNNER_STARTUP_SECONDS = 1
RUNNER_THROUGHPUT_CLOCK_SKEW_SECONDS = 1
RUNNER_CURL_WATCHDOG_KILL_SECONDS = 5
RUNNER_LEASE_TIMEOUT_SECONDS = 20
RUNNER_SHUTDOWN_SECONDS = 5
RUNNER_REPORT_SECONDS = 1
RUNNER_TRANSPORT_DRAIN_SECONDS = 10
RELIABILITY_PROBE_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://github.com/favicon.ico",
)
THROUGHPUT_SOURCE_URLS = (
    "https://fsn1-speed.hetzner.com/100MB.bin",
    "https://nbg1-speed.hetzner.com/100MB.bin",
)
THROUGHPUT_RANGE_END = 1_073_741_823
THROUGHPUT_ATTEMPT_SECONDS = 10
THROUGHPUT_MIN_CAPACITY_ATTEMPT_SECONDS = 3
THROUGHPUT_CAPACITY_SECONDS = 30
THROUGHPUT_STABILITY_LIMIT_BYTES_PER_SECOND = 2_000_000
THROUGHPUT_STABILITY_FLOOR_BYTES_PER_SECOND = 1_250_000


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
    """Return a stdlib-only SOCKS5 DNS and private-route probe for the verifier."""
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

        def socks_reply(sock):
            response = receive_exact(sock, 4)
            if response[0] != 5 or response[2] != 0:
                raise RuntimeError("invalid SOCKS reply")
            address_type = response[3]
            if address_type == 1:
                address = socket.inet_ntoa(receive_exact(sock, 4))
            elif address_type == 4:
                address = socket.inet_ntop(socket.AF_INET6, receive_exact(sock, 16))
            elif address_type == 3:
                address = receive_exact(sock, receive_exact(sock, 1)[0]).decode("ascii")
            else:
                raise RuntimeError("unknown SOCKS reply address type")
            return response[1], address, struct.unpack("!H", receive_exact(sock, 2))[0]

        def private_connect_rejected(address, port):
            control = socket.create_connection(("127.0.0.1", {listen_port}), timeout=2)
            try:
                control.sendall(b"\\x05\\x01\\x00")
                if receive_exact(control, 2) != b"\\x05\\x00":
                    raise RuntimeError("SOCKS authentication failed")
                control.sendall(b"\\x05\\x01\\x00\\x01" + socket.inet_aton(address) + struct.pack("!H", port))
                status, _bound_address, _bound_port = socks_reply(control)
                if status != 0:
                    return True
                control.sendall(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                return control.recv(1) == b""
            finally:
                control.close()

        with socket.create_connection(("127.0.0.1", {listen_port}), timeout=8) as control:
            control.sendall(b"\\x05\\x01\\x00")
            if receive_exact(control, 2) != b"\\x05\\x00":
                raise RuntimeError("SOCKS authentication failed")
            control.sendall(b"\\x05\\x03\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
            response_status, relay_address, relay_port = socks_reply(control)
            if response_status != 0:
                raise RuntimeError(f"SOCKS UDP associate rejected: {{response_status}}")
            if relay_address in {{"0.0.0.0", "::"}}:
                relay_address = "127.0.0.1"

            request = b"\\x00\\x00\\x00\\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + dns_query("example.com")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
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
        private_targets = []
        for address, port in (("10.0.0.1", 80), ("172.19.0.2", 853)):
            try:
                rejected = private_connect_rejected(address, port)
                error = ""
            except Exception as exc:
                rejected = False
                error = str(exc)[:160]
            private_targets.append({{"target": f"{{address}}:{{port}}", "ok": rejected, "error": error}})
        print(json.dumps({{
            "ok": True,
            "answer_bytes": len(reply) - payload_offset,
            "private_reject": {{"ok": all(item["ok"] for item in private_targets), "targets": private_targets}},
        }}))
        """
    )


def render_vless_runner(
    *,
    listen_port: int,
    throughput_urls: tuple[str, ...] = THROUGHPUT_SOURCE_URLS,
    reliability_urls: tuple[str, ...] = RELIABILITY_PROBE_URLS,
) -> str:
    """Render the external, full-path VLESS acceptance runner.

    A short uncapped phase proves available capacity. The remainder is capped
    above the acceptance floor, so a long production stability check cannot
    starve active client traffic while still detecting stalls and disconnects.
    """

    if not throughput_urls:
        raise ValueError("at least one throughput source is required")
    if len(reliability_urls) != 3:
        raise ValueError("exactly three reliability probe URLs are required")

    template = r'''
#!/usr/bin/env bash
set -uo pipefail

config_path=${1:?missing sing-box config path}
udp_probe_path=${2:?missing UDP probe path}
throughput_seconds=${3:-0}
lease_path=${4:?missing controller lease path}
lock_path=${5:?missing runner lock path}
work_dir=$(dirname -- "$config_path")
cd "$work_dir" || exit 1
proxy="socks5h://127.0.0.1:__LISTEN_PORT__"
throughput_urls=(__THROUGHPUT_URLS__)
throughput_sources_json=__THROUGHPUT_SOURCES_JSON__
reliability_urls=(__RELIABILITY_URLS__)
capacity_source_bytes=()
capacity_source_ns=()
throughput_source_failure_counts=()
for _ in "${throughput_urls[@]}"; do
    capacity_source_bytes+=(0)
    capacity_source_ns+=(0)
    throughput_source_failure_counts+=(0)
done
runner_started_ns=$(date +%s%N)
pid=""
watchdog_pid=""

exec 9>"$lock_path"
if ! flock -n 9; then
    printf 'vpn-vless-runner phase=failed:runner-busy elapsed_s=0\n' >&2
    exit 1
fi

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
    if [[ -n "${watchdog_pid:-}" ]] && kill -0 "$watchdog_pid" 2>/dev/null; then
        kill "$watchdog_pid" >/dev/null 2>&1 || true
        wait "$watchdog_pid" >/dev/null 2>&1 || true
    fi
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

watch_controller() {
    local now lease_mtime runner_pgid
    runner_pgid=$(ps -o pgid= -p $$ | tr -d ' ')
    while :; do
        sleep 2
        lease_mtime=$(stat -c %Y -- "$lease_path" 2>/dev/null || printf '0')
        now=$(date +%s)
        if (( lease_mtime == 0 || now - lease_mtime > __LEASE_TIMEOUT_SECONDS__ )); then
            event controller-lease-expired
            kill -TERM -- "-$runner_pgid" >/dev/null 2>&1 || true
            return
        fi
    done
}

trap 'exit 143' TERM INT HUP
trap cleanup EXIT
touch "$lease_path"
watch_controller &
watchdog_pid=$!
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
event private-reject
if ! python3 - "$udp_dns" <<'PY'; then
import json
import sys

payload = json.loads(sys.argv[1])
raise SystemExit(0 if payload.get("private_reject", {}).get("ok") is True else 1)
PY
    fail private-reject
fi
event ipv6-literal
if ! ipv6_literal=$(curl -ksS -o /dev/null -w '%{http_code}' --proxy "$proxy" --connect-timeout 5 --max-time __HTTP_TIMEOUT_SECONDS__ https://[2606:4700:4700::1111]/cdn-cgi/trace 2>>runner-curl.log); then
    fail ipv6-literal
fi

event first-load-reliability
reliability_attempts=0
reliability_failures=0
reliability_results_path=$(mktemp)
while (( reliability_attempts < __RELIABILITY_ATTEMPTS__ )); do
    reliability_url=${reliability_urls[$((reliability_attempts % ${#reliability_urls[@]}))]}
    reliability_attempts=$((reliability_attempts + 1))
    probe_output=$(curl -LsS -o /dev/null -w '%{http_code}|%{time_total}' --proxy "$proxy" --connect-timeout 3 --max-time __RELIABILITY_TIMEOUT_SECONDS__ "$reliability_url" 2>>runner-curl.log)
    probe_status=$?
    probe_code=${probe_output%%|*}
    probe_seconds=${probe_output#*|}
    if (( probe_status != 0 )) || [[ ! "$probe_code" =~ ^(200|204|301|302|403)$ ]] || [[ ! "$probe_seconds" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        printf '%s\t0\t%s\t%s\t%s\n' "$reliability_url" "$probe_status" "$probe_code" "$probe_seconds" >>"$reliability_results_path"
        reliability_failures=$((reliability_failures + 1))
        if (( reliability_failures >= __RELIABILITY_FAILURE_LIMIT__ )); then
            break
        fi
        continue
    fi
    printf '%s\t1\t%s\t%s\t%s\n' "$reliability_url" "$probe_status" "$probe_code" "$probe_seconds" >>"$reliability_results_path"
done

throughput_bytes=0
throughput_attempts=0
throughput_failures=0
throughput_source_failures=0
throughput_runs=0
throughput_start_ns=0
throughput_end_ns=0
stability_bytes=0
stability_ns=0
if (( throughput_seconds > 0 )); then
    event throughput-start
    throughput_start_ns=$(date +%s%N)
    throughput_deadline_ns=$((throughput_start_ns + throughput_seconds * 1000000000))
    capacity_seconds=$throughput_seconds
    if (( capacity_seconds > __THROUGHPUT_CAPACITY_SECONDS__ )); then
        capacity_seconds=__THROUGHPUT_CAPACITY_SECONDS__
    fi
    capacity_deadline_ns=$((throughput_start_ns + capacity_seconds * 1000000000))
    while :; do
        now_ns=$(date +%s%N)
        remaining_ns=$((throughput_deadline_ns - now_ns))
        (( remaining_ns > 0 )) || break
        remaining_seconds=$(((remaining_ns + 999999999) / 1000000000))
        attempt_index=$throughput_runs
        throughput_runs=$((throughput_runs + 1))
        source_index=$((attempt_index % ${#throughput_urls[@]}))
        throughput_url=${throughput_urls[$source_index]}
        attempt_seconds=$remaining_seconds
        phase=stability
        phase_deadline_ns=$throughput_deadline_ns
        curl_rate_args=()
        if (( now_ns < capacity_deadline_ns )); then
            phase=capacity
            phase_deadline_ns=$capacity_deadline_ns
        else
            source_index=$((${#throughput_urls[@]} - 1))
            throughput_url=${throughput_urls[$source_index]}
            curl_rate_args=(--limit-rate __THROUGHPUT_STABILITY_LIMIT_BYTES_PER_SECOND__)
        fi
        phase_remaining_seconds=$(((phase_deadline_ns - now_ns + 999999999) / 1000000000))
        if [[ "$phase" == "capacity" ]] && (( phase_remaining_seconds < __THROUGHPUT_MIN_CAPACITY_ATTEMPT_SECONDS__ )); then
            event throughput-capacity-boundary
            sleep "$phase_remaining_seconds"
            continue
        fi
        if (( attempt_seconds > phase_remaining_seconds )); then
            attempt_seconds=$phase_remaining_seconds
        fi
        if [[ "$phase" == "capacity" ]] && (( attempt_seconds > __THROUGHPUT_ATTEMPT_SECONDS__ )); then
            attempt_seconds=__THROUGHPUT_ATTEMPT_SECONDS__
        fi
        event "throughput-$phase-attempt-$attempt_index-source-$source_index-remaining-$remaining_seconds"
        attempt_start_ns=$now_ns
        throughput_count_file=$(mktemp)
        timeout --foreground --signal=TERM --kill-after=__CURL_WATCHDOG_KILL_SECONDS__s "${attempt_seconds}s" curl -4fsS --proxy "$proxy" --connect-timeout 5 "${curl_rate_args[@]}" --range 0-__THROUGHPUT_RANGE_END__ -o - "$throughput_url" 2>>runner-curl.log | wc -c >"$throughput_count_file"
        pipeline_status=("${PIPESTATUS[@]}")
        curl_status=${pipeline_status[0]}
        counter_status=${pipeline_status[1]}
        curl_output=$(tr -d '[:space:]' <"$throughput_count_file")
        rm -f "$throughput_count_file"
        now_ns=$(date +%s%N)
        if (( counter_status != 0 )) || [[ ! "$curl_output" =~ ^[0-9]+$ ]]; then
            throughput_source_failures=$((throughput_source_failures + 1))
            throughput_source_failure_counts[$source_index]=$((throughput_source_failure_counts[$source_index] + 1))
            event throughput-invalid-metrics
            continue
        fi
        if (( curl_output > 0 )); then
            throughput_bytes=$((throughput_bytes + curl_output))
            throughput_attempts=$((throughput_attempts + 1))
            if [[ "$phase" == "capacity" ]]; then
                capacity_source_bytes[$source_index]=$((capacity_source_bytes[$source_index] + curl_output))
                capacity_source_ns[$source_index]=$((capacity_source_ns[$source_index] + now_ns - attempt_start_ns))
            else
                stability_bytes=$((stability_bytes + curl_output))
                stability_ns=$((stability_ns + now_ns - attempt_start_ns))
            fi
        fi
        if (( curl_status == 0 )); then
            if (( curl_output == 0 )); then
                throughput_source_failures=$((throughput_source_failures + 1))
                throughput_source_failure_counts[$source_index]=$((throughput_source_failure_counts[$source_index] + 1))
                event throughput-empty-response
            fi
            continue
        fi
        if (( (curl_status == 28 || curl_status == 124 || curl_status == 137) && curl_output > 0 )); then
            continue
        fi
        throughput_source_failures=$((throughput_source_failures + 1))
        throughput_source_failure_counts[$source_index]=$((throughput_source_failure_counts[$source_index] + 1))
        event "throughput-curl-exit-$curl_status"
    done
    throughput_end_ns=$(date +%s%N)
    if (( throughput_attempts == 0 || throughput_bytes == 0 )); then
        throughput_failures=1
    fi
    event throughput-complete
fi
capacity_source_bytes_csv=$(IFS=,; printf '%s' "${capacity_source_bytes[*]}")
capacity_source_ns_csv=$(IFS=,; printf '%s' "${capacity_source_ns[*]}")
throughput_source_failure_counts_csv=$(IFS=,; printf '%s' "${throughput_source_failure_counts[*]}")

python3 - "$ru_ip" "$foreign_ip" "$github" "$google" "$throughput_bytes" "$throughput_start_ns" "$throughput_end_ns" "$throughput_attempts" "$throughput_failures" "$throughput_source_failures" "$throughput_sources_json" "$capacity_source_bytes_csv" "$capacity_source_ns_csv" "$throughput_source_failure_counts_csv" "$stability_bytes" "$stability_ns" "$udp_dns" "$ipv6_literal" "$reliability_results_path" <<'PY'
import json
import sys
from pathlib import Path

bytes_downloaded = int(sys.argv[5])
started_ns = int(sys.argv[6])
ended_ns = int(sys.argv[7])
duration_seconds = max(0.0, (ended_ns - started_ns) / 1_000_000_000) if started_ns else 0.0
sources = json.loads(sys.argv[11])
source_bytes = [int(value) for value in sys.argv[12].split(",")]
source_ns = [int(value) for value in sys.argv[13].split(",")]
source_failures = [int(value) for value in sys.argv[14].split(",")]
source_metrics = []
for url, source_byte_count, elapsed_ns, failure_count in zip(sources, source_bytes, source_ns, source_failures):
    source_duration = max(0.0, elapsed_ns / 1_000_000_000)
    source_metrics.append({
        "url": url,
        "bytes_downloaded": source_byte_count,
        "duration_seconds": source_duration,
        "bytes_per_second": source_byte_count / source_duration if source_duration else 0.0,
        "failures": failure_count,
    })
throughput = {
    "bytes_per_second": bytes_downloaded / duration_seconds if duration_seconds else 0.0,
    "capacity_bytes_per_second": max((item["bytes_per_second"] for item in source_metrics), default=0.0),
    "capacity_duration_seconds": sum(item["duration_seconds"] for item in source_metrics),
    "stability_bytes_per_second": int(sys.argv[15]) / (int(sys.argv[16]) / 1_000_000_000) if int(sys.argv[16]) else 0.0,
    "stability_duration_seconds": int(sys.argv[16]) / 1_000_000_000,
    "stability_limit_bytes_per_second": __THROUGHPUT_STABILITY_LIMIT_BYTES_PER_SECOND__,
    "duration_seconds": duration_seconds,
    "bytes_downloaded": bytes_downloaded,
    "attempts": int(sys.argv[8]),
    "failures": int(sys.argv[9]),
    "source_failures": int(sys.argv[10]),
    "sources": sources,
    "source_metrics": source_metrics,
}
reliability_probes = []
for line in Path(sys.argv[19]).read_text(encoding="utf-8").splitlines():
    url, ok, curl_status, http_status, total_seconds = line.split("\t", 4)
    reliability_probes.append({
        "url": url,
        "ok": ok == "1",
        "curl_status": int(curl_status),
        "http_status": http_status,
        "total_seconds": float(total_seconds) if total_seconds else 0.0,
    })
reliability_successes = sum(probe["ok"] for probe in reliability_probes)
successful_times = [probe["total_seconds"] for probe in reliability_probes if probe["ok"]]
reliability = {
    "attempts": len(reliability_probes),
    "successes": reliability_successes,
    "failures": len(reliability_probes) - reliability_successes,
    "average_total_seconds": sum(successful_times) / len(successful_times) if successful_times else 0.0,
    "max_total_seconds": max(successful_times, default=0.0),
    "probes": reliability_probes,
}
print(json.dumps({
    "ru_egress_ip": sys.argv[1],
    "foreign_egress_ip": sys.argv[2],
    "github_status": sys.argv[3],
    "google_status": sys.argv[4],
    "throughput": throughput,
    "udp_dns": json.loads(sys.argv[17]),
    "ipv6_literal_status": sys.argv[18],
    "first_load_reliability": reliability,
}))
PY
'''
    return textwrap.dedent(template).lstrip().replace("__LISTEN_PORT__", str(listen_port)).replace(
        "__THROUGHPUT_URLS__", " ".join(shlex.quote(url) for url in throughput_urls)
    ).replace(
        "__RELIABILITY_URLS__", " ".join(shlex.quote(url) for url in reliability_urls)
    ).replace(
        "__THROUGHPUT_SOURCES_JSON__", shlex.quote(json.dumps(list(throughput_urls), separators=(",", ":")))
    ).replace("__HTTP_TIMEOUT_SECONDS__", str(RUNNER_HTTP_TIMEOUT_SECONDS)).replace(
        "__STARTUP_SECONDS__", str(RUNNER_STARTUP_SECONDS)
    ).replace("__THROUGHPUT_RANGE_END__", str(THROUGHPUT_RANGE_END)).replace(
        "__SHUTDOWN_POLLS__", str(RUNNER_SHUTDOWN_SECONDS * 10)
    ).replace(
        "__CURL_WATCHDOG_KILL_SECONDS__", str(RUNNER_CURL_WATCHDOG_KILL_SECONDS)
    ).replace(
        "__THROUGHPUT_ATTEMPT_SECONDS__", str(THROUGHPUT_ATTEMPT_SECONDS)
    ).replace(
        "__THROUGHPUT_MIN_CAPACITY_ATTEMPT_SECONDS__", str(THROUGHPUT_MIN_CAPACITY_ATTEMPT_SECONDS)
    ).replace(
        "__THROUGHPUT_CAPACITY_SECONDS__", str(THROUGHPUT_CAPACITY_SECONDS)
    ).replace(
        "__THROUGHPUT_STABILITY_LIMIT_BYTES_PER_SECOND__", str(THROUGHPUT_STABILITY_LIMIT_BYTES_PER_SECOND)
    ).replace(
        "__RELIABILITY_ATTEMPTS__", str(RUNNER_RELIABILITY_ATTEMPTS)
    ).replace(
        "__RELIABILITY_FAILURE_LIMIT__", str(RUNNER_RELIABILITY_FAILURE_LIMIT)
    ).replace(
        "__RELIABILITY_TIMEOUT_SECONDS__", str(RUNNER_RELIABILITY_TIMEOUT_SECONDS)
    ).replace(
        "__LEASE_TIMEOUT_SECONDS__", str(RUNNER_LEASE_TIMEOUT_SECONDS)
    )
