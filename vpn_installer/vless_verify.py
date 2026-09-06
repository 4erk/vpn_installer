from __future__ import annotations

import json
import shlex
import textwrap
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlparse


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
    "https://vk.ru/",
    "https://chatgpt.com/",
)
THROUGHPUT_SOURCE_URLS = (
    "https://fsn1-speed.hetzner.com/100MB.bin",
    "https://nbg1-speed.hetzner.com/100MB.bin",
    "https://speed.cloudflare.com/__down?bytes=50000000",
)
THROUGHPUT_ATTEMPT_SECONDS = 10
THROUGHPUT_SUSTAINED_FLOOR_BYTES_PER_SECOND = 1_250_000
THROUGHPUT_MAX_GAP_SECONDS = 2.0


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
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    allowed = {"security", "sni", "pbk", "sid", "fp", "type", "flow"}
    keys = [key for key, _value in pairs]
    if set(keys) != allowed or len(keys) != len(allowed):
        raise ValueError("VLESS URI parameters must match the canonical contract exactly")
    query = dict(pairs)
    if query.get("security") != "reality" or query.get("type") != "tcp":
        raise ValueError("VLESS URI must use Reality over TCP")
    required = {key: query.get(key, "") for key in ("sni", "pbk", "sid", "fp", "flow")}
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
        "inbounds": [
            {"type": "mixed", "listen": "127.0.0.1", "listen_port": listen_port, "tag": "verify-in"},
            {
                "type": "direct",
                "tag": "verify-dns-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port + 1,
                "network": "udp",
                "override_address": "1.1.1.1",
                "override_port": 53,
            },
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "ru-gateway",
                "server": uri.host,
                "server_port": uri.port,
                "uuid": uri.uuid,
                "flow": uri.flow,
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


def render_live_route_probe(*, listen_port: int, dns_listen_port: int, listen_host: str = "127.0.0.1") -> str:
    """Return a stdlib-only direct UDP DNS and SOCKS private-route probe."""
    return textwrap.dedent(
        f"""\
        import json
        import socket
        import struct
        import time

        def receive_exact(sock, size):
            data = b""
            while len(data) < size:
                chunk = sock.recv(size - len(data))
                if not chunk:
                    raise RuntimeError("unexpected SOCKS EOF")
                data += chunk
            return data

        def dns_query(name, query_type, transaction_id):
            labels = name.split(".")
            question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\\x00"
            return struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", query_type, 1)

        def dns_name(packet, offset):
            labels = []
            next_offset = None
            visited = set()
            while True:
                if offset >= len(packet):
                    raise RuntimeError("truncated DNS name")
                length = packet[offset]
                if length & 0xC0 == 0xC0:
                    if offset + 1 >= len(packet):
                        raise RuntimeError("truncated DNS compression pointer")
                    pointer = ((length & 0x3F) << 8) | packet[offset + 1]
                    if pointer in visited or pointer >= len(packet):
                        raise RuntimeError("invalid DNS compression pointer")
                    visited.add(pointer)
                    if next_offset is None:
                        next_offset = offset + 2
                    offset = pointer
                    continue
                if length & 0xC0:
                    raise RuntimeError("invalid DNS label length")
                offset += 1
                if length == 0:
                    return ".".join(labels).lower(), next_offset if next_offset is not None else offset
                if length > 63 or offset + length > len(packet):
                    raise RuntimeError("truncated DNS label")
                try:
                    labels.append(packet[offset:offset + length].decode("ascii"))
                except UnicodeDecodeError as exc:
                    raise RuntimeError("non-ASCII DNS label") from exc
                offset += length

        def validate_dns_response(packet, expected_name, expected_type, expected_transaction_id):
            if len(packet) < 12:
                raise RuntimeError("truncated DNS response")
            transaction_id, flags, question_count, answer_count, _authority_count, _additional_count = struct.unpack("!HHHHHH", packet[:12])
            if transaction_id != expected_transaction_id:
                raise RuntimeError("DNS transaction mismatch")
            if not flags & 0x8000:
                raise RuntimeError("DNS QR bit is not set")
            if flags & 0x0200:
                raise RuntimeError("truncated DNS response")
            rcode = flags & 0x000F
            if rcode != 0:
                raise RuntimeError(f"DNS RCODE is {{rcode}}")
            if question_count != 1:
                raise RuntimeError(f"unexpected DNS question count: {{question_count}}")
            offset = 12
            question_name, offset = dns_name(packet, offset)
            if offset + 4 > len(packet):
                raise RuntimeError("truncated DNS question")
            question_type, question_class = struct.unpack("!HH", packet[offset:offset + 4])
            offset += 4
            if question_name != expected_name or question_type != expected_type or question_class != 1:
                raise RuntimeError("DNS question mismatch")
            expected_data_length = {{1: 4, 28: 16}}[expected_type]
            matching_answers = 0
            for _ in range(answer_count):
                answer_name, offset = dns_name(packet, offset)
                if offset + 10 > len(packet):
                    raise RuntimeError("truncated DNS answer")
                answer_type, answer_class, _ttl, data_length = struct.unpack("!HHIH", packet[offset:offset + 10])
                offset += 10
                if offset + data_length > len(packet):
                    raise RuntimeError("truncated DNS answer data")
                if answer_name == expected_name and answer_type == expected_type and answer_class == 1 and data_length == expected_data_length:
                    matching_answers += 1
                offset += data_length
            if answer_count == 0 or matching_answers == 0:
                raise RuntimeError(f"DNS response has no matching type {{expected_type}} answer")
            return {{
                "verdict": "verified",
                "qr": True,
                "rcode": rcode,
                "question": {{"name": question_name, "type": question_type, "class": question_class}},
                "answer_count": answer_count,
                "matching_answers": matching_answers,
            }}

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

        def private_connect_result(address, port):
            control = socket.create_connection(({listen_host!r}, {listen_port}), timeout=2)
            try:
                control.sendall(b"\\x05\\x01\\x00")
                if receive_exact(control, 2) != b"\\x05\\x00":
                    raise RuntimeError("SOCKS authentication failed")
                control.sendall(b"\\x05\\x01\\x00\\x01" + socket.inet_aton(address) + struct.pack("!H", port))
                status, _bound_address, _bound_port = socks_reply(control)
                if status == 2:
                    return {{
                        "verdict": "verified",
                        "ok": True,
                        "evidence": "socks-reply-reject",
                        "socks_reply_status": status,
                    }}
                if status != 0:
                    return {{
                        "verdict": "inconclusive",
                        "ok": False,
                        "evidence": "socks-non-policy-error",
                        "socks_reply_status": status,
                    }}
                control.sendall(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                if control.recv(1) == b"":
                    return {{
                        "verdict": "inconclusive",
                        "ok": False,
                        "evidence": "socks-success-eof",
                        "correlation_required": True,
                    }}
                return {{
                    "verdict": "failed",
                    "ok": False,
                    "evidence": "private-target-returned-data",
                }}
            finally:
                control.close()

        dns_queries = {{}}
        answer_bytes = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(2)
            for label, query_type, transaction_id in (("A", 1, 0x1122), ("AAAA", 28, 0x1123)):
                request = dns_query("example.com", query_type, transaction_id)
                expected_transaction = struct.pack("!H", transaction_id)
                dns_payload = None
                for attempt in range(2):
                    udp.sendto(request, ({listen_host!r}, {dns_listen_port}))
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        udp.settimeout(max(0.001, deadline - time.monotonic()))
                        try:
                            candidate, _peer = udp.recvfrom(4096)
                        except TimeoutError:
                            break
                        if candidate[:2] == expected_transaction:
                            dns_payload = candidate
                            break
                    if dns_payload is not None:
                        break
                if dns_payload is None:
                    raise TimeoutError(f"DNS {{label}} response timed out")
                answer_bytes += len(dns_payload)
                dns_queries[label] = validate_dns_response(
                    dns_payload,
                    "example.com",
                    query_type,
                    transaction_id,
                )
        dns_result = {{**dns_queries["A"], "queries": dns_queries}}
        private_targets = []
        for address, port in (("10.0.0.1", 80), ("172.19.0.2", 853)):
            started = time.monotonic()
            try:
                target_result = private_connect_result(address, port)
            except Exception as exc:
                target_result = {{"verdict": "failed", "ok": False, "evidence": "probe-error", "error": str(exc)[:160]}}
            private_targets.append({{
                "target": f"{{address}}:{{port}}",
                "elapsed_seconds": round(time.monotonic() - started, 3),
                **target_result,
            }})
        private_verdict = "verified"
        if any(item["verdict"] == "failed" for item in private_targets):
            private_verdict = "failed"
        elif any(item["verdict"] != "verified" for item in private_targets):
            private_verdict = "inconclusive"
        print(json.dumps({{
            "ok": True,
            "dns": dns_result,
            "answer_bytes": answer_bytes,
            "private_reject": {{
                "verdict": private_verdict,
                "ok": private_verdict == "verified",
                "targets": private_targets,
            }},
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

    The optional throughput phase measures the whole requested window. Peak
    capacity remains diagnostic; release semantics are driven by sustained
    goodput and the longest interval without transfer progress.
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
sing_box_bin=/etc/vpn-stack/current/bin/sing-box
if [[ ! -x "$sing_box_bin" ]]; then
    sing_box_bin=$(command -v sing-box 2>/dev/null || true)
fi
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
observer_pid=""
curl_pid=""
reliability_results_path="$work_dir/reliability-results.tsv"
reliability_error_path="$work_dir/reliability-error.txt"
throughput_payload_path="$work_dir/throughput-payload.bin"
: >"$reliability_results_path"
: >"$reliability_error_path"

exec 9>"$lock_path"
if ! flock -n 9; then
    printf 'vpn-vless-runner phase=failed:runner-busy elapsed_s=0\n' >&2
    exit 1
fi

event() {
    printf 'vpn-vless-runner phase=%s elapsed_s=%s\n' "$1" "$(( ($(date +%s%N) - runner_started_ns) / 1000000000 ))" >&2
}

format_duration_ns() {
    local duration_ns=$1
    printf '%d.%09d' "$((duration_ns / 1000000000))" "$((duration_ns % 1000000000))"
}

fail() {
    event "failed:$1"
    tail -n 20 runner-curl.log >&2 2>/dev/null || true
    tail -n 20 sing-box.log >&2 2>/dev/null || true
    exit 1
}

stop_observer() {
    [[ -n "${observer_pid:-}" ]] || return 0
    local attempt interrupted=0
    touch "$work_dir/observer.stop"
    for ((attempt = 0; attempt < __SHUTDOWN_POLLS__; attempt++)); do
        kill -0 "$observer_pid" 2>/dev/null || break
        if (( attempt == __SHUTDOWN_POLLS__ / 3 )); then
            interrupted=1
            kill -TERM "$observer_pid" >/dev/null 2>&1 || true
        elif (( attempt == 2 * __SHUTDOWN_POLLS__ / 3 )); then
            kill -KILL "$observer_pid" >/dev/null 2>&1 || true
        fi
        sleep 0.1
    done
    # Reap only an exited child; even SIGKILL need not finish a stuck procfs read.
    if kill -0 "$observer_pid" 2>/dev/null; then
        interrupted=1
    else
        wait "$observer_pid" >/dev/null 2>&1 || interrupted=1
    fi
    if (( interrupted )); then
        printf '%s\n' '{"status":"error","reason":"runner socket observer did not complete normally","flows":[]}' >"$work_dir/runner-sockets.json"
    fi
    observer_pid=""
}

cleanup() {
    stop_observer
    if [[ -n "${watchdog_pid:-}" ]] && kill -0 "$watchdog_pid" 2>/dev/null; then
        kill "$watchdog_pid" >/dev/null 2>&1 || true
        wait "$watchdog_pid" >/dev/null 2>&1 || true
    fi
    if [[ -n "${curl_pid:-}" ]] && kill -0 "$curl_pid" 2>/dev/null; then
        kill "$curl_pid" >/dev/null 2>&1 || true
        wait "$curl_pid" >/dev/null 2>&1 || true
    fi
    rm -f -- "$reliability_results_path" "$reliability_error_path" "$throughput_payload_path"
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
if [[ ! -x "$sing_box_bin" ]]; then
    fail sing-box-missing
fi
if ! "$sing_box_bin" check -c "$config_path" >sing-box.log 2>&1; then
    fail sing-box-check
fi
"$sing_box_bin" run -c "$config_path" >sing-box.log 2>&1 &
pid=$!
python3 - "$pid" "$config_path" "$work_dir/observer.stop" >"$work_dir/runner-sockets.json" <<'OBSERVER_PY' &
__SOCKET_OBSERVER__
OBSERVER_PY
observer_pid=$!
sleep __STARTUP_SECONDS__
if ! kill -0 "$pid" 2>/dev/null; then
    fail sing-box-start
fi

event ru-identity
if ! ru_ip=$(curl -4fsS --proxy "$proxy" --connect-timeout 5 --max-time __HTTP_TIMEOUT_SECONDS__ https://ipv4-internet.yandex.net/api/v0/ip 2>>runner-curl.log | tr -d '"[:space:]'); then
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
private_reject = payload.get("private_reject", {})
raise SystemExit(0 if private_reject.get("verdict") in {"verified", "inconclusive", "failed"} else 1)
PY
    fail private-reject-result
fi
event ipv6-literal
if ! ipv6_literal=$(curl -ksS -o /dev/null -w '%{http_code}' --proxy "$proxy" --connect-timeout 5 --max-time __HTTP_TIMEOUT_SECONDS__ https://[2606:4700:4700::1111]/cdn-cgi/trace 2>>runner-curl.log); then
    fail ipv6-literal
fi

event first-load-reliability
reliability_attempts=0
reliability_failures=0
while (( reliability_attempts < __RELIABILITY_ATTEMPTS__ )); do
    reliability_url=${reliability_urls[$((reliability_attempts % ${#reliability_urls[@]}))]}
    reliability_attempts=$((reliability_attempts + 1))
    : >"$reliability_error_path"
    probe_output=$(curl -LsS -o /dev/null -w '%{http_code}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{remote_ip}' --proxy "$proxy" --connect-timeout 3 --max-time __RELIABILITY_TIMEOUT_SECONDS__ "$reliability_url" 2>"$reliability_error_path")
    probe_status=$?
    IFS='|' read -r probe_code probe_namelookup probe_connect probe_appconnect probe_starttransfer probe_seconds probe_remote_ip <<<"$probe_output"
    probe_error=$(tr '\t\r\n' '   ' <"$reliability_error_path" | tail -c 500)
    cat "$reliability_error_path" >>runner-curl.log
    if (( probe_status != 0 )) || [[ ! "$probe_code" =~ ^[1-5][0-9][0-9]$ ]] || [[ ! "$probe_seconds" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        printf '%s\t0\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$reliability_url" "$probe_status" "$probe_code" "$probe_namelookup" "$probe_connect" "$probe_appconnect" "$probe_starttransfer" "$probe_seconds" "$probe_remote_ip" "$probe_error" >>"$reliability_results_path"
        reliability_failures=$((reliability_failures + 1))
        if (( reliability_failures >= __RELIABILITY_FAILURE_LIMIT__ )); then
            break
        fi
        continue
    fi
    printf '%s\t1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$reliability_url" "$probe_status" "$probe_code" "$probe_namelookup" "$probe_connect" "$probe_appconnect" "$probe_starttransfer" "$probe_seconds" "$probe_remote_ip" "$probe_error" >>"$reliability_results_path"
done

throughput_bytes=0
throughput_attempts=0
throughput_failures=0
throughput_source_failures=0
throughput_runs=0
throughput_start_ns=0
throughput_end_ns=0
throughput_max_gap_ns=0
if (( throughput_seconds > 0 )); then
    event throughput-start
    throughput_start_ns=$(date +%s%N)
    throughput_deadline_ns=$((throughput_start_ns + throughput_seconds * 1000000000))
    while :; do
        now_ns=$(date +%s%N)
        remaining_ns=$((throughput_deadline_ns - now_ns))
        (( remaining_ns > 0 )) || break
        remaining_seconds=$(((remaining_ns + 999999999) / 1000000000))
        attempt_index=$throughput_runs
        throughput_runs=$((throughput_runs + 1))
        source_index=$((attempt_index % ${#throughput_urls[@]}))
        throughput_url=${throughput_urls[$source_index]}
        attempt_budget_ns=$remaining_ns
        if (( attempt_budget_ns > __THROUGHPUT_ATTEMPT_SECONDS__ * 1000000000 )); then
            attempt_budget_ns=$((__THROUGHPUT_ATTEMPT_SECONDS__ * 1000000000))
        fi
        attempt_seconds=$(format_duration_ns "$attempt_budget_ns")
        event "throughput-attempt-$attempt_index-source-$source_index-remaining-$remaining_seconds"
        attempt_start_ns=$now_ns
        : >"$throughput_payload_path"
        timeout --foreground --signal=TERM --kill-after=__CURL_WATCHDOG_KILL_SECONDS__s "${attempt_seconds}s" \
            curl -4fsS --proxy "$proxy" --connect-timeout 5 -o "$throughput_payload_path" "$throughput_url" 2>>runner-curl.log &
        curl_pid=$!
        observed_bytes=0
        attempt_last_progress_ns=0
        while kill -0 "$curl_pid" 2>/dev/null; do
            curl_state=$(ps -o stat= -p "$curl_pid" 2>/dev/null | tr -d '[:space:]')
            [[ -n "$curl_state" && "${curl_state:0:1}" != "Z" ]] || break
            sleep 0.25
            sample_ns=$(date +%s%N)
            sample_bytes=$(stat -c %s -- "$throughput_payload_path" 2>/dev/null || printf '0')
            [[ "$sample_bytes" =~ ^[0-9]+$ ]] || sample_bytes=0
            if (( sample_bytes > observed_bytes )); then
                if (( attempt_last_progress_ns > 0 )); then
                    progress_gap_ns=$((sample_ns - attempt_last_progress_ns))
                    (( progress_gap_ns > throughput_max_gap_ns )) && throughput_max_gap_ns=$progress_gap_ns
                fi
                attempt_last_progress_ns=$sample_ns
                observed_bytes=$sample_bytes
            elif (( attempt_last_progress_ns > 0 )); then
                current_gap_ns=$((sample_ns - attempt_last_progress_ns))
                (( current_gap_ns > throughput_max_gap_ns )) && throughput_max_gap_ns=$current_gap_ns
            fi
        done
        wait "$curl_pid"
        curl_status=$?
        curl_pid=""
        now_ns=$(date +%s%N)
        curl_output=$(stat -c %s -- "$throughput_payload_path" 2>/dev/null || printf '0')
        metrics_valid=1
        if [[ ! "$curl_output" =~ ^[0-9]+$ ]]; then
            metrics_valid=0
            curl_output=0
        fi
        if (( curl_output > observed_bytes )); then
            if (( attempt_last_progress_ns > 0 )); then
                progress_gap_ns=$((now_ns - attempt_last_progress_ns))
                (( progress_gap_ns > throughput_max_gap_ns )) && throughput_max_gap_ns=$progress_gap_ns
            fi
            attempt_last_progress_ns=$now_ns
        fi
        rm -f -- "$throughput_payload_path"
        if (( metrics_valid == 0 )); then
            throughput_source_failures=$((throughput_source_failures + 1))
            throughput_source_failure_counts[$source_index]=$((throughput_source_failure_counts[$source_index] + 1))
            event throughput-invalid-metrics
            continue
        fi
        capacity_source_ns[$source_index]=$((capacity_source_ns[$source_index] + now_ns - attempt_start_ns))
        if (( curl_output > 0 )); then
            throughput_bytes=$((throughput_bytes + curl_output))
            throughput_attempts=$((throughput_attempts + 1))
            capacity_source_bytes[$source_index]=$((capacity_source_bytes[$source_index] + curl_output))
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
stop_observer

python3 - "$ru_ip" "$foreign_ip" "$github" "$google" "$throughput_bytes" "$throughput_start_ns" "$throughput_end_ns" "$throughput_attempts" "$throughput_failures" "$throughput_source_failures" "$throughput_sources_json" "$capacity_source_bytes_csv" "$capacity_source_ns_csv" "$throughput_source_failure_counts_csv" "$throughput_max_gap_ns" "$udp_dns" "$ipv6_literal" "$reliability_results_path" <<'PY'
import json
import sys
from pathlib import Path

try:
    runner_sockets = json.loads(Path("runner-sockets.json").read_text(encoding="utf-8"))
except (OSError, ValueError):
    runner_sockets = {"status": "error", "reason": "runner socket observer output is unavailable", "flows": []}

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
successful_sources = sum(item["bytes_downloaded"] > 0 and item["duration_seconds"] > 0 for item in source_metrics)
throughput = {
    "bytes_per_second": bytes_downloaded / duration_seconds if duration_seconds else 0.0,
    "sustained_bytes_per_second": bytes_downloaded / duration_seconds if duration_seconds else 0.0,
    "capacity_bytes_per_second": max((item["bytes_per_second"] for item in source_metrics), default=0.0),
    "capacity_duration_seconds": sum(item["duration_seconds"] for item in source_metrics),
    "max_gap_seconds": int(sys.argv[15]) / 1_000_000_000,
    "duration_seconds": duration_seconds,
    "bytes_downloaded": bytes_downloaded,
    "attempts": int(sys.argv[8]),
    "failures": int(sys.argv[9]),
    "source_failures": int(sys.argv[10]),
    "successful_sources": successful_sources,
    "required_successful_sources": min(2, len(sources)),
    "sources": sources,
    "source_metrics": source_metrics,
}
reliability_probes = []


def timing(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def incomplete_phase(probe):
    if probe["ok"]:
        return "completed"
    if probe["connect_seconds"] <= 0:
        return "proxy-connect-not-completed"
    if probe["tls_seconds"] <= 0:
        return "upstream-tls-not-completed"
    if probe["starttransfer_seconds"] <= 0:
        return "first-byte-not-received"
    return "http-or-transfer-failed"


for line in Path(sys.argv[18]).read_text(encoding="utf-8").splitlines():
    fields = line.split("\t", 10)
    if len(fields) != 11:
        continue
    url, ok, curl_status, http_status, namelookup, connect, appconnect, starttransfer, total, remote_ip, error = fields
    probe = {
        "url": url,
        "ok": ok == "1",
        "curl_status": int(curl_status),
        "http_status": http_status,
        "namelookup_seconds": timing(namelookup),
        "connect_seconds": timing(connect),
        "tls_seconds": timing(appconnect),
        "starttransfer_seconds": timing(starttransfer),
        "total_seconds": timing(total),
        "remote_ip": remote_ip,
        "error": error,
    }
    probe["incomplete_phase"] = incomplete_phase(probe)
    reliability_probes.append(probe)
reliability_successes = sum(probe["ok"] for probe in reliability_probes)
successful_times = [probe["total_seconds"] for probe in reliability_probes if probe["ok"]]
required_targets = list(dict.fromkeys(probe["url"] for probe in reliability_probes))
reliability = {
    "attempts": len(reliability_probes),
    "successes": reliability_successes,
    "failures": len(reliability_probes) - reliability_successes,
    "average_total_seconds": sum(successful_times) / len(successful_times) if successful_times else 0.0,
    "max_total_seconds": max(successful_times, default=0.0),
    "required_targets": required_targets,
    "probes": reliability_probes,
}
print(json.dumps({
    "ru_egress_ip": sys.argv[1],
    "foreign_egress_ip": sys.argv[2],
    "github_status": sys.argv[3],
    "google_status": sys.argv[4],
    "throughput": throughput,
    "udp_dns": json.loads(sys.argv[16]),
    "ipv6_literal_status": sys.argv[17],
    "first_load_reliability": reliability,
    "runner_sockets": runner_sockets,
}))
PY
'''
    return textwrap.dedent(template).lstrip().replace(
        "__SOCKET_OBSERVER__", Path(__file__).with_name("runner_observation.py").read_text(encoding="utf-8")
    ).replace("__LISTEN_PORT__", str(listen_port)).replace(
        "__THROUGHPUT_URLS__", " ".join(shlex.quote(url) for url in throughput_urls)
    ).replace(
        "__RELIABILITY_URLS__", " ".join(shlex.quote(url) for url in reliability_urls)
    ).replace(
        "__THROUGHPUT_SOURCES_JSON__", shlex.quote(json.dumps(list(throughput_urls), separators=(",", ":")))
    ).replace("__HTTP_TIMEOUT_SECONDS__", str(RUNNER_HTTP_TIMEOUT_SECONDS)).replace(
        "__STARTUP_SECONDS__", str(RUNNER_STARTUP_SECONDS)
    ).replace("__SHUTDOWN_POLLS__", str(RUNNER_SHUTDOWN_SECONDS * 10)).replace(
        "__CURL_WATCHDOG_KILL_SECONDS__", str(RUNNER_CURL_WATCHDOG_KILL_SECONDS)
    ).replace(
        "__THROUGHPUT_ATTEMPT_SECONDS__", str(THROUGHPUT_ATTEMPT_SECONDS)
    ).replace(
        "__RELIABILITY_ATTEMPTS__", str(RUNNER_RELIABILITY_ATTEMPTS)
    ).replace(
        "__RELIABILITY_FAILURE_LIMIT__", str(RUNNER_RELIABILITY_FAILURE_LIMIT)
    ).replace(
        "__RELIABILITY_TIMEOUT_SECONDS__", str(RUNNER_RELIABILITY_TIMEOUT_SECONDS)
    ).replace(
        "__LEASE_TIMEOUT_SECONDS__", str(RUNNER_LEASE_TIMEOUT_SECONDS)
    )
