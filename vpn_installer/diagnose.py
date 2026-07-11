from __future__ import annotations

import time
from pathlib import Path
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from .common import OUT_DIR, print_header, warn, write_text
from .config import load_existing_deployment_env
from .log_classifier import BUCKETS, summarize_lines
from .localnet import local_route_to_server, route_uses_self_tunnel
from .models import ROLE_FOREIGN, ROLE_RU, AppError, RemoteTarget
from .prompts import select_existing_deployment
from .remote import ssh_capture
from .state import load_state
from .client_artifacts import client_artifact_paths
from .health import current_wg_interface
from .roles import requested_roles
from .targets import build_target
from .workflows import prepare_remote_session

_SOURCE_IP_RE = re.compile(r"^[0-9A-Fa-f:.]+$")
PATH_DIAGNOSE_COMMAND_TIMEOUT = 180


def _diagnostic_run_dir(deployment_name: str) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return OUT_DIR / "diagnostics" / f"{stamp}-{deployment_name}"


def _path_script(role: str, wg_interface: str) -> str:
    peer_public_key = "FOREIGN_PUBLIC_IP" if role == ROLE_RU else "RU_PUBLIC_IP"
    peer_wg_ip = "10.74.0.2" if role == ROLE_RU else "10.74.0.1"
    return f"""\
set +e
export LC_ALL=C

section() {{
  printf '\\n===== %s =====\\n' "$1"
}}

env_value() {{
  local key="$1"
  if [[ -r /etc/vpn-stack/deployment.env ]]; then
    awk -F= -v key="${{key}}" '$1 == key {{ sub(/^[^=]*=/, ""); gsub(/^"/, ""); gsub(/"$/, ""); print; exit }}' /etc/vpn-stack/deployment.env
  fi
}}

journal_since_with_install() {{
  local lookback_seconds="$1"
  local since="-${{lookback_seconds}} seconds"
  local installed_at="" now_epoch="" installed_epoch="" lookback_epoch="" post_install_epoch=""
  if [[ -r /etc/vpn-stack/installed_at ]] && command -v date >/dev/null 2>&1; then
    installed_at="$(tr -d '\\r\\n' </etc/vpn-stack/installed_at)"
    now_epoch="$(date +%s 2>/dev/null || true)"
    installed_epoch="$(date -d "${{installed_at}}" +%s 2>/dev/null || true)"
    if [[ "${{now_epoch}}" =~ ^[0-9]+$ && "${{installed_epoch}}" =~ ^[0-9]+$ ]]; then
      lookback_epoch=$((now_epoch - lookback_seconds))
      post_install_epoch=$((installed_epoch + 10))
      if (( post_install_epoch > lookback_epoch )); then
        since="@${{post_install_epoch}}"
      fi
    fi
  fi
  printf "%s\\n" "${{since}}"
}}

role="$(cat /etc/vpn-stack/role 2>/dev/null || true)"
default_iface="$(ip route show default 2>/dev/null | awk '/default/ {{print $5; exit}}')"
gateway="$(ip route show default 2>/dev/null | awk '/default/ {{print $3; exit}}')"
peer_public="$(env_value {peer_public_key})"
health_urls="$(env_value HEALTH_THROUGHPUT_URLS)"
health_url="${{health_urls%% *}}"
if [[ -z "${{health_url}}" ]]; then health_url="https://cachefly.cachefly.net/1mb.test"; fi
recent_since="$(journal_since_with_install 1800)"

section identity
printf 'date=%s\\n' "$(date -Is 2>/dev/null)"
printf 'hostname=%s\\n' "$(hostname -f 2>/dev/null || hostname)"
printf 'role=%s\\n' "${{role}}"
printf 'default_iface=%s\\n' "${{default_iface}}"
printf 'gateway=%s\\n' "${{gateway}}"
printf 'wg_interface=%s\\n' "{wg_interface}"

section tools
for command in curl ping mtr iperf3 tc ethtool nft wg ss; do
  printf '%s=' "${{command}}"
  command -v "${{command}}" || true
done

section services
for unit in ssh.service ssh.socket nftables "wg-quick@{wg_interface}" sing-box vpn-stack-sync.timer vpn-stack-health.timer vpn-stack-health.service vpn-stack-guard.timer vpn-stack-guard.service; do
  printf '%s ' "${{unit}}"
  systemctl is-active "${{unit}}" 2>/dev/null || true
done

section interfaces
ip -br addr
for iface in "${{default_iface}}" "{wg_interface}"; do
  [[ -n "${{iface}}" ]] || continue
  echo "--- $iface"
  ip -s link show dev "${{iface}}" 2>/dev/null
  tc -s qdisc show dev "${{iface}}" 2>/dev/null
  ethtool -k "${{iface}}" 2>/dev/null | grep -E 'generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|udp-fragmentation-offload|rx-checksumming|tx-checksumming' || true
done

section routes
ip route show table main
ip rule show
ip route show table 51820 2>/dev/null || true

section sysctl
for key in net.core.default_qdisc net.ipv4.tcp_congestion_control net.ipv4.tcp_mtu_probing net.core.netdev_max_backlog net.core.rmem_max net.core.wmem_max net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min net.ipv4.ip_forward net.ipv6.conf.all.forwarding; do
  sysctl -n "${{key}}" 2>/dev/null | sed "s/^/${{key}}=/"
done

section wireguard
wg show {wg_interface} 2>/dev/null || true

section health_state
cat /var/lib/vpn-stack/health-state.env 2>/dev/null || true

section guard_state
cat /var/lib/vpn-stack/guard-state.env 2>/dev/null || true

section abuse_set
nft list set inet vpnstack abuse_ipv4 2>/dev/null || true

ping_loss() {{
  local host="$1"
  local label="$2"
  [[ -n "${{host}}" ]] || return 0
  echo "--- $label $host"
  timeout 8 ping -4 -c 5 -W 1 "${{host}}" 2>&1 | tail -n 4
}}

section ping
ping_loss "${{gateway}}" gateway
ping_loss "${{peer_public}}" peer_public
ping_loss "{peer_wg_ip}" peer_wg
ping_loss "1.1.1.1" internet_1_1_1_1

trace_host() {{
  local host="$1"
  local label="$2"
  [[ -n "${{host}}" ]] || return 0
  echo "--- $label $host"
  if command -v mtr >/dev/null 2>&1; then
    timeout 15 mtr -rwzc 8 "${{host}}" 2>&1 | sed -n '1,35p'
  else
    echo "mtr_not_installed"
  fi
}}

section mtr
trace_host "${{gateway}}" gateway
trace_host "${{peer_public}}" peer_public
trace_host "1.1.1.1" internet_1_1_1_1

curl_probe() {{
  local bind_iface="$1"
  local label="$2"
  local url="$3"
  echo "--- $label $url"
  if [[ -n "${{bind_iface}}" ]]; then
    timeout 10 curl -4kLsS --interface "${{bind_iface}}" --connect-timeout 3 --max-time 8 -o /dev/null -w 'code=%{{http_code}} exit=%{{exitcode}} ip=%{{remote_ip}} time=%{{time_total}} speed=%{{speed_download}}\\n' "${{url}}" 2>&1 || true
  else
    timeout 10 curl -4kLsS --connect-timeout 3 --max-time 8 -o /dev/null -w 'code=%{{http_code}} exit=%{{exitcode}} ip=%{{remote_ip}} time=%{{time_total}} speed=%{{speed_download}}\\n' "${{url}}" 2>&1 || true
  fi
}}

section curl
curl_probe "" direct "https://api.ipify.org"
curl_probe "" direct "${{health_url}}"
curl_probe "" direct "https://speed.cloudflare.com/__down?bytes=1000000"
curl_probe "" direct "https://github.com/"
if [[ "${{role}}" == "ru-gateway" ]]; then
  curl_probe "{wg_interface}" wg "https://api.ipify.org"
  curl_probe "{wg_interface}" wg "${{health_url}}"
  curl_probe "{wg_interface}" wg "https://speed.cloudflare.com/__down?bytes=1000000"
  curl_probe "{wg_interface}" wg "https://github.com/"
fi

section recent_health_logs
journalctl -u vpn-stack-health.service --since '-6 hours' --no-pager 2>/dev/null | tail -n 120 || true

section recent_guard_logs
journalctl -u vpn-stack-guard.service --since '-6 hours' --no-pager 2>/dev/null | tail -n 120 || true

section recent_xray_grouped
if [[ "${{role}}" == "ru-gateway" ]]; then
  xray_log="$(journalctl -u vpn-stack-xray.service --since "${{recent_since}}" --no-pager -o cat 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' || true)"
  printf 'window_minutes=30\n'
  printf 'window_since=%s\n' "${{recent_since}}"
  printf 'accepted=%s\n' "$(grep -c 'accepted tcp:' <<<"${{xray_log}}" || true)"
  printf 'errors=%s\n' "$(printf '%s\n' "${{xray_log}}" | grep -Ev 'accepted tcp:disabled[.]invalid' | grep -Eic 'error|failed|timeout|refused|reset|EOF|panic|fatal|denied|processed invalid connection' || true)"
  printf 'invalid_reality=%s\n' "$(grep -c 'REALITY: processed invalid connection' <<<"${{xray_log}}" || true)"
  printf 'disabled_invalid=%s\n' "$(grep -c 'accepted tcp:disabled[.]invalid' <<<"${{xray_log}}" || true)"
  printf 'ipv6_literals=%s\n' "$(grep -Ec 'accepted tcp:\\[[0-9A-Fa-f:.]+\\]:' <<<"${{xray_log}}" || true)"
  printf 'sources='
  printf '%s\n' "${{xray_log}}" |
    sed -n 's/.*from \\([^: ]*\\):[0-9][0-9]* accepted tcp:.*/\\1/p; s/.*REALITY: processed invalid connection from \\([^: ]*\\):.*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\naccepted_destinations='
  printf '%s\n' "${{xray_log}}" |
    sed -n 's/.*accepted tcp:\\([^ ]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nipv6_literal_destinations='
  printf '%s\n' "${{xray_log}}" |
    sed -n 's/.*accepted tcp:\\(\\[[0-9A-Fa-f:.]*\\]:[0-9][0-9]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nlast_error_sample='
  printf '%s\n' "${{xray_log}}" |
    (grep -Ei 'error|failed|timeout|refused|reset|invalid|EOF|panic|fatal|denied|processed invalid connection' || true) |
    tail -n1 |
    tr -d '\r' |
    cut -c1-240
  printf '\n'
fi

section recent_singbox_grouped
if [[ "${{role}}" == "ru-gateway" ]]; then
  singbox_log="$(journalctl -u sing-box --since "${{recent_since}}" --no-pager -o cat 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' || true)"
  printf 'window_minutes=30\n'
  printf 'window_since=%s\n' "${{recent_since}}"
  printf 'blocked=%s\n' "$(grep -c 'outbound/block\\[blocked\\]' <<<"${{singbox_log}}" || true)"
  printf 'mux_closed=%s\n' "$(grep -c 'mux connection closed' <<<"${{singbox_log}}" || true)"
  printf 'eof=%s\n' "$(grep -c 'EOF' <<<"${{singbox_log}}" || true)"
  printf 'dns_failed=%s\n' "$(grep -Ec 'dns: (lookup|exchange) failed' <<<"${{singbox_log}}" || true)"
  printf 'timeout=%s\n' "$(grep -Ec 'i/o timeout|context deadline exceeded' <<<"${{singbox_log}}" || true)"
  printf 'invalid_reality=%s\n' "$(grep -c 'REALITY: processed invalid connection' <<<"${{singbox_log}}" || true)"
  printf 'sources='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*process connection from \\([^: ]*\\):.*/\\1/p; s/.*REALITY: processed invalid connection from \\([^: ]*\\):.*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nblocked_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*open connection to \\([^ ]*\\) using outbound\\/block.*/\\1/p; s/.*blocked packet connection to \\([^ ]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nto_foreign=%s\n' "$(grep -c 'outbound/direct\\[to-foreign\\]: outbound connection to' <<<"${{singbox_log}}" || true)"
  printf 'to_foreign_ip_literal=%s\n' "$(grep -c 'outbound/direct\\[to-foreign-ip-literal\\]: outbound connection to' <<<"${{singbox_log}}" || true)"
  printf 'to_foreign_ipv6_literal=%s\n' "$(grep -c 'outbound/direct\\[to-foreign-ipv6-literal\\]: outbound connection to' <<<"${{singbox_log}}" || true)"
  printf 'direct_ru=%s\n' "$(grep -c 'outbound/direct\\[direct-ru\\]: outbound connection to' <<<"${{singbox_log}}" || true)"
  printf 'ipv6_literals=%s\n' "$(grep -Ec 'inbound connection to \\[[0-9A-Fa-f:.]+\\]:' <<<"${{singbox_log}}" || true)"
  printf 'to_foreign_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*outbound\\/direct\\[to-foreign\\]: outbound connection to \\([^ ]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nto_foreign_ip_literal_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*outbound\\/direct\\[to-foreign-ip-literal\\]: outbound connection to \\([^ ]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nto_foreign_ipv6_literal_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*outbound\\/direct\\[to-foreign-ipv6-literal\\]: outbound connection to \\([^ ]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\ndirect_ru_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*outbound\\/direct\\[direct-ru\\]: outbound connection to \\([^ ]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\ntimeout_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*open connection to \\([^ ]*\\) using outbound\\/direct\\[[^]]*\\].*/\\1/p; s/.*lookup failed for \\([^: ]*\\):.*/\\1/p; s/.*exchange failed for \\([^ ]*\\)\\. IN \\([A-Z0-9][A-Z0-9]*\\):.*/\\1:\\2/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nip_literal_timeout_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*open connection to \\([^ ]*\\) using outbound\\/direct\\[to-foreign-ip-literal\\].*/\\1/p; s/.*open connection to \\([^ ]*\\) using outbound\\/direct\\[to-foreign-ipv6-literal\\].*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nipv6_literal_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*inbound connection to \\(\\[[0-9A-Fa-f:.]*\\]:[0-9][0-9]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nmux_sources='
  printf '%s\n' "${{singbox_log}}" |
    sed -n '/mux connection closed/s/.*process connection from \\([^: ]*\\):.*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\ninbound_destinations='
  printf '%s\n' "${{singbox_log}}" |
    sed -n 's/.*inbound packet connection to \\([^ ]*\\).*/\\1/p; s/.*inbound connection to \\([^ ]*\\).*/\\1/p' |
    sort | uniq -c | sort -nr | head -n 12 |
    awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
  printf '\nlast_error_sample='
  printf '%s\n' "${{singbox_log}}" |
    (grep -E 'outbound/block\\[blocked\\]|mux connection closed|dns: (lookup|exchange) failed|i/o timeout|context deadline exceeded|REALITY: processed invalid connection|FATAL|ERROR|EOF' || true) |
    tail -n1 |
    tr -d '\r' |
    cut -c1-240
  printf '\n'
fi

section recent_singbox_raw
journalctl -u sing-box --since "${{recent_since}}" --no-pager 2>/dev/null | tail -n 240 || true
"""


def _front_script(source_ip: str | None, minutes: int) -> str:
    source = source_ip or ""
    return f"""\
set +e
export LC_ALL=C
SOURCE_IP={source!r}
MINUTES={minutes}
LISTEN_PORT="$(awk -F= '$1 == "RU_LISTEN_PORT" {{ gsub(/^"/, "", $2); gsub(/"$/, "", $2); print $2; exit }}' /etc/vpn-stack/deployment.env 2>/dev/null)"
if [[ -z "${{LISTEN_PORT}}" ]]; then LISTEN_PORT="443"; fi
xray_log="$(journalctl -u vpn-stack-xray.service --since "-${{MINUTES}} minutes" --no-pager -o cat 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' || true)"
guard_log="$(journalctl -u vpn-stack-guard.service --since "-${{MINUTES}} minutes" --no-pager -o cat 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' || true)"
abuse_set="$(nft list set inet vpnstack abuse_ipv4 2>/dev/null || true)"
ss_front="$(ss -Htan "sport = :${{LISTEN_PORT}}" 2>/dev/null || true)"
nft_chain="$(nft -a list chain inet vpnstack input 2>/dev/null || true)"
nft_port_packets() {{
  local verdict="$1"
  printf '%s\\n' "${{nft_chain}}" |
    grep -F "tcp dport ${{LISTEN_PORT}} " |
    grep -F " ${{verdict}}" |
    grep -F " counter " |
    sed -n 's/.* counter packets \\([0-9][0-9]*\\) bytes .*/\\1/p' |
    head -n1 || true
}}

printf 'window_minutes=%s\\n' "${{MINUTES}}"
printf 'listen_port=%s\\n' "${{LISTEN_PORT}}"
printf 'xray_active=%s\\n' "$(systemctl is-active vpn-stack-xray.service 2>/dev/null || true)"
printf 'nftables_active=%s\\n' "$(systemctl is-active nftables 2>/dev/null || true)"
printf 'accepted_total=%s\\n' "$(grep -c 'accepted tcp:' <<<"${{xray_log}}" || true)"
printf 'invalid_reality_total=%s\\n' "$(grep -c 'REALITY: processed invalid connection' <<<"${{xray_log}}" || true)"
printf 'disabled_invalid_total=%s\\n' "$(grep -c 'accepted tcp:disabled[.]invalid' <<<"${{xray_log}}" || true)"
printf 'sources='
printf '%s\\n' "${{xray_log}}" |
  sed -n 's/.*from \\([^: ]*\\):[0-9][0-9]* accepted tcp:.*/\\1/p; s/.*REALITY: processed invalid connection from \\([^: ]*\\):.*/\\1/p' |
  sort | uniq -c | sort -nr | head -n 20 |
  awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
printf '\\n'
printf 'accepted_destinations='
printf '%s\\n' "${{xray_log}}" |
  sed -n 's/.*accepted tcp:\\([^ ]*\\).*/\\1/p' |
  sort | uniq -c | sort -nr | head -n 20 |
  awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
printf '\\n'
printf 'front_socket_states='
printf '%s\\n' "${{ss_front}}" |
  awk '{{print $1}}' |
  sort | uniq -c | sort -nr |
  awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
printf '\\n'
printf 'nft_vless_accept_packets=%s\\n' "$(nft_port_packets accept)"
printf 'nft_vless_drop_packets=%s\\n' "$(nft_port_packets drop)"

if [[ -n "${{SOURCE_IP}}" ]]; then
  printf 'source_ip=%s\\n' "${{SOURCE_IP}}"
  printf 'accepted_from_source=%s\\n' "$(grep -F "from ${{SOURCE_IP}}:" <<<"${{xray_log}}" | grep -c 'accepted tcp:' || true)"
  printf 'invalid_from_source=%s\\n' "$(grep -F "from ${{SOURCE_IP}}:" <<<"${{xray_log}}" | grep -c 'REALITY: processed invalid connection' || true)"
  printf 'disabled_invalid_from_source=%s\\n' "$(grep -F "from ${{SOURCE_IP}}:" <<<"${{xray_log}}" | grep -c 'accepted tcp:disabled.invalid' || true)"
  printf 'guard_blocks_from_source=%s\\n' "$(grep -F "temporary block ${{SOURCE_IP}}" <<<"${{guard_log}}" | wc -l | tr -d ' ')"
  printf 'abuse_set_contains_source=%s\\n' "$(grep -F "${{SOURCE_IP}}" <<<"${{abuse_set}}" >/dev/null && echo 1 || echo 0)"
  printf 'socket_rows_from_source=%s\\n' "$(grep -F "${{SOURCE_IP}}:" <<<"${{ss_front}}" | wc -l | tr -d ' ')"
  printf 'source_recent='
  grep -F "from ${{SOURCE_IP}}:" <<<"${{xray_log}}" | tail -n 8 | tr '\\n' '|' | cut -c1-1200
  printf '\\n'
fi
"""


def _parse_kv_lines(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _int_value(payload: dict[str, str], key: str) -> int:
    try:
        return int(payload.get(key, "0") or "0")
    except ValueError:
        return 0


def _front_verdict(payload: dict[str, str]) -> str:
    if not payload.get("source_ip"):
        return "inconclusive"
    if _int_value(payload, "abuse_set_contains_source") > 0 or _int_value(payload, "guard_blocks_from_source") > 0:
        return "blocked_by_guard"
    if _int_value(payload, "accepted_from_source") > 0:
        return "reached_xray"
    if _int_value(payload, "invalid_from_source") > 0 or _int_value(payload, "disabled_invalid_from_source") > 0:
        return "rejected_by_front"
    if _int_value(payload, "socket_rows_from_source") > 0:
        return "tcp_reached_no_xray_accept"
    return "not_seen_on_server"


def diagnose_front_workflow(deployment: str | None, *, source_ip: str | None = None, minutes: int = 120, non_interactive: bool = False) -> int:
    if source_ip and not _SOURCE_IP_RE.match(source_ip):
        raise AppError(f"Некорректный source IP: {source_ip}")
    if minutes < 5 or minutes > 1440:
        raise AppError("--minutes должен быть в диапазоне 5..1440")
    deployment_name, _env_path, _env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=[ROLE_RU],
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
    )
    target = targets[0]
    report = ssh_capture(target, _front_script(source_ip, minutes), as_root=True)
    output_dir = _diagnostic_run_dir(deployment_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "front-ru-gateway.txt"
    write_text(report_path, report)
    payload = _parse_kv_lines(report)
    verdict = _front_verdict(payload)

    print_header("Front diagnostics")
    print(f"deployment: {deployment_name}")
    print(f"server: {target.ssh_host}:{payload.get('listen_port', '443')}")
    print(f"window_minutes: {payload.get('window_minutes', minutes)}")
    print(f"xray/nftables: {payload.get('xray_active', '-')}/{payload.get('nftables_active', '-')}")
    print(
        "xray totals: "
        f"accepted={payload.get('accepted_total', '0')}, "
        f"invalid_reality={payload.get('invalid_reality_total', '0')}, "
        f"disabled_invalid={payload.get('disabled_invalid_total', '0')}"
    )
    print(f"front socket states: {payload.get('front_socket_states', '-') or '-'}")
    print(f"nft VLESS accept/drop packets: {payload.get('nft_vless_accept_packets', '-') or '-'}/{payload.get('nft_vless_drop_packets', '-') or '0'}")
    print(f"sources: {payload.get('sources', '-') or '-'}")
    if source_ip:
        print(f"source_ip: {source_ip}")
        print(
            "source counters: "
            f"accepted={payload.get('accepted_from_source', '0')}, "
            f"invalid={payload.get('invalid_from_source', '0')}, "
            f"disabled_invalid={payload.get('disabled_invalid_from_source', '0')}, "
            f"guard_blocks={payload.get('guard_blocks_from_source', '0')}, "
            f"abuse_set={payload.get('abuse_set_contains_source', '0')}, "
            f"sockets={payload.get('socket_rows_from_source', '0')}"
        )
        if payload.get("source_recent"):
            print(f"source recent: {payload.get('source_recent')}")
    print(f"verdict: {verdict}")
    if verdict == "reached_xray":
        print("diagnosis: это устройство доходило до Xray и было принято; если сайты не открываются, проблема после front: routing/DNS/egress/client mode.")
    elif verdict == "rejected_by_front":
        print("diagnosis: устройство дошло до front, но Xray отверг handshake; проверяй актуальность UUID/publicKey/shortId/SNI/fingerprint.")
    elif verdict == "blocked_by_guard":
        print("diagnosis: source IP попал в guard/nft abuse set; это серверный front-block.")
    elif verdict == "tcp_reached_no_xray_accept":
        print("diagnosis: TCP до 443 виден, но Xray accept не появился; это зона listener/backlog/handshake до application accept.")
    elif verdict == "not_seen_on_server":
        print("diagnosis: за окно source IP не виден на RU front; сервер не может принять соединение, которое до него не дошло.")
    else:
        print("diagnosis: без source IP конкретного устройства front-gate не может доказать reached/not_seen; показаны общие источники.")
    print(f"report: {report_path}")
    return 1 if verdict in {"blocked_by_guard", "rejected_by_front", "tcp_reached_no_xray_accept", "not_seen_on_server"} else 0


def _cleanup_iperf_rules(foreign: RemoteTarget) -> None:
    ssh_capture(
        foreign,
        "nft -a list chain inet vpnstack input 2>/dev/null | "
        "awk '/vpnstack-diag-iperf/ {print $NF}' | "
        "while read -r handle; do nft delete rule inet vpnstack input handle \"$handle\" 2>/dev/null || true; done; "
        "systemctl stop vpnstack-iperf3.service >/dev/null 2>&1 || true; "
        "systemctl reset-failed vpnstack-iperf3.service >/dev/null 2>&1 || true",
        as_root=True,
    )


def _run_iperf_smoke(output_dir: Path, targets: list[RemoteTarget]) -> None:
    target_map = {target.role: target for target in targets}
    if ROLE_RU not in target_map or ROLE_FOREIGN not in target_map:
        warn("iperf-проба требует обе роли, пропускаю.")
        return
    ru = target_map[ROLE_RU]
    foreign = target_map[ROLE_FOREIGN]
    tests = [
        ("tcp-ru-to-foreign", "-t 8 -P 4"),
        ("tcp-foreign-to-ru", "-t 8 -P 4 -R"),
        ("udp-ru-to-foreign-10m", "-u -b 10M -l 1200 -t 8"),
        ("udp-foreign-to-ru-10m", "-u -b 10M -l 1200 -t 8 -R"),
    ]
    try:
        _cleanup_iperf_rules(foreign)
        ssh_capture(
            foreign,
            "nft add rule inet vpnstack input iifname wg0 tcp dport 5201 counter accept comment vpnstack-diag-iperf; "
            "nft add rule inet vpnstack input iifname wg0 udp dport 5201 counter accept comment vpnstack-diag-iperf",
            as_root=True,
        )
        for name, args in tests:
            ssh_capture(
                foreign,
                "systemctl stop vpnstack-iperf3.service >/dev/null 2>&1 || true; "
                "systemctl reset-failed vpnstack-iperf3.service >/dev/null 2>&1 || true; "
                "rm -f /tmp/vpnstack-iperf3.log; "
                "systemd-run --unit=vpnstack-iperf3 --property=RuntimeMaxSec=35 "
                "--property=StandardOutput=append:/tmp/vpnstack-iperf3.log "
                "--property=StandardError=append:/tmp/vpnstack-iperf3.log "
                "/usr/bin/iperf3 -s -B 10.74.0.2 -p 5201 --one-off >/dev/null",
                as_root=True,
            )
            time.sleep(1.0)
            client = ssh_capture(
                ru,
                f"timeout 35 iperf3 -c 10.74.0.2 -B 10.74.0.1 -p 5201 {args} 2>&1 || true",
                as_root=True,
            )
            server = ssh_capture(foreign, "cat /tmp/vpnstack-iperf3.log 2>/dev/null || true", as_root=True)
            write_text(output_dir / f"iperf-{name}.txt", f"## client\n{client}\n## server\n{server}\n")
    finally:
        _cleanup_iperf_rules(foreign)


def diagnose_path_workflow(deployment: str | None, role: str, *, iperf: bool = False, non_interactive: bool = False) -> int:
    roles = requested_roles(role)
    deployment_name, _env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
    )
    output_dir = _diagnostic_run_dir(deployment_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    wg_interface = current_wg_interface(env)

    print_header("Path diagnostics")
    with ThreadPoolExecutor(max_workers=max(1, len(targets))) as executor:
        future_to_target = {}
        for target in targets:
            print(f"{target.label}: собираю диагностику")
            future_to_target[
                executor.submit(
                    ssh_capture,
                    target,
                    _path_script(target.role, wg_interface),
                    as_root=True,
                    command_timeout=PATH_DIAGNOSE_COMMAND_TIMEOUT,
                )
            ] = target
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                report = future.result()
            except AppError as exc:
                report = f"diagnose_error={exc}\n"
                warn(f"{target.label}: диагностика завершилась неполно: {exc}")
            write_text(output_dir / f"{target.role}.txt", report)

    if iperf:
        print("Запускаю bounded iperf smoke через wg0.")
        _run_iperf_smoke(output_dir, targets)

    if not any(output_dir.iterdir()):
        raise AppError("Диагностика не собрала ни одного файла.")
    print(f"Диагностика сохранена: {output_dir}")
    return 0


def _print_nonzero_bucket_summary(summary: dict[str, object]) -> None:
    counts = summary["counts"]
    top_destinations = summary["top_destinations"]
    samples = summary["samples"]
    assert isinstance(counts, dict)
    assert isinstance(top_destinations, dict)
    assert isinstance(samples, dict)
    for bucket in BUCKETS:
        count = int(counts.get(bucket, 0))
        if count <= 0:
            continue
        print(f"{bucket}: {count}")
        destinations = top_destinations.get(bucket)
        if destinations:
            rendered = ", ".join(f"{destination}={value}" for destination, value in dict(destinations).items())
            print(f"  top: {rendered}")
        sample = samples.get(bucket)
        if sample:
            print(f"  sample: {sample}")


def diagnose_client_log_workflow(log_path: str, deployment: str | None = None, role: str = "all") -> int:
    path = Path(log_path)
    if not path.is_file():
        raise AppError(f"Файл лога не найден: {path}")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    summary = summarize_lines(lines)
    print_header("Client log diagnostics")
    print(f"log: {path}")
    print(f"lines: {len(lines)}")
    _print_nonzero_bucket_summary(summary)

    counts = summary["counts"]
    assert isinstance(counts, dict)
    if int(counts.get("client_front_connect_failed", 0)) > 0:
        print(
            "diagnosis: клиент не смог подключиться к public VPN endpoint до входа в Xray; "
            "DNS и сайты после этого могут падать вторично."
        )

    if deployment is None:
        return 0

    deployment_name = select_existing_deployment(deployment)
    env_path, env = load_existing_deployment_env(deployment_name)
    state = load_state(deployment_name)
    route_failed = False
    print_header("Client route diagnostics")
    for selected_role in requested_roles(role):
        target = build_target(selected_role, env, state)
        route_info = local_route_to_server(target)
        public_ip = target.public_ip or target.ssh_host or "-"
        if route_info is None:
            print(f"{target.label}: route check unavailable; ip={public_ip}")
            continue
        self_tunnel = route_uses_self_tunnel(route_info, client_tun_name=env.get("CLIENT_TUN_NAME", ""))
        verdict = "BAD: self-tunnel" if self_tunnel else "OK"
        print(
            f"{target.label}: {verdict}; ip={route_info.target_ip}; "
            f"iface={route_info.interface_alias or '-'}; source={route_info.source_address or '-'}; next-hop={route_info.next_hop or '-'}"
        )
        route_failed = route_failed or self_tunnel
    if route_failed:
        paths = client_artifact_paths(env)
        print("diagnosis: IP сервера уходит через VPN-интерфейс; это ломает Reality/VLESS connect до входа на сервер.")
        print(f"Windows bypass helper: {paths['windows_route_bypass']}")
        print(f"Route-safe JSON: {paths['hiddify_json']}")
    print(f"Deployment env: {env_path}")
    return 1 if route_failed or int(counts.get("client_front_connect_failed", 0)) > 0 else 0
