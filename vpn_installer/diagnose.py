from __future__ import annotations

import time
from pathlib import Path

from .common import OUT_DIR, print_header, warn, write_text
from .models import ROLE_FOREIGN, ROLE_RU, AppError, RemoteTarget
from .remote import ssh_capture
from .workflows import current_wg_interface, prepare_remote_session, requested_roles


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

role="$(cat /etc/vpn-stack/role 2>/dev/null || true)"
default_iface="$(ip route show default 2>/dev/null | awk '/default/ {{print $5; exit}}')"
gateway="$(ip route show default 2>/dev/null | awk '/default/ {{print $3; exit}}')"
peer_public="$(env_value {peer_public_key})"
health_urls="$(env_value HEALTH_THROUGHPUT_URLS)"
health_url="${{health_urls%% *}}"
if [[ -z "${{health_url}}" ]]; then health_url="https://cachefly.cachefly.net/1mb.test"; fi

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
  timeout 15 ping -4 -c 10 -W 1 "${{host}}" 2>&1 | tail -n 4
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
    timeout 35 mtr -rwzc 20 "${{host}}" 2>&1 | sed -n '1,35p'
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
    timeout 15 curl -4kLsS --interface "${{bind_iface}}" --connect-timeout 5 --max-time 12 -o /dev/null -w 'code=%{{http_code}} exit=%{{exitcode}} ip=%{{remote_ip}} time=%{{time_total}} speed=%{{speed_download}}\\n' "${{url}}" 2>&1 || true
  else
    timeout 15 curl -4kLsS --connect-timeout 5 --max-time 12 -o /dev/null -w 'code=%{{http_code}} exit=%{{exitcode}} ip=%{{remote_ip}} time=%{{time_total}} speed=%{{speed_download}}\\n' "${{url}}" 2>&1 || true
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
  xray_log="$(journalctl -u vpn-stack-xray.service --since '-30 minutes' --no-pager -o cat 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' || true)"
  printf 'window_minutes=30\n'
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
  singbox_log="$(journalctl -u sing-box --since '-30 minutes' --no-pager -o cat 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' || true)"
  printf 'window_minutes=30\n'
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
journalctl -u sing-box --since '-30 minutes' --no-pager 2>/dev/null | tail -n 240 || true
"""


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
    for target in targets:
        print(f"{target.label}: собираю диагностику")
        report = ssh_capture(target, _path_script(target.role, wg_interface), as_root=True)
        write_text(output_dir / f"{target.role}.txt", report)

    if iperf:
        print("Запускаю bounded iperf smoke через wg0.")
        _run_iperf_smoke(output_dir, targets)

    if not any(output_dir.iterdir()):
        raise AppError("Диагностика не собрала ни одного файла.")
    print(f"Диагностика сохранена: {output_dir}")
    return 0
