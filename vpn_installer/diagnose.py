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
for unit in ssh.service ssh.socket nftables "wg-quick@{wg_interface}" sing-box vpn-stack-sync.timer vpn-stack-health.timer vpn-stack-health.service; do
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


def diagnose_path_workflow(deployment: str | None, role: str, *, iperf: bool = False) -> int:
    roles = requested_roles(role)
    deployment_name, _env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
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
