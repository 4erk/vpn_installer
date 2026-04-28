from __future__ import annotations

import logging
import shlex
import sys
import time
from pathlib import Path
from typing import Any

from .common import command_exists, fail, run_command
from .models import AppError, RemoteTarget
from .runtime_deps import ensure_python_package

SSH_CONNECT_TIMEOUT = 20
SSH_BANNER_TIMEOUT = 20
SSH_AUTH_TIMEOUT = 45
SSH_PASSWORD_AUTH_RETRIES = 3
SSH_PASSWORD_AUTH_RETRY_DELAY = 1.0
_PARAMIKO_LOGGER_CONFIGURED = False


def ensure_paramiko_installed():
    return ensure_python_package("paramiko", "paramiko>=3.5,<4")


def configure_paramiko_logging() -> None:
    global _PARAMIKO_LOGGER_CONFIGURED
    if _PARAMIKO_LOGGER_CONFIGURED:
        return
    logger = logging.getLogger("paramiko")
    if not any(isinstance(handler, logging.NullHandler) for handler in logger.handlers):
        logger.addHandler(logging.NullHandler())
    logger.setLevel(logging.CRITICAL)
    logger.propagate = False
    _PARAMIKO_LOGGER_CONFIGURED = True


def use_python_ssh_backend(target: RemoteTarget) -> bool:
    return target.auth_mode == "password" or not (command_exists("ssh") and command_exists("scp"))


def ssh_base_args(target: RemoteTarget) -> list[str]:
    args = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-p", str(target.ssh_port)]
    if target.identity_path:
        args.extend(["-i", target.identity_path])
    args.append(f"{target.ssh_user}@{target.ssh_host}")
    return args


def scp_base_args(target: RemoteTarget) -> list[str]:
    args = ["scp", "-o", "StrictHostKeyChecking=accept-new", "-P", str(target.ssh_port)]
    if target.identity_path:
        args.extend(["-i", target.identity_path])
    return args


def build_remote_command(command_body: str, target: RemoteTarget, as_root: bool) -> tuple[str, str | None]:
    input_text: str | None = None
    shell_command = f"bash -lc {shlex.quote(command_body)}"
    if as_root and target.ssh_user != "root":
        if target.sudo_mode == "nopasswd":
            shell_command = f"sudo -n {shell_command}"
        elif target.sudo_mode == "password":
            shell_command = f"sudo -S -p '' {shell_command}"
            input_text = f"{target.sudo_password}\n"
        else:
            fail(f"Для {target.label} не подтверждён root/sudo доступ.")
    return shell_command, input_text


def paramiko_connect(target: RemoteTarget):
    paramiko = ensure_paramiko_installed()
    configure_paramiko_logging()
    connect_kwargs: dict[str, Any] = {
        "hostname": target.ssh_host,
        "port": int(target.ssh_port),
        "username": target.ssh_user,
        "timeout": SSH_CONNECT_TIMEOUT,
        "banner_timeout": SSH_BANNER_TIMEOUT,
        "auth_timeout": SSH_AUTH_TIMEOUT,
    }
    if target.auth_mode == "password":
        if not target.ssh_password:
            fail(f"Для {target.label} не задан SSH password.")
        connect_kwargs["password"] = target.ssh_password
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"] = False
    else:
        connect_kwargs["look_for_keys"] = not bool(target.identity_path)
        connect_kwargs["allow_agent"] = not bool(target.identity_path)
        if target.identity_path:
            connect_kwargs["key_filename"] = target.identity_path
    auth_exception_type = getattr(getattr(paramiko, "ssh_exception", None), "AuthenticationException", Exception)
    last_exc: Exception | None = None
    attempts = SSH_PASSWORD_AUTH_RETRIES if target.auth_mode == "password" else 1
    for attempt in range(1, attempts + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(**connect_kwargs)
            return client
        except Exception as exc:  # noqa: BLE001
            client.close()
            last_exc = exc
            retryable_auth_timeout = (
                target.auth_mode == "password"
                and isinstance(exc, auth_exception_type)
                and "timeout" in str(exc).lower()
                and attempt < attempts
            )
            if retryable_auth_timeout:
                time.sleep(SSH_PASSWORD_AUTH_RETRY_DELAY * attempt)
                continue
            banner_timeout = "error reading ssh protocol banner" in str(exc).lower()
            if banner_timeout:
                raise AppError(
                    f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}\n"
                    "Сервер не отдал SSH banner вовремя. Обычно это означает перегруженный или подвисший SSH на хосте, сетевой фильтр перед ним или только что перезагружающийся сервер."
                ) from exc
            if target.auth_mode == "password" and isinstance(exc, auth_exception_type) and "timeout" in str(exc).lower():
                raise AppError(
                    f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}\n"
                    "Сервер слишком долго отвечает на password-аутентификацию. Повтори попытку; если проблема повторяется, проверь пароль или SSH policy хоста."
                ) from exc
            raise AppError(f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}") from exc
    raise AppError(f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {last_exc}")


def paramiko_exec(target: RemoteTarget, remote_command: str, *, input_text: str | None = None) -> tuple[int, str, str]:
    client = paramiko_connect(target)
    try:
        stdin, stdout, stderr = client.exec_command(remote_command, get_pty=bool(input_text))
        if input_text:
            stdin.write(input_text)
            stdin.flush()
            try:
                stdin.channel.shutdown_write()
            except Exception:  # noqa: BLE001
                pass
        channel = stdout.channel
        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        while True:
            if channel.recv_ready():
                out_chunks.append(channel.recv(4096))
            if channel.recv_stderr_ready():
                err_chunks.append(channel.recv_stderr(4096))
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.05)
        exit_status = channel.recv_exit_status()
        return exit_status, b"".join(out_chunks).decode("utf-8", errors="replace"), b"".join(err_chunks).decode("utf-8", errors="replace")
    finally:
        client.close()


def paramiko_upload(target: RemoteTarget, local_path: Path, remote_path: str) -> None:
    client = paramiko_connect(target)
    try:
        sftp = client.open_sftp()
        try:
            sftp.put(str(local_path), remote_path)
        finally:
            sftp.close()
    except Exception as exc:  # noqa: BLE001
        raise AppError(f"Не удалось загрузить {local_path} на {target.label}: {exc}") from exc
    finally:
        client.close()


def ssh_capture(target: RemoteTarget, command_body: str, *, as_root: bool = False) -> str:
    remote_command, input_text = build_remote_command(command_body, target, as_root)
    if use_python_ssh_backend(target):
        exit_status, stdout, stderr = paramiko_exec(target, remote_command, input_text=input_text)
        if exit_status != 0:
            detail = (stderr or stdout).strip()
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{detail or exit_status}")
        return stdout
    completed = run_command(ssh_base_args(target) + [remote_command], capture_output=True, input_text=input_text)
    return completed.stdout


def ssh_stream(target: RemoteTarget, command_body: str, *, as_root: bool = False) -> None:
    remote_command, input_text = build_remote_command(command_body, target, as_root)
    if use_python_ssh_backend(target):
        exit_status, stdout, stderr = paramiko_exec(target, remote_command, input_text=input_text)
        if stdout.strip():
            print(stdout.rstrip())
        if stderr.strip():
            print(stderr.rstrip(), file=sys.stderr)
        if exit_status != 0:
            detail = (stderr or stdout).strip()
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{detail or exit_status}")
        return
    run_command(ssh_base_args(target) + [remote_command], input_text=input_text)


def scp_upload(target: RemoteTarget, local_path: Path, remote_path: str) -> None:
    if use_python_ssh_backend(target):
        paramiko_upload(target, local_path, remote_path)
        return
    run_command(scp_base_args(target) + [str(local_path), f"{target.ssh_user}@{target.ssh_host}:{remote_path}"])


def parse_kv_output(payload: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in payload.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def fetch_remote_deployment_env(target: RemoteTarget) -> str:
    return ssh_capture(target, "cat /etc/vpn-stack/deployment.env", as_root=True)


def preflight_script(wg_interface: str) -> str:
    return f"""\
set -euo pipefail

service_state() {{
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active "$1" 2>/dev/null || true
  else
    printf 'unavailable'
  fi
}}

probe_public_ipv4() {{
  if ! command -v curl >/dev/null 2>&1; then
    return 0
  fi
  curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true
}}

env_value() {{
  local key="$1"
  if [[ -r /etc/vpn-stack/deployment.env ]]; then
    awk -F= -v key="${{key}}" '$1 == key {{ sub(/^[^=]*=/, ""); gsub(/^"/, ""); gsub(/"$/, ""); print; exit }}' /etc/vpn-stack/deployment.env
  fi
}}

state_value() {{
  local key="$1"
  if [[ -r /var/lib/vpn-stack/health-state.env ]]; then
    awk -F= -v key="${{key}}" '$1 == key {{ sub(/^[^=]*=/, ""); gsub(/^"/, ""); gsub(/"$/, ""); print; exit }}' /var/lib/vpn-stack/health-state.env
  fi
}}

probe_download_bps() {{
  local bind_iface="$1"
  local url="$2"
  if ! command -v curl >/dev/null 2>&1 || [[ -z "${{url}}" ]]; then
    printf -- '-1'
    return 0
  fi
  local speed
  if [[ -n "${{bind_iface}}" ]]; then
    speed="$(curl -4fsS --interface "${{bind_iface}}" --max-time 15 -o /dev/null -w '%{{speed_download}}' "${{url}}" 2>/dev/null || true)"
  else
    speed="$(curl -4fsS --max-time 15 -o /dev/null -w '%{{speed_download}}' "${{url}}" 2>/dev/null || true)"
  fi
  if [[ "${{speed}}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    awk -v speed="${{speed}}" 'BEGIN {{ printf "%.0f", speed }}'
  else
    printf -- '-1'
  fi
}}

login_user="$(id -un)"
uid="$(id -u)"
is_root="0"
if [[ "${{uid}}" -eq 0 ]]; then is_root="1"; fi

has_sudo="0"
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then has_sudo="1"; fi

os_id=""
os_version=""
if [[ -r /etc/os-release ]]; then
  source /etc/os-release
  os_id="${{ID:-}}"
  os_version="${{VERSION_ID:-}}"
fi

installed="0"
deployment_name=""
role=""
installed_at=""
configured_wan_interface=""
if [[ -r /etc/vpn-stack/deployment.env ]]; then
  installed="1"
  deployment_name="$(grep -E '^DEPLOY_NAME=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
  configured_wan_interface="$(grep -E '^WAN_INTERFACE=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
fi
if [[ -r /etc/vpn-stack/role ]]; then role="$(tr -d '\\r\\n' </etc/vpn-stack/role)"; fi
if [[ -r /etc/vpn-stack/installed_at ]]; then installed_at="$(tr -d '\\r\\n' </etc/vpn-stack/installed_at)"; fi

default_iface="$(ip route show default 2>/dev/null | awk '/default/ {{print $5; exit}}')"
hostname_value="$(hostname -f 2>/dev/null || hostname)"
default_qdisc="-"
iface_rx_drops="0"
iface_tx_drops="0"
wan_mtu="-"
wan_offload_gro="-"
wan_offload_gso="-"
wan_offload_tso="-"
tcp_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
tcp_mtu_probing="$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || true)"
netdev_backlog="$(sysctl -n net.core.netdev_max_backlog 2>/dev/null || true)"
rmem_max="$(sysctl -n net.core.rmem_max 2>/dev/null || true)"
wmem_max="$(sysctl -n net.core.wmem_max 2>/dev/null || true)"
udp_rmem_min="$(sysctl -n net.ipv4.udp_rmem_min 2>/dev/null || true)"
udp_wmem_min="$(sysctl -n net.ipv4.udp_wmem_min 2>/dev/null || true)"
wg_transfer_rx="-"
wg_transfer_tx="-"
wg_latest_handshake="-"
wg_latest_handshake_age_s="-1"
observed_ipv4="$(probe_public_ipv4)"
wg_observed_ipv4=""
throughput_urls="$(env_value HEALTH_THROUGHPUT_URLS)"
throughput_url="${{throughput_urls%% *}}"
if [[ -z "${{throughput_url}}" ]]; then throughput_url="https://cachefly.cachefly.net/1mb.test"; fi
direct_download_bps="-1"
wg_download_bps="-1"
deep_probe_at="$(state_value DEEP_PROBE_AT)"
deep_probe_verdict="$(state_value DEEP_PROBE_VERDICT)"
deep_probe_reasons="$(state_value DEEP_PROBE_REASONS)"
deep_foreign_direct_download_min_bps="$(state_value DEEP_FOREIGN_DIRECT_DOWNLOAD_MIN_BPS)"
deep_foreign_direct_download_detail="$(state_value DEEP_FOREIGN_DIRECT_DOWNLOAD_DETAIL)"
deep_foreign_direct_upload_bps="$(state_value DEEP_FOREIGN_DIRECT_UPLOAD_BPS)"
deep_foreign_gateway_ping_loss_pct="$(state_value DEEP_FOREIGN_GATEWAY_PING_LOSS_PCT)"
deep_foreign_ru_ping_loss_pct="$(state_value DEEP_FOREIGN_RU_PING_LOSS_PCT)"
deep_foreign_internet_ping_loss_pct="$(state_value DEEP_FOREIGN_INTERNET_PING_LOSS_PCT)"
deep_ru_wg_download_min_bps="$(state_value DEEP_RU_WG_DOWNLOAD_MIN_BPS)"
deep_ru_wg_download_detail="$(state_value DEEP_RU_WG_DOWNLOAD_DETAIL)"
deep_ru_wg_upload_bps="$(state_value DEEP_RU_WG_UPLOAD_BPS)"

if [[ -n "${{default_iface}}" ]]; then
  default_qdisc="$(tc qdisc show dev "${{default_iface}}" 2>/dev/null | awk 'NR==1 {{print $2; exit}}')"
  wan_mtu="$(ip link show dev "${{default_iface}}" 2>/dev/null | awk '/mtu/ {{for (i=1; i<=NF; i++) if ($i == "mtu") {{print $(i+1); exit}}}}')"
  proc_row="$(grep -E "^[[:space:]]*${{default_iface}}:" /proc/net/dev 2>/dev/null || true)"
  if [[ -n "${{proc_row}}" ]]; then
    iface_rx_drops="$(awk '{{gsub(":", "", $1); print $5}}' <<<"${{proc_row}}")"
    iface_tx_drops="$(awk '{{gsub(":", "", $1); print $13}}' <<<"${{proc_row}}")"
  fi
  if command -v ethtool >/dev/null 2>&1; then
    wan_offload_gro="$(ethtool -k "${{default_iface}}" 2>/dev/null | awk '/generic-receive-offload:/ {{print $2; exit}}')"
    wan_offload_gso="$(ethtool -k "${{default_iface}}" 2>/dev/null | awk '/generic-segmentation-offload:/ {{print $2; exit}}')"
    wan_offload_tso="$(ethtool -k "${{default_iface}}" 2>/dev/null | awk '/tcp-segmentation-offload:/ {{print $2; exit}}')"
  fi
fi

if command -v wg >/dev/null 2>&1; then
  transfer_row="$(wg show {wg_interface} transfer 2>/dev/null | awk 'NR==1')"
  handshake_row="$(wg show {wg_interface} latest-handshakes 2>/dev/null | awk 'NR==1')"
  if [[ -n "${{transfer_row}}" ]]; then
    wg_transfer_rx="$(awk '{{print $2}}' <<<"${{transfer_row}}")"
    wg_transfer_tx="$(awk '{{print $3}}' <<<"${{transfer_row}}")"
  fi
  if [[ -n "${{handshake_row}}" ]]; then
    wg_latest_handshake="$(awk '{{print $2}}' <<<"${{handshake_row}}")"
    if [[ -n "${{wg_latest_handshake}}" && "${{wg_latest_handshake}}" != "0" ]]; then
      now_epoch="$(date +%s)"
      if [[ "${{wg_latest_handshake}}" =~ ^[0-9]+$ && "${{now_epoch}}" =~ ^[0-9]+$ && "${{now_epoch}}" -ge "${{wg_latest_handshake}}" ]]; then
        wg_latest_handshake_age_s="$((now_epoch - wg_latest_handshake))"
      fi
    fi
  fi
fi

if [[ "${{role}}" == "ru-gateway" ]] && ip link show dev {wg_interface} >/dev/null 2>&1; then
  wg_observed_ipv4="$(curl -4fsS --interface {wg_interface} --max-time 8 https://api.ipify.org 2>/dev/null || true)"
fi

if [[ "${{installed}}" == "1" ]]; then
  direct_download_bps="$(probe_download_bps "" "${{throughput_url}}")"
fi
if [[ "${{installed}}" == "1" && "${{role}}" == "ru-gateway" ]] && ip link show dev {wg_interface} >/dev/null 2>&1; then
  wg_download_bps="$(probe_download_bps "{wg_interface}" "${{throughput_url}}")"
fi

printf 'login_user=%s\\n' "${{login_user}}"
printf 'is_root=%s\\n' "${{is_root}}"
printf 'has_sudo=%s\\n' "${{has_sudo}}"
printf 'os_id=%s\\n' "${{os_id}}"
printf 'os_version=%s\\n' "${{os_version}}"
printf 'hostname=%s\\n' "${{hostname_value}}"
printf 'default_iface=%s\\n' "${{default_iface}}"
printf 'configured_wan_interface=%s\\n' "${{configured_wan_interface}}"
printf 'wan_mtu=%s\\n' "${{wan_mtu}}"
printf 'default_qdisc=%s\\n' "${{default_qdisc}}"
printf 'wan_offload_gro=%s\\n' "${{wan_offload_gro}}"
printf 'wan_offload_gso=%s\\n' "${{wan_offload_gso}}"
printf 'wan_offload_tso=%s\\n' "${{wan_offload_tso}}"
printf 'iface_rx_drops=%s\\n' "${{iface_rx_drops}}"
printf 'iface_tx_drops=%s\\n' "${{iface_tx_drops}}"
printf 'tcp_cc=%s\\n' "${{tcp_cc}}"
printf 'tcp_mtu_probing=%s\\n' "${{tcp_mtu_probing}}"
printf 'netdev_backlog=%s\\n' "${{netdev_backlog}}"
printf 'rmem_max=%s\\n' "${{rmem_max}}"
printf 'wmem_max=%s\\n' "${{wmem_max}}"
printf 'udp_rmem_min=%s\\n' "${{udp_rmem_min}}"
printf 'udp_wmem_min=%s\\n' "${{udp_wmem_min}}"
printf 'wg_transfer_rx=%s\\n' "${{wg_transfer_rx}}"
printf 'wg_transfer_tx=%s\\n' "${{wg_transfer_tx}}"
printf 'wg_latest_handshake=%s\\n' "${{wg_latest_handshake}}"
printf 'wg_latest_handshake_age_s=%s\\n' "${{wg_latest_handshake_age_s}}"
printf 'observed_ipv4=%s\\n' "${{observed_ipv4}}"
printf 'wg_observed_ipv4=%s\\n' "${{wg_observed_ipv4}}"
printf 'direct_download_bps=%s\\n' "${{direct_download_bps}}"
printf 'wg_download_bps=%s\\n' "${{wg_download_bps}}"
printf 'deep_probe_at=%s\\n' "${{deep_probe_at}}"
printf 'deep_probe_verdict=%s\\n' "${{deep_probe_verdict}}"
printf 'deep_probe_reasons=%s\\n' "${{deep_probe_reasons}}"
printf 'deep_foreign_direct_download_min_bps=%s\\n' "${{deep_foreign_direct_download_min_bps}}"
printf 'deep_foreign_direct_download_detail=%s\\n' "${{deep_foreign_direct_download_detail}}"
printf 'deep_foreign_direct_upload_bps=%s\\n' "${{deep_foreign_direct_upload_bps}}"
printf 'deep_foreign_gateway_ping_loss_pct=%s\\n' "${{deep_foreign_gateway_ping_loss_pct}}"
printf 'deep_foreign_ru_ping_loss_pct=%s\\n' "${{deep_foreign_ru_ping_loss_pct}}"
printf 'deep_foreign_internet_ping_loss_pct=%s\\n' "${{deep_foreign_internet_ping_loss_pct}}"
printf 'deep_ru_wg_download_min_bps=%s\\n' "${{deep_ru_wg_download_min_bps}}"
printf 'deep_ru_wg_download_detail=%s\\n' "${{deep_ru_wg_download_detail}}"
printf 'deep_ru_wg_upload_bps=%s\\n' "${{deep_ru_wg_upload_bps}}"
printf 'installed=%s\\n' "${{installed}}"
printf 'deployment_name=%s\\n' "${{deployment_name}}"
printf 'role=%s\\n' "${{role}}"
printf 'installed_at=%s\\n' "${{installed_at}}"
printf 'sing_box=%s\\n' "$(service_state sing-box)"
printf 'nftables=%s\\n' "$(service_state nftables)"
printf 'wireguard=%s\\n' "$(service_state wg-quick@{wg_interface})"
printf 'sync_timer=%s\\n' "$(service_state vpn-stack-sync.timer)"
printf 'health_timer=%s\\n' "$(service_state vpn-stack-health.timer)"
printf 'ssh_service=%s\\n' "$(service_state ssh.service)"
printf 'ssh_socket=%s\\n' "$(service_state ssh.socket)"
""".strip()


def remote_preflight(target: RemoteTarget, wg_interface: str) -> dict[str, str]:
    return parse_kv_output(ssh_capture(target, preflight_script(wg_interface)))


def print_preflight(target: RemoteTarget, preflight: dict[str, str]) -> None:
    from .common import print_header

    print_header(f"Проверка {target.label}")
    print(f"host: {preflight.get('hostname', '-')}")
    print(f"login user: {preflight.get('login_user', '-')}")
    print(f"os: {preflight.get('os_id', '-')} {preflight.get('os_version', '-')}")
    print(f"default iface: {preflight.get('default_iface', '-')}")
    print(f"configured WAN iface: {preflight.get('configured_wan_interface', '-')}")
    print(f"wan mtu: {preflight.get('wan_mtu', '-')}")
    print(f"qdisc: {preflight.get('default_qdisc', '-')}")
    print(
        "wan offloads gro/gso/tso: "
        f"{preflight.get('wan_offload_gro', '-')}/"
        f"{preflight.get('wan_offload_gso', '-')}/"
        f"{preflight.get('wan_offload_tso', '-')}"
    )
    print(f"tcp cc: {preflight.get('tcp_cc', '-')}")
    print(f"tcp mtu probing: {preflight.get('tcp_mtu_probing', '-')}")
    print(f"netdev backlog: {preflight.get('netdev_backlog', '-')}")
    print(f"rmem/wmem max: {preflight.get('rmem_max', '-')}/{preflight.get('wmem_max', '-')}")
    print(f"udp rmem/wmem min: {preflight.get('udp_rmem_min', '-')}/{preflight.get('udp_wmem_min', '-')}")
    print(f"iface drops rx/tx: {preflight.get('iface_rx_drops', '0')}/{preflight.get('iface_tx_drops', '0')}")
    print(f"installed: {preflight.get('installed', '0')}")
    print(f"role: {preflight.get('role', '-')}")
    print(f"deployment: {preflight.get('deployment_name', '-')}")
    print(f"sing-box: {preflight.get('sing_box', '-')}")
    print(f"nftables: {preflight.get('nftables', '-')}")
    print(f"wireguard: {preflight.get('wireguard', '-')}")
    print(f"wireguard transfer rx/tx: {preflight.get('wg_transfer_rx', '-')}/{preflight.get('wg_transfer_tx', '-')}")
    print(f"wireguard latest handshake: {preflight.get('wg_latest_handshake', '-')}")
    print(f"wireguard handshake age (s): {preflight.get('wg_latest_handshake_age_s', '-')}")
    print(f"observed IPv4: {preflight.get('observed_ipv4', '-')}")
    print(f"RU over wg IPv4: {preflight.get('wg_observed_ipv4', '-')}")
    print(f"direct download B/s: {preflight.get('direct_download_bps', '-')}")
    print(f"RU over wg download B/s: {preflight.get('wg_download_bps', '-')}")
    if preflight.get("deep_probe_at"):
        print(f"deep probe at: {preflight.get('deep_probe_at', '-')}")
        print(f"deep probe verdict: {preflight.get('deep_probe_verdict', '-')}")
        print(f"deep probe reasons: {preflight.get('deep_probe_reasons', '-')}")
        print(f"foreign direct min download B/s: {preflight.get('deep_foreign_direct_download_min_bps', '-')}")
        print(f"foreign direct upload B/s: {preflight.get('deep_foreign_direct_upload_bps', '-')}")
        print(f"foreign ping loss to gateway (%): {preflight.get('deep_foreign_gateway_ping_loss_pct', '-')}")
        print(f"foreign ping loss to RU (%): {preflight.get('deep_foreign_ru_ping_loss_pct', '-')}")
        print(f"foreign ping loss to internet (%): {preflight.get('deep_foreign_internet_ping_loss_pct', '-')}")
        print(f"RU over wg min download B/s: {preflight.get('deep_ru_wg_download_min_bps', '-')}")
        print(f"RU over wg upload B/s: {preflight.get('deep_ru_wg_upload_bps', '-')}")
    print(f"sync timer: {preflight.get('sync_timer', '-')}")
    print(f"health timer: {preflight.get('health_timer', '-')}")
    print(f"ssh service: {preflight.get('ssh_service', '-')}")
    print(f"ssh socket: {preflight.get('ssh_socket', '-')}")


def ensure_remote_privilege(target: RemoteTarget, preflight: dict[str, str], *, prompt_yes_no, prompt_secret) -> None:
    if preflight.get("is_root") == "1":
        target.sudo_mode = "root"
        print(f"{target.label}: удалённый вход уже под root.")
        return
    if preflight.get("has_sudo") == "1":
        target.sudo_mode = "nopasswd"
        print(f"{target.label}: найден passwordless sudo.")
        return
    if not prompt_yes_no(
        f"Пользователь {preflight.get('login_user', 'unknown')} на {preflight.get('hostname', 'unknown')} не root и без passwordless sudo. Попробовать sudo по паролю?",
        default=True,
    ):
        fail(f"Для {target.label} нужен root или sudo.")
    target.sudo_mode = "password"
    target.sudo_password = prompt_secret(f"Введите sudo-пароль для {target.label}")
