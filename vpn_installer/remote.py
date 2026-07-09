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
SSH_COMMAND_TIMEOUT = 1800
SSH_PASSWORD_AUTH_RETRIES = 3
SSH_PASSWORD_AUTH_RETRY_DELAY = 1.0
SSH_BANNER_RETRIES = 3
SSH_BANNER_RETRY_DELAY = 1.0
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
    attempts = max(SSH_PASSWORD_AUTH_RETRIES if target.auth_mode == "password" else 1, SSH_BANNER_RETRIES)
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
            if banner_timeout and attempt < attempts:
                time.sleep(SSH_BANNER_RETRY_DELAY * attempt)
                continue
            if banner_timeout:
                raise AppError(
                    f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}\n"
                    "Сервер не отдал SSH banner вовремя. Обычно это означает перегруженный или подвисший SSH на хосте, сетевой фильтр перед ним или только что перезагружающийся сервер."
                ) from exc
            connection_reset = "forcibly closed" in str(exc).lower() or "connection reset" in str(exc).lower()
            if connection_reset and attempt < attempts:
                time.sleep(SSH_BANNER_RETRY_DELAY * attempt)
                continue
            if target.auth_mode == "password" and isinstance(exc, auth_exception_type) and "timeout" in str(exc).lower():
                raise AppError(
                    f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}\n"
                    "Сервер слишком долго отвечает на password-аутентификацию. Повтори попытку; если проблема повторяется, проверь пароль или SSH policy хоста."
                ) from exc
            raise AppError(f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}") from exc
    raise AppError(f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {last_exc}")


def paramiko_exec(
    target: RemoteTarget,
    remote_command: str,
    *,
    input_text: str | None = None,
    command_timeout: int = SSH_COMMAND_TIMEOUT,
    get_pty: bool = False,
) -> tuple[int, str, str]:
    client = paramiko_connect(target)
    try:
        stdin, stdout, stderr = client.exec_command(remote_command, get_pty=get_pty)
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
        started_at = time.monotonic()
        while True:
            if channel.recv_ready():
                out_chunks.append(channel.recv(4096))
            if channel.recv_stderr_ready():
                err_chunks.append(channel.recv_stderr(4096))
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if command_timeout > 0 and time.monotonic() - started_at > command_timeout:
                try:
                    channel.close()
                except Exception:  # noqa: BLE001
                    pass
                partial_stdout = b"".join(out_chunks).decode("utf-8", errors="replace")
                partial_stderr = b"".join(err_chunks).decode("utf-8", errors="replace")
                detail = partial_stderr.strip() or partial_stdout.strip()
                if detail:
                    detail = f"\nPartial remote output:\n{detail[-4000:]}"
                raise AppError(
                    f"Удалённая команда не завершилась за {command_timeout} сек. на {target.label}."
                    f"{detail}"
                )
            time.sleep(0.05)
        exit_status = channel.recv_exit_status()
        return exit_status, b"".join(out_chunks).decode("utf-8", errors="replace"), b"".join(err_chunks).decode("utf-8", errors="replace")
    finally:
        client.close()


def paramiko_stream(
    target: RemoteTarget,
    remote_command: str,
    *,
    input_text: str | None = None,
    command_timeout: int = SSH_COMMAND_TIMEOUT,
    get_pty: bool = False,
) -> int:
    client = paramiko_connect(target)
    try:
        stdin, stdout, stderr = client.exec_command(remote_command, get_pty=get_pty)
        if input_text:
            stdin.write(input_text)
            stdin.flush()
            try:
                stdin.channel.shutdown_write()
            except Exception:  # noqa: BLE001
                pass
        channel = stdout.channel
        out_tail: list[str] = []
        err_tail: list[str] = []
        started_at = time.monotonic()
        while True:
            if channel.recv_ready():
                text = channel.recv(4096).decode("utf-8", errors="replace")
                if text:
                    sys.stdout.write(text)
                    sys.stdout.flush()
                    out_tail.append(text)
                    out_tail[:] = out_tail[-20:]
            if channel.recv_stderr_ready():
                text = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                if text:
                    sys.stderr.write(text)
                    sys.stderr.flush()
                    err_tail.append(text)
                    err_tail[:] = err_tail[-20:]
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if command_timeout > 0 and time.monotonic() - started_at > command_timeout:
                try:
                    channel.close()
                except Exception:  # noqa: BLE001
                    pass
                detail = "".join(err_tail).strip() or "".join(out_tail).strip()
                if detail:
                    detail = f"\nPartial remote output:\n{detail[-4000:]}"
                raise AppError(
                    f"Удалённая команда не завершилась за {command_timeout} сек. на {target.label}."
                    f"{detail}"
                )
            time.sleep(0.05)
        return channel.recv_exit_status()
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
        exit_status, stdout, stderr = paramiko_exec(target, remote_command, input_text=input_text, get_pty=bool(input_text))
        if exit_status != 0:
            detail = (stderr or stdout).strip()
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{detail or exit_status}")
        return stdout
    completed = run_command(ssh_base_args(target) + [remote_command], capture_output=True, input_text=input_text)
    return completed.stdout


def ssh_stream(target: RemoteTarget, command_body: str, *, as_root: bool = False) -> None:
    remote_command, input_text = build_remote_command(command_body, target, as_root)
    if use_python_ssh_backend(target):
        exit_status = paramiko_stream(target, remote_command, input_text=input_text, get_pty=bool(input_text))
        if exit_status != 0:
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{exit_status}")
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

cache_value() {{
  local key="$1"
  if [[ -r /var/lib/vpn-stack/dataplane-cache.env ]]; then
    awk -F= -v key="${{key}}" '$1 == key {{ sub(/^[^=]*=/, ""); gsub(/^"/, ""); gsub(/"$/, ""); print; exit }}' /var/lib/vpn-stack/dataplane-cache.env
  fi
}}

age_from_epoch() {{
  local epoch="$1"
  local now=""
  now="$(date +%s)"
  if [[ "${{epoch}}" =~ ^[0-9]+$ && "${{now}}" =~ ^[0-9]+$ && "${{now}}" -ge "${{epoch}}" ]]; then
    printf '%s' "$((now - epoch))"
  else
    printf -- '-1'
  fi
}}

guard_state_value() {{
  local key="$1"
  if [[ -r /var/lib/vpn-stack/guard-state.env ]]; then
    awk -F= -v key="${{key}}" '$1 == key {{ sub(/^[^=]*=/, ""); gsub(/^"/, ""); gsub(/"$/, ""); print; exit }}' /var/lib/vpn-stack/guard-state.env
  fi
}}

nft_port_packets() {{
  local port="$1"
  local verdict="$2"
  if ! command -v nft >/dev/null 2>&1; then
    return 0
  fi
  nft -a list chain inet vpnstack input 2>/dev/null |
    grep -F "tcp dport ${{port}} " |
    grep -F " ${{verdict}}" |
    grep -F " counter " |
    sed -n 's/.* counter packets \\([0-9][0-9]*\\) bytes .*/\\1/p' |
    head -n1 || true
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

target_verdict() {{
  local code="$1"
  local exit_code="$2"
  if [[ "${{exit_code}}" != "0" || "${{code}}" == "000" || -z "${{code}}" ]]; then
    printf 'broken'
  elif [[ "${{code}}" == "451" ]]; then
    printf 'blocked'
  elif [[ "${{code}}" =~ ^[23] || "${{code}}" == "401" || "${{code}}" == "403" || "${{code}}" == "404" || "${{code}}" == "421" || "${{code}}" == "429" ]]; then
    printf 'reachable'
  else
    printf 'http_%s' "${{code}}"
  fi
}}

target_probe_needs_body_fallback() {{
  local code="$1"
  local exit_code="$2"
  if [[ "${{exit_code}}" != "0" || "${{code}}" == "000" || -z "${{code}}" || "${{code}}" == "405" ]]; then
    return 0
  fi
  if [[ "${{code}}" =~ ^[23] || "${{code}}" == "401" || "${{code}}" == "403" || "${{code}}" == "404" || "${{code}}" == "421" || "${{code}}" == "429" || "${{code}}" == "451" ]]; then
    return 1
  fi
  return 0
}}

probe_target_urls() {{
  local bind_iface="$1"
  local urls="$2"
  local connect_timeout="$3"
  local max_time="$4"
  local url="" label="" result="" result_tail="" code="" exit_code="" remote_ip="" time_total="" verdict="" joined=""
  if ! command -v curl >/dev/null 2>&1 || [[ -z "${{urls}}" ]]; then
    return 0
  fi
  if ! [[ "${{connect_timeout}}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then connect_timeout="2"; fi
  if ! [[ "${{max_time}}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then max_time="4"; fi
  for url in ${{urls}}; do
    label="${{url#*://}}"
    label="${{label%%/*}}"
    if [[ -n "${{bind_iface}}" ]]; then
      result="$(curl -4kIsS --interface "${{bind_iface}}" --connect-timeout "${{connect_timeout}}" --max-time "${{max_time}}" -o /dev/null -w '%{{http_code}}|%{{exitcode}}|%{{remote_ip}}|%{{time_total}}' "${{url}}" 2>/dev/null || true)"
    else
      result="$(curl -4kIsS --connect-timeout "${{connect_timeout}}" --max-time "${{max_time}}" -o /dev/null -w '%{{http_code}}|%{{exitcode}}|%{{remote_ip}}|%{{time_total}}' "${{url}}" 2>/dev/null || true)"
    fi
    code="${{result%%|*}}"
    result_tail="${{result#*|}}"
    exit_code="${{result_tail%%|*}}"
    if target_probe_needs_body_fallback "${{code}}" "${{exit_code}}"; then
      if [[ -n "${{bind_iface}}" ]]; then
        result="$(curl -4kLsS --range 0-0 --interface "${{bind_iface}}" --connect-timeout "${{connect_timeout}}" --max-time "${{max_time}}" -o /dev/null -w '%{{http_code}}|%{{exitcode}}|%{{remote_ip}}|%{{time_total}}' "${{url}}" 2>/dev/null || printf '000|curl_failed||0')"
      else
        result="$(curl -4kLsS --range 0-0 --connect-timeout "${{connect_timeout}}" --max-time "${{max_time}}" -o /dev/null -w '%{{http_code}}|%{{exitcode}}|%{{remote_ip}}|%{{time_total}}' "${{url}}" 2>/dev/null || printf '000|curl_failed||0')"
      fi
    fi
    code="${{result%%|*}}"
    result="${{result#*|}}"
    exit_code="${{result%%|*}}"
    result="${{result#*|}}"
    remote_ip="${{result%%|*}}"
    time_total="${{result#*|}}"
    verdict="$(target_verdict "${{code}}" "${{exit_code}}")"
    if [[ -n "${{joined}}" ]]; then joined="${{joined}};"; fi
    joined="${{joined}}${{label}}:${{verdict}}:${{code}}:${{exit_code}}:${{remote_ip}}:${{time_total}}"
  done
  printf '%s' "${{joined}}"
}}

probe_ipv6_literal_tcp_path() {{
  local bind_iface="$1"
  local port="29080"
  local route_mark=""
  local config="" log="" pid="" target="" url="" label="" result="" code="" exit_code="" remote_ip="" time_total="" verdict="" joined="" started="0"
  if ! command -v sing-box >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    return 0
  fi
  if ! ip link show dev "${{bind_iface}}" >/dev/null 2>&1; then
    return 0
  fi
  if command -v ss >/dev/null 2>&1; then
    for candidate in 29080 29081 29082 29083 29084; do
      if ! ss -ltn "sport = :${{candidate}}" 2>/dev/null | grep -q LISTEN; then
        port="${{candidate}}"
        break
      fi
    done
  fi
  route_mark="$(env_value APP_ROUTE_MARK)"
  if ! [[ "${{route_mark}}" =~ ^[0-9]+$ ]]; then
    route_mark="48"
  fi
  config="$(mktemp /tmp/vpn-ipv6-literal-probe.XXXXXX.json 2>/dev/null || true)"
  log="$(mktemp /tmp/vpn-ipv6-literal-probe.XXXXXX.log 2>/dev/null || true)"
  if [[ -z "${{config}}" || -z "${{log}}" ]]; then
    rm -f "${{config}}" "${{log}}"
    return 0
  fi
  cat >"${{config}}" <<JSON
{{
  "log": {{"level": "error", "timestamp": true}},
  "inbounds": [{{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": ${{port}}}}],
  "outbounds": [{{"type": "direct", "tag": "to-foreign-ipv6-literal-probe", "bind_interface": "${{bind_iface}}", "routing_mark": ${{route_mark}}, "connect_timeout": "4s"}}],
  "route": {{"final": "to-foreign-ipv6-literal-probe"}}
}}
JSON
  sing-box run -c "${{config}}" >"${{log}}" 2>&1 &
  pid="$!"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "${{pid}}" 2>/dev/null; then
      break
    fi
    if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :${{port}}" 2>/dev/null | grep -q LISTEN; then
      started="1"
      break
    fi
    sleep 0.1
  done
  if [[ "${{started}}" != "1" ]] && kill -0 "${{pid}}" 2>/dev/null; then
    sleep 0.4
  fi
  for target in "cloudflare_v6=https://[2606:4700:4700::1111]/cdn-cgi/trace" "google_v6=https://[2a00:1450:400f:807::200e]/generate_204" "meta_v6=https://[2a02:ec80:600:ed1a::2:b]/"; do
    label="${{target%%=*}}"
    url="${{target#*=}}"
    result="$(curl -kLsS --proxy "socks5h://127.0.0.1:${{port}}" --connect-timeout 4 --max-time 6 -o /dev/null -w '%{{http_code}}|%{{exitcode}}|%{{remote_ip}}|%{{time_total}}' "${{url}}" 2>/dev/null || printf '000|curl_failed||0')"
    code="${{result%%|*}}"
    result="${{result#*|}}"
    exit_code="${{result%%|*}}"
    result="${{result#*|}}"
    remote_ip="${{result%%|*}}"
    time_total="${{result#*|}}"
    verdict="$(target_verdict "${{code}}" "${{exit_code}}")"
    if [[ -n "${{joined}}" ]]; then joined="${{joined}};"; fi
    joined="${{joined}}${{label}}:${{verdict}}:${{code}}:${{exit_code}}:${{remote_ip}}:${{time_total}}"
  done
  if [[ -n "${{pid}}" ]] && kill -0 "${{pid}}" 2>/dev/null; then
    kill "${{pid}}" >/dev/null 2>&1 || true
    wait "${{pid}}" >/dev/null 2>&1 || true
  fi
  rm -f "${{config}}" "${{log}}"
  printf '%s' "${{joined}}"
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
singbox_configured_log_level=""
global_doh_server=""
global_doh_server_name=""
ru_literal_policy=""
ru_ipv6_literal_policy=""
deprecated_routing_overrides=""
installed_env_sha256=""
installed_singbox_sha256=""
installed_singbox_base_sha256=""
render_manifest_policy_version=""
render_manifest_singbox_sha256=""
drift="unknown"
if [[ -r /etc/vpn-stack/deployment.env ]]; then
  installed="1"
  deployment_name="$(grep -E '^DEPLOY_NAME=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
  configured_wan_interface="$(grep -E '^WAN_INTERFACE=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
  singbox_configured_log_level="$(grep -E '^SING_BOX_LOG_LEVEL=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
  global_doh_server="$(grep -E '^GLOBAL_DOH_SERVER=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
  global_doh_server_name="$(grep -E '^GLOBAL_DOH_SERVER_NAME=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
  ru_literal_policy="$(env_value RU_LITERAL_POLICY)"
  ru_ipv6_literal_policy="$(env_value RU_IPV6_LITERAL_POLICY)"
  if [[ "$(env_value TO_FOREIGN_CONNECT_TIMEOUT)" != "" ]]; then deprecated_routing_overrides="${{deprecated_routing_overrides}},TO_FOREIGN_CONNECT_TIMEOUT"; fi
  if [[ "$(env_value TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT)" != "2s" ]]; then deprecated_routing_overrides="${{deprecated_routing_overrides}},TO_FOREIGN_IP_LITERAL_CONNECT_TIMEOUT"; fi
  if [[ "$(env_value TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT)" != "3s" ]]; then deprecated_routing_overrides="${{deprecated_routing_overrides}},TO_FOREIGN_IPV6_LITERAL_CONNECT_TIMEOUT"; fi
  deprecated_routing_overrides="${{deprecated_routing_overrides#,}}"
fi
if [[ -r /etc/vpn-stack/role ]]; then role="$(tr -d '\\r\\n' </etc/vpn-stack/role)"; fi
if [[ -r /etc/vpn-stack/installed_at ]]; then installed_at="$(tr -d '\\r\\n' </etc/vpn-stack/installed_at)"; fi
if command -v sha256sum >/dev/null 2>&1; then
  if [[ -r /etc/vpn-stack/deployment.env ]]; then
    installed_env_sha256="$(sha256sum /etc/vpn-stack/deployment.env 2>/dev/null | awk '{{print $1}}' || true)"
  fi
  if [[ -r /etc/sing-box/config.json ]]; then
    installed_singbox_sha256="$(sha256sum /etc/sing-box/config.json 2>/dev/null | awk '{{print $1}}' || true)"
  fi
  if [[ -r /etc/vpn-stack/sing-box.base.json ]]; then
    installed_singbox_base_sha256="$(sha256sum /etc/vpn-stack/sing-box.base.json 2>/dev/null | awk '{{print $1}}' || true)"
  fi
fi
if [[ -r /etc/vpn-stack/render-manifest.json ]]; then
  render_manifest_policy_version="$(sed -n 's/.*"policy_version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' /etc/vpn-stack/render-manifest.json | head -n1)"
  render_manifest_singbox_sha256="$(sed -n 's/.*"config_sha256"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' /etc/vpn-stack/render-manifest.json | head -n1)"
  if [[ -n "${{render_manifest_singbox_sha256}}" ]]; then
    if [[ -n "${{installed_singbox_base_sha256}}" && "${{render_manifest_singbox_sha256}}" == "${{installed_singbox_base_sha256}}" ]]; then
      drift="none"
    elif [[ -n "${{installed_singbox_sha256}}" && "${{render_manifest_singbox_sha256}}" == "${{installed_singbox_sha256}}" ]]; then
      drift="none"
    else
      drift="server-mutated"
    fi
  fi
fi

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
target_probe_urls="$(env_value HEALTH_TARGET_PROBE_URLS)"
if [[ -z "${{target_probe_urls}}" ]]; then
  target_probe_urls="https://chatgpt.com/ https://discord.com/ https://github.com/ https://www.google.com/generate_204"
fi
ru_direct_target_probe_urls="$(env_value HEALTH_RU_DIRECT_TARGET_PROBE_URLS)"
if [[ -z "${{ru_direct_target_probe_urls}}" ]]; then
  ru_direct_target_probe_urls="https://api.ipify.org/ https://2ip.ru/"
fi
target_probe_connect_timeout="$(env_value HEALTH_TARGET_CONNECT_TIMEOUT_SECONDS)"
if [[ -z "${{target_probe_connect_timeout}}" ]]; then target_probe_connect_timeout="2"; fi
target_probe_max_time="$(env_value HEALTH_TARGET_MAX_TIME_SECONDS)"
if [[ -z "${{target_probe_max_time}}" ]]; then target_probe_max_time="4"; fi
throughput_url="${{throughput_urls%% *}}"
if [[ -z "${{throughput_url}}" ]]; then throughput_url="https://cachefly.cachefly.net/1mb.test"; fi
ssh_port="$(env_value SSH_PORT)"
if [[ -z "${{ssh_port}}" ]]; then ssh_port="22"; fi
ru_listen_port="$(env_value RU_LISTEN_PORT)"
if [[ -z "${{ru_listen_port}}" ]]; then ru_listen_port="443"; fi
direct_download_bps="-1"
wg_download_bps="-1"
target_probe_direct=""
target_probe_wg=""
ipv6_literal_tcp_probe=""
nft_ssh_accept_packets=""
nft_ssh_drop_packets=""
nft_vless_accept_packets=""
nft_vless_drop_packets=""
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
fast_foreign_ru_ping_loss_pct="$(state_value FAST_FOREIGN_RU_PING_LOSS_PCT)"
fast_ru_foreign_ping_loss_pct="$(state_value FAST_RU_FOREIGN_PING_LOSS_PCT)"
self_heal_last_reason="$(state_value SELF_HEAL_LAST_REASON)"
self_heal_consecutive="$(state_value SELF_HEAL_CONSECUTIVE)"
self_heal_last_action="$(state_value SELF_HEAL_LAST_ACTION)"
self_heal_last_action_reason="$(state_value SELF_HEAL_LAST_ACTION_REASON)"
self_heal_last_action_result="$(state_value SELF_HEAL_LAST_ACTION_RESULT)"
self_heal_last_action_epoch="$(state_value SELF_HEAL_LAST_ACTION_EPOCH)"
self_heal_last_action_age_s="$(age_from_epoch "${{self_heal_last_action_epoch}}")"
profile_updated_at="$(state_value PROFILE_UPDATED_AT)"
profile_handshake_age_s="$(state_value PROFILE_HANDSHAKE_AGE_S)"
profile_handshake_grace_s="$(state_value PROFILE_HANDSHAKE_GRACE_S)"
profile_wg_path_ok="$(state_value PROFILE_WG_PATH_OK)"
profile_fast_ping_loss_pct="$(state_value PROFILE_FAST_PING_LOSS_PCT)"
profile_stale_handshake_live_path_s="$(state_value PROFILE_STALE_HANDSHAKE_WITH_LIVE_PATH_S)"
good_wg_path_at="$(cache_value GOOD_WG_PATH_AT)"
good_wg_path_at_epoch="$(cache_value GOOD_WG_PATH_AT_EPOCH)"
good_wg_path_age_s="$(age_from_epoch "${{good_wg_path_at_epoch}}")"
good_wg_path_source="$(cache_value GOOD_WG_PATH_SOURCE)"
good_wg_path_handshake_age_s="$(cache_value GOOD_WG_PATH_HANDSHAKE_AGE_S)"
good_cache_ttl_seconds="$(cache_value GOOD_CACHE_TTL_SECONDS)"
route_fail_cache_ttl_seconds="$(cache_value ROUTE_FAIL_CACHE_TTL_SECONDS)"
route_fail_ipv4_literal_count="$(cache_value ROUTE_FAIL_IPV4_LITERAL_COUNT)"
route_fail_ipv4_literal_top_dest="$(cache_value ROUTE_FAIL_IPV4_LITERAL_TOP_DEST)"
route_fail_ipv4_literal_last_at="$(cache_value ROUTE_FAIL_IPV4_LITERAL_LAST_AT)"
route_fail_ipv4_literal_last_epoch="$(cache_value ROUTE_FAIL_IPV4_LITERAL_LAST_EPOCH)"
route_fail_ipv4_literal_age_s="$(age_from_epoch "${{route_fail_ipv4_literal_last_epoch}}")"
route_fail_ipv6_literal_count="$(cache_value ROUTE_FAIL_IPV6_LITERAL_COUNT)"
route_fail_ipv6_literal_top_dest="$(cache_value ROUTE_FAIL_IPV6_LITERAL_TOP_DEST)"
route_fail_ipv6_literal_last_at="$(cache_value ROUTE_FAIL_IPV6_LITERAL_LAST_AT)"
route_fail_ipv6_literal_last_epoch="$(cache_value ROUTE_FAIL_IPV6_LITERAL_LAST_EPOCH)"
route_fail_ipv6_literal_age_s="$(age_from_epoch "${{route_fail_ipv6_literal_last_epoch}}")"
reality_invalid_recent_count="0"
reality_invalid_recent_sources=""
guard_last_run="$(guard_state_value GUARD_LAST_RUN_AT)"
guard_ssh_blocked_count="$(guard_state_value GUARD_SSH_BLOCKED_COUNT)"
guard_reality_blocked_count="$(guard_state_value GUARD_REALITY_BLOCKED_COUNT)"
singbox_to_foreign_timeout_count="0"
singbox_to_foreign_ip_literal_timeout_count="0"
singbox_to_foreign_ipv6_literal_timeout_count="0"
singbox_direct_ru_timeout_count="0"
singbox_dns_timeout_count="0"
singbox_recent_timeout_sample=""
singbox_log_window_minutes="30"
singbox_recent_blocked_count="0"
singbox_recent_mux_closed_count="0"
singbox_recent_eof_count="0"
singbox_recent_dns_failed_count="0"
singbox_recent_timeout_count="0"
singbox_recent_invalid_reality_count="0"
singbox_recent_sources=""
singbox_recent_blocked_destinations=""
singbox_recent_to_foreign_count="0"
singbox_recent_to_foreign_ip_literal_count="0"
singbox_recent_to_foreign_ipv6_literal_count="0"
singbox_recent_direct_ru_count="0"
singbox_recent_to_foreign_destinations=""
singbox_recent_to_foreign_ip_literal_destinations=""
singbox_recent_to_foreign_ipv6_literal_destinations=""
singbox_recent_direct_ru_destinations=""
singbox_recent_timeout_destinations=""
singbox_recent_ip_literal_timeout_destinations=""
singbox_recent_ipv6_literal_count="0"
singbox_recent_ipv6_literal_destinations=""
singbox_recent_mux_sources=""
singbox_recent_inbound_destinations=""
singbox_recent_error_sample=""
xray_log_window_minutes="30"
xray_recent_error_count="0"
xray_recent_invalid_reality_count="0"
xray_recent_disabled_invalid_count="0"
xray_recent_accepted_count="0"
xray_recent_sources=""
xray_recent_accepted_destinations=""
xray_recent_ipv6_literal_count="0"
xray_recent_ipv6_literal_destinations=""
xray_recent_error_sample=""

if [[ "${{role}}" == "ru-gateway" ]] && command -v journalctl >/dev/null 2>&1; then
  set +o pipefail
  xray_recent_log="$(journalctl -u vpn-stack-xray.service --since "-${{xray_log_window_minutes}} minutes" --no-pager -o cat 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' || true)"
  if [[ -n "${{xray_recent_log}}" ]]; then
    xray_recent_error_count="$(
      printf '%s\n' "${{xray_recent_log}}" |
        grep -Ev 'accepted tcp:disabled[.]invalid' |
        grep -Eic 'error|failed|timeout|refused|reset|EOF|panic|fatal|denied|processed invalid connection' || true
    )"
    xray_recent_invalid_reality_count="$(grep -c 'REALITY: processed invalid connection' <<<"${{xray_recent_log}}" || true)"
    xray_recent_disabled_invalid_count="$(grep -c 'accepted tcp:disabled[.]invalid' <<<"${{xray_recent_log}}" || true)"
    xray_recent_accepted_count="$(grep -c 'accepted tcp:' <<<"${{xray_recent_log}}" || true)"
    xray_recent_sources="$(
      printf '%s\n' "${{xray_recent_log}}" |
        sed -n 's/.*from \\([^: ]*\\):[0-9][0-9]* accepted tcp:.*/\\1/p; s/.*REALITY: processed invalid connection from \\([^: ]*\\):.*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    xray_recent_accepted_destinations="$(
      printf '%s\n' "${{xray_recent_log}}" |
        sed -n 's/.*accepted tcp:\\([^ ]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 12 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    xray_recent_ipv6_literal_count="$(grep -Ec 'accepted tcp:\\[[0-9A-Fa-f:.]+\\]:' <<<"${{xray_recent_log}}" || true)"
    xray_recent_ipv6_literal_destinations="$(
      printf '%s\n' "${{xray_recent_log}}" |
        sed -n 's/.*accepted tcp:\\(\\[[0-9A-Fa-f:.]*\\]:[0-9][0-9]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 12 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    xray_recent_error_sample="$(
      printf '%s\n' "${{xray_recent_log}}" |
        (grep -Ei 'error|failed|timeout|refused|reset|invalid|EOF|panic|fatal|denied|processed invalid connection' || true) |
        tail -n1 |
        tr -d '\r' |
        cut -c1-240
    )"
  fi
  singbox_recent_timeouts="$(journalctl -u sing-box --since '4 hours ago' --no-pager 2>/dev/null | grep -E 'i/o timeout|dns: (lookup|exchange) failed|context deadline exceeded' || true)"
  if [[ -n "${{singbox_recent_timeouts}}" ]]; then
    singbox_to_foreign_timeout_count="$(grep -c 'outbound/direct\\[to-foreign\\].*i/o timeout' <<<"${{singbox_recent_timeouts}}" || true)"
    singbox_to_foreign_ip_literal_timeout_count="$(printf '%s\n' "${{singbox_recent_timeouts}}" | grep -E 'outbound/direct\\[to-foreign-ip-literal\\].*i/o timeout' | grep -Ev 'open connection to \\[[0-9A-Fa-f:.]+\\]' | grep -c . || true)"
    singbox_to_foreign_ipv6_literal_timeout_count="$(printf '%s\n' "${{singbox_recent_timeouts}}" | grep -E 'outbound/direct\\[to-foreign-ipv6-literal\\].*i/o timeout|open connection to \\[[0-9A-Fa-f:.]+\\].*outbound/direct\\[to-foreign-ip-literal\\].*i/o timeout' | grep -c . || true)"
    singbox_direct_ru_timeout_count="$(grep -c 'outbound/direct\\[direct-ru\\].*i/o timeout' <<<"${{singbox_recent_timeouts}}" || true)"
    singbox_dns_timeout_count="$(grep -Ec 'dns: (lookup|exchange) failed' <<<"${{singbox_recent_timeouts}}" || true)"
    singbox_recent_timeout_sample="$(tail -n1 <<<"${{singbox_recent_timeouts}}" | tr -d '\\r' | cut -c1-240)"
    singbox_recent_timeout_destinations="$(
      printf '%s\n' "${{singbox_recent_timeouts}}" |
        sed -n 's/.*open connection to \\([^ ]*\\) using outbound\\/direct\\[[^]]*\\].*/\\1/p; s/.*lookup failed for \\([^: ]*\\):.*/\\1/p; s/.*exchange failed for \\([^ ]*\\)\\. IN \\([A-Z0-9][A-Z0-9]*\\):.*/\\1:\\2/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 12 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_ip_literal_timeout_destinations="$(
      printf '%s\n' "${{singbox_recent_timeouts}}" |
        grep -Ev 'open connection to \\[[0-9A-Fa-f:.]+\\]' |
        sed -n 's/.*open connection to \\([^ ]*\\) using outbound\\/direct\\[to-foreign-ip-literal\\].*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 12 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
  fi
  singbox_recent_log="$(journalctl -u sing-box --since "-${{singbox_log_window_minutes}} minutes" --no-pager -o cat 2>/dev/null | sed -r 's/\\x1B\\[[0-9;]*[mK]//g' || true)"
  if [[ -n "${{singbox_recent_log}}" ]]; then
    singbox_recent_blocked_count="$(grep -c 'outbound/block\\[blocked\\]' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_mux_closed_count="$(grep -c 'mux connection closed' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_eof_count="$(grep -c 'EOF' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_dns_failed_count="$(grep -Ec 'dns: (lookup|exchange) failed' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_timeout_count="$(grep -Ec 'i/o timeout|context deadline exceeded' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_invalid_reality_count="$(grep -c 'REALITY: processed invalid connection' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_sources="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        sed -n 's/.*process connection from \\([^: ]*\\):.*/\\1/p; s/.*REALITY: processed invalid connection from \\([^: ]*\\):.*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_blocked_destinations="$(
        printf '%s\n' "${{singbox_recent_log}}" |
        sed -n 's/.*open connection to \\([^ ]*\\) using outbound\\/block.*/\\1/p; s/.*blocked packet connection to \\([^ ]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_to_foreign_count="$(grep -c 'outbound/direct\\[to-foreign\\]: outbound connection to' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_to_foreign_ip_literal_count="$(grep -c 'outbound/direct\\[to-foreign-ip-literal\\]: outbound connection to' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_to_foreign_ipv6_literal_count="$(grep -c 'outbound/direct\\[to-foreign-ipv6-literal\\]: outbound connection to' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_direct_ru_count="$(grep -c 'outbound/direct\\[direct-ru\\]: outbound connection to' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_to_foreign_destinations="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        sed -n 's/.*outbound\\/direct\\[to-foreign\\]: outbound connection to \\([^ ]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_direct_ru_destinations="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        sed -n 's/.*outbound\\/direct\\[direct-ru\\]: outbound connection to \\([^ ]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_to_foreign_ip_literal_destinations="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        sed -n 's/.*outbound\\/direct\\[to-foreign-ip-literal\\]: outbound connection to \\([^ ]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_to_foreign_ipv6_literal_destinations="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        sed -n 's/.*outbound\\/direct\\[to-foreign-ipv6-literal\\]: outbound connection to \\([^ ]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_ipv6_literal_count="$(grep -Ec 'inbound connection to \\[[0-9A-Fa-f:.]+\\]:' <<<"${{singbox_recent_log}}" || true)"
    singbox_recent_ipv6_literal_destinations="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        sed -n 's/.*inbound connection to \\(\\[[0-9A-Fa-f:.]*\\]:[0-9][0-9]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_mux_sources="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        sed -n '/mux connection closed/s/.*process connection from \\([^: ]*\\):.*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 8 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_inbound_destinations="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        sed -n 's/.*inbound packet connection to \\([^ ]*\\).*/\\1/p; s/.*inbound connection to \\([^ ]*\\).*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 12 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
    singbox_recent_error_sample="$(
      printf '%s\n' "${{singbox_recent_log}}" |
        (grep -E 'outbound/block\\[blocked\\]|mux connection closed|dns: (lookup|exchange) failed|i/o timeout|context deadline exceeded|REALITY: processed invalid connection|FATAL|ERROR|EOF' || true) |
        tail -n1 |
        tr -d '\\r' |
        cut -c1-240
    )"
  fi
fi

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

nft_ssh_accept_packets="$(nft_port_packets "${{ssh_port}}" "accept")"
nft_ssh_drop_packets="$(nft_port_packets "${{ssh_port}}" "drop")"
nft_vless_accept_packets="$(nft_port_packets "${{ru_listen_port}}" "accept")"
nft_vless_drop_packets="$(nft_port_packets "${{ru_listen_port}}" "drop")"
if [[ -n "${{nft_vless_accept_packets}}" && -z "${{nft_vless_drop_packets}}" ]]; then
  nft_vless_drop_packets="0"
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

if [[ "${{installed}}" == "1" && "${{role}}" == "foreign-exit" ]]; then
  direct_download_bps="$(probe_download_bps "" "${{throughput_url}}")"
  target_probe_direct="$(probe_target_urls "" "${{target_probe_urls}}" "${{target_probe_connect_timeout}}" "${{target_probe_max_time}}")"
elif [[ "${{installed}}" == "1" && "${{role}}" == "ru-gateway" ]]; then
  direct_download_bps="$(probe_download_bps "" "${{throughput_url}}")"
  target_probe_direct="$(probe_target_urls "" "${{ru_direct_target_probe_urls}}" "${{target_probe_connect_timeout}}" "${{target_probe_max_time}}")"
fi
if [[ "${{installed}}" == "1" && "${{role}}" == "ru-gateway" ]] && ip link show dev {wg_interface} >/dev/null 2>&1; then
  wg_download_bps="$(probe_download_bps "{wg_interface}" "${{throughput_url}}")"
  target_probe_wg="$(probe_target_urls "{wg_interface}" "${{target_probe_urls}}" "${{target_probe_connect_timeout}}" "${{target_probe_max_time}}")"
  ipv6_literal_tcp_probe="$(probe_ipv6_literal_tcp_path "{wg_interface}")"
fi

if command -v wg >/dev/null 2>&1; then
  handshake_row="$(wg show {wg_interface} latest-handshakes 2>/dev/null | awk 'NR==1')"
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

if [[ "${{installed}}" == "1" && "${{role}}" == "ru-gateway" ]] && command -v journalctl >/dev/null 2>&1; then
  set +o pipefail
  reality_invalid_lines="$(journalctl -u vpn-stack-xray.service --since '-30 minutes' --no-pager 2>/dev/null | grep 'REALITY: processed invalid connection' || true)"
  if [[ -n "${{reality_invalid_lines}}" ]]; then
    reality_invalid_recent_count="$(printf '%s\n' "${{reality_invalid_lines}}" | grep -c . || true)"
    reality_invalid_recent_sources="$(
      printf '%s\n' "${{reality_invalid_lines}}" |
        sed -n 's/.*from \\([^: ]*\\):.*/\\1/p' |
        sort |
        uniq -c |
        sort -nr |
        head -n 5 |
        awk 'BEGIN {{ sep="" }} {{ printf "%s%s=%s", sep, $2, $1; sep="," }}'
    )"
  fi
fi
set -o pipefail

printf 'login_user=%s\\n' "${{login_user}}"
printf 'is_root=%s\\n' "${{is_root}}"
printf 'has_sudo=%s\\n' "${{has_sudo}}"
printf 'os_id=%s\\n' "${{os_id}}"
printf 'os_version=%s\\n' "${{os_version}}"
printf 'hostname=%s\\n' "${{hostname_value}}"
printf 'default_iface=%s\\n' "${{default_iface}}"
printf 'configured_wan_interface=%s\\n' "${{configured_wan_interface}}"
printf 'singbox_configured_log_level=%s\\n' "${{singbox_configured_log_level}}"
printf 'global_doh_server=%s\\n' "${{global_doh_server}}"
printf 'global_doh_server_name=%s\\n' "${{global_doh_server_name}}"
printf 'ru_literal_policy=%s\\n' "${{ru_literal_policy}}"
printf 'ru_ipv6_literal_policy=%s\\n' "${{ru_ipv6_literal_policy}}"
printf 'deprecated_routing_overrides=%s\\n' "${{deprecated_routing_overrides}}"
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
printf 'nft_ssh_accept_packets=%s\\n' "${{nft_ssh_accept_packets}}"
printf 'nft_ssh_drop_packets=%s\\n' "${{nft_ssh_drop_packets}}"
printf 'nft_vless_accept_packets=%s\\n' "${{nft_vless_accept_packets}}"
printf 'nft_vless_drop_packets=%s\\n' "${{nft_vless_drop_packets}}"
printf 'target_probe_urls=%s\\n' "${{target_probe_urls}}"
printf 'ru_direct_target_probe_urls=%s\\n' "${{ru_direct_target_probe_urls}}"
printf 'target_probe_connect_timeout_seconds=%s\\n' "${{target_probe_connect_timeout}}"
printf 'target_probe_max_time_seconds=%s\\n' "${{target_probe_max_time}}"
printf 'target_probe_direct=%s\\n' "${{target_probe_direct}}"
printf 'target_probe_wg=%s\\n' "${{target_probe_wg}}"
printf 'ipv6_literal_tcp_probe=%s\\n' "${{ipv6_literal_tcp_probe}}"
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
printf 'fast_foreign_ru_ping_loss_pct=%s\\n' "${{fast_foreign_ru_ping_loss_pct}}"
printf 'fast_ru_foreign_ping_loss_pct=%s\\n' "${{fast_ru_foreign_ping_loss_pct}}"
printf 'self_heal_last_reason=%s\\n' "${{self_heal_last_reason}}"
printf 'self_heal_consecutive=%s\\n' "${{self_heal_consecutive}}"
printf 'self_heal_last_action=%s\\n' "${{self_heal_last_action}}"
printf 'self_heal_last_action_reason=%s\\n' "${{self_heal_last_action_reason}}"
printf 'self_heal_last_action_result=%s\\n' "${{self_heal_last_action_result}}"
printf 'self_heal_last_action_epoch=%s\\n' "${{self_heal_last_action_epoch}}"
printf 'self_heal_last_action_age_s=%s\\n' "${{self_heal_last_action_age_s}}"
printf 'profile_updated_at=%s\\n' "${{profile_updated_at}}"
printf 'profile_handshake_age_s=%s\\n' "${{profile_handshake_age_s}}"
printf 'profile_handshake_grace_s=%s\\n' "${{profile_handshake_grace_s}}"
printf 'profile_wg_path_ok=%s\\n' "${{profile_wg_path_ok}}"
printf 'profile_fast_ping_loss_pct=%s\\n' "${{profile_fast_ping_loss_pct}}"
printf 'profile_stale_handshake_live_path_s=%s\\n' "${{profile_stale_handshake_live_path_s}}"
printf 'good_wg_path_at=%s\\n' "${{good_wg_path_at}}"
printf 'good_wg_path_age_s=%s\\n' "${{good_wg_path_age_s}}"
printf 'good_wg_path_source=%s\\n' "${{good_wg_path_source}}"
printf 'good_wg_path_handshake_age_s=%s\\n' "${{good_wg_path_handshake_age_s}}"
printf 'good_cache_ttl_seconds=%s\\n' "${{good_cache_ttl_seconds}}"
printf 'route_fail_cache_ttl_seconds=%s\\n' "${{route_fail_cache_ttl_seconds}}"
printf 'route_fail_ipv4_literal_count=%s\\n' "${{route_fail_ipv4_literal_count}}"
printf 'route_fail_ipv4_literal_top_dest=%s\\n' "${{route_fail_ipv4_literal_top_dest}}"
printf 'route_fail_ipv4_literal_last_at=%s\\n' "${{route_fail_ipv4_literal_last_at}}"
printf 'route_fail_ipv4_literal_age_s=%s\\n' "${{route_fail_ipv4_literal_age_s}}"
printf 'route_fail_ipv6_literal_count=%s\\n' "${{route_fail_ipv6_literal_count}}"
printf 'route_fail_ipv6_literal_top_dest=%s\\n' "${{route_fail_ipv6_literal_top_dest}}"
printf 'route_fail_ipv6_literal_last_at=%s\\n' "${{route_fail_ipv6_literal_last_at}}"
printf 'route_fail_ipv6_literal_age_s=%s\\n' "${{route_fail_ipv6_literal_age_s}}"
printf 'reality_invalid_recent_count=%s\\n' "${{reality_invalid_recent_count}}"
printf 'reality_invalid_recent_sources=%s\\n' "${{reality_invalid_recent_sources}}"
printf 'singbox_to_foreign_timeout_count=%s\\n' "${{singbox_to_foreign_timeout_count}}"
printf 'singbox_to_foreign_ip_literal_timeout_count=%s\\n' "${{singbox_to_foreign_ip_literal_timeout_count}}"
printf 'singbox_to_foreign_ipv6_literal_timeout_count=%s\\n' "${{singbox_to_foreign_ipv6_literal_timeout_count}}"
printf 'singbox_direct_ru_timeout_count=%s\\n' "${{singbox_direct_ru_timeout_count}}"
printf 'singbox_dns_timeout_count=%s\\n' "${{singbox_dns_timeout_count}}"
printf 'singbox_recent_timeout_sample=%s\\n' "${{singbox_recent_timeout_sample}}"
printf 'singbox_log_window_minutes=%s\\n' "${{singbox_log_window_minutes}}"
printf 'singbox_recent_blocked_count=%s\\n' "${{singbox_recent_blocked_count}}"
printf 'singbox_recent_mux_closed_count=%s\\n' "${{singbox_recent_mux_closed_count}}"
printf 'singbox_recent_eof_count=%s\\n' "${{singbox_recent_eof_count}}"
printf 'singbox_recent_dns_failed_count=%s\\n' "${{singbox_recent_dns_failed_count}}"
printf 'singbox_recent_timeout_count=%s\\n' "${{singbox_recent_timeout_count}}"
printf 'singbox_recent_invalid_reality_count=%s\\n' "${{singbox_recent_invalid_reality_count}}"
printf 'singbox_recent_sources=%s\\n' "${{singbox_recent_sources}}"
printf 'singbox_recent_blocked_destinations=%s\\n' "${{singbox_recent_blocked_destinations}}"
printf 'singbox_recent_to_foreign_count=%s\\n' "${{singbox_recent_to_foreign_count}}"
printf 'singbox_recent_to_foreign_ip_literal_count=%s\\n' "${{singbox_recent_to_foreign_ip_literal_count}}"
printf 'singbox_recent_to_foreign_ipv6_literal_count=%s\\n' "${{singbox_recent_to_foreign_ipv6_literal_count}}"
printf 'singbox_recent_direct_ru_count=%s\\n' "${{singbox_recent_direct_ru_count}}"
printf 'singbox_recent_to_foreign_destinations=%s\\n' "${{singbox_recent_to_foreign_destinations}}"
printf 'singbox_recent_to_foreign_ip_literal_destinations=%s\\n' "${{singbox_recent_to_foreign_ip_literal_destinations}}"
printf 'singbox_recent_to_foreign_ipv6_literal_destinations=%s\\n' "${{singbox_recent_to_foreign_ipv6_literal_destinations}}"
printf 'singbox_recent_direct_ru_destinations=%s\\n' "${{singbox_recent_direct_ru_destinations}}"
printf 'singbox_recent_timeout_destinations=%s\\n' "${{singbox_recent_timeout_destinations}}"
printf 'singbox_recent_ip_literal_timeout_destinations=%s\\n' "${{singbox_recent_ip_literal_timeout_destinations}}"
printf 'singbox_recent_ipv6_literal_count=%s\\n' "${{singbox_recent_ipv6_literal_count}}"
printf 'singbox_recent_ipv6_literal_destinations=%s\\n' "${{singbox_recent_ipv6_literal_destinations}}"
printf 'singbox_recent_mux_sources=%s\\n' "${{singbox_recent_mux_sources}}"
printf 'singbox_recent_inbound_destinations=%s\\n' "${{singbox_recent_inbound_destinations}}"
printf 'singbox_recent_error_sample=%s\\n' "${{singbox_recent_error_sample}}"
printf 'xray_log_window_minutes=%s\\n' "${{xray_log_window_minutes}}"
printf 'xray_recent_error_count=%s\\n' "${{xray_recent_error_count}}"
printf 'xray_recent_invalid_reality_count=%s\\n' "${{xray_recent_invalid_reality_count}}"
printf 'xray_recent_disabled_invalid_count=%s\\n' "${{xray_recent_disabled_invalid_count}}"
printf 'xray_recent_accepted_count=%s\\n' "${{xray_recent_accepted_count}}"
printf 'xray_recent_sources=%s\\n' "${{xray_recent_sources}}"
printf 'xray_recent_accepted_destinations=%s\\n' "${{xray_recent_accepted_destinations}}"
printf 'xray_recent_ipv6_literal_count=%s\\n' "${{xray_recent_ipv6_literal_count}}"
printf 'xray_recent_ipv6_literal_destinations=%s\\n' "${{xray_recent_ipv6_literal_destinations}}"
printf 'xray_recent_error_sample=%s\\n' "${{xray_recent_error_sample}}"
printf 'guard_last_run=%s\\n' "${{guard_last_run}}"
printf 'guard_ssh_blocked_count=%s\\n' "${{guard_ssh_blocked_count}}"
printf 'guard_reality_blocked_count=%s\\n' "${{guard_reality_blocked_count}}"
printf 'installed=%s\\n' "${{installed}}"
printf 'deployment_name=%s\\n' "${{deployment_name}}"
printf 'role=%s\\n' "${{role}}"
printf 'installed_at=%s\\n' "${{installed_at}}"
printf 'installed_env_sha256=%s\\n' "${{installed_env_sha256}}"
printf 'installed_singbox_sha256=%s\\n' "${{installed_singbox_sha256}}"
printf 'installed_singbox_base_sha256=%s\\n' "${{installed_singbox_base_sha256}}"
printf 'render_manifest_policy_version=%s\\n' "${{render_manifest_policy_version}}"
printf 'render_manifest_singbox_sha256=%s\\n' "${{render_manifest_singbox_sha256}}"
printf 'drift=%s\\n' "${{drift}}"
printf 'sing_box=%s\\n' "$(service_state sing-box)"
printf 'xray=%s\\n' "$(service_state vpn-stack-xray.service)"
printf 'nftables=%s\\n' "$(service_state nftables)"
printf 'wireguard=%s\\n' "$(service_state wg-quick@{wg_interface})"
printf 'sync_timer=%s\\n' "$(service_state vpn-stack-sync.timer)"
printf 'health_timer=%s\\n' "$(service_state vpn-stack-health.timer)"
printf 'guard_timer=%s\\n' "$(service_state vpn-stack-guard.timer)"
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
    singbox_log_level = preflight.get("singbox_configured_log_level", "").strip().lower()
    if preflight.get("role") == "ru-gateway" and singbox_log_level and singbox_log_level != "info":
        print(
            "warning: sing-box log level is "
            f"{singbox_log_level}; routed diagnostics need info-level connection logs."
        )
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
    if preflight.get("drift"):
        print(f"drift: {preflight.get('drift', '-')}")
    if preflight.get("render_manifest_policy_version"):
        print(f"routing policy version: {preflight.get('render_manifest_policy_version', '-')}")
    if preflight.get("ru_literal_policy") or preflight.get("ru_ipv6_literal_policy"):
        print(
            "literal policy: "
            f"ipv4={preflight.get('ru_literal_policy', '-')}, "
            f"ipv6={preflight.get('ru_ipv6_literal_policy', '-')}"
        )
    if preflight.get("deprecated_routing_overrides"):
        print(f"deprecated routing overrides: {preflight.get('deprecated_routing_overrides')}")
    print(f"sing-box: {preflight.get('sing_box', '-')}")
    print(f"xray: {preflight.get('xray', '-')}")
    print(f"nftables: {preflight.get('nftables', '-')}")
    if any(preflight.get(key) for key in ("nft_ssh_accept_packets", "nft_ssh_drop_packets", "nft_vless_accept_packets", "nft_vless_drop_packets")):
        print(f"nft SSH accept/drop packets: {preflight.get('nft_ssh_accept_packets', '-')}/{preflight.get('nft_ssh_drop_packets', '-')}")
        print(f"nft VLESS accept/drop packets: {preflight.get('nft_vless_accept_packets', '-')}/{preflight.get('nft_vless_drop_packets', '-')}")
    print(f"wireguard: {preflight.get('wireguard', '-')}")
    print(f"wireguard transfer rx/tx: {preflight.get('wg_transfer_rx', '-')}/{preflight.get('wg_transfer_tx', '-')}")
    print(f"wireguard latest handshake: {preflight.get('wg_latest_handshake', '-')}")
    print(f"wireguard handshake age (s): {preflight.get('wg_latest_handshake_age_s', '-')}")
    print(f"observed IPv4: {preflight.get('observed_ipv4', '-')}")
    print(f"RU over wg IPv4: {preflight.get('wg_observed_ipv4', '-')}")
    print(f"direct download B/s: {preflight.get('direct_download_bps', '-')}")
    print(f"RU over wg download B/s: {preflight.get('wg_download_bps', '-')}")
    if preflight.get("target_probe_direct") or preflight.get("target_probe_wg"):
        print(f"target probes direct: {preflight.get('target_probe_direct', '-')}")
        print(f"target probes RU over wg: {preflight.get('target_probe_wg', '-')}")
    if preflight.get("ipv6_literal_tcp_probe"):
        print(f"IPv6 literal TCP path: {preflight.get('ipv6_literal_tcp_probe', '-')}")
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
    if preflight.get("fast_foreign_ru_ping_loss_pct") or preflight.get("fast_ru_foreign_ping_loss_pct"):
        print(f"fast foreign->RU ping loss (%): {preflight.get('fast_foreign_ru_ping_loss_pct', '-')}")
        print(f"fast RU->foreign ping loss (%): {preflight.get('fast_ru_foreign_ping_loss_pct', '-')}")
    if preflight.get("profile_updated_at"):
        print(f"runtime profile at: {preflight.get('profile_updated_at', '-')}")
        print(f"profile handshake age/grace (s): {preflight.get('profile_handshake_age_s', '-')}/{preflight.get('profile_handshake_grace_s', '-')}")
        print(f"profile wg path ok: {preflight.get('profile_wg_path_ok', '-')}")
        print(f"profile fast ping loss (%): {preflight.get('profile_fast_ping_loss_pct', '-')}")
        if preflight.get("profile_stale_handshake_live_path_s"):
            print(f"profile stale handshake with live path (s): {preflight.get('profile_stale_handshake_live_path_s', '-')}")
    if preflight.get("good_wg_path_at"):
        print(
            "dataplane cache good WG path: "
            f"age={preflight.get('good_wg_path_age_s', '-')}s/"
            f"ttl={preflight.get('good_cache_ttl_seconds', '-')}s, "
            f"source={preflight.get('good_wg_path_source', '-')}, "
            f"handshake_age={preflight.get('good_wg_path_handshake_age_s', '-')}s"
        )
    route_cache_keys = (
        "route_fail_ipv4_literal_count",
        "route_fail_ipv6_literal_count",
    )
    if any(preflight.get(key) not in {"", None, "0"} for key in route_cache_keys):
        print(
            "dataplane route-fail cache: "
            f"ttl={preflight.get('route_fail_cache_ttl_seconds', '-')}s, "
            f"ipv4_literal={preflight.get('route_fail_ipv4_literal_count', '0')}"
            f"@{preflight.get('route_fail_ipv4_literal_age_s', '-')}s "
            f"{preflight.get('route_fail_ipv4_literal_top_dest', '')}, "
            f"ipv6_literal={preflight.get('route_fail_ipv6_literal_count', '0')}"
            f"@{preflight.get('route_fail_ipv6_literal_age_s', '-')}s "
            f"{preflight.get('route_fail_ipv6_literal_top_dest', '')}"
        )
    if preflight.get("self_heal_last_action") or preflight.get("self_heal_last_reason"):
        print(f"self-heal last reason: {preflight.get('self_heal_last_reason', '-')}")
        print(f"self-heal consecutive: {preflight.get('self_heal_consecutive', '-')}")
        print(
            "self-heal last action: "
            f"{preflight.get('self_heal_last_action', '-')}/"
            f"{preflight.get('self_heal_last_action_result', '-')}"
            f" age={preflight.get('self_heal_last_action_age_s', '-')}s"
        )
        print(f"self-heal last action reason: {preflight.get('self_heal_last_action_reason', '-')}")
    if preflight.get("reality_invalid_recent_count") not in {"", None, "0"}:
        print(f"recent invalid Reality handshakes: {preflight.get('reality_invalid_recent_count', '-')}")
        print(f"invalid Reality sources: {preflight.get('reality_invalid_recent_sources', '-')}")
        print("diagnosis: invalid Reality happens before routing; if this is your IP, at least one active client/profile does not match current generated credentials.")
    if any(preflight.get(key) not in {"", None, "0"} for key in ("singbox_to_foreign_timeout_count", "singbox_to_foreign_ip_literal_timeout_count", "singbox_to_foreign_ipv6_literal_timeout_count", "singbox_direct_ru_timeout_count", "singbox_dns_timeout_count")):
        print(f"sing-box to-foreign timeouts / 4h: {preflight.get('singbox_to_foreign_timeout_count', '0')}")
        print(f"sing-box IPv4-literal to-foreign timeouts / 4h: {preflight.get('singbox_to_foreign_ip_literal_timeout_count', '0')}")
        print(f"sing-box IPv6-literal to-foreign timeouts / 4h: {preflight.get('singbox_to_foreign_ipv6_literal_timeout_count', '0')}")
        print(f"sing-box direct-ru timeouts / 4h: {preflight.get('singbox_direct_ru_timeout_count', '0')}")
        print(f"sing-box DNS timeouts / 4h: {preflight.get('singbox_dns_timeout_count', '0')}")
        if preflight.get("global_doh_server") or preflight.get("global_doh_server_name"):
            print(
                "sing-box global DoH: "
                f"{preflight.get('global_doh_server', '-')}/"
                f"{preflight.get('global_doh_server_name', '-')}"
            )
        if preflight.get("singbox_recent_ip_literal_timeout_destinations"):
            print(f"sing-box IP-literal timeout destinations / 4h: {preflight.get('singbox_recent_ip_literal_timeout_destinations')}")
        if preflight.get("singbox_recent_timeout_destinations"):
            print(f"sing-box timeout destinations / 4h: {preflight.get('singbox_recent_timeout_destinations')}")
        print(f"sing-box last timeout sample: {preflight.get('singbox_recent_timeout_sample', '-')}")
    xray_keys = (
        "xray_recent_error_count",
        "xray_recent_invalid_reality_count",
        "xray_recent_disabled_invalid_count",
        "xray_recent_accepted_count",
        "xray_recent_ipv6_literal_count",
    )
    if any(preflight.get(key) not in {"", None, "0"} for key in xray_keys):
        print(f"Xray front recent window (min): {preflight.get('xray_log_window_minutes', '-')}")
        print(
            "Xray front recent: "
            f"accepted={preflight.get('xray_recent_accepted_count', '0')}, "
            f"errors={preflight.get('xray_recent_error_count', '0')}, "
            f"invalid_reality={preflight.get('xray_recent_invalid_reality_count', '0')}, "
            f"disabled_invalid={preflight.get('xray_recent_disabled_invalid_count', '0')}, "
            f"ipv6_literals={preflight.get('xray_recent_ipv6_literal_count', '0')}"
        )
        if preflight.get("xray_recent_sources"):
            print(f"Xray front recent sources: {preflight.get('xray_recent_sources')}")
        if preflight.get("xray_recent_accepted_destinations"):
            print(f"Xray front recent destinations: {preflight.get('xray_recent_accepted_destinations')}")
        if preflight.get("xray_recent_ipv6_literal_destinations"):
            print(f"Xray front recent IPv6 literal destinations: {preflight.get('xray_recent_ipv6_literal_destinations')}")
        if preflight.get("xray_recent_error_sample"):
            print(f"Xray front recent sample: {preflight.get('xray_recent_error_sample')}")
    recent_singbox_keys = (
        "singbox_recent_blocked_count",
        "singbox_recent_mux_closed_count",
        "singbox_recent_eof_count",
        "singbox_recent_dns_failed_count",
        "singbox_recent_timeout_count",
        "singbox_recent_invalid_reality_count",
    )
    if any(preflight.get(key) not in {"", None, "0"} for key in recent_singbox_keys):
        print(f"sing-box recent window (min): {preflight.get('singbox_log_window_minutes', '-')}")
        print(
            "sing-box recent grouped errors: "
            f"blocked={preflight.get('singbox_recent_blocked_count', '0')}, "
            f"mux_closed={preflight.get('singbox_recent_mux_closed_count', '0')}, "
            f"eof={preflight.get('singbox_recent_eof_count', '0')}, "
            f"dns_failed={preflight.get('singbox_recent_dns_failed_count', '0')}, "
            f"timeout={preflight.get('singbox_recent_timeout_count', '0')}, "
            f"invalid_reality={preflight.get('singbox_recent_invalid_reality_count', '0')}"
        )
        if preflight.get("singbox_recent_sources"):
            print(f"sing-box recent sources: {preflight.get('singbox_recent_sources')}")
        if preflight.get("singbox_recent_blocked_destinations"):
            print(f"sing-box recent blocked destinations: {preflight.get('singbox_recent_blocked_destinations')}")
        if preflight.get("singbox_recent_mux_sources"):
            print(f"sing-box recent mux sources: {preflight.get('singbox_recent_mux_sources')}")
        if preflight.get("singbox_recent_error_sample"):
            print(f"sing-box recent sample: {preflight.get('singbox_recent_error_sample')}")
    recent_route_keys = (
        "singbox_recent_to_foreign_count",
        "singbox_recent_to_foreign_ip_literal_count",
        "singbox_recent_to_foreign_ipv6_literal_count",
        "singbox_recent_direct_ru_count",
        "singbox_recent_ipv6_literal_count",
    )
    if any(preflight.get(key) not in {"", None, "0"} for key in recent_route_keys):
        print(
            "sing-box recent routed: "
            f"to_foreign={preflight.get('singbox_recent_to_foreign_count', '0')}, "
            f"to_foreign_ip_literal={preflight.get('singbox_recent_to_foreign_ip_literal_count', '0')}, "
            f"to_foreign_ipv6_literal={preflight.get('singbox_recent_to_foreign_ipv6_literal_count', '0')}, "
            f"direct_ru={preflight.get('singbox_recent_direct_ru_count', '0')}, "
            f"ipv6_literals={preflight.get('singbox_recent_ipv6_literal_count', '0')}"
        )
        if preflight.get("singbox_recent_to_foreign_destinations"):
            print(f"sing-box recent to-foreign destinations: {preflight.get('singbox_recent_to_foreign_destinations')}")
        if preflight.get("singbox_recent_to_foreign_ip_literal_destinations"):
            print(f"sing-box recent IPv4-literal to-foreign destinations: {preflight.get('singbox_recent_to_foreign_ip_literal_destinations')}")
        if preflight.get("singbox_recent_to_foreign_ipv6_literal_destinations"):
            print(f"sing-box recent IPv6-literal to-foreign destinations: {preflight.get('singbox_recent_to_foreign_ipv6_literal_destinations')}")
        if preflight.get("singbox_recent_direct_ru_destinations"):
            print(f"sing-box recent direct-ru destinations: {preflight.get('singbox_recent_direct_ru_destinations')}")
        if preflight.get("singbox_recent_ipv6_literal_destinations"):
            print(f"sing-box recent IPv6 literal destinations: {preflight.get('singbox_recent_ipv6_literal_destinations')}")
            if preflight.get("ru_ipv6_literal_policy") == "reject":
                print("diagnosis: clients sent IPv6 literal destinations; current RU IPv6 literal policy rejects new IPv6 literals fail-fast.")
            else:
                print("diagnosis: clients sent IPv6 literal destinations; current RU IPv6 literal policy routes them through the dedicated IPv6-literal foreign outbound.")
        if preflight.get("singbox_recent_inbound_destinations"):
            print(f"sing-box recent inbound destinations: {preflight.get('singbox_recent_inbound_destinations')}")
    if preflight.get("guard_last_run"):
        print(f"guard timer: {preflight.get('guard_timer', '-')}")
        print(f"guard last run: {preflight.get('guard_last_run', '-')}")
        print(f"guard blocked SSH/REALITY sources: {preflight.get('guard_ssh_blocked_count', '-')}/{preflight.get('guard_reality_blocked_count', '-')}")
    print(f"sync timer: {preflight.get('sync_timer', '-')}")
    print(f"health timer: {preflight.get('health_timer', '-')}")
    if not preflight.get("guard_last_run"):
        print(f"guard timer: {preflight.get('guard_timer', '-')}")
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
