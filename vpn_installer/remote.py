from __future__ import annotations

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


def ensure_paramiko_installed():
    return ensure_python_package("paramiko", "paramiko>=3.5,<4")


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
if [[ -r /etc/vpn-stack/deployment.env ]]; then
  installed="1"
  deployment_name="$(grep -E '^DEPLOY_NAME=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//')"
fi
if [[ -r /etc/vpn-stack/role ]]; then role="$(tr -d '\\r\\n' </etc/vpn-stack/role)"; fi
if [[ -r /etc/vpn-stack/installed_at ]]; then installed_at="$(tr -d '\\r\\n' </etc/vpn-stack/installed_at)"; fi

default_iface="$(ip route show default 2>/dev/null | awk '/default/ {{print $5; exit}}')"
hostname_value="$(hostname -f 2>/dev/null || hostname)"

printf 'login_user=%s\\n' "${{login_user}}"
printf 'is_root=%s\\n' "${{is_root}}"
printf 'has_sudo=%s\\n' "${{has_sudo}}"
printf 'os_id=%s\\n' "${{os_id}}"
printf 'os_version=%s\\n' "${{os_version}}"
printf 'hostname=%s\\n' "${{hostname_value}}"
printf 'default_iface=%s\\n' "${{default_iface}}"
printf 'installed=%s\\n' "${{installed}}"
printf 'deployment_name=%s\\n' "${{deployment_name}}"
printf 'role=%s\\n' "${{role}}"
printf 'installed_at=%s\\n' "${{installed_at}}"
printf 'sing_box=%s\\n' "$(service_state sing-box)"
printf 'nftables=%s\\n' "$(service_state nftables)"
printf 'wireguard=%s\\n' "$(service_state wg-quick@{wg_interface})"
printf 'sync_timer=%s\\n' "$(service_state vpn-stack-sync.timer)"
printf 'subscription_server=%s\\n' "$(service_state vpn-stack-subscription.service)"
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
    print(f"installed: {preflight.get('installed', '0')}")
    print(f"role: {preflight.get('role', '-')}")
    print(f"deployment: {preflight.get('deployment_name', '-')}")
    print(f"sing-box: {preflight.get('sing_box', '-')}")
    print(f"nftables: {preflight.get('nftables', '-')}")
    print(f"wireguard: {preflight.get('wireguard', '-')}")
    print(f"sync timer: {preflight.get('sync_timer', '-')}")
    print(f"subscription server: {preflight.get('subscription_server', '-')}")


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
