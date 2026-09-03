from __future__ import annotations

import logging
import base64
import hashlib
import json
import os
import shlex
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from .common import STATE_DIR, command_exists, fail, print_header, run_command
from .compatibility import require_compatible_installed
from .diagnostics import SCHEMA_VERSION as DIAGNOSTICS_SCHEMA_VERSION, DiagnosticsSnapshot
from .models import AppError, RemoteTarget
from .runtime_deps import ensure_python_package

SSH_CONNECT_TIMEOUT = 20
SSH_BANNER_TIMEOUT = 20
SSH_AUTH_TIMEOUT = 45
SSH_COMMAND_TIMEOUT = 1800
SSH_COMMAND_TIMEOUT_GRACE = 10
SSH_UPLOAD_TIMEOUT = 300
SSH_CAPTURE_MAX_BYTES = 16 * 1024 * 1024
SSH_PASSWORD_AUTH_RETRIES = 3
SSH_PASSWORD_AUTH_RETRY_DELAY = 1.0
SSH_BANNER_RETRIES = 3
SSH_BANNER_RETRY_DELAY = 1.0
SSH_CONNECT_RETRY_DELAY = 1.0
_PARAMIKO_LOGGER_CONFIGURED = False
_KNOWN_HOSTS_LOCK = threading.Lock()
KNOWN_HOSTS_PATH = STATE_DIR / "known_hosts"


def ensure_known_hosts_file() -> Path:
    KNOWN_HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    KNOWN_HOSTS_PATH.touch(exist_ok=True)
    return KNOWN_HOSTS_PATH


def host_key_alias(target: RemoteTarget) -> str:
    return target.ssh_host if target.ssh_port == 22 else f"[{target.ssh_host}]:{target.ssh_port}"


def persist_host_key(hostname: str, key: Any) -> None:
    paramiko = ensure_paramiko_installed()
    path = ensure_known_hosts_file()
    with _KNOWN_HOSTS_LOCK:
        host_keys = paramiko.HostKeys()
        if path.stat().st_size:
            host_keys.load(str(path))
        host_keys.add(hostname, key.get_name(), key)
        fd, tmp_name = tempfile.mkstemp(prefix=".known_hosts.", dir=str(path.parent))
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            host_keys.save(str(tmp_path))
            os.replace(tmp_path, path)
        finally:
            tmp_path.unlink(missing_ok=True)


def host_key_fingerprint(key: Any) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def probe_host_key(target: RemoteTarget) -> Any:
    paramiko = ensure_paramiko_installed()
    sock = open_ssh_socket(target)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=SSH_BANNER_TIMEOUT)
        key = transport.get_remote_server_key()
        if key is None:
            raise AppError(f"{target.label}: SSH-сервер не предоставил host key.")
        return key
    except AppError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AppError(f"{target.label}: не удалось получить SSH host key: {exc}") from exc
    finally:
        transport.close()


def ensure_target_host_key(
    target: RemoteTarget,
    *,
    allow_enroll: bool,
    prompt_yes_no: Any | None = None,
) -> None:
    paramiko = ensure_paramiko_installed()
    alias = host_key_alias(target)
    managed = paramiko.HostKeys()
    managed_path = ensure_known_hosts_file()
    if managed_path.stat().st_size:
        managed.load(str(managed_path))
    if managed.lookup(alias) is not None:
        return

    key = probe_host_key(target)
    fingerprint = host_key_fingerprint(key)
    system_client = paramiko.SSHClient()
    system_client.load_system_host_keys()
    system_entry = getattr(system_client, "_system_host_keys", paramiko.HostKeys()).lookup(alias)
    if system_entry is not None:
        trusted = system_entry.get(key.get_name())
        if trusted is not None and trusted.asbytes() == key.asbytes():
            persist_host_key(alias, key)
            return
    if not allow_enroll or prompt_yes_no is None:
        raise AppError(
            f"{target.label}: неизвестный SSH host key {key.get_name()} {fingerprint}. "
            "Первое доверие разрешено только в интерактивном режиме."
        )
    if not prompt_yes_no(
        f"{target.label}: доверять SSH host key {key.get_name()} {fingerprint}?",
        default=False,
    ):
        raise AppError(f"{target.label}: SSH host key не подтверждён.")
    persist_host_key(alias, key)


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


def canonical_host_key_type(algorithm: str) -> str:
    base = algorithm.removesuffix("-cert-v01@openssh.com")
    if base in {"rsa-sha2-256", "rsa-sha2-512"}:
        return "ssh-rsa"
    return base


def known_host_key_types(client: Any, hostname: str) -> set[str]:
    result: set[str] = set()
    for store in (getattr(client, "_system_host_keys", None), getattr(client, "_host_keys", None)):
        if store is None:
            continue
        try:
            entry = store.lookup(hostname)
            if entry is not None:
                result.update(str(key_type) for key_type in entry.keys())
        except (AttributeError, TypeError):
            continue
    return result


def load_trusted_host_keys(client: Any, hostname: str) -> Path:
    known_hosts = ensure_known_hosts_file()
    if known_hosts.stat().st_size:
        client.load_host_keys(str(known_hosts))
    return known_hosts


def known_host_disabled_algorithms(paramiko: Any, client: Any, hostname: str) -> dict[str, list[str]] | None:
    known_types = known_host_key_types(client, hostname)
    if not known_types:
        return None
    try:
        preferred = tuple(str(item) for item in paramiko.Transport._preferred_keys)  # noqa: SLF001
    except (AttributeError, TypeError):
        return None
    disabled = [algorithm for algorithm in preferred if canonical_host_key_type(algorithm) not in known_types]
    return {"keys": disabled} if disabled else None


def use_python_ssh_backend(target: RemoteTarget) -> bool:
    return target.auth_mode == "password" or not (command_exists("ssh") and command_exists("scp"))


def system_key_auth_args() -> list[str]:
    options = (
        "BatchMode=yes",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "PreferredAuthentications=publickey",
        "LogLevel=ERROR",
    )
    return [item for option in options for item in ("-o", option)]


def ssh_base_args(target: RemoteTarget) -> list[str]:
    known_hosts = ensure_known_hosts_file()
    args = [
        "ssh",
        *system_key_auth_args(),
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-p",
        str(target.ssh_port),
    ]
    if target.ssh_bind_address:
        args.extend(["-o", f"BindAddress={target.ssh_bind_address}"])
    if target.identity_path:
        args.extend(["-i", target.identity_path])
    args.append(f"{target.ssh_user}@{target.ssh_host}")
    return args


def scp_base_args(target: RemoteTarget) -> list[str]:
    known_hosts = ensure_known_hosts_file()
    args = [
        "scp",
        *system_key_auth_args(),
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-P",
        str(target.ssh_port),
    ]
    if target.ssh_bind_address:
        args.extend(["-o", f"BindAddress={target.ssh_bind_address}"])
    if target.identity_path:
        args.extend(["-i", target.identity_path])
    return args


def build_remote_command(
    command_body: str,
    target: RemoteTarget,
    as_root: bool,
    *,
    command_timeout: int = SSH_COMMAND_TIMEOUT,
) -> tuple[str, str | None]:
    input_text: str | None = None
    shell_command = f"bash -lc {shlex.quote(command_body)}"
    if command_timeout > 0:
        shell_command = f"timeout --signal=TERM --kill-after=5s {int(command_timeout)}s {shell_command}"
    if as_root and target.ssh_user != "root":
        if target.sudo_mode == "nopasswd":
            shell_command = f"sudo -n {shell_command}"
        elif target.sudo_mode == "password":
            shell_command = f"sudo -S -p '' {shell_command}"
            input_text = f"{target.sudo_password}\n"
        else:
            fail(f"Для {target.label} не подтверждён root/sudo доступ.")
    return shell_command, input_text


def open_bound_ssh_socket(target: RemoteTarget) -> socket.socket:
    """Open an explicitly bound SSH transport without changing the client route table."""
    try:
        source_info = socket.getaddrinfo(target.ssh_bind_address, 0, type=socket.SOCK_STREAM)[0]
        family = source_info[0]
        destination = socket.getaddrinfo(target.ssh_host, target.ssh_port, family=family, type=socket.SOCK_STREAM)[0][4]
    except OSError as exc:
        raise AppError(f"Не удалось подготовить SSH bind {target.ssh_bind_address} для {target.label}: {exc}") from exc
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(SSH_CONNECT_TIMEOUT)
        sock.bind(source_info[4])
        sock.connect(destination)
        return sock
    except OSError as exc:
        sock.close()
        raise AppError(f"Прямой SSH через {target.ssh_bind_address} к {target.label} недоступен: {exc}") from exc


def open_ssh_socket(target: RemoteTarget) -> socket.socket:
    if target.ssh_bind_address:
        return open_bound_ssh_socket(target)
    try:
        return socket.create_connection((target.ssh_host, target.ssh_port), timeout=SSH_CONNECT_TIMEOUT)
    except OSError as exc:
        raise AppError(f"Прямой SSH к {target.label} недоступен: {exc}") from exc


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
        alias = host_key_alias(target)
        load_trusted_host_keys(client, alias)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        bound_socket: socket.socket | None = None
        try:
            attempt_kwargs = connect_kwargs.copy()
            disabled_algorithms = known_host_disabled_algorithms(paramiko, client, alias)
            if disabled_algorithms:
                attempt_kwargs["disabled_algorithms"] = disabled_algorithms
            if target.ssh_bind_address:
                bound_socket = open_bound_ssh_socket(target)
                attempt_kwargs["sock"] = bound_socket
            client.connect(**attempt_kwargs)
            return client
        except Exception as exc:  # noqa: BLE001
            client.close()
            if bound_socket is not None:
                bound_socket.close()
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
            error_text = str(exc).lower()
            banner_timeout = "error reading ssh protocol banner" in error_text
            if banner_timeout and attempt < attempts:
                time.sleep(SSH_BANNER_RETRY_DELAY * attempt)
                continue
            if banner_timeout:
                raise AppError(
                    f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}\n"
                    "Сервер не отдал SSH banner вовремя. Обычно это означает перегруженный или подвисший SSH на хосте, сетевой фильтр перед ним или только что перезагружающийся сервер."
                ) from exc
            if target.auth_mode == "password" and isinstance(exc, auth_exception_type) and "timeout" in error_text:
                raise AppError(
                    f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}\n"
                    "Сервер слишком долго отвечает на password-аутентификацию. Повтори попытку; если проблема повторяется, проверь пароль или SSH policy хоста."
                ) from exc
            connect_timeout = isinstance(exc, TimeoutError) or "timed out" in error_text or "timeout" in error_text
            if connect_timeout and attempt < attempts:
                time.sleep(SSH_CONNECT_RETRY_DELAY * attempt)
                continue
            if connect_timeout:
                raise AppError(
                    f"SSH connection failed для {target.ssh_user}@{target.ssh_host}:{target.ssh_port}: {exc}\n"
                    "TCP/SSH connect timed out после повторных попыток. Это проблема control-plane доступа к серверу, а не доказательство поломки VLESS dataplane."
                ) from exc
            connection_reset = "forcibly closed" in error_text or "connection reset" in error_text
            if connection_reset and attempt < attempts:
                time.sleep(SSH_BANNER_RETRY_DELAY * attempt)
                continue
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
        captured_bytes = 0
        started_at = time.monotonic()
        while True:
            if channel.recv_ready():
                chunk = channel.recv(4096)
                out_chunks.append(chunk)
                captured_bytes += len(chunk)
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096)
                err_chunks.append(chunk)
                captured_bytes += len(chunk)
            if captured_bytes > SSH_CAPTURE_MAX_BYTES:
                channel.close()
                raise AppError(
                    f"Удалённая команда на {target.label} превысила лимит вывода "
                    f"{SSH_CAPTURE_MAX_BYTES} байт."
                )
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
        exit_status = channel.recv_exit_status()
        if exit_status != 0:
            detail = "".join(err_tail).strip() or "".join(out_tail).strip()
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{detail or exit_status}")
        return exit_status
    finally:
        client.close()


def paramiko_upload(target: RemoteTarget, local_path: Path, remote_path: str) -> None:
    client = paramiko_connect(target)
    try:
        sftp = client.open_sftp()
        try:
            sftp.get_channel().settimeout(SSH_UPLOAD_TIMEOUT)
            sftp.put(str(local_path), remote_path)
        finally:
            sftp.close()
    except Exception as exc:  # noqa: BLE001
        raise AppError(f"Не удалось загрузить {local_path} на {target.label}: {exc}") from exc
    finally:
        client.close()


def raise_for_system_ssh_failure(
    target: RemoteTarget,
    returncode: int,
    stdout: str | None,
    stderr: str | None,
    *,
    action: str,
) -> None:
    if returncode == 0:
        return
    detail = (stderr or stdout).strip()
    if returncode == 255:
        summary = (
            f"{target.label}: вход по SSH key не выполнен. "
            "Проверь имя/путь ключа и authorized_keys либо выбери SSH password."
        )
    else:
        summary = f"{target.label}: {action.lower()} завершилась с кодом {returncode}."
    raise AppError(f"{summary}\n{detail}" if detail else summary)


def ssh_capture(target: RemoteTarget, command_body: str, *, as_root: bool = False, command_timeout: int = SSH_COMMAND_TIMEOUT) -> str:
    remote_command, input_text = build_remote_command(command_body, target, as_root, command_timeout=command_timeout)
    local_timeout = command_timeout + SSH_COMMAND_TIMEOUT_GRACE if command_timeout > 0 else 0
    if use_python_ssh_backend(target):
        exit_status, stdout, stderr = paramiko_exec(
            target,
            remote_command,
            input_text=input_text,
            get_pty=bool(input_text),
            command_timeout=local_timeout,
        )
        if exit_status != 0:
            detail = (stderr or stdout).strip()
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{detail or exit_status}")
        return stdout
    completed = run_command(
        ssh_base_args(target) + [remote_command],
        capture_output=True,
        input_text=input_text,
        check=False,
        timeout=local_timeout if local_timeout > 0 else None,
    )
    raise_for_system_ssh_failure(target, completed.returncode, completed.stdout, completed.stderr, action="Удалённая команда")
    return completed.stdout


def ssh_stream(
    target: RemoteTarget,
    command_body: str,
    *,
    as_root: bool = False,
    command_timeout: int = SSH_COMMAND_TIMEOUT,
) -> None:
    remote_command, input_text = build_remote_command(command_body, target, as_root, command_timeout=command_timeout)
    local_timeout = command_timeout + SSH_COMMAND_TIMEOUT_GRACE if command_timeout > 0 else 0
    if use_python_ssh_backend(target):
        exit_status = paramiko_stream(
            target,
            remote_command,
            input_text=input_text,
            get_pty=bool(input_text),
            command_timeout=local_timeout,
        )
        if exit_status != 0:
            raise AppError(f"Удалённая команда завершилась с ошибкой на {target.label}.\n{exit_status}")
        return
    completed = run_command(
        ssh_base_args(target) + [remote_command],
        input_text=input_text,
        capture_stderr=True,
        check=False,
        timeout=local_timeout if local_timeout > 0 else None,
    )
    raise_for_system_ssh_failure(target, completed.returncode, completed.stdout, completed.stderr, action="Удалённая команда")


def scp_upload(target: RemoteTarget, local_path: Path, remote_path: str) -> None:
    if use_python_ssh_backend(target):
        paramiko_upload(target, local_path, remote_path)
        return
    completed = run_command(
        scp_base_args(target) + [str(local_path), f"{target.ssh_user}@{target.ssh_host}:{remote_path}"],
        capture_output=True,
        check=False,
        timeout=SSH_UPLOAD_TIMEOUT,
    )
    raise_for_system_ssh_failure(target, completed.returncode, completed.stdout, completed.stderr, action="Загрузка файла")


def parse_kv_output(payload: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in payload.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def fetch_remote_deployment_env(target: RemoteTarget) -> str:
    return ssh_capture(target, "cat /etc/vpn-stack/deployment.env", as_root=True)


def preflight_script(
    wg_interface: str,
    fresh_since_epoch: int | None = None,
    *,
    run_live_probes: bool = False,
) -> str:
    """Minimal bootstrap probe for fresh hosts without the managed agent."""
    del fresh_since_epoch, run_live_probes
    quoted_interface = shlex.quote(wg_interface)
    return "\n".join(
        [
            "set -euo pipefail",
            f"WG_INTERFACE={quoted_interface}",
            "service_state() { systemctl is-active \"$1\" 2>/dev/null || true; }",
            "os_id=''; os_version=''; os_id_like=''",
            "if [[ -r /etc/os-release ]]; then . /etc/os-release; os_id=\"${ID:-}\"; os_version=\"${VERSION_ID:-}\"; os_id_like=\"${ID_LIKE:-}\"; fi",
            "architecture=\"$(uname -m)\"",
            "init_system=\"$(cat /proc/1/comm 2>/dev/null || true)\"",
            "[[ -d /run/systemd/system ]] && init_system=systemd",
            "security_mode=none",
            "if [[ -r /sys/fs/selinux/enforce ]]; then [[ \"$(cat /sys/fs/selinux/enforce)\" == 1 ]] && security_mode=selinux-enforcing || security_mode=selinux-permissive; elif [[ -e /sys/module/apparmor/parameters/enabled ]]; then security_mode=apparmor; fi",
            "host_firewall=none",
            "[[ \"$(service_state firewalld.service)\" == active ]] && host_firewall=firewalld",
            "if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then host_firewall=ufw; fi",
            "installed=0; node_id=''; deployment_name=''; installed_at=''",
            "[[ -r /etc/vpn-stack/node-id ]] && node_id=\"$(tr -d '\\r\\n' </etc/vpn-stack/node-id)\"",
            "[[ -r /etc/vpn-stack/installed-at ]] && installed_at=\"$(tr -d '\\r\\n' </etc/vpn-stack/installed-at)\"",
            "[[ -n \"$node_id\" && -n \"$installed_at\" ]] && installed=1",
            "if [[ -r /etc/vpn-stack/deployment.env ]]; then deployment_name=\"$(awk -F= '$1 == \"DEPLOY_NAME\" {gsub(/^\"|\"$/, \"\", $2); print $2; exit}' /etc/vpn-stack/deployment.env)\"; fi",
            "default_iface=\"$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')\"",
            "wg_latest_handshake=''; wg_transfer_rx=''; wg_transfer_tx=''",
            "if command -v wg >/dev/null 2>&1; then",
            "  read -r wg_transfer_rx wg_transfer_tx < <(wg show \"$WG_INTERFACE\" transfer 2>/dev/null | awk 'NR == 1 {print $2, $3}') || true",
            "  wg_latest_handshake=\"$(wg show \"$WG_INTERFACE\" latest-handshakes 2>/dev/null | awk 'NR == 1 {print $2}')\"",
            "fi",
            "now_epoch=\"$(date +%s)\"; wg_latest_handshake_age_s=''",
            "if [[ \"$wg_latest_handshake\" =~ ^[0-9]+$ && \"$wg_latest_handshake\" != 0 ]]; then wg_latest_handshake_age_s=$((now_epoch - wg_latest_handshake)); fi",
            "printf 'login_user=%s\\n' \"$(id -un)\"",
            "printf 'is_root=%s\\n' \"$([[ $(id -u) -eq 0 ]] && echo 1 || echo 0)\"",
            "printf 'has_sudo=%s\\n' \"$(command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1 && echo 1 || echo 0)\"",
            "printf 'os_id=%s\\n' \"$os_id\"",
            "printf 'os_version=%s\\n' \"$os_version\"",
            "printf 'os_id_like=%s\\n' \"$os_id_like\"",
            "printf 'architecture=%s\\n' \"$architecture\"",
            "printf 'init_system=%s\\n' \"$init_system\"",
            "printf 'security_mode=%s\\n' \"$security_mode\"",
            "printf 'host_firewall=%s\\n' \"$host_firewall\"",
            "printf 'hostname=%s\\n' \"$(hostname -f 2>/dev/null || hostname)\"",
            "printf 'default_iface=%s\\n' \"$default_iface\"",
            "printf 'installed=%s\\n' \"$installed\"",
            "printf 'deployment_name=%s\\n' \"$deployment_name\"",
            "printf 'node_id=%s\\n' \"$node_id\"",
            "printf 'installed_at=%s\\n' \"$installed_at\"",
            "printf 'sing_box=%s\\n' \"$(service_state sing-box.service)\"",
            "printf 'xray=%s\\n' \"$(service_state vpn-stack-xray.service)\"",
            "printf 'nftables=%s\\n' \"$(service_state vpn-stack-nftables.service)\"",
            "printf 'wireguard=%s\\n' \"$(service_state wg-quick@${WG_INTERFACE}.service)\"",
            "printf 'health_timer=%s\\n' \"$(service_state vpn-stack-health.timer)\"",
            "printf 'ssh_socket=%s\\n' \"$(service_state ssh.socket)\"",
            "printf 'wg_latest_handshake=%s\\n' \"$wg_latest_handshake\"",
            "printf 'wg_latest_handshake_age_s=%s\\n' \"$wg_latest_handshake_age_s\"",
            "printf 'wg_transfer_rx=%s\\n' \"$wg_transfer_rx\"",
            "printf 'wg_transfer_tx=%s\\n' \"$wg_transfer_tx\"",
        ]
    )

def remote_preflight(
    target: RemoteTarget,
    wg_interface: str,
    *,
    fresh_since_epoch: int | None = None,
    run_live_probes: bool = False,
) -> dict[str, str]:
    try:
        payload = _remote_agent_payload(target, live_probes=run_live_probes, compact=not run_live_probes)
        if int(payload.get("schema_version", 0)) == DIAGNOSTICS_SCHEMA_VERSION:
            return bootstrap_from_snapshot(payload)
        raise AppError("vpn-stack-agent returned an unsupported snapshot schema")
    except (AppError, ValueError, json.JSONDecodeError):
        installed = ssh_capture(
            target,
            "if test -r /usr/local/lib/vpn-stack/vpn-stack-agent.py; then printf 1; else printf 0; fi",
            command_timeout=30,
        ).strip()
        if installed == "1":
            raise
        # Only fresh unmanaged hosts may use the bootstrap collector.
    return parse_kv_output(
        ssh_capture(
            target,
            preflight_script(wg_interface, fresh_since_epoch=fresh_since_epoch, run_live_probes=run_live_probes),
        )
    )


def _remote_agent_payload(target: RemoteTarget, *, live_probes: bool = False, profile: str = "light", compact: bool = False) -> dict[str, Any]:
    command = "test -r /usr/local/lib/vpn-stack/vpn-stack-agent.py && /usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py snapshot"
    if live_probes:
        command += f" --live-probes --profile {shlex.quote(profile)}"
    if compact:
        command += " --compact"
    return json.loads(ssh_capture(target, command, command_timeout=180 if live_probes else 90))


def remote_agent_snapshot(target: RemoteTarget, *, live_probes: bool = False, profile: str = "light", compact: bool = False) -> dict[str, Any]:
    payload = _remote_agent_payload(target, live_probes=live_probes, profile=profile, compact=compact)
    if not isinstance(payload, dict):
        raise AppError("vpn-stack-agent returned an invalid snapshot payload")
    if int(payload.get("schema_version", 0)) != DIAGNOSTICS_SCHEMA_VERSION:
        release = payload.get("release")
        if isinstance(release, dict) and release.get("version"):
            try:
                require_compatible_installed(release)
            except ValueError as exc:
                raise AppError(str(exc)) from exc
        raise AppError("vpn-stack-agent returned an unsupported snapshot schema")
    return payload


def bootstrap_from_snapshot(snapshot: dict[str, Any]) -> dict[str, str]:
    """Extract lifecycle fields after the single agent-schema boundary."""
    normalized = DiagnosticsSnapshot.from_agent(snapshot)
    services = normalized.services
    artifacts = normalized.artifacts
    host = normalized.host
    wireguard = normalized.wg_state
    peer = next(iter(wireguard.get("peers", [])), {})
    front = normalized.front
    tcp_adaptation = normalized.network.get("tcp_adaptation", {})
    interfaces = normalized.network.get("interfaces", {})
    public_interface = next(iter(interfaces), "")
    return {
        "schema_version": str(normalized.schema_version),
        "login_user": str(host.get("login_user", "")),
        "is_root": "1" if host.get("is_root") is True else "0",
        "has_sudo": "1" if host.get("has_sudo") is True else "0",
        "hostname": str(host.get("hostname", "")),
        "os_id": str(host.get("os_id", "")),
        "os_version": str(host.get("os_version", "")),
        "os_id_like": " ".join(str(value) for value in host.get("os_id_like", ()) if value),
        "architecture": str(host.get("architecture", "")),
        "init_system": str(host.get("init_system", "")),
        "security_mode": str(host.get("security_mode", "unknown")),
        "host_firewall": str(host.get("host_firewall", "none")),
        "deployment_name": normalized.deployment,
        "topology": normalized.topology,
        "node": normalized.node_id,
        "location": normalized.location,
        "capabilities": ",".join(normalized.capabilities),
        "installed": "1" if normalized.release.get("release_id") else "0",
        "release_version": str(normalized.release.get("version", "")),
        "release_id": str(normalized.release.get("release_id", "")),
        "installed_at": str(normalized.release.get("installed_at", "")),
        "sing_box": str(services.get("sing-box", "")),
        "xray": str(services.get("xray", "")),
        "nftables": str(services.get("nftables", "")),
        "wireguard": str(services.get("wireguard", "")),
        "admin": str(services.get("admin", "")),
        "resolver": str(services.get("resolver", "")),
        "health_timer": str(services.get("health_timer", "unknown")),
        "installed_env_sha256": str(artifacts.get("installed_env_sha256", "")),
        "installed_singbox_sha256": str(artifacts.get("files", {}).get("sing-box.json", {}).get("actual_sha256", "")),
        "render_manifest_singbox_sha256": str(artifacts.get("files", {}).get("sing-box.json", {}).get("expected_sha256", "")),
        "render_manifest_policy_version": str(normalized.release.get("policy_version", "")),
        "drift": str(artifacts.get("drift", "unknown")),
        "default_iface": str(host.get("default_interface", "") or public_interface),
        "wg_latest_handshake": str(peer.get("latest_handshake", "")),
        "wg_latest_handshake_age_s": str(peer.get("handshake_age_s", "")),
        "wg_transfer_rx": str(peer.get("transfer_rx", "")),
        "wg_transfer_tx": str(peer.get("transfer_tx", "")),
        "front_retransmissions_lifetime": str(front.get("socket_retransmissions", 0)),
        "front_retransmitted_bytes": str(front.get("bytes_retrans", 0)),
        "front_retransmit_ratio_pct": str(front.get("retransmit_ratio_pct", 0)),
        "front_retransmissions_scope": str(front.get("socket_retransmissions_scope", "lifetime counters of currently active ESTAB sockets")),
        "front_fin_wait_1": str(front.get("state_counts", {}).get("FIN-WAIT-1", 0)),
        "front_active_connections": str(front.get("active_connections", 0)),
        "front_closing_connections": str(front.get("closing_connections", 0)),
        "front_rtt_p95_ms": str(front.get("rtt_ms", {}).get("p95", "")),
        "tcp_congestion_control": str(tcp_adaptation.get("congestion_control", "")),
        "tcp_default_qdisc": str(tcp_adaptation.get("qdisc", "")),
        "tcp_qdisc_limit": str(tcp_adaptation.get("qdisc_limit", "")),
        "tcp_qdisc_flow_limit": str(tcp_adaptation.get("qdisc_flow_limit", "")),
        "tcp_qdisc_drops": str(tcp_adaptation.get("qdisc_drops", "")),
        "tcp_qdisc_flow_limit_drops": str(tcp_adaptation.get("qdisc_flow_limit_drops", "")),
        "wg_qdisc": str(tcp_adaptation.get("overlay_qdisc", "")),
        "wg_qdisc_limit": str(tcp_adaptation.get("overlay_qdisc_limit", "")),
        "wg_qdisc_flow_limit": str(tcp_adaptation.get("overlay_qdisc_flow_limit", "")),
        "wg_qdisc_drops": str(tcp_adaptation.get("overlay_qdisc_drops", "")),
        "wg_qdisc_flow_limit_drops": str(tcp_adaptation.get("overlay_qdisc_flow_limit_drops", "")),
        "tcp_mtu_probing": str(tcp_adaptation.get("mtu_probing", "")),
        "tcp_mtu_probe_floor": str(tcp_adaptation.get("mtu_probe_floor", "")),
        "tcp_metrics_save_disabled": str(tcp_adaptation.get("metrics_save_disabled", "")),
        "tcp_probe_interval_seconds": str(tcp_adaptation.get("probe_interval_seconds", "")),
        "udp_rmem_default": str(tcp_adaptation.get("udp_rmem_default", "")),
        "udp_rmem_max": str(tcp_adaptation.get("udp_rmem_max", "")),
        "udp_wmem_default": str(tcp_adaptation.get("udp_wmem_default", "")),
        "udp_wmem_max": str(tcp_adaptation.get("udp_wmem_max", "")),
    }

def print_preflight(target: RemoteTarget, preflight: dict[str, str]) -> None:
    print_header(f"Проверка {target.label}")
    print(f"host: {preflight.get('hostname', '-')}")
    print(f"login user: {preflight.get('login_user', '-')}")
    print(
        f"os: {preflight.get('os_id', '-')} {preflight.get('os_version', '-')} "
        f"{preflight.get('architecture', '-')}; init={preflight.get('init_system', '-')}; "
        f"security={preflight.get('security_mode', '-')}; host-firewall={preflight.get('host_firewall', '-')}"
    )
    print(f"default iface: {preflight.get('default_iface', '-')}")
    print(
        f"installed: {preflight.get('installed', '0')}; deployment: {preflight.get('deployment_name', '-')}; "
        f"topology: {preflight.get('topology', '-')}; node: {preflight.get('node', '-')}; location: {preflight.get('location', '-')}"
    )
    if preflight.get("drift"):
        print(f"drift: {preflight['drift']}")
    capabilities = set(filter(None, preflight.get("capabilities", "").split(",")))
    service_parts = [
        f"nft={preflight.get('nftables', '-')}",
        f"sing-box={preflight.get('sing_box', '-')}",
        f"resolver={preflight.get('resolver', '-')}",
        f"health={preflight.get('health_timer', '-')}",
    ]
    if capabilities & {"interserver-client", "interserver-server"}:
        service_parts.append(f"wg={preflight.get('wireguard', '-')}")
    if "public-front" in capabilities:
        service_parts.append(f"xray={preflight.get('xray', '-')}")
    if "web-admin" in capabilities:
        service_parts.append(f"admin={preflight.get('admin', '-')}")
    print("services: " + ", ".join(service_parts))
    if capabilities & {"interserver-client", "interserver-server"}:
        print(
            "wireguard: "
            f"handshake_age_s={preflight.get('wg_latest_handshake_age_s', '-')}, "
            f"transfer_rx_tx={preflight.get('wg_transfer_rx', '-')}/{preflight.get('wg_transfer_tx', '-')}"
        )
    if "public-front" in capabilities:
        print(
            "front: "
            f"rtt_p95_ms={preflight.get('front_rtt_p95_ms', '-')}, "
            f"retransmissions_lifetime={preflight.get('front_retransmissions_lifetime', '0')}, "
            f"retransmit_ratio_pct={preflight.get('front_retransmit_ratio_pct', '0')}, "
            f"active={preflight.get('front_active_connections', '0')}, "
            f"closing={preflight.get('front_closing_connections', '0')}, "
            f"fin_wait_1={preflight.get('front_fin_wait_1', '0')}"
        )
        print(f"front retransmission scope: {preflight.get('front_retransmissions_scope', 'unknown')}")
    print(
        "tcp adaptation: "
        f"cc={preflight.get('tcp_congestion_control', '-')}, "
        f"qdisc={preflight.get('tcp_default_qdisc', '-')}"
        f"(limit={preflight.get('tcp_qdisc_limit', '-')},flow_limit={preflight.get('tcp_qdisc_flow_limit', '-')},"
        f"drops={preflight.get('tcp_qdisc_drops', '-')},flow_limit_drops={preflight.get('tcp_qdisc_flow_limit_drops', '-')}), "
        f"wg_qdisc={preflight.get('wg_qdisc', '-')}"
        f"(limit={preflight.get('wg_qdisc_limit', '-')},flow_limit={preflight.get('wg_qdisc_flow_limit', '-')},"
        f"drops={preflight.get('wg_qdisc_drops', '-')},flow_limit_drops={preflight.get('wg_qdisc_flow_limit_drops', '-')}), "
        f"mtu_probing={preflight.get('tcp_mtu_probing', '-')}, mtu_floor={preflight.get('tcp_mtu_probe_floor', '-')}, "
        f"metrics_save_disabled={preflight.get('tcp_metrics_save_disabled', '-')}, "
        f"probe_interval_s={preflight.get('tcp_probe_interval_seconds', '-')}, "
        f"udp_rmem={preflight.get('udp_rmem_default', '-')}/{preflight.get('udp_rmem_max', '-')}, "
        f"udp_wmem={preflight.get('udp_wmem_default', '-')}/{preflight.get('udp_wmem_max', '-')}"
    )


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
