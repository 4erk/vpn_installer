from __future__ import annotations

import socket
import socketserver
import threading
import webbrowser
from typing import Any

from .common import print_header
from .models import AppError, ROLE_RU
from .remote import paramiko_connect
from .topology import CAP_WEB_ADMIN, NODE_GATEWAY, TopologySpec

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_ADMIN_PORT = 11333


def _valid_port(value: int, label: str) -> int:
    if not 1 <= value <= 65535:
        raise AppError(f"{label} должен быть в диапазоне 1..65535")
    return value


def _relay(source: Any, destination: Any) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except (EOFError, OSError):
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except (EOFError, OSError):
            pass


class _ForwardHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        channel = None
        try:
            channel = server.ssh_transport.open_channel(  # type: ignore[attr-defined]
                "direct-tcpip",
                (LOOPBACK_HOST, server.remote_port),  # type: ignore[attr-defined]
                self.client_address,
            )
            if channel is None:
                return
            upload = threading.Thread(target=_relay, args=(self.request, channel), daemon=True)
            upload.start()
            _relay(channel, self.request)
            upload.join(timeout=1)
        except (EOFError, OSError):
            return
        finally:
            if channel is not None:
                channel.close()


class _ForwardServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, local_port: int, ssh_transport: Any, remote_port: int) -> None:
        self.ssh_transport = ssh_transport
        self.remote_port = remote_port
        super().__init__((LOOPBACK_HOST, local_port), _ForwardHandler)


def admin_tunnel_workflow(
    deployment: str | None,
    *,
    local_port: int | None = None,
    open_browser: bool = False,
    non_interactive: bool = False,
) -> int:
    from .workflows import prepare_remote_session

    deployment_name, _env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=[ROLE_RU],
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
    )
    topology = TopologySpec.from_env(env, require_addresses=False)
    if CAP_WEB_ADMIN not in topology.plan(NODE_GATEWAY).capabilities:
        raise AppError(f"Web-admin отключён для deployment {deployment_name} (ADMIN_WEB_ENABLED=0).")

    try:
        remote_port = _valid_port(int(env.get("ADMIN_WEB_PORT", str(DEFAULT_ADMIN_PORT)) or DEFAULT_ADMIN_PORT), "ADMIN_WEB_PORT")
    except ValueError as exc:
        raise AppError("ADMIN_WEB_PORT должен быть целым числом") from exc
    selected_local_port = _valid_port(local_port if local_port is not None else remote_port, "--local-port")

    client = paramiko_connect(targets[0])
    server: _ForwardServer | None = None
    try:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise AppError("SSH transport не активен; tunnel не открыт.")
        try:
            server = _ForwardServer(selected_local_port, transport, remote_port)
        except OSError as exc:
            raise AppError(f"Не удалось занять {LOOPBACK_HOST}:{selected_local_port}: {exc}") from exc

        url = f"http://{LOOPBACK_HOST}:{selected_local_port}"
        print_header("Web-admin SSH tunnel")
        print(f"deployment: {deployment_name}")
        print(f"Адрес: {url}")
        print("Tunnel работает только на loopback. Нажми Ctrl+C для завершения.")
        if open_browser:
            webbrowser.open(url, new=2)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            print("\nSSH tunnel остановлен.")
        return 0
    finally:
        if server is not None:
            server.server_close()
        client.close()
