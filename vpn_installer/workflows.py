from __future__ import annotations

import argparse
import json
import shlex
import shutil
import textwrap
import time
from pathlib import Path
from typing import Any

from . import VERSION
from .admin_access import admin_access_workflow, admin_url
from .clipboard import copy_to_clipboard
from .client_drift import find_client_drift
from .common import DEPLOYMENTS_DIR, OUT_DIR, RUNTIME_DIR, INSTALL_SCRIPT_PATH, cli_command, ensure_directories, error_summary, fail, print_header, sanitize_name, warn, write_private_text
from .config import (
    apply_ru_direct_overlays,
    load_existing_deployment_env,
    load_env_file,
    merge_env_with_defaults,
    merge_node_env_with_defaults,
    normalize_deployment_env,
    parse_env_text,
    render_env_text,
    require_env,
    ensure_deployment_env,
)
from .error_logging import log_exception
from .diagnostics import DiagnosticsSnapshot
from .localnet import assert_server_route_not_self_tunneled, local_route_to_server, route_uses_self_tunnel
from .models import AppError, NODE_META, RemoteTarget, UserCancelled
from .manifest import project_node_env
from .network_profile import FQ_KIND
from .platforms import HostFacts, PlatformError, resolve_platform
from .prompts import (
    ask_install_action,
    auth_mode_label,
    hydrate_runtime_auth,
    persist_runtime_auth,
    prompt_choice,
    prompt_secret,
    prompt_server_connection,
    prompt_topology,
    prompt_yes_no,
    select_deployment,
    select_existing_deployment,
    select_node_for_menu,
    validate_target_settings,
)
from .remote import ensure_remote_privilege, ensure_target_host_key, fetch_remote_deployment_env, print_preflight, remote_agent_snapshot, remote_preflight, scp_upload, ssh_capture, ssh_stream
from .client_artifacts import client_artifact_paths
from .render import deployment_out_dir, package_bundle, package_control_bundle, render_all_artifacts, render_config_artifacts
from .state import load_state, state_json_path, write_state
from .status_output import format_snapshot_summary
from .targets import (
    apply_env_connection_overrides,
    build_target,
    can_fetch_remote_env,
    remote_env_matches_target,
    node_env_prefix,
    update_env_with_targets,
)
from .topology import (
    CAP_WEB_ADMIN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TopologySpec,
    execution_node_ids,
    normalize_node_id,
    requested_node_ids,
)


POSTCUTOVER_VERIFY_ATTEMPTS = 2
POSTCUTOVER_VERIFY_RETRY_DELAY_SECONDS = 2


def is_audit_failure(exc: BaseException) -> bool:
    return exc.__class__.__name__ == "AuditFailure" and exc.__class__.__module__.startswith("vpn_installer.audit")


def load_remote_authoritative_env(
    deployment_name: str,
    env_path: Path,
    env: dict[str, str],
    targets: list[RemoteTarget],
    preflights: dict[str, dict[str, str]],
) -> tuple[dict[str, str], bool]:
    """Validate installed node projections without reconstructing deployment secrets."""

    for target in targets:
        preflight = preflights.get(target.node_id, {})
        if not remote_env_matches_target(target, deployment_name, preflight):
            continue
        if not can_fetch_remote_env(target):
            continue
        remote_env_text = fetch_remote_deployment_env(target)
        parsed_remote_env = normalize_deployment_env(parse_env_text(remote_env_text))
        if not parsed_remote_env.get("NODE_ID", "").strip():
            raise AppError(f"{target.label}: installed release has no canonical NODE_ID")
        remote_env = merge_node_env_with_defaults(parsed_remote_env, deployment_name)
        observed = project_node_env(remote_env, target.node_id)
        expected = project_node_env(env, target.node_id)
        differences = [
            key
            for key in sorted(set(observed) | set(expected))
            if observed.get(key, "") != expected.get(key, "")
        ]
        if differences:
            preview = ", ".join(differences[:6]) + (", ..." if len(differences) > 6 else "")
            raise AppError(f"{target.label}: installed node env drift: {preview}")
    return env, False


def ensure_foreign_wan_interface(env: dict[str, str], foreign_preflight: dict[str, str]) -> None:
    if env.get("WAN_INTERFACE", "").strip():
        return
    detected = foreign_preflight.get("default_iface", "").strip()
    if detected:
        env["WAN_INTERFACE"] = detected
        print(f"Автоматически выбран WAN_INTERFACE={detected}")
        return
    from .prompts import prompt_value

    env["WAN_INTERFACE"] = prompt_value("Не удалось определить WAN interface автоматически. Укажите его вручную")


def print_summary(deployment_name: str, env: dict[str, str], targets: list[RemoteTarget]) -> None:
    topology = TopologySpec.from_env(env, require_addresses=False)
    print_header("Сводка deployment")
    print(f"deployment: {deployment_name}")
    print(f"topology: {topology.mode}")
    print(f"gateway: {topology.gateway.location}, {topology.gateway.public_ip or '-'}")
    if topology.exit:
        print(f"exit: {topology.exit.location}, {topology.exit.public_ip or '-'}")
    for target in targets:
        print(f"{target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port} ({auth_mode_label(target.auth_mode)})")
    print(f"WAN_INTERFACE: {env.get('WAN_INTERFACE') or '-'}")


def print_step(step: int, total: int, message: str) -> None:
    print(f"[{step}/{total}] {message}")


def validate_server_platform(target: RemoteTarget, preflight: dict[str, str]) -> None:
    try:
        platform = resolve_platform(HostFacts.from_mapping(preflight))
    except PlatformError as exc:
        raise AppError(f"{target.label}: {exc}") from exc
    preflight["platform_family"] = platform.family
    preflight["package_provider"] = platform.package_provider
    if preflight.get("host_firewall") not in {"", "none"}:
        raise AppError(
            f"{target.label}: активен {preflight['host_firewall']}. "
            "vpn-stack должен быть единственным владельцем ingress/forward nftables policy; "
            "отключи сторонний firewall до установки."
        )


def verify_target_interactively(
    target: RemoteTarget,
    *,
    env: dict[str, str],
    wg_interface: str,
    require_privilege: bool,
    validate_os: bool,
    confirm_existing_connection: bool,
    enforce_safe_route: bool = True,
    fresh_since_epoch: int | None = None,
    run_live_probes: bool = False,
) -> tuple[RemoteTarget, dict[str, str]]:
    force_prompt = not target.saved_connection
    while True:
        target = prompt_server_connection(target, force_prompt=force_prompt, confirm_existing=confirm_existing_connection)
        backend = "встроенный password backend" if target.auth_mode == "password" else "OpenSSH publickey-only"
        print(f"Проверяю подключение к {target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port} ({backend})")
        try:
            if enforce_safe_route:
                assert_server_route_not_self_tunneled(target, env)
            ensure_target_host_key(target, allow_enroll=True, prompt_yes_no=prompt_yes_no)
            if fresh_since_epoch is None:
                preflight = remote_preflight(target, wg_interface, run_live_probes=run_live_probes)
            else:
                preflight = remote_preflight(
                    target,
                    wg_interface,
                    fresh_since_epoch=fresh_since_epoch,
                    run_live_probes=run_live_probes,
                )
            print_preflight(target, preflight)
            persist_runtime_auth(target)
            if validate_os:
                validate_server_platform(target, preflight)
            if require_privilege:
                ensure_remote_privilege(target, preflight, prompt_yes_no=prompt_yes_no, prompt_secret=prompt_secret)
            return target, preflight
        except Exception as exc:  # noqa: BLE001
            log_path = log_exception("ssh.preflight", exc, extra={"node_id": target.node_id, "host": target.ssh_host})
            warn(error_summary(exc))
            if log_path:
                print(f"Технические детали: {log_path}")
            action = prompt_choice(
                f"{target.label}: подключение или preflight не прошли. Что делать?",
                [("edit", "Исправить параметры сервера"), ("retry", "Повторить с теми же параметрами"), ("cancel", "Отменить операцию")],
                default="edit",
            )
            if action == "cancel":
                raise UserCancelled(f"{target.label}: операция отменена пользователем.")
            if action == "retry":
                target.saved_connection = True
                if target.auth_mode == "password":
                    target.ssh_password = ""
                force_prompt = False
            else:
                target.saved_connection = False
                force_prompt = True


def verify_target_non_interactively(
    target: RemoteTarget,
    *,
    env: dict[str, str],
    wg_interface: str,
    require_privilege: bool,
    validate_os: bool,
    enforce_safe_route: bool = True,
    fresh_since_epoch: int | None = None,
    run_live_probes: bool = False,
) -> tuple[RemoteTarget, dict[str, str]]:
    if not target.saved_connection:
        raise AppError(
            f"{target.label}: нет полного сохранённого подключения для non-interactive режима. "
            f"Задай state через обычный запуск или env {node_env_prefix(target.node_id)}_PUBLIC_IP/{node_env_prefix(target.node_id)}_SSH_HOST."
        )
    validate_target_settings(target)
    target = hydrate_runtime_auth(target, interactive=False)
    if target.auth_mode == "password" and not target.ssh_password:
        raise AppError(
            f"{target.label}: для non-interactive password-входа нужен пароль в системном хранилище или env "
            f"{node_env_prefix(target.node_id)}_SSH_PASSWORD/VPN_SSH_PASSWORD."
        )
    backend = "встроенный password backend" if target.auth_mode == "password" else "OpenSSH publickey-only"
    print(f"Проверяю подключение к {target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port} ({backend})")
    if enforce_safe_route:
        assert_server_route_not_self_tunneled(target, env)
    ensure_target_host_key(target, allow_enroll=False)
    if fresh_since_epoch is None:
        preflight = remote_preflight(target, wg_interface, run_live_probes=run_live_probes)
    else:
        preflight = remote_preflight(
            target,
            wg_interface,
            fresh_since_epoch=fresh_since_epoch,
            run_live_probes=run_live_probes,
        )
    print_preflight(target, preflight)
    if validate_os:
        validate_server_platform(target, preflight)
    if require_privilege:
        if preflight.get("is_root") == "1":
            target.sudo_mode = "root"
            print(f"{target.label}: удалённый вход уже под root.")
        elif preflight.get("has_sudo") == "1":
            target.sudo_mode = "nopasswd"
            print(f"{target.label}: найден passwordless sudo.")
        else:
            raise AppError(f"{target.label}: для non-interactive режима нужен root или passwordless sudo.")
    return target, preflight


def prepare_remote_session(
    deployment_arg: str | None,
    *,
    nodes: list[str] | None,
    require_privilege: bool,
    validate_os: bool = True,
    allow_create: bool = False,
    persist_local: bool = True,
    confirm_existing_connections: bool = True,
    non_interactive: bool = False,
    enforce_safe_route: bool = True,
    fresh_since_epoch: int | None = None,
    run_live_probes: bool = False,
    sync_remote_env: bool = False,
    topology_mode: str | None = None,
    gateway_location: str | None = None,
) -> tuple[str, Path, dict[str, str], dict[str, Any], list[RemoteTarget], dict[str, dict[str, str]]]:
    if allow_create or persist_local:
        ensure_directories()
    if allow_create:
        deployment_name = select_deployment(deployment_arg)
        env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
        is_new = not env_path.exists()
        if not is_new and (topology_mode is not None or gateway_location is not None):
            current_env = normalize_deployment_env(load_env_file(env_path))
            current_topology = TopologySpec.from_env(current_env, require_addresses=False)
            requested_mode = topology_mode or current_topology.mode
            requested_location = gateway_location or current_topology.gateway.location
            if (requested_mode, requested_location) != (
                current_topology.mode,
                current_topology.gateway.location,
            ):
                raise AppError(
                    "Нельзя менять topology или расположение gateway существующего deployment: "
                    "это меняет набор физических серверов. Создай новый deployment и удаляй старый только после verify."
                )
        if is_new and topology_mode is None and not non_interactive:
            topology_mode, gateway_location = prompt_topology()
        if topology_mode == "dual" and gateway_location not in {None, LOCATION_RU}:
            raise AppError("dual topology поддерживает только RU gateway и foreign exit")
        env = ensure_deployment_env(
            env_path,
            deployment_name,
            topology=topology_mode,
            gateway_location=gateway_location,
        )
    else:
        deployment_name = select_existing_deployment(deployment_arg)
        env_path, env = load_existing_deployment_env(deployment_name)
    topology = TopologySpec.from_env(env, require_addresses=False)
    configured_nodes = [node.node_id for node in topology.nodes]
    selected_nodes = configured_nodes if nodes is None else [node_id for node_id in nodes if node_id in configured_nodes]
    if not selected_nodes:
        raise AppError(f"Запрошенный сервер отсутствует в topology={topology.mode}.")
    state = load_state(deployment_name)
    print_header("Параметры deployment")
    print(f"deployment: {deployment_name}")
    targets: list[RemoteTarget] = []
    preflights: dict[str, dict[str, str]] = {}
    wg_interface = (env.get("WG_INTERFACE", "").strip() or "wg0")
    for node_id in selected_nodes:
        target = apply_env_connection_overrides(build_target(node_id, env, state))
        if non_interactive:
            target, preflight = verify_target_non_interactively(
                target,
                env=env,
                wg_interface=wg_interface,
                require_privilege=require_privilege,
                validate_os=validate_os,
                enforce_safe_route=enforce_safe_route,
                fresh_since_epoch=fresh_since_epoch,
                run_live_probes=run_live_probes,
            )
        else:
            target, preflight = verify_target_interactively(
                target,
                env=env,
                wg_interface=wg_interface,
                require_privilege=require_privilege,
                validate_os=validate_os,
                confirm_existing_connection=confirm_existing_connections,
                enforce_safe_route=enforce_safe_route,
                fresh_since_epoch=fresh_since_epoch,
                run_live_probes=run_live_probes,
            )
        targets.append(target)
        preflights[node_id] = preflight
    update_env_with_targets(env, targets)
    synced_from_remote = False
    if sync_remote_env:
        env, synced_from_remote = load_remote_authoritative_env(deployment_name, env_path, env, targets, preflights)
    if persist_local or synced_from_remote:
        write_private_text(env_path, render_env_text(env))
    if persist_local:
        write_state(deployment_name, targets, existing_state=state, topology=TopologySpec.from_env(env, require_addresses=False).mode)
    return deployment_name, env_path, env, state, targets, preflights


def cleanup_remote_workdir(target: RemoteTarget, remote_root: str) -> None:
    try:
        ssh_stream(target, f"rm -rf {shlex.quote(remote_root)}")
    except Exception as exc:  # noqa: BLE001
        log_exception("ssh.cleanup", exc, extra={"node_id": target.node_id, "host": target.ssh_host})
        warn(f"Не удалось очистить временную папку на {target.label}: {error_summary(exc)}")


def wait_for_remote_recovery(target: RemoteTarget, wg_interface: str, *, timeout_sec: int = 120, interval_sec: int = 5) -> dict[str, str]:
    deadline = time.time() + timeout_sec
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            return remote_preflight(target, wg_interface)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(interval_sec)
    if last_error is not None:
        raise AppError(f"{target.label}: SSH-сессия оборвалась и сервер не вернулся в доступное состояние за {timeout_sec} секунд: {last_error}") from last_error
    raise AppError(f"{target.label}: SSH-сессия оборвалась и сервер не вернулся в доступное состояние за {timeout_sec} секунд.")


def remote_install_transaction_state(target: RemoteTarget) -> dict[str, Any]:
    source = textwrap.dedent(
        """
        import json
        import subprocess
        from pathlib import Path

        root = Path("/etc/vpn-stack")
        acceptance_path = root / "last-acceptance.json"
        result = {"state": "idle", "acceptance_present": acceptance_path.is_file()}
        if acceptance_path.is_file():
            try:
                payload = json.loads(acceptance_path.read_text(encoding="utf-8"))
                release = payload.get("release", {})
                result.update(
                    acceptance_release_id=str(release.get("release_id", "")),
                    acceptance_node_id=str(payload.get("node_id", "")),
                    acceptance_deployment=str(payload.get("deployment", "")),
                )
            except (OSError, ValueError, TypeError) as exc:
                result["acceptance_error"] = str(exc)

        current_path = root / "current"
        result["current_present"] = current_path.is_symlink()
        if current_path.is_symlink():
            try:
                current = current_path.resolve(strict=True)
                releases = (root / "releases").resolve(strict=False)
                if releases not in current.parents:
                    raise ValueError("current points outside releases")
                manifest = json.loads((current / "render-manifest.json").read_text(encoding="utf-8"))
                node = manifest.get("node")
                nested_node_id = node.get("id", "") if isinstance(node, dict) else ""
                result.update(
                    current_target=str(current),
                    current_release_id=str(manifest.get("release_id", "")),
                    current_node_id=str(manifest.get("node_id") or nested_node_id),
                )
            except (OSError, ValueError, TypeError) as exc:
                result["current_error"] = str(exc)

        def systemctl_state(action, unit):
            try:
                completed = subprocess.run(
                    ["systemctl", action, unit],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return f"error:{exc}"
            lines = completed.stdout.strip().splitlines()
            return lines[0].strip() if lines else "unknown"

        latest_path = root / "backups" / "latest"
        result["rollback_services_present"] = False
        if latest_path.is_symlink():
            try:
                snapshot = latest_path.resolve(strict=True)
                revisions = (root / "backups" / "revisions").resolve(strict=False)
                if revisions not in snapshot.parents:
                    raise ValueError("latest snapshot points outside revisions")
                rows = []
                state_path = snapshot / "service-state.tsv"
                for raw in state_path.read_text(encoding="utf-8").splitlines():
                    if not raw:
                        continue
                    fields = raw.split("\\t")
                    if len(fields) != 5:
                        raise ValueError("invalid service-state row")
                    name, unit, ownership, enabled, active = fields
                    rows.append(
                        {
                            "name": name,
                            "unit": unit,
                            "ownership": ownership,
                            "expected_enabled": enabled,
                            "expected_active": active,
                            "actual_enabled": systemctl_state("is-enabled", unit),
                            "actual_active": systemctl_state("is-active", unit),
                        }
                    )
                result.update(
                    rollback_snapshot=str(snapshot),
                    rollback_services_present=True,
                    rollback_services=rows,
                )
            except (OSError, ValueError, TypeError) as exc:
                result["rollback_services_error"] = str(exc)
        print(json.dumps(result, separators=(",", ":")))
        """
    ).strip()
    command = (
        "if ! flock -n /run/lock/vpn-stack-install.lock -c true; then printf busy; "
        f"else python3 -c {shlex.quote(source)}; fi"
    )
    payload = ssh_capture(target, command, as_root=True, command_timeout=20).strip()
    if payload == "busy":
        return {"state": "busy"}
    parsed = json.loads(payload)
    if not isinstance(parsed, dict) or parsed.get("state") != "idle":
        raise AppError(f"{target.label}: некорректное состояние install transaction.")
    return parsed


def wait_for_remote_install_completion(
    target: RemoteTarget,
    wg_interface: str,
    *,
    timeout_sec: int = 180,
    interval_sec: int = 3,
) -> dict[str, Any]:
    deadline = time.time() + timeout_sec
    last_error: Exception | None = None
    last_transaction: dict[str, Any] = {}
    while time.time() < deadline:
        try:
            transaction = remote_install_transaction_state(target)
            last_transaction = transaction
            if transaction.get("state") == "busy":
                time.sleep(interval_sec)
                continue
            observed = remote_preflight(target, wg_interface)
            observed.update(
                {
                    str(key): value if isinstance(value, (dict, list)) else str(value)
                    for key, value in transaction.items()
                }
            )
            return observed
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(interval_sec)
    detail = f": {last_error}" if last_error else ""
    failure = AppError(f"{target.label}: install transaction не завершилась за {timeout_sec} секунд{detail}")
    setattr(failure, "vpn_transaction_state", last_transaction)
    raise failure from last_error


def wait_for_remote_install_idle(
    target: RemoteTarget,
    *,
    timeout_sec: int = 60,
    interval_sec: float = 0.5,
) -> dict[str, Any]:
    """Wait out short agent read cycles without hiding a stuck install writer."""

    deadline = time.monotonic() + timeout_sec
    while True:
        transaction = remote_install_transaction_state(target)
        if transaction.get("state") == "idle":
            return transaction
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AppError(
                f"{target.label}: install transaction не освободила lock за {timeout_sec} секунд."
            )
        time.sleep(min(interval_sec, remaining))


def filter_targets_for_action(
    action: str,
    targets: list[RemoteTarget],
    preflights: dict[str, dict[str, str]],
) -> list[RemoteTarget]:
    if action not in {"remove", "purge"}:
        return targets
    actionable: list[RemoteTarget] = []
    for target in targets:
        preflight = preflights.get(target.node_id, {})
        installed = preflight.get("installed", "0")
        if installed != "1":
            print(f"{target.label}: стек не найден на сервере, действие {action} пропущено.")
            continue
        actionable.append(target)
    return actionable


REMOTE_INSTALL_LOG_DIR = "/var/log/vpn-stack"
REMOTE_INSTALL_LOG = f"{REMOTE_INSTALL_LOG_DIR}/install.log"


def remote_install_systemd_command(node_id: str, remote_root: str, command: str) -> str:
    unit = f"vpn-stack-install-{normalize_node_id(node_id)}"
    cleanup = shlex.quote(f"rm -rf -- {shlex.quote(remote_root)}")
    wrapped = f"set -Eeuo pipefail; trap {cleanup} EXIT; {command}"
    return " ".join(
        (
            "systemd-run",
            "--quiet",
            "--wait",
            "--collect",
            "--service-type=exec",
            f"--unit={shlex.quote(unit)}",
            f"--property={shlex.quote(f'StandardOutput=append:{REMOTE_INSTALL_LOG}')}",
            f"--property={shlex.quote(f'StandardError=append:{REMOTE_INSTALL_LOG}')}",
            "/bin/bash",
            "-lc",
            shlex.quote(wrapped),
        )
    )


def install_remote_node(target: RemoteTarget, deployment_name: str, env: dict[str, str], action: str) -> None:
    node_id = target.node_id
    remote_root = f"/tmp/vpn-stack-installer-{sanitize_name(deployment_name)}-{node_id}-{time.time_ns()}"
    archive_name = f"{node_id}.tar.gz"
    print_header(f"Подготовка {target.label}")
    try:
        ssh_stream(target, f"umask 077 && mkdir -p {shlex.quote(remote_root)}")
        if action in {"install", "reinstall"}:
            bundle_path = deployment_out_dir(env) / "bundle" / archive_name
            if not bundle_path.is_file():
                fail(f"Не найден bundle для {target.label}: {bundle_path}")
            print_header(f"Загрузка bundle на {target.label}")
            scp_upload(target, bundle_path, f"{remote_root}/{archive_name}")
            remote_command = (
                f"cd {shlex.quote(remote_root)} && "
                "umask 077 && "
                f"tar -xzf {shlex.quote(archive_name)} && "
                "chmod 0600 ./deployment.env && "
                "chmod 0700 ./install.sh && "
                f"./install.sh --node {shlex.quote(node_id)} --action {shlex.quote(action)} --env-file ./deployment.env --assets-dir ./assets"
            )
        else:
            support_bundle = package_control_bundle()
            archive_name = "installer-support.tar.gz"
            scp_upload(target, support_bundle, f"{remote_root}/{archive_name}")
            remote_command = (
                f"cd {shlex.quote(remote_root)} && "
                "umask 077 && "
                f"tar -xzf {shlex.quote(archive_name)} && "
                "chmod 0700 ./install.sh && "
                f"./install.sh --node {shlex.quote(node_id)} --action {shlex.quote(action)}"
            )
        print_header(f"Действие {action} для {target.label}")
        ssh_stream(
            target,
            f"install -d -m 0700 {shlex.quote(REMOTE_INSTALL_LOG_DIR)} && "
            f": > {shlex.quote(REMOTE_INSTALL_LOG)} && chmod 0600 {shlex.quote(REMOTE_INSTALL_LOG)}",
            as_root=True,
        )
        ssh_stream(
            target,
            remote_install_systemd_command(node_id, remote_root, remote_command),
            as_root=True,
        )
    except Exception as exc:  # noqa: BLE001
        setattr(exc, "vpn_remote_log", REMOTE_INSTALL_LOG)
        if action in {"install", "reinstall"}:
            setattr(exc, "vpn_remote_root", remote_root)
            raise
        cleanup_remote_workdir(target, remote_root)
        raise


def expected_release_id_for_node(env: dict[str, str], node_id: str) -> str:
    node_id = normalize_node_id(node_id)
    manifest_path = deployment_out_dir(env) / "preview" / node_id / "render-manifest.json"
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AppError(f"Не удалось прочитать release manifest для {node_id}: {exc}") from exc
    release_id = str(payload.get("release_id", "")).strip()
    if not release_id:
        raise AppError(f"Release manifest для {node_id} не содержит release_id.")
    return release_id


def install_remote_node_with_recovery(
    target: RemoteTarget,
    deployment_name: str,
    env: dict[str, str],
    action: str,
    wg_interface: str,
) -> None:
    if action not in {"install", "reinstall"}:
        install_remote_node(target, deployment_name, env, action)
        return

    expected_release_id = expected_release_id_for_node(env, target.node_id)
    baseline = wait_for_remote_install_idle(target)
    command_error: Exception | None = None
    try:
        install_remote_node(target, deployment_name, env, action)
    except Exception as exc:  # noqa: BLE001
        command_error = exc
        remote_log = str(getattr(exc, "vpn_remote_log", REMOTE_INSTALL_LOG))
        warn(
            f"{target.label}: управляющее соединение завершилось ошибкой. "
            f"Сверяю серверную transaction; полный журнал: {remote_log}."
        )
    try:
        observed = wait_for_remote_install_completion(target, wg_interface)
    except Exception as reconciliation_error:  # noqa: BLE001
        transaction = getattr(reconciliation_error, "vpn_transaction_state", {})
        failure = AppError(f"{target.label}: не удалось согласовать состояние после {action}: {reconciliation_error}")
        setattr(failure, "remote_node_changed", install_cutover_observed(baseline, transaction, expected_release_id))
        if transaction.get("state") == "idle" and command_error is not None:
            remote_root = str(getattr(command_error, "vpn_remote_root", ""))
            if remote_root:
                cleanup_remote_workdir(target, remote_root)
        raise failure from (command_error or reconciliation_error)

    if command_error is not None:
        remote_root = str(getattr(command_error, "vpn_remote_root", ""))
        if remote_root:
            cleanup_remote_workdir(target, remote_root)
    mismatches = []
    if observed.get("installed") != "1":
        mismatches.append("stack is not installed")
    if observed.get("node") != target.node_id:
        mismatches.append(f"node={observed.get('node', '') or 'missing'}")
    if observed.get("deployment_name") != deployment_name:
        mismatches.append(f"deployment={observed.get('deployment_name', '') or 'missing'}")
    if observed.get("release_id") != expected_release_id:
        mismatches.append(f"release_id={observed.get('release_id', '') or 'missing'}")
    if observed.get("current_present") != "True":
        mismatches.append("current release link is missing")
    if observed.get("current_release_id") != expected_release_id:
        mismatches.append(f"current_release_id={observed.get('current_release_id', '') or 'missing'}")
    if observed.get("current_node_id") != target.node_id:
        mismatches.append(f"current_node_id={observed.get('current_node_id', '') or 'missing'}")
    if observed.get("drift") != "none":
        mismatches.append(f"drift={observed.get('drift', '') or 'missing'}")
    if observed.get("acceptance_present") != "True":
        mismatches.append("acceptance marker is missing")
    if observed.get("acceptance_release_id") != expected_release_id:
        mismatches.append(f"acceptance_release_id={observed.get('acceptance_release_id', '') or 'missing'}")
    if observed.get("acceptance_node_id") != target.node_id:
        mismatches.append(f"acceptance_node_id={observed.get('acceptance_node_id', '') or 'missing'}")
    if observed.get("acceptance_deployment") != deployment_name:
        mismatches.append(f"acceptance_deployment={observed.get('acceptance_deployment', '') or 'missing'}")
    if mismatches:
        failure = AppError(
            f"{target.label}: установка не подтверждена ({', '.join(mismatches)}; expected release_id={expected_release_id})."
        )
        setattr(
            failure,
            "remote_node_changed",
            install_cutover_observed(baseline, observed, expected_release_id),
        )
        if command_error is not None:
            raise failure from command_error
        raise failure


def install_cutover_observed(
    baseline: dict[str, Any],
    observed: dict[str, Any],
    expected_release_id: str,
) -> bool:
    """Return true when the attempted transaction created rollback-owned state."""

    def present(payload: dict[str, Any]) -> bool:
        return str(payload.get("current_present", "False")).lower() == "true"

    before_present = present(baseline)
    after_present = present(observed)
    before_target = str(baseline.get("current_target", ""))
    after_target = str(observed.get("current_target", ""))
    if before_target and after_target:
        return before_target != after_target
    before_release_id = str(baseline.get("current_release_id", ""))
    after_release_id = str(observed.get("current_release_id", ""))
    if before_release_id and after_release_id:
        return before_release_id != after_release_id
    if before_present != after_present:
        return True
    if after_present and after_release_id == expected_release_id:
        return not before_present

    before_snapshot = str(baseline.get("rollback_snapshot", ""))
    after_snapshot = str(observed.get("rollback_snapshot", ""))
    return bool(after_snapshot and after_snapshot != before_snapshot and before_present and not after_release_id)


def wait_for_ru_transport_ready(
    target: RemoteTarget,
    *,
    timeout_sec: int = 20,
    interval_sec: float = 0.5,
) -> dict[str, Any]:
    """Reconcile the gateway selector after an install transaction releases its lock."""

    deadline = time.monotonic() + timeout_sec
    last_payload: dict[str, Any] = {}
    last_error: Exception | None = None
    command = "/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py transport-reconcile"
    while time.monotonic() < deadline:
        try:
            payload = json.loads(ssh_capture(target, command, as_root=True, command_timeout=10))
            if not isinstance(payload, dict):
                raise ValueError("transport reconciliation returned a non-object response")
            last_payload = payload
            if payload.get("state") == "healthy" and payload.get("selected") in {
                "interserver-underlay-wg",
                "interserver-underlay-hy2",
            }:
                return payload
        except (AppError, OSError, ValueError) as exc:
            last_error = exc
        time.sleep(interval_sec)
    reason = str(last_payload.get("reason", "")).strip()
    if not reason and last_error is not None:
        reason = str(last_error)
    raise AppError(f"{target.label}: межсерверный transport не стабилизировался после установки: {reason or 'unknown'}")


def settle_transport_after_install(
    node_id: str,
    target_map: dict[str, RemoteTarget],
    preflights: dict[str, dict[str, str]] | None,
    env: dict[str, str],
) -> None:
    topology = TopologySpec.from_env(env, require_addresses=False)
    if not topology.is_dual or NODE_GATEWAY not in target_map:
        return
    if node_id == NODE_GATEWAY:
        wait_for_ru_transport_ready(target_map[NODE_GATEWAY])
        return
    if node_id == NODE_EXIT and preflights and preflights.get(NODE_GATEWAY, {}).get("installed") == "1":
        wait_for_ru_transport_ready(target_map[NODE_GATEWAY])


def verify_rollback_node(
    target: RemoteTarget,
    deployment_name: str,
    wg_interface: str,
    expected_release_id: str,
    *,
    wireguard_required: bool = True,
    public_front_required: bool = False,
    admin_required: bool = False,
) -> None:
    observed = remote_preflight(target, wg_interface)
    transaction = remote_install_transaction_state(target)
    mismatches = []
    expected = {"installed": "1" if expected_release_id else "0"}
    if expected_release_id:
        expected.update(
            node=target.node_id,
            deployment_name=deployment_name,
            release_id=expected_release_id,
            drift="none",
        )
    for key, value in expected.items():
        if observed.get(key) != value:
            mismatches.append(f"{key}={observed.get(key, '') or 'missing'}")
    if expected_release_id and wireguard_required and observed.get("wg_qdisc") != FQ_KIND:
        mismatches.append(f"wg_qdisc={observed.get('wg_qdisc', '') or 'missing'} expected={FQ_KIND}")

    current_present = transaction.get("current_present") is True
    if expected_release_id:
        if not current_present:
            mismatches.append("current release link is missing")
        if transaction.get("current_release_id") != expected_release_id:
            mismatches.append(f"current_release_id={transaction.get('current_release_id', '') or 'missing'}")
    elif current_present:
        mismatches.append(f"current_release_id={transaction.get('current_release_id', '') or 'unexpected'}")

    service_rows = transaction.get("rollback_services")
    if transaction.get("rollback_services_present") is not True or not isinstance(service_rows, list):
        detail = transaction.get("rollback_services_error", "missing")
        mismatches.append(f"rollback service snapshot={detail}")
    else:
        required_names = {"sing-box", "nftables", "resolver"} if expected_release_id else set()
        if expected_release_id and wireguard_required:
            required_names.add("wireguard")
        if expected_release_id and public_front_required:
            required_names.add("xray")
        if expected_release_id and admin_required:
            required_names.add("admin")
        present_names: set[str] = set()
        for row in service_rows:
            if not isinstance(row, dict):
                mismatches.append("rollback service snapshot contains a non-object row")
                continue
            name = str(row.get("name", ""))
            unit = str(row.get("unit", ""))
            ownership = str(row.get("ownership", ""))
            present_names.add(name)
            if ownership not in {"managed", "borrowed"}:
                mismatches.append(f"{unit or name}: ownership={ownership or 'missing'}")
            expected_enabled = normalize_snapshot_service_state("enabled", row.get("expected_enabled", ""))
            actual_enabled = normalize_snapshot_service_state("enabled", row.get("actual_enabled", ""))
            expected_active = normalize_snapshot_service_state("active", row.get("expected_active", ""))
            actual_active = normalize_snapshot_service_state("active", row.get("actual_active", ""))
            if actual_enabled != expected_enabled:
                mismatches.append(f"{unit or name}: enabled={row.get('actual_enabled', '') or 'missing'} expected={row.get('expected_enabled', '') or 'missing'}")
            if actual_active != expected_active:
                mismatches.append(f"{unit or name}: active={row.get('actual_active', '') or 'missing'} expected={row.get('expected_active', '') or 'missing'}")
        missing_names = sorted(required_names - present_names)
        if missing_names:
            mismatches.append(f"rollback service snapshot missing={','.join(missing_names)}")
    if mismatches:
        raise AppError(f"{target.label}: rollback state не подтверждён ({', '.join(mismatches)}).")


def normalize_snapshot_service_state(kind: str, value: Any) -> str:
    state = str(value or "unknown")
    if kind == "enabled":
        if state in {"enabled", "enabled-runtime"}:
            return "enabled"
        if state in {"masked", "masked-runtime"}:
            return "masked"
        return state
    if state in {"active", "activating", "reloading"}:
        return "active"
    if state in {"inactive", "failed", "deactivating"}:
        return "inactive"
    return state


def verify_postcutover(
    deployment_name: str,
    *,
    throughput_seconds: int = 0,
    require_native_agent: bool = True,
) -> None:
    """Prove the public client contract and confirm a failure before rollback."""

    from .verify import verify_live_workflow

    for attempt in range(POSTCUTOVER_VERIFY_ATTEMPTS):
        result = verify_live_workflow(
            deployment_name,
            non_interactive=True,
            throughput_seconds=throughput_seconds,
            require_native_agent=require_native_agent,
            accept_install_gate=True,
        )
        if result == 0:
            return
        if attempt + 1 < POSTCUTOVER_VERIFY_ATTEMPTS:
            warn("Первый post-cutover VLESS-цикл не пройден; подтверждаю состояние повторной свежей проверкой.")
            time.sleep(POSTCUTOVER_VERIFY_RETRY_DELAY_SECONDS)
    raise AppError("Свежая проверка полного VLESS-пути после установки не пройдена в двух последовательных циклах.")


def rollback_changed_nodes(
    changed_nodes: list[str],
    target_map: dict[str, RemoteTarget],
    deployment_name: str,
    env: dict[str, str],
    previous_release_ids: dict[str, str] | None = None,
) -> None:
    """Restore every changed server in reverse cutover order and prove each node."""

    failures: list[str] = []
    wg_interface = env.get("WG_INTERFACE", "").strip() or "wg0"
    previous_release_ids = previous_release_ids or {}
    topology = TopologySpec.from_env(env, require_addresses=False)
    for node_id in reversed(changed_nodes):
        target = target_map[node_id]
        plan = topology.plan(target.node_id)
        try:
            try:
                install_remote_node(target, deployment_name, env, "rollback")
            except Exception as command_error:  # noqa: BLE001
                warn(
                    f"{target.label}: управляющее соединение rollback завершилось ошибкой. "
                    "Сверяю завершение server-side transaction."
                )
                try:
                    wait_for_remote_install_completion(target, wg_interface)
                except Exception as reconciliation_error:  # noqa: BLE001
                    raise AppError(
                        f"{target.label}: rollback transaction не подтверждена: {reconciliation_error}"
                    ) from command_error
            verify_rollback_node(
                target,
                deployment_name,
                wg_interface,
                previous_release_ids.get(node_id, ""),
                wireguard_required=plan.requires_wireguard,
                public_front_required=plan.requires_xray,
                admin_required=CAP_WEB_ADMIN in plan.capabilities,
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{target.label}: {exc}")
    if not failures and all(previous_release_ids.get(node_id, "") for node_id in changed_nodes):
        try:
            verify_postcutover(deployment_name, throughput_seconds=0, require_native_agent=False)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"полный VLESS-путь после отката: {exc}")
    if failures:
        raise AppError("Откат изменённых узлов не завершён: " + "; ".join(failures))


def finalize_install_output(env: dict[str, str], deployment_name: str) -> None:
    paths = client_artifact_paths(env)
    uri_payload = paths["vless_uri"].read_text(encoding="utf-8") if paths["vless_uri"].is_file() else ""
    clipboard_ok, clipboard_message = copy_to_clipboard(uri_payload)
    print_header("Готово")
    print(f"Deployment: {deployment_name}")
    topology = TopologySpec.from_env(env, require_addresses=False)
    if CAP_WEB_ADMIN in topology.plan(NODE_GATEWAY).capabilities:
        print(f"Web-admin: {admin_url(env)}")
    print(f"Основной VLESS URI: {paths['vless_uri']}")
    print(f"Hiddify URI alias: {paths['hiddify_uri_compat']}")
    print(f"Windows/v2rayN Xray JSON fallback: {paths['windows_xray_json']}")
    print(f"Android/v2rayNG Xray JSON fallback: {paths['android_xray_json']}")
    print(f"Route-safe VLESS профиль без multiplex для Hiddify: {paths['hiddify_json']}")
    print(f"Стандартный Hysteria2 URI для Hiddify/v2rayN: {paths['hysteria2_uri']}")
    print(f"Route-safe Android VLESS профиль без multiplex для Hiddify: {paths['android_hiddify_json']}")
    print(f"Windows direct server route helper: {paths['windows_route_bypass']}")
    print(f"JSON backup для Linux: {paths['linux_json']}")
    print(f"Следующие шаги: {paths['next_steps']}")
    print(clipboard_message)
    print("Что делать дальше:")
    print(f"1. Сначала импортируй {paths['vless_uri'].name}. Это основной контракт: обычный VLESS/Reality tunnel, маршрутизация на сервере.")
    print(f"2. JSON-файлы используй только как fallback, если конкретный клиент не умеет нормально импортировать URI.")
    print(f"3. Если клиент отправляет private/fake IP вместо домена, {cli_command('status')} покажет это в bucket blocked_private_fake.")
    print(f"4. В JSON-профилях multiplex явно выключен, чтобы независимые загрузки не делили один outer TCP stream; URI {paths['hiddify_uri_compat'].name} остаётся основным совместимым VLESS-контрактом.")
    print(f"5. Для импорта QUIC как отдельного узла в Hiddify/v2rayN используй {paths['hysteria2_uri'].name}.")
    print(f"6. Если сайты висят, сначала проверь серверные группы ошибок: {cli_command(f'status --deployment {deployment_name} --node gateway')}")
    print(f"7. Если включён TUN/full VPN и client-check показывает self-tunnel, запусти PowerShell от администратора: .\\{paths['windows_route_bypass'].name}")
    print(f"8. После install/reinstall запусти live-приёмку: {cli_command(f'verify live --deployment {deployment_name}')}")


def load_env_for_render(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        fail(f"Не найден deployment env: {env_path}")
    env = merge_env_with_defaults(normalize_deployment_env(load_env_file(env_path)), sanitize_name(env_path.stem))
    write_private_text(env_path, render_env_text(env))
    return apply_ru_direct_overlays(env, env_path)


def run_selected_remote_action(
    action: str,
    deployment_name: str,
    env_path: Path,
    env: dict[str, str],
    targets: list[RemoteTarget],
    *,
    node_arg: str = "all",
    preflights: dict[str, dict[str, str]] | None = None,
) -> None:
    target_map = {target.node_id: target for target in targets}
    topology = TopologySpec.from_env(env)
    requested = requested_node_ids(node_arg)
    available_nodes = [node_id for node_id in requested if node_id in target_map]
    wg_interface = (env.get("WG_INTERFACE", "").strip() or "wg0")
    if action in {"install", "reinstall"}:
        print_header("Локальная сборка артефактов")
        render_all_artifacts(env_path, env)
    changed_nodes: list[str] = []
    previous_release_ids = {
        node_id: str((preflights or {}).get(node_id, {}).get("release_id", ""))
        for node_id in available_nodes
    }
    try:
        for node_id in execution_node_ids(action, topology, tuple(available_nodes)):
            target = target_map[node_id]
            try:
                install_remote_node_with_recovery(target, deployment_name, env, action, wg_interface)
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "remote_node_changed", False) and node_id not in changed_nodes:
                    changed_nodes.append(node_id)
                raise
            if action in {"install", "reinstall"}:
                changed_nodes.append(node_id)
                settle_transport_after_install(node_id, target_map, preflights, env)
            if action not in {"install", "reinstall"}:
                print_preflight(target, remote_preflight(target, wg_interface))
        if changed_nodes:
            verify_postcutover(deployment_name)
    except Exception as exc:  # noqa: BLE001
        if not changed_nodes:
            raise
        try:
            rollback_changed_nodes(changed_nodes, target_map, deployment_name, env, previous_release_ids)
        except AppError as rollback_exc:
            raise AppError(f"{exc} Автоматический откат также завершился ошибкой: {rollback_exc}") from exc
        raise AppError(f"{exc} Изменённые узлы автоматически возвращены к предыдущему релизу.") from exc


def install_workflow(
    deployment: str | None,
    *,
    non_interactive: bool = False,
    yes: bool = False,
    topology_mode: str | None = None,
    gateway_location: str | None = None,
) -> int:
    print_header(f"Установка / обновление VPN {VERSION}")
    deployment_name, env_path, env, state, targets, preflights = prepare_remote_session(
        deployment,
        nodes=None,
        require_privilege=True,
        allow_create=True,
        persist_local=True,
        confirm_existing_connections=not non_interactive,
        non_interactive=non_interactive,
        sync_remote_env=topology_mode is None and gateway_location is None,
        topology_mode=topology_mode,
        gateway_location=gateway_location,
    )
    topology = TopologySpec.from_env(env)
    nodes = [target.node_id for target in targets]
    if topology.is_dual:
        ensure_foreign_wan_interface(env, preflights[NODE_EXIT])
    write_private_text(env_path, render_env_text(env))
    write_state(deployment_name, targets, existing_state=state, topology=TopologySpec.from_env(env, require_addresses=False).mode)
    print_summary(deployment_name, env, targets)
    target_map = {target.node_id: target for target in targets}
    actions = {
        node_id: ("reinstall" if preflights[node_id].get("installed") == "1" else "install")
        if non_interactive
        else ask_install_action(node_id, deployment_name, preflights[node_id], label=target_map[node_id].label)
        for node_id in nodes
    }
    if all(action == "skip" for action in actions.values()):
        print("Все серверы пропущены.")
        return 0
    if not yes and not prompt_yes_no("Продолжить установку / обновление?", default=True):
        print("Остановлено пользователем.")
        return 0
    total_steps = 1 + sum(1 for action in actions.values() if action != "skip")
    step = 1
    print_step(step, total_steps, "Локальная сборка артефактов")
    render_all_artifacts(env_path, env)
    step += 1
    previous_release_ids = {
        node_id: str(preflights.get(node_id, {}).get("release_id", ""))
        for node_id in nodes
    }
    changed_nodes: list[str] = []
    try:
        for node_id in execution_node_ids("install", topology, tuple(nodes)):
            action = actions[node_id]
            if action == "skip":
                continue
            print_step(step, total_steps, f"{target_map[node_id].label}: {action}")
            try:
                install_remote_node_with_recovery(
                    target_map[node_id],
                    deployment_name,
                    env,
                    action,
                    env.get("WG_INTERFACE", "").strip() or "wg0",
                )
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "remote_node_changed", False) and node_id not in changed_nodes:
                    changed_nodes.append(node_id)
                raise
            changed_nodes.append(node_id)
            settle_transport_after_install(node_id, target_map, preflights, env)
            step += 1
        verify_postcutover(deployment_name)
    except Exception as exc:  # noqa: BLE001
        if not changed_nodes:
            raise
        try:
            rollback_changed_nodes(changed_nodes, target_map, deployment_name, env, previous_release_ids)
        except AppError as rollback_exc:
            raise AppError(f"{exc} Автоматический откат также завершился ошибкой: {rollback_exc}") from exc
        raise AppError(f"{exc} Изменённые узлы автоматически возвращены к предыдущему релизу.") from exc
    finalize_install_output(env, deployment_name)
    print(f"Deployment env: {env_path}")
    print(f"Локальное состояние: {state_json_path(deployment_name)}")
    return 0


def status_workflow(deployment: str | None, node: str, *, non_interactive: bool = False) -> int:
    nodes = requested_node_ids(node)
    deployment_name, env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        nodes=nodes,
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
    )
    print_summary(deployment_name, env, targets)
    exit_code = 0
    for target in targets:
        try:
            snapshot = DiagnosticsSnapshot.from_agent(remote_agent_snapshot(target, compact=True))
        except Exception as exc:  # noqa: BLE001
            log_exception("status.snapshot", exc, extra={"node_id": target.node_id, "host": target.ssh_host})
            warn(f"{target.label}: structured snapshot unavailable: {error_summary(exc)}")
            exit_code = 1
            continue
        print_header(f"Snapshot {target.label}")
        for line in format_snapshot_summary(snapshot):
            print(line)
        window_statuses = {window.collector.status for window in snapshot.log_windows.values()}
        if snapshot.verdict == "failed" or snapshot.collector_status == "error" or "error" in window_statuses:
            exit_code = 1
        elif exit_code == 0 and (
            snapshot.verdict == "degraded"
            or snapshot.collector_status == "stale"
            or "stale" in window_statuses
            or (snapshot.verdict == "inconclusive" and snapshot.collector_status != "skipped")
        ):
            exit_code = 2
    print(f"Deployment env: {env_path}")
    return exit_code


def maintain_workflow(
    deployment: str | None,
    *,
    apply_updates: bool,
    refresh_assets: bool,
    reboot: bool,
    non_interactive: bool = False,
    yes: bool = False,
) -> int:
    """Apply OS maintenance in egress-first order with a live acceptance gate."""
    nodes = requested_node_ids("all")
    deployment_name, _env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        nodes=nodes,
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
        sync_remote_env=refresh_assets,
    )
    target_map = {target.node_id: target for target in targets}
    nodes = list(target_map)
    topology = TopologySpec.from_env(env)
    if not apply_updates and not refresh_assets:
        print_header("Обслуживание серверов")
        for node_id in execution_node_ids("install", topology, tuple(nodes)):
            target = target_map[node_id]
            snapshot = DiagnosticsSnapshot.from_agent(remote_agent_snapshot(target))
            maintenance = snapshot.maintenance
            print(
                f"{target.label}: updates={maintenance.get('upgradable', 'unknown')}, "
                f"security={maintenance.get('security_upgradable', 'unknown')}, "
                f"reboot_required={maintenance.get('reboot_required', 'unknown')}"
            )
        print(f"Для применения обновлений используй {cli_command('maintain --apply --yes')}; для rule assets добавь --refresh-assets.")
        return 0

    if not yes and not prompt_yes_no("Применить выбранное обслуживание по очереди с live acceptance после каждой роли?", default=False):
        print("Остановлено пользователем.")
        return 0

    if refresh_assets:
        print_header("Транзакционное обновление rule assets")
        render_config_artifacts(_env_path, env, fetch_assets_first=True)
        package_bundle(env)
        for node_id in execution_node_ids("install", topology, tuple(nodes)):
            target = target_map[node_id]
            install_remote_node_with_recovery(
                target,
                deployment_name,
                env,
                "reinstall",
                env.get("WG_INTERFACE", "wg0") or "wg0",
            )
            verify_postcutover(deployment_name)

    for node_id in execution_node_ids("install", topology, tuple(nodes)) if apply_updates else ():
        target = target_map[node_id]
        print_header(f"Обслуживание {target.label}")
        ssh_stream(
            target,
            "/usr/bin/python3 /usr/local/lib/vpn-stack/vpn-stack-agent.py maintain --apply",
            as_root=True,
        )
        snapshot = DiagnosticsSnapshot.from_agent(remote_agent_snapshot(target, live_probes=True, profile="acceptance"))
        verdicts = snapshot.component_verdicts
        if verdicts.get("server_path") != "verified" or (node_id == NODE_GATEWAY and verdicts.get("public_front") != "verified"):
            raise AppError(f"{target.label}: maintenance acceptance failed: {snapshot.reasons}")
        if snapshot.collector_status != "ok":
            raise AppError(f"{target.label}: maintenance acceptance evidence is incomplete")
        if reboot and snapshot.maintenance.get("reboot_required"):
            ssh_stream(target, "systemctl reboot", as_root=True)
            wait_for_remote_recovery(target, env.get("WG_INTERFACE", "wg0") or "wg0", timeout_sec=300)
            recovered = DiagnosticsSnapshot.from_agent(remote_agent_snapshot(target, live_probes=True, profile="acceptance"))
            if recovered.component_verdicts.get("server_path") != "verified" or recovered.collector_status != "ok":
                raise AppError(f"{target.label}: acceptance after reboot failed")
        verify_postcutover(deployment_name)

    return 0


def routes_workflow(
    deployment: str | None,
    action: str,
    *,
    value: str = "",
    outbound: str = "",
    rule_type: str = "domain",
    include_subdomains: bool = False,
    rule_id: str = "",
    non_interactive: bool = False,
) -> int:
    import json
    import shlex

    deployment_name, _env_path, _env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        nodes=[NODE_GATEWAY],
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
    )
    target = targets[0]
    command = ["/usr/bin/python3", "/usr/local/lib/vpn-stack/vpn-stack-agent.py", "routes", action]
    if action == "add":
        command.extend(["--type", rule_type, "--value", value, "--outbound", outbound])
        if include_subdomains:
            command.append("--include-subdomains")
    elif action == "remove":
        command.extend(["--id", rule_id])
    payload = json.loads(ssh_capture(target, " ".join(shlex.quote(part) for part in command), as_root=True, command_timeout=60))
    print_header("Маршруты web-админки")
    print(f"deployment: {deployment_name}")
    for rule in payload.get("rules", []):
        print(f"{rule['id']} {rule['type']} {rule['value']} -> {rule['outbound']} enabled={rule['enabled']}")
    return 0


def remote_action_workflow(deployment: str | None, node: str, action: str, *, non_interactive: bool = False, yes: bool = False) -> int:
    nodes = requested_node_ids(node)
    deployment_name, env_path, env, state, targets, preflights = prepare_remote_session(
        deployment,
        nodes=nodes,
        require_privilege=True,
        allow_create=False,
        persist_local=True,
        confirm_existing_connections=not non_interactive,
        non_interactive=non_interactive,
        sync_remote_env=action in {"install", "reinstall"},
    )
    nodes = [target.node_id for target in targets]
    if action in {"install", "reinstall"} and NODE_EXIT in nodes:
        ensure_foreign_wan_interface(env, preflights[NODE_EXIT])
        write_private_text(env_path, render_env_text(env))
        write_state(deployment_name, targets, existing_state=state, topology=TopologySpec.from_env(env, require_addresses=False).mode)
    targets = filter_targets_for_action(action, targets, preflights)
    print_summary(deployment_name, env, targets)
    if not targets:
        print_header("Готово")
        print("Подходящих серверов для действия не найдено.")
        return 0
    if not yes and not prompt_yes_no(f"Продолжить действие {action}?", default=False):
        print("Остановлено пользователем.")
        return 0
    run_selected_remote_action(action, deployment_name, env_path, env, targets, node_arg=node, preflights=preflights)
    if action in {"install", "reinstall"}:
        finalize_install_output(env, deployment_name)
    else:
        print_header("Готово")
        print(f"Deployment env: {env_path}")
        print(f"Локальное состояние: {state_json_path(deployment_name)}")
    return 0


def client_check_workflow(deployment: str | None, node: str) -> int:
    ensure_directories()
    deployment_name = select_existing_deployment(deployment)
    env_path, env = load_existing_deployment_env(deployment_name)
    state = load_state(deployment_name)
    configured_nodes = {item.node_id for item in TopologySpec.from_env(env, require_addresses=False).nodes}
    selected_nodes = [candidate for candidate in requested_node_ids(node) if candidate in configured_nodes]
    if not selected_nodes:
        raise AppError("Запрошенный сервер отсутствует в topology deployment.")
    print_header("Проверка клиентских маршрутов")
    print(f"deployment: {deployment_name}")
    failed = False
    route_failed = False
    for selected_node in selected_nodes:
        target = build_target(selected_node, env, state)
        route = local_route_to_server(target)
        public_ip = target.public_ip or target.ssh_host or "-"
        if route is None:
            print(f"{target.label}: локальная route-проверка недоступна или IP не найден ({public_ip})")
            continue
        verdict = "BAD: self-tunnel" if route_uses_self_tunnel(route, client_tun_name=env.get("CLIENT_TUN_NAME", "")) else "OK"
        print(
            f"{target.label}: {verdict}; "
            f"ip={route.target_ip}; iface={route.interface_alias or '-'}; "
            f"source={route.source_address or '-'}; next-hop={route.next_hop or '-'}"
        )
        if verdict.startswith("BAD"):
            route_failed = True
            failed = True
    print_header("Проверка локальных клиентских профилей")
    drift_findings = find_client_drift(env)
    if drift_findings:
        for finding in drift_findings:
            print(f"STALE: {finding.path}: {finding.issue}")
        print("Проблема: локальный клиентский профиль не совпадает с текущим deployment. Удали старый профиль в клиенте и импортируй заново свежий vless-uri.txt или JSON из out/<deployment>/client.")
        failed = True
    else:
        print("Явно устаревшие локальные профили не найдены.")
    if failed:
        if route_failed:
            print("Проблема: IP сервера уходит через VPN-интерфейс. В TUN/full VPN используй route-safe JSON или добавь прямой маршрут к IP серверов.")
        paths = client_artifact_paths(env)
        print(f"Свежий VLESS URI: {paths['vless_uri']}")
        print(f"Свежий Hiddify JSON: {paths['hiddify_json']}")
        print(f"Windows helper: {paths['windows_route_bypass']}")
        print(f"Deployment env: {env_path}")
        return 1
    print("Клиентские маршруты до серверов не выглядят как self-tunnel.")
    print(f"Deployment env: {env_path}")
    return 0


def cleanup_local_workflow(deployment: str | None, *, drop_env: bool, drop_runtime: bool) -> int:
    ensure_directories()
    deployment_name = select_existing_deployment(deployment)
    removed: list[str] = []
    out_dir = OUT_DIR / deployment_name
    env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
    if out_dir.is_dir():
        shutil.rmtree(out_dir)
        removed.append(str(out_dir))
    for path in (state_json_path(deployment_name),):
        if path.is_file():
            path.unlink()
            removed.append(str(path))
    if drop_env and env_path.is_file():
        env_path.unlink()
        removed.append(str(env_path))
    if drop_runtime and RUNTIME_DIR.is_dir():
        shutil.rmtree(RUNTIME_DIR)
        removed.append(str(RUNTIME_DIR))
    if removed:
        print("Удалено:")
        for item in removed:
            print(item)
    else:
        print("Локальные артефакты для этого deployment не найдены.")
    return 0


def run_menu_action(action: Any, *, return_to: str) -> None:
    try:
        result = action()
        if isinstance(result, int) and result != 0:
            warn(f"Действие завершилось с кодом {result}.")
    except UserCancelled as exc:
        warn(error_summary(exc) if str(exc) else "Операция отменена пользователем.")
    except KeyboardInterrupt:
        warn("Остановлено пользователем.")
    except EOFError:
        warn(f"Ввод прерван. Возврат в {return_to}.")
    except AppError as exc:
        log_path = log_exception("menu.app_error", exc, extra={"return_to": return_to})
        warn(f"Ошибка: {error_summary(exc)}")
        if log_path:
            print(f"Лог ошибки: {log_path}")
        print(f"Возврат в {return_to}.")
    except Exception as exc:  # noqa: BLE001
        if is_audit_failure(exc):
            warn(f"Самопроверка завершилась с ошибкой: {error_summary(exc)}")
            print("Смотри summary и логи в out/audit/<run_id>/.")
            print(f"Возврат в {return_to}.")
            return
        log_path = log_exception("menu.unhandled", exc, extra={"return_to": return_to})
        warn(f"Непредвиденная ошибка: {error_summary(exc)}")
        if log_path:
            print(f"Лог ошибки: {log_path}")
        print(f"Возврат в {return_to}.")
    else:
        print(f"Возврат в {return_to}.")


def audit_menu_workflow() -> int:
    while True:
        print_header("Самопроверка")
        audit_mode = prompt_choice(
            "Выбери режим самопроверки",
            [
                ("quick", "Локальная проверка"),
                ("docker", "Docker regression"),
                ("lab", "Глубокий Docker lab"),
                ("all", "Полный прогон"),
                ("back", "Назад в главное меню"),
            ],
            default="quick",
        )
        if audit_mode == "back":
            return 0
        from .audit.runner import main as audit_main

        run_menu_action(lambda mode=audit_mode: audit_main([mode]), return_to="меню самопроверки")


def menu_workflow() -> int:
    while True:
        print_header(f"VPN Installer {VERSION}")
        choice = prompt_choice(
            "Выбери действие",
            [
                ("install", "Установить или обновить VPN"),
                ("status", "Проверить текущее состояние"),
                ("admin", "Показать адрес web-admin"),
                ("reinstall", "Переустановить"),
                ("remove", "Удалить с серверов"),
                ("purge", "Полностью очистить состояние"),
                ("cleanup-local", "Удалить локальные файлы"),
                ("audit", "Запустить самопроверку"),
                ("exit", "Выход"),
            ],
            default="install",
        )
        if choice == "exit":
            print("Завершено.")
            return 0
        if choice == "audit":
            audit_menu_workflow()
            continue
        if choice == "admin":
            run_menu_action(lambda: admin_access_workflow(None), return_to="главное меню")
            continue
        if choice == "cleanup-local":
            run_menu_action(lambda: cleanup_local_workflow(None, drop_env=False, drop_runtime=False), return_to="главное меню")
            continue
        node = select_node_for_menu(choice)
        if choice == "install":
            run_menu_action(lambda: install_workflow(None), return_to="главное меню")
            continue
        if choice == "status":
            run_menu_action(lambda selected_node=node: status_workflow(None, selected_node), return_to="главное меню")
            continue
        run_menu_action(lambda selected_node=node, action_name=choice: remote_action_workflow(None, selected_node, action_name), return_to="главное меню")
