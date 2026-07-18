from __future__ import annotations

import argparse
import os
import shlex
import shutil
import textwrap
import time
import traceback
from pathlib import Path
from typing import Any

from .clipboard import copy_to_clipboard
from .client_drift import find_client_drift
from .common import DEPLOYMENTS_DIR, OUT_DIR, RUNTIME_DIR, INSTALL_SCRIPT_PATH, ensure_directories, fail, print_header, sanitize_name, warn, write_text
from .config import (
    apply_ru_direct_overlays,
    critical_env_view,
    load_existing_deployment_env,
    load_env_file,
    merge_env_with_defaults,
    parse_env_text,
    render_env_text,
    require_env,
    ensure_deployment_env,
)
from .error_logging import log_exception
from .diagnostics import DiagnosticsSnapshot
from .localnet import assert_server_route_not_self_tunneled, local_route_to_server, route_uses_self_tunnel
from .models import AppError, ROLE_FOREIGN, ROLE_META, ROLE_RU, RemoteTarget, UserCancelled
from .prompts import (
    ask_install_action,
    auth_mode_label,
    prompt_choice,
    prompt_secret,
    prompt_server_connection,
    prompt_yes_no,
    select_deployment,
    select_existing_deployment,
    select_role_for_menu,
    validate_target_settings,
)
from .remote import ensure_remote_privilege, fetch_remote_deployment_env, print_preflight, remote_agent_snapshot, remote_preflight, scp_upload, ssh_capture, ssh_stream
from .roles import execution_roles, requested_roles
from .client_artifacts import client_artifact_paths
from .render import deployment_out_dir, package_bundle, render_all_artifacts, render_config_artifacts
from .state import load_state, state_json_path, state_legacy_path, write_state
from .status_output import format_snapshot_summary
from .targets import (
    apply_env_connection_overrides,
    build_target,
    can_fetch_remote_env,
    remote_env_matches_target,
    role_env_prefix,
    sync_targets_from_env,
    update_env_with_targets,
)


def is_audit_failure(exc: BaseException) -> bool:
    return exc.__class__.__name__ == "AuditFailure" and exc.__class__.__module__.startswith("vpn_installer.audit")


def load_remote_authoritative_env(
    deployment_name: str,
    env_path: Path,
    env: dict[str, str],
    targets: list[RemoteTarget],
    preflights: dict[str, dict[str, str]],
) -> tuple[dict[str, str], bool]:
    remote_envs: dict[str, dict[str, str]] = {}
    for target in targets:
        preflight = preflights.get(target.role, {})
        if not remote_env_matches_target(target, deployment_name, preflight):
            continue
        if not can_fetch_remote_env(target):
            continue
        remote_env_text = fetch_remote_deployment_env(target)
        remote_envs[target.role] = merge_env_with_defaults(parse_env_text(remote_env_text), deployment_name)
    if len(remote_envs) > 1:
        role_items = list(remote_envs.items())
        baseline_role, baseline_env = role_items[0]
        baseline_view = critical_env_view(baseline_env)
        for role, candidate_env in role_items[1:]:
            candidate_view = critical_env_view(candidate_env)
            if candidate_view != baseline_view:
                diff_keys = [key for key in sorted(set(baseline_view) | set(candidate_view)) if baseline_view.get(key, "") != candidate_view.get(key, "")]
                preview = ", ".join(diff_keys[:6])
                if len(diff_keys) > 6:
                    preview += ", ..."
                raise AppError(
                    f"Remote env mismatch between roles: {baseline_role} vs {role}. "
                    f"Отличаются критичные поля: {preview}"
                )
    if not remote_envs:
        return env, False
    source_env = remote_envs.get(ROLE_RU) or remote_envs.get(ROLE_FOREIGN) or env
    if source_env == env:
        return env, False
    write_text(env_path, render_env_text(source_env))
    sync_targets_from_env(source_env, targets)
    print("Локальный deployment env синхронизирован из установленного сервера.")
    return source_env, True


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
    print_header("Сводка deployment")
    print(f"deployment: {deployment_name}")
    print(f"IP российского сервера: {env.get('RU_PUBLIC_IP', '-')}")
    print(f"IP зарубежного сервера: {env.get('FOREIGN_PUBLIC_IP', '-')}")
    for target in targets:
        print(f"{target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port} ({auth_mode_label(target.auth_mode)})")
    print(f"WAN_INTERFACE: {env.get('WAN_INTERFACE') or '-'}")


def print_step(step: int, total: int, message: str) -> None:
    print(f"[{step}/{total}] {message}")


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
        print(f"Проверяю подключение к {target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port}")
        try:
            if enforce_safe_route:
                assert_server_route_not_self_tunneled(target, env)
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
                if preflight.get("os_id") != "ubuntu":
                    fail(f"{target.label} должен быть Ubuntu.")
                if preflight.get("os_version") and preflight["os_version"] != "24.04":
                    warn(f"{target.label} не на Ubuntu 24.04: {preflight['os_version']}")
            if require_privilege:
                ensure_remote_privilege(target, preflight, prompt_yes_no=prompt_yes_no, prompt_secret=prompt_secret)
            return target, preflight
        except Exception as exc:  # noqa: BLE001
            warn(str(exc))
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
            f"Задай state через обычный запуск или env {role_env_prefix(target.role)}_PUBLIC_IP/{role_env_prefix(target.role)}_SSH_HOST."
        )
    validate_target_settings(target)
    if target.auth_mode == "password" and not target.ssh_password:
        raise AppError(
            f"{target.label}: для non-interactive password-входа нужен env "
            f"{role_env_prefix(target.role)}_SSH_PASSWORD или VPN_SSH_PASSWORD."
        )
    print(f"Проверяю подключение к {target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port}")
    if enforce_safe_route:
        assert_server_route_not_self_tunneled(target, env)
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
        if preflight.get("os_id") != "ubuntu":
            fail(f"{target.label} должен быть Ubuntu.")
        if preflight.get("os_version") and preflight["os_version"] != "24.04":
            warn(f"{target.label} не на Ubuntu 24.04: {preflight['os_version']}")
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
    roles: list[str],
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
) -> tuple[str, Path, dict[str, str], dict[str, Any], list[RemoteTarget], dict[str, dict[str, str]]]:
    if allow_create or persist_local:
        ensure_directories()
    if allow_create:
        deployment_name = select_deployment(deployment_arg)
        env_path = DEPLOYMENTS_DIR / f"{deployment_name}.env"
        env = ensure_deployment_env(env_path, deployment_name)
    else:
        deployment_name = select_existing_deployment(deployment_arg)
        env_path, env = load_existing_deployment_env(deployment_name)
    state = load_state(deployment_name)
    print_header("Параметры deployment")
    print(f"deployment: {deployment_name}")
    targets: list[RemoteTarget] = []
    preflights: dict[str, dict[str, str]] = {}
    wg_interface = (env.get("WG_INTERFACE", "").strip() or "wg0")
    for role in roles:
        target = apply_env_connection_overrides(build_target(role, env, state))
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
        preflights[role] = preflight
    update_env_with_targets(env, targets)
    synced_from_remote = False
    if sync_remote_env:
        env, synced_from_remote = load_remote_authoritative_env(deployment_name, env_path, env, targets, preflights)
    if persist_local or synced_from_remote:
        write_text(env_path, render_env_text(env))
    if persist_local:
        write_state(deployment_name, targets, existing_state=state)
    return deployment_name, env_path, env, state, targets, preflights


def postcheck_command(role: str, wg_interface: str) -> str:
    ru_service_checks = (
        '\n'.join(
            [
                'check_service_active sing-box sing-box',
                'check_service_active vpn-stack-xray.service vpn-stack-xray',
                'admin_web_enabled="$(grep -E \'^ADMIN_WEB_ENABLED=\' /etc/vpn-stack/deployment.env 2>/dev/null | head -n1 | cut -d= -f2- | sed \'s/^"//; s/"$//\')"',
                'admin_web_enabled="${admin_web_enabled:-1}"',
                'case "${admin_web_enabled,,}" in 0|false|no|off) ;; *) check_service_active vpn-stack-admin.service vpn-stack-admin ;; esac',
            ]
        )
        if role == ROLE_RU
        else textwrap.dedent(
            """\
            if systemctl list-unit-files sing-box.service >/dev/null 2>&1; then
              systemctl is-active sing-box >/dev/null || true
            fi
            """
        ).strip()
    )
    return textwrap.dedent(
        f"""\
        set -euo pipefail
        check_service_active() {{
          local service="$1"
          local label="$2"
          local state=""
          local attempt
          for attempt in 1 2 3 4 5 6 7 8 9 10; do
            state="$(systemctl is-active "$service" 2>/dev/null || true)"
            if [[ "$state" == "active" ]]; then
              return 0
            fi
            if [[ "$state" != "activating" ]]; then
              break
            fi
            sleep 1
          done
          printf 'postcheck_failed_service=%s\\n' "${{label}}"
          printf 'postcheck_service_state=%s\\n' "${{state:-$(systemctl is-active "$service" 2>/dev/null || true)}}"
          printf 'postcheck_service_enabled=%s\\n' "$(systemctl is-enabled "$service" 2>/dev/null || true)"
          systemctl status "$service" --no-pager --full || true
          journalctl -u "$service" -n 20 --no-pager || true
          exit 1
        }}
        check_service_active nftables nftables
        check_service_active vpn-stack-health.timer vpn-stack-health.timer
        check_service_active wg-quick@{wg_interface} wg-quick@{wg_interface}
        test -x /usr/local/lib/vpn-stack/vpn-stack-agent.py
        {ru_service_checks}
        printf 'role='
        cat /etc/vpn-stack/role
        printf 'installed_at='
        cat /etc/vpn-stack/installed_at
        deployment_name="$(grep -E '^DEPLOY_NAME=' /etc/vpn-stack/deployment.env | head -n1 | cut -d= -f2- | sed 's/^\"//; s/\"$//')"
        printf 'deployment=%s\\n' "${{deployment_name}}"
        """
    ).strip()


def cleanup_remote_workdir(target: RemoteTarget, remote_root: str) -> None:
    try:
        ssh_stream(target, f"rm -rf {shlex.quote(remote_root)}")
    except Exception as exc:  # noqa: BLE001
        warn(f"Не удалось очистить временную папку на {target.label}: {exc}")


def is_recoverable_remote_disconnect(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(
        marker in text
        for marker in (
            "socket exception",
            "forcibly closed by the remote host",
            "connection reset",
            "connection aborted",
            "broken pipe",
            "closed by remote host",
            "eof during negotiation",
        )
    )


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


def filter_targets_for_action(
    action: str,
    targets: list[RemoteTarget],
    preflights: dict[str, dict[str, str]],
) -> list[RemoteTarget]:
    if action not in {"remove", "purge"}:
        return targets
    actionable: list[RemoteTarget] = []
    for target in targets:
        preflight = preflights.get(target.role, {})
        installed = preflight.get("installed", "0")
        if installed != "1":
            print(f"{target.label}: стек не найден на сервере, действие {action} пропущено.")
            continue
        actionable.append(target)
    return actionable


def install_remote_role(target: RemoteTarget, deployment_name: str, env: dict[str, str], action: str) -> None:
    remote_root = f"vpn-installer/{deployment_name}/{target.role}"
    archive_name = f"{target.role}.tar.gz"
    print_header(f"Подготовка {target.label}")
    ssh_stream(target, f"rm -rf {shlex.quote(remote_root)} && mkdir -p {shlex.quote(remote_root)}")
    try:
        if action in {"install", "reinstall"}:
            bundle_path = deployment_out_dir(env) / "bundle" / f"{target.role}.tar.gz"
            if not bundle_path.is_file():
                fail(f"Не найден bundle для {target.label}: {bundle_path}")
            print_header(f"Загрузка bundle на {target.label}")
            scp_upload(target, bundle_path, f"{remote_root}/{archive_name}")
            remote_command = (
                f"cd {shlex.quote(remote_root)} && "
                f"tar -xzf {shlex.quote(archive_name)} && "
                "chmod +x ./install.sh && "
                f"./install.sh --role {shlex.quote(target.role)} --action {shlex.quote(action)} --env-file ./deployment.env --assets-dir ./assets"
            )
        else:
            scp_upload(target, INSTALL_SCRIPT_PATH, f"{remote_root}/install.sh")
            remote_command = f"cd {shlex.quote(remote_root)} && chmod +x ./install.sh && ./install.sh --role {shlex.quote(target.role)} --action {shlex.quote(action)}"
        print_header(f"Действие {action} для {target.label}")
        ssh_stream(target, remote_command, as_root=True)
    finally:
        cleanup_remote_workdir(target, remote_root)


def postcheck_remote_role(target: RemoteTarget, wg_interface: str) -> None:
    print_header(f"Пост-проверка {target.label}")
    ssh_stream(target, postcheck_command(target.role, wg_interface), as_root=True)


def finalize_install_output(env: dict[str, str], deployment_name: str) -> None:
    paths = client_artifact_paths(env)
    uri_payload = paths["vless_uri"].read_text(encoding="utf-8") if paths["vless_uri"].is_file() else ""
    clipboard_ok, clipboard_message = copy_to_clipboard(uri_payload)
    print_header("Готово")
    print(f"Deployment: {deployment_name}")
    print(f"Основной простой VLESS URI: {paths['vless_uri']}")
    print(f"Hiddify URI alias: {paths['hiddify_uri_compat']}")
    print(f"Windows/v2rayN Xray JSON fallback: {paths['windows_xray_json']}")
    print(f"Android/v2rayNG Xray JSON fallback: {paths['android_xray_json']}")
    print(f"JSON fallback для Hiddify: {paths['hiddify_json']}")
    print(f"Android JSON fallback для Hiddify: {paths['android_hiddify_json']}")
    print(f"Windows route bypass helper: {paths['windows_route_bypass']}")
    print(f"JSON backup для Linux: {paths['linux_json']}")
    print(f"Следующие шаги: {paths['next_steps']}")
    print(clipboard_message)
    print("Что делать дальше:")
    print(f"1. Сначала импортируй простой {paths['vless_uri'].name}. Это основной контракт: обычный VLESS/Reality tunnel, маршрутизация на сервере.")
    print(f"2. JSON-файлы используй только как fallback, если конкретный клиент не умеет нормально импортировать URI.")
    print("3. Если клиент отправляет private/fake IP вместо домена, vpn status покажет это в bucket blocked_private_fake.")
    print(f"4. Для Hiddify сначала пробуй URI {paths['hiddify_uri_compat'].name}; JSON оставлен как запасной вариант.")
    print(f"5. Если сайты висят, сначала проверь серверные группы ошибок: vpn status --deployment {deployment_name} --role ru-gateway")
    print(f"6. Если включён TUN/full VPN и client-check показывает self-tunnel, запусти PowerShell от администратора: .\\{paths['windows_route_bypass'].name}")
    print(f"7. После install/reinstall запусти live-приёмку: vpn verify live --deployment {deployment_name}")


def load_env_for_render(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        fail(f"Не найден deployment env: {env_path}")
    env = merge_env_with_defaults(load_env_file(env_path), sanitize_name(env_path.stem))
    write_text(env_path, render_env_text(env))
    return apply_ru_direct_overlays(env, env_path)


def run_selected_remote_action(
    action: str,
    deployment_name: str,
    env_path: Path,
    env: dict[str, str],
    targets: list[RemoteTarget],
    *,
    role_arg: str = "all",
) -> None:
    target_map = {target.role: target for target in targets}
    requested = requested_roles(role_arg)
    available_roles = [role for role in requested if role in target_map]
    wg_interface = (env.get("WG_INTERFACE", "").strip() or "wg0")
    if action in {"install", "reinstall"}:
        print_header("Локальная сборка артефактов")
        render_all_artifacts(env_path, env)
    for role in execution_roles(action, available_roles):
        target = target_map[role]
        try:
            install_remote_role(target, deployment_name, env, action)
        except AppError as exc:
            if action in {"install", "reinstall"} and is_recoverable_remote_disconnect(exc):
                warn(f"{target.label}: SSH-сессия оборвалась во время {action}. Жду повторной доступности сервера и проверяю итоговое состояние.")
                wait_for_remote_recovery(target, wg_interface)
            else:
                raise
        if action in {"install", "reinstall"}:
            postcheck_remote_role(target, wg_interface)
        else:
            print_preflight(target, remote_preflight(target, wg_interface))


def install_workflow(deployment: str | None, *, non_interactive: bool = False, yes: bool = False) -> int:
    print_header("Установка / обновление VPN")
    print("Сценарий:")
    print("1. Выбор или создание deployment")
    print("2. Проверка российского сервера")
    print("3. Проверка зарубежного сервера")
    print("4. Локальная сборка артефактов")
    print("5. Установка сначала на зарубежный сервер, затем на российский")
    roles = requested_roles("all")
    deployment_name, env_path, env, state, targets, preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=True,
        allow_create=True,
        persist_local=True,
        confirm_existing_connections=not non_interactive,
        non_interactive=non_interactive,
        sync_remote_env=True,
    )
    ensure_foreign_wan_interface(env, preflights[ROLE_FOREIGN])
    write_text(env_path, render_env_text(env))
    write_state(deployment_name, targets, existing_state=state)
    print_summary(deployment_name, env, targets)
    actions = {
        ROLE_RU: ("reinstall" if preflights[ROLE_RU].get("installed") == "1" else "install") if non_interactive else ask_install_action(ROLE_RU, deployment_name, preflights[ROLE_RU]),
        ROLE_FOREIGN: ("reinstall" if preflights[ROLE_FOREIGN].get("installed") == "1" else "install") if non_interactive else ask_install_action(ROLE_FOREIGN, deployment_name, preflights[ROLE_FOREIGN]),
    }
    if all(action == "skip" for action in actions.values()):
        print("Обе роли пропущены.")
        return 0
    if not yes and not prompt_yes_no("Продолжить установку / обновление?", default=True):
        print("Остановлено пользователем.")
        return 0
    total_steps = 1 + 2 * sum(1 for action in actions.values() if action != "skip")
    step = 1
    print_step(step, total_steps, "Локальная сборка артефактов")
    render_all_artifacts(env_path, env)
    step += 1
    target_map = {target.role: target for target in targets}
    for role in execution_roles("install", roles):
        action = actions[role]
        if action == "skip":
            continue
        print_step(step, total_steps, f"{ROLE_META[role]['label']}: {action}")
        install_remote_role(target_map[role], deployment_name, env, action)
        step += 1
        print_step(step, total_steps, f"{ROLE_META[role]['label']}: пост-проверка")
        postcheck_remote_role(target_map[role], (env.get("WG_INTERFACE", "").strip() or "wg0"))
        step += 1
    finalize_install_output(env, deployment_name)
    print(f"Deployment env: {env_path}")
    print(f"Локальное состояние: {state_json_path(deployment_name)}")
    return 0


def status_workflow(deployment: str | None, role: str, *, non_interactive: bool = False) -> int:
    roles = requested_roles(role)
    deployment_name, env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
    )
    print_summary(deployment_name, env, targets)
    failures = 0
    for target in targets:
        try:
            snapshot = DiagnosticsSnapshot.from_agent(remote_agent_snapshot(target, compact=True))
        except Exception as exc:  # noqa: BLE001
            warn(f"{target.label}: structured snapshot unavailable: {exc}")
            failures += 1
            continue
        print_header(f"Snapshot {target.label}")
        for line in format_snapshot_summary(snapshot):
            print(line)
    print(f"Deployment env: {env_path}")
    return 1 if failures else 0


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
    roles = requested_roles("all")
    deployment_name, _env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=True,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
        non_interactive=non_interactive,
        enforce_safe_route=False,
        sync_remote_env=refresh_assets,
    )
    target_map = {target.role: target for target in targets}
    if not apply_updates and not refresh_assets:
        print_header("Обслуживание серверов")
        for role in execution_roles("install", roles):
            target = target_map[role]
            snapshot = remote_agent_snapshot(target)
            maintenance = snapshot.get("maintenance", {})
            print(
                f"{target.label}: updates={maintenance.get('upgradable', 0)}, "
                f"security={maintenance.get('security_upgradable', 0)}, "
                f"reboot_required={maintenance.get('reboot_required', False)}"
            )
        print("Для применения обновлений используй vpn maintain --apply --yes; для rule assets добавь --refresh-assets.")
        return 0

    if not yes and not prompt_yes_no("Применить выбранное обслуживание по очереди с live acceptance после каждой роли?", default=False):
        print("Остановлено пользователем.")
        return 0

    if refresh_assets:
        print_header("Транзакционное обновление rule assets")
        render_config_artifacts(_env_path, env, fetch_assets_first=True)
        package_bundle(env)
        for role in execution_roles("install", roles):
            target = target_map[role]
            install_remote_role(target, deployment_name, env, "reinstall")
            postcheck_remote_role(target, env.get("WG_INTERFACE", "wg0") or "wg0")

    for role in execution_roles("install", roles) if apply_updates else ():
        target = target_map[role]
        print_header(f"Обслуживание {target.label}")
        ssh_stream(
            target,
            "DEBIAN_FRONTEND=noninteractive apt-get update && "
            "DEBIAN_FRONTEND=noninteractive apt-get -y --with-new-pkgs upgrade",
            as_root=True,
        )
        snapshot = remote_agent_snapshot(target, live_probes=True, profile="acceptance")
        verdicts = snapshot.get("verdicts", {})
        if verdicts.get("server_path") != "verified" or (role == ROLE_RU and verdicts.get("public_front") != "verified"):
            raise AppError(f"{target.label}: maintenance acceptance failed: {verdicts.get('reasons', [])}")
        if reboot and snapshot.get("maintenance", {}).get("reboot_required"):
            ssh_stream(target, "systemctl reboot", as_root=True)
            wait_for_remote_recovery(target, env.get("WG_INTERFACE", "wg0") or "wg0", timeout_sec=300)
            recovered = remote_agent_snapshot(target, live_probes=True, profile="acceptance")
            if recovered.get("verdicts", {}).get("server_path") != "verified":
                raise AppError(f"{target.label}: acceptance after reboot failed")

    from .verify import verify_live_workflow

    return verify_live_workflow(deployment_name, non_interactive=True)


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
        roles=[ROLE_RU],
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


def remote_action_workflow(deployment: str | None, role: str, action: str, *, non_interactive: bool = False, yes: bool = False) -> int:
    roles = requested_roles(role)
    deployment_name, env_path, env, state, targets, preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=True,
        allow_create=False,
        persist_local=True,
        confirm_existing_connections=not non_interactive,
        non_interactive=non_interactive,
        sync_remote_env=action in {"install", "reinstall"},
    )
    if action in {"install", "reinstall"} and ROLE_FOREIGN in roles:
        ensure_foreign_wan_interface(env, preflights[ROLE_FOREIGN])
        write_text(env_path, render_env_text(env))
        write_state(deployment_name, targets, existing_state=state)
    targets = filter_targets_for_action(action, targets, preflights)
    print_summary(deployment_name, env, targets)
    if not targets:
        print_header("Готово")
        print("Подходящих серверов для действия не найдено.")
        return 0
    if not yes and not prompt_yes_no(f"Продолжить действие {action}?", default=False):
        print("Остановлено пользователем.")
        return 0
    run_selected_remote_action(action, deployment_name, env_path, env, targets, role_arg=role)
    if action in {"install", "reinstall"}:
        finalize_install_output(env, deployment_name)
    else:
        print_header("Готово")
        print(f"Deployment env: {env_path}")
        print(f"Локальное состояние: {state_json_path(deployment_name)}")
    return 0


def client_check_workflow(deployment: str | None, role: str) -> int:
    ensure_directories()
    deployment_name = select_existing_deployment(deployment)
    env_path, env = load_existing_deployment_env(deployment_name)
    state = load_state(deployment_name)
    print_header("Проверка клиентских маршрутов")
    print(f"deployment: {deployment_name}")
    failed = False
    route_failed = False
    for selected_role in requested_roles(role):
        target = build_target(selected_role, env, state)
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
            print("Проблема: IP сервера уходит через VPN-интерфейс. В TUN/full VPN используй route-safe JSON или добавь bypass/direct rule для IP обоих серверов.")
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
    for path in (state_json_path(deployment_name), state_legacy_path(deployment_name)):
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
        warn(str(exc) or "Операция отменена пользователем.")
    except KeyboardInterrupt:
        warn("Остановлено пользователем.")
    except EOFError:
        warn(f"Ввод прерван. Возврат в {return_to}.")
    except AppError as exc:
        log_path = log_exception("menu.app_error", exc, extra={"return_to": return_to})
        warn(f"Ошибка: {exc}")
        if log_path:
            print(f"Лог ошибки: {log_path}")
        print(f"Возврат в {return_to}.")
    except Exception as exc:  # noqa: BLE001
        if is_audit_failure(exc):
            warn(f"Самопроверка завершилась с ошибкой: {exc}")
            print("Смотри summary и логи в out/audit/<run_id>/.")
            print(f"Возврат в {return_to}.")
            return
        log_path = log_exception("menu.unhandled", exc, extra={"return_to": return_to})
        if os.environ.get("VPN_DEBUG"):
            traceback.print_exc()
        warn(f"Непредвиденная ошибка: {exc}")
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
                ("quick", "Быстрая локальная проверка"),
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
        print_header("VPN Installer")
        choice = prompt_choice(
            "Выбери действие",
            [
                ("install", "Установить или обновить VPN"),
                ("status", "Проверить текущее состояние"),
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
        if choice == "cleanup-local":
            run_menu_action(lambda: cleanup_local_workflow(None, drop_env=False, drop_runtime=False), return_to="главное меню")
            continue
        role = select_role_for_menu(choice)
        if choice == "install":
            run_menu_action(lambda: install_workflow(None), return_to="главное меню")
            continue
        if choice == "status":
            run_menu_action(lambda selected_role=role: status_workflow(None, selected_role), return_to="главное меню")
            continue
        run_menu_action(lambda selected_role=role, action_name=choice: remote_action_workflow(None, selected_role, action_name), return_to="главное меню")
