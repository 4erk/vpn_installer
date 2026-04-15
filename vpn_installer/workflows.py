from __future__ import annotations

import argparse
import os
import shlex
import shutil
import textwrap
import traceback
from pathlib import Path
from typing import Any

from .clipboard import copy_to_clipboard
from .common import DEPLOYMENTS_DIR, OUT_DIR, RUNTIME_DIR, INSTALL_SCRIPT_PATH, ensure_directories, fail, print_header, sanitize_name, warn, write_text
from .config import (
    load_existing_deployment_env,
    load_env_file,
    merge_env_with_defaults,
    render_env_text,
    require_env,
    ensure_deployment_env,
)
from .error_logging import log_exception
from .models import AppError, ROLE_FOREIGN, ROLE_META, ROLE_RU, RemoteTarget, UserCancelled
from .prompts import (
    ask_install_action,
    auth_mode_label,
    has_saved_connection,
    prompt_choice,
    prompt_secret,
    prompt_server_connection,
    prompt_yes_no,
    select_deployment,
    select_existing_deployment,
    select_role_for_menu,
)
from .remote import ensure_remote_privilege, print_preflight, remote_preflight, scp_upload, ssh_stream
from .render import client_artifact_paths, deployment_out_dir, render_all_artifacts, render_client_profiles, render_config_artifacts, render_next_steps, render_vless_uri
from .state import load_state, state_json_path, state_legacy_path, write_state


def is_audit_failure(exc: BaseException) -> bool:
    return exc.__class__.__name__ == "AuditFailure" and exc.__class__.__module__.startswith("vpn_installer.audit")


def build_target(role: str, env: dict[str, str], state: dict[str, Any]) -> RemoteTarget:
    role_state = state.get(role, {})
    saved_connection = has_saved_connection(role_state)
    public_ip_key = ROLE_META[role]["public_ip_key"]
    ssh_port_raw = str((role_state.get("ssh_port") if saved_connection else None) or env.get("SSH_PORT", "22") or "22")
    ssh_port = int(ssh_port_raw)
    public_ip = str((role_state.get("public_ip") if saved_connection else None) or env.get(public_ip_key, ""))
    return RemoteTarget(
        role=role,
        public_ip=public_ip,
        ssh_host=str((role_state.get("ssh_host") if saved_connection else None) or public_ip),
        ssh_port=ssh_port,
        ssh_user=str((role_state.get("ssh_user") if saved_connection else None) or "root"),
        auth_mode=str((role_state.get("auth_mode") if saved_connection else None) or "key"),
        identity_path=str((role_state.get("identity_path") if saved_connection else None) or ""),
        saved_connection=saved_connection,
    )


def current_wg_interface(env: dict[str, str]) -> str:
    return env.get("WG_INTERFACE", "").strip() or "wg0"


def requested_roles(role_arg: str) -> list[str]:
    return [ROLE_RU, ROLE_FOREIGN] if role_arg == "all" else [role_arg]


def execution_roles(action: str, roles: list[str]) -> list[str]:
    if action in {"install", "reinstall"}:
        preferred = [ROLE_FOREIGN, ROLE_RU]
    elif action in {"remove", "purge"}:
        preferred = [ROLE_RU, ROLE_FOREIGN]
    else:
        preferred = [ROLE_RU, ROLE_FOREIGN]
    return [role for role in preferred if role in roles]


def update_env_with_targets(env: dict[str, str], targets: list[RemoteTarget]) -> None:
    for target in targets:
        env[ROLE_META[target.role]["public_ip_key"]] = target.public_ip


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
    wg_interface: str,
    require_privilege: bool,
    validate_os: bool,
    confirm_existing_connection: bool,
) -> tuple[RemoteTarget, dict[str, str]]:
    force_prompt = not target.saved_connection
    while True:
        target = prompt_server_connection(target, force_prompt=force_prompt, confirm_existing=confirm_existing_connection)
        print(f"Проверяю подключение к {target.label}: {target.ssh_user}@{target.ssh_host}:{target.ssh_port}")
        try:
            preflight = remote_preflight(target, wg_interface)
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


def prepare_remote_session(
    deployment_arg: str | None,
    *,
    roles: list[str],
    require_privilege: bool,
    validate_os: bool = True,
    allow_create: bool = False,
    persist_local: bool = True,
    confirm_existing_connections: bool = True,
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
    wg_interface = current_wg_interface(env)
    for role in roles:
        target = build_target(role, env, state)
        target, preflight = verify_target_interactively(
            target,
            wg_interface=wg_interface,
            require_privilege=require_privilege,
            validate_os=validate_os,
            confirm_existing_connection=confirm_existing_connections,
        )
        targets.append(target)
        preflights[role] = preflight
    update_env_with_targets(env, targets)
    if persist_local:
        write_text(env_path, render_env_text(env))
        write_state(deployment_name, targets, existing_state=state)
    return deployment_name, env_path, env, state, targets, preflights


def postcheck_command(role: str, wg_interface: str) -> str:
    sing_box_check = (
        'check_service_active sing-box sing-box'
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
          if systemctl is-active --quiet "$service"; then
            return 0
          fi
          printf 'postcheck_failed_service=%s\\n' "${{label}}"
          printf 'postcheck_service_state=%s\\n' "$(systemctl is-active "$service" 2>/dev/null || true)"
          printf 'postcheck_service_enabled=%s\\n' "$(systemctl is-enabled "$service" 2>/dev/null || true)"
          systemctl status "$service" --no-pager --full || true
          journalctl -u "$service" -n 20 --no-pager || true
          exit 1
        }}
        check_service_active nftables nftables
        check_service_active vpn-stack-sync.timer vpn-stack-sync.timer
        check_service_active wg-quick@{wg_interface} wg-quick@{wg_interface}
        {sing_box_check}
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
    uri_payload = render_vless_uri(env)
    clipboard_ok, clipboard_message = copy_to_clipboard(uri_payload)
    print_header("Готово")
    print(f"Deployment: {deployment_name}")
    print(f"Hiddify URI: {paths['uri']}")
    print(f"JSON backup для Hiddify: {paths['hiddify_json']}")
    print(f"JSON backup для Linux: {paths['linux_json']}")
    print(f"Следующие шаги: {paths['next_steps']}")
    print(clipboard_message)
    print("Что делать дальше:")
    print("1. Открой Hiddify.")
    print("2. Выбери импорт из буфера обмена.")
    print(f"3. Если буфер обмена не сработал, открой {paths['uri'].name} и вставь URI вручную.")
    print(f"4. Для проверки серверов потом запусти: vpn status --deployment {deployment_name}")


def load_env_for_render(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        fail(f"Не найден deployment env: {env_path}")
    env = merge_env_with_defaults(load_env_file(env_path), sanitize_name(env_path.stem))
    write_text(env_path, render_env_text(env))
    return env


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
    roles = requested_roles(role_arg)
    wg_interface = current_wg_interface(env)
    if action in {"install", "reinstall"}:
        print_header("Локальная сборка артефактов")
        render_all_artifacts(env_path, env)
    for role in execution_roles(action, roles):
        target = target_map[role]
        install_remote_role(target, deployment_name, env, action)
        if action in {"install", "reinstall"}:
            postcheck_remote_role(target, wg_interface)
        else:
            print_preflight(target, remote_preflight(target, wg_interface))


def install_workflow(deployment: str | None) -> int:
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
        confirm_existing_connections=True,
    )
    ensure_foreign_wan_interface(env, preflights[ROLE_FOREIGN])
    write_text(env_path, render_env_text(env))
    write_state(deployment_name, targets, existing_state=state)
    print_summary(deployment_name, env, targets)
    actions = {
        ROLE_RU: ask_install_action(ROLE_RU, deployment_name, preflights[ROLE_RU]),
        ROLE_FOREIGN: ask_install_action(ROLE_FOREIGN, deployment_name, preflights[ROLE_FOREIGN]),
    }
    if all(action == "skip" for action in actions.values()):
        print("Обе роли пропущены.")
        return 0
    if not prompt_yes_no("Продолжить установку / обновление?", default=True):
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
        postcheck_remote_role(target_map[role], current_wg_interface(env))
        step += 1
    finalize_install_output(env, deployment_name)
    print(f"Deployment env: {env_path}")
    print(f"Локальное состояние: {state_json_path(deployment_name)}")
    return 0


def status_workflow(deployment: str | None, role: str) -> int:
    roles = requested_roles(role)
    deployment_name, env_path, env, _state, targets, _preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=False,
        validate_os=False,
        allow_create=False,
        persist_local=False,
        confirm_existing_connections=False,
    )
    print_summary(deployment_name, env, targets)
    print(f"Deployment env: {env_path}")
    return 0


def remote_action_workflow(deployment: str | None, role: str, action: str) -> int:
    roles = requested_roles(role)
    deployment_name, env_path, env, state, targets, preflights = prepare_remote_session(
        deployment,
        roles=roles,
        require_privilege=True,
        allow_create=False,
        persist_local=True,
        confirm_existing_connections=True,
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
    if not prompt_yes_no(f"Продолжить действие {action}?", default=False):
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
