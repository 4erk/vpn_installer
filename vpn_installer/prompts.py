from __future__ import annotations

import getpass
import os
from typing import Any

from .common import error_summary, fail, print_header, sanitize_name, warn
from .config import (
    find_existing_deployments,
    normalize_identity_path,
    validate_auth_mode,
    validate_deployment_name,
    validate_identity_path,
    validate_ip_literal,
    validate_ssh_host,
    validate_ssh_port,
    validate_ssh_user,
)
from .credential_store import SSHCredentialRef, CredentialStoreError, system_credential_store
from .models import NODE_META, RemoteTarget
from .topology import (
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
)

DEFAULT_FIRST_DEPLOYMENT_NAME = "home-vpn"


def prompt_value(label: str, default: str | None = None, allow_empty: bool = False) -> str:
    while True:
        suffix = f" (Enter = {default})" if default not in (None, "") else ""
        value = input(f"{label}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        if allow_empty:
            return ""


def prompt_validated_value(
    label: str,
    *,
    default: str | None = None,
    allow_empty: bool = False,
    validator: Any | None = None,
) -> str:
    while True:
        value = prompt_value(label, default=default, allow_empty=allow_empty)
        if not value and allow_empty:
            return value
        if validator is None:
            return value
        try:
            return validator(value)
        except Exception as exc:  # noqa: BLE001
            warn(error_summary(exc))


def prompt_secret(label: str) -> str:
    return getpass.getpass(f"{label}: ")


def prompt_yes_no(label: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{label} [{suffix}]: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes", "д", "да"}:
            return True
        if answer in {"n", "no", "н", "нет"}:
            return False


def prompt_choice(label: str, options: list[tuple[str, str]], default: str) -> str:
    if default not in {value for value, _ in options}:
        fail(f"Некорректный default для prompt_choice: {default}")
    print(label)
    default_index = 1
    option_map: dict[str, str] = {}
    for index, (value, description) in enumerate(options, start=1):
        if value == default:
            default_index = index
        option_map[str(index)] = value
        print(f"{index}. {description} [{value}]")
    while True:
        raw = input(f"Выберите вариант [{default_index}]: ").strip().lower()
        if not raw:
            return default
        if raw in option_map:
            return option_map[raw]
        for value, _ in options:
            if raw == value:
                return value


def prompt_topology(*, current_mode: str = TOPOLOGY_DUAL, current_location: str = LOCATION_RU) -> tuple[str, str]:
    mode = prompt_choice(
        "Схема установки",
        [
            (TOPOLOGY_DUAL, "Два сервера: gateway в России и зарубежный exit"),
            (TOPOLOGY_SINGLE, "Один gateway без межсерверного туннеля"),
        ],
        default=current_mode,
    )
    if mode == TOPOLOGY_DUAL:
        return mode, LOCATION_RU
    location = prompt_choice(
        "Где расположен единственный gateway?",
        [(LOCATION_RU, "Россия"), (LOCATION_FOREIGN, "За рубежом")],
        default=current_location,
    )
    return mode, location


def has_saved_connection(role_state: dict[str, Any]) -> bool:
    auth_mode = str(role_state.get("auth_mode", "")).strip().lower()
    return bool(
        str(role_state.get("public_ip", "")).strip()
        and str(role_state.get("ssh_host", "")).strip()
        and str(role_state.get("ssh_user", "")).strip()
        and str(role_state.get("ssh_port", "")).strip()
        and auth_mode in {"key", "password"}
    )


def validate_target_settings(target: RemoteTarget) -> None:
    target.public_ip = validate_ip_literal(target.public_ip)
    target.ssh_host = validate_ssh_host(target.ssh_host)
    target.ssh_port = int(validate_ssh_port(str(target.ssh_port)))
    target.ssh_user = validate_ssh_user(target.ssh_user)
    target.auth_mode = validate_auth_mode(target.auth_mode)
    if target.auth_mode == "key":
        target.identity_path = validate_identity_path(target.identity_path)
    else:
        target.identity_path = ""


def auth_mode_label(auth_mode: str) -> str:
    return "SSH key" if auth_mode == "key" else "SSH password"


def human_target_label(target: RemoteTarget) -> str:
    return target.label[:1].lower() + target.label[1:]


def display_target_connection(target: RemoteTarget) -> None:
    print(f"Public IP: {target.public_ip}")
    print(f"SSH: {target.ssh_user}@{target.ssh_host}:{target.ssh_port}")
    print(f"Вход: {auth_mode_label(target.auth_mode)}")
    if target.auth_mode == "key":
        print(f"SSH key: {target.identity_path or 'ssh-agent / стандартный ключ'}; password fallback отключён")
    elif target.saved_connection:
        print("SSH password: будет взят из системного хранилища или запрошен без вывода на экран")


def credential_ref(target: RemoteTarget) -> SSHCredentialRef:
    return SSHCredentialRef(target.ssh_host, target.ssh_port, target.ssh_user)


def hydrate_runtime_auth(
    target: RemoteTarget,
    *,
    interactive: bool = True,
    use_saved_password: bool = True,
    offer_save: bool = False,
) -> RemoteTarget:
    if target.auth_mode == "password":
        if target.ssh_password:
            return target
        env_names = (
            ["VPN_GATEWAY_SSH_PASSWORD", "VPN_RU_SSH_PASSWORD", "VPN_SSH_PASSWORD"]
            if target.node_id == NODE_GATEWAY
            else ["VPN_EXIT_SSH_PASSWORD", "VPN_FOREIGN_SSH_PASSWORD", "VPN_SSH_PASSWORD"]
        )
        for env_name in env_names:
            password = os.environ.get(env_name, "")
            if password:
                target.ssh_password = password
                return target
        store = system_credential_store()
        if use_saved_password and store is not None:
            try:
                password = store.load(credential_ref(target))
            except CredentialStoreError as exc:
                warn(str(exc))
            else:
                if password:
                    target.ssh_password = password
                    print(f"{target.label}: использую SSH-пароль из {store.label}.")
                    return target
        if not interactive:
            return target
        while True:
            password = prompt_secret(f"{target.label}: SSH пароль")
            if password:
                target.ssh_password = password
                if offer_save:
                    if store is None:
                        warn("Безопасное системное хранилище недоступно; пароль останется только в памяти процесса.")
                    elif prompt_yes_no(
                        f"{target.label}: сохранить пароль в {store.label}? В файлы проекта он не попадёт",
                        default=False,
                    ):
                        target.save_ssh_password = True
                return target
            warn("SSH пароль не может быть пустым.")
    return target


def persist_runtime_auth(target: RemoteTarget) -> None:
    if target.auth_mode != "password" or not target.save_ssh_password or not target.ssh_password:
        return
    store = system_credential_store()
    if store is None:
        warn("Безопасное системное хранилище недоступно; SSH-пароль не сохранён.")
        target.save_ssh_password = False
        return
    try:
        store.save(credential_ref(target), target.ssh_password)
    except CredentialStoreError as exc:
        warn(str(exc))
    else:
        print(f"{target.label}: проверенный SSH-пароль сохранён в {store.label}.")
    finally:
        target.save_ssh_password = False


def prompt_server_connection(target: RemoteTarget, *, force_prompt: bool = False, confirm_existing: bool = True) -> RemoteTarget:
    print_header(f"Подключение: {human_target_label(target)}")
    use_saved_password = not force_prompt
    if target.saved_connection:
        try:
            validate_target_settings(target)
        except Exception as exc:  # noqa: BLE001
            warn(f"{target.label}: сохранённые SSH-данные повреждены или неполны, нужно ввести заново ({error_summary(exc)})")
            force_prompt = True
            use_saved_password = False
        else:
            print("Найдены сохранённые SSH-данные:")
            display_target_connection(target)
            if not force_prompt and not confirm_existing:
                print("Использую сохранённое подключение.")
                return hydrate_runtime_auth(target)
            if not force_prompt:
                action = prompt_choice(
                    "Что делать с этим подключением?",
                    [("reuse", "Использовать сохранённые SSH-данные"), ("edit", "Изменить SSH-данные")],
                    default="reuse",
                )
                if action == "reuse":
                    print(f"{target.label}: использую сохранённое подключение, дальше будет реальная SSH-проверка.")
                    return hydrate_runtime_auth(target, offer_save=True)
                use_saved_password = False
    elif target.public_ip:
        print(f"Подставлен public IP из deployment env: {target.public_ip}")

    target.public_ip = prompt_validated_value(
        f"{target.label}: Public IP (пример 203.0.113.10)",
        default=target.public_ip or None,
        validator=validate_ip_literal,
    )
    ssh_port_raw = prompt_validated_value(
        f"{target.label}: SSH port (пример 22)",
        default=str(target.ssh_port or 22),
        validator=validate_ssh_port,
    )
    target.ssh_port = int(ssh_port_raw)
    target.ssh_user = prompt_validated_value(
        f"{target.label}: SSH user (пример root или ubuntu)",
        default=target.ssh_user or "root",
        validator=validate_ssh_user,
    )
    target.auth_mode = prompt_choice(
        f"{target.label}: способ входа",
        [("password", "SSH password"), ("key", "SSH key")],
        default=(target.auth_mode if target.saved_connection else "password"),
    )
    use_custom_host_default = bool(target.ssh_host and target.ssh_host != target.public_ip)
    if prompt_yes_no(f"{target.label}: SSH адрес отличается от Public IP?", default=use_custom_host_default):
        target.ssh_host = prompt_validated_value(
            f"{target.label}: SSH host/IP (пример ssh.example.com)",
            default=(target.ssh_host if use_custom_host_default else None),
            validator=validate_ssh_host,
        )
    else:
        target.ssh_host = target.public_ip
    if target.auth_mode == "key":
        target.identity_path = prompt_validated_value(
            f"{target.label}: SSH key (пусто = авто; имя = ~/.ssh/<имя>; либо полный путь)",
            default=target.identity_path or None,
            allow_empty=True,
            validator=validate_identity_path,
        )
        target.ssh_password = ""
    else:
        target.identity_path = ""
        target.ssh_password = ""
        target = hydrate_runtime_auth(
            target,
            use_saved_password=use_saved_password,
            offer_save=True,
        )
    target.saved_connection = False
    validate_target_settings(target)
    print("Будет использовано подключение:")
    display_target_connection(target)
    return target


def select_deployment(cli_name: str | None) -> str:
    if cli_name:
        return validate_deployment_name(cli_name)
    existing = find_existing_deployments()
    if not existing:
        return validate_deployment_name(prompt_value("Имя новой установки", default=DEFAULT_FIRST_DEPLOYMENT_NAME))
    print_header("Выбор deployment")
    for index, name in enumerate(existing, start=1):
        print(f"{index}. {name}")
    create_index = len(existing) + 1
    print(f"{create_index}. Создать новый deployment")
    while True:
        selection_raw = input(f"Выберите deployment [{create_index}]: ").strip() or str(create_index)
        if not selection_raw.isdigit():
            continue
        selection = int(selection_raw)
        if 1 <= selection <= len(existing):
            print(f"Выбран существующий deployment: {existing[selection - 1]}")
            return existing[selection - 1]
        if selection == create_index:
            return validate_deployment_name(prompt_value("Имя нового deployment"))


def select_existing_deployment(cli_name: str | None) -> str:
    if cli_name:
        return validate_deployment_name(cli_name)
    existing = find_existing_deployments()
    if not existing:
        fail("Не найдено ни одного deployment env.")
    print_header("Выбор deployment")
    for index, name in enumerate(existing, start=1):
        print(f"{index}. {name}")
    while True:
        selection_raw = input("Выберите deployment [1]: ").strip() or "1"
        if not selection_raw.isdigit():
            continue
        selection = int(selection_raw)
        if 1 <= selection <= len(existing):
            return existing[selection - 1]


def ask_install_action(node_id: str, deployment_name: str, preflight: dict[str, str], *, label: str | None = None) -> str:
    target_label = label or NODE_META[node_id]["label"]
    if preflight.get("installed") != "1":
        print(f"На {target_label} стек не найден.")
        return prompt_choice(
            f"Что делать с {target_label}?",
            [("install", "Установить узел"), ("skip", "Пока ничего не делать")],
            default="install",
        )
    existing_node = preflight.get("node", "")
    existing_deployment = preflight.get("deployment_name", "")
    if existing_node and existing_node != node_id:
        print(f"На {target_label} уже установлен узел {existing_node} (deployment: {existing_deployment or '-'})")
        return prompt_choice(
            f"Что делать с {target_label}?",
            [("reinstall", "Переустановить и обновить узел"), ("skip", "Пока ничего не делать")],
            default="skip",
        )
    if existing_deployment and existing_deployment != deployment_name:
        print(f"На сервере уже найден другой deployment: {existing_deployment}")
    return prompt_choice(
        f"Что делать с {target_label}?",
        [("reinstall", "Обновить / переустановить узел"), ("skip", "Пока ничего не делать")],
        default="reinstall",
    )


def select_node_for_menu(command_name: str) -> str:
    if command_name not in {"status", "reinstall", "remove", "purge"}:
        return "all"
    return prompt_choice(
        "Какой сервер нужно затронуть?",
        [
            ("all", "Все настроенные серверы"),
            (NODE_GATEWAY, "VPN gateway"),
            (NODE_EXIT, "Exit (только для схемы из двух серверов)"),
        ],
        default="all",
    )
