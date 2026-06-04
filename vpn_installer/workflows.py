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
from .localnet import assert_server_route_not_self_tunneled, local_route_to_server, route_uses_self_tunnel
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
from .remote import ensure_remote_privilege, fetch_remote_deployment_env, print_preflight, remote_preflight, scp_upload, ssh_stream
from .render import client_artifact_paths, deployment_out_dir, render_all_artifacts, render_client_profiles, render_config_artifacts, render_next_steps
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


def sync_targets_from_env(env: dict[str, str], targets: list[RemoteTarget]) -> None:
    for target in targets:
        public_ip = env.get(ROLE_META[target.role]["public_ip_key"], "").strip()
        if public_ip:
            target.public_ip = public_ip


def remote_env_matches_target(target: RemoteTarget, deployment_name: str, preflight: dict[str, str]) -> bool:
    return (
        preflight.get("installed") == "1"
        and preflight.get("deployment_name", "").strip() == deployment_name
        and preflight.get("role", "").strip() == target.role
    )


def can_fetch_remote_env(target: RemoteTarget) -> bool:
    return target.ssh_user == "root" or target.sudo_mode in {"root", "nopasswd", "password"}


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
    render_client_profiles(source_env)
    sync_targets_from_env(source_env, targets)
    print("Локальный deployment env синхронизирован из установленного сервера.")
    return source_env, True


def handshake_age_seconds(preflight: dict[str, str]) -> int:
    raw_value = preflight.get("wg_latest_handshake_age_s", "").strip()
    try:
        return int(raw_value)
    except ValueError:
        return -1


def handshake_grace_seconds(env: dict[str, str]) -> int:
    try:
        keepalive = int(env.get("WG_KEEPALIVE", "25"))
    except ValueError:
        keepalive = 25
    return max(120, keepalive * 4)


def env_int(env: dict[str, str], key: str, default: int) -> int:
    try:
        return int(env.get(key, str(default)).strip())
    except ValueError:
        return default


def preflight_int(preflight: dict[str, str], key: str, default: int = -1) -> int:
    try:
        return int(preflight.get(key, str(default)).strip())
    except ValueError:
        return default


def preflight_int_any(preflight: dict[str, str], keys: list[str], default: int = -1) -> int:
    for key in keys:
        value = preflight.get(key, "").strip()
        if not value:
            continue
        try:
            return int(value)
        except ValueError:
            continue
    return default


def deployment_health_snapshot(env: dict[str, str], preflights: dict[str, dict[str, str]]) -> dict[str, str]:
    foreign = preflights.get(ROLE_FOREIGN, {})
    ru = preflights.get(ROLE_RU, {})
    foreign_ip = foreign.get("observed_ipv4", "").strip()
    ru_wg_ip = ru.get("wg_observed_ipv4", "").strip()
    ru_handshake_age = handshake_age_seconds(ru)
    foreign_handshake_age = handshake_age_seconds(foreign)
    max_age = handshake_grace_seconds(env)
    foreign_download_bps = preflight_int_any(foreign, ["deep_foreign_direct_download_min_bps", "direct_download_bps"])
    ru_wg_download_bps = preflight_int_any(ru, ["deep_ru_wg_download_min_bps", "wg_download_bps"])
    foreign_upload_bps = preflight_int_any(foreign, ["deep_foreign_direct_upload_bps"])
    ru_wg_upload_bps = preflight_int_any(ru, ["deep_ru_wg_upload_bps"])
    foreign_gateway_ping_loss_pct = preflight_int_any(foreign, ["deep_foreign_gateway_ping_loss_pct"])
    foreign_ru_ping_loss_pct = preflight_int_any(foreign, ["deep_foreign_ru_ping_loss_pct"])
    foreign_internet_ping_loss_pct = preflight_int_any(foreign, ["deep_foreign_internet_ping_loss_pct"])
    min_foreign_download_bps = env_int(env, "HEALTH_MIN_FOREIGN_DIRECT_DOWNLOAD_BPS", 500000)
    min_ru_wg_download_bps = env_int(env, "HEALTH_MIN_RU_WG_DOWNLOAD_BPS", 500000)
    min_foreign_upload_bps = env_int(env, "HEALTH_MIN_FOREIGN_DIRECT_UPLOAD_BPS", 1000000)
    min_ru_wg_upload_bps = env_int(env, "HEALTH_MIN_RU_WG_UPLOAD_BPS", 1000000)
    max_foreign_ru_ping_loss_pct = env_int(env, "HEALTH_MAX_FOREIGN_RU_PING_LOSS_PCT", 5)
    max_foreign_internet_ping_loss_pct = env_int(env, "HEALTH_MAX_FOREIGN_INTERNET_PING_LOSS_PCT", 5)
    verdict = "ok"
    if not foreign_ip:
        verdict = "foreign_direct_egress_failed"
    elif not ru_wg_ip:
        verdict = "ru_wg_egress_failed"
    elif ru_wg_ip != foreign_ip:
        verdict = "foreign_ru_ip_mismatch"
    elif (ru_handshake_age < 0 or foreign_handshake_age < 0 or ru_handshake_age > max_age or foreign_handshake_age > max_age) and not (foreign_ip and ru_wg_ip == foreign_ip):
        verdict = "wg_handshake_stale"
    elif foreign_gateway_ping_loss_pct >= 0 and foreign_gateway_ping_loss_pct > max_foreign_internet_ping_loss_pct:
        verdict = "foreign_gateway_ping_loss_degraded"
    elif foreign_ru_ping_loss_pct >= 0 and foreign_ru_ping_loss_pct > max_foreign_ru_ping_loss_pct:
        verdict = "foreign_ru_ping_loss_degraded"
    elif foreign_internet_ping_loss_pct >= 0 and foreign_internet_ping_loss_pct > max_foreign_internet_ping_loss_pct:
        verdict = "foreign_internet_ping_loss_degraded"
    elif foreign_download_bps >= 0 and foreign_download_bps < min_foreign_download_bps:
        verdict = "foreign_direct_download_degraded"
    elif ru_wg_download_bps >= 0 and ru_wg_download_bps < min_ru_wg_download_bps:
        verdict = "ru_wg_download_degraded"
    elif foreign_upload_bps >= 0 and foreign_upload_bps < min_foreign_upload_bps:
        verdict = "foreign_direct_upload_degraded"
    elif ru_wg_upload_bps >= 0 and ru_wg_upload_bps < min_ru_wg_upload_bps:
        verdict = "ru_wg_upload_degraded"
    return {
        "health_verdict": verdict,
        "foreign_direct_observed_ipv4": foreign_ip or "-",
        "ru_wg_observed_ipv4": ru_wg_ip or "-",
        "ru_handshake_age_s": str(ru_handshake_age),
        "foreign_handshake_age_s": str(foreign_handshake_age),
        "handshake_grace_s": str(max_age),
        "foreign_direct_download_bps": str(foreign_download_bps),
        "ru_wg_download_bps": str(ru_wg_download_bps),
        "min_foreign_direct_download_bps": str(min_foreign_download_bps),
        "min_ru_wg_download_bps": str(min_ru_wg_download_bps),
        "foreign_direct_upload_bps": str(foreign_upload_bps),
        "ru_wg_upload_bps": str(ru_wg_upload_bps),
        "min_foreign_direct_upload_bps": str(min_foreign_upload_bps),
        "min_ru_wg_upload_bps": str(min_ru_wg_upload_bps),
        "foreign_gateway_ping_loss_pct": str(foreign_gateway_ping_loss_pct),
        "foreign_ru_ping_loss_pct": str(foreign_ru_ping_loss_pct),
        "foreign_internet_ping_loss_pct": str(foreign_internet_ping_loss_pct),
        "max_foreign_ru_ping_loss_pct": str(max_foreign_ru_ping_loss_pct),
        "max_foreign_internet_ping_loss_pct": str(max_foreign_internet_ping_loss_pct),
    }


def print_deployment_health(health: dict[str, str]) -> None:
    print_header("Dataplane health")
    print(f"foreign direct IPv4: {health['foreign_direct_observed_ipv4']}")
    print(f"RU over wg IPv4: {health['ru_wg_observed_ipv4']}")
    print(f"RU handshake age (s): {health['ru_handshake_age_s']}")
    print(f"foreign handshake age (s): {health['foreign_handshake_age_s']}")
    print(f"handshake grace (s): {health['handshake_grace_s']}")
    print(
        "foreign direct download B/s: "
        f"{health.get('foreign_direct_download_bps', '-')} "
        f"(min {health.get('min_foreign_direct_download_bps', '-')})"
    )
    print(
        "RU over wg download B/s: "
        f"{health.get('ru_wg_download_bps', '-')} "
        f"(min {health.get('min_ru_wg_download_bps', '-')})"
    )
    print(
        "foreign direct upload B/s: "
        f"{health.get('foreign_direct_upload_bps', '-')} "
        f"(min {health.get('min_foreign_direct_upload_bps', '-')})"
    )
    print(
        "RU over wg upload B/s: "
        f"{health.get('ru_wg_upload_bps', '-')} "
        f"(min {health.get('min_ru_wg_upload_bps', '-')})"
    )
    print(
        "foreign ping loss to gateway / RU / internet (%): "
        f"{health.get('foreign_gateway_ping_loss_pct', '-')}/"
        f"{health.get('foreign_ru_ping_loss_pct', '-')}/"
        f"{health.get('foreign_internet_ping_loss_pct', '-')} "
        f"(max {health.get('max_foreign_internet_ping_loss_pct', '-')}/"
        f"{health.get('max_foreign_ru_ping_loss_pct', '-')}/"
        f"{health.get('max_foreign_internet_ping_loss_pct', '-')})"
    )
    print(f"health verdict: {health['health_verdict']}")


def deployment_is_healthy(env: dict[str, str], preflights: dict[str, dict[str, str]]) -> tuple[bool, dict[str, str]]:
    health = deployment_health_snapshot(env, preflights)
    return health["health_verdict"] == "ok", health


def is_soft_health_verdict(verdict: str) -> bool:
    return verdict in {
        "foreign_gateway_ping_loss_degraded",
        "foreign_ru_ping_loss_degraded",
        "foreign_internet_ping_loss_degraded",
        "foreign_direct_download_degraded",
        "ru_wg_download_degraded",
        "foreign_direct_upload_degraded",
        "ru_wg_upload_degraded",
    }


def is_hard_health_verdict(verdict: str) -> bool:
    if verdict == "ok":
        return False
    if is_soft_health_verdict(verdict):
        return False
    return True


def collect_role_preflights(targets: list[RemoteTarget], wg_interface: str) -> dict[str, dict[str, str]]:
    return {target.role: remote_preflight(target, wg_interface) for target in targets}


def health_failure_message(health: dict[str, str]) -> str:
    return (
        f"{health['health_verdict']}: "
        f"foreign_direct_observed_ipv4={health['foreign_direct_observed_ipv4']}, "
        f"ru_wg_observed_ipv4={health['ru_wg_observed_ipv4']}, "
        f"ru_handshake_age_s={health['ru_handshake_age_s']}, "
        f"foreign_handshake_age_s={health['foreign_handshake_age_s']}, "
        f"handshake_grace_s={health['handshake_grace_s']}, "
        f"foreign_direct_download_bps={health.get('foreign_direct_download_bps', '-')}, "
        f"ru_wg_download_bps={health.get('ru_wg_download_bps', '-')}, "
        f"min_foreign_direct_download_bps={health.get('min_foreign_direct_download_bps', '-')}, "
        f"min_ru_wg_download_bps={health.get('min_ru_wg_download_bps', '-')}, "
        f"foreign_direct_upload_bps={health.get('foreign_direct_upload_bps', '-')}, "
        f"ru_wg_upload_bps={health.get('ru_wg_upload_bps', '-')}, "
        f"min_foreign_direct_upload_bps={health.get('min_foreign_direct_upload_bps', '-')}, "
        f"min_ru_wg_upload_bps={health.get('min_ru_wg_upload_bps', '-')}, "
        f"foreign_gateway_ping_loss_pct={health.get('foreign_gateway_ping_loss_pct', '-')}, "
        f"foreign_ru_ping_loss_pct={health.get('foreign_ru_ping_loss_pct', '-')}, "
        f"foreign_internet_ping_loss_pct={health.get('foreign_internet_ping_loss_pct', '-')}, "
        f"max_foreign_ru_ping_loss_pct={health.get('max_foreign_ru_ping_loss_pct', '-')}, "
        f"max_foreign_internet_ping_loss_pct={health.get('max_foreign_internet_ping_loss_pct', '-')}"
    )


def nonblocking_systemd_restart_command(*units: str) -> str:
    quoted_units = " ".join(shlex.quote(unit) for unit in units)
    return (
        f"systemctl reset-failed {quoted_units} >/dev/null 2>&1 || true; "
        f"systemctl restart --no-block {quoted_units}"
    )


def run_dataplane_repair_cycle(target_map: dict[str, RemoteTarget], wg_interface: str) -> None:
    print_header("Dataplane repair")
    print(f"{target_map[ROLE_FOREIGN].label}: запускаю repair units без блокировки")
    ssh_stream(
        target_map[ROLE_FOREIGN],
        nonblocking_systemd_restart_command(f"wg-quick@{wg_interface}", "nftables", "vpn-stack-sync.service"),
        as_root=True,
    )
    print(f"{target_map[ROLE_RU].label}: запускаю repair units без блокировки")
    ssh_stream(
        target_map[ROLE_RU],
        nonblocking_systemd_restart_command(f"wg-quick@{wg_interface}", "sing-box"),
        as_root=True,
    )
    print("Repair-команды отправлены, жду восстановления dataplane.")


def prime_runtime_health(targets: list[RemoteTarget]) -> None:
    print_header("Runtime health")
    for target in targets:
        if not target.ssh_host:
            continue
        try:
            ssh_stream(target, "/usr/local/lib/vpn-stack/health-check.sh", as_root=True)
        except Exception as exc:  # noqa: BLE001
            warn(f"{target.label}: runtime health reported a problem, продолжаю deployment-level проверку: {exc}")


def wait_for_dataplane_health(
    env: dict[str, str],
    targets: list[RemoteTarget],
    *,
    timeout_sec: int = 45,
    interval_sec: int = 5,
    allow_soft_degraded: bool = False,
) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    deadline = time.time() + timeout_sec
    wg_interface = current_wg_interface(env)
    latest_preflights: dict[str, dict[str, str]] = {}
    latest_health = deployment_health_snapshot(env, latest_preflights)
    while time.time() < deadline:
        latest_preflights = collect_role_preflights(targets, wg_interface)
        healthy, latest_health = deployment_is_healthy(env, latest_preflights)
        if healthy or (allow_soft_degraded and not is_hard_health_verdict(latest_health["health_verdict"])):
            return latest_preflights, latest_health
        time.sleep(interval_sec)
    return latest_preflights, latest_health


def ensure_deployment_health(
    env: dict[str, str],
    targets: list[RemoteTarget],
    *,
    auto_repair: bool,
) -> dict[str, dict[str, str]]:
    if {target.role for target in targets} != {ROLE_RU, ROLE_FOREIGN}:
        return {}
    if auto_repair:
        prime_runtime_health(targets)
    preflights, health = wait_for_dataplane_health(env, targets, timeout_sec=20, interval_sec=5, allow_soft_degraded=True)
    print_deployment_health(health)
    if health["health_verdict"] == "ok":
        return preflights
    if is_soft_health_verdict(health["health_verdict"]):
        warn(f"Dataplane degraded but operational: {health_failure_message(health)}")
        return preflights
    if not auto_repair:
        return preflights
    target_map = {target.role: target for target in targets}
    run_dataplane_repair_cycle(target_map, current_wg_interface(env))
    repaired_preflights, repaired_health = wait_for_dataplane_health(env, targets, allow_soft_degraded=True)
    print_deployment_health(repaired_health)
    if repaired_health["health_verdict"] == "ok":
        return repaired_preflights
    if is_soft_health_verdict(repaired_health["health_verdict"]):
        warn(f"Dataplane degraded but operational after repair: {health_failure_message(repaired_health)}")
        return repaired_preflights
    if is_hard_health_verdict(repaired_health["health_verdict"]):
        raise AppError(f"Dataplane health check failed after repair: {health_failure_message(repaired_health)}")
    return repaired_preflights


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
        if target.saved_connection:
            assert_server_route_not_self_tunneled(target, env)
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
        check_service_active vpn-stack-sync.timer vpn-stack-sync.timer
        check_service_active vpn-stack-health.timer vpn-stack-health.timer
        check_service_active wg-quick@{wg_interface} wg-quick@{wg_interface}
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
    print(f"Основной VLESS URI: {paths['vless_uri']}")
    print(f"JSON fallback для Hiddify: {paths['hiddify_json']}")
    print(f"Android JSON fallback для Hiddify: {paths['android_hiddify_json']}")
    print(f"Windows/v2rayN Xray JSON: {paths['windows_xray_json']}")
    print(f"Windows route bypass helper: {paths['windows_route_bypass']}")
    print(f"Hiddify URI alias: {paths['hiddify_uri_compat']}")
    print(f"JSON backup для Linux: {paths['linux_json']}")
    print(f"Следующие шаги: {paths['next_steps']}")
    print(clipboard_message)
    print("Что делать дальше:")
    print("1. На любой платформе сначала используй прямой VLESS URI.")
    print(f"2. На Windows/v2rayN используй {paths['windows_xray_json'].name} с Xray core.")
    print(f"3. Основной файл: {paths['vless_uri'].name}. На Android эталонные клиенты: v2rayNG или NekoBox.")
    print(f"4. Если нужен Hiddify на Android, используй локальный JSON {paths['android_hiddify_json'].name}.")
    print(f"5. Файл {paths['hiddify_uri_compat'].name} оставлен как совместимый alias того же VLESS URI.")
    print(f"6. Если включён TUN/full VPN и client-check показывает self-tunnel, запусти PowerShell от администратора: .\\{paths['windows_route_bypass'].name}")
    print(f"7. Для проверки серверов потом запусти: vpn status --deployment {deployment_name}")


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
    wg_interface = current_wg_interface(env)
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
    ensure_deployment_health(env, targets, auto_repair=True)
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
    if set(roles) == {ROLE_RU, ROLE_FOREIGN} and {target.role for target in targets} == {ROLE_RU, ROLE_FOREIGN}:
        ensure_deployment_health(env, targets, auto_repair=False)
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
        if {target.role for target in targets} == {ROLE_RU, ROLE_FOREIGN}:
            ensure_deployment_health(env, targets, auto_repair=True)
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
        failed = failed or verdict.startswith("BAD")
    if failed:
        print("Проблема: IP сервера уходит через VPN-интерфейс. В TUN/full VPN используй route-safe JSON или добавь bypass/direct rule для IP обоих серверов.")
        paths = client_artifact_paths(env)
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
