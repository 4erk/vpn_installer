from __future__ import annotations

from .common import print_header
from .models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from .remote import remote_preflight


def current_wg_interface(env: dict[str, str]) -> str:
    return env.get("WG_INTERFACE", "").strip() or "wg0"


def handshake_age_seconds(preflight: dict[str, str]) -> int:
    raw_value = preflight.get("wg_latest_handshake_age_s", "").strip()
    try:
        return int(raw_value)
    except ValueError:
        return -1


def handshake_grace_seconds(env: dict[str, str]) -> int:
    keepalive = env_int(env, "WG_KEEPALIVE", 25)
    configured_grace = env_int(env, "HEALTH_HANDSHAKE_GRACE_SECONDS", 180)
    min_grace = env_int(env, "HEALTH_HANDSHAKE_MIN_GRACE_SECONDS", 180)
    multiplier = env_int(env, "HEALTH_HANDSHAKE_GRACE_MULTIPLIER", 8)
    return max(configured_grace, min_grace, keepalive * multiplier)


def env_int(env: dict[str, str], key: str, default: int) -> int:
    try:
        return int(env.get(key, str(default)).strip())
    except ValueError:
        return default


def preflight_int_any(preflight: dict[str, str], keys: list[str], default: int = -1) -> int:
    for key in keys:
        value = preflight.get(key, "").strip()
        if not value:
            continue
        try:
            parsed = int(value)
        except ValueError:
            continue
        if parsed < 0:
            continue
        return parsed
    return default


def target_probe_issues(raw_probe: str) -> list[str]:
    issues: list[str] = []
    for item in raw_probe.split(";"):
        item = item.strip()
        if not item:
            continue
        label, separator, rest = item.partition(":")
        if not separator:
            continue
        verdict, _separator, rest = rest.partition(":")
        code = rest.split(":", 1)[0] if rest else "-"
        if verdict in {"blocked", "broken"} or verdict.startswith("http_"):
            issues.append(f"{label}:{verdict}:{code or '-'}")
    return issues


def target_probe_has_reachable(raw_probe: str) -> bool:
    for item in raw_probe.split(";"):
        item = item.strip()
        if not item:
            continue
        _label, separator, rest = item.partition(":")
        if not separator:
            continue
        verdict, _separator, _rest = rest.partition(":")
        if verdict == "reachable":
            return True
    return False


def target_probe_is_degraded(raw_probe: str) -> bool:
    return bool(target_probe_issues(raw_probe)) and not target_probe_has_reachable(raw_probe)


def below_soft_min(value: int, minimum: int, *, tolerance_percent: int = 10) -> bool:
    if value < 0:
        return False
    effective_minimum = minimum * (100 - tolerance_percent)
    return value * 100 < effective_minimum


def deployment_health_snapshot(env: dict[str, str], preflights: dict[str, dict[str, str]]) -> dict[str, str]:
    foreign = preflights.get(ROLE_FOREIGN, {})
    ru = preflights.get(ROLE_RU, {})
    foreign_ip = foreign.get("observed_ipv4", "").strip()
    ru_wg_ip = ru.get("wg_observed_ipv4", "").strip()
    ru_handshake_age = handshake_age_seconds(ru)
    foreign_handshake_age = handshake_age_seconds(foreign)
    max_age = handshake_grace_seconds(env)
    foreign_download_bps = preflight_int_any(foreign, ["direct_download_bps", "deep_foreign_direct_download_bps"])
    ru_wg_download_bps = preflight_int_any(ru, ["wg_download_bps", "deep_ru_wg_download_bps"])
    foreign_upload_bps = preflight_int_any(foreign, ["deep_foreign_direct_upload_bps"])
    ru_wg_upload_bps = preflight_int_any(ru, ["deep_ru_wg_upload_bps"])
    foreign_gateway_ping_loss_pct = preflight_int_any(foreign, ["deep_foreign_gateway_ping_loss_pct"])
    foreign_ru_ping_loss_pct = preflight_int_any(foreign, ["deep_foreign_ru_ping_loss_pct"])
    foreign_internet_ping_loss_pct = preflight_int_any(foreign, ["deep_foreign_internet_ping_loss_pct"])
    foreign_target_probe = foreign.get("target_probe_direct", "").strip()
    ru_wg_target_probe = ru.get("target_probe_wg", "").strip()
    foreign_target_issues = target_probe_issues(foreign_target_probe)
    ru_wg_target_issues = target_probe_issues(ru_wg_target_probe)
    foreign_target_degraded = target_probe_is_degraded(foreign_target_probe)
    ru_wg_target_degraded = target_probe_is_degraded(ru_wg_target_probe)
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
    elif ru_wg_target_degraded:
        verdict = "ru_wg_target_degraded"
    elif foreign_target_degraded:
        verdict = "foreign_target_degraded"
    elif foreign_gateway_ping_loss_pct > max_foreign_internet_ping_loss_pct >= 0:
        verdict = "foreign_gateway_ping_loss_degraded"
    elif foreign_ru_ping_loss_pct > max_foreign_ru_ping_loss_pct >= 0:
        verdict = "foreign_ru_ping_loss_degraded"
    elif foreign_internet_ping_loss_pct > max_foreign_internet_ping_loss_pct >= 0:
        verdict = "foreign_internet_ping_loss_degraded"
    elif below_soft_min(foreign_download_bps, min_foreign_download_bps):
        verdict = "foreign_direct_download_degraded"
    elif below_soft_min(ru_wg_download_bps, min_ru_wg_download_bps):
        verdict = "ru_wg_download_degraded"
    elif below_soft_min(foreign_upload_bps, min_foreign_upload_bps):
        verdict = "foreign_direct_upload_degraded"
    elif below_soft_min(ru_wg_upload_bps, min_ru_wg_upload_bps):
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
        "target_probe_direct": foreign_target_probe or "-",
        "target_probe_ru_wg": ru_wg_target_probe or "-",
        "target_probe_issues": ",".join(ru_wg_target_issues or foreign_target_issues) or "-",
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
    if health.get("target_probe_issues", "-") != "-":
        print(f"target probe issues: {health.get('target_probe_issues', '-')}")
        print(f"target probes direct: {health.get('target_probe_direct', '-')}")
        print(f"target probes RU over wg: {health.get('target_probe_ru_wg', '-')}")
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
        "foreign_target_degraded",
        "ru_wg_target_degraded",
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
        f"max_foreign_internet_ping_loss_pct={health.get('max_foreign_internet_ping_loss_pct', '-')}, "
        f"target_probe_issues={health.get('target_probe_issues', '-')}"
    )
