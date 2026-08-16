from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Iterator

sys.dont_write_bytecode = True

try:
    import fcntl
except ImportError:  # Windows unit tests.
    fcntl = None  # type: ignore[assignment]

BASE_CONFIG_PATH = Path("/etc/vpn-stack/sing-box.base.json")
CONFIG_PATH = Path("/etc/sing-box/config.json")
RULES_PATH = Path("/etc/vpn-stack/admin-routing-rules.json")
OPERATOR_MANIFEST_PATH = Path("/etc/vpn-stack/operator-state.json")
RULES_LOCK_PATH = Path("/run/lock/vpn-stack-routes.lock")
SING_BOX_BINARY_PATH = Path("/etc/vpn-stack/current/bin/sing-box")
_THREAD_LOCK = threading.Lock()

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
OUTBOUND_LABELS = {
    "direct-ru": "российский сервер",
    "to-foreign": "зарубежный сервер",
    "local-egress": "текущий сервер",
}


class RulesConflictError(RuntimeError):
    pass


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def write_bytes_atomic(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


@contextmanager
def routes_lock(path: Path = RULES_LOCK_PATH) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _THREAD_LOCK, path.open("a+b") as handle:
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle, fcntl.LOCK_UN)


def normalize_domain(raw_value: str) -> tuple[str, bool]:
    value = raw_value.strip().lower().rstrip(".")
    include_subdomains = False
    if value.startswith("*."):
        include_subdomains = True
        value = value[2:]
    if value.startswith("."):
        include_subdomains = True
        value = value[1:]
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("Домен должен быть обычным DNS-именем, например example.com или *.example.com")
    return value, include_subdomains


def normalize_rule(raw_rule: dict[str, Any]) -> dict[str, Any]:
    outbound = str(raw_rule.get("outbound", "")).strip()
    if outbound not in OUTBOUND_LABELS:
        raise ValueError("Нужно выбрать доступный сервер")
    value = str(raw_rule.get("value", "")).strip()
    if not value:
        raise ValueError("Значение правила не может быть пустым")
    rule_type = str(raw_rule.get("type", "domain")).strip()
    include_subdomains = bool(raw_rule.get("include_subdomains", False))
    if rule_type == "cidr" or "/" in value:
        network = ipaddress.ip_network(value, strict=False)
        if not network.is_global:
            raise ValueError("CIDR web-правила разрешены только для публичных сетей")
        rule = {
            "id": str(raw_rule.get("id", "")).strip() or uuid.uuid4().hex,
            "type": "cidr",
            "value": str(network),
            "include_subdomains": False,
            "outbound": outbound,
            "enabled": bool(raw_rule.get("enabled", True)),
        }
        if not rule["enabled"] and str(raw_rule.get("conflict", "")).strip():
            rule["conflict"] = str(raw_rule["conflict"]).strip()
        return rule
    domain, wildcard = normalize_domain(value)
    rule = {
        "id": str(raw_rule.get("id", "")).strip() or uuid.uuid4().hex,
        "type": "domain",
        "value": domain,
        "include_subdomains": include_subdomains or wildcard,
        "outbound": outbound,
        "enabled": bool(raw_rule.get("enabled", True)),
    }
    if not rule["enabled"] and str(raw_rule.get("conflict", "")).strip():
        rule["conflict"] = str(raw_rule["conflict"]).strip()
    return rule


def load_rules(path: Path = RULES_PATH) -> list[dict[str, Any]]:
    payload = read_json(path, {"rules": []})
    rules = payload.get("rules", []) if isinstance(payload, dict) else []
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str, bool, str]] = set()
    for raw_rule in rules:
        if not isinstance(raw_rule, dict):
            continue
        rule = normalize_rule(raw_rule)
        key = (rule["type"], rule["value"], rule["include_subdomains"], rule["outbound"])
        if key in seen:
            continue
        seen.add(key)
        normalized.append(rule)
    return normalized


def normalize_rules(raw_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str, bool, str]] = set()
    seen_ids: set[str] = set()
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            raise ValueError("routing rules must be JSON objects")
        rule = normalize_rule(raw_rule)
        key = (rule["type"], rule["value"], rule["include_subdomains"], rule["outbound"])
        if key in seen:
            continue
        if rule["id"] in seen_ids:
            raise ValueError(f"duplicate route id: {rule['id']}")
        seen.add(key)
        seen_ids.add(rule["id"])
        normalized.append(rule)
    return normalized


def rules_generation(rules: list[dict[str, Any]]) -> str:
    payload = json.dumps(normalize_rules(rules), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def route_insert_index(rules: list[dict[str, Any]]) -> int:
    index = 0
    for i, rule in enumerate(rules):
        if rule.get("inbound") == ["router-in"]:
            index = i + 1
        elif rule.get("action") == "route-options":
            index = i + 1
        elif rule.get("port") == 53 and rule.get("outbound") == "to-foreign":
            index = i + 1
    return index


def dns_insert_index(rules: list[dict[str, Any]]) -> int:
    index = 0
    for i, rule in enumerate(rules):
        if rule.get("query_type") == ["AAAA"]:
            index = i + 1
    return index


def rule_domains(rule: dict[str, Any]) -> tuple[list[str], list[str]]:
    value = rule["value"]
    if not rule["include_subdomains"]:
        return [value], []
    return [value], [f".{value}"]


def outbound_catalog(base_config: dict[str, Any]) -> dict[str, dict[str, str]]:
    catalog: dict[str, dict[str, str]] = {}
    for outbound in base_config.get("outbounds", []):
        if not isinstance(outbound, dict):
            continue
        tag = str(outbound.get("tag", ""))
        if tag not in OUTBOUND_LABELS:
            continue
        resolver = outbound.get("domain_resolver", {})
        dns_server = str(resolver.get("server", "")) if isinstance(resolver, dict) else ""
        if not dns_server:
            continue
        catalog[tag] = {"tag": tag, "label": OUTBOUND_LABELS[tag], "dns_server": dns_server}
    return catalog


def resolve_outbound(outbound: str, catalog: dict[str, dict[str, str]]) -> str:
    if outbound in catalog:
        return outbound
    raise ValueError(f"Направление {outbound or '-'} отсутствует в текущей topology")


def reconcile_rules_with_catalog(
    rules: list[dict[str, Any]],
    catalog: dict[str, dict[str, str]],
    *,
    migrate_unavailable: bool,
) -> list[dict[str, Any]]:
    reconciled: list[dict[str, Any]] = []
    for rule in rules:
        if rule["outbound"] in catalog:
            reconciled.append({key: value for key, value in rule.items() if key != "conflict"})
            continue
        if not migrate_unavailable:
            resolve_outbound(rule["outbound"], catalog)
        reconciled.append(
            {
                **rule,
                "enabled": False,
                "conflict": f"outbound {rule['outbound']} is unavailable in the installed topology",
            }
        )
    return reconciled


def apply_admin_rules_to_config(base_config: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    config = json.loads(json.dumps(base_config))
    catalog = outbound_catalog(config)
    if not catalog:
        raise ValueError("В base config нет egress, доступного для operator rules")
    enabled = [rule for rule in rules if rule.get("enabled", True)]
    dns_rules = config.setdefault("dns", {}).setdefault("rules", [])
    route_rules = config.setdefault("route", {}).setdefault("rules", [])
    dns_inserts: list[dict[str, Any]] = []
    guard_rules: list[dict[str, Any]] = []
    for route_rule in route_rules:
        if route_rule.get("action") != "reject" or not ("ip_cidr" in route_rule or route_rule.get("ip_is_private") is True):
            continue
        if route_rule not in guard_rules:
            guard_rules.append(route_rule)
    route_inserts: list[dict[str, Any]] = []
    for rule in enabled:
        outbound = resolve_outbound(rule["outbound"], catalog)
        dns_server = catalog[outbound]["dns_server"]
        if rule["type"] == "cidr":
            route_inserts.extend((*guard_rules, {"ip_cidr": [rule["value"]], "action": "route", "outbound": outbound}))
            continue
        domains, suffixes = rule_domains(rule)
        if domains:
            dns_inserts.append({"domain": domains, "action": "route", "server": dns_server, "strategy": "ipv4_only"})
            route_inserts.extend((
                {"domain": domains, "action": "resolve", "server": dns_server, "strategy": "ipv4_only"},
                *guard_rules,
                {"domain": domains, "action": "route", "outbound": outbound},
            ))
        if suffixes:
            dns_inserts.append({"domain_suffix": suffixes, "action": "route", "server": dns_server, "strategy": "ipv4_only"})
            route_inserts.extend((
                {"domain_suffix": suffixes, "action": "resolve", "server": dns_server, "strategy": "ipv4_only"},
                *guard_rules,
                {"domain_suffix": suffixes, "action": "route", "outbound": outbound},
            ))
    if dns_inserts:
        index = dns_insert_index(dns_rules)
        dns_rules[index:index] = dns_inserts
    if route_inserts:
        index = route_insert_index(route_rules)
        route_rules[index:index] = route_inserts
    return config


def render_checked_config(
    base_path: Path,
    config_path: Path,
    rules: list[dict[str, Any]],
    *,
    sing_box_binary: Path = SING_BOX_BINARY_PATH,
) -> Path:
    base_config = read_json(base_path, None)
    if not isinstance(base_config, dict):
        raise RuntimeError(f"Base sing-box config not found or invalid: {base_path}")
    config = apply_admin_rules_to_config(base_config, rules)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(config_path.parent), suffix=".json") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        tmp_name = handle.name
    tmp_path = Path(tmp_name)
    try:
        if not sing_box_binary.is_file():
            raise RuntimeError(f"Managed sing-box binary is missing: {sing_box_binary}")
        subprocess.run([str(sing_box_binary), "check", "-c", str(tmp_path)], check=True, timeout=30)
        os.chmod(tmp_path, 0o600)
        return tmp_path
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def restart_and_verify_singbox() -> None:
    if not shutil.which("systemctl"):
        return
    subprocess.run(["systemctl", "restart", "sing-box"], check=True, timeout=30)
    subprocess.run(["systemctl", "is-active", "--quiet", "sing-box"], check=True, timeout=15)


def commit_rules(
    raw_rules: list[dict[str, Any]],
    base_path: Path = BASE_CONFIG_PATH,
    config_path: Path = CONFIG_PATH,
    rules_path: Path = RULES_PATH,
    *,
    restart: bool = True,
    lock_path: Path | None = None,
    operator_manifest_path: Path | None = None,
    sing_box_binary: Path = SING_BOX_BINARY_PATH,
    expected_generation: str | None = None,
    migrate_unavailable: bool = False,
) -> list[dict[str, Any]]:
    rules = normalize_rules(raw_rules)
    base_config = read_json(base_path, None)
    if not isinstance(base_config, dict):
        raise RuntimeError(f"Base sing-box config not found or invalid: {base_path}")
    catalog = outbound_catalog(base_config)
    rules = reconcile_rules_with_catalog(rules, catalog, migrate_unavailable=migrate_unavailable)
    effective_lock = lock_path or (RULES_LOCK_PATH if rules_path == RULES_PATH else rules_path.with_suffix(".lock"))
    effective_manifest = operator_manifest_path or (
        OPERATOR_MANIFEST_PATH if rules_path == RULES_PATH else rules_path.with_suffix(".operator-state.json")
    )
    with routes_lock(effective_lock):
        current_rules = load_rules(rules_path)
        current_generation = rules_generation(current_rules)
        if expected_generation is not None and current_generation != expected_generation:
            raise RulesConflictError("Правила уже изменены другим запросом; перечитайте список и повторите операцию.")
        old_rules = rules_path.read_bytes() if rules_path.exists() else None
        old_config = config_path.read_bytes() if config_path.exists() else None
        old_manifest = effective_manifest.read_bytes() if effective_manifest.exists() else None
        staged_config = render_checked_config(base_path, config_path, rules, sing_box_binary=sing_box_binary)
        try:
            write_json_atomic(rules_path, {"schema_version": 2, "rules": rules})
            os.replace(staged_config, config_path)
            manifest = {
                "schema_version": 2,
                "generation": rules_generation(rules),
                "base_sha256": hashlib.sha256(base_path.read_bytes()).hexdigest(),
                "rules_sha256": hashlib.sha256(rules_path.read_bytes()).hexdigest(),
                "effective_config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
                "conflicts": sum(bool(rule.get("conflict")) for rule in rules),
            }
            write_json_atomic(effective_manifest, manifest)
            if restart:
                restart_and_verify_singbox()
        except Exception as exc:
            if old_rules is None:
                rules_path.unlink(missing_ok=True)
            else:
                write_bytes_atomic(rules_path, old_rules)
            if old_config is None:
                config_path.unlink(missing_ok=True)
            else:
                write_bytes_atomic(config_path, old_config)
            if old_manifest is None:
                effective_manifest.unlink(missing_ok=True)
            else:
                write_bytes_atomic(effective_manifest, old_manifest)
            if restart and old_config is not None:
                try:
                    restart_and_verify_singbox()
                except Exception as rollback_exc:
                    raise RuntimeError(f"route apply failed: {exc}; rollback failed: {rollback_exc}") from exc
            raise
        finally:
            staged_config.unlink(missing_ok=True)
    return rules


def apply_rules(
    base_path: Path = BASE_CONFIG_PATH,
    config_path: Path = CONFIG_PATH,
    rules_path: Path = RULES_PATH,
    *,
    restart: bool = True,
    operator_manifest_path: Path | None = None,
    sing_box_binary: Path = SING_BOX_BINARY_PATH,
    migrate_unavailable: bool = True,
) -> None:
    commit_rules(
        load_rules(rules_path),
        base_path,
        config_path,
        rules_path,
        restart=restart,
        operator_manifest_path=operator_manifest_path,
        sing_box_binary=sing_box_binary,
        migrate_unavailable=migrate_unavailable,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, default=BASE_CONFIG_PATH)
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--rules", type=Path, default=RULES_PATH)
    parser.add_argument("--no-restart", action="store_true")
    args = parser.parse_args(argv)
    apply_rules(args.base, args.config, args.rules, restart=not args.no_restart)
    return 0


if __name__ == "__main__":
    sys.exit(main())
