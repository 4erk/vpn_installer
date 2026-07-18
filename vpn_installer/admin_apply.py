from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

BASE_CONFIG_PATH = Path("/etc/vpn-stack/sing-box.base.json")
CONFIG_PATH = Path("/etc/sing-box/config.json")
RULES_PATH = Path("/etc/vpn-stack/admin-routing-rules.json")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
OUTBOUND_TO_DNS = {"direct-ru": "dns-ru-direct", "to-foreign": "dns-global"}
OUTBOUND_LABELS = {"direct-ru": "российский сервер", "to-foreign": "зарубежный сервер"}


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
    if outbound not in OUTBOUND_TO_DNS:
        raise ValueError("Нужно выбрать российский или зарубежный сервер")
    value = str(raw_rule.get("value", "")).strip()
    if not value:
        raise ValueError("Значение правила не может быть пустым")
    rule_type = str(raw_rule.get("type", "domain")).strip()
    include_subdomains = bool(raw_rule.get("include_subdomains", False))
    if rule_type == "cidr" or "/" in value:
        network = ipaddress.ip_network(value, strict=False)
        return {
            "id": str(raw_rule.get("id", "")),
            "type": "cidr",
            "value": str(network),
            "include_subdomains": False,
            "outbound": outbound,
            "enabled": bool(raw_rule.get("enabled", True)),
        }
    domain, wildcard = normalize_domain(value)
    return {
        "id": str(raw_rule.get("id", "")),
        "type": "domain",
        "value": domain,
        "include_subdomains": include_subdomains or wildcard,
        "outbound": outbound,
        "enabled": bool(raw_rule.get("enabled", True)),
    }


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


def route_insert_index(rules: list[dict[str, Any]]) -> int:
    index = 0
    for i, rule in enumerate(rules):
        if rule.get("inbound") == ["router-in"]:
            index = i + 1
        elif rule.get("action") == "route-options":
            index = i + 1
        elif rule.get("protocol") == "dns":
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


def apply_admin_rules_to_config(base_config: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    config = json.loads(json.dumps(base_config))
    enabled = [rule for rule in rules if rule.get("enabled", True)]
    dns_rules = config.setdefault("dns", {}).setdefault("rules", [])
    route_rules = config.setdefault("route", {}).setdefault("rules", [])
    dns_inserts: list[dict[str, Any]] = []
    route_inserts: list[dict[str, Any]] = []
    for rule in enabled:
        outbound = rule["outbound"]
        dns_server = OUTBOUND_TO_DNS[outbound]
        if rule["type"] == "cidr":
            route_inserts.append({"ip_cidr": [rule["value"]], "action": "route", "outbound": outbound})
            continue
        domains, suffixes = rule_domains(rule)
        if domains:
            dns_inserts.append({"domain": domains, "action": "route", "server": dns_server, "strategy": "ipv4_only"})
            route_inserts.append({"domain": domains, "action": "route", "outbound": outbound})
        if suffixes:
            dns_inserts.append({"domain_suffix": suffixes, "action": "route", "server": dns_server, "strategy": "ipv4_only"})
            route_inserts.append({"domain_suffix": suffixes, "action": "route", "outbound": outbound})
    if dns_inserts:
        index = dns_insert_index(dns_rules)
        dns_rules[index:index] = dns_inserts
    if route_inserts:
        index = route_insert_index(route_rules)
        route_rules[index:index] = route_inserts
    return config


def apply_rules(base_path: Path = BASE_CONFIG_PATH, config_path: Path = CONFIG_PATH, rules_path: Path = RULES_PATH, *, restart: bool = True) -> None:
    base_config = read_json(base_path, None)
    if not isinstance(base_config, dict):
        raise RuntimeError(f"Base sing-box config not found or invalid: {base_path}")
    rules = load_rules(rules_path)
    config = apply_admin_rules_to_config(base_config, rules)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(config_path.parent), suffix=".json") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        tmp_name = handle.name
    tmp_path = Path(tmp_name)
    try:
        if shutil.which("sing-box"):
            subprocess.run(["sing-box", "check", "-c", str(tmp_path)], check=True)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, config_path)
        if restart and shutil.which("systemctl"):
            subprocess.run(["systemctl", "restart", "sing-box"], check=True)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


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
