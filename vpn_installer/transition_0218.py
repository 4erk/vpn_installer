from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping

from .common import parse_env_value
from .topology import (
    CAP_INTERSERVER_CLIENT,
    CAP_NAT_EXIT,
    CAP_PUBLIC_FRONT,
    CAP_RU_SPLIT_ROUTING,
    CAP_WEB_ADMIN,
    CONFIG_SCHEMA_VERSION,
    NODE_GATEWAY,
    TopologySpec,
)


SOURCE_VERSION = "0.21.8"
SOURCE_MANIFEST_SCHEMA = 4
SOURCE_INSTALL_PLAN_SCHEMA = 4
SOURCE_DIAGNOSTICS_SCHEMA = 5
SOURCE_POLICY_VERSION = "0.18.0"
SOURCE_UPDATE_COMPATIBILITY = {
    "installed_min": "0.21.7",
    "installed_max": SOURCE_VERSION,
    "transitions": [{"from": "0.21.7", "to": SOURCE_VERSION}],
}

BASE_PACKAGES = (
    "ca-certificates", "curl", "e2fsprogs", "iproute2", "kmod", "logrotate",
    "nftables", "python3", "systemd-resolved", "tar", "unattended-upgrades", "util-linux",
)
PUBLIC_FRONT_PACKAGES = ("unzip",)
INTERSERVER_PACKAGES = ("iperf3", "iputils-ping", "wireguard", "wireguard-tools")


@dataclass(frozen=True)
class _Artifact:
    install_path: str
    capability: str
    ownership: str = "managed"


BASE_ARTIFACTS = {
    "sing-box.service": _Artifact("/etc/systemd/system/sing-box.service", "base"),
    "nftables.conf": _Artifact("/etc/vpn-stack/nftables.conf", "base"),
    "vpn-stack-nft-apply.sh": _Artifact("/usr/local/lib/vpn-stack/nft-apply.sh", "base"),
    "vpn-stack-nftables.service": _Artifact("/etc/systemd/system/vpn-stack-nftables.service", "base"),
    "sshd-vpn-stack.conf": _Artifact("/etc/ssh/sshd_config.d/90-vpn-stack.conf", "base"),
    "sysctl-vpn-stack.conf": _Artifact("/etc/sysctl.d/90-vpn-stack.conf", "base"),
    "modules-vpn-stack.conf": _Artifact("/etc/modules-load.d/90-vpn-stack.conf", "base"),
    "journald-vpn-stack.conf": _Artifact("/etc/systemd/journald.conf.d/90-vpn-stack.conf", "base"),
    "apt-vpn-stack-unattended.conf": _Artifact("/etc/apt/apt.conf.d/90-vpn-stack-unattended", "base"),
    "resolved-vpn-stack.conf": _Artifact("/etc/systemd/resolved.conf.d/90-vpn-stack.conf", "base"),
    "btmp-vpn-stack.conf": _Artifact("/usr/local/lib/vpn-stack/btmp-logrotate.conf", "base"),
    "vpn-stack-agent.py": _Artifact("/usr/local/lib/vpn-stack/vpn-stack-agent.py", "base"),
    "diagnostics.py": _Artifact("/usr/local/lib/vpn-stack/diagnostics.py", "base"),
    "log_classifier.py": _Artifact("/usr/local/lib/vpn-stack/log_classifier.py", "base"),
    "network_profile.py": _Artifact("/usr/local/lib/vpn-stack/network_profile.py", "base"),
    "release_integrity.py": _Artifact("/usr/local/lib/vpn-stack/release_integrity.py", "base"),
    "resource_control.py": _Artifact("/usr/local/lib/vpn-stack/resource_control.py", "base"),
    "vpn-stack-health.service": _Artifact("/etc/systemd/system/vpn-stack-health.service", "base"),
    "vpn-stack-health.timer": _Artifact("/etc/systemd/system/vpn-stack-health.timer", "base"),
    "node.env": _Artifact("/etc/vpn-stack/deployment.env", "base"),
}
GATEWAY_ARTIFACTS = {
    "sing-box.json": _Artifact("/etc/vpn-stack/sing-box.base.json", "router"),
    "admin_apply.py": _Artifact("/usr/local/lib/vpn-stack/admin_apply.py", "router"),
}
EXIT_ARTIFACTS = {"sing-box.json": _Artifact("/etc/sing-box/config.json", "nat-exit")}
PUBLIC_FRONT_ARTIFACTS = {
    "xray.json": _Artifact("/etc/xray/config.json", CAP_PUBLIC_FRONT),
    "vpn-stack-xray.service": _Artifact("/etc/systemd/system/vpn-stack-xray.service", CAP_PUBLIC_FRONT),
}
WEB_ADMIN_ARTIFACTS = {
    "admin_web.py": _Artifact("/usr/local/lib/vpn-stack/admin_web.py", CAP_WEB_ADMIN),
    "vpn-stack-admin.service": _Artifact("/etc/systemd/system/vpn-stack-admin.service", CAP_WEB_ADMIN),
}
INTERSERVER_ARTIFACTS = {
    "interserver_transport.py": _Artifact("/usr/local/lib/vpn-stack/interserver_transport.py", "interserver"),
    "topology.py": _Artifact("/usr/local/lib/vpn-stack/topology.py", "interserver"),
}
INTERSERVER_CLIENT_ARTIFACTS = {
    "vpn-stack-transport.service": _Artifact("/etc/systemd/system/vpn-stack-transport.service", CAP_INTERSERVER_CLIENT)
}
SERVICE_UNITS = {
    "sing-box": ("sing-box.service", "managed"),
    "nftables": ("vpn-stack-nftables.service", "managed"),
    "resolver": ("systemd-resolved.service", "borrowed"),
    "health_timer": ("vpn-stack-health.timer", "managed"),
    "xray": ("vpn-stack-xray.service", "managed"),
    "admin": ("vpn-stack-admin.service", "managed"),
    "wireguard": ("wg-quick@{wg_interface}.service", "managed"),
    "transport": ("vpn-stack-transport.service", "managed"),
}
BINARIES = {
    "sing-box": {
        "version": "1.13.12",
        "archive_sha256": "1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4",
        "sha256": "989e848637725005fdac7f1d3fa3d6eeb16992c5e0a68789da96b6b3fde06ea2",
        "path": "/etc/vpn-stack/current/bin/sing-box",
        "service": "sing-box.service",
    },
    "xray": {
        "version": "26.3.27",
        "archive_sha256": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
        "sha256": "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed",
        "path": "/etc/vpn-stack/current/bin/xray",
        "service": "vpn-stack-xray.service",
    },
}


def _fail(message: str) -> None:
    raise ValueError(f"invalid {SOURCE_VERSION} transition source: {message}")


def _object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"{label}: {exc}")
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def _canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _parse_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            _fail(f"invalid node.env line {number}")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            _fail(f"invalid node.env key on line {number}")
        result[key] = parse_env_value(raw_value)
    return result


def _safe_name(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@+-]*", value):
        _fail(f"unsafe {label}: {value!r}")
    return value


def _safe_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    roots = (
        "/etc/vpn-stack/", "/etc/sing-box/", "/etc/xray/", "/etc/wireguard/",
        "/etc/systemd/system/", "/etc/ssh/sshd_config.d/", "/etc/sysctl.d/",
        "/etc/modules-load.d/", "/etc/systemd/journald.conf.d/", "/etc/apt/apt.conf.d/",
        "/etc/systemd/resolved.conf.d/", "/usr/local/lib/vpn-stack/", "/var/lib/vpn-stack/",
    )
    if not path.is_absolute() or ".." in path.parts or not any(value.startswith(root) for root in roots):
        _fail(f"unsafe {label}: {value!r}")
    return value


def _write_rows(root: Path, name: str, rows: list[tuple[str, ...]]) -> None:
    if any("\t" in item or "\n" in item for row in rows for item in row):
        _fail(f"unsafe value in {name}")
    with (root / name).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("".join("\t".join(row) + "\n" for row in rows))


def _artifact_specs(plan, env: Mapping[str, str]) -> dict[str, _Artifact]:
    result = dict(BASE_ARTIFACTS)
    if str(env.get("JOURNAL_LIMIT_ENABLED", "1")).strip().lower() in {"0", "false", "no", "off"}:
        result.pop("journald-vpn-stack.conf")
    result.update(GATEWAY_ARTIFACTS if plan.node_id == NODE_GATEWAY else EXIT_ARTIFACTS)
    if CAP_PUBLIC_FRONT in plan.capabilities:
        result.update(PUBLIC_FRONT_ARTIFACTS)
    if CAP_WEB_ADMIN in plan.capabilities:
        result.update(WEB_ADMIN_ARTIFACTS)
    if plan.has_interserver:
        result.update(INTERSERVER_ARTIFACTS)
        interface = str(env.get("WG_INTERFACE", "")).strip() or "wg0"
        result[f"{interface}.conf"] = _Artifact(f"/etc/wireguard/{interface}.conf", "interserver")
    if CAP_INTERSERVER_CLIENT in plan.capabilities:
        result.update(INTERSERVER_CLIENT_ARTIFACTS)
    return result


def _asset_names(plan, env: Mapping[str, str]) -> set[str]:
    if CAP_RU_SPLIT_ROUTING in plan.capabilities:
        return {"geosite-ru.srs", "geoip-ru.srs"}
    if CAP_NAT_EXIT in plan.capabilities and str(env.get("FOREIGN_BLOCK_RU", "0")).strip() == "1":
        return {"ru-ipv4.zone", "ru-ipv6.zone"}
    return set()


def validate_installed_bundle(bundle: Path, expected_node: str, contract_dir: Path) -> None:
    bundle = Path(bundle)
    manifest = _object(bundle / "render-manifest.json", "render-manifest.json")
    plan = _object(bundle / "install-plan.json", "install-plan.json")
    env_path = bundle / "node.env"
    if not env_path.is_file():
        _fail("node.env is missing")
    if manifest.get("version") != SOURCE_VERSION or manifest.get("schema_version") != SOURCE_MANIFEST_SCHEMA:
        _fail("release or manifest schema mismatch")
    if plan.get("schema_version") != SOURCE_INSTALL_PLAN_SCHEMA:
        _fail("install plan schema mismatch")
    if manifest.get("update_compatibility") != SOURCE_UPDATE_COMPATIBILITY:
        _fail("update compatibility metadata mismatch")
    if manifest.get("install_plan") != plan or manifest.get("install_plan_sha256") != _canonical_digest(plan):
        _fail("embedded install plan mismatch")

    env = _parse_env(env_path)
    if env.get("CONFIG_SCHEMA") != str(CONFIG_SCHEMA_VERSION) or env.get("NODE_ID") != expected_node:
        _fail("node.env schema or node mismatch")
    try:
        node = TopologySpec.from_env(env, require_addresses=False).plan(expected_node)
    except ValueError as exc:
        _fail(str(exc))
    canonical = {
        "topology": node.topology, "node_id": node.node_id, "location": node.location,
        "capabilities": sorted(node.capabilities), "required_services": list(node.required_services),
    }
    descriptor = {
        "id": node.node_id, "location": node.location, "public_ip": node.public_ip,
        "capabilities": sorted(node.capabilities), "required_services": list(node.required_services),
    }
    for field, value in canonical.items():
        if manifest.get(field) != value or plan.get(field) != value:
            _fail(f"canonical field mismatch: {field}")
    if manifest.get("node") != descriptor or plan.get("node") != descriptor:
        _fail("node descriptor mismatch")
    env_digest = _digest(env_path)
    if manifest.get("env_sha256") != env_digest or manifest.get("node_env_sha256") != env_digest:
        _fail("node.env digest mismatch")
    if manifest.get("policy_version") != SOURCE_POLICY_VERSION:
        _fail("routing policy version mismatch")

    artifacts = manifest.get("artifacts")
    assets = manifest.get("assets")
    binaries = manifest.get("binaries")
    if not isinstance(artifacts, dict) or not isinstance(assets, dict) or not isinstance(binaries, dict):
        _fail("artifact sections must be objects")
    if plan.get("artifacts") != artifacts or plan.get("assets") != assets or plan.get("binaries") != binaries:
        _fail("install plan payload sections mismatch")

    specs = _artifact_specs(node, env)
    if set(artifacts) != set(specs):
        _fail("artifact set mismatch")
    artifact_rows: list[tuple[str, ...]] = []
    for name in sorted(specs):
        entry = artifacts[name]
        spec = specs[name]
        if not isinstance(entry, dict):
            _fail(f"artifact entry is invalid: {name}")
        expected = {
            "sha256": entry.get("sha256"), "install_path": spec.install_path,
            "required": True, "capability": spec.capability, "ownership": spec.ownership,
        }
        if entry != expected or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
            _fail(f"artifact contract mismatch: {name}")
        payload = bundle / name
        if not payload.is_file() or _digest(payload) != entry["sha256"]:
            _fail(f"artifact payload mismatch: {name}")
        artifact_rows.append((_safe_name(name, "artifact name"), _safe_path(spec.install_path, "artifact path"), spec.ownership, str(entry["sha256"]), spec.capability))

    expected_assets = _asset_names(node, env)
    if set(assets) != expected_assets:
        _fail("asset set mismatch")
    asset_rows: list[tuple[str, ...]] = []
    for name in sorted(expected_assets):
        entry = assets[name]
        expected_path = f"/var/lib/vpn-stack/rules/{name}"
        if not isinstance(entry, dict) or entry.get("install_path") != expected_path:
            _fail(f"asset contract mismatch: {name}")
        digest = str(entry.get("sha256", ""))
        payload = bundle / "assets" / name
        if entry.get("required") is not True or entry.get("ownership") != "managed":
            _fail(f"asset ownership mismatch: {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not payload.is_file() or _digest(payload) != digest:
            _fail(f"asset payload mismatch: {name}")
        asset_rows.append((_safe_name(name, "asset name"), expected_path, "managed", digest))

    expected_binaries = {"sing-box": BINARIES["sing-box"]}
    if node.requires_xray:
        expected_binaries["xray"] = BINARIES["xray"]
    if binaries != expected_binaries:
        _fail("binary contract mismatch")
    binary_rows: list[tuple[str, ...]] = []
    for name, entry in sorted(expected_binaries.items()):
        payload = bundle / "bin" / name
        if not payload.is_file() or _digest(payload) != entry["sha256"]:
            _fail(f"binary payload mismatch: {name}")
        binary_rows.append((name, entry["version"], entry["archive_sha256"], entry["sha256"], entry["path"], entry["service"]))

    interface = str(env.get("WG_INTERFACE", "")).strip() or "wg0"
    services = [
        {"name": name, "unit": SERVICE_UNITS[name][0].format(wg_interface=interface), "ownership": SERVICE_UNITS[name][1]}
        for name in node.required_services
    ]
    if plan.get("services") != services:
        _fail("service contract mismatch")
    service_rows = [(entry["name"], entry["unit"], entry["ownership"]) for entry in services]

    package_sets: dict[str, list[str]] = {"base": list(BASE_PACKAGES)}
    packages = set(BASE_PACKAGES)
    if node.requires_xray:
        package_sets[CAP_PUBLIC_FRONT] = list(PUBLIC_FRONT_PACKAGES)
        packages.update(PUBLIC_FRONT_PACKAGES)
    if node.has_interserver:
        package_sets["interserver"] = list(INTERSERVER_PACKAGES)
        packages.update(INTERSERVER_PACKAGES)
    if plan.get("packages") != sorted(packages) or plan.get("package_sets") != package_sets:
        _fail("package contract mismatch")

    allowed_files = set(specs) | {"render-manifest.json", "install-plan.json"}
    if any(path.name not in allowed_files for path in bundle.iterdir() if path.is_file()):
        _fail("unknown bundle file")
    if any(path.name not in {"assets", "bin"} for path in bundle.iterdir() if path.is_dir()):
        _fail("unknown bundle directory")

    contract_dir.mkdir(parents=True, exist_ok=True)
    _write_rows(contract_dir, "artifacts.tsv", artifact_rows)
    _write_rows(contract_dir, "assets.tsv", asset_rows)
    _write_rows(contract_dir, "binaries.tsv", binary_rows)
    _write_rows(contract_dir, "services.tsv", service_rows)
    _write_rows(contract_dir, "packages.tsv", [(name,) for name in sorted(packages)])
    _write_rows(contract_dir, "meta.tsv", [
        ("schema_version", str(SOURCE_MANIFEST_SCHEMA)),
        ("release_id", _safe_name(str(manifest.get("release_id", "")), "release id")),
        ("version", SOURCE_VERSION),
        ("deployment", _safe_name(env.get("DEPLOY_NAME", ""), "deployment name")),
        ("topology", node.topology), ("node_id", node.node_id), ("location", node.location),
        ("capabilities", ",".join(sorted(node.capabilities))),
    ])


def require_snapshot(payload: Mapping[str, object], manifest: Mapping[str, object]) -> None:
    if manifest.get("version") != SOURCE_VERSION or manifest.get("schema_version") != SOURCE_MANIFEST_SCHEMA:
        _fail("legacy acceptance manifest mismatch")
    if payload.get("schema_version") != SOURCE_DIAGNOSTICS_SCHEMA:
        _fail("legacy diagnostics schema mismatch")
    release = payload.get("release")
    if not isinstance(release, Mapping) or release.get("version") != SOURCE_VERSION:
        _fail("legacy diagnostics release mismatch")
    for field in ("topology", "node_id", "location", "capabilities"):
        if payload.get(field) != manifest.get(field):
            _fail(f"legacy diagnostics canonical field mismatch: {field}")


def normalize_snapshot(
    payload: Mapping[str, object],
    manifest: Mapping[str, object],
    *,
    target_schema: int,
) -> dict[str, object]:
    require_snapshot(payload, manifest)
    normalized = dict(payload)
    normalized["schema_version"] = target_schema
    return normalized


def preflight_projection(payload: Mapping[str, object]) -> dict[str, str]:
    if payload.get("schema_version") != SOURCE_DIAGNOSTICS_SCHEMA:
        _fail("legacy preflight diagnostics schema mismatch")
    release = payload.get("release")
    if not isinstance(release, Mapping) or release.get("version") != SOURCE_VERSION:
        _fail("legacy preflight release mismatch")
    host = payload.get("host") if isinstance(payload.get("host"), Mapping) else {}
    services = payload.get("services") if isinstance(payload.get("services"), Mapping) else {}
    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), Mapping) else {}
    return {
        "schema_version": str(SOURCE_DIAGNOSTICS_SCHEMA), "login_user": str(host.get("login_user", "")),
        "is_root": "1" if host.get("is_root") is True else "0", "has_sudo": "1" if host.get("has_sudo") is True else "0",
        "hostname": str(host.get("hostname", "")), "os_id": str(host.get("os_id", "")),
        "os_version": str(host.get("os_version", "")), "architecture": "x86_64", "init_system": "systemd",
        "security_mode": "unknown", "host_firewall": "none", "deployment_name": str(payload.get("deployment", "")),
        "topology": str(payload.get("topology", "")), "node": str(payload.get("node_id", "")),
        "location": str(payload.get("location", "")),
        "capabilities": ",".join(str(value) for value in payload.get("capabilities", []) if value),
        "installed": "1", "release_version": SOURCE_VERSION, "release_id": str(release.get("release_id", "")),
        "installed_at": str(release.get("installed_at", "")), "sing_box": str(services.get("sing-box", "")),
        "xray": str(services.get("xray", "")), "nftables": str(services.get("nftables", "")),
        "wireguard": str(services.get("wireguard", "")), "admin": str(services.get("admin", "")),
        "resolver": str(services.get("resolver", "")), "health_timer": str(services.get("health_timer", "unknown")),
        "drift": str(artifacts.get("drift", "unknown")),
    }
