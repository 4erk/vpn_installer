from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from . import VERSION
from .common import parse_env_value
from .compatibility import CompatibilityWindow, require_compatible_installed
from .manifest import (
    INSTALL_PLAN_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    SERVICE_UNITS,
    _binary_entries,
    artifact_specs,
    build_install_plan,
    required_asset_names,
)
from .platforms import PlatformSpec
from .topology import CONFIG_SCHEMA_VERSION, TopologySpec


class InstallContractError(ValueError):
    """The rendered bundle does not satisfy its versioned install contract."""


def is_planned_install_maintenance(snapshot: Mapping[str, Any]) -> bool:
    """Recognize only the transport maintenance state caused by the active install lock."""

    if snapshot.get("verdict") != "degraded":
        return False
    if snapshot.get("reasons") != ["interserver_adaptation=maintenance"]:
        return False
    transport = snapshot.get("transport")
    if not isinstance(transport, Mapping):
        return False
    interserver = transport.get("interserver")
    if not isinstance(interserver, Mapping):
        return False
    adaptive = interserver.get("adaptive_state")
    return (
        isinstance(adaptive, Mapping)
        and adaptive.get("state") == "maintenance"
        and adaptive.get("reason") == "install transaction is active"
    )


def _fail(message: str) -> None:
    raise InstallContractError(message)


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"invalid {label}: {exc}")
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


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
    if not path.is_absolute() or ".." in path.parts or any("\t" in part or "\n" in part for part in path.parts):
        _fail(f"unsafe {label}: {value!r}")
    allowed = (
        "/etc/vpn-stack/",
        "/etc/sing-box/",
        "/etc/xray/",
        "/etc/wireguard/",
        "/etc/systemd/system/",
        "/etc/ssh/sshd_config.d/",
        "/etc/sysctl.d/",
        "/etc/modules-load.d/",
        "/etc/systemd/journald.conf.d/",
        "/etc/apt/apt.conf.d/",
        "/etc/systemd/resolved.conf.d/",
        "/usr/local/lib/vpn-stack/",
        "/var/lib/vpn-stack/",
    )
    if not any(value.startswith(prefix) for prefix in allowed):
        _fail(f"{label} is outside managed roots: {value}")
    return value


def _write_lines(contract_dir: Path, name: str, rows: list[tuple[str, ...]]) -> None:
    for row in rows:
        if any("\t" in value or "\n" in value for value in row):
            _fail(f"unsafe tabular value in {name}")
    text = "".join("\t".join(row) + "\n" for row in rows)
    with (contract_dir / name).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def validate_bundle(
    bundle: Path,
    expected_node: str,
    contract_dir: Path,
    *,
    external_assets: Path | None = None,
    require_assets: bool = False,
    require_binaries: bool = False,
    expected_platform: PlatformSpec | None = None,
) -> None:
    """Validate a current rendered node bundle and emit its fail-closed TSV contract."""

    _validate_bundle(
        bundle,
        expected_node,
        contract_dir,
        external_assets=external_assets,
        require_assets=require_assets,
        require_binaries=require_binaries,
        expected_version=VERSION,
        expected_platform=expected_platform,
    )


def validate_installed_bundle(
    bundle: Path,
    expected_node: str,
    contract_dir: Path,
) -> None:
    """Dispatch installed-release validation through the explicit compatibility window."""

    manifest_path = Path(bundle) / "render-manifest.json"
    if not manifest_path.is_file():
        _fail("installed release has no render-manifest.json")
    manifest = _read_object(manifest_path, "installed render-manifest.json")
    try:
        version = str(require_compatible_installed(manifest))
    except ValueError as exc:
        _fail(str(exc))
    if version == "0.21.8":
        from .transition_0218 import validate_installed_bundle as validate_legacy

        try:
            validate_legacy(bundle, expected_node, contract_dir)
        except ValueError as exc:
            _fail(str(exc))
        return
    _validate_bundle(
        bundle,
        expected_node,
        contract_dir,
        require_assets=True,
        require_binaries=True,
        expected_version=version,
    )


def normalize_acceptance_snapshot(
    payload: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate an installed release snapshot and return the current diagnostics schema."""

    from .diagnostics import SCHEMA_VERSION as diagnostics_schema

    version = str(manifest.get("version", ""))
    if version == "0.21.8":
        from .transition_0218 import normalize_snapshot

        try:
            return normalize_snapshot(payload, manifest, target_schema=diagnostics_schema)
        except ValueError as exc:
            _fail(str(exc))

    if version != VERSION or manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        _fail("acceptance manifest does not belong to a supported release")
    if payload.get("schema_version") != diagnostics_schema:
        _fail(f"post-activation agent did not return diagnostics schema {diagnostics_schema}")
    for field in ("topology", "node_id", "location", "capabilities"):
        if payload.get(field) != manifest.get(field):
            _fail(f"post-activation canonical field mismatch: {field}")
    return dict(payload)


def validate_acceptance_snapshot(payload: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    normalize_acceptance_snapshot(payload, manifest)


def _validate_bundle(
    bundle: Path,
    expected_node: str,
    contract_dir: Path,
    *,
    external_assets: Path | None = None,
    require_assets: bool,
    require_binaries: bool,
    expected_version: str,
    expected_platform: PlatformSpec | None = None,
) -> None:

    bundle = Path(bundle)
    contract_dir = Path(contract_dir)
    external_assets = Path(external_assets) if external_assets is not None else None

    manifest_path = bundle / "render-manifest.json"
    plan_path = bundle / "install-plan.json"
    env_path = bundle / "node.env"
    for path in (manifest_path, plan_path, env_path):
        if not path.is_file():
            _fail(f"missing bundle control file: {path.name}")

    manifest = _read_object(manifest_path, "render-manifest.json")
    standalone_plan = _read_object(plan_path, "install-plan.json")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        _fail(f"unsupported render manifest schema: {manifest.get('schema_version')!r}")
    if manifest.get("version") != expected_version:
        _fail(f"bundle version must be {expected_version}, got {manifest.get('version')!r}")
    if expected_version == VERSION:
        if manifest.get("update_compatibility") != CompatibilityWindow.current().to_manifest():
            _fail("current manifest update compatibility does not match the release contract")
    else:
        try:
            declared = CompatibilityWindow.from_manifest(manifest.get("update_compatibility"))
            declared.require(expected_version)
        except ValueError as exc:
            _fail(f"installed manifest has invalid update compatibility: {exc}")
    if standalone_plan.get("schema_version") != INSTALL_PLAN_SCHEMA_VERSION:
        _fail(f"unsupported install plan schema: {standalone_plan.get('schema_version')!r}")
    embedded_plan = manifest.get("install_plan")
    if not isinstance(embedded_plan, dict) or embedded_plan != standalone_plan:
        _fail("standalone install plan does not match the manifest")
    if manifest.get("install_plan_sha256") != _canonical_digest(standalone_plan):
        _fail("install plan digest mismatch")
    try:
        platform = PlatformSpec.from_dict(manifest.get("platform"))
    except ValueError as exc:
        _fail(f"invalid platform descriptor: {exc}")
    if standalone_plan.get("platform") != platform.to_dict():
        _fail("install plan platform does not match the manifest")
    if expected_platform is not None and platform != expected_platform:
        _fail(
            "bundle platform does not match the target host: "
            f"bundle={platform.os_id} {platform.os_version} {platform.architecture}, "
            f"host={expected_platform.os_id} {expected_platform.os_version} {expected_platform.architecture}"
        )

    env = _parse_env(env_path)
    if env.get("CONFIG_SCHEMA") != str(CONFIG_SCHEMA_VERSION):
        _fail(f"node.env CONFIG_SCHEMA must be {CONFIG_SCHEMA_VERSION}")
    if env.get("NODE_ID") != expected_node:
        _fail(f"node.env node mismatch: expected {expected_node}, got {env.get('NODE_ID')!r}")
    topology = TopologySpec.from_env(env, require_addresses=False)
    try:
        node_plan = topology.plan(expected_node)
    except ValueError as exc:
        _fail(str(exc))

    canonical = {
        "topology": node_plan.topology,
        "node_id": node_plan.node_id,
        "location": node_plan.location,
        "capabilities": sorted(node_plan.capabilities),
        "required_services": list(node_plan.required_services),
    }
    descriptor = {
        "id": node_plan.node_id,
        "location": node_plan.location,
        "public_ip": node_plan.public_ip,
        "capabilities": sorted(node_plan.capabilities),
        "required_services": list(node_plan.required_services),
    }
    for field, value in canonical.items():
        if manifest.get(field) != value or standalone_plan.get(field) != value:
            _fail(f"canonical field mismatch: {field}")
    if manifest.get("node") != descriptor or standalone_plan.get("node") != descriptor:
        _fail("canonical node descriptor mismatch")
    if "role" in manifest or "compatibility" in manifest:
        _fail("current manifest contains retired compatibility fields")

    env_sha = _digest(env_path)
    if manifest.get("env_sha256") != env_sha or manifest.get("node_env_sha256") != env_sha:
        _fail("node.env digest mismatch")

    artifacts = manifest.get("artifacts")
    assets = manifest.get("assets")
    binaries = manifest.get("binaries")
    if not isinstance(artifacts, dict) or not isinstance(assets, dict) or not isinstance(binaries, dict):
        _fail("manifest artifacts, assets and binaries must be objects")
    if standalone_plan.get("artifacts") != artifacts:
        _fail("install plan artifacts do not match the manifest")
    if standalone_plan.get("assets") != assets:
        _fail("install plan assets do not match the manifest")
    if standalone_plan.get("binaries") != binaries:
        _fail("install plan binaries do not match the manifest")

    expected_specs = artifact_specs(node_plan, env=env)
    if set(artifacts) != set(expected_specs):
        unknown = sorted(set(artifacts) - set(expected_specs))
        missing = sorted(set(expected_specs) - set(artifacts))
        _fail(f"artifact ownership mismatch; unknown={unknown}, missing={missing}")

    artifact_rows: list[tuple[str, ...]] = []
    for name in sorted(artifacts):
        _safe_name(name, "artifact name")
        entry = artifacts[name]
        if not isinstance(entry, dict):
            _fail(f"artifact entry must be an object: {name}")
        spec = expected_specs[name]
        expected_entry = {
            "sha256": entry.get("sha256"),
            "install_path": spec.install_path,
            "required": True,
            "capability": spec.capability,
            "ownership": spec.ownership,
        }
        if entry != expected_entry:
            _fail(f"artifact contract mismatch: {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
            _fail(f"artifact digest is invalid: {name}")
        artifact_path = bundle / name
        if not artifact_path.is_file() or _digest(artifact_path) != entry["sha256"]:
            _fail(f"artifact payload mismatch: {name}")
        artifact_rows.append(
            (
                name,
                _safe_path(str(entry["install_path"]), "artifact path"),
                str(entry["ownership"]),
                str(entry["sha256"]),
                str(entry["capability"]),
            )
        )

    foreign_block_ru = env.get("FOREIGN_BLOCK_RU", "0").strip() == "1"
    expected_assets = required_asset_names(node_plan, foreign_block_ru=foreign_block_ru)
    if set(assets) != set(expected_assets):
        _fail(f"asset contract mismatch; expected={sorted(expected_assets)}, got={sorted(assets)}")
    asset_rows: list[tuple[str, ...]] = []
    for name in sorted(assets):
        _safe_name(name, "asset name")
        entry = assets[name]
        expected_path = f"/var/lib/vpn-stack/rules/{name}"
        if not isinstance(entry, dict) or entry.get("install_path") != expected_path:
            _fail(f"asset path mismatch: {name}")
        if entry.get("required") is not True or entry.get("ownership") != "managed":
            _fail(f"asset ownership mismatch: {name}")
        expected_sha = str(entry.get("sha256", ""))
        if expected_sha and not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            _fail(f"asset digest is invalid: {name}")
        candidates = [bundle / "assets" / name]
        if external_assets is not None:
            candidates.append(external_assets / name)
        payload = next((path for path in candidates if path.is_file()), None)
        if payload is not None:
            if not expected_sha or _digest(payload) != expected_sha:
                _fail(f"asset payload mismatch: {name}")
        elif require_assets:
            _fail(f"required asset payload is missing: {name}")
        asset_rows.append((name, _safe_path(expected_path, "asset path"), "managed", expected_sha))

    expected_binaries = _binary_entries(node_plan)
    if binaries != expected_binaries:
        _fail("binary contract does not match canonical node capabilities")
    binary_rows: list[tuple[str, ...]] = []
    for name in sorted(binaries):
        _safe_name(name, "binary name")
        entry = binaries[name]
        if not isinstance(entry, dict):
            _fail(f"binary entry must be an object: {name}")
        for field in ("sha256", "archive_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", str(entry.get(field, ""))):
                _fail(f"binary {field} is invalid: {name}")
        path = _safe_path(str(entry.get("path", "")), "binary path")
        service = _safe_name(str(entry.get("service", "")), "binary service")
        payload = bundle / "bin" / name
        if payload.is_file():
            if _digest(payload) != entry["sha256"]:
                _fail(f"binary payload mismatch: {name}")
        elif require_binaries:
            _fail(f"required binary payload is missing: {name}")
        binary_rows.append(
            (
                name,
                str(entry["version"]),
                str(entry["archive_sha256"]),
                str(entry["sha256"]),
                path,
                service,
            )
        )

    services = standalone_plan.get("services")
    if not isinstance(services, list):
        _fail("install plan services must be an array")
    expected_services = []
    wg_interface = env.get("WG_INTERFACE", "").strip() or "wg0"
    for name in node_plan.required_services:
        unit_template, ownership = SERVICE_UNITS[name]
        expected_services.append(
            {"name": name, "unit": unit_template.format(wg_interface=wg_interface), "ownership": ownership}
        )
    if services != expected_services:
        _fail("service contract does not match canonical node capabilities")
    service_rows: list[tuple[str, ...]] = []
    for entry in services:
        name = _safe_name(str(entry["name"]), "service name")
        unit = _safe_name(str(entry["unit"]), "service unit")
        ownership = str(entry["ownership"])
        if ownership not in {"managed", "borrowed"}:
            _fail(f"unknown service ownership: {ownership}")
        service_rows.append((name, unit, ownership))

    expected_plan = build_install_plan(node_plan, artifacts, assets, binaries, env=env, platform=platform)
    expected_plan["schema_version"] = INSTALL_PLAN_SCHEMA_VERSION
    if standalone_plan != expected_plan:
        _fail(f"install plan differs from the canonical schema-{INSTALL_PLAN_SCHEMA_VERSION} compiler output")

    allowed_files = set(artifacts) | {"render-manifest.json", "install-plan.json"}
    unknown_files = sorted(path.name for path in bundle.iterdir() if path.is_file() and path.name not in allowed_files)
    unknown_dirs = sorted(path.name for path in bundle.iterdir() if path.is_dir() and path.name not in {"assets", "bin"})
    if unknown_files or unknown_dirs:
        _fail(f"unknown bundle entries: files={unknown_files}, dirs={unknown_dirs}")

    packages = standalone_plan.get("packages")
    if not isinstance(packages, list) or packages != sorted(set(packages)):
        _fail("install plan packages must be a sorted unique array")
    package_rows = [(_safe_name(str(package), "package"),) for package in packages]

    contract_dir.mkdir(parents=True, exist_ok=True)
    _write_lines(contract_dir, "artifacts.tsv", artifact_rows)
    _write_lines(contract_dir, "assets.tsv", asset_rows)
    _write_lines(contract_dir, "binaries.tsv", binary_rows)
    _write_lines(contract_dir, "services.tsv", service_rows)
    _write_lines(contract_dir, "packages.tsv", package_rows)
    with (contract_dir / "platform.json").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(platform.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
    _write_lines(
        contract_dir,
        "meta.tsv",
        [
            ("schema_version", str(MANIFEST_SCHEMA_VERSION)),
            ("release_id", _safe_name(str(manifest.get("release_id", "")), "release id")),
            ("version", _safe_name(str(manifest.get("version", "")), "version")),
            ("deployment", _safe_name(env.get("DEPLOY_NAME", ""), "deployment name")),
            ("topology", node_plan.topology),
            ("node_id", node_plan.node_id),
            ("location", node_plan.location),
            ("capabilities", ",".join(sorted(node_plan.capabilities))),
            ("platform", f"{platform.os_id}:{platform.os_version}:{platform.architecture}"),
            ("package_provider", platform.package_provider),
        ],
    )
