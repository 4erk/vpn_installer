from __future__ import annotations

import re
from pathlib import Path

from .install_contract import (
    InstallContractError,
    _digest,
    _parse_env,
    _read_object,
    _safe_name,
    _safe_path,
    _write_lines,
)
from .topology import LEGACY_ROLE_FOREIGN, LEGACY_ROLE_RU, NODE_EXIT, NODE_GATEWAY


REMOVE_IN_VERSION = "0.20.1"

_COMMON_ARTIFACT_PATHS = {
    "sing-box.json": "/etc/vpn-stack/sing-box.base.json",
    "sing-box.service": "/etc/systemd/system/sing-box.service",
    "nftables.conf": "/etc/vpn-stack/nftables.conf",
    "vpn-stack-nft-apply.sh": "/usr/local/lib/vpn-stack/nft-apply.sh",
    "vpn-stack-nftables.service": "/etc/systemd/system/vpn-stack-nftables.service",
    "sshd-vpn-stack.conf": "/etc/ssh/sshd_config.d/90-vpn-stack.conf",
    "sysctl-vpn-stack.conf": "/etc/sysctl.d/90-vpn-stack.conf",
    "modules-vpn-stack.conf": "/etc/modules-load.d/90-vpn-stack.conf",
    "apt-vpn-stack-unattended.conf": "/etc/apt/apt.conf.d/90-vpn-stack-unattended",
    "resolved-vpn-stack.conf": "/etc/systemd/resolved.conf.d/90-vpn-stack.conf",
    "vpn-stack-agent.py": "/usr/local/lib/vpn-stack/vpn-stack-agent.py",
    "diagnostics.py": "/usr/local/lib/vpn-stack/diagnostics.py",
    "log_classifier.py": "/usr/local/lib/vpn-stack/log_classifier.py",
    "interserver_transport.py": "/usr/local/lib/vpn-stack/interserver_transport.py",
    "network_profile.py": "/usr/local/lib/vpn-stack/network_profile.py",
    "vpn-stack-health.service": "/etc/systemd/system/vpn-stack-health.service",
    "vpn-stack-health.timer": "/etc/systemd/system/vpn-stack-health.timer",
}
_OPTIONAL_ARTIFACT_PATHS = {
    "journald-vpn-stack.conf": "/etc/systemd/journald.conf.d/90-vpn-stack.conf",
}
_GATEWAY_ARTIFACT_PATHS = {
    "xray.json": "/etc/xray/config.json",
    "vpn-stack-xray.service": "/etc/systemd/system/vpn-stack-xray.service",
    "vpn-stack-transport.service": "/etc/systemd/system/vpn-stack-transport.service",
    "admin_apply.py": "/usr/local/lib/vpn-stack/admin_apply.py",
    "admin_web.py": "/usr/local/lib/vpn-stack/admin_web.py",
    "vpn-stack-admin.service": "/etc/systemd/system/vpn-stack-admin.service",
}
_ROLE_NODE = {LEGACY_ROLE_RU: NODE_GATEWAY, LEGACY_ROLE_FOREIGN: NODE_EXIT}
_ROLE_LOCATION = {LEGACY_ROLE_RU: "ru", LEGACY_ROLE_FOREIGN: "foreign"}
_ROLE_ASSETS = {
    LEGACY_ROLE_RU: frozenset({"geoip-ru.srs", "geosite-ru.srs"}),
    LEGACY_ROLE_FOREIGN: frozenset({"ru-ipv4.zone", "ru-ipv6.zone"}),
}
_ROLE_BINARIES = {
    LEGACY_ROLE_RU: {"sing-box": "sing-box.service", "xray": "vpn-stack-xray.service"},
    LEGACY_ROLE_FOREIGN: {"sing-box": "sing-box.service"},
}


def _fail(message: str) -> None:
    raise InstallContractError(f"schema-2 migration rejected: {message}")


def _system_path(system_root: Path, path: str) -> Path:
    return Path(path) if system_root == Path("/") else system_root / path.lstrip("/")


def _validate_digest(value: object, label: str) -> str:
    digest = str(value or "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        _fail(f"invalid {label} digest")
    return digest


def _validate_live_payload(system_root: Path, install_path: str, payload: Path, digest: str) -> None:
    live_path = _system_path(system_root, install_path)
    if live_path.is_symlink():
        try:
            if live_path.resolve(strict=True) != payload.resolve(strict=True):
                _fail(f"live symlink does not resolve to the owned payload: {install_path}")
        except OSError as exc:
            _fail(f"cannot resolve live symlink {install_path}: {exc}")
        return
    if not live_path.is_file():
        _fail(f"owned live path is missing: {install_path}")
    if _digest(live_path) != digest:
        _fail(f"owned live path was modified: {install_path}")


def _artifact_contract(
    current_release: Path,
    manifest: dict[str, object],
    role: str,
    system_root: Path,
) -> tuple[list[tuple[str, ...]], str]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        _fail("artifacts must be an object")
    expected = dict(_COMMON_ARTIFACT_PATHS)
    if role == LEGACY_ROLE_RU:
        expected.update(_GATEWAY_ARTIFACT_PATHS)
    missing = sorted(set(expected) - set(artifacts))
    allowed = set(expected) | set(_OPTIONAL_ARTIFACT_PATHS)
    unknown = sorted(
        name
        for name, entry in artifacts.items()
        if name not in allowed
        and not (
            isinstance(name, str)
            and name.endswith(".conf")
            and isinstance(entry, dict)
            and entry.get("install_path") == f"/etc/wireguard/{name}"
        )
    )
    if missing or unknown:
        _fail(f"artifact set differs from the known schema-2 contract; missing={missing}, unknown={unknown}")
    wireguard_names = [
        name
        for name, entry in artifacts.items()
        if isinstance(name, str)
        and isinstance(entry, dict)
        and entry.get("install_path") == f"/etc/wireguard/{name}"
    ]
    if len(wireguard_names) != 1:
        _fail("schema-2 contract must own exactly one WireGuard configuration")

    rows: list[tuple[str, ...]] = []
    for name in sorted(artifacts):
        entry = artifacts[name]
        if not isinstance(name, str) or not isinstance(entry, dict):
            _fail(f"invalid artifact entry: {name!r}")
        if set(entry) != {"sha256", "install_path", "required"} or entry.get("required") is not True:
            _fail(f"invalid artifact fields: {name}")
        if name in expected:
            manifest_path = expected[name]
        elif name in _OPTIONAL_ARTIFACT_PATHS:
            manifest_path = _OPTIONAL_ARTIFACT_PATHS[name]
        else:
            manifest_path = f"/etc/wireguard/{name}"
        if entry.get("install_path") != manifest_path:
            _fail(f"unexpected artifact path for {name}: {entry.get('install_path')!r}")
        digest = _validate_digest(entry.get("sha256"), name)
        payload = current_release / name
        if not payload.is_file() or _digest(payload) != digest:
            _fail(f"release payload differs from manifest: {name}")
        live_paths = [manifest_path]
        if role == LEGACY_ROLE_FOREIGN and name == "sing-box.json":
            # Schema 2 linked the same payload at both paths but recorded only the
            # gateway-oriented path. Own both after verifying both, so schema 3
            # can retain the real exit config and retire the stale base link.
            live_paths.append("/etc/sing-box/config.json")
        for live_path in live_paths:
            _safe_path(live_path, "legacy artifact path")
            _validate_live_payload(system_root, live_path, payload, digest)
            rows.append((name, live_path, "managed", digest, "legacy-schema2"))
    return rows, wireguard_names[0][:-5]


def _asset_contract(
    current_release: Path,
    manifest: dict[str, object],
    role: str,
    system_root: Path,
) -> list[tuple[str, ...]]:
    assets = manifest.get("assets")
    if not isinstance(assets, dict):
        _fail("assets must be an object")
    names = frozenset(assets)
    allowed = _ROLE_ASSETS[role]
    if role == LEGACY_ROLE_RU and names != allowed:
        _fail(f"gateway assets differ from the known schema-2 contract: {sorted(names)}")
    if role == LEGACY_ROLE_FOREIGN and names not in {frozenset(), allowed}:
        _fail(f"exit assets differ from the known schema-2 contract: {sorted(names)}")
    rows: list[tuple[str, ...]] = []
    for name in sorted(assets):
        entry = assets[name]
        install_path = f"/var/lib/vpn-stack/rules/{name}"
        if (
            not isinstance(entry, dict)
            or set(entry) != {"sha256", "install_path", "required"}
            or entry.get("required") is not True
            or entry.get("install_path") != install_path
        ):
            _fail(f"invalid asset contract: {name}")
        digest = _validate_digest(entry.get("sha256"), name)
        payload = current_release / "assets" / name
        if not payload.is_file() or _digest(payload) != digest:
            _fail(f"release asset differs from manifest: {name}")
        _validate_live_payload(system_root, install_path, payload, digest)
        rows.append((name, install_path, "managed", digest))
    return rows


def _binary_contract(current_release: Path, manifest: dict[str, object], role: str) -> list[tuple[str, ...]]:
    binaries = manifest.get("binaries")
    expected = _ROLE_BINARIES[role]
    if not isinstance(binaries, dict) or set(binaries) != set(expected):
        _fail(f"binary set differs from the known schema-2 contract: {sorted(binaries) if isinstance(binaries, dict) else []}")
    rows: list[tuple[str, ...]] = []
    for name in sorted(binaries):
        entry = binaries[name]
        if not isinstance(entry, dict) or set(entry) != {"version", "archive_sha256", "sha256", "path", "service"}:
            _fail(f"invalid binary contract: {name}")
        version = _safe_name(str(entry.get("version", "")), "legacy binary version")
        archive_digest = _validate_digest(entry.get("archive_sha256"), f"{name} archive")
        digest = _validate_digest(entry.get("sha256"), name)
        path = f"/etc/vpn-stack/current/bin/{name}"
        if entry.get("path") != path or entry.get("service") != expected[name]:
            _fail(f"unexpected binary path or service: {name}")
        payload = current_release / "bin" / name
        if not payload.is_file() or _digest(payload) != digest:
            _fail(f"release binary differs from manifest: {name}")
        rows.append((name, version, archive_digest, digest, path, expected[name]))
    return rows


def adapt_schema2_install(
    current_release: Path,
    deployment_env: Path,
    contract_dir: Path,
    *,
    system_root: Path = Path("/"),
) -> None:
    """Validate one known schema-2 install and emit ownership for one schema-3 migration."""

    current_release = Path(current_release)
    deployment_env = Path(deployment_env)
    contract_dir = Path(contract_dir)
    system_root = Path(system_root)
    manifest = _read_object(current_release / "render-manifest.json", "legacy render-manifest.json")
    if manifest.get("schema_version") != 2:
        _fail(f"unsupported manifest schema: {manifest.get('schema_version')!r}")
    role = str(manifest.get("role", ""))
    if role not in _ROLE_NODE:
        _fail(f"unsupported role: {role!r}")
    version = str(manifest.get("version", ""))
    if not re.fullmatch(r"0\.(?:18|19)\.\d+", version):
        _fail(f"unsupported release version: {version!r}")
    release_id = str(manifest.get("release_id", ""))
    if not re.fullmatch(re.escape(version) + r"-[0-9a-f]{12}", release_id):
        _fail(f"invalid release id: {release_id!r}")

    env_digest = _validate_digest(manifest.get("env_sha256"), "deployment env")
    if not deployment_env.is_file() or _digest(deployment_env) != env_digest:
        _fail("installed deployment.env differs from the schema-2 manifest")
    env = _parse_env(deployment_env)
    deployment = _safe_name(env.get("DEPLOY_NAME", ""), "deployment name")

    artifact_rows, wg_interface = _artifact_contract(current_release, manifest, role, system_root)
    deployment_path = "/etc/vpn-stack/deployment.env"
    _validate_live_payload(system_root, deployment_path, deployment_env, env_digest)
    artifact_rows.append(("node.env", deployment_path, "managed", env_digest, "legacy-schema2"))
    asset_rows = _asset_contract(current_release, manifest, role, system_root)
    binary_rows = _binary_contract(current_release, manifest, role)

    service_rows = [
        ("sing-box", "sing-box.service", "managed"),
        ("nftables", "vpn-stack-nftables.service", "managed"),
        ("resolver", "systemd-resolved.service", "borrowed"),
        ("health_timer", "vpn-stack-health.timer", "managed"),
        ("wireguard", f"wg-quick@{wg_interface}.service", "managed"),
    ]
    if role == LEGACY_ROLE_RU:
        service_rows.extend(
            [
                ("xray", "vpn-stack-xray.service", "managed"),
                ("admin", "vpn-stack-admin.service", "managed"),
                ("transport", "vpn-stack-transport.service", "managed"),
            ]
        )

    contract_dir.mkdir(parents=True, exist_ok=True)
    _write_lines(contract_dir, "artifacts.tsv", sorted(artifact_rows))
    _write_lines(contract_dir, "assets.tsv", asset_rows)
    _write_lines(contract_dir, "binaries.tsv", binary_rows)
    _write_lines(contract_dir, "services.tsv", service_rows)
    _write_lines(contract_dir, "packages.tsv", [])
    _write_lines(
        contract_dir,
        "meta.tsv",
        [
            ("schema_version", "2"),
            ("release_id", release_id),
            ("version", version),
            ("deployment", deployment),
            ("topology", "dual"),
            ("node_id", _ROLE_NODE[role]),
            ("location", _ROLE_LOCATION[role]),
            ("compatibility_adapter", "schema2-install-contract"),
            ("remove_in", REMOVE_IN_VERSION),
        ],
    )
