from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import VERSION
from .diagnostics import sha256_text
from .models import ROLE_FOREIGN, ROLE_RU
from .routing_policy import POLICY_VERSION

SING_BOX_VERSION = "1.13.12"
SING_BOX_LINUX_AMD64_ARCHIVE_SHA256 = "1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4"
SING_BOX_LINUX_AMD64_BINARY_SHA256 = "989e848637725005fdac7f1d3fa3d6eeb16992c5e0a68789da96b6b3fde06ea2"
XRAY_VERSION = "26.3.27"
XRAY_LINUX_AMD64_SHA256 = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
XRAY_LINUX_AMD64_BINARY_SHA256 = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"


def required_asset_names(role: str, *, foreign_block_ru: bool = True) -> frozenset[str]:
    if role == ROLE_RU:
        return frozenset({"geosite-ru.srs", "geoip-ru.srs"})
    if role == ROLE_FOREIGN and foreign_block_ru:
        return frozenset({"ru-ipv4.zone", "ru-ipv6.zone"})
    return frozenset()


def installed_artifact_paths(role: str) -> dict[str, str]:
    common = {
        "sing-box.json": "/etc/vpn-stack/sing-box.base.json",
        "sing-box.service": "/etc/systemd/system/sing-box.service",
        "wg0.conf": "/etc/wireguard/wg0.conf",
        "nftables.conf": "/etc/vpn-stack/nftables.conf",
        "vpn-stack-nft-apply.sh": "/usr/local/lib/vpn-stack/nft-apply.sh",
        "vpn-stack-nftables.service": "/etc/systemd/system/vpn-stack-nftables.service",
        "sshd-vpn-stack.conf": "/etc/ssh/sshd_config.d/90-vpn-stack.conf",
        "sysctl-vpn-stack.conf": "/etc/sysctl.d/90-vpn-stack.conf",
        "modules-vpn-stack.conf": "/etc/modules-load.d/90-vpn-stack.conf",
        "journald-vpn-stack.conf": "/etc/systemd/journald.conf.d/90-vpn-stack.conf",
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
    if role == ROLE_RU:
        common.update(
            {
                "xray.json": "/etc/xray/config.json",
                "vpn-stack-xray.service": "/etc/systemd/system/vpn-stack-xray.service",
                "vpn-stack-transport.service": "/etc/systemd/system/vpn-stack-transport.service",
                "admin_apply.py": "/usr/local/lib/vpn-stack/admin_apply.py",
                "admin_web.py": "/usr/local/lib/vpn-stack/admin_web.py",
                "vpn-stack-admin.service": "/etc/systemd/system/vpn-stack-admin.service",
            }
        )
    return common


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_manifest(
    env_text: str,
    role: str,
    rendered_files: dict[str, str],
    *,
    assets: dict[str, Path] | None = None,
    foreign_block_ru: bool = True,
) -> str:
    artifact_paths = installed_artifact_paths(role)
    for name, content in rendered_files.items():
        if name not in artifact_paths and name.endswith(".conf") and content.lstrip().startswith("[Interface]"):
            artifact_paths[name] = f"/etc/wireguard/{name}"
    missing_paths = sorted(set(rendered_files) - set(artifact_paths))
    if missing_paths:
        raise ValueError(f"missing installed artifact path: {', '.join(missing_paths)}")
    artifacts = {
        name: {
            "sha256": sha256_text(content),
            "install_path": artifact_paths[name],
            "required": True,
        }
        for name, content in sorted(rendered_files.items())
    }
    required_assets = required_asset_names(role, foreign_block_ru=foreign_block_ru)
    available_assets = assets or {}
    asset_entries = {
        name: {
            "sha256": sha256_path(available_assets[name]) if name in available_assets and available_assets[name].is_file() else "",
            "install_path": f"/var/lib/vpn-stack/rules/{name}",
            "required": True,
        }
        for name in sorted(required_assets)
    }
    binaries = {
        "sing-box": {
            "version": SING_BOX_VERSION,
            "archive_sha256": SING_BOX_LINUX_AMD64_ARCHIVE_SHA256,
            "sha256": SING_BOX_LINUX_AMD64_BINARY_SHA256,
            "path": "/etc/vpn-stack/current/bin/sing-box",
            "service": "sing-box.service",
        }
    }
    if role == ROLE_RU:
        binaries["xray"] = {
            "version": XRAY_VERSION,
            "archive_sha256": XRAY_LINUX_AMD64_SHA256,
            "sha256": XRAY_LINUX_AMD64_BINARY_SHA256,
            "path": "/etc/vpn-stack/current/bin/xray",
            "service": "vpn-stack-xray.service",
        }
    release_material = json.dumps(
        {
            "version": VERSION,
            "role": role,
            "env": sha256_text(env_text),
            "artifacts": artifacts,
            "assets": asset_entries,
            "binaries": binaries,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    release_id = f"{VERSION}-{sha256_text(release_material)[:12]}"
    manifest = {
        "schema_version": 2,
        "version": VERSION,
        "release_id": release_id,
        "role": role,
        "env_sha256": sha256_text(env_text),
        "config_sha256": artifacts.get("sing-box.json", {}).get("sha256", ""),
        "policy_version": POLICY_VERSION,
        "runtime": {},
        "artifacts": artifacts,
        "assets": asset_entries,
        "binaries": binaries,
    }
    return json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
