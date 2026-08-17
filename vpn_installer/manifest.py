from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from . import VERSION
from .common import env_line, parse_env_value
from .compatibility import CompatibilityWindow
from .diagnostics import sha256_text
from .routing_policy import POLICY_VERSION
from .topology import (
    CAP_INTERSERVER_CLIENT,
    CAP_INTERSERVER_SERVER,
    CAP_NAT_EXIT,
    CAP_PUBLIC_FRONT,
    CAP_RU_SPLIT_ROUTING,
    CAP_WEB_ADMIN,
    CONFIG_SCHEMA_VERSION,
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    NodePlan,
    NodeSpec,
    TopologySpec,
    normalize_node_id,
)

MANIFEST_SCHEMA_VERSION = 4
INSTALL_PLAN_SCHEMA_VERSION = 4

SING_BOX_VERSION = "1.13.12"
SING_BOX_LINUX_AMD64_ARCHIVE_SHA256 = "1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4"
SING_BOX_LINUX_AMD64_BINARY_SHA256 = "989e848637725005fdac7f1d3fa3d6eeb16992c5e0a68789da96b6b3fde06ea2"
XRAY_VERSION = "26.3.27"
XRAY_LINUX_AMD64_SHA256 = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
XRAY_LINUX_AMD64_BINARY_SHA256 = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"

BASE_PACKAGES = (
    "ca-certificates",
    "curl",
    "e2fsprogs",
    "iproute2",
    "kmod",
    "nftables",
    "python3",
    "systemd-resolved",
    "tar",
    "unattended-upgrades",
    "util-linux",
)
PUBLIC_FRONT_PACKAGES = ("unzip",)
INTERSERVER_PACKAGES = ("iperf3", "iputils-ping", "wireguard", "wireguard-tools")

COMMON_NODE_ENV_KEYS = (
    "SSH_PORT",
    "SSH_LOGIN_GRACE_TIME",
    "SSH_MAX_AUTH_TRIES",
    "SSH_MAX_STARTUPS",
    "SSH_PER_SOURCE_MAX_STARTUPS",
    "SSH_PER_SOURCE_NETBLOCK_SIZE",
    "SING_BOX_LOG_LEVEL",
    "JOURNAL_LIMIT_ENABLED",
    "JOURNAL_SYSTEM_MAX_USE",
    "JOURNAL_MAX_RETENTION_SEC",
)
EXIT_NODE_ENV_KEYS = ("WAN_INTERFACE",)
GATEWAY_NODE_ENV_KEYS = (
    "CLIENT_UUID",
    "CLIENT_FLOW",
    "RU_LISTEN_PORT",
    "RU_ROUTER_LISTEN_PORT",
    "RU_REALITY_SERVER_NAME",
    "RU_REALITY_PRIVATE_KEY",
    "RU_REALITY_SHORT_ID",
    "RU_REALITY_ACCEPT_EMPTY_SHORT_ID",
    "RU_SNIFF_TIMEOUT",
    "PUBLIC_HY2_CERTIFICATE_B64",
    "PUBLIC_HY2_PRIVATE_KEY_B64",
    "RU_BLOCK_IP_CIDR",
)
WEB_ADMIN_ENV_KEYS = (
    "ADMIN_WEB_PORT",
    "ADMIN_WEB_USERNAME",
    "ADMIN_WEB_PASSWORD",
)
SPLIT_GATEWAY_ENV_KEYS = (
    "RULESET_DIR",
    "RU_FORCE_DIRECT_DOMAIN",
    "RU_FORCE_DIRECT_DOMAIN_SUFFIX",
    "RU_FORCE_DIRECT_IP_CIDR",
)
INTERSERVER_COMMON_ENV_KEYS = (
    "WG_INTERFACE",
    "WG_PORT",
    "WG_MTU",
    "WG_ROUTE_TABLE",
    "APP_ROUTE_MARK",
    "WG_TUNNEL_FWMARK",
    "WG_RU_ADDRESS",
    "WG_FOREIGN_ADDRESS",
    "WG_RU_ADDRESS_V6",
    "WG_FOREIGN_ADDRESS_V6",
    "WG_IPV6_PREFIX",
    "WG_PRESHARED_KEY",
)
INTERSERVER_GATEWAY_ENV_KEYS = (
    "WG_RU_PRIVATE_KEY",
    "WG_FOREIGN_PUBLIC_KEY",
    "INTERSERVER_HY2_PUBLIC_KEY_SHA256",
)
INTERSERVER_EXIT_ENV_KEYS = (
    "WG_FOREIGN_PRIVATE_KEY",
    "WG_RU_PUBLIC_KEY",
    "INTERSERVER_HY2_CERTIFICATE_B64",
    "INTERSERVER_HY2_PRIVATE_KEY_B64",
    "INTERSERVER_HY2_PUBLIC_KEY_SHA256",
    "FOREIGN_BLOCK_RU",
)


@dataclass(frozen=True)
class ArtifactSpec:
    install_path: str
    capability: str
    ownership: str = "managed"


BASE_ARTIFACTS = {
    "sing-box.service": ArtifactSpec("/etc/systemd/system/sing-box.service", "base"),
    "nftables.conf": ArtifactSpec("/etc/vpn-stack/nftables.conf", "base"),
    "vpn-stack-nft-apply.sh": ArtifactSpec("/usr/local/lib/vpn-stack/nft-apply.sh", "base"),
    "vpn-stack-nftables.service": ArtifactSpec("/etc/systemd/system/vpn-stack-nftables.service", "base"),
    "sshd-vpn-stack.conf": ArtifactSpec("/etc/ssh/sshd_config.d/90-vpn-stack.conf", "base"),
    "sysctl-vpn-stack.conf": ArtifactSpec("/etc/sysctl.d/90-vpn-stack.conf", "base"),
    "modules-vpn-stack.conf": ArtifactSpec("/etc/modules-load.d/90-vpn-stack.conf", "base"),
    "journald-vpn-stack.conf": ArtifactSpec("/etc/systemd/journald.conf.d/90-vpn-stack.conf", "base"),
    "apt-vpn-stack-unattended.conf": ArtifactSpec("/etc/apt/apt.conf.d/90-vpn-stack-unattended", "base"),
    "resolved-vpn-stack.conf": ArtifactSpec("/etc/systemd/resolved.conf.d/90-vpn-stack.conf", "base"),
    "vpn-stack-agent.py": ArtifactSpec("/usr/local/lib/vpn-stack/vpn-stack-agent.py", "base"),
    "diagnostics.py": ArtifactSpec("/usr/local/lib/vpn-stack/diagnostics.py", "base"),
    "log_classifier.py": ArtifactSpec("/usr/local/lib/vpn-stack/log_classifier.py", "base"),
    "network_profile.py": ArtifactSpec("/usr/local/lib/vpn-stack/network_profile.py", "base"),
    "release_integrity.py": ArtifactSpec("/usr/local/lib/vpn-stack/release_integrity.py", "base"),
    "vpn-stack-health.service": ArtifactSpec("/etc/systemd/system/vpn-stack-health.service", "base"),
    "vpn-stack-health.timer": ArtifactSpec("/etc/systemd/system/vpn-stack-health.timer", "base"),
    "node.env": ArtifactSpec("/etc/vpn-stack/deployment.env", "base"),
}
GATEWAY_ARTIFACTS = {
    "sing-box.json": ArtifactSpec("/etc/vpn-stack/sing-box.base.json", "router"),
    "admin_apply.py": ArtifactSpec("/usr/local/lib/vpn-stack/admin_apply.py", "router"),
}
EXIT_ARTIFACTS = {
    "sing-box.json": ArtifactSpec("/etc/sing-box/config.json", "nat-exit"),
}
PUBLIC_FRONT_ARTIFACTS = {
    "xray.json": ArtifactSpec("/etc/xray/config.json", CAP_PUBLIC_FRONT),
    "vpn-stack-xray.service": ArtifactSpec("/etc/systemd/system/vpn-stack-xray.service", CAP_PUBLIC_FRONT),
}
WEB_ADMIN_ARTIFACTS = {
    "admin_web.py": ArtifactSpec("/usr/local/lib/vpn-stack/admin_web.py", CAP_WEB_ADMIN),
    "vpn-stack-admin.service": ArtifactSpec("/etc/systemd/system/vpn-stack-admin.service", CAP_WEB_ADMIN),
}
INTERSERVER_ARTIFACTS = {
    "interserver_transport.py": ArtifactSpec("/usr/local/lib/vpn-stack/interserver_transport.py", "interserver"),
    "topology.py": ArtifactSpec("/usr/local/lib/vpn-stack/topology.py", "interserver"),
}
INTERSERVER_CLIENT_ARTIFACTS = {
    "vpn-stack-transport.service": ArtifactSpec(
        "/etc/systemd/system/vpn-stack-transport.service",
        CAP_INTERSERVER_CLIENT,
    ),
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


def _parse_env_text(env_text: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw_line in env_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        env[key.strip()] = parse_env_value(raw_value)
    return env


def _default_dual_topology() -> TopologySpec:
    return TopologySpec(
        mode=TOPOLOGY_DUAL,
        gateway=NodeSpec(NODE_GATEWAY, LOCATION_RU, ""),
        exit=NodeSpec(NODE_EXIT, LOCATION_FOREIGN, ""),
    )


def resolve_node_plan(node: str | NodePlan, env: Mapping[str, str] | None = None) -> NodePlan:
    if isinstance(node, NodePlan):
        return node
    node_id = normalize_node_id(node)
    topology = TopologySpec.from_env(env, require_addresses=False) if env is not None else _default_dual_topology()
    return topology.plan(node_id)


def required_asset_names(node: str | NodePlan, *, foreign_block_ru: bool = True, env: Mapping[str, str] | None = None) -> frozenset[str]:
    plan = resolve_node_plan(node, env)
    if CAP_RU_SPLIT_ROUTING in plan.capabilities:
        return frozenset({"geosite-ru.srs", "geoip-ru.srs"})
    if CAP_NAT_EXIT in plan.capabilities and foreign_block_ru:
        return frozenset({"ru-ipv4.zone", "ru-ipv6.zone"})
    return frozenset()


def artifact_specs(node: str | NodePlan, *, env: Mapping[str, str] | None = None) -> dict[str, ArtifactSpec]:
    plan = resolve_node_plan(node, env)
    specs = dict(BASE_ARTIFACTS)
    if env is not None and str(env.get("JOURNAL_LIMIT_ENABLED", "1")).strip().lower() in {"0", "false", "no", "off"}:
        specs.pop("journald-vpn-stack.conf", None)
    specs.update(GATEWAY_ARTIFACTS if plan.node_id == NODE_GATEWAY else EXIT_ARTIFACTS)
    if CAP_PUBLIC_FRONT in plan.capabilities:
        specs.update(PUBLIC_FRONT_ARTIFACTS)
    if CAP_WEB_ADMIN in plan.capabilities:
        specs.update(WEB_ADMIN_ARTIFACTS)
    if plan.has_interserver:
        specs.update(INTERSERVER_ARTIFACTS)
        wg_interface = str((env or {}).get("WG_INTERFACE", "")).strip() or "wg0"
        specs[f"{wg_interface}.conf"] = ArtifactSpec(f"/etc/wireguard/{wg_interface}.conf", "interserver")
    if CAP_INTERSERVER_CLIENT in plan.capabilities:
        specs.update(INTERSERVER_CLIENT_ARTIFACTS)
    return specs


def installed_artifact_paths(node: str | NodePlan, *, env: Mapping[str, str] | None = None) -> dict[str, str]:
    return {name: spec.install_path for name, spec in artifact_specs(node, env=env).items()}


def _is_wireguard_config(name: str, content: str) -> bool:
    return name.endswith(".conf") and content.lstrip().startswith("[Interface]")


def _known_artifact(name: str, content: str) -> bool:
    if name in {
        *BASE_ARTIFACTS,
        *GATEWAY_ARTIFACTS,
        *EXIT_ARTIFACTS,
        *PUBLIC_FRONT_ARTIFACTS,
        *WEB_ADMIN_ARTIFACTS,
        *INTERSERVER_ARTIFACTS,
        *INTERSERVER_CLIENT_ARTIFACTS,
    }:
        return True
    return _is_wireguard_config(name, content)


def project_node_env(env: Mapping[str, str], node: str | NodePlan) -> dict[str, str]:
    plan = resolve_node_plan(node, env)
    topology = TopologySpec.from_env(env, require_addresses=False)
    projected: dict[str, str] = {
        "CONFIG_SCHEMA": str(env.get("CONFIG_SCHEMA", CONFIG_SCHEMA_VERSION) or CONFIG_SCHEMA_VERSION),
        "DEPLOY_NAME": str(env.get("DEPLOY_NAME", "")),
        "TOPOLOGY": plan.topology,
        "GATEWAY_LOCATION": topology.gateway.location,
        "GATEWAY_PUBLIC_IP": topology.gateway.public_ip,
        "NODE_ID": plan.node_id,
        "NODE_LOCATION": plan.location,
        "NODE_PUBLIC_IP": plan.public_ip,
    }
    if topology.exit is not None:
        projected["EXIT_PUBLIC_IP"] = topology.exit.public_ip

    keys = list(COMMON_NODE_ENV_KEYS)
    if plan.node_id == NODE_GATEWAY:
        keys.extend(GATEWAY_NODE_ENV_KEYS)
    else:
        keys.extend(EXIT_NODE_ENV_KEYS)
    if CAP_WEB_ADMIN in plan.capabilities:
        keys.extend(WEB_ADMIN_ENV_KEYS)
    if CAP_RU_SPLIT_ROUTING in plan.capabilities:
        keys.extend(SPLIT_GATEWAY_ENV_KEYS)
    if plan.has_interserver:
        keys.extend(INTERSERVER_COMMON_ENV_KEYS)
    if CAP_INTERSERVER_CLIENT in plan.capabilities:
        keys.extend(INTERSERVER_GATEWAY_ENV_KEYS)
    if CAP_INTERSERVER_SERVER in plan.capabilities:
        keys.extend(INTERSERVER_EXIT_ENV_KEYS)

    for key in keys:
        value = str(env.get(key, ""))
        if value:
            projected[key] = value
    return projected


def render_node_env_text(env: Mapping[str, str], node: str | NodePlan) -> str:
    projected = project_node_env(env, node)
    canonical_order = (
        "CONFIG_SCHEMA",
        "DEPLOY_NAME",
        "TOPOLOGY",
        "GATEWAY_LOCATION",
        "GATEWAY_PUBLIC_IP",
        "EXIT_PUBLIC_IP",
        "NODE_ID",
        "NODE_LOCATION",
        "NODE_PUBLIC_IP",
    )
    ordered = [key for key in canonical_order if key in projected]
    ordered.extend(sorted(set(projected) - set(ordered)))
    return "\n".join(env_line(key, projected[key]) for key in ordered) + "\n"


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _node_descriptor(plan: NodePlan) -> dict[str, object]:
    return {
        "id": plan.node_id,
        "location": plan.location,
        "public_ip": plan.public_ip,
        "capabilities": sorted(plan.capabilities),
        "required_services": list(plan.required_services),
    }


def _canonical_plan_fields(plan: NodePlan) -> dict[str, object]:
    return {
        "topology": plan.topology,
        "node_id": plan.node_id,
        "location": plan.location,
        "capabilities": sorted(plan.capabilities),
        "required_services": list(plan.required_services),
    }


def _binary_entries(plan: NodePlan) -> dict[str, dict[str, str]]:
    binaries = {
        "sing-box": {
            "version": SING_BOX_VERSION,
            "archive_sha256": SING_BOX_LINUX_AMD64_ARCHIVE_SHA256,
            "sha256": SING_BOX_LINUX_AMD64_BINARY_SHA256,
            "path": "/etc/vpn-stack/current/bin/sing-box",
            "service": "sing-box.service",
        }
    }
    if plan.requires_xray:
        binaries["xray"] = {
            "version": XRAY_VERSION,
            "archive_sha256": XRAY_LINUX_AMD64_SHA256,
            "sha256": XRAY_LINUX_AMD64_BINARY_SHA256,
            "path": "/etc/vpn-stack/current/bin/xray",
            "service": "vpn-stack-xray.service",
        }
    return binaries


def build_install_plan(
    plan: NodePlan,
    artifacts: Mapping[str, Mapping[str, object]],
    assets: Mapping[str, Mapping[str, object]],
    binaries: Mapping[str, Mapping[str, str]],
    *,
    env: Mapping[str, str],
) -> dict[str, object]:
    packages = set(BASE_PACKAGES)
    package_sets: dict[str, list[str]] = {"base": list(BASE_PACKAGES)}
    if plan.requires_xray:
        packages.update(PUBLIC_FRONT_PACKAGES)
        package_sets[CAP_PUBLIC_FRONT] = list(PUBLIC_FRONT_PACKAGES)
    if plan.has_interserver:
        packages.update(INTERSERVER_PACKAGES)
        package_sets["interserver"] = list(INTERSERVER_PACKAGES)

    wg_interface = str(env.get("WG_INTERFACE", "")).strip() or "wg0"
    services = []
    for name in plan.required_services:
        unit_template, ownership = SERVICE_UNITS[name]
        services.append(
            {
                "name": name,
                "unit": unit_template.format(wg_interface=wg_interface),
                "ownership": ownership,
            }
        )
    return {
        "schema_version": INSTALL_PLAN_SCHEMA_VERSION,
        **_canonical_plan_fields(plan),
        "node": _node_descriptor(plan),
        "services": services,
        "packages": sorted(packages),
        "package_sets": package_sets,
        "artifacts": {name: dict(entry) for name, entry in sorted(artifacts.items())},
        "assets": {name: dict(entry) for name, entry in sorted(assets.items())},
        "binaries": {name: dict(entry) for name, entry in sorted(binaries.items())},
    }


def render_manifest(
    env_text: str,
    node: str | NodePlan,
    rendered_files: dict[str, str],
    *,
    assets: dict[str, Path] | None = None,
    foreign_block_ru: bool = True,
) -> str:
    env = _parse_env_text(env_text)
    plan = resolve_node_plan(node, env)
    specs = artifact_specs(plan, env=env)
    if plan.requires_wireguard:
        for name, content in rendered_files.items():
            if name not in specs and _is_wireguard_config(name, content):
                specs[name] = ArtifactSpec(f"/etc/wireguard/{name}", "interserver")
    unknown = sorted(name for name, content in rendered_files.items() if name not in specs and not _known_artifact(name, content))
    if unknown:
        raise ValueError(f"missing installed artifact path: {', '.join(unknown)}")
    artifacts = {
        name: {
            "sha256": sha256_text(content),
            "install_path": specs[name].install_path,
            "required": True,
            "capability": specs[name].capability,
            "ownership": specs[name].ownership,
        }
        for name, content in sorted(rendered_files.items())
        if name in specs
    }
    required_assets = required_asset_names(plan, foreign_block_ru=foreign_block_ru)
    available_assets = assets or {}
    asset_entries = {
        name: {
            "sha256": sha256_path(available_assets[name]) if name in available_assets and available_assets[name].is_file() else "",
            "install_path": f"/var/lib/vpn-stack/rules/{name}",
            "required": True,
            "ownership": "managed",
        }
        for name in sorted(required_assets)
    }
    binaries = _binary_entries(plan)
    node_env_text = render_node_env_text(env, plan)
    node_env_sha256 = sha256_text(node_env_text)
    install_plan = build_install_plan(plan, artifacts, asset_entries, binaries, env=env)
    install_plan_text = json.dumps(install_plan, sort_keys=True, separators=(",", ":"))
    release_material = json.dumps(
        {
            "version": VERSION,
            "topology": plan.topology,
            "node": _node_descriptor(plan),
            "node_env": node_env_sha256,
            "artifacts": artifacts,
            "assets": asset_entries,
            "binaries": binaries,
            "install_plan": sha256_text(install_plan_text),
            "update_compatibility": CompatibilityWindow.current().to_manifest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    release_id = f"{VERSION}-{sha256_text(release_material)[:12]}"
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "version": VERSION,
        "release_id": release_id,
        **_canonical_plan_fields(plan),
        "node": _node_descriptor(plan),
        "update_compatibility": CompatibilityWindow.current().to_manifest(),
        "env_sha256": sha256_text(env_text),
        "node_env_sha256": node_env_sha256,
        "config_sha256": artifacts.get("sing-box.json", {}).get("sha256", ""),
        "policy_version": POLICY_VERSION,
        "runtime": {},
        "artifacts": artifacts,
        "assets": asset_entries,
        "binaries": binaries,
        "install_plan_sha256": sha256_text(install_plan_text),
        "install_plan": install_plan,
    }
    return json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def finalize_node_files(
    env: Mapping[str, str],
    node: str | NodePlan,
    rendered_files: Mapping[str, str],
    *,
    assets: Mapping[str, Path] | None = None,
    foreign_block_ru: bool | None = None,
) -> dict[str, str]:
    """Attach canonical node control files after the renderer composes artifacts."""

    plan = resolve_node_plan(node, env)
    files = {
        name: content
        for name, content in rendered_files.items()
        if name not in {"node.env", "render-manifest.json", "install-plan.json"}
    }
    specs = artifact_specs(plan, env=env)
    incompatible = sorted(name for name in files if name not in specs)
    if incompatible:
        raise ValueError(f"artifacts are not supported by node capabilities: {', '.join(incompatible)}")

    node_env_text = render_node_env_text(env, plan)
    files["node.env"] = node_env_text
    manifest_text = render_manifest(
        node_env_text,
        plan,
        files,
        assets=dict(assets or {}),
        foreign_block_ru=(
            str(env.get("FOREIGN_BLOCK_RU", "0")).strip() == "1"
            if foreign_block_ru is None
            else foreign_block_ru
        ),
    )
    manifest = json.loads(manifest_text)
    files["render-manifest.json"] = manifest_text
    files["install-plan.json"] = json.dumps(manifest["install_plan"], ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return files
