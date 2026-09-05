from __future__ import annotations

import argparse
import json
from pathlib import Path

from .common import sanitize_name, write_text
from .config import (
    apply_ru_direct_overlays,
    load_env_file,
    merge_env_with_defaults,
    merge_node_env_with_defaults,
    normalize_deployment_env,
    render_example_env_text,
)
from .install_contract import InstallContractError, validate_bundle, validate_installed_bundle
from .platforms import PlatformError, PlatformSpec, default_build_platform, install_packages, install_platform, prepare_host_platform
from .render import write_node_rendered_files
from .specs import DeploymentSpec
from .topology import CONFIG_SCHEMA_VERSION, TopologySpec, normalize_node_id


def load_runtime_env(env_file: Path, overrides: dict[str, str] | None = None) -> dict[str, str]:
    source = load_env_file(env_file)
    projected_node = bool(source.get("NODE_ID", "").strip())
    if projected_node:
        if source.get("CONFIG_SCHEMA", "").strip() != str(CONFIG_SCHEMA_VERSION):
            raise ValueError(
                f"projected node env requires CONFIG_SCHEMA={CONFIG_SCHEMA_VERSION}"
            )
        loaded = source
    else:
        loaded = normalize_deployment_env(source)
    deploy_name = loaded.get("DEPLOY_NAME", "").strip() or sanitize_name(env_file.stem)
    if projected_node:
        candidate = loaded.copy()
        if overrides:
            candidate.update(overrides)
        env = merge_node_env_with_defaults(candidate, deploy_name)
        effective = apply_ru_direct_overlays(env, env_file)
        TopologySpec.from_env(effective).plan(normalize_node_id(effective["NODE_ID"]))
        return effective

    env = merge_env_with_defaults(loaded, deploy_name)
    if overrides:
        env.update(overrides)
    return DeploymentSpec.from_env(apply_ru_direct_overlays(env, env_file)).values


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpn-install-support")
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_node = subparsers.add_parser("render-node", help="Render one canonical topology node and its install plan.")
    render_node.add_argument("--node", required=True, help="Canonical node id: gateway or exit.")
    render_node.add_argument("--env-file", type=Path, required=True)
    render_node.add_argument("--output-dir", type=Path, required=True)
    render_node.add_argument("--assets-dir", type=Path, help="Directory with already fetched rule assets.")
    render_node.add_argument("--current-platform", action="store_true", help="Compile for the detected target platform.")
    render_node.add_argument("--expected-manifest", type=Path, help="Require exact agreement with a target-bound bundle manifest.")
    render_node.add_argument("--set", dest="overrides", action="append", default=[], help="Override a detected runtime value, e.g. WAN_INTERFACE=eth1")
    render_node.set_defaults(func=cmd_render_node)

    write_example = subparsers.add_parser("write-example-env", help="Write the checked-in example env from code defaults.")
    write_example.add_argument("--output", type=Path, required=True)
    write_example.set_defaults(func=cmd_write_example_env)

    validate = subparsers.add_parser("validate-bundle", help="Validate a current bundle and emit its TSV install contract.")
    validate.add_argument("--bundle", type=Path, required=True)
    validate.add_argument("--expected-node", required=True)
    validate.add_argument("--contract-dir", type=Path, required=True)
    validate.add_argument("--external-assets", type=Path)
    validate.add_argument("--require-assets", action="store_true")
    validate.add_argument("--require-binaries", action="store_true")
    validate.add_argument("--require-current-platform", action="store_true")
    validate.set_defaults(func=cmd_validate_bundle)

    packages = subparsers.add_parser("install-packages", help="Install the validated platform package plan.")
    packages.add_argument("--contract-dir", type=Path, required=True)
    packages.set_defaults(func=cmd_install_packages)

    prepare = subparsers.add_parser("prepare-host", help="Apply validated platform prerequisites.")
    prepare.add_argument("--contract-dir", type=Path, required=True)
    prepare.add_argument("--release-dir", type=Path, required=True)
    prepare.set_defaults(func=cmd_prepare_host)

    installed = subparsers.add_parser(
        "validate-installed",
        help="Validate an installed release selected by the current compatibility window.",
    )
    installed.add_argument("--current-release", type=Path, required=True)
    installed.add_argument("--expected-node", required=True)
    installed.add_argument("--contract-dir", type=Path, required=True)
    installed.set_defaults(func=cmd_validate_installed)

    return parser


def _parse_overrides(items: list[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for item in items:
        key, _, value = item.partition("=")
        if not key or not _:
            raise SystemExit(f"Invalid override: {item}")
        overrides[key] = value
    return overrides


def _load_assets(assets_dir: Path | None) -> dict[str, Path] | None:
    return {path.name: path for path in assets_dir.glob("*") if path.is_file()} if assets_dir and assets_dir.is_dir() else None


def cmd_render_node(args: argparse.Namespace) -> int:
    overrides = _parse_overrides(args.overrides)
    env = load_runtime_env(args.env_file, overrides=overrides)
    node_id = normalize_node_id(args.node)
    TopologySpec.from_env(env).plan(node_id)
    expected = None
    expected_platform = None
    if args.expected_manifest is not None:
        expected = json.loads(args.expected_manifest.read_text(encoding="utf-8"))
        if not isinstance(expected, dict):
            raise ValueError("expected manifest must be an object")
        expected_platform = PlatformSpec.from_dict(expected.get("platform"))
    platform = install_platform() if args.current_platform else expected_platform or default_build_platform()
    write_node_rendered_files(
        env,
        node_id,
        args.output_dir,
        assets=_load_assets(args.assets_dir),
        platform=platform,
        expected_manifest=expected,
    )
    return 0


def cmd_write_example_env(args: argparse.Namespace) -> int:
    write_text(args.output, render_example_env_text())
    return 0


def cmd_validate_bundle(args: argparse.Namespace) -> int:
    try:
        validate_bundle(
            args.bundle,
            args.expected_node,
            args.contract_dir,
            external_assets=args.external_assets,
            require_assets=args.require_assets,
            require_binaries=args.require_binaries,
            expected_platform=install_platform() if getattr(args, "require_current_platform", False) else None,
        )
    except InstallContractError as exc:
        raise SystemExit(str(exc)) from None
    return 0


def cmd_install_packages(args: argparse.Namespace) -> int:
    platform_path = args.contract_dir / "platform.json"
    packages_path = args.contract_dir / "packages.tsv"
    if not platform_path.is_file() or not packages_path.is_file():
        raise SystemExit("validated contract has no platform or package plan")
    platform = PlatformSpec.from_dict(json.loads(platform_path.read_text(encoding="utf-8")))
    packages = [line.strip() for line in packages_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    install_packages(platform, packages)
    return 0


def cmd_prepare_host(args: argparse.Namespace) -> int:
    platform_path = args.contract_dir / "platform.json"
    if not platform_path.is_file():
        raise SystemExit("validated contract has no platform descriptor")
    platform = PlatformSpec.from_dict(json.loads(platform_path.read_text(encoding="utf-8")))
    prepare_host_platform(platform, args.release_dir)
    return 0


def cmd_validate_installed(args: argparse.Namespace) -> int:
    try:
        validate_installed_bundle(
            args.current_release,
            normalize_node_id(args.expected_node),
            args.contract_dir,
        )
    except InstallContractError as exc:
        raise SystemExit(str(exc)) from None
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PlatformError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    raise SystemExit(main())
