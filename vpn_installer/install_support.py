from __future__ import annotations

import argparse
from pathlib import Path

from .common import sanitize_name, write_text
from .config import (
    apply_ru_direct_overlays,
    load_env_file,
    merge_env_with_defaults,
    merge_node_env_with_defaults,
    render_example_env_text,
)
from .install_contract import InstallContractError, validate_bundle
from .legacy_install_contract import adapt_schema2_install
from .models import ROLE_FOREIGN, ROLE_RU
from .migration import migrate_env
from .render import write_node_rendered_files, write_role_rendered_files
from .specs import DeploymentSpec
from .topology import CONFIG_SCHEMA_VERSION, TopologySpec, legacy_role_for_node, normalize_node_id


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
        loaded = migrate_env(source).env
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

    render_role = subparsers.add_parser("render-role", help="Render one role into a flat directory.")
    render_role.add_argument("--role", choices=[ROLE_RU, ROLE_FOREIGN], required=True)
    render_role.add_argument("--env-file", type=Path, required=True)
    render_role.add_argument("--output-dir", type=Path, required=True)
    render_role.add_argument("--assets-dir", type=Path, help="Directory with already fetched rule assets.")
    render_role.add_argument("--set", dest="overrides", action="append", default=[], help="Override env values for this render, e.g. WAN_INTERFACE=eth1")
    render_role.set_defaults(func=cmd_render_role)

    render_node = subparsers.add_parser("render-node", help="Render one canonical topology node and its install plan.")
    render_node.add_argument("--node", required=True, help="Canonical node id (gateway or exit); legacy role aliases are normalized at this boundary.")
    render_node.add_argument("--env-file", type=Path, required=True)
    render_node.add_argument("--output-dir", type=Path, required=True)
    render_node.add_argument("--assets-dir", type=Path, help="Directory with already fetched rule assets.")
    render_node.add_argument("--set", dest="overrides", action="append", default=[], help="Override a detected runtime value, e.g. WAN_INTERFACE=eth1")
    render_node.set_defaults(func=cmd_render_node)

    write_example = subparsers.add_parser("write-example-env", help="Write the checked-in example env from code defaults.")
    write_example.add_argument("--output", type=Path, required=True)
    write_example.set_defaults(func=cmd_write_example_env)

    validate = subparsers.add_parser("validate-bundle", help="Validate a schema-3 bundle and emit its TSV install contract.")
    validate.add_argument("--bundle", type=Path, required=True)
    validate.add_argument("--expected-node", required=True)
    validate.add_argument("--contract-dir", type=Path, required=True)
    validate.add_argument("--external-assets", type=Path)
    validate.add_argument("--require-assets", action="store_true")
    validate.add_argument("--require-binaries", action="store_true")
    validate.set_defaults(func=cmd_validate_bundle)

    adapt_schema2 = subparsers.add_parser(
        "adapt-schema2",
        help="Validate one installed schema-2 release and emit migration-only ownership.",
    )
    adapt_schema2.add_argument("--current-release", type=Path, required=True)
    adapt_schema2.add_argument("--deployment-env", type=Path, required=True)
    adapt_schema2.add_argument("--contract-dir", type=Path, required=True)
    adapt_schema2.set_defaults(func=cmd_adapt_schema2)

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


def cmd_render_role(args: argparse.Namespace) -> int:
    overrides = _parse_overrides(args.overrides)
    env = load_runtime_env(args.env_file, overrides=overrides)
    node_id = normalize_node_id(args.role)
    TopologySpec.from_env(env).plan(node_id)
    write_role_rendered_files(env, legacy_role_for_node(node_id), args.output_dir, assets=_load_assets(args.assets_dir))
    return 0


def cmd_render_node(args: argparse.Namespace) -> int:
    overrides = _parse_overrides(args.overrides)
    env = load_runtime_env(args.env_file, overrides=overrides)
    node_id = normalize_node_id(args.node)
    TopologySpec.from_env(env).plan(node_id)
    write_node_rendered_files(env, node_id, args.output_dir, assets=_load_assets(args.assets_dir))
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
        )
    except InstallContractError as exc:
        raise SystemExit(str(exc)) from None
    return 0


def cmd_adapt_schema2(args: argparse.Namespace) -> int:
    try:
        adapt_schema2_install(args.current_release, args.deployment_env, args.contract_dir)
    except InstallContractError as exc:
        raise SystemExit(str(exc)) from None
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
