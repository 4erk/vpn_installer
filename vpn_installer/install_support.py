from __future__ import annotations

import argparse
from pathlib import Path

from .common import sanitize_name, write_text
from .config import load_env_file, merge_env_with_defaults, render_example_env_text
from .models import ROLE_FOREIGN, ROLE_RU
from .render import write_role_rendered_files


def load_runtime_env(env_file: Path, overrides: dict[str, str] | None = None) -> dict[str, str]:
    loaded = load_env_file(env_file)
    deploy_name = loaded.get("DEPLOY_NAME", "").strip() or sanitize_name(env_file.stem)
    env = merge_env_with_defaults(loaded, deploy_name)
    if overrides:
        env.update(overrides)
    return env


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpn-install-support")
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_role = subparsers.add_parser("render-role", help="Render one role into a flat directory.")
    render_role.add_argument("--role", choices=[ROLE_RU, ROLE_FOREIGN], required=True)
    render_role.add_argument("--env-file", type=Path, required=True)
    render_role.add_argument("--output-dir", type=Path, required=True)
    render_role.add_argument("--set", dest="overrides", action="append", default=[], help="Override env values for this render, e.g. WAN_INTERFACE=eth1")
    render_role.set_defaults(func=cmd_render_role)

    write_example = subparsers.add_parser("write-example-env", help="Write the checked-in example env from code defaults.")
    write_example.add_argument("--output", type=Path, required=True)
    write_example.set_defaults(func=cmd_write_example_env)

    return parser


def cmd_render_role(args: argparse.Namespace) -> int:
    overrides: dict[str, str] = {}
    for item in args.overrides:
        key, _, value = item.partition("=")
        if not key or not _:
            raise SystemExit(f"Invalid override: {item}")
        overrides[key] = value
    env = load_runtime_env(args.env_file, overrides=overrides)
    write_role_rendered_files(env, args.role, args.output_dir)
    return 0


def cmd_write_example_env(args: argparse.Namespace) -> int:
    write_text(args.output, render_example_env_text())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
