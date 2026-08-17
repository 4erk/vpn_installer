from __future__ import annotations

import builtins
from collections import Counter
import ipaddress
import json
import os
import shutil
import subprocess
import tarfile
import textwrap
import time
from pathlib import Path
from unittest.mock import patch

from .. import VERSION
from ..common import OUT_DIR, ROOT_DIR, RUNTIME_SITE_PACKAGES, cli_command
from ..client_artifacts import PUBLIC_VLESS_OUTBOUND_TAG
from ..compatibility import CompatibilityWindow
from ..config import load_env_file
from ..dns_policy import GLOBAL_FOREIGN_DOMAINS, GLOBAL_FOREIGN_DOMAIN_SUFFIXES
from ..manifest import INSTALL_PLAN_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION, XRAY_VERSION, required_asset_names
from ..render import render_all_artifacts
from ..runtime_deps import ensure_python_package
from ..targets import build_target
from ..topology import (
    CONFIG_SCHEMA_VERSION,
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
    TopologySpec,
)
from ..vless_verify import render_live_route_probe
from .runner import AUDIT_IMAGE, VALID_GEOIP_SRS, VALID_GEOSITE_SRS, VPN_CMD, AuditFailure, AuditRunner, python_cmd, write_bytes

COVERAGE_THRESHOLD = 80
COVERAGE_OMIT = "vpn_installer/audit/*"
QUICK_ASSET_FIXTURES = {
    "geosite-ru.srs": VALID_GEOSITE_SRS,
    "geoip-ru.srs": VALID_GEOIP_SRS,
    "ru-ipv4.zone": b"203.0.113.0/24\n",
    "ru-ipv6.zone": b"2001:db8::/32\n",
}
TOPOLOGY_AUDIT_CASES = (
    ("single-ru", TOPOLOGY_SINGLE, LOCATION_RU),
    ("single-foreign", TOPOLOGY_SINGLE, LOCATION_FOREIGN),
    ("dual", TOPOLOGY_DUAL, LOCATION_RU),
)


def coverage_command(*args: str) -> list[str]:
    runner = (
        "import runpy, sys; "
        f"sys.path.insert(0, {str(RUNTIME_SITE_PACKAGES)!r}); "
        "sys.argv=['coverage', *sys.argv[1:]]; "
        "runpy.run_module('coverage', run_name='__main__')"
    )
    return python_cmd() + ["-c", runner, *args]


def coverage_driver_text() -> str:
    return textwrap.dedent(
        f"""
        import pathlib
        import sys
        import unittest

        repo = pathlib.Path({str(ROOT_DIR)!r}).resolve()
        sys.path.insert(0, str(repo))
        suite = unittest.defaultTestLoader.discover(str(repo / "tests"), pattern="test_*.py")
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
        """
    ).strip() + "\n"


def docker_readiness() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker не найден"
    try:
        completed = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"docker daemon недоступен: {exc}"
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        reason = detail[0] if detail else f"docker info завершился с кодом {completed.returncode}"
        return False, f"docker daemon недоступен: {reason}"
    return True, ""


def test_bash_syntax_in_container(runner: AuditRunner) -> dict[str, str]:
    container = f"audit-bash-syntax-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, ROOT_DIR / "install.sh", "/work/install.sh")
        runner.docker_exec(container, "bash -n /work/install.sh")
    return {"runtime": "docker"}


def run(runner: AuditRunner) -> None:
    full_mode = runner.mode == "all"
    windows_host = os.name == "nt"
    docker_available = False
    docker_skip_reason = ""
    bash_available = False
    powershell_available = False

    if full_mode:
        docker_available, docker_skip_reason = docker_readiness()
        bash_available = shutil.which("bash") is not None
        powershell_available = shutil.which("powershell") is not None or shutil.which("pwsh") is not None
        if docker_available:
            runner.ensure_audit_image()
    env_path, out_dir = runner.ensure_quick_env()
    env = load_env_file(env_path)
    runner.seed_foreign_block_cache(out_dir.name)
    ps_env = {"VPN_NO_PAUSE": "1"}

    if full_mode:
        runner.record("quick-coverage", lambda: test_coverage(runner))

    if full_mode and docker_available:
        runner.record("quick-bash-syntax", lambda: test_bash_syntax_in_container(runner))
    elif full_mode and bash_available:
        runner.record("quick-bash-syntax", lambda: runner.run_bash("bash-syntax", "bash -n install.sh") or None)
    elif full_mode:
        runner.skip("quick-bash-syntax", "bash не найден, shell-проверки пропущены")
    runner.record(
        "quick-py-compile",
        lambda: runner.run_command(
            "py-compile",
            python_cmd()
            + [
                "-m",
                "py_compile",
                str(ROOT_DIR / "vpn_installer" / "__main__.py"),
                str(ROOT_DIR / "vpn_installer" / "client_drift.py"),
                str(ROOT_DIR / "vpn_installer" / "launcher.py"),
                str(ROOT_DIR / "vpn_installer" / "cli.py"),
                str(ROOT_DIR / "vpn_installer" / "compatibility.py"),
                str(ROOT_DIR / "vpn_installer" / "diagnostics.py"),
                str(ROOT_DIR / "vpn_installer" / "install_contract.py"),
                str(ROOT_DIR / "vpn_installer" / "install_support.py"),
                str(ROOT_DIR / "vpn_installer" / "runtime_deps.py"),
                str(ROOT_DIR / "vpn_installer" / "targets.py"),
                str(ROOT_DIR / "vpn_installer" / "workflows.py"),
                str(ROOT_DIR / "vpn_installer" / "render.py"),
                str(ROOT_DIR / "vpn_installer" / "specs.py"),
                str(ROOT_DIR / "vpn_installer" / "interserver_transport.py"),
                str(ROOT_DIR / "vpn_installer" / "system_resolver.py"),
                str(ROOT_DIR / "vpn_installer" / "routing_policy.py"),
                str(ROOT_DIR / "vpn_installer" / "server_agent.py"),
                str(ROOT_DIR / "vpn_installer" / "upgrade_0200.py"),
                str(ROOT_DIR / "vpn_installer" / "vless_verify.py"),
                str(ROOT_DIR / "vpn_installer" / "verify.py"),
                str(ROOT_DIR / "vpn_installer" / "manifest.py"),
                str(ROOT_DIR / "vpn_installer" / "audit" / "runner.py"),
                str(ROOT_DIR / "vpn_installer" / "audit" / "quick.py"),
                str(ROOT_DIR / "vpn_installer" / "audit" / "docker.py"),
                str(ROOT_DIR / "vpn_installer" / "audit" / "lab.py"),
            ],
        )
        or None,
    )
    if full_mode and windows_host and powershell_available:
        runner.record("quick-vpn-cmd-help", lambda: runner.run_command("vpn-cmd-help", [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(VPN_CMD), "--help"], env=ps_env) or None)
        runner.record("quick-vpn-cmd-install-help", lambda: runner.run_command("vpn-cmd-install-help", [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(VPN_CMD), "install", "--help"], env=ps_env) or None)
        runner.record("quick-vpn-menu-exit", lambda: test_vpn_menu_exit(runner))
        runner.record("quick-windows-clean-room", lambda: test_windows_clean_room(runner))
    elif full_mode and windows_host:
        runner.skip("quick-vpn-cmd-help", "PowerShell не найден, Windows launcher help пропущен")
        runner.skip("quick-vpn-cmd-install-help", "PowerShell не найден, Windows install help пропущен")
        runner.skip("quick-vpn-menu-exit", "PowerShell не найден, menu smoke пропущен")
        runner.skip("quick-windows-clean-room", "PowerShell не найден, Windows clean-room пропущен")
    if full_mode and not windows_host and bash_available:
        runner.record("quick-vpn-sh-help", lambda: runner.run_bash("vpn-sh-help", "bash ./vpn.sh --help", cwd=ROOT_DIR) or None)
        runner.record("quick-vpn-sh-audit-help", lambda: runner.run_bash("vpn-sh-audit-help", "bash ./vpn.sh audit --help", cwd=ROOT_DIR) or None)
    elif full_mode and not windows_host:
        runner.skip("quick-vpn-sh-help", "bash не найден, Linux launcher help пропущен")
        runner.skip("quick-vpn-sh-audit-help", "bash не найден, Linux audit help пропущен")
    runner.record("quick-install-ux", test_install_ux_helpers)
    runner.record(
        "quick-render-all",
        lambda: test_render_all(
            env_path,
            env,
            out_dir,
            refresh_assets=False,
        ),
    )
    runner.record("quick-topology-matrix", lambda: test_topology_matrix(runner))
    runner.record("quick-validate-json", lambda: test_validate_json(out_dir, env))
    runner.record("quick-user-artifacts", lambda: test_user_artifacts(out_dir))
    runner.record("quick-validate-bundle", lambda: test_validate_bundle(out_dir, env))
    if full_mode and docker_available:
        runner.record("quick-singbox-runtime-ru", lambda: test_ru_singbox_runtime_smoke(runner, out_dir))
        runner.record("quick-interserver-hysteria-runtime", lambda: test_interserver_hysteria_runtime(runner, out_dir))
    elif full_mode:
        runner.skip("quick-singbox-runtime-ru", f"{docker_skip_reason}, runtime smoke для RU sing-box пропущен")
        runner.skip("quick-interserver-hysteria-runtime", f"{docker_skip_reason}, Hysteria2 runtime check пропущен")

    if full_mode and docker_available:
        runner.record("quick-xray-reality-interop", lambda: test_xray_reality_interop(runner, out_dir))
        runner.record("quick-cloud-init-schema", lambda: test_cloud_init_schema(runner, out_dir, env))
        runner.record("quick-cloud-init-render-only", lambda: test_cloud_init_render_only(runner, out_dir, env))
        runner.record("quick-bundle-render-only", lambda: test_bundle_render_only(runner, out_dir, env))
        runner.record("quick-linux-launcher-no-python", lambda: test_linux_launcher_no_python(runner))
        runner.record("quick-linux-launcher-python", lambda: test_linux_launcher_with_python(runner))
    elif full_mode:
        runner.skip("quick-xray-reality-interop", f"{docker_skip_reason}, Xray Reality interop check пропущен")
        runner.skip("quick-cloud-init-schema", f"{docker_skip_reason}, cloud-init schema check пропущен")
        runner.skip("quick-cloud-init-render-only", f"{docker_skip_reason}, cloud-init render-only check пропущен")
        runner.skip("quick-bundle-render-only", f"{docker_skip_reason}, bundle render-only check пропущен")
        runner.skip("quick-linux-launcher-no-python", f"{docker_skip_reason}, Linux launcher test пропущен")
        runner.skip("quick-linux-launcher-python", f"{docker_skip_reason}, Linux launcher test пропущен")


def run_interop(runner: AuditRunner) -> None:
    docker_available, docker_skip_reason = docker_readiness()
    if not docker_available:
        runner.skip("quick-xray-reality-interop", f"{docker_skip_reason}, Xray Reality interop check пропущен")
        return
    runner.ensure_audit_image()
    env_path, out_dir = runner.ensure_quick_env()
    env = load_env_file(env_path)
    runner.seed_foreign_block_cache(out_dir.name)
    render_all_artifacts(env_path, env)
    runner.record("quick-xray-reality-interop", lambda: test_xray_reality_interop(runner, out_dir))


def test_coverage(runner: AuditRunner) -> dict[str, str]:
    ensure_python_package("coverage", "coverage>=7,<8")
    coverage_data = runner.run_dir / "coverage.json"
    coverage_driver = runner.run_dir / "coverage_driver.py"
    coverage_driver.write_text(coverage_driver_text(), encoding="utf-8")
    runner.run_command("coverage-erase", coverage_command("erase"))
    runner.run_command(
        "coverage-branch-run",
        coverage_command("run", "--branch", "--source", "vpn_installer", str(coverage_driver)),
    )
    runner.run_command(
        "coverage-report",
        coverage_command("report", f"--fail-under={COVERAGE_THRESHOLD}", f"--omit={COVERAGE_OMIT}"),
    )
    runner.run_command(
        "coverage-json",
        coverage_command("json", f"--omit={COVERAGE_OMIT}", "-o", str(coverage_data)),
    )
    return {
        "coverage_json": str(coverage_data),
        "threshold": str(COVERAGE_THRESHOLD),
        "omit": COVERAGE_OMIT,
        "modules": "all",
    }


def test_install_ux_helpers() -> dict[str, str]:
    import getpass

    from ..prompts import prompt_server_connection, select_deployment

    existing = ["alpha", "beta"]
    answers = iter(["", "my new vpn"])
    with patch("vpn_installer.prompts.find_existing_deployments", return_value=existing), patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
        selected = select_deployment(None)
    with patch("vpn_installer.prompts.find_existing_deployments", return_value=[]), patch.object(builtins, "input", return_value=""):
        first_selected = select_deployment(None)

    env_only_target = build_target(
        NODE_GATEWAY,
        {
            "CONFIG_SCHEMA": str(CONFIG_SCHEMA_VERSION),
            "TOPOLOGY": TOPOLOGY_SINGLE,
            "GATEWAY_LOCATION": LOCATION_RU,
            "GATEWAY_PUBLIC_IP": "1.2.3.4",
            "SSH_PORT": "22",
        },
        {},
    )
    answers = iter(["1.2.3.4", "22", "root", "1", "n", ""])
    with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
        prompted_target = prompt_server_connection(env_only_target, force_prompt=not env_only_target.saved_connection, confirm_existing=True)

    saved_state = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "topology": TOPOLOGY_SINGLE,
        "nodes": {
            NODE_GATEWAY: {
                "location": LOCATION_RU,
                "public_ip": "5.6.7.8",
                "ssh_host": "5.6.7.8",
                "ssh_port": "2222",
                "ssh_user": "root",
                "auth_mode": "password",
                "identity_path": "",
            }
        },
    }
    saved_target = build_target(
        NODE_GATEWAY,
        {
            "CONFIG_SCHEMA": str(CONFIG_SCHEMA_VERSION),
            "TOPOLOGY": TOPOLOGY_SINGLE,
            "GATEWAY_LOCATION": LOCATION_RU,
            "GATEWAY_PUBLIC_IP": "9.9.9.9",
            "SSH_PORT": "22",
        },
        saved_state,
    )
    answers = iter(["1"])
    with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)), patch.object(getpass, "getpass", return_value="secret"):
        reused_target = prompt_server_connection(saved_target, force_prompt=False, confirm_existing=True)

    if selected != "my-new-vpn":
        raise AuditFailure("select_deployment не нормализовал имя нового deployment")
    if first_selected != "home-vpn":
        raise AuditFailure("первая установка не предлагает home-vpn по умолчанию")
    if env_only_target.saved_connection:
        raise AuditFailure("env без state не должен считаться сохранённым подключением")
    if prompted_target.ssh_host != "1.2.3.4" or prompted_target.auth_mode != "key":
        raise AuditFailure("не прошёл key-flow для prompt_server_connection")
    if not reused_target.saved_connection or reused_target.auth_mode != "password" or reused_target.ssh_password != "secret":
        raise AuditFailure("не прошёл reuse password-flow для prompt_server_connection")
    return {
        "selected": selected,
        "first_selected": first_selected,
        "prompted_host": prompted_target.ssh_host,
        "prompted_auth_mode": prompted_target.auth_mode,
        "reused_auth_mode": reused_target.auth_mode,
    }


def test_vpn_menu_exit(runner: AuditRunner) -> dict[str, str]:
    completed = runner.run_command(
        "vpn-menu-exit",
        [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(VPN_CMD)],
        input_text="8\n",
        env={"VPN_NO_PAUSE": "1"},
    )
    output = completed.stdout + completed.stderr
    if "VPN Installer" not in output or "Выбери действие" not in output:
        raise AuditFailure("vpn.cmd без аргументов не показал главное меню")
    if "Завершено." not in output:
        raise AuditFailure("vpn.cmd меню не завершилось через пункт Выход")
    return {"launcher": str(VPN_CMD)}


def seed_quick_asset_cache(env: dict[str, str], out_dir: Path) -> None:
    names = ["geosite-ru.srs", "geoip-ru.srs"]
    if env.get("FOREIGN_BLOCK_RU", "0") == "1":
        names.extend(["ru-ipv4.zone", "ru-ipv6.zone"])
    assets_dir = out_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        write_bytes(assets_dir / name, QUICK_ASSET_FIXTURES[name])


def test_render_all(
    env_path: Path,
    env: dict[str, str],
    out_dir: Path,
    *,
    refresh_assets: bool = False,
) -> dict[str, str]:
    if not refresh_assets:
        seed_quick_asset_cache(env, out_dir)
    render_all_artifacts(env_path, env, fetch_assets_first=refresh_assets)
    return {"out_dir": str(out_dir)}


def validate_topology_artifacts(env: dict[str, str], out_dir: Path) -> dict[str, object]:
    topology = TopologySpec.from_env(env)
    expected_nodes = {node.node_id for node in topology.nodes}
    actual_preview_nodes = {path.name for path in (out_dir / "preview").iterdir() if path.is_dir()}
    actual_server_nodes = {path.stem for path in (out_dir / "server").glob("*.env")}
    actual_cloud_nodes = {path.stem for path in (out_dir / "cloud-init").glob("*.yaml")}
    actual_bundle_nodes = {path.name.removesuffix(".tar.gz") for path in (out_dir / "bundle").glob("*.tar.gz")}
    for label, actual in (
        ("preview", actual_preview_nodes),
        ("server env", actual_server_nodes),
        ("cloud-init", actual_cloud_nodes),
        ("bundle", actual_bundle_nodes),
    ):
        if actual != expected_nodes:
            raise AuditFailure(f"{label} nodes mismatch: expected={sorted(expected_nodes)}, actual={sorted(actual)}")

    matrix: dict[str, object] = {}
    for node in topology.nodes:
        plan = topology.plan(node.node_id)
        node_dir = out_dir / "preview" / node.node_id
        manifest_path = node_dir / "render-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        install_plan = json.loads((node_dir / "install-plan.json").read_text(encoding="utf-8"))
        expected_capabilities = sorted(plan.capabilities)
        if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION or manifest.get("version") != VERSION:
            raise AuditFailure(f"{node.node_id}: manifest release/schema mismatch")
        if install_plan.get("schema_version") != INSTALL_PLAN_SCHEMA_VERSION:
            raise AuditFailure(f"{node.node_id}: install plan schema mismatch")
        if manifest.get("install_plan") != install_plan:
            raise AuditFailure(f"{node.node_id}: standalone and embedded install plans differ")
        if manifest.get("update_compatibility") != CompatibilityWindow.current().to_manifest():
            raise AuditFailure(f"{node.node_id}: update compatibility window mismatch")
        if manifest.get("topology") != topology.mode:
            raise AuditFailure(f"{node.node_id}: manifest topology mismatch")
        if manifest.get("node_id") != node.node_id or manifest.get("location") != node.location:
            raise AuditFailure(f"{node.node_id}: manifest node descriptor mismatch")
        if manifest.get("capabilities") != expected_capabilities:
            raise AuditFailure(f"{node.node_id}: manifest capabilities mismatch")

        wireguard_path = node_dir / f"{env.get('WG_INTERFACE', 'wg0')}.conf"
        component_presence = {
            "wireguard": wireguard_path.is_file(),
            "xray": (node_dir / "xray.json").is_file(),
            "interserver": (node_dir / "interserver_transport.py").is_file(),
        }
        expected_presence = {
            "wireguard": plan.requires_wireguard,
            "xray": plan.requires_xray,
            "interserver": plan.has_interserver,
        }
        if component_presence != expected_presence:
            raise AuditFailure(
                f"{node.node_id}: capability artifacts mismatch: "
                f"expected={expected_presence}, actual={component_presence}"
            )
        node_env = load_env_file(node_dir / "node.env")
        if node_env.get("CONFIG_SCHEMA") != str(CONFIG_SCHEMA_VERSION) or node_env.get("NODE_ID") != node.node_id:
            raise AuditFailure(f"{node.node_id}: node.env is not canonical schema {CONFIG_SCHEMA_VERSION}")
        if not topology.is_dual and "EXIT_PUBLIC_IP" in node_env:
            raise AuditFailure("single topology leaked EXIT_PUBLIC_IP into node.env")
        matrix[node.node_id] = {
            "location": node.location,
            "capabilities": expected_capabilities,
            **component_presence,
        }
    return {"topology": topology.mode, "nodes": matrix}


def test_topology_matrix(runner: AuditRunner) -> dict[str, str]:
    results: dict[str, str] = {}
    for case_name, topology, gateway_location in TOPOLOGY_AUDIT_CASES:
        env_path, env = runner.create_env(
            f"topology-{case_name}",
            topology=topology,
            gateway_location=gateway_location,
        )
        out_dir = OUT_DIR / env["DEPLOY_NAME"]
        seed_quick_asset_cache(env, out_dir)
        render_all_artifacts(env_path, env, fetch_assets_first=False)
        result = validate_topology_artifacts(env, out_dir)
        test_validate_json(out_dir, env)
        test_validate_bundle(out_dir, env)
        results[case_name] = json.dumps(result, ensure_ascii=False, sort_keys=True)
    return results


def test_validate_json(out_dir: Path, env: dict[str, str]) -> dict[str, str]:
    topology = TopologySpec.from_env(env)
    json_paths = [
        out_dir / "client" / "hiddify-cross-platform.json",
        out_dir / "client" / "linux-sing-box.json",
        out_dir / "client" / "android-v2rayng-xray.json",
    ]
    for node in topology.nodes:
        node_dir = out_dir / "preview" / node.node_id
        json_paths.append(node_dir / "sing-box.json")
        if topology.plan(node.node_id).requires_xray:
            json_paths.append(node_dir / "xray.json")
    for path in json_paths:
        if not path.is_file():
            raise AuditFailure(f"Не найден JSON-артефакт: {path}")
        json.loads(path.read_text(encoding="utf-8"))
    return {"validated": ", ".join(str(path) for path in json_paths)}


def test_user_artifacts(out_dir: Path) -> dict[str, str]:
    vless_uri_path = out_dir / "client" / "vless-uri.txt"
    hiddify_uri_alias_path = out_dir / "client" / "hiddify-uri.txt"
    v2rayn_uri_alias_path = out_dir / "client" / "v2rayn-uri.txt"
    hiddify_json_path = out_dir / "client" / "hiddify-cross-platform.json"
    hysteria2_uri_path = out_dir / "client" / "hysteria2-uri.txt"
    linux_json_path = out_dir / "client" / "linux-sing-box.json"
    android_hiddify_json_path = out_dir / "client" / "hiddify-android.json"
    android_xray_json_path = out_dir / "client" / "android-v2rayng-xray.json"
    next_steps = out_dir / "NEXT-STEPS.txt"
    if not vless_uri_path.is_file():
        raise AuditFailure(f"Не найден VLESS URI fallback файл: {vless_uri_path}")
    if not hiddify_uri_alias_path.is_file():
        raise AuditFailure(f"Не найден Hiddify URI alias файл: {hiddify_uri_alias_path}")
    if not v2rayn_uri_alias_path.is_file():
        raise AuditFailure(f"Не найден v2rayN URI alias файл: {v2rayn_uri_alias_path}")
    if not hiddify_json_path.is_file():
        raise AuditFailure(f"Не найден Hiddify JSON файл: {hiddify_json_path}")
    if not hysteria2_uri_path.is_file():
        raise AuditFailure(f"Не найден Hysteria2 URI файл: {hysteria2_uri_path}")
    if not linux_json_path.is_file():
        raise AuditFailure(f"Не найден Linux sing-box JSON файл: {linux_json_path}")
    if not android_hiddify_json_path.is_file():
        raise AuditFailure(f"Не найден Android Hiddify JSON файл: {android_hiddify_json_path}")
    if not android_xray_json_path.is_file():
        raise AuditFailure(f"Не найден Android/v2rayNG Xray JSON файл: {android_xray_json_path}")
    if not next_steps.is_file():
        raise AuditFailure(f"Не найден NEXT-STEPS.txt: {next_steps}")
    vless_uri_payload = vless_uri_path.read_text(encoding="utf-8")
    if not vless_uri_payload.startswith("vless://"):
        raise AuditFailure("VLESS URI fallback не похож на VLESS URI")
    hiddify_uri_alias_payload = hiddify_uri_alias_path.read_text(encoding="utf-8")
    if hiddify_uri_alias_payload != vless_uri_payload:
        raise AuditFailure("Совместимый Hiddify URI alias расходится с VLESS URI fallback")
    if v2rayn_uri_alias_path.read_text(encoding="utf-8") != vless_uri_payload:
        raise AuditFailure("Совместимый v2rayN URI alias расходится с основным VLESS URI")
    hiddify_payload = json.loads(hiddify_json_path.read_text(encoding="utf-8"))
    hysteria2_uri_payload = hysteria2_uri_path.read_text(encoding="utf-8").strip()
    linux_payload = json.loads(linux_json_path.read_text(encoding="utf-8"))
    if hiddify_payload.get("inbounds", [{}])[0].get("auto_redirect") is not False:
        raise AuditFailure("Hiddify profile должен отключать auto_redirect")
    hiddify_outbounds = {item.get("tag"): item for item in hiddify_payload.get("outbounds", []) if isinstance(item, dict)}
    public_transport = hiddify_outbounds.get(PUBLIC_VLESS_OUTBOUND_TAG, {})
    if public_transport.get("type") != "vless" or public_transport.get("multiplex") != {"enabled": False}:
        raise AuditFailure("Hiddify profile не содержит mux-free VLESS transport")
    if any(item.get("type") == "urltest" for item in hiddify_payload.get("outbounds", []) if isinstance(item, dict)):
        raise AuditFailure("Hiddify profile не должен использовать latency-based urltest как failover")
    if hiddify_payload.get("route", {}).get("final") != PUBLIC_VLESS_OUTBOUND_TAG:
        raise AuditFailure("Hiddify profile не закрепляет default route за VLESS transport")
    dns_servers = hiddify_payload.get("dns", {}).get("servers", [])
    if not dns_servers or dns_servers[0].get("detour") != PUBLIC_VLESS_OUTBOUND_TAG:
        raise AuditFailure("Hiddify profile не закрепляет remote DNS за VLESS transport")
    if not hysteria2_uri_payload.startswith("hysteria2://") or "pinSHA256=" not in hysteria2_uri_payload:
        raise AuditFailure("Hysteria2 URI не содержит стандартную схему и certificate pin")
    if linux_payload.get("inbounds", [{}])[0].get("auto_redirect") is not True:
        raise AuditFailure("Linux sing-box profile должен включать auto_redirect")
    linux_payload["inbounds"][0]["auto_redirect"] = False
    if linux_payload != hiddify_payload:
        raise AuditFailure("Hiddify и Linux sing-box profiles расходятся не только по auto_redirect")
    android_xray_payload = json.loads(android_xray_json_path.read_text(encoding="utf-8"))
    if "dns" in android_xray_payload:
        raise AuditFailure("Android/v2rayNG Xray JSON не должен включать клиентский DNS: домены должны доходить до серверного роутера")
    if android_xray_payload.get("routing", {}).get("domainStrategy") != "AsIs":
        raise AuditFailure("Android/v2rayNG Xray JSON должен использовать routing.domainStrategy=AsIs")
    routing_rules = android_xray_payload.get("routing", {}).get("rules", [])
    if not routing_rules or routing_rules[0] != {"type": "field", "ip": ["::/0"], "outboundTag": "block"}:
        raise AuditFailure("Android/v2rayNG Xray JSON не блокирует клиентский IPv6 правилом ::/0 -> block первым правилом")
    sniffing = android_xray_payload.get("inbounds", [{}])[0].get("sniffing", {})
    if sniffing.get("enabled") is not True or sniffing.get("routeOnly") is not False or set(sniffing.get("destOverride", [])) != {"http", "tls", "quic"}:
        raise AuditFailure("Android/v2rayNG Xray JSON не содержит ожидаемый sniffing http/tls/quic с routeOnly=false")
    next_steps_text = next_steps.read_text(encoding="utf-8")
    if "VLESS URI" not in next_steps_text or cli_command("status") not in next_steps_text or "v2rayNG" not in next_steps_text or "android-v2rayng-xray.json" not in next_steps_text:
        raise AuditFailure("NEXT-STEPS.txt не содержит ожидаемых Android/v2rayNG инструкций")
    return {
        "vless_uri": str(vless_uri_path),
        "hiddify_uri_alias": str(hiddify_uri_alias_path),
        "v2rayn_uri_alias": str(v2rayn_uri_alias_path),
        "hiddify_json": str(hiddify_json_path),
        "hysteria2_uri": str(hysteria2_uri_path),
        "android_hiddify_json": str(android_hiddify_json_path),
        "android_xray_json": str(android_xray_json_path),
        "next_steps": str(next_steps),
    }


def test_validate_bundle(out_dir: Path, env: dict[str, str]) -> dict[str, str]:
    topology = TopologySpec.from_env(env)
    bundle_dir = out_dir / "bundle"
    tarballs = [bundle_dir / f"{node.node_id}.tar.gz" for node in topology.nodes]
    expected: dict[str, set[str]] = {}
    for node in topology.nodes:
        plan = topology.plan(node.node_id)
        expected_files = {
            "install.sh",
            "deployment.env",
            "vpn_installer/install_support.py",
            "vpn_installer/render.py",
            "vpn_installer/server_agent.py",
        }
        expected_files.update(
            f"assets/{name}"
            for name in required_asset_names(
                plan,
                foreign_block_ru=env.get("FOREIGN_BLOCK_RU", "0") == "1",
            )
        )
        expected[node.node_id] = expected_files
    for tarball in tarballs:
        if not tarball.is_file():
            raise AuditFailure(f"Не найден bundle: {tarball}")
        with tarfile.open(tarball, "r:gz") as archive:
            member_names = [member.name.lstrip("./") for member in archive.getmembers() if member.name not in {".", "./"}]
        duplicates = sorted(name for name, count in Counter(member_names).items() if count > 1)
        if duplicates:
            raise AuditFailure(f"Bundle {tarball.name} содержит дубли: {', '.join(duplicates)}")
        names = set(member_names)
        missing = sorted(expected[tarball.name.removesuffix(".tar.gz")] - names)
        if missing:
            raise AuditFailure(f"Bundle {tarball.name} не содержит: {', '.join(missing)}")
        legacy = sorted(name for name in names if name == "rendered" or name.startswith("rendered/"))
        if legacy:
            raise AuditFailure(f"Bundle {tarball.name} содержит legacy rendered tree: {', '.join(legacy)}")
        unrelated = sorted(
            name
            for name in names
            if name.startswith("vpn_installer/audit/")
            or name in {"vpn_installer/cli.py", "vpn_installer/workflows.py", "vpn_installer/client_artifacts.py"}
        )
        if unrelated:
            raise AuditFailure(f"Bundle {tarball.name} содержит локальный код: {', '.join(unrelated)}")
    return {"bundle_dir": str(bundle_dir)}


def test_ru_singbox_runtime_smoke(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    container = f"audit-singbox-runtime-ru-{runner.run_id}"
    config_path = out_dir / "preview" / NODE_GATEWAY / "sing-box.json"
    client_configs = [
        out_dir / "client" / "linux-sing-box.json",
    ]
    if runner.mode != "quick":
        client_configs.append(out_dir / "client" / "hiddify-cross-platform.json")
    work_dir = runner.work_dir / "ru-runtime-smoke"
    work_dir.mkdir(parents=True, exist_ok=True)
    router_plain_path = work_dir / "ru-sing-box-router.json"

    router_config = json.loads(config_path.read_text(encoding="utf-8"))
    direct_rules = [rule for rule in router_config.get("route", {}).get("rules", []) if rule.get("outbound") == "direct-ru"]
    direct_domains = {domain.lower() for rule in direct_rules for domain in rule.get("domain", [])}
    direct_suffixes = {suffix.lower() for rule in direct_rules for suffix in rule.get("domain_suffix", [])}
    leaked_domains = direct_domains & {domain.lower() for domain in GLOBAL_FOREIGN_DOMAINS}
    leaked_suffixes = direct_suffixes & {suffix.lower() for suffix in GLOBAL_FOREIGN_DOMAIN_SUFFIXES}
    if leaked_domains or leaked_suffixes:
        leaked = ", ".join(sorted(leaked_domains | leaked_suffixes))
        raise AuditFailure(f"RU direct policy перехватывает global foreign traffic: {leaked}")
    route_rules = router_config.get("route", {}).get("rules", [])
    global_domain_index = next(
        (index for index, rule in enumerate(route_rules) if rule.get("outbound") == "to-foreign" and "mtalk.google.com" in rule.get("domain", [])),
        None,
    )
    global_suffix_index = next(
        (index for index, rule in enumerate(route_rules) if rule.get("outbound") == "to-foreign" and ".gstatic.com" in rule.get("domain_suffix", [])),
        None,
    )
    ru_asset_index = next(
        (index for index, rule in enumerate(route_rules) if rule.get("outbound") == "direct-ru" and rule.get("rule_set") == ["ru-geosite"]),
        None,
    )
    if None in {global_domain_index, global_suffix_index, ru_asset_index} or not (
        global_domain_index < ru_asset_index and global_suffix_index < ru_asset_index
    ):
        raise AuditFailure("Global foreign overrides должны предшествовать RU geosite routing")
    inbound = router_config["inbounds"][0]
    if inbound.get("type") != "mixed" or inbound.get("tag") != "router-in" or inbound.get("listen") != "127.0.0.1":
        raise AuditFailure("RU sing-box не содержит локальный mixed-router перед routing policy")
    public_hy2 = next((item for item in router_config["inbounds"] if item.get("tag") == "public-hy2-in"), None)
    if not isinstance(public_hy2, dict) or public_hy2.get("type") != "hysteria2":
        raise AuditFailure("RU sing-box не содержит публичный Hysteria2 ingress")
    router_listen_port = int(inbound.get("listen_port", 0))
    if not (1 <= router_listen_port <= 65535):
        raise AuditFailure("RU sing-box router содержит некорректный listen_port")
    router_config["log"] = {"level": "info", "timestamp": True}
    for dns_server in router_config.get("dns", {}).get("servers", []):
        dns_server.pop("detour", None)
    router_config["route"]["final"] = "direct-ru"
    router_config["outbounds"] = [
        {"type": "direct", "tag": "direct-ru", "domain_resolver": {"server": "dns-ru-direct", "strategy": "ipv4_only"}},
        {"type": "direct", "tag": "to-foreign", "domain_resolver": {"server": "dns-global", "strategy": "ipv4_only"}},
    ]
    router_config["route"]["rules"].insert(0, {"ip_cidr": ["127.0.0.0/8"], "action": "route", "outbound": "direct-ru"})
    write_bytes(router_plain_path, json.dumps(router_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")

    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work /var/lib/vpn-stack/rules")
        for asset in ("geosite-ru.srs", "geoip-ru.srs"):
            runner.docker_copy(container, out_dir / "assets" / asset, f"/var/lib/vpn-stack/rules/{asset}")
        runner.docker_copy(container, config_path, "/work/ru-sing-box.json")
        for client_config in client_configs:
            destination = f"/work/{client_config.name}"
            runner.docker_copy(container, client_config, destination)
        check_starts: list[str] = []
        check_waits: list[str] = []
        check_failures: list[str] = []
        check_logs: list[str] = []
        for index, client_config in enumerate(client_configs):
            label = f"client_{index}"
            log_path = f"/tmp/{label}-check.log"
            check_starts.append(
                f"sing-box check -c /work/{client_config.name} >{log_path} 2>&1 & {label}_pid=$!;"
            )
            check_waits.append(f'wait "${label}_pid"; {label}_rc=$?;')
            check_failures.append(f"{label}_rc != 0")
            check_logs.append(log_path)
        failure_expression = " || ".join([*check_failures, "runtime_ready != 1"])
        runner.docker_exec(
            container,
            " ".join(check_starts)
            + " "
            "sing-box run -c /work/ru-sing-box.json >/tmp/ru-singbox.log 2>&1 & "
            "runtime_pid=$!; "
            "runtime_ready=0; "
            "for _ in $(seq 1 30); do "
            f"if ss -Hltn | grep -q '127.0.0.1:{router_listen_port}'; then "
            "sleep 0.2; "
            "kill -0 \"$runtime_pid\" 2>/dev/null && runtime_ready=1; "
            "break; "
            "fi; "
            "kill -0 \"$runtime_pid\" 2>/dev/null || break; "
            "sleep 0.1; "
            "done; "
            "kill \"$runtime_pid\" 2>/dev/null || true; "
            + " ".join(check_waits)
            + " "
            "wait \"$runtime_pid\" 2>/dev/null || true; "
            f"if (( {failure_expression} )); then "
            f"cat {' '.join(check_logs)} /tmp/ru-singbox.log; "
            "exit 1; "
            "fi",
        )
        runner.docker_copy(container, router_plain_path, "/work/ru-sing-box-router.json")
        runner.docker_exec(container, "sing-box check -c /work/ru-sing-box-router.json")
        runner.docker_exec(container, "mkdir -p /srv/ru-plain && printf 'ru plain ok\\n' >/srv/ru-plain/index.html")
        runner.docker_exec(container, "python3 -m http.server 18080 --bind 127.0.0.1 --directory /srv/ru-plain >/tmp/ru-plain-web.log 2>&1 &")
        runner.docker_exec(container, "sing-box run -c /work/ru-sing-box-router.json >/tmp/ru-router.log 2>&1 & sleep 1")
        try:
            completed = runner.docker_exec(
                container,
                "curl --silent --show-error --fail --max-time 10 --socks5-hostname 127.0.0.1:2080 http://127.0.0.1:18080/",
            )
        except Exception:
            runner.docker_exec(container, "cat /tmp/ru-router.log", expected_codes={0, 1})
            raise
        if "ru plain ok" not in completed.stdout:
            raise AuditFailure("RU sing-box router runtime smoke не вернул ожидаемый HTTP payload")
    return {
        "config": str(config_path),
        "client_configs": ", ".join(path.name for path in client_configs),
        "router_config": str(router_plain_path),
        "result": "runtime-smoke-ok",
    }


def test_interserver_hysteria_runtime(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    network = f"audit-hysteria-{runner.run_id}"
    server = f"audit-hysteria-server-{runner.run_id}"
    client = f"audit-hysteria-client-{runner.run_id}"
    server_ip = "172.31.249.10"
    client_ip = "172.31.249.11"
    work_dir = runner.work_dir / "interserver-hysteria-runtime"
    work_dir.mkdir(parents=True, exist_ok=True)
    client_config_path = work_dir / "client.json"
    rendered_server_config_path = out_dir / "preview" / NODE_EXIT / "sing-box.json"
    server_config_path = work_dir / "server.json"

    ru_config = json.loads((out_dir / "preview" / NODE_GATEWAY / "sing-box.json").read_text(encoding="utf-8"))
    hysteria_candidate = next(
        (item for item in ru_config.get("outbounds", []) if item.get("tag") == "interserver-underlay-hy2"),
        None,
    )
    if not isinstance(hysteria_candidate, dict) or hysteria_candidate.get("type") != "hysteria2":
        raise AuditFailure("RU config не содержит Hysteria2 transport candidate")
    if hysteria_candidate.get("obfs", {}).get("type") != "salamander":
        raise AuditFailure("Interserver Hysteria2 candidate не содержит Salamander obfs")
    hysteria_candidate = dict(hysteria_candidate)
    hysteria_candidate["server"] = server_ip
    rendered_server_config = json.loads(rendered_server_config_path.read_text(encoding="utf-8"))
    hysteria_inbound = next(
        (item for item in rendered_server_config.get("inbounds", []) if item.get("tag") == "interserver-hy2-in"),
        None,
    )
    if not isinstance(hysteria_inbound, dict) or hysteria_inbound.get("type") != "hysteria2":
        raise AuditFailure("Foreign config не содержит Hysteria2 transport inbound")
    server_config = {
        "log": rendered_server_config.get("log", {"level": "info", "timestamp": True}),
        "inbounds": [hysteria_inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }
    write_bytes(server_config_path, json.dumps(server_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
    client_config = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{"type": "mixed", "tag": "probe-in", "listen": "0.0.0.0", "listen_port": 1080}],
        "outbounds": [hysteria_candidate],
        "route": {"final": "interserver-underlay-hy2"},
        "experimental": ru_config["experimental"],
    }
    write_bytes(client_config_path, json.dumps(client_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")

    with runner.docker_network(network, subnet="172.31.249.0/24"):
        with runner.docker_container(server, AUDIT_IMAGE, network=network, ip=server_ip):
            with runner.docker_container(client, AUDIT_IMAGE, network=network, ip=client_ip):
                runner.docker_exec(server, "mkdir -p /work /srv/probe && printf 'hysteria transport ok\\n' >/srv/probe/index.html")
                runner.docker_exec(client, "mkdir -p /work /var/lib/vpn-stack")
                runner.docker_copy(server, server_config_path, "/work/server.json")
                runner.docker_copy(client, client_config_path, "/work/client.json")
                runner.docker_exec(server, "sing-box check -c /work/server.json")
                runner.docker_exec(client, "sing-box check -c /work/client.json")
                runner.docker_exec(server, "python3 -m http.server 18080 --bind 127.0.0.1 --directory /srv/probe >/tmp/web.log 2>&1 &")
                runner.docker_exec(server, "sing-box run -c /work/server.json >/tmp/hysteria-server.log 2>&1 &")
                runner.docker_exec(client, "sing-box run -c /work/client.json >/tmp/hysteria-client.log 2>&1 &")
                runner.docker_exec(server, "for i in $(seq 1 40); do ss -Huln | grep -q ':18443 ' && exit 0; sleep 0.25; done; cat /tmp/hysteria-server.log; exit 1")
                runner.docker_exec(client, "for i in $(seq 1 40); do ss -Hltn | grep -q ':1080 ' && ss -Hltn | grep -q ':19090 ' && exit 0; sleep 0.25; done; cat /tmp/hysteria-client.log; exit 1")
                try:
                    completed = runner.docker_exec(
                        client,
                        "curl --silent --show-error --fail --max-time 15 --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:18080/",
                    )
                except Exception:
                    runner.docker_exec(server, "cat /tmp/hysteria-server.log /tmp/web.log", expected_codes={0, 1})
                    runner.docker_exec(client, "cat /tmp/hysteria-client.log", expected_codes={0, 1})
                    raise
                if completed.stdout.strip() != "hysteria transport ok":
                    raise AuditFailure("Hysteria2 runtime не вернул payload с foreign endpoint")
                runner.docker_exec(
                    client,
                    "curl --silent --show-error --fail http://127.0.0.1:19090/proxies/interserver-underlay-hy2 | jq -e '.type == \"Hysteria2\"'",
                )
    return {"server_config": str(server_config_path), "client_config": str(client_config_path), "result": "handshake-and-http-ok"}


def test_xray_reality_interop(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    network = f"audit-xray-interop-{runner.run_id}"
    router = f"audit-singbox-router-{runner.run_id}"
    xray_front = f"audit-xray-front-{runner.run_id}"
    xray_client = f"audit-xray-client-{runner.run_id}"
    work_dir = runner.work_dir / "xray-reality-interop"
    work_dir.mkdir(parents=True, exist_ok=True)
    router_config_path = work_dir / "sing-box-router.json"
    xray_server_config_path = work_dir / "xray-server.json"
    client_config_path = work_dir / "xray-client.json"

    router_config = json.loads((out_dir / "preview" / NODE_GATEWAY / "sing-box.json").read_text(encoding="utf-8"))
    router_config["inbounds"][0]["listen"] = "0.0.0.0"
    router_config["log"] = {"level": "debug", "timestamp": True}
    router_config["dns"] = {
        "servers": [
            {
                "type": "hosts",
                "tag": "interop-hosts",
                "predefined": {"example.com": ["127.0.0.1", "::1"]},
            }
        ],
        "final": "interop-hosts",
    }
    router_config["route"]["final"] = "direct-ru"
    router_config["route"]["auto_detect_interface"] = False
    router_config["route"]["default_domain_resolver"] = {"server": "interop-hosts"}
    router_config["route"]["rules"] = [rule for rule in router_config["route"]["rules"] if rule.get("action") != "resolve"]
    router_config["outbounds"] = [
        {"type": "direct", "tag": "direct-ru"},
        {"type": "direct", "tag": "to-foreign"},
    ]
    xray_server_config = json.loads((out_dir / "preview" / NODE_GATEWAY / "xray.json").read_text(encoding="utf-8"))
    xray_server_config["log"] = {"loglevel": "debug"}
    xray_server_config["inbounds"][0]["listen"] = "0.0.0.0"
    xray_server_config["inbounds"][0]["port"] = 443
    reality_settings = xray_server_config["inbounds"][0]["streamSettings"]["realitySettings"]
    reality_settings.pop("dest", None)
    reality_settings["target"] = "singbox-router:443"
    xray_server_config["outbounds"][0]["settings"]["servers"][0]["address"] = "singbox-router"
    xray_server_config["outbounds"][0]["settings"]["servers"][0]["port"] = router_config["inbounds"][0]["listen_port"]
    foreign_overlay = next(item for item in xray_server_config["outbounds"] if item.get("tag") == "foreign-overlay")
    foreign_overlay.pop("streamSettings", None)

    generated_client_config = json.loads((out_dir / "client" / "windows-xray.json").read_text(encoding="utf-8"))
    proxy_outbound = generated_client_config["outbounds"][0]
    proxy_outbound["settings"]["vnext"][0]["address"] = "xray-front"
    proxy_outbound["settings"]["vnext"][0]["port"] = 443
    client_config = {
        "log": {"loglevel": "debug"},
        "inbounds": [
            {
                "tag": "socks",
                "listen": "0.0.0.0",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
            },
            {
                "tag": "dns-probe",
                "listen": "0.0.0.0",
                "port": 1053,
                "protocol": "dokodemo-door",
                "settings": {"address": "1.1.1.1", "port": 53, "network": "udp"},
            },
        ],
        "outbounds": [proxy_outbound],
    }
    route_probe_path = work_dir / "route-probe.py"
    write_bytes(router_config_path, json.dumps(router_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
    write_bytes(xray_server_config_path, json.dumps(xray_server_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
    write_bytes(client_config_path, json.dumps(client_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
    with runner.docker_network(network):
        try:
            with runner.docker_container(router, AUDIT_IMAGE, network=network, extra_args=["--network-alias", "singbox-router"]):
                runner.docker_exec(router, "mkdir -p /work /var/lib/vpn-stack/rules")
                for asset in ("geosite-ru.srs", "geoip-ru.srs"):
                    runner.docker_copy(router, out_dir / "assets" / asset, f"/var/lib/vpn-stack/rules/{asset}")
                runner.docker_copy(router, router_config_path, "/work/sing-box-router.json")
                runner.docker_exec(router, "ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true sing-box check -c /work/sing-box-router.json")
                runner.docker_exec(router, "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/example.key -out /tmp/example.crt -subj /CN=www.bing.com -days 1 >/tmp/openssl-gen.log 2>&1")
                runner.docker_exec(router, "openssl s_server -quiet -accept 443 -cert /tmp/example.crt -key /tmp/example.key -www >/tmp/example-tls.log 2>&1 & sleep 1")
                runner.docker_exec(router, "ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true sing-box run -c /work/sing-box-router.json >/tmp/sing-box-router.log 2>&1 & sleep 1")
                runner.docker_exec(router, "for i in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q ':2080 ' && exit 0; sleep 0.25; done; cat /tmp/sing-box-router.log; exit 1")
                router_ip = runner.docker(
                    "inspect-singbox-router-interop",
                    ["inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", router],
                ).stdout.strip()
                try:
                    ipaddress.ip_address(router_ip)
                except ValueError as exc:
                    raise AuditFailure(f"sing-box router container IP is invalid: {router_ip!r}") from exc
                xray_server_config["routing"]["rules"].insert(
                    1,
                    {"type": "field", "network": "udp", "ip": [router_ip], "outboundTag": "foreign-overlay"},
                )
                write_bytes(
                    xray_server_config_path,
                    json.dumps(xray_server_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
                )
                client_config["inbounds"][1]["settings"].update({"address": router_ip, "port": 1053})
                write_bytes(client_config_path, json.dumps(client_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
                runner.docker_exec(
                    router,
                    "dnsmasq --no-daemon --no-hosts --no-resolv --log-queries --interface=eth0 --bind-interfaces --port=1053 "
                    "--host-record=example.com,93.184.216.34,2606:2800:220:1:248:1893:25c8:1946 "
                    ">/tmp/dnsmasq.log 2>&1 & "
                    "for i in $(seq 1 20); do ss -lun 2>/dev/null | grep -q ':1053 ' && exit 0; sleep 0.1; done; "
                    "cat /tmp/dnsmasq.log; exit 1",
                )
                runner.docker(
                    "run-xray-front-interop",
                    [
                        "run",
                        "-d",
                        "--name",
                        xray_front,
                        "--label",
                        "vpn-installer.audit=1",
                        "--network",
                        network,
                        "--network-alias",
                        "xray-front",
                        "-v",
                        f"{xray_server_config_path}:/etc/xray/config.json:ro",
                        f"ghcr.io/xtls/xray-core:{XRAY_VERSION}",
                        "run",
                        "-config",
                        "/etc/xray/config.json",
                    ],
                )
                runner.docker(
                    "run-xray-client-interop",
                    [
                        "run",
                        "-d",
                        "--name",
                        xray_client,
                        "--label",
                        "vpn-installer.audit=1",
                        "--network",
                        network,
                        "-v",
                        f"{client_config_path}:/etc/xray/config.json:ro",
                        f"ghcr.io/xtls/xray-core:{XRAY_VERSION}",
                        "run",
                        "-config",
                        "/etc/xray/config.json",
                    ],
                )
                client_ip = runner.docker(
                    "inspect-xray-client-interop",
                    ["inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", xray_client],
                ).stdout.strip()
                try:
                    ipaddress.ip_address(client_ip)
                except ValueError as exc:
                    raise AuditFailure(f"Xray client container IP is invalid: {client_ip!r}") from exc
                write_bytes(
                    route_probe_path,
                    render_live_route_probe(listen_host=client_ip, listen_port=10808, dns_listen_port=1053).encode("utf-8"),
                )
                runner.docker_copy(router, route_probe_path, "/work/route-probe.py")
                def dump_interop_logs() -> None:
                    runner.docker(
                        "interop-router-singbox-log",
                        ["exec", router, "bash", "-lc", "cat /tmp/sing-box-router.log 2>/dev/null || true"],
                        expected_codes={0, 1},
                    )
                    runner.docker(
                        "interop-router-tls-log",
                        ["exec", router, "bash", "-lc", "cat /tmp/example-tls.log 2>/dev/null || true"],
                        expected_codes={0, 1},
                    )
                    runner.docker(
                        "interop-router-dns-log",
                        ["exec", router, "bash", "-lc", "cat /tmp/dnsmasq.log 2>/dev/null || true"],
                        expected_codes={0, 1},
                    )
                    runner.docker("interop-router-container-log", ["logs", router], expected_codes={0, 1})
                    runner.docker("interop-xray-front-log", ["logs", xray_front], expected_codes={0, 1})
                    runner.docker("interop-xray-client-log", ["logs", xray_client], expected_codes={0, 1})

                try:
                    completed = None
                    for attempt in range(1, 4):
                        try:
                            completed = runner.docker(
                                f"curl-xray-reality-interop-{attempt}",
                                [
                                    "run",
                                    "--rm",
                                    "--network",
                                    network,
                                    "curlimages/curl:latest",
                                    "-k",
                                    "-fsS",
                                    "--max-time",
                                    "45",
                                    "-x",
                                    f"socks5://{xray_client}:10808",
                                    "https://example.com/",
                                ],
                            )
                            break
                        except Exception:
                            dump_interop_logs()
                            if attempt == 3:
                                raise
                            time.sleep(1)
                except Exception:
                    dump_interop_logs()
                    raise
                if completed is None or not completed.stdout.strip():
                    raise AuditFailure("Xray Reality interop не вернул ответ от локального TLS probe")
                try:
                    route_probe = json.loads(runner.docker_exec(router, "python3 /work/route-probe.py").stdout)
                except Exception:
                    dump_interop_logs()
                    raise
                queries = route_probe.get("dns", {}).get("queries", {})
                if not all(queries.get(record, {}).get("verdict") == "verified" for record in ("A", "AAAA")):
                    raise AuditFailure("Xray Reality interop не подтвердил UDP DNS A/AAAA")
                private_reject = route_probe.get("private_reject", {})
                if not isinstance(private_reject, dict):
                    raise AuditFailure("Xray Reality interop получил malformed private/fake probe result")
                private_targets = private_reject.get("targets", [])
                if private_reject.get("verdict") == "failed" or not private_targets:
                    raise AuditFailure("Xray Reality interop получил некорректный private/fake probe result")
                if private_reject.get("verdict") == "inconclusive" and not all(
                    isinstance(target, dict)
                    and target.get("evidence") == "socks-success-eof"
                    and target.get("correlation_required") is True
                    for target in private_targets
                ):
                    raise AuditFailure("Xray Reality interop потерял обязательную private/fake log correlation")
        finally:
            if not runner.keep_docker:
                runner._docker_cleanup(f"rm-{xray_front}", ["rm", "-f", xray_front])
                runner._docker_cleanup(f"rm-{xray_client}", ["rm", "-f", xray_client])
    return {"xray_server_config": str(xray_server_config_path), "router_config": str(router_config_path), "client_config": str(client_config_path)}


def test_cloud_init_schema(runner: AuditRunner, out_dir: Path, env: dict[str, str]) -> dict[str, str]:
    topology = TopologySpec.from_env(env)
    container = f"audit-cloudinit-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        for node in topology.nodes:
            yaml_path = out_dir / "cloud-init" / f"{node.node_id}.yaml"
            runner.docker_copy(container, yaml_path, f"/work/{node.node_id}.yaml")
            runner.docker_exec(container, f"cloud-init schema --config-file /work/{node.node_id}.yaml")
    return {"cloud_init_dir": str(out_dir / "cloud-init")}


def test_cloud_init_render_only(runner: AuditRunner, out_dir: Path, env: dict[str, str]) -> dict[str, str]:
    topology = TopologySpec.from_env(env)
    artifacts_dir = runner.work_dir / "cloud-init-render"
    container = f"audit-cloudinit-render-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        for node in topology.nodes:
            node_id = node.node_id
            yaml_path = out_dir / "cloud-init" / f"{node_id}.yaml"
            files, _ = runner.parse_cloud_init_payload(yaml_path)
            node_dir = artifacts_dir / node_id
            for file_path, content in files.items():
                relative = Path(file_path.lstrip("/"))
                write_bytes(node_dir / relative, content)
            payload_root = node_dir / "root" / "vpn-stack"
            assets_argument = " --assets-dir ./assets" if (payload_root / "assets").is_dir() else ""
            runner.docker_copy(container, payload_root, f"/work/{node_id}")
            runner.docker_exec(
                container,
                f"cd /work/{node_id} && bash ./install.sh --node {node_id} --env-file ./deployment.env{assets_argument} --render-only --output-dir ./rendered && test -s ./rendered/sing-box.json",
            )
    return {"artifacts_dir": str(artifacts_dir)}


def test_bundle_render_only(runner: AuditRunner, out_dir: Path, env: dict[str, str]) -> dict[str, str]:
    topology = TopologySpec.from_env(env)
    container = f"audit-bundle-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        for node in topology.nodes:
            node_id = node.node_id
            tarball = out_dir / "bundle" / f"{node_id}.tar.gz"
            runner.docker_copy(container, tarball, f"/work/{node_id}.tar.gz")
            runner.docker_exec(
                container,
                textwrap.dedent(
                    f"""\
                    set -euo pipefail
                    mkdir -p /work/{node_id}
                    tar -xzf /work/{node_id}.tar.gz -C /work/{node_id}
                    cd /work/{node_id}
                    bash ./install.sh --node {node_id} --env-file ./deployment.env --assets-dir ./assets --render-only --output-dir /work/{node_id}/preview
                    test -s /work/{node_id}/preview/sing-box.json
                    """
                ),
            )
    return {"bundle_dir": str(out_dir / "bundle")}


def test_windows_clean_room(runner: AuditRunner) -> dict[str, str]:
    if os.name != "nt":
        return {"skipped": "vpn.cmd clean-room проверяется только на Windows"}
    with runner.temp_repo_copy("windows-clean-room") as repo_copy:
        portable_downloads = ROOT_DIR / ".runtime" / "downloads"
        env = os.environ.copy()
        env["VPN_NO_PAUSE"] = "1"
        if portable_downloads.is_dir():
            zips = sorted(portable_downloads.glob("python-*-embeddable-*.zip"))
            if zips:
                env["VPN_BOOTSTRAP_PYTHON_URL"] = zips[-1].resolve().as_uri()
        runner.run_command(
            "windows-clean-room",
            [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(repo_copy / "vpn.cmd"), "install", "--help"],
            cwd=repo_copy,
            env=env,
        )
        portable = repo_copy / ".runtime" / "python" / "windows" / "python.exe"
        if not portable.is_file():
            raise AuditFailure("Clean-room vpn.cmd не поднял portable Python")
        return {"portable_python": str(portable)}


def test_linux_launcher_no_python(runner: AuditRunner) -> dict[str, str]:
    repo_copy = runner.work_dir / "linux-launcher-no-python"
    for rel in ("vpn.sh", "vpn_installer"):
        source = ROOT_DIR / rel
        destination = repo_copy / rel
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    container = f"audit-linux-nopy-{runner.run_id}"
    with runner.docker_container(container, "ubuntu:24.04"):
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, repo_copy / "vpn.sh", "/work/vpn.sh")
        runner.docker_copy(container, repo_copy / "vpn_installer", "/work/vpn_installer")
        runner.docker_exec(
            container,
            "cd /work && chmod +x ./vpn.sh && ./vpn.sh --help >/tmp/out 2>/tmp/err && grep -q 'Если запустить без аргументов' /tmp/out",
        )
    return {"status": "help-without-python-ok"}


def test_linux_launcher_with_python(runner: AuditRunner) -> dict[str, str]:
    repo_copy = runner.work_dir / "linux-launcher-python"
    for rel in ("vpn.sh", "vpn_installer"):
        source = ROOT_DIR / rel
        destination = repo_copy / rel
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    container = f"audit-linux-py-{runner.run_id}"
    with runner.docker_container(container, "python:3.13"):
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, repo_copy / "vpn.sh", "/work/vpn.sh")
        runner.docker_copy(container, repo_copy / "vpn_installer", "/work/vpn_installer")
        runner.docker_exec(container, "cd /work && chmod +x ./vpn.sh && ./vpn.sh install --help | grep -q 'usage: ./vpn.sh install'")
    return {"status": "help-ok"}
