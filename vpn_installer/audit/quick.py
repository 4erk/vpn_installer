from __future__ import annotations

import builtins
import json
import os
import shutil
import tarfile
import textwrap
from pathlib import Path
from unittest.mock import patch

from ..common import OUT_DIR, ROOT_DIR, RUNTIME_SITE_PACKAGES
from ..config import load_env_file
from ..render import render_all_artifacts
from ..runtime_deps import ensure_python_package
from ..workflows import build_target
from .runner import AUDIT_IMAGE, VPN_PS1, AuditFailure, AuditRunner, powershell_executable, python_cmd, write_bytes

COVERAGE_THRESHOLD = 90
COVERAGE_OMIT = "vpn_installer/audit/*"


def coverage_command(*args: str) -> list[str]:
    runner = (
        "import runpy, sys; "
        f"sys.path.insert(0, {str(RUNTIME_SITE_PACKAGES)!r}); "
        "sys.argv=['coverage', *sys.argv[1:]]; "
        "runpy.run_module('coverage', run_name='__main__')"
    )
    return python_cmd() + ["-c", runner, *args]


def unit_test_modules() -> list[str]:
    return sorted(f"tests.{path.stem}" for path in (ROOT_DIR / "tests").glob("test_*.py"))


def unittest_driver_text() -> str:
    return textwrap.dedent(
        f"""
        import pathlib
        import sys
        import unittest

        repo = pathlib.Path({str(ROOT_DIR)!r}).resolve()
        sys.path.insert(0, str(repo))
        module_name = sys.argv[1]
        suite = unittest.defaultTestLoader.loadTestsFromName(module_name)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
        """
    ).strip() + "\n"


def coverage_driver_text() -> str:
    return unittest_driver_text()


def run(runner: AuditRunner) -> None:
    dev_mode = runner.mode == "all" or os.environ.get("VPN_AUDIT_DEV") == "1"
    windows_host = os.name == "nt"
    docker_available = shutil.which("docker") is not None
    bash_available = shutil.which("bash") is not None
    powershell_available = shutil.which("powershell") is not None or shutil.which("pwsh") is not None

    if dev_mode and docker_available:
        runner.ensure_audit_image()
    env_path, out_dir = runner.ensure_quick_env()
    env = load_env_file(env_path)
    runner.seed_foreign_block_cache(out_dir.name)
    ps_env = {"VPN_NO_PAUSE": "1"}

    if dev_mode:
        runner.record("quick-unittest", lambda: test_unittest_modules(runner))
        runner.record("quick-coverage", lambda: test_coverage(runner))
    else:
        runner.skip("quick-unittest", "dev-only: unit-тесты запускаются только в полном аудите")
        runner.skip("quick-coverage", "dev-only: coverage запускается только в полном аудите")

    if dev_mode and bash_available:
        runner.record("quick-bash-syntax", lambda: runner.run_bash("bash-syntax", "bash -n install.sh") or None)
    elif dev_mode:
        runner.skip("quick-bash-syntax", "bash не найден, shell-проверки пропущены")
    else:
        runner.skip("quick-bash-syntax", "dev-only: shell-проверка выполняется только в полном аудите")
    runner.record(
        "quick-py-compile",
        lambda: runner.run_command(
            "py-compile",
            python_cmd()
            + [
                "-m",
                "py_compile",
                str(ROOT_DIR / "vpn_installer" / "__main__.py"),
                str(ROOT_DIR / "vpn_installer" / "launcher.py"),
                str(ROOT_DIR / "vpn_installer" / "cli.py"),
                str(ROOT_DIR / "vpn_installer" / "install_support.py"),
                str(ROOT_DIR / "vpn_installer" / "runtime_deps.py"),
                str(ROOT_DIR / "vpn_installer" / "workflows.py"),
                str(ROOT_DIR / "vpn_installer" / "render.py"),
                str(ROOT_DIR / "vpn_installer" / "audit" / "runner.py"),
                str(ROOT_DIR / "vpn_installer" / "audit" / "quick.py"),
                str(ROOT_DIR / "vpn_installer" / "audit" / "docker.py"),
                str(ROOT_DIR / "vpn_installer" / "audit" / "lab.py"),
            ],
        )
        or None,
    )
    if windows_host and powershell_available:
        runner.record("quick-vpn-ps1-help", lambda: runner.run_powershell("vpn-ps1-help", ["-File", str(VPN_PS1), "--help"], env=ps_env) or None)
        runner.record("quick-vpn-ps1-install-help", lambda: runner.run_powershell("vpn-ps1-install-help", ["-File", str(VPN_PS1), "install", "--help"], env=ps_env) or None)
        runner.record("quick-vpn-menu-exit", lambda: test_vpn_menu_exit(runner))
        if dev_mode:
            runner.record("quick-windows-clean-room", lambda: test_windows_clean_room(runner))
        else:
            runner.skip("quick-windows-clean-room", "dev-only: clean-room Windows bootstrap выполняется только в полном аудите")
    elif windows_host:
        runner.skip("quick-vpn-ps1-help", "PowerShell не найден, Windows launcher help пропущен")
        runner.skip("quick-vpn-ps1-install-help", "PowerShell не найден, Windows install help пропущен")
        runner.skip("quick-vpn-menu-exit", "PowerShell не найден, menu smoke пропущен")
        runner.skip("quick-windows-clean-room", "PowerShell не найден, Windows clean-room пропущен")
    else:
        runner.skip("quick-vpn-ps1-help", "не Windows-хост: PowerShell smoke пропущен")
        runner.skip("quick-vpn-ps1-install-help", "не Windows-хост: PowerShell smoke пропущен")
        runner.skip("quick-vpn-menu-exit", "не Windows-хост: menu smoke для PowerShell пропущен")
        runner.skip("quick-windows-clean-room", "не Windows-хост: Windows clean-room пропущен")

    if not windows_host and bash_available:
        runner.record("quick-vpn-sh-help", lambda: runner.run_bash("vpn-sh-help", "bash ./vpn.sh --help", cwd=ROOT_DIR) or None)
        runner.record("quick-vpn-sh-audit-help", lambda: runner.run_bash("vpn-sh-audit-help", "bash ./vpn.sh audit --help", cwd=ROOT_DIR) or None)
    elif not windows_host:
        runner.skip("quick-vpn-sh-help", "bash не найден, Linux launcher help пропущен")
        runner.skip("quick-vpn-sh-audit-help", "bash не найден, Linux audit help пропущен")
    else:
        runner.skip("quick-vpn-sh-help", "не Linux-хост: Linux launcher help пропущен")
        runner.skip("quick-vpn-sh-audit-help", "не Linux-хост: Linux audit help пропущен")
    runner.record("quick-install-ux", test_install_ux_helpers)
    runner.record("quick-render-all", lambda: test_render_all(env_path, env, out_dir))
    runner.record("quick-validate-json", lambda: test_validate_json(out_dir))
    runner.record("quick-user-artifacts", lambda: test_user_artifacts(out_dir))
    runner.record("quick-validate-bundle", lambda: test_validate_bundle(out_dir))
    if docker_available:
        runner.record("quick-singbox-check", lambda: test_singbox_check(runner, out_dir))
        runner.record("quick-singbox-runtime-ru", lambda: test_ru_singbox_runtime_smoke(runner, out_dir))
    else:
        runner.skip("quick-singbox-check", "docker не найден, sing-box container check пропущен")
        runner.skip("quick-singbox-runtime-ru", "docker не найден, runtime smoke для RU sing-box пропущен")

    if dev_mode and docker_available:
        runner.record("quick-cloud-init-schema", lambda: test_cloud_init_schema(runner, out_dir))
        runner.record("quick-cloud-init-render-only", lambda: test_cloud_init_render_only(runner, out_dir))
        runner.record("quick-bundle-render-only", lambda: test_bundle_render_only(runner, out_dir))
        runner.record("quick-linux-launcher-no-python", lambda: test_linux_launcher_no_python(runner))
        runner.record("quick-linux-launcher-python", lambda: test_linux_launcher_with_python(runner))
    elif dev_mode:
        runner.skip("quick-cloud-init-schema", "docker не найден, cloud-init schema check пропущен")
        runner.skip("quick-cloud-init-render-only", "docker не найден, cloud-init render-only check пропущен")
        runner.skip("quick-bundle-render-only", "docker не найден, bundle render-only check пропущен")
        runner.skip("quick-linux-launcher-no-python", "docker не найден, Linux launcher test пропущен")
        runner.skip("quick-linux-launcher-python", "docker не найден, Linux launcher test пропущен")
    else:
        runner.skip("quick-cloud-init-schema", "dev-only: cloud-init schema выполняется только в полном аудите")
        runner.skip("quick-cloud-init-render-only", "dev-only: cloud-init render-only выполняется только в полном аудите")
        runner.skip("quick-bundle-render-only", "dev-only: bundle render-only выполняется только в полном аудите")
        runner.skip("quick-linux-launcher-no-python", "dev-only: Linux launcher regression выполняется только в полном аудите")
        runner.skip("quick-linux-launcher-python", "dev-only: Linux launcher regression выполняется только в полном аудите")


def test_unittest_modules(runner: AuditRunner) -> dict[str, str]:
    driver = runner.run_dir / "unittest_driver.py"
    driver.write_text(unittest_driver_text(), encoding="utf-8")
    modules = unit_test_modules()
    for module_name in modules:
        short_name = module_name.split(".")[-1]
        runner.run_command(f"unittest-{short_name}", python_cmd() + [str(driver), module_name])
    return {"modules": str(len(modules))}


def test_coverage(runner: AuditRunner) -> dict[str, str]:
    ensure_python_package("coverage", "coverage>=7,<8")
    coverage_data = runner.run_dir / "coverage.json"
    coverage_driver = runner.run_dir / "coverage_driver.py"
    coverage_driver.write_text(coverage_driver_text(), encoding="utf-8")
    modules = unit_test_modules()
    runner.run_command("coverage-erase", coverage_command("erase"))
    for index, module_name in enumerate(modules):
        short_name = module_name.split(".")[-1]
        args = ["run", "--source", "vpn_installer"]
        if index > 0:
            args.append("--append")
        args.extend([str(coverage_driver), module_name])
        runner.run_command(f"coverage-run-{short_name}", coverage_command(*args))
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
        "modules": str(len(modules)),
    }


def test_install_ux_helpers() -> dict[str, str]:
    import getpass

    from ..models import ROLE_RU
    from ..prompts import prompt_server_connection, select_deployment

    existing = ["alpha", "beta"]
    answers = iter(["", "my new vpn"])
    with patch("vpn_installer.prompts.find_existing_deployments", return_value=existing), patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
        selected = select_deployment(None)

    env_only_target = build_target(ROLE_RU, {"RU_PUBLIC_IP": "1.2.3.4", "SSH_PORT": "22"}, {})
    answers = iter(["1.2.3.4", "22", "root", "1", "n", ""])
    with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)):
        prompted_target = prompt_server_connection(env_only_target, force_prompt=not env_only_target.saved_connection, confirm_existing=True)

    saved_state = {
        ROLE_RU: {
            "public_ip": "5.6.7.8",
            "ssh_host": "5.6.7.8",
            "ssh_port": "2222",
            "ssh_user": "root",
            "auth_mode": "password",
            "identity_path": "",
        }
    }
    saved_target = build_target(ROLE_RU, {"RU_PUBLIC_IP": "9.9.9.9", "SSH_PORT": "22"}, saved_state)
    answers = iter(["1"])
    with patch.object(builtins, "input", side_effect=lambda _prompt="": next(answers)), patch.object(getpass, "getpass", return_value="secret"):
        reused_target = prompt_server_connection(saved_target, force_prompt=False, confirm_existing=True)

    if selected != "my-new-vpn":
        raise AuditFailure("select_deployment не нормализовал имя нового deployment")
    if env_only_target.saved_connection:
        raise AuditFailure("env без state не должен считаться сохранённым подключением")
    if prompted_target.ssh_host != "1.2.3.4" or prompted_target.auth_mode != "key":
        raise AuditFailure("не прошёл key-flow для prompt_server_connection")
    if not reused_target.saved_connection or reused_target.auth_mode != "password" or reused_target.ssh_password != "secret":
        raise AuditFailure("не прошёл reuse password-flow для prompt_server_connection")
    return {
        "selected": selected,
        "prompted_host": prompted_target.ssh_host,
        "prompted_auth_mode": prompted_target.auth_mode,
        "reused_auth_mode": reused_target.auth_mode,
    }


def test_vpn_menu_exit(runner: AuditRunner) -> dict[str, str]:
    completed = runner.run_command(
        "vpn-menu-exit",
        [powershell_executable(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(VPN_PS1)],
        input_text="8\n",
        env={"VPN_NO_PAUSE": "1"},
    )
    output = completed.stdout + completed.stderr
    if "VPN Installer" not in output or "Выбери действие" not in output:
        raise AuditFailure("vpn.ps1 без аргументов не показал главное меню")
    if "Завершено." not in output:
        raise AuditFailure("vpn.ps1 меню не завершилось через пункт Выход")
    return {"launcher": str(VPN_PS1)}


def test_render_all(env_path: Path, env: dict[str, str], out_dir: Path) -> dict[str, str]:
    render_all_artifacts(env_path, env)
    return {"out_dir": str(out_dir)}


def test_validate_json(out_dir: Path) -> dict[str, str]:
    json_paths = [
        out_dir / "preview" / "ru" / "sing-box.json",
        out_dir / "preview" / "foreign" / "sing-box.json",
        out_dir / "client" / "hiddify-cross-platform.json",
        out_dir / "client" / "linux-sing-box.json",
    ]
    for path in json_paths:
        if not path.is_file():
            raise AuditFailure(f"Не найден JSON-артефакт: {path}")
        json.loads(path.read_text(encoding="utf-8"))
    return {"validated": ", ".join(str(path) for path in json_paths)}


def test_user_artifacts(out_dir: Path) -> dict[str, str]:
    uri_path = out_dir / "client" / "hiddify-uri.txt"
    next_steps = out_dir / "NEXT-STEPS.txt"
    if not uri_path.is_file():
        raise AuditFailure(f"Не найден Hiddify URI файл: {uri_path}")
    if not next_steps.is_file():
        raise AuditFailure(f"Не найден NEXT-STEPS.txt: {next_steps}")
    uri_payload = uri_path.read_text(encoding="utf-8")
    if not uri_payload.startswith("vless://"):
        raise AuditFailure("Hiddify URI не похожа на VLESS URI")
    next_steps_text = next_steps.read_text(encoding="utf-8")
    if "Hiddify" not in next_steps_text or "vpn status" not in next_steps_text:
        raise AuditFailure("NEXT-STEPS.txt не содержит ожидаемых инструкций")
    return {"uri": str(uri_path), "next_steps": str(next_steps)}


def test_validate_bundle(out_dir: Path) -> dict[str, str]:
    bundle_dir = out_dir / "bundle"
    tarballs = [bundle_dir / "ru-gateway.tar.gz", bundle_dir / "foreign-exit.tar.gz"]
    expected = {
        "ru-gateway.tar.gz": {"install.sh", "deployment.env", "assets/geosite-ru.srs", "assets/geoip-ru.srs", "rendered/sing-box.json", "rendered/sync-state.sh", "vpn_installer/install_support.py"},
        "foreign-exit.tar.gz": {"install.sh", "deployment.env", "assets/ru-ipv4.zone", "assets/ru-ipv6.zone", "rendered/sing-box.json", "rendered/sync-state.sh", "vpn_installer/install_support.py"},
    }
    for tarball in tarballs:
        if not tarball.is_file():
            raise AuditFailure(f"Не найден bundle: {tarball}")
        with tarfile.open(tarball, "r:gz") as archive:
            names = {member.name.lstrip("./") for member in archive.getmembers() if member.name not in {".", "./"}}
        missing = sorted(expected[tarball.name] - names)
        if missing:
            raise AuditFailure(f"Bundle {tarball.name} не содержит: {', '.join(missing)}")
    return {"bundle_dir": str(bundle_dir)}


def test_singbox_check(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    container = f"audit-singbox-{runner.run_id}"
    configs = [
        out_dir / "preview" / "ru" / "sing-box.json",
        out_dir / "preview" / "foreign" / "sing-box.json",
        out_dir / "client" / "linux-sing-box.json",
        out_dir / "client" / "hiddify-cross-platform.json",
    ]
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work /var/lib/vpn-stack/rules")
        for asset in ("geosite-ru.srs", "geoip-ru.srs"):
            runner.docker_copy(container, out_dir / "assets" / asset, f"/var/lib/vpn-stack/rules/{asset}")
        for path in configs:
            runner.docker_copy(container, path, f"/work/{path.name}")
            runner.docker_exec(container, f"sing-box check -c /work/{path.name}")
    return {"checked_configs": ", ".join(path.name for path in configs)}


def test_ru_singbox_runtime_smoke(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    container = f"audit-singbox-runtime-ru-{runner.run_id}"
    config_path = out_dir / "preview" / "ru" / "sing-box.json"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work /var/lib/vpn-stack/rules")
        for asset in ("geosite-ru.srs", "geoip-ru.srs"):
            runner.docker_copy(container, out_dir / "assets" / asset, f"/var/lib/vpn-stack/rules/{asset}")
        runner.docker_copy(container, config_path, "/work/ru-sing-box.json")
        runner.docker_exec(
            container,
            "timeout 3s sing-box run -c /work/ru-sing-box.json >/tmp/ru-singbox.log 2>&1",
            expected_codes={124},
        )
    return {"config": str(config_path), "result": "runtime-smoke-ok"}


def test_cloud_init_schema(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    container = f"audit-cloudinit-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        for role in ("ru", "foreign"):
            yaml_path = out_dir / "cloud-init" / f"{role}.yaml"
            runner.docker_copy(container, yaml_path, f"/work/{role}.yaml")
            runner.docker_exec(container, f"cloud-init schema --config-file /work/{role}.yaml")
    return {"cloud_init_dir": str(out_dir / "cloud-init")}


def test_cloud_init_render_only(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    artifacts_dir = runner.work_dir / "cloud-init-render"
    for role in ("ru", "foreign"):
        yaml_path = out_dir / "cloud-init" / f"{role}.yaml"
        files, _ = runner.parse_cloud_init_payload(yaml_path)
        role_dir = artifacts_dir / role
        for file_path, content in files.items():
            relative = Path(file_path.lstrip("/"))
            write_bytes(role_dir / relative, content)
        role_name = "ru-gateway" if role == "ru" else "foreign-exit"
        runner.run_bash(
            f"cloud-init-render-{role}",
            f"bash ./install.sh --role {role_name} --env-file ./deployment.env --assets-dir ./assets --render-only --output-dir ./rendered",
            cwd=role_dir / "root" / "vpn-stack",
        )
        output_dir = role_dir / "root" / "vpn-stack" / "rendered"
        if not (output_dir / "sing-box.json").is_file():
            raise AuditFailure(f"Cloud-init payload {role} не отрендерил sing-box.json")
    return {"artifacts_dir": str(artifacts_dir)}


def test_bundle_render_only(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    container = f"audit-bundle-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        for role in ("ru-gateway", "foreign-exit"):
            tarball = out_dir / "bundle" / f"{role}.tar.gz"
            runner.docker_copy(container, tarball, f"/work/{role}.tar.gz")
            runner.docker_exec(
                container,
                textwrap.dedent(
                    f"""\
                    set -euo pipefail
                    mkdir -p /work/{role}
                    tar -xzf /work/{role}.tar.gz -C /work/{role}
                    cd /work/{role}
                    bash ./install.sh --role {role} --env-file ./deployment.env --assets-dir ./assets --render-only --output-dir /work/{role}/preview
                    test -s /work/{role}/preview/sing-box.json
                    """
                ),
            )
    return {"bundle_dir": str(out_dir / "bundle")}


def test_windows_clean_room(runner: AuditRunner) -> dict[str, str]:
    if os.name != "nt":
        return {"skipped": "vpn.ps1 clean-room проверяется только на Windows"}
    with runner.temp_repo_copy("windows-clean-room") as repo_copy:
        portable_downloads = ROOT_DIR / ".runtime" / "downloads"
        env = os.environ.copy()
        env["VPN_NO_PAUSE"] = "1"
        if portable_downloads.is_dir():
            zips = sorted(portable_downloads.glob("python-*-embeddable-*.zip"))
            if zips:
                env["VPN_BOOTSTRAP_PYTHON_URL"] = zips[-1].resolve().as_uri()
        runner.run_powershell(
            "windows-clean-room",
            ["-File", str(repo_copy / "vpn.ps1"), "install", "--help"],
            cwd=repo_copy,
            env=env,
        )
        portable = repo_copy / ".runtime" / "python" / "windows" / "python.exe"
        if not portable.is_file():
            raise AuditFailure("Clean-room vpn.ps1 не поднял portable Python")
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
        runner.docker_exec(container, "cd /work && chmod +x ./vpn.sh && ./vpn.sh install --help | grep -q 'usage: vpn install'")
    return {"status": "help-ok"}
