from __future__ import annotations

import builtins
import json
import os
import shutil
import subprocess
import tarfile
import textwrap
import time
from pathlib import Path
from unittest.mock import patch

from ..common import OUT_DIR, ROOT_DIR, RUNTIME_SITE_PACKAGES
from ..config import load_env_file
from ..manifest import XRAY_VERSION
from ..render import render_all_artifacts
from ..runtime_deps import ensure_python_package
from ..targets import build_target
from .runner import AUDIT_IMAGE, VPN_PS1, AuditFailure, AuditRunner, powershell_executable, python_cmd, write_bytes

COVERAGE_THRESHOLD = 80
COVERAGE_OMIT = "vpn_installer/audit/*"


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


def run(runner: AuditRunner) -> None:
    dev_mode = runner.mode == "all" or os.environ.get("VPN_AUDIT_DEV") == "1"
    windows_host = os.name == "nt"
    docker_available, docker_skip_reason = docker_readiness()
    bash_available = shutil.which("bash") is not None
    powershell_available = shutil.which("powershell") is not None or shutil.which("pwsh") is not None

    if dev_mode and docker_available:
        runner.ensure_audit_image()
    env_path, out_dir = runner.ensure_quick_env()
    env = load_env_file(env_path)
    runner.seed_foreign_block_cache(out_dir.name)
    ps_env = {"VPN_NO_PAUSE": "1"}

    if dev_mode:
        runner.skip("quick-unittest", "full audit uses one instrumented branch-coverage run")
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
                str(ROOT_DIR / "vpn_installer" / "client_drift.py"),
                str(ROOT_DIR / "vpn_installer" / "launcher.py"),
                str(ROOT_DIR / "vpn_installer" / "cli.py"),
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
        runner.record("quick-interserver-hysteria-runtime", lambda: test_interserver_hysteria_runtime(runner, out_dir))
    else:
        runner.skip("quick-singbox-check", f"{docker_skip_reason}, sing-box container check пропущен")
        runner.skip("quick-singbox-runtime-ru", f"{docker_skip_reason}, runtime smoke для RU sing-box пропущен")
        runner.skip("quick-interserver-hysteria-runtime", f"{docker_skip_reason}, Hysteria2 runtime check пропущен")

    if dev_mode and docker_available:
        runner.record("quick-xray-reality-interop", lambda: test_xray_reality_interop(runner, out_dir))
        runner.record("quick-cloud-init-schema", lambda: test_cloud_init_schema(runner, out_dir))
        runner.record("quick-cloud-init-render-only", lambda: test_cloud_init_render_only(runner, out_dir))
        runner.record("quick-bundle-render-only", lambda: test_bundle_render_only(runner, out_dir))
        runner.record("quick-linux-launcher-no-python", lambda: test_linux_launcher_no_python(runner))
        runner.record("quick-linux-launcher-python", lambda: test_linux_launcher_with_python(runner))
    elif dev_mode:
        runner.skip("quick-xray-reality-interop", f"{docker_skip_reason}, Xray Reality interop check пропущен")
        runner.skip("quick-cloud-init-schema", f"{docker_skip_reason}, cloud-init schema check пропущен")
        runner.skip("quick-cloud-init-render-only", f"{docker_skip_reason}, cloud-init render-only check пропущен")
        runner.skip("quick-bundle-render-only", f"{docker_skip_reason}, bundle render-only check пропущен")
        runner.skip("quick-linux-launcher-no-python", f"{docker_skip_reason}, Linux launcher test пропущен")
        runner.skip("quick-linux-launcher-python", f"{docker_skip_reason}, Linux launcher test пропущен")
    else:
        runner.skip("quick-xray-reality-interop", "dev-only: Xray Reality interop выполняется только в полном аудите")
        runner.skip("quick-cloud-init-schema", "dev-only: cloud-init schema выполняется только в полном аудите")
        runner.skip("quick-cloud-init-render-only", "dev-only: cloud-init render-only выполняется только в полном аудите")
        runner.skip("quick-bundle-render-only", "dev-only: bundle render-only выполняется только в полном аудите")
        runner.skip("quick-linux-launcher-no-python", "dev-only: Linux launcher regression выполняется только в полном аудите")
        runner.skip("quick-linux-launcher-python", "dev-only: Linux launcher regression выполняется только в полном аудите")


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
        out_dir / "preview" / "ru" / "xray.json",
        out_dir / "preview" / "foreign" / "sing-box.json",
        out_dir / "client" / "hiddify-cross-platform.json",
        out_dir / "client" / "linux-sing-box.json",
        out_dir / "client" / "android-v2rayng-xray.json",
    ]
    for path in json_paths:
        if not path.is_file():
            raise AuditFailure(f"Не найден JSON-артефакт: {path}")
        json.loads(path.read_text(encoding="utf-8"))
    return {"validated": ", ".join(str(path) for path in json_paths)}


def test_user_artifacts(out_dir: Path) -> dict[str, str]:
    vless_uri_path = out_dir / "client" / "vless-uri.txt"
    hiddify_uri_alias_path = out_dir / "client" / "hiddify-uri.txt"
    hiddify_json_path = out_dir / "client" / "hiddify-cross-platform.json"
    android_hiddify_json_path = out_dir / "client" / "hiddify-android.json"
    android_xray_json_path = out_dir / "client" / "android-v2rayng-xray.json"
    next_steps = out_dir / "NEXT-STEPS.txt"
    if not vless_uri_path.is_file():
        raise AuditFailure(f"Не найден VLESS URI fallback файл: {vless_uri_path}")
    if not hiddify_uri_alias_path.is_file():
        raise AuditFailure(f"Не найден Hiddify URI alias файл: {hiddify_uri_alias_path}")
    if not hiddify_json_path.is_file():
        raise AuditFailure(f"Не найден Hiddify JSON файл: {hiddify_json_path}")
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
    if "VLESS URI" not in next_steps_text or "vpn status" not in next_steps_text or "v2rayNG" not in next_steps_text or "android-v2rayng-xray.json" not in next_steps_text:
        raise AuditFailure("NEXT-STEPS.txt не содержит ожидаемых Android/v2rayNG инструкций")
    return {
        "vless_uri": str(vless_uri_path),
        "hiddify_uri_alias": str(hiddify_uri_alias_path),
        "hiddify_json": str(hiddify_json_path),
        "android_hiddify_json": str(android_hiddify_json_path),
        "android_xray_json": str(android_xray_json_path),
        "next_steps": str(next_steps),
    }


def test_validate_bundle(out_dir: Path) -> dict[str, str]:
    bundle_dir = out_dir / "bundle"
    tarballs = [bundle_dir / "ru-gateway.tar.gz", bundle_dir / "foreign-exit.tar.gz"]
    expected = {
        "ru-gateway.tar.gz": {
            "install.sh",
            "deployment.env",
            "assets/geosite-ru.srs",
            "assets/geoip-ru.srs",
            "rendered/sing-box.json",
            "rendered/xray.json",
            "rendered/vpn-stack-agent.py",
            "rendered/vpn-stack-xray.service",
            "vpn_installer/install_support.py",
        },
        "foreign-exit.tar.gz": {"install.sh", "deployment.env", "rendered/sing-box.json", "rendered/vpn-stack-agent.py", "vpn_installer/install_support.py"},
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
    work_dir = runner.work_dir / "ru-runtime-smoke"
    work_dir.mkdir(parents=True, exist_ok=True)
    router_plain_path = work_dir / "ru-sing-box-router.json"

    router_config = json.loads(config_path.read_text(encoding="utf-8"))
    inbound = router_config["inbounds"][0]
    if inbound.get("type") != "mixed" or inbound.get("tag") != "router-in" or inbound.get("listen") != "127.0.0.1":
        raise AuditFailure("RU sing-box должен быть локальным mixed-router, а публичный VLESS/Reality должен быть в Xray")
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
        runner.docker_exec(
            container,
            "timeout 3s sing-box run -c /work/ru-sing-box.json >/tmp/ru-singbox.log 2>&1",
            expected_codes={124},
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
    return {"config": str(config_path), "router_config": str(router_plain_path), "result": "runtime-smoke-ok"}


def test_interserver_hysteria_runtime(runner: AuditRunner, out_dir: Path) -> dict[str, str]:
    network = f"audit-hysteria-{runner.run_id}"
    server = f"audit-hysteria-server-{runner.run_id}"
    client = f"audit-hysteria-client-{runner.run_id}"
    server_ip = "172.31.249.10"
    client_ip = "172.31.249.11"
    work_dir = runner.work_dir / "interserver-hysteria-runtime"
    work_dir.mkdir(parents=True, exist_ok=True)
    client_config_path = work_dir / "client.json"
    server_config_path = out_dir / "preview" / "foreign" / "sing-box.json"

    ru_config = json.loads((out_dir / "preview" / "ru" / "sing-box.json").read_text(encoding="utf-8"))
    primary = next(
        (item for item in ru_config.get("outbounds", []) if item.get("tag") == "to-foreign-hy2"),
        None,
    )
    if not isinstance(primary, dict) or primary.get("type") != "hysteria2":
        raise AuditFailure("RU config не содержит Hysteria2 primary outbound")
    primary = dict(primary)
    primary["server"] = server_ip
    selector = {
        "type": "selector",
        "tag": "to-foreign",
        "outbounds": ["to-foreign-hy2"],
        "default": "to-foreign-hy2",
        "interrupt_exist_connections": False,
    }
    client_config = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{"type": "mixed", "tag": "probe-in", "listen": "0.0.0.0", "listen_port": 1080}],
        "outbounds": [primary, selector],
        "route": {"final": "to-foreign"},
        "experimental": ru_config["experimental"],
    }
    write_bytes(client_config_path, json.dumps(client_config, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")

    with runner.docker_network(network, subnet="172.31.249.0/24"):
        with runner.docker_container(server, AUDIT_IMAGE, network=network, ip=server_ip):
            with runner.docker_container(client, AUDIT_IMAGE, network=network, ip=client_ip):
                runner.docker_exec(server, "mkdir -p /work /srv/probe && printf 'hysteria transport ok\\n' >/srv/probe/index.html")
                runner.docker_exec(client, "mkdir -p /work")
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
                    "curl --silent --show-error --fail http://127.0.0.1:19090/proxies/to-foreign | jq -e '.now == \"to-foreign-hy2\"'",
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

    router_config = json.loads((out_dir / "preview" / "ru" / "sing-box.json").read_text(encoding="utf-8"))
    router_config["inbounds"][0]["listen"] = "0.0.0.0"
    router_config["log"] = {"level": "debug", "timestamp": True}
    router_config["dns"] = {
        "servers": [
            {
                "type": "hosts",
                "tag": "interop-hosts",
                "predefined": {"example.com": ["127.0.0.1"]},
            }
        ],
        "final": "interop-hosts",
    }
    router_config["route"]["final"] = "direct-ru"
    router_config["route"]["default_domain_resolver"] = "interop-hosts"
    router_config["route"]["rules"] = [rule for rule in router_config["route"]["rules"] if rule.get("action") != "resolve"]
    router_config["outbounds"] = [
        {"type": "direct", "tag": "direct-ru"},
        {"type": "direct", "tag": "to-foreign"},
    ]

    xray_server_config = json.loads((out_dir / "preview" / "ru" / "xray.json").read_text(encoding="utf-8"))
    xray_server_config["log"] = {"loglevel": "debug"}
    xray_server_config["inbounds"][0]["listen"] = "0.0.0.0"
    xray_server_config["inbounds"][0]["port"] = 443
    xray_server_config["inbounds"][0]["streamSettings"]["realitySettings"]["dest"] = "singbox-router:443"
    xray_server_config["outbounds"][0]["settings"]["servers"][0]["address"] = "singbox-router"
    xray_server_config["outbounds"][0]["settings"]["servers"][0]["port"] = router_config["inbounds"][0]["listen_port"]

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
            }
        ],
        "outbounds": [proxy_outbound],
    }
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
        finally:
            if not runner.keep_docker:
                runner._docker_cleanup(f"rm-{xray_front}", ["rm", "-f", xray_front])
                runner._docker_cleanup(f"rm-{xray_client}", ["rm", "-f", xray_client])
    return {"xray_server_config": str(xray_server_config_path), "router_config": str(router_config_path), "client_config": str(client_config_path)}


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
