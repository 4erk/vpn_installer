from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

from ..common import INSTALL_SCRIPT_PATH, ROOT_DIR
from ..models import ROLE_FOREIGN, ROLE_RU
from ..render import render_all_artifacts
from .runner import AuditFailure, AuditRunner, write_text


def run(runner: AuditRunner) -> None:
    runner.ensure_audit_image()
    runner.record("docker-unmanaged-remove-purge-render-only", lambda: test_unmanaged_remove_purge_render_only(runner))
    runner.record("docker-asset-fail-fast", lambda: test_asset_fail_fast(runner))
    runner.record("docker-status-readonly-role", lambda: test_status_readonly_role(runner))
    runner.record("docker-remote-action-reinstall-role", lambda: test_remote_action_role(runner, "reinstall"))
    runner.record("docker-remote-action-remove-role", lambda: test_remote_action_role(runner, "remove"))
    runner.record("docker-remote-action-purge-role", lambda: test_remote_action_role(runner, "purge"))


def test_unmanaged_remove_purge_render_only(runner: AuditRunner) -> dict[str, str]:
    env_path, _env = runner.create_env("unmanaged")
    container = f"audit-unmanaged-{runner.run_id}"
    with runner.docker_container(container, "ubuntu:24.04"):
        runner.docker_exec(container, "mkdir -p /work/assets")
        runner.docker_copy(container, INSTALL_SCRIPT_PATH, "/work/install.sh")
        runner.docker_copy(container, env_path, "/work/deployment.env")
        runner.docker_exec(
            container,
            textwrap.dedent(
                """\
                set -euo pipefail
                chmod +x /work/install.sh
                echo dummy >/etc/nftables.conf
                if /work/install.sh --role ru-gateway --action remove >/tmp/remove.out 2>/tmp/remove.err; then
                  exit 31
                fi
                grep -q "metadata not found" /tmp/remove.err
                test "$(cat /etc/nftables.conf)" = dummy
                if /work/install.sh --role ru-gateway --action purge >/tmp/purge.out 2>/tmp/purge.err; then
                  exit 32
                fi
                grep -q "metadata not found" /tmp/purge.err
                test "$(cat /etc/nftables.conf)" = dummy
                echo x >/work/assets/geosite-ru.srs
                echo x >/work/assets/geoip-ru.srs
                echo 203.0.113.0/24 >/work/assets/ru-ipv4.zone
                echo 2001:db8::/32 >/work/assets/ru-ipv6.zone
                mkdir -p /work/out
                /work/install.sh --role ru-gateway --env-file /work/deployment.env --assets-dir /work/assets --render-only --output-dir /work/out/ru >/dev/null
                test -s /work/out/ru/sing-box.json
                /work/install.sh --role foreign-exit --env-file /work/deployment.env --assets-dir /work/assets --render-only --output-dir /work/out/foreign >/dev/null
                test -s /work/out/foreign/sing-box.json
                """
            ),
        )
    return {"container": container}


def test_asset_fail_fast(runner: AuditRunner) -> dict[str, str]:
    env_path, env = runner.create_env(
        "asset-fail-fast",
        {
            "RU_GEOSITE_URL": "http://127.0.0.1:9/geosite-ru.srs",
            "RU_GEOIP_URL": "http://127.0.0.1:9/geoip-ru.srs",
            "FOREIGN_RU_IPV4_LIST_URL": "http://127.0.0.1:9/ru-ipv4.zone",
            "FOREIGN_RU_IPV6_LIST_URL": "http://127.0.0.1:9/ru-ipv6.zone",
        },
    )
    try:
        render_all_artifacts(env_path, env)
    except Exception as exc:  # noqa: BLE001
        if "Не удалось получить обязательные assets" not in str(exc):
            raise
    else:
        raise AuditFailure("Не сработал fail-fast по обязательным assets")

    assets_dir = ROOT_DIR / "out" / env["DEPLOY_NAME"] / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    write_text(assets_dir / "geosite-ru.srs", "dummy")
    write_text(assets_dir / "geoip-ru.srs", "dummy")
    write_text(assets_dir / "ru-ipv4.zone", "203.0.113.0/24")
    write_text(assets_dir / "ru-ipv6.zone", "2001:db8::/32")
    render_all_artifacts(env_path, env)
    return {"env_path": str(env_path)}


def prepare_mock_state(runner: AuditRunner, action: str) -> tuple[Path, Path]:
    env_path, env = runner.create_env(
        f"mock-{action}",
        {"WG_INTERFACE": "wg-test", "RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"},
    )
    state_dir = runner.work_dir / f"state-{action}"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / f"{env['DEPLOY_NAME']}.json"
    write_text(
        state_path,
        json.dumps(
            {
                "updated_at": "2026-04-11T00:00:00Z",
                ROLE_RU: {
                    "public_ip": "203.0.113.10",
                    "ssh_host": "ru.example",
                    "ssh_port": "22",
                    "ssh_user": "root",
                    "identity_path": "",
                    "auth_mode": "key",
                },
                ROLE_FOREIGN: {
                    "public_ip": "198.51.100.20",
                    "ssh_host": "foreign.example",
                    "ssh_port": "22",
                    "ssh_user": "root",
                    "identity_path": "",
                    "auth_mode": "key",
                },
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    )
    return env_path, state_path


def write_mock_ssh_scripts(base_dir: Path, *, allow_foreign: bool = False) -> tuple[Path, Path]:
    fakebin = base_dir / "fakebin"
    fakebin.mkdir(parents=True, exist_ok=True)
    ssh_script = textwrap.dedent(
        """\
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'ssh|%s\\n' "$*" >> /work/calls.log
        host=""
        for arg in "$@"; do
          case "$arg" in
            *@*.*)
              host="${arg#*@}"
              break
              ;;
          esac
        done
        if [[ "$host" == "ru.example" ]]; then
          cat <<'EOF'
        login_user=root
        is_root=1
        has_sudo=1
        os_id=ubuntu
        os_version=24.04
        hostname=ru-host
        default_iface=eth0
        installed=1
        deployment_name=mock
        role=ru-gateway
        installed_at=2026-04-11T00:00:00Z
        sing_box=active
        nftables=active
        wireguard=active
        sync_timer=active
        EOF
          exit 0
        fi
        if [[ "$host" == "foreign.example" ]]; then
        """
    )
    if allow_foreign:
        ssh_script += textwrap.dedent(
            """\
              cat <<'EOF'
            login_user=root
            is_root=1
            has_sudo=1
            os_id=ubuntu
            os_version=24.04
            hostname=foreign-host
            default_iface=eth0
            installed=1
            deployment_name=mock
            role=foreign-exit
            installed_at=2026-04-11T00:00:00Z
            sing_box=inactive
            nftables=active
            wireguard=active
            sync_timer=active
            EOF
              exit 0
            """
        )
    else:
        ssh_script += "  exit 93\n"
    ssh_script += textwrap.dedent(
        """\
        fi
        echo "unexpected host: ${host:-missing}" >&2
        exit 92
        """
    )
    scp_script = textwrap.dedent(
        """\
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'scp|%s\\n' "$*" >> /work/calls.log
        exit 0
        """
    )
    ssh_path = fakebin / "ssh"
    scp_path = fakebin / "scp"
    write_text(ssh_path, ssh_script)
    write_text(scp_path, scp_script)
    ssh_path.chmod(0o755)
    scp_path.chmod(0o755)
    return ssh_path, scp_path


def test_status_readonly_role(runner: AuditRunner) -> dict[str, str]:
    env_path, state_path = prepare_mock_state(runner, "status")
    temp_repo = runner.work_dir / "mock-status"
    deploy_dir = temp_repo / "deployments"
    state_dir = temp_repo / "state"
    deploy_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(env_path, deploy_dir / env_path.name)
    shutil.copy2(state_path, state_dir / state_path.name)
    write_mock_ssh_scripts(temp_repo)
    container = f"audit-status-{runner.run_id}"
    with runner.docker_container(container, "python:3.13"):
        runner.docker_exec(container, "mkdir -p /work/deployments /work/state /work/fakebin")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        runner.docker_copy(container, deploy_dir / env_path.name, f"/work/deployments/{env_path.name}")
        runner.docker_copy(container, state_dir / state_path.name, f"/work/state/{state_path.name}")
        runner.docker_copy(container, temp_repo / "fakebin" / "ssh", "/work/fakebin/ssh")
        runner.docker_copy(container, temp_repo / "fakebin" / "scp", "/work/fakebin/scp")
        runner.docker_exec(
            container,
            textwrap.dedent(
                f"""\
                set -euo pipefail
                chmod +x /work/fakebin/ssh /work/fakebin/scp
                : > /work/calls.log
                env_before=$(stat -c %Y /work/deployments/{env_path.name})
                state_before=$(stat -c %Y /work/state/{state_path.name})
                PATH=/work/fakebin:$PATH PYTHONPATH=/work python3 -m vpn_installer status --deployment {env_path.stem} --role ru-gateway >/work/status.out
                env_after=$(stat -c %Y /work/deployments/{env_path.name})
                state_after=$(stat -c %Y /work/state/{state_path.name})
                test "$env_before" = "$env_after"
                test "$state_before" = "$state_after"
                grep -q "ru.example" /work/calls.log
                if grep -q "foreign.example" /work/calls.log; then
                  exit 41
                fi
                grep -q "wg-quick@wg-test" /work/calls.log
                """
            ),
        )
    return {"deployment": env_path.stem}


def test_remote_action_role(runner: AuditRunner, action: str) -> dict[str, str]:
    env_path, state_path = prepare_mock_state(runner, action)
    temp_repo = runner.work_dir / f"mock-{action}"
    deploy_dir = temp_repo / "deployments"
    state_dir = temp_repo / "state"
    deploy_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(env_path, deploy_dir / env_path.name)
    shutil.copy2(state_path, state_dir / state_path.name)
    write_mock_ssh_scripts(temp_repo)
    driver = textwrap.dedent(
        f"""\
        import vpn_installer.prompts as prompts
        import vpn_installer.workflows as wf

        answers = iter([True])

        def fake_prompt_yes_no(label: str, default: bool = True) -> bool:
            return next(answers)

        def fake_prompt_choice(label: str, options, default: str):
            if "подключением" in label:
                return "reuse"
            return default

        wf.prompt_yes_no = fake_prompt_yes_no
        prompts.prompt_choice = fake_prompt_choice
        rc = wf.remote_action_workflow("{env_path.stem}", "ru-gateway", "{action}")
        print(f"rc={{rc}}")
        """
    )
    driver_path = temp_repo / "driver.py"
    write_text(driver_path, driver)
    container = f"audit-{action}-{runner.run_id}"
    with runner.docker_container(container, "python:3.13"):
        runner.docker_exec(container, "mkdir -p /work/deployments /work/state /work/fakebin")
        runner.docker_copy(container, INSTALL_SCRIPT_PATH, "/work/install.sh")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        runner.docker_copy(container, deploy_dir / env_path.name, f"/work/deployments/{env_path.name}")
        runner.docker_copy(container, state_dir / state_path.name, f"/work/state/{state_path.name}")
        runner.docker_copy(container, temp_repo / "fakebin" / "ssh", "/work/fakebin/ssh")
        runner.docker_copy(container, temp_repo / "fakebin" / "scp", "/work/fakebin/scp")
        runner.docker_copy(container, driver_path, "/work/driver.py")
        runner.docker_exec(
            container,
            textwrap.dedent(
                """\
                set -euo pipefail
                chmod +x /work/fakebin/ssh /work/fakebin/scp
                : > /work/calls.log
                PATH=/work/fakebin:$PATH PYTHONPATH=/work python3 /work/driver.py >/work/driver.out
                grep -q "rc=0" /work/driver.out
                grep -q "ru.example" /work/calls.log
                if grep -q "foreign.example" /work/calls.log; then
                  exit 42
                fi
                grep -q "wg-quick@wg-test" /work/calls.log
                """
            ),
        )
    return {"action": action, "deployment": env_path.stem}
