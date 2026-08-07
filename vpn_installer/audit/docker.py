from __future__ import annotations

import contextlib
import io
import json
import shutil
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from ..common import INSTALL_SCRIPT_PATH, ROOT_DIR
from ..diagnostics import COLLECTOR_NAMES, LOG_WINDOW_KEYS, CollectorState, DiagnosticsSnapshot, LogWindowSnapshot
from ..log_classifier import BUCKETS
from ..models import ROLE_FOREIGN, ROLE_RU
from ..render import render_all_artifacts
from .runner import (
    AUDIT_COMMAND_TIMEOUT_SECONDS,
    AUDIT_IMAGE,
    VALID_GEOIP_SRS,
    VALID_GEOIP_SRS_BASE64,
    VALID_GEOSITE_SRS,
    VALID_GEOSITE_SRS_BASE64,
    AuditFailure,
    AuditRunner,
    write_bytes,
    write_text,
)


def acceptance_snapshot_fixture(server_path: str, *, role: str = "foreign-exit") -> dict[str, object]:
    if server_path not in {"verified", "failed"}:
        raise ValueError(f"unsupported server_path verdict: {server_path}")
    overall = "verified" if server_path == "verified" else "failed"
    observed_at = datetime.now(timezone.utc).isoformat()
    component_verdicts = {
            "server_path": server_path,
            "public_front": "verified" if role == "ru-gateway" else "not-applicable",
            "public_quic": "verified" if role == "ru-gateway" else "not-applicable",
            "client_observation": "observed" if role == "ru-gateway" else "not-applicable",
            "host_integrity": "verified",
        }
    return DiagnosticsSnapshot(
        generated_at=observed_at,
        deployment="audit-install-rollback",
        role=role,
        collectors={name: CollectorState.ok(observed_at) for name in COLLECTOR_NAMES},
        log_windows={
            name: LogWindowSnapshot.collected({bucket: 0 for bucket in BUCKETS}, observed_at=observed_at)
            for name in LOG_WINDOW_KEYS
        },
        services={"sing-box": "active", "wireguard": "active", "nftables": "active", "resolver": "active", "xray": "active"},
        artifacts={"drift": "none", "files": {}},
        drift="none",
        network={"profile_mismatches": []},
        route_probes={"profile": "acceptance", "ok": server_path == "verified"},
        component_verdicts=component_verdicts,
        verdict=overall,
    ).to_dict()


def run(runner: AuditRunner) -> None:
    runner.ensure_audit_image()
    runner.record("docker-unmanaged-remove-purge-render-only", lambda: test_unmanaged_remove_purge_render_only(runner))
    runner.record("docker-asset-fail-fast", lambda: test_asset_fail_fast(runner))
    runner.record("docker-install-rollback-state", lambda: test_install_rollback_state(runner))
    runner.record("docker-role-scoped-workflows", lambda: test_role_scoped_workflows(runner))


def test_unmanaged_remove_purge_render_only(runner: AuditRunner) -> dict[str, str]:
    env_path, _env = runner.create_env("unmanaged")
    container = f"audit-unmanaged-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work/assets")
        runner.docker_copy(container, INSTALL_SCRIPT_PATH, "/work/install.sh")
        runner.docker_copy(container, env_path, "/work/deployment.env")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        runner.docker_exec(
            container,
            textwrap.dedent(
                f"""\
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
                echo {VALID_GEOSITE_SRS_BASE64} | base64 -d >/work/assets/geosite-ru.srs
                echo {VALID_GEOIP_SRS_BASE64} | base64 -d >/work/assets/geoip-ru.srs
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
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            render_all_artifacts(env_path, env)
        except Exception as exc:  # noqa: BLE001
            if "Не удалось получить обязательные assets" not in str(exc):
                raise
        else:
            raise AuditFailure("Не сработал fail-fast по обязательным assets")

    assets_dir = ROOT_DIR / "out" / env["DEPLOY_NAME"] / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    write_bytes(assets_dir / "geosite-ru.srs", VALID_GEOSITE_SRS)
    write_bytes(assets_dir / "geoip-ru.srs", VALID_GEOIP_SRS)
    write_text(assets_dir / "ru-ipv4.zone", "203.0.113.0/24")
    write_text(assets_dir / "ru-ipv6.zone", "2001:db8::/32")
    with contextlib.redirect_stderr(io.StringIO()):
        render_all_artifacts(env_path, env)
    return {"env_path": str(env_path)}


def test_install_rollback_state(runner: AuditRunner) -> dict[str, str]:
    env_path, _env = runner.create_env("install-rollback", {"WG_INTERFACE": "wg-test"})
    container = f"audit-install-rollback-{runner.run_id}"
    failed_snapshot = repr(json.dumps(acceptance_snapshot_fixture("failed"), separators=(",", ":")))
    verified_snapshot = repr(json.dumps(acceptance_snapshot_fixture("verified"), separators=(",", ":")))
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, INSTALL_SCRIPT_PATH, "/work/install.sh")
        runner.docker_copy(container, env_path, "/work/deployment.env")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        runner.docker_exec(
            container,
            textwrap.dedent(
                """\
                set -euo pipefail
                export VPNSTACK_INSTALL_LIBRARY_ONLY=1
                source /work/install.sh --role foreign-exit --env-file /work/deployment.env

                test_root=/tmp/vpn-stack-transaction
                VPNSTACK_ROOT="${test_root}/etc"
                VPNSTACK_BACKUP_DIR="${VPNSTACK_ROOT}/backups"
                VPNSTACK_BASELINE_DIR="${VPNSTACK_BACKUP_DIR}/baseline"
                VPNSTACK_SNAPSHOT_DIR="${VPNSTACK_BACKUP_DIR}/snapshots"
                VPNSTACK_RELEASES_DIR="${VPNSTACK_ROOT}/releases"
                VPNSTACK_ROLE_FILE="${VPNSTACK_ROOT}/role"
                VPNSTACK_DEPLOYMENT_FILE="${VPNSTACK_ROOT}/deployment.env"
                VPNSTACK_INSTALLED_AT_FILE="${VPNSTACK_ROOT}/installed_at"
                VPNSTACK_REMOVED_AT_FILE="${VPNSTACK_ROOT}/removed_at"
                VPNSTACK_RENDER_MANIFEST_FILE="${VPNSTACK_ROOT}/render-manifest.json"
                VPNSTACK_ADMIN_AUTH_FILE="${VPNSTACK_ROOT}/admin-auth.json"
                VPNSTACK_CURRENT_RELEASE="${VPNSTACK_ROOT}/current"
                VPNSTACK_PREVIOUS_RELEASE="${VPNSTACK_ROOT}/previous"
                VPNSTACK_ACCEPTANCE_FILE="${VPNSTACK_ROOT}/acceptance.json"
                VPNSTACK_FAILED_ACCEPTANCE_FILE="${VPNSTACK_ROOT}/last-failed-acceptance.json"
                SINGBOX_CONFIG_PATH="${test_root}/sing-box/config.json"
                SINGBOX_BASE_CONFIG_PATH="${VPNSTACK_ROOT}/sing-box.base.json"
                WG_CONFIG_PATH="${test_root}/wireguard/wg-test.conf"
                RESOLVED_DROPIN_PATH="${test_root}/resolved/90-vpn-stack.conf"
                RESOLV_CONF_PATH="${VPNSTACK_ROOT}/resolv.conf"
                RESOLVED_STUB_PATH="${test_root}/run/systemd/resolve/stub-resolv.conf"
                HEALTH_STATE_PATH="${test_root}/state/health-state.json"
                LEGACY_ADAPTIVE_ROUTING_RULES_PATH="${test_root}/state/adaptive-routing-rules.json"
                LEGACY_DATAPLANE_CACHE_PATH="${test_root}/state/dataplane-cache.env"
                RULESET_DIR="${test_root}/state/rules"

                SYSTEMCTL_LOG="${test_root}/systemctl.log"
                systemctl() {
                  printf '%s\n' "$*" >>"${SYSTEMCTL_LOG}"
                  if [[ "${SYSTEMCTL_FAIL_DAEMON_RELOAD:-0}" == "1" && "$*" == "daemon-reload" ]]; then
                    return 1
                  fi
                  if [[ "$1" == "is-enabled" && ( "$*" == *"test-disabled.service"* || "$*" == *"vpn-stack-health.service"* ) ]]; then
                    return 1
                  fi
                  if [[ "$1" == "is-active" && "$*" == *"test-disabled.service"* ]]; then
                    [[ "${SYSTEMCTL_FORCE_TEST_ACTIVE:-0}" == "1" ]] && return 0
                    return 1
                  fi
                  return 0
                }
                ss() {
                  if [[ "$*" == *"sport = :53"* ]]; then
                    printf 'LISTEN 0 4096 127.0.0.53%%lo:53 0.0.0.0:*\n'
                    return 0
                  fi
                  return 1
                }
                sysctl() { return 0; }

                mkdir -p "${VPNSTACK_ROOT}"
                printf 'ru-gateway\n' >"${VPNSTACK_ROLE_FILE}"
                printf '2026-08-06T00:00:00Z\n' >"${VPNSTACK_INSTALLED_AT_FILE}"
                printf 'DEPLOY_NAME="install-rollback"\n' >"${VPNSTACK_DEPLOYMENT_FILE}"
                if (ROLE=foreign-exit; DEPLOY_NAME=install-rollback; require_matching_install_identity) 2>/tmp/role-mismatch.err; then
                  exit 74
                fi
                grep -q 'Installed role mismatch' /tmp/role-mismatch.err
                : >"${VPNSTACK_ROLE_FILE}"
                if (ROLE=foreign-exit; DEPLOY_NAME=install-rollback; require_matching_install_identity) 2>/tmp/missing-role.err; then
                  exit 75
                fi
                grep -q 'found missing' /tmp/missing-role.err
                rm -f "${VPNSTACK_ROLE_FILE}" "${VPNSTACK_INSTALLED_AT_FILE}" "${VPNSTACK_DEPLOYMENT_FILE}"

                WAN_INTERFACE=""
                detect_primary_interface() { printf 'ens7\n'; }
                ensure_target_wan_interface
                grep -Fxq 'WAN_INTERFACE="ens7"' "${NORMALIZED_ENV_FILE}"
                wan_render="${test_root}/wan-render"
                render_role_with_python "${wan_render}"
                grep -Fq 'oifname "ens7"' "${wan_render}/nftables.conf"

                paths="$(managed_paths)"
                grep -Fxq "${VPNSTACK_RENDER_MANIFEST_FILE}" <<<"${paths}"
                grep -Fxq "${VPNSTACK_ADMIN_AUTH_FILE}" <<<"${paths}"
                grep -Fxq "${HEALTH_STATE_PATH}" <<<"${paths}"

                mkdir -p "${VPNSTACK_RELEASES_DIR}/old" "${VPNSTACK_RELEASES_DIR}/new" "$(dirname "${SINGBOX_CONFIG_PATH}")" "$(dirname "${HEALTH_STATE_PATH}")" "${RULESET_DIR}" "$(dirname "${RESOLVED_STUB_PATH}")"
                printf 'old manifest\n' >"${VPNSTACK_RENDER_MANIFEST_FILE}"
                printf 'old config\n' >"${SINGBOX_CONFIG_PATH}"
                printf 'old health\n' >"${HEALTH_STATE_PATH}"
                printf 'old auth\n' >"${VPNSTACK_ADMIN_AUTH_FILE}"
                printf 'old rules\n' >"${RULESET_DIR}/rules.srs"
                printf 'old resolver\n' >"${RESOLVED_STUB_PATH}"
                configure_system_resolver
                test -L "${RESOLV_CONF_PATH}"
                grep -Fxq 'restart systemd-resolved.service' "${SYSTEMCTL_LOG}"

                printf 'same resolver config\n' >"${VPNSTACK_RELEASES_DIR}/old/resolved-vpn-stack.conf"
                printf 'same resolver config\n' >"${VPNSTACK_RELEASES_DIR}/new/resolved-vpn-stack.conf"
                ln -s "${VPNSTACK_RELEASES_DIR}/old" "${VPNSTACK_PREVIOUS_RELEASE}"
                ln -s "${VPNSTACK_RELEASES_DIR}/new" "${VPNSTACK_CURRENT_RELEASE}"
                : >"${SYSTEMCTL_LOG}"
                configure_system_resolver
                ! grep -Fq 'restart systemd-resolved.service' "${SYSTEMCTL_LOG}"
                printf 'changed resolver config\n' >"${VPNSTACK_RELEASES_DIR}/new/resolved-vpn-stack.conf"
                configure_system_resolver
                grep -Fxq 'restart systemd-resolved.service' "${SYSTEMCTL_LOG}"
                rm -f "${VPNSTACK_CURRENT_RELEASE}" "${VPNSTACK_PREVIOUS_RELEASE}"
                ln -s "${VPNSTACK_RELEASES_DIR}/old" "${VPNSTACK_CURRENT_RELEASE}"

                create_revision_snapshot
                printf 'new manifest\n' >"${VPNSTACK_RENDER_MANIFEST_FILE}"
                printf 'new config\n' >"${SINGBOX_CONFIG_PATH}"
                rm -f "${HEALTH_STATE_PATH}"
                printf 'new auth\n' >"${VPNSTACK_ADMIN_AUTH_FILE}"
                printf 'new rules\n' >"${RULESET_DIR}/rules.srs"
                rm -f "${RESOLV_CONF_PATH}"
                printf 'new resolver\n' >"${RESOLV_CONF_PATH}"
                ln -s "${VPNSTACK_RELEASES_DIR}/new" "${VPNSTACK_ROOT}/.current.tmp"
                mv -Tf "${VPNSTACK_ROOT}/.current.tmp" "${VPNSTACK_CURRENT_RELEASE}"
                INSTALL_MUTATION_STARTED=1
                restore_install_state_on_error

                grep -Fxq 'old manifest' "${VPNSTACK_RENDER_MANIFEST_FILE}"
                grep -Fxq 'old config' "${SINGBOX_CONFIG_PATH}"
                grep -Fxq 'old health' "${HEALTH_STATE_PATH}"
                grep -Fxq 'old auth' "${VPNSTACK_ADMIN_AUTH_FILE}"
                grep -Fxq 'old rules' "${RULESET_DIR}/rules.srs"
                test -L "${RESOLV_CONF_PATH}"
                grep -Fxq 'old resolver' "${RESOLV_CONF_PATH}"
                test "$(readlink -f "${VPNSTACK_CURRENT_RELEASE}")" = "${VPNSTACK_RELEASES_DIR}/old"
                grep -Fxq 'daemon-reload' "${SYSTEMCTL_LOG}"
                grep -Eq '^(start|restart) sing-box$' "${SYSTEMCTL_LOG}"
                if grep -Fxq 'disable vpn-stack-health.service' "${SYSTEMCTL_LOG}"; then
                  exit 77
                fi
                apply_service_restore_flags test-disabled.service 0 0
                SYSTEMCTL_FORCE_TEST_ACTIVE=1
                if apply_service_restore_flags test-disabled.service 0 0; then
                  exit 76
                fi
                SYSTEMCTL_FORCE_TEST_ACTIVE=0

                SYSTEMCTL_FAIL_DAEMON_RELOAD=1
                if restore_install_snapshot "${CURRENT_ROLLBACK_DIR}"; then
                  exit 72
                fi
                SYSTEMCTL_FAIL_DAEMON_RELOAD=0

                incomplete_snapshot="${VPNSTACK_SNAPSHOT_DIR}/incomplete"
                mkdir -p "${incomplete_snapshot}"
                cp "${CURRENT_ROLLBACK_DIR}/service-state.env" "${incomplete_snapshot}/service-state.env"
                if restore_install_snapshot "${incomplete_snapshot}"; then
                  exit 73
                fi

                rm -rf "${VPNSTACK_SNAPSHOT_DIR}"
                mkdir -p "${VPNSTACK_SNAPSHOT_DIR}"
                for i in $(seq 1 12); do
                  mkdir "${VPNSTACK_SNAPSHOT_DIR}/snapshot-${i}"
                  touch "${VPNSTACK_SNAPSHOT_DIR}/snapshot-${i}/.complete"
                  touch -d "@${i}" "${VPNSTACK_SNAPSHOT_DIR}/snapshot-${i}"
                done
                prune_revision_snapshots 3
                test "$(find "${VPNSTACK_SNAPSHOT_DIR}" -mindepth 1 -maxdepth 1 -type d | wc -l)" = 3
                test -d "${VPNSTACK_SNAPSHOT_DIR}/snapshot-12"
                test ! -e "${VPNSTACK_SNAPSHOT_DIR}/snapshot-1"

                source_dir="${test_root}/source"
                mkdir -p "${source_dir}"
                printf '{"release_id":"release-1"}\n' >"${source_dir}/render-manifest.json"
                printf 'wg\n' >"${source_dir}/wg-test.conf"
                printf 'payload\n' >"${source_dir}/payload"
                mkdir -p "${VPNSTACK_RELEASES_DIR}/release-1"
                printf 'legacy release\n' >"${VPNSTACK_RELEASES_DIR}/release-1/marker"
                ASSETS_DIR=""
                stage_release "${source_dir}"
                test "$(cat "${VPNSTACK_RELEASES_DIR}/release-1/marker")" = 'legacy release'
                staged="${STAGED_RELEASE_DIR}"
                publish_staged_release "${staged}"
                test -d "${PUBLISHED_RELEASE_DIR}"
                test "${PUBLISHED_RELEASE_DIR}" != "${VPNSTACK_RELEASES_DIR}/release-1"

                AGENT_SCRIPT_PATH="${test_root}/agent.py"
                cat >"${AGENT_SCRIPT_PATH}" <<'PY'
                import json
                print(__FAILED_ACCEPTANCE_JSON__)
                PY
                if verify_active_release; then
                  exit 71
                fi
                test -s "${VPNSTACK_FAILED_ACCEPTANCE_FILE}"
                ! find "${VPNSTACK_ROOT}" -maxdepth 1 -type f -name '.acceptance.*.json' | grep -q .

                cat >"${AGENT_SCRIPT_PATH}" <<'PY'
                import json
                print(__VERIFIED_ACCEPTANCE_JSON__)
                PY
                verify_active_release
                test -s "${VPNSTACK_ACCEPTANCE_FILE}"
                test ! -e "${VPNSTACK_FAILED_ACCEPTANCE_FILE}"
                ! find "${VPNSTACK_ROOT}" -maxdepth 1 -type f -name '.acceptance.*.json' | grep -q .
                """
            )
            .replace("__FAILED_ACCEPTANCE_JSON__", failed_snapshot)
            .replace("__VERIFIED_ACCEPTANCE_JSON__", verified_snapshot),
        )
    return {"container": container}


def prepare_mock_state(runner: AuditRunner, action: str) -> tuple[Path, Path]:
    env_path, env = runner.create_env(
        f"mock-{action}",
        {
            "WG_INTERFACE": "wg-test",
            "RU_PUBLIC_IP": "203.0.113.10",
            "FOREIGN_PUBLIC_IP": "198.51.100.20",
            "RU_GEOSITE_URL": "file:///work/fixtures/geosite-ru.srs",
            "RU_GEOIP_URL": "file:///work/fixtures/geoip-ru.srs",
        },
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
    ru_payload = acceptance_snapshot_fixture("verified", role="ru-gateway")
    ru_payload.update(
        {
            "deployment": "mock",
            "release": {"release_id": "mock-release", "policy_version": "0.11.0", "installed_at": datetime.now(timezone.utc).isoformat()},
            "host": {"hostname": "ru-host", "login_user": "root", "is_root": True, "has_sudo": True, "os_id": "ubuntu", "os_version": "24.04", "default_interface": "eth0"},
            "wg_state": {"interface": "wg0", "state": "up", "peers": []},
            "network": {"interfaces": {"eth0": {}}, "tcp_adaptation": {}},
            "front": {"listening": True, "state_counts": {}, "socket_retransmissions": 0, "rtt_ms": {}},
        }
    )
    ru_agent_snapshot = json.dumps(ru_payload, ensure_ascii=True)
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
          if [[ "$*" == *"vpn-stack-agent.py snapshot"* ]]; then
            cat <<'EOF'
        """
    ) + ru_agent_snapshot + textwrap.dedent(
        """
        EOF
            exit 0
          fi
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
        health_timer=active
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
            sing_box=active
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


def test_role_scoped_workflows(runner: AuditRunner) -> dict[str, str]:
    scenarios = ("status", "reinstall", "remove", "purge")
    fixtures = {action: prepare_mock_state(runner, action) for action in scenarios}
    temp_repo = runner.work_dir / "mock-role-scoped"
    deploy_dir = temp_repo / "deployments"
    state_dir = temp_repo / "state"
    deploy_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    for env_path, state_path in fixtures.values():
        shutil.copy2(env_path, deploy_dir / env_path.name)
        shutil.copy2(state_path, state_dir / state_path.name)
    write_mock_ssh_scripts(temp_repo)
    status_env, status_state = fixtures["status"]
    action_rows = [(action, fixtures[action][0].stem) for action in scenarios if action != "status"]
    driver = textwrap.dedent(
        f"""\
        import json
        from pathlib import Path

        import vpn_installer.workflows as wf

        # This scenario validates role scoping with fake ssh/scp commands. Host-key
        # enrollment is covered independently by remote unit tests.
        wf.ensure_target_host_key = lambda *args, **kwargs: None
        wf.verify_postcutover = lambda *args, **kwargs: None

        def accepted_install(target, _wg_interface):
            role_dir = "ru" if target.role == "ru-gateway" else "foreign"
            manifests = list(Path("/work/out").glob(f"*/preview/{{role_dir}}/render-manifest.json"))
            if len(manifests) != 1:
                raise RuntimeError(f"expected one rendered manifest for {{target.role}}, got {{len(manifests)}}")
            manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
            release_id = manifest["release_id"]
            deployment = manifests[0].parents[2].name
            return {{
                "installed": "1", "role": target.role, "deployment_name": deployment,
                "release_id": release_id, "drift": "none", "acceptance_present": "True",
                "acceptance_release_id": release_id, "acceptance_role": target.role,
                "acceptance_deployment": deployment,
            }}

        wf.wait_for_remote_install_completion = accepted_install

        status_env = Path("/work/deployments/{status_env.name}")
        status_state = Path("/work/state/{status_state.name}")
        before = (status_env.stat().st_mtime_ns, status_state.stat().st_mtime_ns)
        status_rc = wf.status_workflow("{status_env.stem}", "ru-gateway", non_interactive=True)
        after = (status_env.stat().st_mtime_ns, status_state.stat().st_mtime_ns)
        if before != after:
            raise RuntimeError("status mutated deployment env or state")
        print(f"scenario=status rc={{status_rc}}", flush=True)

        for action, deployment in {action_rows!r}:
            rc = wf.remote_action_workflow(
                deployment,
                "ru-gateway",
                action,
                non_interactive=True,
                yes=True,
            )
            print(f"scenario={{action}} rc={{rc}}", flush=True)
        """
    )
    driver_path = temp_repo / "driver.py"
    write_text(driver_path, driver)
    container = f"audit-role-scoped-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work/deployments /work/state /work/fakebin /work/fixtures")
        runner.docker_copy(container, INSTALL_SCRIPT_PATH, "/work/install.sh")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        for env_path, state_path in fixtures.values():
            runner.docker_copy(container, deploy_dir / env_path.name, f"/work/deployments/{env_path.name}")
            runner.docker_copy(container, state_dir / state_path.name, f"/work/state/{state_path.name}")
        runner.docker_copy(container, temp_repo / "fakebin" / "ssh", "/work/fakebin/ssh")
        runner.docker_copy(container, temp_repo / "fakebin" / "scp", "/work/fakebin/scp")
        runner.docker_copy(container, driver_path, "/work/driver.py")
        runner.docker_exec(
            container,
            textwrap.dedent(
                f"""\
                set -euo pipefail
                echo {VALID_GEOSITE_SRS_BASE64} | base64 -d >/work/fixtures/geosite-ru.srs
                echo {VALID_GEOIP_SRS_BASE64} | base64 -d >/work/fixtures/geoip-ru.srs
                chmod +x /work/fakebin/ssh /work/fakebin/scp
                : > /work/calls.log
                PATH=/work/fakebin:$PATH PYTHONPATH=/work python3 /work/driver.py >/work/driver.out
                grep -q "scenario=status rc=0" /work/driver.out
                grep -q "scenario=reinstall rc=0" /work/driver.out
                grep -q "scenario=remove rc=0" /work/driver.out
                grep -q "scenario=purge rc=0" /work/driver.out
                grep -q "ru.example" /work/calls.log
                if grep -q "foreign.example" /work/calls.log; then
                  exit 42
                fi
                grep -q "vpn-stack-agent.py snapshot" /work/calls.log
                grep -q -- "--action reinstall" /work/calls.log
                grep -q -- "--action remove" /work/calls.log
                grep -q -- "--action purge" /work/calls.log
                """
            ),
            timeout_seconds=AUDIT_COMMAND_TIMEOUT_SECONDS,
        )
    return {"scenarios": ",".join(scenarios), "container": container}
