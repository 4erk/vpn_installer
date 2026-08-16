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
from ..render import render_all_artifacts
from ..topology import (
    CAP_INTERSERVER_CLIENT,
    CAP_PUBLIC_FRONT,
    CAP_WEB_ADMIN,
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
    NodeSpec,
    TopologySpec,
)
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

SCHEMA2_MIGRATION_TIMEOUT_SECONDS = 45
TRANSACTION_ACCEPTANCE_TIMEOUT_SECONDS = 45
TRANSACTION_ACCEPTANCE_GATES = (
    "acceptance-marker-path",
    "failed-acceptance-evidence",
    "single-rollback-without-wireguard",
    "node-mismatch-rejection",
    "sigkill-production-cutover-reconciliation",
    "schema2-rollback-verification",
)


def acceptance_snapshot_fixture(
    server_path: str,
    *,
    topology: str = TOPOLOGY_DUAL,
    node_id: str = NODE_EXIT,
    gateway_location: str = LOCATION_RU,
) -> dict[str, object]:
    if server_path not in {"verified", "failed"}:
        raise ValueError(f"unsupported server_path verdict: {server_path}")
    gateway_ip = "203.0.113.10" if gateway_location == LOCATION_RU else "198.51.100.10"
    topology_spec = TopologySpec(
        mode=topology,
        gateway=NodeSpec(NODE_GATEWAY, gateway_location, gateway_ip),
        exit=NodeSpec(NODE_EXIT, LOCATION_FOREIGN, "198.51.100.20") if topology == TOPOLOGY_DUAL else None,
    )
    plan = topology_spec.plan(node_id)
    overall = "verified" if server_path == "verified" else "failed"
    observed_at = datetime.now(timezone.utc).isoformat()
    component_verdicts = {
        "server_path": server_path,
        "public_front": "verified" if CAP_PUBLIC_FRONT in plan.capabilities else "not-applicable",
        "public_quic": "verified" if CAP_PUBLIC_FRONT in plan.capabilities else "not-applicable",
        "client_observation": "observed" if CAP_PUBLIC_FRONT in plan.capabilities else "not-applicable",
        "host_integrity": "verified",
    }
    collectors = {name: CollectorState.ok(observed_at) for name in COLLECTOR_NAMES}
    if not plan.requires_wireguard:
        collectors["wireguard"] = CollectorState.not_applicable("node has no interserver capability")
        collectors["transport"] = CollectorState.not_applicable("node has no interserver capability")
    if not plan.requires_xray:
        collectors["front"] = CollectorState.not_applicable("node has no public-front capability")
    services = {
        "sing-box": "active",
        "nftables": "active",
        "resolver": "active",
        "health_timer": "active",
    }
    if plan.requires_wireguard:
        services["wireguard"] = "active"
    if plan.requires_xray:
        services["xray"] = "active"
    if CAP_WEB_ADMIN in plan.capabilities:
        services["admin"] = "active"
    if CAP_INTERSERVER_CLIENT in plan.capabilities:
        services["transport"] = "active"
    return DiagnosticsSnapshot(
        generated_at=observed_at,
        deployment="audit-install-rollback",
        topology=topology_spec.mode,
        node_id=plan.node_id,
        location=plan.location,
        capabilities=tuple(sorted(plan.capabilities)),
        collectors=collectors,
        log_windows={
            name: LogWindowSnapshot.collected({bucket: 0 for bucket in BUCKETS}, observed_at=observed_at)
            for name in LOG_WINDOW_KEYS
        },
        services=services,
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
    runner.record("docker-schema2-to-schema3-migration", lambda: test_schema2_to_schema3_migration(runner))
    runner.record("docker-install-rollback-state", lambda: test_install_rollback_state(runner))
    runner.record("docker-node-scoped-workflows", lambda: test_node_scoped_workflows(runner))


def schema2_fixture_builder_text() -> str:
    return textwrap.dedent(
        """\
        from __future__ import annotations

        import hashlib
        import json
        import shutil
        import sys
        from pathlib import Path

        from vpn_installer.config import load_env_file
        from vpn_installer.legacy_install_contract import _COMMON_ARTIFACT_PATHS, _GATEWAY_ARTIFACT_PATHS
        from vpn_installer.topology import LEGACY_ROLE_FOREIGN, LEGACY_ROLE_RU


        def digest(payload: bytes) -> str:
            return hashlib.sha256(payload).hexdigest()


        role = sys.argv[1]
        current = Path(sys.argv[2])
        target_env = Path(sys.argv[3])
        if role not in {LEGACY_ROLE_RU, LEGACY_ROLE_FOREIGN}:
            raise SystemExit(f"unsupported fixture role: {role}")
        if current.exists():
            shutil.rmtree(current)
        current.mkdir(parents=True)

        deployment = load_env_file(target_env)["DEPLOY_NAME"]
        env_payload = f'DEPLOY_NAME="{deployment}"\\n'.encode()
        deployment_env = Path("/etc/vpn-stack/deployment.env")
        deployment_env.parent.mkdir(parents=True, exist_ok=True)
        deployment_env.write_bytes(env_payload)

        paths = dict(_COMMON_ARTIFACT_PATHS)
        if role == LEGACY_ROLE_RU:
            paths.update(_GATEWAY_ARTIFACT_PATHS)
        paths["wg0.conf"] = "/etc/wireguard/wg0.conf"
        artifacts = {}
        for name, manifest_path in paths.items():
            if name == "vpn-stack-agent.py":
                payload = (
                    "from pathlib import Path\\n"
                    "import json\\n"
                    "import sys\\n"
                    "if sys.argv[1:] == ['network-apply']:\\n"
                    "    Path('/work/result/schema2-network-apply.marker').write_text('applied\\\\n', encoding='utf-8')\\n"
                    "    print(json.dumps({'verdict': 'applied'}))\\n"
                    "else:\\n"
                    "    raise SystemExit('unsupported fixture command')\\n"
                ).encode()
            else:
                payload = f"{role}:artifact:{name}\\n".encode()
            (current / name).write_bytes(payload)
            artifacts[name] = {
                "sha256": digest(payload),
                "install_path": manifest_path,
                "required": True,
            }
            effective_paths = [manifest_path]
            if role == LEGACY_ROLE_FOREIGN and name == "sing-box.json":
                effective_paths.append("/etc/sing-box/config.json")
            for effective_path in effective_paths:
                live = Path(effective_path)
                live.parent.mkdir(parents=True, exist_ok=True)
                live.write_bytes(payload)

        asset_names = {"geoip-ru.srs", "geosite-ru.srs"} if role == LEGACY_ROLE_RU else set()
        assets = {}
        for name in asset_names:
            payload = f"{role}:asset:{name}\\n".encode()
            release_asset = current / "assets" / name
            release_asset.parent.mkdir(parents=True, exist_ok=True)
            release_asset.write_bytes(payload)
            install_path = f"/var/lib/vpn-stack/rules/{name}"
            live = Path(install_path)
            live.parent.mkdir(parents=True, exist_ok=True)
            live.write_bytes(payload)
            assets[name] = {"sha256": digest(payload), "install_path": install_path, "required": True}

        binary_services = {"sing-box": "sing-box.service"}
        if role == LEGACY_ROLE_RU:
            binary_services["xray"] = "vpn-stack-xray.service"
        binaries = {}
        for name, service in binary_services.items():
            payload = f"{role}:binary:{name}\\n".encode()
            binary = current / "bin" / name
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(payload)
            binaries[name] = {
                "version": "1.2.3",
                "archive_sha256": digest(f"{role}:archive:{name}".encode()),
                "sha256": digest(payload),
                "path": f"/etc/vpn-stack/current/bin/{name}",
                "service": service,
            }

        manifest = {
            "schema_version": 2,
            "version": "0.19.10",
            "release_id": "0.19.10-0123456789ab",
            "role": role,
            "env_sha256": digest(env_payload),
            "artifacts": artifacts,
            "assets": assets,
            "binaries": binaries,
        }
        (current / "render-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        """
    )


def schema2_migration_acceptance_script() -> str:
    return textwrap.dedent(
        """\
        set -euo pipefail
        export LC_ALL=C
        support() { PYTHONPATH=/work python3 -m vpn_installer.install_support "$@"; }
        meta_value() { awk -F '\t' -v key="$2" '$1 == key { print $2 }' "$1/meta.tsv"; }

        gateway_release=/etc/vpn-stack/releases/schema2-gateway
        gateway_contract=/work/contracts/schema2-gateway
        single_bundle=/work/schema3-single-gateway
        single_contract=/work/contracts/schema3-single-gateway
        mkdir -p /work/contracts /work/assets
        echo __GEOSITE_SRS_BASE64__ | base64 -d >/work/assets/geosite-ru.srs
        echo __GEOIP_SRS_BASE64__ | base64 -d >/work/assets/geoip-ru.srs

        PYTHONPATH=/work python3 /work/build-schema2.py ru-gateway "$gateway_release" /work/single.env
        support adapt-schema2 \
          --current-release "$gateway_release" \
          --deployment-env /etc/vpn-stack/deployment.env \
          --contract-dir "$gateway_contract"
        support render-node \
          --node gateway \
          --env-file /work/single.env \
          --assets-dir /work/assets \
          --output-dir "$single_bundle"
        support validate-bundle \
          --bundle "$single_bundle" \
          --expected-node gateway \
          --external-assets /work/assets \
          --require-assets \
          --contract-dir "$single_contract"

        test "$(meta_value "$gateway_contract" schema_version)" = 2
        test "$(meta_value "$gateway_contract" topology)" = dual
        test "$(meta_value "$gateway_contract" node_id)" = gateway
        test "$(meta_value "$single_contract" schema_version)" = 3
        test "$(meta_value "$single_contract" topology)" = single
        test "$(meta_value "$single_contract" node_id)" = gateway
        test "$(meta_value "$gateway_contract" deployment)" = "$(meta_value "$single_contract" deployment)"
        test "$(meta_value "$gateway_contract" compatibility_adapter)" = schema2-install-contract
        test -n "$(meta_value "$gateway_contract" remove_in)"
        for contract_meta in /work/contracts/*/meta.tsv; do
          if test "$(meta_value "${contract_meta%/meta.tsv}" schema_version)" = 3 \
            && test "$(meta_value "${contract_meta%/meta.tsv}" topology)" = dual; then
            echo "intermediate dual schema-3 contract is not allowed" >&2
            exit 60
          fi
        done

        cut -f2 "$gateway_contract/artifacts.tsv" | sort -u >/work/schema2.paths
        cut -f2 "$single_contract/artifacts.tsv" | sort -u >/work/schema3.paths
        comm -23 /work/schema2.paths /work/schema3.paths >/work/retired.paths
        cut -f2 "$gateway_contract/services.tsv" | sort -u >/work/schema2.services
        cut -f2 "$single_contract/services.tsv" | sort -u >/work/schema3.services
        comm -23 /work/schema2.services /work/schema3.services >/work/retired.services
        grep -Fq $'wg0.conf\t/etc/wireguard/wg0.conf\tmanaged\t' "$gateway_contract/artifacts.tsv"
        grep -Fxq $'transport\tvpn-stack-transport.service\tmanaged' "$gateway_contract/services.tsv"
        grep -Fxq /etc/wireguard/wg0.conf /work/retired.paths
        grep -Fxq /usr/local/lib/vpn-stack/interserver_transport.py /work/retired.paths
        grep -Fxq wg-quick@wg0.service /work/retired.services
        grep -Fxq vpn-stack-transport.service /work/retired.services

        printf 'corrupt\n' >/etc/xray/config.json
        corrupt_contract=/work/contracts/corrupt
        if support adapt-schema2 \
          --current-release "$gateway_release" \
          --deployment-env /etc/vpn-stack/deployment.env \
          --contract-dir "$corrupt_contract" >/work/corrupt.out 2>/work/corrupt.err; then
          echo "corrupt schema-2 install was accepted" >&2
          exit 61
        fi
        grep -Fq 'owned live path was modified: /etc/xray/config.json' /work/corrupt.err
        test ! -d "$corrupt_contract" || test -z "$(find "$corrupt_contract" -type f -print -quit)"

        foreign_release=/etc/vpn-stack/releases/schema2-foreign
        foreign_contract=/work/contracts/schema2-foreign
        PYTHONPATH=/work python3 /work/build-schema2.py foreign-exit "$foreign_release" /work/single.env
        cmp -s "$foreign_release/sing-box.json" /etc/vpn-stack/sing-box.base.json
        cmp -s "$foreign_release/sing-box.json" /etc/sing-box/config.json
        support adapt-schema2 \
          --current-release "$foreign_release" \
          --deployment-env /etc/vpn-stack/deployment.env \
          --contract-dir "$foreign_contract"
        grep -Fq $'sing-box.json\t/etc/sing-box/config.json\tmanaged\t' "$foreign_contract/artifacts.tsv"
        grep -Fq $'sing-box.json\t/etc/vpn-stack/sing-box.base.json\tmanaged\t' "$foreign_contract/artifacts.tsv"

        mkdir -p /work/result
        cp /work/retired.paths /work/retired.services /work/corrupt.err /work/result/
        cp "$gateway_contract/meta.tsv" /work/result/schema2-gateway-meta.tsv
        cp "$single_contract/meta.tsv" /work/result/schema3-single-gateway-meta.tsv
        cp "$foreign_contract/artifacts.tsv" /work/result/schema2-foreign-artifacts.tsv
        """
    ).replace("__GEOSITE_SRS_BASE64__", VALID_GEOSITE_SRS_BASE64).replace(
        "__GEOIP_SRS_BASE64__", VALID_GEOIP_SRS_BASE64
    )


def test_schema2_to_schema3_migration(runner: AuditRunner) -> dict[str, str]:
    env_path, env = runner.create_env(
        "schema2-migration",
        topology=TOPOLOGY_SINGLE,
        gateway_location=LOCATION_RU,
    )
    fixture_builder = runner.work_dir / "schema2-migration" / "build-schema2.py"
    write_text(fixture_builder, schema2_fixture_builder_text())
    result_dir = runner.work_dir / "schema2-migration-result"
    container = f"audit-schema2-migration-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        runner.docker_copy(container, env_path, "/work/single.env")
        runner.docker_copy(container, fixture_builder, "/work/build-schema2.py")
        runner.docker_exec(
            container,
            schema2_migration_acceptance_script(),
            timeout_seconds=SCHEMA2_MIGRATION_TIMEOUT_SECONDS,
        )
        runner.docker_cp_from(container, "/work/result", result_dir)
    return {
        "container": container,
        "deployment": env["DEPLOY_NAME"],
        "transition": "schema2-dual-gateway->schema3-single-gateway",
        "artifacts": str(result_dir),
    }


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
                if /work/install.sh --node gateway --action remove >/tmp/remove.out 2>/tmp/remove.err; then
                  exit 31
                fi
                grep -q "no current release is installed" /tmp/remove.err
                test "$(cat /etc/nftables.conf)" = dummy
                if /work/install.sh --node gateway --action purge >/tmp/purge.out 2>/tmp/purge.err; then
                  exit 32
                fi
                grep -q "no current release is installed" /tmp/purge.err
                test "$(cat /etc/nftables.conf)" = dummy
                echo {VALID_GEOSITE_SRS_BASE64} | base64 -d >/work/assets/geosite-ru.srs
                echo {VALID_GEOIP_SRS_BASE64} | base64 -d >/work/assets/geoip-ru.srs
                echo 203.0.113.0/24 >/work/assets/ru-ipv4.zone
                echo 2001:db8::/32 >/work/assets/ru-ipv6.zone
                mkdir -p /work/out
                /work/install.sh --node gateway --env-file /work/deployment.env --assets-dir /work/assets --render-only --output-dir /work/out/gateway >/dev/null
                test -s /work/out/gateway/sing-box.json
                /work/install.sh --node exit --env-file /work/deployment.env --assets-dir /work/assets --render-only --output-dir /work/out/exit >/dev/null
                test -s /work/out/exit/sing-box.json
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


def transaction_rollback_acceptance_script(verified_snapshot: str) -> str:
    return (
        textwrap.dedent(
            r"""
            set -euo pipefail
            export LC_ALL=C
            support() { PYTHONPATH=/work python3 -m vpn_installer.install_support "$@"; }
            pass_gate() { printf '%s\tpassed\n' "$1" >>/work/result/gates.tsv; }

            mkdir -p /work/assets /work/result
            : >/work/result/gates.tsv
            echo __GEOSITE_SRS_BASE64__ | base64 -d >/work/assets/geosite-ru.srs
            echo __GEOIP_SRS_BASE64__ | base64 -d >/work/assets/geoip-ru.srs
            single_bundle=/work/schema3-single-gateway
            single_contract=/work/schema3-single-contract
            support render-node \
              --node gateway \
              --env-file /work/deployment.env \
              --assets-dir /work/assets \
              --output-dir "$single_bundle"
            support validate-bundle \
              --bundle "$single_bundle" \
              --expected-node gateway \
              --external-assets /work/assets \
              --require-assets \
              --contract-dir "$single_contract"

            export VPNSTACK_ROOT=/etc/vpn-stack
            export VPNSTACK_INSTALL_LIBRARY_ONLY=1
            export PYTHON_BIN=python3
            export SYSTEMCTL_BIN=systemctl
            source /work/install.sh
            NODE=gateway
            SYSTEMCTL_LOG=/work/systemctl.log
            : >"$SYSTEMCTL_LOG"
            systemctl() {
              printf '%s\n' "$*" >>"$SYSTEMCTL_LOG"
              local action="${1:-}"
              local unit="${2:-}"
              if [[ "$action" == daemon-reload && "${SIGKILL_AFTER_CURRENT:-0}" == 1 && -L "$VPNSTACK_CURRENT_RELEASE" ]]; then
                if [[ "$(manifest_schema "$VPNSTACK_CURRENT_RELEASE/render-manifest.json")" == 3 ]]; then
                  printf 'after-current-before-acceptance\n' >/work/result/crash-window.marker
                  while true; do :; done
                fi
              fi
              if [[ "$action" == is-active && "$unit" == --quiet ]]; then
                unit="${3:-}"
              fi
              case "$action" in
                is-enabled)
                  if [[ "$unit" == vpn-stack-admin.service ]]; then
                    printf 'disabled\n'
                  else
                    printf 'enabled\n'
                  fi
                  ;;
                is-active)
                  if [[ "$unit" == vpn-stack-admin.service ]]; then
                    [[ "${2:-}" == --quiet ]] || printf 'inactive\n'
                    return 3
                  fi
                  [[ "${2:-}" == --quiet ]] || printf 'active\n'
                  ;;
              esac
              return 0
            }
            sysctl() {
              [[ "${1:-}" != "-n" ]] || printf '0\n'
              return 0
            }

            agent_path="$(contract_artifact_path "$single_contract" vpn-stack-agent.py)"
            mkdir -p "$(dirname "$agent_path")" "$VPNSTACK_ROOT"
            cat >"$agent_path" <<'PY'
            import json
            print(__VERIFIED_SNAPSHOT__)
            PY
            printf 'stale-failure\n' >"$VPNSTACK_FAILED_ACCEPTANCE_PATH"
            PUBLISHED_RELEASE_DIR="$single_bundle"
            verify_active_release "$single_contract"
            test "$VPNSTACK_ACCEPTANCE_PATH" = /etc/vpn-stack/last-acceptance.json
            test -s "$VPNSTACK_ACCEPTANCE_PATH"
            test ! -e "$VPNSTACK_ROOT/acceptance.json"
            test ! -e "$VPNSTACK_FAILED_ACCEPTANCE_PATH"
            ! find "$VPNSTACK_ROOT" -maxdepth 1 -type f -name '.acceptance.*.json' | grep -q .
            pass_gate acceptance-marker-path

            cat >"$agent_path" <<'PY'
            import json
            payload = json.loads(__VERIFIED_SNAPSHOT__)
            payload["verdict"] = "failed"
            payload["reasons"] = ["public_front=failed"]
            payload["component_verdicts"]["public_front"] = "failed"
            print(json.dumps(payload, separators=(",", ":")))
            PY
            WORK_DIR=/work/failed-acceptance-work
            mkdir -p "$WORK_DIR"
            rm -f "$VPNSTACK_FAILED_ACCEPTANCE_PATH"
            if verify_active_release "$single_contract"; then
              echo 'failed acceptance was accepted' >&2
              exit 75
            fi
            test -s "$FAILED_ACCEPTANCE_STASH"
            set +e
            (false; on_exit)
            failed_status=$?
            set -e
            test "$failed_status" = 1
            python3 - "$VPNSTACK_FAILED_ACCEPTANCE_PATH" <<'PY'
            import json
            import sys
            payload = json.load(open(sys.argv[1], encoding="utf-8"))
            assert payload["verdict"] == "failed"
            assert payload["component_verdicts"]["public_front"] == "failed"
            PY
            pass_gate failed-acceptance-evidence

            printf 'single-before\n' >"$VPNSTACK_NODE_PATH"
            single_scope=/work/single-scope
            build_operation_scope "$single_contract" "" "$single_scope"
            grep -Fxq "$VPNSTACK_ACCEPTANCE_PATH" "$single_scope/paths.list"
            ! grep -Fq '/etc/wireguard/' "$single_scope/paths.list"
            ! awk -F '\t' '$1 == "wireguard" || $1 == "transport" {found=1} END {exit !found}' "$single_scope/services.tsv"
            : >"$SYSTEMCTL_LOG"
            create_transaction_snapshots "$single_scope" "$single_bundle"
            test -L "$VPNSTACK_LATEST_SNAPSHOT"
            printf 'single-mutated\n' >"$VPNSTACK_NODE_PATH"
            rm -f "$VPNSTACK_ACCEPTANCE_PATH"
            rollback_action
            TRANSACTION_ACTIVE=0
            grep -Fxq single-before "$VPNSTACK_NODE_PATH"
            test -s "$VPNSTACK_ACCEPTANCE_PATH"
            ! grep -Fq 'wg-quick@' "$SYSTEMCTL_LOG"
            pass_gate single-rollback-without-wireguard

            schema3_check_release="$VPNSTACK_RELEASES_DIR/schema3-check"
            mkdir -p "$VPNSTACK_RELEASES_DIR"
            cp -a "$single_bundle" "$schema3_check_release"
            mkdir -p "$schema3_check_release/assets"
            cp /work/assets/geosite-ru.srs /work/assets/geoip-ru.srs "$schema3_check_release/assets/"
            ln -s "$schema3_check_release" "$VPNSTACK_CURRENT_RELEASE"
            NODE=exit
            if (current_release_contract /work/node-mismatch-contract) 2>/work/node-mismatch.err; then
              echo 'schema-3 node mismatch was accepted' >&2
              exit 74
            fi
            grep -Fq 'installed node is gateway, not exit' /work/node-mismatch.err
            test ! -d /work/node-mismatch-contract || test -z "$(find /work/node-mismatch-contract -type f -print -quit)"
            NODE=gateway
            pass_gate node-mismatch-rejection

            rm -rf -- "$VPNSTACK_ROOT"
            schema2_release="$VPNSTACK_RELEASES_DIR/schema2-old"
            PYTHONPATH=/work python3 /work/build-schema2.py ru-gateway "$schema2_release" /work/deployment.env
            ln -s "$schema2_release" "$VPNSTACK_CURRENT_RELEASE"
            schema2_release_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["release_id"])' "$schema2_release/render-manifest.json")"
            python3 - "$VPNSTACK_ACCEPTANCE_PATH" "$schema2_release_id" <<'PY'
            import json
            import sys
            from pathlib import Path

            Path(sys.argv[1]).write_text(
                json.dumps(
                    {
                        "deployment": "audit-install-rollback",
                        "node_id": "gateway",
                        "release": {"release_id": sys.argv[2]},
                    },
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            PY
            cp "$VPNSTACK_ACCEPTANCE_PATH" /work/schema2-acceptance.json
            WORK_DIR=/work/schema2-contract-work
            mkdir -p "$WORK_DIR"
            PREVIOUS_CONTRACT=""
            prepare_previous_contract
            test "$(contract_value "$PREVIOUS_CONTRACT" schema_version)" = 2
            cp "$PREVIOUS_CONTRACT/services.tsv" /work/schema2-services.tsv
            grep -Fqx $'admin\tvpn-stack-admin.service\tmanaged' /work/schema2-services.tsv

            (
              set -euo pipefail
              trap on_exit EXIT
              install_packages_from_plan() { :; }
              stage_binaries() { mkdir -p "$1/bin"; }
              validate_staged_payloads() { :; }
              verify_target_units() { :; }
              apply_planned_host_files() { :; }
              validate_bundle() {
                local bundle="$1"
                local expected_node="$2"
                local contract_dir="$3"
                local external_assets="${4:-}"
                local require_assets="${5:-0}"
                local args=(
                  validate-bundle
                  --bundle "$bundle"
                  --expected-node "$expected_node"
                  --contract-dir "$contract_dir"
                )
                [[ -z "$external_assets" ]] || args+=(--external-assets "$external_assets")
                [[ "$require_assets" != 1 ]] || args+=(--require-assets)
                rm -rf -- "$contract_dir"
                support "${args[@]}"
              }
              ACTION=reinstall
              NODE=gateway
              ENV_FILE=/work/deployment.env
              ASSETS_DIR=/work/assets
              SIGKILL_AFTER_CURRENT=1
              exec 9>"$INSTALL_LOCK_PATH"
              flock 9
              install_action
            ) >/work/crash.out 2>/work/crash.err &
            installer_pid=$!
            for _attempt in $(seq 1 100); do
              [[ ! -f /work/result/crash-window.marker ]] || break
              kill -0 "$installer_pid" 2>/dev/null || break
              sleep 0.05
            done
            grep -Fxq after-current-before-acceptance /work/result/crash-window.marker
            kill -0 "$installer_pid"
            kill -KILL "$installer_pid"
            set +e
            wait "$installer_pid"
            crash_status=$?
            set -e
            test "$crash_status" = 137
            ! grep -Fq 'Installation failed; restoring the pre-install snapshot.' /work/crash.err
            flock -n "$INSTALL_LOCK_PATH" -c true
            test "$(manifest_schema "$VPNSTACK_CURRENT_RELEASE/render-manifest.json")" = 3
            schema3_release="$(readlink -f "$VPNSTACK_CURRENT_RELEASE")"
            test "$schema3_release" != "$schema2_release"
            cmp -s "$VPNSTACK_ACCEPTANCE_PATH" /work/schema2-acceptance.json
            snapshot="$(readlink -f "$VPNSTACK_LATEST_SNAPSHOT")"
            cp "$snapshot/service-state.tsv" /work/schema2-service-state.tsv

            : >"$SYSTEMCTL_LOG"
            rollback_action >/work/schema2-rollback.out
            grep -Fq 'Rollback snapshot restored:' /work/schema2-rollback.out
            test "$(readlink -f "$VPNSTACK_CURRENT_RELEASE")" = "$schema2_release"
            test "$(manifest_schema "$VPNSTACK_CURRENT_RELEASE/render-manifest.json")" = 2
            cmp -s "$VPNSTACK_ACCEPTANCE_PATH" /work/schema2-acceptance.json
            test -f /etc/wireguard/wg0.conf
            grep -Fxq applied /work/result/schema2-network-apply.marker
            pass_gate sigkill-production-cutover-reconciliation

            verified_services=0
            admin_state_verified=0
            while IFS=$'\t' read -r name unit ownership expected_enabled expected_active; do
              [[ "$ownership" == managed || "$ownership" == borrowed ]]
              grep -Fxq "is-enabled $unit" "$SYSTEMCTL_LOG"
              grep -Fxq "is-active $unit" "$SYSTEMCTL_LOG"
              if [[ "$name" == admin ]]; then
                test "$expected_enabled" = disabled
                test "$expected_active" = inactive
                admin_state_verified=1
              fi
              verified_services=$((verified_services + 1))
            done </work/schema2-service-state.tsv
            test "$verified_services" -gt 0
            test "$admin_state_verified" = 1
            test "$(grep -c '^is-enabled ' "$SYSTEMCTL_LOG")" = "$verified_services"
            test "$(grep -c '^is-active ' "$SYSTEMCTL_LOG")" = "$verified_services"
            cp "$SYSTEMCTL_LOG" /work/result/schema2-service-verification.log
            pass_gate schema2-rollback-verification
            test "$(wc -l </work/result/gates.tsv)" = 6
            """
        ).lstrip()
        .replace("__GEOSITE_SRS_BASE64__", VALID_GEOSITE_SRS_BASE64)
        .replace("__GEOIP_SRS_BASE64__", VALID_GEOIP_SRS_BASE64)
        .replace("__VERIFIED_SNAPSHOT__", verified_snapshot)
    )


def test_install_rollback_state(runner: AuditRunner) -> dict[str, str]:
    env_path, env = runner.create_env(
        "install-rollback",
        topology=TOPOLOGY_SINGLE,
        gateway_location=LOCATION_RU,
    )
    verified_snapshot = repr(
        json.dumps(
            acceptance_snapshot_fixture(
                "verified",
                topology=TOPOLOGY_SINGLE,
                node_id=NODE_GATEWAY,
                gateway_location=LOCATION_RU,
            ),
            separators=(",", ":"),
        )
    )
    fixture_builder = runner.work_dir / "install-rollback" / "build-schema2.py"
    write_text(fixture_builder, schema2_fixture_builder_text())
    result_dir = runner.work_dir / "install-rollback-result"
    container = f"audit-install-rollback-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, INSTALL_SCRIPT_PATH, "/work/install.sh")
        runner.docker_copy(container, env_path, "/work/deployment.env")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        runner.docker_copy(container, fixture_builder, "/work/build-schema2.py")
        runner.docker_exec(
            container,
            transaction_rollback_acceptance_script(verified_snapshot),
            timeout_seconds=TRANSACTION_ACCEPTANCE_TIMEOUT_SECONDS,
        )
        runner.docker_cp_from(container, "/work/result", result_dir)
    gates_path = result_dir / "gates.tsv"
    actual_gates = gates_path.read_text(encoding="utf-8").splitlines() if gates_path.is_file() else []
    expected_gates = [f"{name}\tpassed" for name in TRANSACTION_ACCEPTANCE_GATES]
    if actual_gates != expected_gates:
        raise AuditFailure(f"transaction acceptance gates are incomplete: {actual_gates}")
    crash_marker = result_dir / "crash-window.marker"
    if not crash_marker.is_file() or crash_marker.read_text(encoding="utf-8").strip() != "after-current-before-acceptance":
        raise AuditFailure("transaction crash-window marker is missing")
    service_verification = result_dir / "schema2-service-verification.log"
    service_evidence = service_verification.read_text(encoding="utf-8") if service_verification.is_file() else ""
    if "is-enabled vpn-stack-admin.service" not in service_evidence or "is-active vpn-stack-admin.service" not in service_evidence:
        raise AuditFailure("schema-2 rollback service verification evidence is missing")
    return {
        "container": container,
        "deployment": env["DEPLOY_NAME"],
        "gates": ",".join(TRANSACTION_ACCEPTANCE_GATES),
        "artifacts": str(result_dir),
    }


def prepare_mock_state(runner: AuditRunner, action: str) -> tuple[Path, Path]:
    env_path, env = runner.create_env(
        f"mock-{action}",
        {
            "WG_INTERFACE": "wg-test",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "EXIT_PUBLIC_IP": "198.51.100.20",
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
                "schema_version": 2,
                "topology": TOPOLOGY_DUAL,
                "updated_at": "2026-04-11T00:00:00Z",
                "nodes": {
                    NODE_GATEWAY: {
                        "location": LOCATION_RU,
                        "public_ip": "203.0.113.10",
                        "ssh_host": "gateway.example",
                        "ssh_port": "22",
                        "ssh_user": "root",
                        "identity_path": "",
                        "auth_mode": "key",
                    },
                    NODE_EXIT: {
                        "location": LOCATION_FOREIGN,
                        "public_ip": "198.51.100.20",
                        "ssh_host": "exit.example",
                        "ssh_port": "22",
                        "ssh_user": "root",
                        "identity_path": "",
                        "auth_mode": "key",
                    },
                },
                "migration": {"state": "native", "legacy_inputs": []},
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    )
    return env_path, state_path


def write_mock_ssh_scripts(base_dir: Path, *, allow_exit: bool = False) -> tuple[Path, Path]:
    fakebin = base_dir / "fakebin"
    fakebin.mkdir(parents=True, exist_ok=True)
    gateway_payload = acceptance_snapshot_fixture("verified", node_id=NODE_GATEWAY)
    gateway_payload.update(
        {
            "deployment": "mock",
            "release": {"release_id": "mock-release", "policy_version": "0.11.0", "installed_at": datetime.now(timezone.utc).isoformat()},
            "host": {"hostname": "ru-host", "login_user": "root", "is_root": True, "has_sudo": True, "os_id": "ubuntu", "os_version": "24.04", "default_interface": "eth0"},
            "wg_state": {"interface": "wg0", "state": "up", "peers": []},
            "network": {"interfaces": {"eth0": {}}, "tcp_adaptation": {}},
            "front": {"listening": True, "state_counts": {}, "socket_retransmissions": 0, "rtt_ms": {}},
        }
    )
    gateway_agent_snapshot = json.dumps(gateway_payload, ensure_ascii=True)
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
        if [[ "$host" == "gateway.example" ]]; then
          if [[ "$*" == *"vpn-stack-agent.py snapshot"* ]]; then
            cat <<'EOF'
        """
    ) + gateway_agent_snapshot + textwrap.dedent(
        """
        EOF
            exit 0
          fi
          if [[ "$*" == *"vpn-stack-agent.py transport-reconcile"* ]]; then
            printf '%s\\n' '{"state":"healthy","selected":"interserver-underlay-hy2"}'
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
        topology=dual
        node=gateway
        location=ru
        installed_at=2026-04-11T00:00:00Z
        sing_box=active
        nftables=active
        wireguard=active
        health_timer=active
        EOF
          exit 0
        fi
        if [[ "$host" == "exit.example" ]]; then
        """
    )
    if allow_exit:
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
            topology=dual
            node=exit
            location=foreign
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


def test_node_scoped_workflows(runner: AuditRunner) -> dict[str, str]:
    scenarios = ("status", "reinstall", "remove", "purge")
    fixtures = {action: prepare_mock_state(runner, action) for action in scenarios}
    temp_repo = runner.work_dir / "mock-node-scoped"
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

        # This scenario validates node scoping with fake ssh/scp commands. Host-key
        # enrollment is covered independently by remote unit tests.
        wf.ensure_target_host_key = lambda *args, **kwargs: None
        wf.verify_postcutover = lambda *args, **kwargs: None

        def accepted_install(target, deployment_name, env, action, _wg_interface):
            node_id = target.node_id
            if action in {{"install", "reinstall"}}:
                manifests = list(Path("/work/out").glob(f"*/preview/{{node_id}}/render-manifest.json"))
                if len(manifests) != 1:
                    raise RuntimeError(f"expected one rendered manifest for {{node_id}}, got {{len(manifests)}}")
                manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
                if manifest.get("node_id") != node_id:
                    raise RuntimeError(f"manifest node mismatch for {{node_id}}")
            wf.install_remote_role(target, deployment_name, env, action)

        wf.install_remote_role_with_recovery = accepted_install

        status_env = Path("/work/deployments/{status_env.name}")
        status_state = Path("/work/state/{status_state.name}")
        before = (status_env.stat().st_mtime_ns, status_state.stat().st_mtime_ns)
        status_rc = wf.status_workflow("{status_env.stem}", "gateway", non_interactive=True)
        after = (status_env.stat().st_mtime_ns, status_state.stat().st_mtime_ns)
        if before != after:
            raise RuntimeError("status mutated deployment env or state")
        print(f"scenario=status rc={{status_rc}}", flush=True)

        for action, deployment in {action_rows!r}:
            rc = wf.remote_action_workflow(
                deployment,
                "gateway",
                action,
                non_interactive=True,
                yes=True,
            )
            print(f"scenario={{action}} rc={{rc}}", flush=True)
        """
    )
    driver_path = temp_repo / "driver.py"
    write_text(driver_path, driver)
    container = f"audit-node-scoped-{runner.run_id}"
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
                grep -q "gateway.example" /work/calls.log
                if grep -q "exit.example" /work/calls.log; then
                  exit 42
                fi
                grep -q "vpn-stack-agent.py snapshot" /work/calls.log
                grep -q "vpn-stack-agent.py transport-reconcile" /work/calls.log
                grep -q -- "--action reinstall" /work/calls.log
                grep -q -- "--action remove" /work/calls.log
                grep -q -- "--action purge" /work/calls.log
                """
            ),
            timeout_seconds=AUDIT_COMMAND_TIMEOUT_SECONDS,
        )
    return {"scenarios": ",".join(scenarios), "container": container}
