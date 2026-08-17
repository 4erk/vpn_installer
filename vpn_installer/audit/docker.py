from __future__ import annotations

import contextlib
import io
import json
import shutil
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from .. import VERSION
from ..common import INSTALL_SCRIPT_PATH, ROOT_DIR
from ..compatibility import COMPATIBLE_INSTALLED_MIN
from ..diagnostics import (
    SCHEMA_VERSION as DIAGNOSTICS_SCHEMA_VERSION,
    COLLECTOR_NAMES,
    LOG_WINDOW_KEYS,
    CollectorState,
    DiagnosticsSnapshot,
    LogWindowSnapshot,
)
from ..log_classifier import BUCKETS
from ..manifest import INSTALL_PLAN_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION
from ..render import render_all_artifacts
from ..topology import (
    CAP_INTERSERVER_CLIENT,
    CAP_PUBLIC_FRONT,
    CAP_WEB_ADMIN,
    CONFIG_SCHEMA_VERSION,
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

COMPATIBLE_UPDATE_TIMEOUT_SECONDS = 45
TRANSACTION_ACCEPTANCE_TIMEOUT_SECONDS = 45
TRANSACTION_ACCEPTANCE_GATES = (
    "acceptance-marker-path",
    "failed-acceptance-evidence",
    "single-rollback-without-wireguard",
    "node-mismatch-rejection",
    "sigkill-production-cutover-reconciliation",
    "previous-release-rollback-verification",
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
    runner.record("docker-compatible-update", lambda: test_compatible_update(runner))
    runner.record("docker-install-rollback-state", lambda: test_install_rollback_state(runner))
    runner.record("docker-node-scoped-workflows", lambda: test_node_scoped_workflows(runner))


def previous_release_fixture_builder_text() -> str:
    return textwrap.dedent(
        """\
        from __future__ import annotations

        import hashlib
        import json
        import shutil
        import sys
        from pathlib import Path

        from vpn_installer.audit.docker import acceptance_snapshot_fixture
        from vpn_installer.compatibility import COMPATIBLE_INSTALLED_MIN


        def digest(payload: bytes) -> str:
            return hashlib.sha256(payload).hexdigest()


        def canonical_digest(value: object) -> str:
            return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


        node_id = sys.argv[1]
        current_bundle = Path(sys.argv[2])
        release = Path(sys.argv[3])
        sing_box_binary = Path(sys.argv[4])
        previous_version = COMPATIBLE_INSTALLED_MIN
        if node_id not in {"gateway", "exit"}:
            raise SystemExit(f"unsupported fixture node: {node_id}")
        if release.exists():
            shutil.rmtree(release)
        release.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(current_bundle, release)

        env_path = release / "node.env"
        source_snapshot = acceptance_snapshot_fixture("verified", node_id=node_id)
        source_snapshot.update(
            {
                "release": {
                    "version": previous_version,
                    "release_id": f"{previous_version}-audit-{node_id}",
                    "installed_at": "2026-08-17T00:00:00+00:00",
                },
            }
        )
        source_snapshot_json = json.dumps(source_snapshot, separators=(",", ":"))
        agent_path = release / "vpn-stack-agent.py"
        agent_path.write_text(
            "from pathlib import Path\\n"
            "from datetime import datetime, timezone\\n"
            "import json\\n"
            "import sys\\n"
            f"PAYLOAD = json.loads({source_snapshot_json!r})\\n"
            "if sys.argv[1:] == ['network-apply']:\\n"
            "    Path('/work/result/previous-release-network-apply.marker').write_text('applied\\\\n', encoding='utf-8')\\n"
            "    print(json.dumps({'verdict': 'applied'}))\\n"
            "elif sys.argv[1:2] == ['snapshot']:\\n"
            "    now = datetime.now(timezone.utc).isoformat()\\n"
            "    PAYLOAD['generated_at'] = now\\n"
            "    for state in PAYLOAD['collectors'].values():\\n"
            "        if state.get('status') == 'ok': state['observed_at'] = now\\n"
            "    print(json.dumps(PAYLOAD, separators=(',', ':')))\\n"
            "else:\\n"
            "    raise SystemExit('unsupported fixture command')\\n",
            encoding="utf-8",
        )

        manifest_path = release / "render-manifest.json"
        plan_path = release / "install-plan.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        artifacts = manifest["artifacts"]
        for name, entry in artifacts.items():
            entry["sha256"] = digest((release / name).read_bytes())

        plan["artifacts"] = artifacts
        manifest.update(
            {
                "version": previous_version,
                "release_id": f"{previous_version}-audit-{node_id}",
                "env_sha256": digest(env_path.read_bytes()),
                "node_env_sha256": digest(env_path.read_bytes()),
                "config_sha256": artifacts["sing-box.json"]["sha256"],
                "artifacts": artifacts,
                "install_plan": plan,
                "install_plan_sha256": canonical_digest(plan),
            }
        )
        manifest["update_compatibility"] = {
            "installed_min": previous_version,
            "installed_max": previous_version,
            "transitions": [],
        }
        plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\\n", encoding="utf-8")

        binary_dir = release / "bin"
        binary_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sing_box_binary, binary_dir / "sing-box")
        if "xray" in manifest["binaries"]:
            raise SystemExit("the previous-release audit fixture requires an explicit Xray binary")

        for name, entry in artifacts.items():
            destination = Path(entry["install_path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(release / name, destination)
        for name, entry in manifest["assets"].items():
            source = release / "assets" / name
            destination = Path(entry["install_path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        deployment_env = Path("/etc/vpn-stack/deployment.env")
        deployment_env.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(env_path, deployment_env)
        """
    )


def compatible_update_acceptance_script() -> str:
    return textwrap.dedent(
        """\
        set -euo pipefail
        export LC_ALL=C
        support() { PYTHONPATH=/work python3 -m vpn_installer.install_support "$@"; }
        meta_value() { awk -F '\t' -v key="$2" '$1 == key { print $2 }' "$1/meta.tsv"; }

        current_bundle=/work/current-exit
        current_contract=/work/contracts/current-exit
        source_release=/etc/vpn-stack/releases/previous-exit
        source_contract=/work/contracts/previous-exit
        mkdir -p /work/contracts /work/assets /work/result
        echo __GEOSITE_SRS_BASE64__ | base64 -d >/work/assets/geosite-ru.srs
        echo __GEOIP_SRS_BASE64__ | base64 -d >/work/assets/geoip-ru.srs

        support render-node \
          --node exit \
          --env-file /work/dual.env \
          --assets-dir /work/assets \
          --output-dir "$current_bundle"
        support validate-bundle \
          --bundle "$current_bundle" \
          --expected-node exit \
          --external-assets /work/assets \
          --contract-dir "$current_contract"
        PYTHONPATH=/work python3 /work/build-previous-release.py \
          exit "$current_bundle" "$source_release" /usr/local/bin/sing-box
        support validate-installed \
          --current-release "$source_release" \
          --expected-node exit \
          --contract-dir "$source_contract"

        test "$(meta_value "$source_contract" version)" = __PREVIOUS_VERSION__
        test "$(meta_value "$source_contract" schema_version)" = __CURRENT_MANIFEST_SCHEMA__
        test "$(meta_value "$current_contract" version)" = __CURRENT_VERSION__
        test "$(meta_value "$current_contract" schema_version)" = __CURRENT_MANIFEST_SCHEMA__

        PYTHONPATH=/work python3 - "$source_release" /work/result <<'PY'
        import json
        import shutil
        import sys
        from pathlib import Path

        from vpn_installer import VERSION
        from vpn_installer.compatibility import COMPATIBLE_INSTALLED_MIN, CompatibilityWindow, Version
        from vpn_installer.config import load_env_file
        from vpn_installer.diagnostics import SCHEMA_VERSION as DIAGNOSTICS_SCHEMA_VERSION
        from vpn_installer.install_contract import InstallContractError, validate_installed_bundle
        from vpn_installer.manifest import INSTALL_PLAN_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION
        from vpn_installer.topology import CONFIG_SCHEMA_VERSION

        source_release = Path(sys.argv[1])
        result_dir = Path(sys.argv[2])
        window = CompatibilityWindow.current()
        assert str(window.minimum) == COMPATIBLE_INSTALLED_MIN
        assert str(window.maximum) == VERSION
        assert (
            CONFIG_SCHEMA_VERSION,
            MANIFEST_SCHEMA_VERSION,
            INSTALL_PLAN_SCHEMA_VERSION,
            DIAGNOSTICS_SCHEMA_VERSION,
        ) == (3, 4, 4, 5)

        source_env = load_env_file(source_release / "node.env")
        source_manifest = json.loads((source_release / "render-manifest.json").read_text(encoding="utf-8"))
        source_plan = json.loads((source_release / "install-plan.json").read_text(encoding="utf-8"))
        assert source_env["CONFIG_SCHEMA"] == str(CONFIG_SCHEMA_VERSION)
        assert source_manifest["version"] == COMPATIBLE_INSTALLED_MIN
        assert source_manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
        assert source_plan["schema_version"] == INSTALL_PLAN_SCHEMA_VERSION

        current = Version.parse(VERSION)
        future = str(Version(current.major, current.minor, current.patch + 1))
        for invalid in ("0.0.0", future):
            candidate = result_dir / f"out-of-window-{invalid}"
            shutil.copytree(source_release, candidate)
            manifest_path = candidate / "render-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = invalid
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            try:
                validate_installed_bundle(candidate, "exit", result_dir / f"contract-{invalid}")
            except InstallContractError as exc:
                assert f"installed release {invalid} cannot be updated" in str(exc)
                assert f"tag {invalid}" in str(exc)
            else:
                raise AssertionError(f"out-of-window release accepted: {invalid}")

        result = {
            "from": {
                "version": COMPATIBLE_INSTALLED_MIN,
                "config": CONFIG_SCHEMA_VERSION,
                "state": CONFIG_SCHEMA_VERSION,
                "manifest": MANIFEST_SCHEMA_VERSION,
                "install_plan": INSTALL_PLAN_SCHEMA_VERSION,
                "diagnostics": DIAGNOSTICS_SCHEMA_VERSION,
            },
            "to": {
                "version": VERSION,
                "config": CONFIG_SCHEMA_VERSION,
                "state": CONFIG_SCHEMA_VERSION,
                "manifest": MANIFEST_SCHEMA_VERSION,
                "install_plan": INSTALL_PLAN_SCHEMA_VERSION,
                "diagnostics": DIAGNOSTICS_SCHEMA_VERSION,
            },
            "window": CompatibilityWindow.current().to_manifest(),
        }
        (result_dir / "transition.json").write_text(json.dumps(result, indent=2) + "\\n", encoding="utf-8")
        PY
        """
    ).replace("__GEOSITE_SRS_BASE64__", VALID_GEOSITE_SRS_BASE64).replace(
        "__GEOIP_SRS_BASE64__", VALID_GEOIP_SRS_BASE64
    ).replace(
        "__PREVIOUS_VERSION__", COMPATIBLE_INSTALLED_MIN
    ).replace(
        "__CURRENT_MANIFEST_SCHEMA__", str(MANIFEST_SCHEMA_VERSION)
    ).replace(
        "__CURRENT_VERSION__", VERSION
    )


def test_compatible_update(runner: AuditRunner) -> dict[str, str]:
    env_path, env = runner.create_env(
        "compatible-update",
        {"FOREIGN_BLOCK_RU": "0"},
        topology=TOPOLOGY_DUAL,
        gateway_location=LOCATION_RU,
    )
    fixture_builder = runner.work_dir / "compatible-update" / "build-previous-release.py"
    write_text(fixture_builder, previous_release_fixture_builder_text())
    result_dir = runner.work_dir / "compatible-update-result"
    container = f"audit-compatible-update-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        runner.docker_copy(container, env_path, "/work/dual.env")
        runner.docker_copy(container, fixture_builder, "/work/build-previous-release.py")
        runner.docker_exec(
            container,
            compatible_update_acceptance_script(),
            timeout_seconds=COMPATIBLE_UPDATE_TIMEOUT_SECONDS,
        )
        runner.docker_cp_from(container, "/work/result", result_dir)
    return {
        "container": container,
        "deployment": env["DEPLOY_NAME"],
        "transition": f"{COMPATIBLE_INSTALLED_MIN}->{VERSION} (schemas 3/3/4/4/5 unchanged)",
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


def transaction_rollback_acceptance_script(verified_snapshot: str, deployment_name: str) -> str:
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
            single_bundle=/work/current-single-gateway
            single_contract=/work/current-single-contract
            exit_bundle=/work/current-dual-exit
            exit_contract=/work/current-exit-contract
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
            support render-node \
              --node exit \
              --env-file /work/dual.env \
              --assets-dir /work/assets \
              --output-dir "$exit_bundle"
            support validate-bundle \
              --bundle "$exit_bundle" \
              --expected-node exit \
              --external-assets /work/assets \
              --contract-dir "$exit_contract"

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
                if [[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["schema_version"])' "$VPNSTACK_CURRENT_RELEASE/render-manifest.json")" == __CURRENT_MANIFEST_SCHEMA__ ]]; then
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

            cat >"$agent_path" <<'PY'
            import json
            print(__VERIFIED_SNAPSHOT__)
            PY

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

            current_check_release="$VPNSTACK_RELEASES_DIR/current-check"
            mkdir -p "$VPNSTACK_RELEASES_DIR"
            cp -a "$single_bundle" "$current_check_release"
            mkdir -p "$current_check_release/assets"
            cp /work/assets/geosite-ru.srs /work/assets/geoip-ru.srs "$current_check_release/assets/"
            ln -s "$current_check_release" "$VPNSTACK_CURRENT_RELEASE"
            NODE=exit
            if (current_release_contract /work/node-mismatch-contract) 2>/work/node-mismatch.err; then
              echo 'current node mismatch was accepted' >&2
              exit 74
            fi
            grep -Fq 'installed node is gateway, not exit' /work/node-mismatch.err
            test ! -d /work/node-mismatch-contract || test -z "$(find /work/node-mismatch-contract -type f -print -quit)"
            NODE=gateway
            pass_gate node-mismatch-rejection

            rm -rf -- "$VPNSTACK_ROOT"
            previous_release="$VPNSTACK_RELEASES_DIR/previous-release"
            PYTHONPATH=/work python3 /work/build-previous-release.py \
              exit "$exit_bundle" "$previous_release" /usr/local/bin/sing-box
            ln -s "$previous_release" "$VPNSTACK_CURRENT_RELEASE"
            previous_release_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["release_id"])' "$previous_release/render-manifest.json")"
            python3 - "$VPNSTACK_ACCEPTANCE_PATH" "$previous_release_id" <<'PY'
            import json
            import sys
            from pathlib import Path

            Path(sys.argv[1]).write_text(
                json.dumps(
                    {
                        "deployment": __DEPLOYMENT_NAME__,
                        "node_id": "exit",
                        "release": {"release_id": sys.argv[2]},
                    },
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            PY
            cp "$VPNSTACK_ACCEPTANCE_PATH" /work/previous-release-acceptance.json
            WORK_DIR=/work/previous-release-contract-work
            mkdir -p "$WORK_DIR"
            PREVIOUS_CONTRACT=""
            prepare_previous_contract
            test "$(contract_value "$PREVIOUS_CONTRACT" version)" = __PREVIOUS_VERSION__
            test "$(contract_value "$PREVIOUS_CONTRACT" schema_version)" = __CURRENT_MANIFEST_SCHEMA__
            cp "$PREVIOUS_CONTRACT/services.tsv" /work/previous-release-services.tsv
            grep -Fqx $'wireguard\twg-quick@wg0.service\tmanaged' /work/previous-release-services.tsv
            ! grep -Fq $'transport\t' /work/previous-release-services.tsv
            ! grep -Fq $'admin\t' /work/previous-release-services.tsv

            (
              set -euo pipefail
              trap on_exit EXIT
              install_packages_from_plan() { :; }
              stage_binaries() {
                mkdir -p "$1/bin"
                cp /usr/local/bin/sing-box "$1/bin/sing-box"
              }
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
              NODE=exit
              ENV_FILE=/work/dual.env
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
            test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["schema_version"])' "$VPNSTACK_CURRENT_RELEASE/render-manifest.json")" = __CURRENT_MANIFEST_SCHEMA__
            current_release="$(readlink -f "$VPNSTACK_CURRENT_RELEASE")"
            test "$current_release" != "$previous_release"
            cmp -s "$VPNSTACK_ACCEPTANCE_PATH" /work/previous-release-acceptance.json
            snapshot="$(readlink -f "$VPNSTACK_LATEST_SNAPSHOT")"
            cp "$snapshot/service-state.tsv" /work/previous-release-service-state.tsv

            : >"$SYSTEMCTL_LOG"
            rollback_action >/work/previous-release-rollback.out
            grep -Fq 'Rollback snapshot restored:' /work/previous-release-rollback.out
            test "$(readlink -f "$VPNSTACK_CURRENT_RELEASE")" = "$previous_release"
            test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["schema_version"])' "$VPNSTACK_CURRENT_RELEASE/render-manifest.json")" = __CURRENT_MANIFEST_SCHEMA__
            python3 - "$VPNSTACK_ACCEPTANCE_PATH" __PREVIOUS_VERSION__ <<'PY'
            import json
            import sys

            payload = json.load(open(sys.argv[1], encoding="utf-8"))
            assert payload["schema_version"] == __CURRENT_DIAGNOSTICS_SCHEMA__
            assert payload["node_id"] == "exit"
            assert payload["release"]["version"] == sys.argv[2]
            assert payload["verdict"] == "verified"
            PY
            test -f /etc/wireguard/wg0.conf
            grep -Fxq applied /work/result/previous-release-network-apply.marker
            pass_gate sigkill-production-cutover-reconciliation

            verified_services=0
            wireguard_state_verified=0
            while IFS=$'\t' read -r name unit ownership expected_enabled expected_active; do
              [[ "$ownership" == managed || "$ownership" == borrowed ]]
              grep -Fxq "is-enabled $unit" "$SYSTEMCTL_LOG"
              grep -Fxq "is-active $unit" "$SYSTEMCTL_LOG"
              if [[ "$name" == wireguard ]]; then
                test "$expected_enabled" = enabled
                test "$expected_active" = active
                wireguard_state_verified=1
              fi
              verified_services=$((verified_services + 1))
            done </work/previous-release-service-state.tsv
            test "$verified_services" -gt 0
            test "$wireguard_state_verified" = 1
            test "$(grep -c '^is-enabled ' "$SYSTEMCTL_LOG")" = "$verified_services"
            test "$(grep -c '^is-active ' "$SYSTEMCTL_LOG")" = "$verified_services"
            cp "$SYSTEMCTL_LOG" /work/result/previous-release-service-verification.log
            pass_gate previous-release-rollback-verification
            test "$(wc -l </work/result/gates.tsv)" = 6
            """
        ).lstrip()
        .replace("__GEOSITE_SRS_BASE64__", VALID_GEOSITE_SRS_BASE64)
        .replace("__GEOIP_SRS_BASE64__", VALID_GEOIP_SRS_BASE64)
        .replace("__VERIFIED_SNAPSHOT__", verified_snapshot)
        .replace("__DEPLOYMENT_NAME__", json.dumps(deployment_name))
        .replace("__PREVIOUS_VERSION__", COMPATIBLE_INSTALLED_MIN)
        .replace("__CURRENT_DIAGNOSTICS_SCHEMA__", str(DIAGNOSTICS_SCHEMA_VERSION))
        .replace("__CURRENT_MANIFEST_SCHEMA__", str(MANIFEST_SCHEMA_VERSION))
    )


def test_install_rollback_state(runner: AuditRunner) -> dict[str, str]:
    env_path, env = runner.create_env(
        "install-rollback",
        topology=TOPOLOGY_SINGLE,
        gateway_location=LOCATION_RU,
    )
    dual_env_path, dual_env = runner.create_env(
        "install-rollback-upgrade",
        {"FOREIGN_BLOCK_RU": "0"},
        topology=TOPOLOGY_DUAL,
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
    fixture_builder = runner.work_dir / "install-rollback" / "build-previous-release.py"
    write_text(fixture_builder, previous_release_fixture_builder_text())
    result_dir = runner.work_dir / "install-rollback-result"
    container = f"audit-install-rollback-{runner.run_id}"
    with runner.docker_container(container, AUDIT_IMAGE):
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, INSTALL_SCRIPT_PATH, "/work/install.sh")
        runner.docker_copy(container, env_path, "/work/deployment.env")
        runner.docker_copy(container, dual_env_path, "/work/dual.env")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work")
        runner.docker_copy(container, fixture_builder, "/work/build-previous-release.py")
        runner.docker_exec(
            container,
            transaction_rollback_acceptance_script(verified_snapshot, dual_env["DEPLOY_NAME"]),
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
    service_verification = result_dir / "previous-release-service-verification.log"
    service_evidence = service_verification.read_text(encoding="utf-8") if service_verification.is_file() else ""
    if "is-enabled wg-quick@wg0.service" not in service_evidence or "is-active wg-quick@wg0.service" not in service_evidence:
        raise AuditFailure("previous-release rollback service verification evidence is missing")
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
                "schema_version": CONFIG_SCHEMA_VERSION,
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
            wf.install_remote_node(target, deployment_name, env, action)

        wf.install_remote_node_with_recovery = accepted_install

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
