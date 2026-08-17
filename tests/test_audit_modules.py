from __future__ import annotations

import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import VERSION
from vpn_installer.audit import docker as audit_docker
from vpn_installer.audit import lab as audit_lab
from vpn_installer.audit import quick as audit_quick
from vpn_installer.audit.runner import AuditFailure
from vpn_installer.client_artifacts import PUBLIC_VLESS_OUTBOUND_TAG
from vpn_installer.compatibility import COMPATIBLE_INSTALLED_MIN
from vpn_installer.config import generate_default_env
from vpn_installer.diagnostics import SCHEMA_VERSION as DIAGNOSTICS_SCHEMA_VERSION
from vpn_installer.manifest import INSTALL_PLAN_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION
from vpn_installer.topology import (
    CONFIG_SCHEMA_VERSION,
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
)


class FakeRunner:
    def __init__(self) -> None:
        self.records: list[str] = []
        self.skips: list[str] = []
        self.run_id = "rid"
        self.mode = "quick"

    def ensure_audit_image(self) -> None:
        self.records.append("ensure")

    def record(self, name, fn):
        self.records.append(name)

    def skip(self, name, _reason):
        self.skips.append(name)


class AuditModuleTests(unittest.TestCase):
    @staticmethod
    def canonical_dual_env() -> dict[str, str]:
        env = generate_default_env("demo", topology=TOPOLOGY_DUAL, gateway_location=LOCATION_RU)
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        return env

    def test_quick_run_registers_expected_checks(self) -> None:
        class QuickRunner(FakeRunner):
            def ensure_quick_env(self):
                with tempfile.TemporaryDirectory() as tmp:
                    pass
                path = Path(tempfile.gettempdir()) / "demo.env"
                path.write_text('DEPLOY_NAME="demo"\n', encoding="utf-8")
                return path, Path(tempfile.gettempdir()) / "demo"

            def seed_foreign_block_cache(self, _name):
                return None

        runner = QuickRunner()
        no_op = patch.multiple(
            audit_quick,
            test_coverage=lambda *_args, **_kwargs: {},
            test_install_ux_helpers=lambda *_args, **_kwargs: {},
            test_render_all=lambda *_args, **_kwargs: {},
            test_topology_matrix=lambda *_args, **_kwargs: {},
            test_validate_json=lambda *_args, **_kwargs: {},
            test_user_artifacts=lambda *_args, **_kwargs: {},
            test_validate_bundle=lambda *_args, **_kwargs: {},
            test_cloud_init_schema=lambda *_args, **_kwargs: {},
            test_cloud_init_render_only=lambda *_args, **_kwargs: {},
            test_bundle_render_only=lambda *_args, **_kwargs: {},
            test_windows_clean_room=lambda *_args, **_kwargs: {},
            test_linux_launcher_no_python=lambda *_args, **_kwargs: {},
            test_linux_launcher_with_python=lambda *_args, **_kwargs: {},
            test_vpn_menu_exit=lambda *_args, **_kwargs: {},
            load_env_file=lambda *_args, **_kwargs: {"DEPLOY_NAME": "demo"},
        )
        with (
            no_op,
            patch("vpn_installer.audit.quick.shutil.which", return_value="found"),
            patch("vpn_installer.audit.quick.docker_readiness", return_value=(True, "")),
        ):
            audit_quick.run(runner)  # type: ignore[arg-type]
        self.assertNotIn("quick-unittest", runner.records)
        self.assertIn("quick-install-ux", runner.records)
        self.assertIn("quick-topology-matrix", runner.records)
        self.assertNotIn("quick-interserver-hysteria-runtime", runner.records)
        self.assertEqual(runner.skips, [])

    def test_transaction_acceptance_fixture_uses_current_snapshot_schema(self) -> None:
        verified = audit_docker.acceptance_snapshot_fixture("verified")
        failed = audit_docker.acceptance_snapshot_fixture("failed")

        self.assertEqual(verified["schema_version"], DIAGNOSTICS_SCHEMA_VERSION)
        self.assertEqual(verified["topology"], TOPOLOGY_DUAL)
        self.assertEqual(verified["node_id"], NODE_EXIT)
        self.assertEqual(verified["location"], LOCATION_FOREIGN)
        self.assertNotIn("role", verified)
        self.assertIn("wireguard", verified["services"])
        self.assertNotIn("xray", verified["services"])
        self.assertEqual(verified["network"], {"profile_mismatches": []})
        self.assertEqual(verified["artifacts"]["drift"], "none")
        self.assertEqual(verified["component_verdicts"]["server_path"], "verified")
        self.assertEqual(verified["component_verdicts"]["host_integrity"], "verified")
        self.assertEqual(failed["component_verdicts"]["server_path"], "failed")
        with self.assertRaises(ValueError):
            audit_docker.acceptance_snapshot_fixture("inconclusive")

    def test_acceptance_fixture_topology_capability_matrix(self) -> None:
        single_ru = audit_docker.acceptance_snapshot_fixture(
            "verified",
            topology=TOPOLOGY_SINGLE,
            node_id=NODE_GATEWAY,
            gateway_location=LOCATION_RU,
        )
        single_foreign = audit_docker.acceptance_snapshot_fixture(
            "verified",
            topology=TOPOLOGY_SINGLE,
            node_id=NODE_GATEWAY,
            gateway_location=LOCATION_FOREIGN,
        )
        dual_gateway = audit_docker.acceptance_snapshot_fixture(
            "verified",
            topology=TOPOLOGY_DUAL,
            node_id=NODE_GATEWAY,
        )
        dual_exit = audit_docker.acceptance_snapshot_fixture(
            "verified",
            topology=TOPOLOGY_DUAL,
            node_id=NODE_EXIT,
        )

        for snapshot, location in ((single_ru, LOCATION_RU), (single_foreign, LOCATION_FOREIGN)):
            self.assertEqual(snapshot["topology"], TOPOLOGY_SINGLE)
            self.assertEqual(snapshot["node_id"], NODE_GATEWAY)
            self.assertEqual(snapshot["location"], location)
            self.assertIn("xray", snapshot["services"])
            self.assertNotIn("wireguard", snapshot["services"])
            self.assertEqual(snapshot["collectors"]["wireguard"]["status"], "not_applicable")

        self.assertIn("xray", dual_gateway["services"])
        self.assertIn("wireguard", dual_gateway["services"])
        self.assertIn("wireguard", dual_exit["services"])
        self.assertNotIn("xray", dual_exit["services"])
        self.assertEqual(dual_exit["collectors"]["front"]["status"], "not_applicable")
        with self.assertRaisesRegex(ValueError, "not configured"):
            audit_docker.acceptance_snapshot_fixture(
                "verified",
                topology=TOPOLOGY_SINGLE,
                node_id=NODE_EXIT,
            )

    def test_release_workflow_requires_bounded_gates_before_publish(self) -> None:
        workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("from vpn_installer import VERSION", workflow)
        self.assertIn("if tag != VERSION", workflow)
        self.assertIn("python -m vpn_installer audit all --json", workflow)
        self.assertNotIn("python -m unittest discover", workflow)
        self.assertIn("timeout-minutes:", workflow)
        self.assertIn("needs: gate", workflow)

    def test_quick_helper_validations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            preview = out_dir / "preview"
            client = out_dir / "client"
            bundle = out_dir / "bundle"
            cloud = out_dir / "cloud-init"
            (preview / NODE_GATEWAY).mkdir(parents=True)
            (preview / NODE_EXIT).mkdir(parents=True)
            client.mkdir(parents=True)
            bundle.mkdir(parents=True)
            cloud.mkdir(parents=True)
            server = out_dir / "server"
            server.mkdir(parents=True)
            (server / f"{NODE_GATEWAY}.env").write_text('DEPLOY_NAME="demo"\n', encoding="utf-8")
            for path in [
                preview / NODE_GATEWAY / "sing-box.json",
                preview / NODE_GATEWAY / "xray.json",
                preview / NODE_EXIT / "sing-box.json",
            ]:
                path.write_text("{}\n", encoding="utf-8")
            public_outbounds = [
                {
                    "type": "vless",
                    "tag": PUBLIC_VLESS_OUTBOUND_TAG,
                    "multiplex": {"enabled": False},
                }
            ]
            public_profile = {
                "dns": {"servers": [{"detour": PUBLIC_VLESS_OUTBOUND_TAG}]},
                "route": {"final": PUBLIC_VLESS_OUTBOUND_TAG},
                "outbounds": public_outbounds,
            }
            (client / "hiddify-cross-platform.json").write_text(
                json.dumps({**public_profile, "inbounds": [{"auto_redirect": False}]}) + "\n",
                encoding="utf-8",
            )
            (client / "hysteria2-uri.txt").write_text(
                "hysteria2://secret@203.0.113.10:443/?insecure=1&pinSHA256=AA#demo\n",
                encoding="utf-8",
            )
            (client / "linux-sing-box.json").write_text(
                json.dumps({**public_profile, "inbounds": [{"auto_redirect": True}]}) + "\n",
                encoding="utf-8",
            )
            (client / "android-v2rayng-xray.json").write_text(
                json.dumps(
                    {
                        "inbounds": [{"sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}}],
                        "routing": {
                            "domainStrategy": "AsIs",
                            "rules": [{"type": "field", "ip": ["::/0"], "outboundTag": "block"}],
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (client / "vless-uri.txt").write_text("vless://demo\n", encoding="utf-8")
            (client / "hiddify-android.json").write_text("{}\n", encoding="utf-8")
            (client / "hiddify-uri.txt").write_text("vless://demo\n", encoding="utf-8")
            (client / "v2rayn-uri.txt").write_text("vless://demo\n", encoding="utf-8")
            (out_dir / "NEXT-STEPS.txt").write_text(
                f"VLESS URI\nv2rayNG\nandroid-v2rayng-xray.json\n{audit_quick.cli_command('status')}\n",
                encoding="utf-8",
            )
            for name in (f"{NODE_GATEWAY}.tar.gz", f"{NODE_EXIT}.tar.gz"):
                with tarfile.open(bundle / name, "w:gz") as archive:
                    keep = out_dir / f"{name}.txt"
                    keep.write_text("x", encoding="utf-8")
                    archive.add(keep, arcname="demo.txt")
            with self.assertRaises(AuditFailure):
                audit_quick.test_validate_bundle(out_dir, self.canonical_dual_env())
            self.assertIn("validated", audit_quick.test_validate_json(out_dir, self.canonical_dual_env()))
            self.assertIn("vless_uri", audit_quick.test_user_artifacts(out_dir))

    def test_quick_vpn_menu_exit_accepts_expected_output(self) -> None:
        class Runner:
            def run_command(self, *_args, **_kwargs):
                import subprocess

                return subprocess.CompletedProcess(["pwsh"], 0, stdout="VPN Installer\nВыбери действие\nЗавершено.\n", stderr="")

        result = audit_quick.test_vpn_menu_exit(Runner())
        self.assertIn("launcher", result)

    def test_docker_run_registers_checks(self) -> None:
        runner = FakeRunner()
        audit_docker.run(runner)  # type: ignore[arg-type]
        self.assertIn("docker-unmanaged-remove-purge-render-only", runner.records)
        self.assertIn("docker-compatible-update", runner.records)
        self.assertIn("docker-install-rollback-state", runner.records)
        self.assertIn("docker-node-scoped-workflows", runner.records)

    def test_compatible_update_gate_keeps_schemas_and_rejects_out_of_window_releases(self) -> None:
        self.assertEqual(VERSION, "0.20.2")
        self.assertEqual(
            (
                CONFIG_SCHEMA_VERSION,
                MANIFEST_SCHEMA_VERSION,
                INSTALL_PLAN_SCHEMA_VERSION,
                DIAGNOSTICS_SCHEMA_VERSION,
            ),
            (3, 4, 4, 5),
        )

        builder = audit_docker.previous_release_fixture_builder_text()
        compile(builder, "<previous-release-fixture-builder>", "exec")
        self.assertIn("previous_version = COMPATIBLE_INSTALLED_MIN", builder)

        script = audit_docker.compatible_update_acceptance_script()
        self.assertIn("support validate-installed", script)
        self.assertIn('(3, 4, 4, 5)', script)
        self.assertIn(f'= {COMPATIBLE_INSTALLED_MIN}', script)
        self.assertIn("current.patch + 1", script)
        self.assertIn("cannot be updated", script)
        self.assertLessEqual(audit_docker.COMPATIBLE_UPDATE_TIMEOUT_SECONDS, 45)

    def test_transaction_rollback_linux_gate_uses_bounded_release_contracts(self) -> None:
        script = audit_docker.transaction_rollback_acceptance_script(repr("{}"), "audit-upgrade")

        for helper in (
            "build_operation_scope",
            "create_transaction_snapshots",
            "rollback_action",
            "current_release_contract",
            "prepare_previous_contract",
            "install_action",
            "on_exit",
        ):
            self.assertIn(helper, script)
        for gate in (
            "acceptance-marker-path",
            "failed-acceptance-evidence",
            "single-rollback-without-wireguard",
            "node-mismatch-rejection",
            "sigkill-production-cutover-reconciliation",
            "previous-release-rollback-verification",
        ):
            self.assertIn(f"pass_gate {gate}", script)
        for stale in (
            "require_matching_install_identity",
            "create_revision_snapshot",
            "restore_install_state_on_error",
            "VPNSTACK_ACCEPTANCE_FILE",
        ):
            self.assertNotIn(stale, script)
        self.assertIn("/etc/vpn-stack/last-acceptance.json", script)
        self.assertIn("test -f /etc/wireguard/wg0.conf", script)
        self.assertEqual(script.count("rollback_action"), 2)
        self.assertIn('kill -KILL "$installer_pid"', script)
        self.assertIn('flock 9', script)
        self.assertIn('grep -Fxq "is-enabled $unit"', script)
        self.assertIn('grep -Fxq "is-active $unit"', script)
        self.assertIn('test "$expected_enabled" = enabled', script)
        self.assertIn('test "$expected_active" = active', script)
        crash_section = script.split("cp \"$PREVIOUS_CONTRACT/services.tsv\" /work/previous-release-services.tsv", 1)[1].split(
            "pass_gate sigkill-production-cutover-reconciliation", 1
        )[0]
        self.assertIn("install_action", crash_section)
        self.assertNotIn("install_planned_links", crash_section)
        self.assertNotIn("switch_current_release", crash_section)
        self.assertNotIn("retire_previous_services", crash_section)
        self.assertIn("previous_release", crash_section)
        self.assertIn("build-previous-release.py", script)
        self.assertNotIn("manifest_schema", script)
        self.assertEqual(script.count("pass_gate "), 6)
        self.assertLessEqual(audit_docker.TRANSACTION_ACCEPTANCE_TIMEOUT_SECONDS, 45)

    def test_install_cutover_starts_new_services_before_retiring_previous_services(self) -> None:
        script = (Path(__file__).parents[1] / "install.sh").read_text(encoding="utf-8")
        install_body = script.split("install_action() {", 1)[1].split("\n}\n\ncurrent_release_contract()", 1)[0]

        start = install_body.index('start_planned_services "${staged_contract}"')
        retire = install_body.index('retire_previous_services "${PREVIOUS_CONTRACT}" "${staged_contract}"')
        self.assertLess(start, retire)

    def test_lab_builders_return_expected_content(self) -> None:
        self.assertIn("address=/ya.ru/", audit_lab.build_lab_dnsmasq())
        self.assertIn("server=ru-web", audit_lab.build_lab_web_server("ru-web"))
        env = self.canonical_dual_env()
        env["CLIENT_UUID"] = "00000000-0000-0000-0000-000000000000"
        client_cfg = audit_lab.build_lab_client_config(env)
        self.assertIn('"server": "198.18.0.10"', client_cfg)

    def test_lab_network_apply_validation_uses_nested_agent_contract(self) -> None:
        lab_source = (Path(__file__).parents[1] / "vpn_installer" / "audit" / "lab.py").read_text(encoding="utf-8")
        self.assertIn("topology.py", audit_lab.SERVER_AGENT_INTERSERVER_MODULES)
        self.assertIn("release_integrity.py", audit_lab.SERVER_AGENT_BASE_MODULES)
        self.assertIn("*SERVER_AGENT_BASE_MODULES, *SERVER_AGENT_INTERSERVER_MODULES", lab_source)
        audit_lab.validate_network_apply_result(
            {
                "qdisc": {
                    "overlay_qdisc": "fq",
                    "overlay_qdisc_limit": 10_000,
                    "overlay_qdisc_flow_limit": 512,
                },
                "wireguard_policy": {"managed": True, "ok": True},
            }
        )
        with self.assertRaises(AuditFailure):
            audit_lab.validate_network_apply_result({"overlay_qdisc": "fq"})

    def test_lab_run_registers_dataplane_check(self) -> None:
        runner = FakeRunner()
        audit_lab.run(runner)  # type: ignore[arg-type]
        self.assertIn("lab-dataplane", runner.records)


if __name__ == "__main__":
    unittest.main()
