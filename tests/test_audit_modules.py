from __future__ import annotations

import ast
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

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
    def test_lab_logs_survive_failure_without_masking_the_original_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = Mock(work_dir=Path(temporary), run_id="fixture")
            runner.docker_cp_from.side_effect = [None, AuditFailure("missing log"), None, None, None]
            with self.assertRaisesRegex(RuntimeError, "original probe failure"):
                with audit_lab._lab_logs(runner):
                    raise RuntimeError("original probe failure")
            self.assertEqual(runner.docker_cp_from.call_count, 5)
            errors = (Path(temporary) / "lab/runtime-logs/collection-errors.txt").read_text(encoding="utf-8")
            self.assertIn("exit: missing log", errors)

    def test_lab_stream_is_detached_without_retrying_or_bypassing_socks(self) -> None:
        runner = Mock()
        audit_lab._lab_start_stream(runner, "client")
        node, command = runner.docker_exec.call_args.args
        self.assertEqual(node, "client")
        self.assertIn("--noproxy '' --socks5-hostname 127.0.0.1:1080", command)
        self.assertIn(f"--max-time {audit_lab.LAB_STREAM_MAX_SECONDS}", command)
        self.assertIn("echo $? >/opt/stream.rc", command)
        self.assertTrue(command.endswith("</dev/null >/opt/stream.log 2>&1 &"))
        self.assertNotIn("--retry", command)

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
        self.assertIn("docker-platform-contract-matrix", runner.records)
        self.assertIn("docker-unmanaged-remove-purge-render-only", runner.records)
        self.assertIn("docker-compatible-update", runner.records)
        self.assertIn("docker-install-rollback-state", runner.records)
        self.assertIn("docker-node-scoped-workflows", runner.records)

    def test_compatible_update_gate_migrates_exact_predecessor_and_rejects_out_of_window_releases(self) -> None:
        self.assertEqual(
            (
                CONFIG_SCHEMA_VERSION,
                MANIFEST_SCHEMA_VERSION,
                INSTALL_PLAN_SCHEMA_VERSION,
                DIAGNOSTICS_SCHEMA_VERSION,
            ),
            (3, 5, 5, 8),
        )

        script = audit_docker.compatible_update_acceptance_script()
        self.assertIn("support validate-installed", script)
        self.assertIn("PYTHONPATH=/work/previous", script)
        self.assertIn('(3, 5, 5, 7)', script)
        self.assertIn('source_manifest["schema_version"] == MANIFEST_SCHEMA_VERSION', script)
        self.assertNotIn("transition_0218", script)
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
            "fresh-install-with-incomplete-history",
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
        self.assertEqual(script.count("pass_gate "), 7)
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

    @staticmethod
    def lab_loss_cycles(*, both_dead: bool = False):
        selected, target = audit_lab.TRANSPORT_CANDIDATE_TAGS
        first = {
            "state": "suspect", "selected": selected, "changed": False,
            "hard_failure_evidence": False, "cycle_id": "first",
            "updated_at": "2026-10-08T12:00:00+00:00",
            "failure": {"path": selected, "confirmations": 1},
            "probes": {selected: {"checked": True, "ok": False}},
        }
        failure = {"path": selected, "confirmations": 2, "cycle_ids": ["first", "second"]}
        second = {
            "state": "failed" if both_dead else "degraded",
            "selected": selected if both_dead else target, "changed": not both_dead,
            "hard_failure_evidence": True, "cycle_id": "second",
            "updated_at": "2026-10-08T12:00:02+00:00",
            "probes": {selected: {"checked": True, "ok": False}},
            "selector_before": selected, "selector_after": target,
            "overlay_probe": {"phase": "activation", "ok": True, "path": target, "cycle_id": "second"},
            "last_transition": {"cycle_id": "second", "activation_proof": {"ok": True},
                                "decision_evidence": {"failure": failure,
                                                      "alternate_health": {**failure, "path": target}}},
        }
        if both_dead:
            second["failure"] = failure
        return selected, None if both_dead else target, [first, second]

    def test_lab_loss_requires_two_distinct_cycles_for_switch_and_both_dead(self) -> None:
        for both_dead in (False, True):
            with self.subTest(both_dead=both_dead):
                selected, target, cycles = self.lab_loss_cycles(both_dead=both_dead)
                runner = Mock()
                runner.docker_exec.side_effect = [Mock(stdout=json.dumps(state)) for state in cycles]
                with patch.object(audit_lab.time, "sleep") as sleep:
                    self.assertEqual(audit_lab._lab_confirmed_loss(runner, "gateway", selected, target), cycles)
                sleep.assert_called_once_with(audit_lab.TRANSPORT_PROBE_INTERVAL_SECONDS)
                self.assertEqual(runner.docker_exec.call_count, 2)

    def test_lab_loss_rejects_confirmation_or_switch_in_first_cycle(self) -> None:
        for change in ({"hard_failure_evidence": True}, {"changed": True}, {"would_switch": True},
                       {"failure": {"path": audit_lab.TRANSPORT_PREFERRED_TAG, "confirmations": 2}}):
            with self.subTest(change=change):
                selected, target, cycles = self.lab_loss_cycles()
                runner = Mock()
                runner.docker_exec.return_value.stdout = json.dumps({**cycles[0], **change})
                with self.assertRaisesRegex(AuditFailure, "One failed cycle"):
                    audit_lab._lab_confirmed_loss(runner, "gateway", selected, target)
                self.assertEqual(runner.docker_exec.call_count, 1)

    def test_lab_loss_rejects_stale_missing_or_unproven_second_cycle(self) -> None:
        for change in (
            {"cycle_id": "first"}, {"cycle_id": ""}, {"updated_at": "invalid"},
            {"updated_at": "2026-10-08T12:00:00+00:00"},
            {"updated_at": "2026-10-08T12:00:11+00:00"},
            {"hard_failure_evidence": False}, {"probes": {}}, {"changed": False},
            {"overlay_probe": {"ok": True, "phase": "activation", "cycle_id": "first"}},
            {"last_transition": {"decision_evidence": {}}},
            {"last_transition": {"cycle_id": "first", "activation_proof": {"ok": True}}},
            {"last_transition": {"cycle_id": "second", "activation_proof": {"ok": False}}},
        ):
            with self.subTest(change=change), patch.object(audit_lab.time, "sleep"):
                selected, target, cycles = self.lab_loss_cycles()
                if "last_transition" in change:
                    change = {"last_transition": {**cycles[1]["last_transition"], **change["last_transition"]}}
                runner = Mock()
                runner.docker_exec.side_effect = [Mock(stdout=json.dumps(state)) for state in (cycles[0], {**cycles[1], **change})]
                with self.assertRaises(AuditFailure):
                    audit_lab._lab_confirmed_loss(runner, "gateway", selected, target)

    def test_lab_both_dead_rejects_false_health_or_switch(self) -> None:
        for change in ({"state": "healthy"}, {"changed": True}, {"selected": audit_lab.TRANSPORT_HY2_TAG}):
            with self.subTest(change=change), patch.object(audit_lab.time, "sleep"):
                selected, target, cycles = self.lab_loss_cycles(both_dead=True)
                runner = Mock()
                runner.docker_exec.side_effect = [Mock(stdout=json.dumps(state)) for state in (cycles[0], {**cycles[1], **change})]
                with self.assertRaisesRegex(AuditFailure, "Both-path loss"):
                    audit_lab._lab_confirmed_loss(runner, "gateway", selected, target)

    def test_lab_post_activation_failure_must_belong_to_new_path_only(self) -> None:
        selected, target, cycles = self.lab_loss_cycles()
        transient = {**cycles[0], "selected": target,
                     "failure": {"path": target, "confirmations": 1},
                     "probes": {target: {"checked": True, "ok": False}}}
        audit_lab._lab_require_suspect(transient, target)
        for failure in ({"path": selected, "confirmations": 1}, {"path": target, "confirmations": 2}):
            with self.subTest(failure=failure), self.assertRaises(AuditFailure):
                audit_lab._lab_require_suspect({**transient, "failure": failure}, target)

    def test_lab_quality_requires_equal_fresh_udp_samples_with_actual_counts(self) -> None:
        selected, target = audit_lab.TRANSPORT_CANDIDATE_TAGS
        quality = {"scope": "raw-underlay-udp", "quality_ok": True,
                   "budget_ms": audit_lab.TRANSPORT_CANDIDATE_QUALITY_PROBE_TIMEOUT_MS,
                   **dict.fromkeys(("attempts", "attempts_limit", "transmitted", "received", "valid_responses"),
                                   audit_lab.TRANSPORT_CANDIDATE_QUALITY_PROBE_ATTEMPTS)}
        state = {"probes": {selected: {"quality_sampled": True, "quality_probe": quality}, target: quality}}
        audit_lab._lab_require_udp_quality(state, selected)
        for tag in (selected, target):
            for change in ({"scope": "overlay-quality"}, {"budget_ms": 1200}, {"received": 7}, {"attempts": 1}):
                bad = {**quality, **change}
                probes = {**state["probes"], tag: {"quality_sampled": True, "quality_probe": bad} if tag == selected else bad}
                with self.subTest(tag=tag, change=change), self.assertRaises(AuditFailure):
                    audit_lab._lab_require_udp_quality({"probes": probes}, selected)
        with self.assertRaisesRegex(AuditFailure, "fresh selected"):
            audit_lab._lab_require_udp_quality({"probes": {selected: {"quality_sampled": False}, target: quality}}, selected)

    def test_lab_one_way_faults_drop_at_receiver_without_local_send_errors(self) -> None:
        for reverse, receiver, peer, port_field in (
            (False, "exit", audit_lab.LAB_IPS["gateway"], "dport"),
            (True, "gateway", audit_lab.LAB_IPS["exit"], "sport"),
        ):
            with self.subTest(reverse=reverse):
                runner = Mock()
                with audit_lab._lab_underlay_loss(runner, "gateway", "exit", (51820,), reverse=reverse) as add_loss:
                    self.assertEqual(runner.docker_exec.call_count, 3)
                    add_loss(audit_lab.HY2_PORT)
                    self.assertEqual(runner.docker_exec.call_count, 4)
                calls = [call.args for call in runner.docker_exec.call_args_list]
                for _, command in calls:
                    self.assertNotIn("output", command.lower())
                self.assertEqual(calls, [
                    (receiver, "nft add table inet underlay_fault"),
                    (receiver, "nft 'add chain inet underlay_fault input { type filter hook input priority -10; policy accept; }'"),
                    (receiver, f"nft add rule inet underlay_fault input ip saddr {peer} udp {port_field} 51820 drop"),
                    (receiver, f"nft add rule inet underlay_fault input ip saddr {peer} udp {port_field} {audit_lab.HY2_PORT} drop"),
                    (receiver, "nft delete table inet underlay_fault"),
                ])

    def test_lab_one_way_faults_clean_up_on_error_in_body_or_setup(self) -> None:
        for reverse in (False, True):
            runner = Mock()
            with self.subTest(reverse=reverse), self.assertRaisesRegex(RuntimeError, "probe failed"):
                with audit_lab._lab_underlay_loss(runner, "gateway", "exit", (51820,), reverse=reverse):
                    raise RuntimeError("probe failed")
            commands = [call.args[1] for call in runner.docker_exec.call_args_list]
            self.assertIn(f"udp {'sport' if reverse else 'dport'} 51820 drop", commands[2])
            self.assertEqual(commands[-1], "nft delete table inet underlay_fault")
        runner = Mock()
        runner.docker_exec.side_effect = [None, AuditFailure("chain failed"), None]
        with self.assertRaisesRegex(AuditFailure, "chain failed"):
            with audit_lab._lab_underlay_loss(runner, "gateway", "exit", (51820,)):
                self.fail("Invalid fault setup entered the scenario")
        self.assertEqual(runner.docker_exec.call_args.args[1], "nft delete table inet underlay_fault")

    def test_lab_added_loss_rule_failure_cleans_up_both_path_fixture(self) -> None:
        runner = Mock()
        runner.docker_exec.side_effect = [None, None, None, AuditFailure("second rule failed"), None]
        with self.assertRaisesRegex(AuditFailure, "second rule failed"):
            with audit_lab._lab_underlay_loss(runner, "gateway", "exit", (51820,), reverse=True) as add_loss:
                add_loss(audit_lab.HY2_PORT)
        self.assertEqual(runner.docker_exec.call_args.args, ("gateway", "nft delete table inet underlay_fault"))

    def test_lab_process_identity_detects_restart_even_with_reused_pid(self) -> None:
        before = {"gateway": {"42": "100"}, "exit": {"52": "200"}, "client": {"62": "300"}}
        audit_lab.validate_process_continuity(before, dict(before))
        for after in ({}, {**before, "gateway": {"43": "100"}}, {**before, "gateway": {"42": "101"}}):
            with self.subTest(after=after), self.assertRaisesRegex(AuditFailure, "restarted"):
                audit_lab.validate_process_continuity(before, after)
        for processes in ({}, {"42": "100", "43": "101"}):
            runner = Mock()
            runner.docker_exec.return_value.stdout = json.dumps(processes)
            with self.subTest(processes=processes), self.assertRaisesRegex(AuditFailure, "one live"):
                audit_lab._lab_processes(runner, {"gateway": "gateway"})

    def test_lab_stream_covers_one_reverse_failover_before_both_paths_fail(self) -> None:
        source = (Path(__file__).parents[1] / "vpn_installer/audit/lab.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        scenario = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "test_lab_dataplane")

        def calls(node, name):
            return sorted((item for item in ast.walk(node) if isinstance(item, ast.Call)
                           and isinstance(item.func, ast.Name) and item.func.id == name), key=lambda item: item.lineno)

        faults = sorted((node for node in ast.walk(scenario) if isinstance(node, ast.With)
                         and any(isinstance(item.context_expr, ast.Call)
                                 and isinstance(item.context_expr.func, ast.Name)
                                 and item.context_expr.func.id == "_lab_underlay_loss" for item in node.items)),
                        key=lambda node: node.lineno)
        self.assertEqual(len(faults), 3)
        starts = calls(scenario, "_lab_start_stream")
        active = calls(scenario, "_lab_require_stream_active")
        self.assertEqual(len(starts), 1)
        self.assertEqual(len(active), 1)
        recovery_guard = next(node for node in ast.walk(scenario) if isinstance(node, ast.Raise)
                              and "Transport agent did not return" in (ast.get_source_segment(source, node) or ""))
        self.assertLess(faults[1].end_lineno, recovery_guard.lineno)
        self.assertLess(recovery_guard.lineno, starts[0].lineno)
        self.assertLess(starts[0].lineno, faults[2].lineno)
        self.assertLess(faults[2].lineno, active[0].lineno)
        self.assertLess(active[0].lineno, calls(faults[2], "_lab_confirmed_loss")[0].lineno)
        add_loss = calls(faults[2], "add_loss")[0]
        checks = [node for node in faults[2].body if isinstance(node, ast.If)
                  and any(isinstance(item, ast.Name) and item.id in {
                      "stream_result", "stream_sha256", "stream_seconds", "request_count"
                  } for item in ast.walk(node.test))]
        self.assertEqual(len(checks), 4)
        self.assertTrue(all(node.end_lineno < add_loss.lineno for node in checks))
        self.assertEqual(audit_lab.LAB_STREAM_BYTES, 20 * 1024 * 1024)
        self.assertEqual(audit_lab.LAB_STREAM_MAX_SECONDS, 30)

    def test_lab_stream_fixture_sends_one_bounded_checksummed_response(self) -> None:
        with patch("socketserver.ThreadingTCPServer") as server:
            exec(audit_lab.build_lab_web_server("global-web"), {})
        handler = server.call_args.args[1].__new__(server.call_args.args[1])
        handler.path = "/stream"
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        with patch("builtins.open", mock_open()), patch.object(audit_lab.time, "sleep") as sleep:
            handler.do_GET()
        handler.send_response.assert_called_once_with(200)
        handler.send_header.assert_any_call("Content-Length", str(audit_lab.LAB_STREAM_BYTES))
        payload = handler.wfile.getvalue()
        self.assertEqual(len(payload), audit_lab.LAB_STREAM_BYTES)
        expected = b"".join(bytes([index % 256]) * audit_lab.LAB_STREAM_CHUNK_BYTES for index in range(audit_lab.LAB_STREAM_CHUNKS))
        self.assertEqual(hashlib.sha256(payload).digest(), hashlib.sha256(expected).digest())
        self.assertGreater(sleep.call_count * 0.05, audit_lab.LAB_FAILOVER_MAX_SECONDS)
        self.assertLess(sleep.call_count * 0.05, audit_lab.LAB_STREAM_MAX_SECONDS)

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
