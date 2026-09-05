from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from vpn_installer.config import generate_default_env, render_env_text
from vpn_installer.manifest import render_node_env_text
from vpn_installer.platforms import HostFacts, resolve_platform
from vpn_installer.render import copy_python_package, write_node_rendered_files


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = ROOT / "install.sh"


def find_bash() -> Path:
    candidates = (
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    resolved = shutil.which("bash")
    if resolved:
        return Path(resolved)
    raise unittest.SkipTest("bash is unavailable")


def find_python() -> Path:
    bundled = ROOT / ".runtime" / "python" / "windows" / "python.exe"
    if os.name == "nt" and bundled.is_file():
        return bundled
    return Path(os.sys.executable)


class InstallScriptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bash = find_bash()
        cls.python = find_python()

    def run_bash(
        self,
        *args: str,
        script: str | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(self.bash)]
        if script is None:
            command.extend([str(INSTALL_SCRIPT), *args])
        else:
            command.extend(["-c", script])
        process_env = os.environ.copy()
        process_env["PYTHON_BIN"] = self.python.as_posix()
        if env:
            process_env.update(env)
        return subprocess.run(
            command,
            cwd=ROOT,
            env=process_env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def write_single_env(self, path: Path) -> None:
        env = generate_default_env(
            "install-script-contract",
            topology="single",
            gateway_location="foreign",
        )
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        text = render_env_text(env)
        self.assertNotIn("RU_PUBLIC_IP", text)
        self.assertNotIn("FOREIGN_PUBLIC_IP", text)
        path.write_text(text, encoding="utf-8")

    def write_dual_env(self, path: Path) -> None:
        env = generate_default_env(
            "install-script-dual-contract",
            topology="dual",
            gateway_location="ru",
        )
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        env.pop("RU_PUBLIC_IP", None)
        env.pop("FOREIGN_PUBLIC_IP", None)
        path.write_text(render_env_text(env), encoding="utf-8")

    def render_single(self, root: Path) -> tuple[Path, subprocess.CompletedProcess[str]]:
        root.mkdir(parents=True, exist_ok=True)
        env_path = root / "single.env"
        output = root / "rendered"
        self.write_single_env(env_path)
        result = self.run_bash(
            "--node",
            "gateway",
            "--env-file",
            env_path.as_posix(),
            "--render-only",
            "--output-dir",
            output.as_posix(),
        )
        return output, result

    @staticmethod
    def canonical_plan_digest(plan: dict[str, object]) -> str:
        payload = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def validate_from_shell(self, bundle: Path, contract: Path) -> subprocess.CompletedProcess[str]:
        source = INSTALL_SCRIPT.as_posix()
        command = "\n".join(
            (
                "set -euo pipefail",
                "export VPNSTACK_INSTALL_LIBRARY_ONLY=1",
                f"source '{source}'",
                f"validate_bundle '{bundle.as_posix()}' gateway '{contract.as_posix()}' '' 0 0 0",
            )
        )
        return self.run_bash(script=command)

    def run_python_bootstrap(self, provider: str) -> subprocess.CompletedProcess[str]:
        source = INSTALL_SCRIPT.as_posix()
        command = "\n".join(
            (
                "set -euo pipefail",
                "export VPNSTACK_INSTALL_LIBRARY_ONLY=1",
                f"source '{source}'",
                f"PROVIDER='{provider}'",
                "PY_READY=0",
                "select_python() {",
                "  if [[ \"$PY_READY\" == 1 ]]; then PYTHON_BIN=python3; return 0; fi",
                "  return 1",
                "}",
                "command() {",
                "  if [[ \"${1:-}\" == -v ]]; then [[ \"${2:-}\" == \"$PROVIDER\" ]]; return; fi",
                "  builtin command \"$@\"",
                "}",
                "apt-get() { printf 'apt-get:%s:%s\\n' \"${DEBIAN_FRONTEND:-}\" \"$*\"; [[ \"$1\" != install ]] || PY_READY=1; }",
                "dnf5() { printf 'dnf5:%s\\n' \"$*\"; PY_READY=1; }",
                "dnf() { printf 'dnf:%s\\n' \"$*\"; PY_READY=1; }",
                "bootstrap_python",
                "printf 'python=%s\\n' \"$PYTHON_BIN\"",
            )
        )
        return self.run_bash(script=command)

    def test_bash_syntax_and_canonical_static_contract(self) -> None:
        syntax = subprocess.run(
            [str(self.bash), "-n", str(INSTALL_SCRIPT)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        text = INSTALL_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("render-node", text)
        self.assertIn("validate-bundle", text)
        self.assertIn("validate-installed", text)
        self.assertNotIn("render-role", text)
        self.assertNotIn("--role", text)
        self.assertNotIn("from vpn_installer.manifest import", text)
        self.assertNotIn("def canonical_digest", text)
        self.assertNotIn("RU_PUBLIC_IP", text)
        self.assertNotIn("FOREIGN_PUBLIC_IP", text)
        self.assertNotRegex(text, r"(?m)^ROLE=")
        self.assertNotIn("install schema 3 in dual mode first", text)
        self.assertIn('VPNSTACK_ACCEPTANCE_PATH="${VPNSTACK_ROOT}/last-acceptance.json"', text)
        self.assertIn("installed node ${previous_node} does not match requested node ${requested_node}", text)
        self.assertIn('verify_previous_owned_path "${previous_contract}" "${path}"', text)
        self.assertIn("normalize_acceptance_snapshot", text)
        self.assertIn('local require_current_platform="${7:-1}"', text)
        self.assertIn('verify_snapshot_service_states "${snapshot}"', text)
        self.assertNotIn("restored schema-2 service is not active", text)
        self.assertLess(
            text.index('install_packages_from_plan "${source_contract}"'),
            text.index('create_transaction_snapshots "${scope_dir}" "${source_bundle}"'),
        )
        self.assertLess(
            text.index('start_planned_services "${staged_contract}"'),
            text.index('retire_previous_services "${PREVIOUS_CONTRACT}" "${staged_contract}"'),
        )
        install_body = text.split("install_action() {", 1)[1].split("\n}\n\ncurrent_release_contract()", 1)[0]
        self.assertLess(install_body.index('verify_active_release "${staged_contract}"'), install_body.index("prune_unreferenced_releases"))
        self.assertIn('storage-maintain --deep', install_body)
        self.assertIn("VPNSTACK_REVISION_LIMIT=10", text)
        snapshot_body = text.split("create_transaction_snapshots() {", 1)[1].split("\n}\n\nprune_revision_snapshots()", 1)[0]
        self.assertLess(snapshot_body.index("prune_revision_snapshots"), snapshot_body.index("TRANSACTION_SNAPSHOT="))
        bootstrap_body = text.split("bootstrap_python() {", 1)[1].split("\n}\n\nparse_cli()", 1)[0]
        self.assertIn("apt-get install -y --no-install-recommends python3", bootstrap_body)
        self.assertIn("dnf5 -y --setopt=install_weak_deps=False install python3", bootstrap_body)
        self.assertIn("dnf -y --setopt=install_weak_deps=False install python3", bootstrap_body)
        self.assertNotIn("route", bootstrap_body)
        self.assertNotIn("sysctl", bootstrap_body)
        main_body = text.split("main() {", 1)[1].split("\n}\n\nif [[", 1)[0]
        self.assertLess(main_body.index("validate_install_request"), main_body.index("bootstrap_python"))
        bootstrap_index = main_body.index("bootstrap_python")
        self.assertLess(bootstrap_index, main_body.index("find_python", bootstrap_index))

    def test_bound_manifest_is_checked_before_install_packages(self) -> None:
        env = generate_default_env("bound-test", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        platform = resolve_platform(HostFacts("debian", "13", "x86_64", init_system="systemd"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / "upload"
            stage.mkdir()
            copy_python_package(stage)
            write_node_rendered_files(env, "gateway", root / "preview", platform=platform)
            shutil.copy2(root / "preview" / "render-manifest.json", stage / "expected-manifest.json")
            env_path = stage / "deployment.env"
            for changed in (False, True):
                with self.subTest(changed=changed):
                    selected_env = {**env, "RU_LISTEN_PORT": "8443"} if changed else env
                    env_path.write_text(render_node_env_text(selected_env, "gateway"), encoding="utf-8")
                    script = "\n".join((
                        "set -Eeuo pipefail",
                        "export VPNSTACK_INSTALL_LIBRARY_ONLY=1",
                        f"source '{INSTALL_SCRIPT.as_posix()}'",
                        f"SCRIPT_DIR='{stage.as_posix()}'",
                        f"ENV_FILE='{env_path.as_posix()}'",
                        "NODE=gateway",
                        "RENDER_ONLY=1",
                        "trap on_exit EXIT",
                        "validate_bundle() { :; }",
                        "prepare_previous_contract() { PREVIOUS_CONTRACT=''; }",
                        "install_packages_from_plan() { printf 'PACKAGES_REACHED\\n'; exit 0; }",
                        "install_action",
                    ))
                    result = self.run_bash(script=script)
                    if changed:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("target render differs from expected manifest", result.stderr)
                        self.assertNotIn("PACKAGES_REACHED", result.stdout)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("PACKAGES_REACHED", result.stdout)

    def test_python_bootstrap_uses_exact_supported_provider_commands(self) -> None:
        expected = {
            "apt-get": (
                "apt-get:noninteractive:update",
                "apt-get:noninteractive:install -y --no-install-recommends python3",
            ),
            "dnf5": ("dnf5:-y --setopt=install_weak_deps=False install python3",),
            "dnf": ("dnf:-y --setopt=install_weak_deps=False install python3",),
        }
        for provider, commands in expected.items():
            with self.subTest(provider=provider):
                result = self.run_python_bootstrap(provider)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [*commands, "python=python3"])

    def test_python_bootstrap_fails_closed_without_supported_provider(self) -> None:
        result = self.run_python_bootstrap("none")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no supported package manager (apt-get, dnf5, dnf) was found", result.stderr)

    @unittest.skipIf(os.name == "nt", "Windows Git Bash does not preserve POSIX symlink semantics")
    def test_release_pruning_keeps_only_current_and_previous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "vpn-stack"
            shell_root = root.as_posix()
            source = INSTALL_SCRIPT.as_posix()
            command = "\n".join(
                (
                    "set -euo pipefail",
                    f"export VPNSTACK_ROOT='{shell_root}'",
                    "export VPNSTACK_INSTALL_LIBRARY_ONLY=1",
                    f"source '{source}'",
                    "mkdir -p \"$VPNSTACK_RELEASES_DIR/current\" \"$VPNSTACK_RELEASES_DIR/previous\" \"$VPNSTACK_RELEASES_DIR/stale\"",
                    "touch \"$VPNSTACK_RELEASES_DIR/sentinel\"",
                    "ln -s \"$VPNSTACK_RELEASES_DIR/current\" \"$VPNSTACK_CURRENT_RELEASE\"",
                    "ln -s \"$VPNSTACK_RELEASES_DIR/previous\" \"$VPNSTACK_PREVIOUS_RELEASE\"",
                    "prune_unreferenced_releases",
                    "test -d \"$VPNSTACK_RELEASES_DIR/current\"",
                    "test -d \"$VPNSTACK_RELEASES_DIR/previous\"",
                    "test ! -e \"$VPNSTACK_RELEASES_DIR/stale\"",
                    "test -f \"$VPNSTACK_RELEASES_DIR/sentinel\"",
                )
            )
            result = self.run_bash(script=command)

        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipIf(os.name == "nt", "Windows Git Bash does not preserve POSIX symlink semantics")
    def test_revision_pruning_keeps_latest_and_bounded_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "vpn-stack"
            source = INSTALL_SCRIPT.as_posix()
            command = "\n".join(
                (
                    "set -euo pipefail",
                    f"export VPNSTACK_ROOT='{root.as_posix()}'",
                    "export VPNSTACK_INSTALL_LIBRARY_ONLY=1",
                    f"source '{source}'",
                    "mkdir -p \"$VPNSTACK_REVISION_DIR\"",
                    "for n in $(seq -w 1 15); do mkdir \"$VPNSTACK_REVISION_DIR/revision-${n}\"; done",
                    "ln -s \"$VPNSTACK_REVISION_DIR/revision-01\" \"$VPNSTACK_LATEST_SNAPSHOT\"",
                    "prune_revision_snapshots",
                    "test -d \"$(readlink -f \"$VPNSTACK_LATEST_SNAPSHOT\")\"",
                    "test \"$(find \"$VPNSTACK_REVISION_DIR\" -mindepth 1 -maxdepth 1 -type d | wc -l)\" = 9",
                )
            )
            result = self.run_bash(script=command)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_render_only_writes_current_single_gateway_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output, result = self.render_single(Path(temp))
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "render-manifest.json").read_text(encoding="utf-8"))
            plan = json.loads((output / "install-plan.json").read_text(encoding="utf-8"))
            node_env = (output / "node.env").read_text(encoding="utf-8")

        self.assertEqual(manifest["schema_version"], 5)
        self.assertEqual(plan["schema_version"], 5)
        self.assertEqual(manifest["install_plan"], plan)
        self.assertEqual(plan["node_id"], "gateway")
        self.assertEqual(plan["topology"], "single")
        self.assertNotIn("RU_PUBLIC_IP", node_env)
        self.assertNotIn("FOREIGN_PUBLIC_IP", node_env)
        self.assertNotIn("wireguard", {service["name"] for service in plan["services"]})
        self.assertNotIn("transport", {service["name"] for service in plan["services"]})
        self.assertFalse(any(path.startswith("/etc/wireguard/") for path in (
            item["install_path"] for item in plan["artifacts"].values()
        )))
        self.assertNotIn("wireguard", plan["packages"])
        self.assertNotIn("wireguard-tools", plan["packages"])
        self.assertNotIn("interserver_transport.py", plan["artifacts"])
        self.assertNotIn("topology.py", plan["artifacts"])

    def test_dual_render_only_supports_both_canonical_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env_path = root / "dual.env"
            self.write_dual_env(env_path)
            for node in ("gateway", "exit"):
                with self.subTest(node=node):
                    output = root / node
                    result = self.run_bash(
                        "--node",
                        node,
                        "--env-file",
                        env_path.as_posix(),
                        "--render-only",
                        "--output-dir",
                        output.as_posix(),
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    plan = json.loads((output / "install-plan.json").read_text(encoding="utf-8"))
                    service_names = {service["name"] for service in plan["services"]}
                    self.assertEqual(plan["node_id"], node)
                    self.assertEqual(plan["topology"], "dual")
                    self.assertIn("wireguard", service_names)
                    self.assertEqual("transport" in service_names, node == "gateway")
                    self.assertIn("topology.py", plan["artifacts"])

    def test_validator_fails_closed_on_schema_artifact_and_service_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            clean, render = self.render_single(root / "clean")
            self.assertEqual(render.returncode, 0, render.stderr)
            valid = self.validate_from_shell(clean, root / "valid-contract")
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn(
                "deployment\tinstall-script-contract",
                (root / "valid-contract/meta.tsv").read_text(encoding="utf-8"),
            )

            for mutation in ("schema", "artifact", "service"):
                with self.subTest(mutation=mutation):
                    bundle = root / mutation
                    shutil.copytree(clean, bundle)
                    manifest_path = bundle / "render-manifest.json"
                    plan_path = bundle / "install-plan.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    plan = json.loads(plan_path.read_text(encoding="utf-8"))
                    if mutation == "schema":
                        manifest["schema_version"] = 99
                    elif mutation == "artifact":
                        payload = b"unexpected\n"
                        (bundle / "unexpected.service").write_bytes(payload)
                        entry = {
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "install_path": "/etc/systemd/system/unexpected.service",
                            "required": True,
                            "capability": "base",
                            "ownership": "managed",
                        }
                        manifest["artifacts"]["unexpected.service"] = entry
                        plan["artifacts"]["unexpected.service"] = entry
                    else:
                        plan["services"].append(
                            {
                                "name": "unexpected",
                                "unit": "unexpected.service",
                                "ownership": "managed",
                            }
                        )
                    manifest["install_plan"] = plan
                    manifest["install_plan_sha256"] = self.canonical_plan_digest(plan)
                    self.write_json(plan_path, plan)
                    self.write_json(manifest_path, manifest)
                    result = self.validate_from_shell(bundle, root / f"{mutation}-contract")
                    self.assertNotEqual(result.returncode, 0)

    def test_single_gateway_service_execution_never_touches_interserver_units(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle, render = self.render_single(root / "bundle")
            self.assertEqual(render.returncode, 0, render.stderr)
            contract = root / "contract"
            validated = self.validate_from_shell(bundle, contract)
            self.assertEqual(validated.returncode, 0, validated.stderr)

            log = root / "commands.log"
            fake_systemctl = root / "systemctl"
            fake_python = root / "python"
            fake_systemctl.write_text(
                "#!/usr/bin/env bash\nprintf 'systemctl %s\\n' \"$*\" >>\"$COMMAND_LOG\"\n",
                encoding="utf-8",
            )
            fake_python.write_text(
                "#!/usr/bin/env bash\nprintf 'python %s\\n' \"$*\" >>\"$COMMAND_LOG\"\n",
                encoding="utf-8",
            )
            fake_systemctl.chmod(0o755)
            fake_python.chmod(0o755)
            scope = root / "scope"
            source = INSTALL_SCRIPT.as_posix()
            command = "\n".join(
                (
                    "set -euo pipefail",
                    "export VPNSTACK_INSTALL_LIBRARY_ONLY=1",
                    f"source '{source}'",
                    f"SYSTEMCTL_BIN='{fake_systemctl.as_posix()}'",
                    f"PYTHON_BIN='{fake_python.as_posix()}'",
                    f"build_operation_scope '{contract.as_posix()}' '' '{scope.as_posix()}'",
                    f"start_planned_services '{contract.as_posix()}'",
                )
            )
            result = self.run_bash(
                script=command,
                env={"COMMAND_LOG": log.as_posix()},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            commands = log.read_text(encoding="utf-8")
            scope_paths = (scope / "paths.list").read_text(encoding="utf-8")

        self.assertNotIn("wg-quick@", commands)
        self.assertNotIn("transport", commands)
        self.assertNotIn("/etc/wireguard/", scope_paths)
        self.assertNotIn("transport-state", scope_paths)
        self.assertIn("restart sing-box.service", commands)
        self.assertIn("restart vpn-stack-xray.service", commands)

    def test_previous_owned_path_rejects_a_modified_live_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            release = root / "release"
            contract = root / "contract"
            release.mkdir()
            contract.mkdir()
            source = release / "owned.conf"
            live = root / "live.conf"
            source.write_text("owned\n", encoding="utf-8")
            live.write_text("owned\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            (contract / "artifacts.tsv").write_text(
                f"owned.conf\t{live.as_posix()}\tmanaged\t{digest}\tbase\n",
                encoding="utf-8",
            )
            (contract / "assets.tsv").write_text("", encoding="utf-8")
            script = "\n".join(
                (
                    "set -euo pipefail",
                    "export VPNSTACK_INSTALL_LIBRARY_ONLY=1",
                    f"source '{INSTALL_SCRIPT.as_posix()}'",
                    f"PREVIOUS_RELEASE_DIR='{release.as_posix()}'",
                    f"verify_previous_owned_path '{contract.as_posix()}' '{live.as_posix()}'",
                )
            )
            clean = self.run_bash(script=script)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            live.write_text("operator change\n", encoding="utf-8")
            modified = self.run_bash(script=script)
        self.assertNotEqual(modified.returncode, 0)
        self.assertIn("managed file was modified", modified.stderr)

    def test_rollback_service_verifier_preserves_disabled_admin_snapshot_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            (snapshot / "service-state.tsv").write_text(
                "sing-box\tsing-box.service\tmanaged\tenabled\tactive\n"
                "admin\tvpn-stack-admin.service\tmanaged\tdisabled\tinactive\n"
                "resolver\tsystemd-resolved.service\tborrowed\tenabled\tactive\n",
                encoding="utf-8",
            )
            fake_systemctl = root / "systemctl"
            fake_systemctl.write_text(
                "#!/usr/bin/env bash\n"
                "case \"$1:$2\" in\n"
                "  is-enabled:vpn-stack-admin.service) printf 'disabled\\n' ;;\n"
                "  is-active:vpn-stack-admin.service) printf '%s\\n' \"${ADMIN_ACTIVE:-inactive}\" ;;\n"
                "  is-enabled:*) printf 'enabled\\n' ;;\n"
                "  is-active:*) printf 'active\\n' ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_systemctl.chmod(0o755)
            script = "\n".join(
                (
                    "set -euo pipefail",
                    "export VPNSTACK_INSTALL_LIBRARY_ONLY=1",
                    f"source '{INSTALL_SCRIPT.as_posix()}'",
                    f"SYSTEMCTL_BIN='{fake_systemctl.as_posix()}'",
                    f"verify_snapshot_service_states '{snapshot.as_posix()}'",
                )
            )
            matching = self.run_bash(script=script, env={"ADMIN_ACTIVE": "inactive"})
            mismatched = self.run_bash(script=script, env={"ADMIN_ACTIVE": "active"})

        self.assertEqual(matching.returncode, 0, matching.stderr)
        self.assertNotEqual(mismatched.returncode, 0)
        self.assertIn("restored service activity differs from snapshot: vpn-stack-admin.service", mismatched.stderr)
        self.assertIn("actual=active", mismatched.stderr)


if __name__ == "__main__":
    unittest.main()
