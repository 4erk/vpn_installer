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
    if bundled.is_file():
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
        env["EXIT_PUBLIC_IP"] = ""
        env.pop("RU_PUBLIC_IP", None)
        env.pop("FOREIGN_PUBLIC_IP", None)
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

    def render_single(self, root: Path, *, legacy_role: bool = False) -> tuple[Path, subprocess.CompletedProcess[str]]:
        root.mkdir(parents=True, exist_ok=True)
        env_path = root / "single.env"
        output = root / "rendered"
        self.write_single_env(env_path)
        selector = ("--role", "ru-gateway") if legacy_role else ("--node", "gateway")
        result = self.run_bash(
            *selector,
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
                f"validate_bundle '{bundle.as_posix()}' gateway '{contract.as_posix()}' '' 0 0",
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
        self.assertIn("adapt-schema2", text)
        self.assertNotIn("render-role", text)
        self.assertNotIn("from vpn_installer.manifest import", text)
        self.assertNotIn("def canonical_digest", text)
        self.assertNotIn("RU_PUBLIC_IP", text)
        self.assertNotIn("FOREIGN_PUBLIC_IP", text)
        self.assertNotRegex(text, r"(?m)^ROLE=")
        self.assertNotIn("install schema 3 in dual mode first", text)
        self.assertIn('VPNSTACK_ACCEPTANCE_PATH="${VPNSTACK_ROOT}/last-acceptance.json"', text)
        self.assertIn("installed node ${previous_node} does not match requested node ${requested_node}", text)
        self.assertIn('verify_previous_owned_path "${previous_contract}" "${path}"', text)
        self.assertIn('elif [[ "${schema}" == "2" ]]; then', text)
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

    def test_render_only_writes_schema_three_single_gateway_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output, result = self.render_single(Path(temp))
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "render-manifest.json").read_text(encoding="utf-8"))
            plan = json.loads((output / "install-plan.json").read_text(encoding="utf-8"))
            node_env = (output / "node.env").read_text(encoding="utf-8")

        self.assertEqual(manifest["schema_version"], 3)
        self.assertEqual(plan["schema_version"], 3)
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

    def test_legacy_role_is_only_a_deprecated_cli_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output, result = self.render_single(Path(temp), legacy_role=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "render-manifest.json").read_text(encoding="utf-8"))
        self.assertIn("--role is deprecated; use --node gateway", result.stderr)
        self.assertEqual(manifest["node_id"], "gateway")

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
