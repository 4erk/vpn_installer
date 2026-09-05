from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import client_artifacts
from vpn_installer.config import generate_default_env
from vpn_installer.models import AppError


class ClientArtifactTests(unittest.TestCase):
    def make_env(self) -> dict[str, str]:
        env = generate_default_env("demo")
        env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        return env

    def test_primary_vless_uri_dual_contract_is_byte_stable(self) -> None:
        env = self.make_env()
        env.update(
            {
                "CLIENT_UUID": "00000000-0000-0000-0000-000000000000",
                "RU_REALITY_PUBLIC_KEY": "public-key",
                "RU_REALITY_SHORT_ID": "0123456789abcdef",
            }
        )
        self.assertEqual(
            client_artifacts.render_vless_uri(env),
            "vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?"
            "security=reality&sni=www.bing.com&pbk=public-key&sid=0123456789abcdef&"
            "fp=chrome&type=tcp&flow=xtls-rprx-vision#demo-ru-gateway\n",
        )

    def test_single_client_excludes_only_its_gateway(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "198.51.100.20"
        self.assertEqual(client_artifacts.client_route_excludes(env), ["198.51.100.20/32"])
        self.assertIn("@198.51.100.20:443?", client_artifacts.render_vless_uri(env))
        self.assertNotIn("203.0.113.10", client_artifacts.render_client_profile(env, auto_redirect=False))

    def test_client_artifact_paths_honor_explicit_out_dir(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            paths = client_artifacts.client_artifact_paths(env, out_dir=Path(tmp))

        self.assertEqual(paths["client_dir"], Path(tmp) / "demo" / "client")
        self.assertEqual(paths["vless_uri"].name, "vless-uri.txt")
        self.assertEqual(paths["v2rayn_uri"].name, "v2rayn-uri.txt")
        self.assertEqual(paths["android_xray_json"].name, "android-v2rayng-xray.json")
        self.assertEqual(paths["hysteria2_uri"].name, "hysteria2-uri.txt")
        self.assertEqual(paths["next_steps"], Path(tmp) / "demo" / "NEXT-STEPS.txt")

    def test_next_steps_use_canonical_node_selector(self) -> None:
        rendered = client_artifacts.render_next_steps(self.make_env())

        self.assertIn("status --deployment demo --node gateway", rendered)
        self.assertIn("diagnose client --deployment demo --source <public-ip>", rendered)
        self.assertNotIn("--role ru-gateway", rendered)

    def test_render_client_profiles_honors_explicit_out_dir(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            client_dir = client_artifacts.render_client_profiles(env, out_dir=Path(tmp))

            self.assertEqual(client_dir, Path(tmp) / "demo" / "client")
            self.assertTrue((client_dir / "vless-uri.txt").is_file())
            self.assertEqual(
                (client_dir / "v2rayn-uri.txt").read_text(encoding="utf-8"),
                (client_dir / "vless-uri.txt").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (client_dir / "hiddify-uri.txt").read_text(encoding="utf-8"),
                (client_dir / "vless-uri.txt").read_text(encoding="utf-8"),
            )
            self.assertTrue((client_dir / "android-v2rayng-xray.json").is_file())
            self.assertTrue((client_dir / "hiddify-cross-platform.json").is_file())
            hiddify = json.loads((client_dir / "hiddify-cross-platform.json").read_text(encoding="utf-8"))
            self.assertEqual(hiddify["route"]["final"], client_artifacts.PUBLIC_VLESS_OUTBOUND_TAG)
            self.assertEqual(hiddify["outbounds"][0]["multiplex"], {"enabled": False})
            self.assertTrue((client_dir / "hysteria2-uri.txt").read_text(encoding="utf-8").startswith("hysteria2://"))
            self.assertEqual(
                (client_dir / "android-v2rayng-xray.json").read_text(encoding="utf-8"),
                (client_dir / "windows-xray.json").read_text(encoding="utf-8"),
            )
            self.assertTrue((Path(tmp) / "demo" / "NEXT-STEPS.txt").is_file())
            if os.name != "nt":
                for path in client_dir.iterdir():
                    if path.is_file():
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)

    def test_render_client_profiles_replaces_stale_generated_directory(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            client_dir = Path(tmp) / "demo" / "client"
            stale_path = client_dir / "android-v2rayng-xray.json"
            stale_path.mkdir(parents=True)
            (client_dir / "sing-box-adaptive.json").write_text("stale", encoding="utf-8")
            (client_dir / "live-xray-smoke.json").write_text("stale", encoding="utf-8")
            operator_notes = client_dir / "operator-notes.txt"
            operator_notes.write_text("keep", encoding="utf-8")

            client_artifacts.render_client_profiles(env, out_dir=Path(tmp))

            self.assertTrue(stale_path.is_file())
            self.assertIn('"protocol": "vless"', stale_path.read_text(encoding="utf-8"))
            self.assertFalse((client_dir / "sing-box-adaptive.json").exists())
            self.assertFalse((client_dir / "live-xray-smoke.json").exists())
            self.assertEqual(operator_notes.read_text(encoding="utf-8"), "keep")

    def snapshot(self, client_dir: Path) -> dict[str, bytes | None]:
        return {
            str(path.relative_to(client_dir.parent)): path.read_bytes() if path.is_file() else None
            for path in [*client_dir.rglob("*"), client_dir.parent / "NEXT-STEPS.txt"]
            if path.exists()
        }

    def seed_artifacts(self, env: dict[str, str], root: Path) -> Path:
        client_dir = client_artifacts.render_client_profiles(env, out_dir=root)
        (client_dir / "operator-notes.txt").write_bytes(b"keep operator notes")
        (client_dir / "windows-route-bypass.state.json").write_bytes(b'{"owned":"keep"}')
        (client_dir / "windows-route-bypass.state.json.lock").touch()
        return client_dir

    def test_render_failure_preserves_previous_set(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            before = self.snapshot(client_dir)
            with patch.object(client_artifacts, "render_hysteria2_uri", side_effect=ValueError("render failed")):
                with self.assertRaisesRegex(ValueError, "render failed"):
                    client_artifacts.render_client_profiles(env, out_dir=root)
            self.assertEqual(self.snapshot(client_dir), before)
            self.assertEqual(list(client_dir.parent.glob(".client-stage-*")), [])

    def test_every_staging_write_failure_preserves_previous_set(self) -> None:
        env = self.make_env()
        writer = client_artifacts.write_private_text
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            before = self.snapshot(client_dir)
            for name in (*client_artifacts.GENERATED_CLIENT_FILE_NAMES, "NEXT-STEPS.txt"):
                with self.subTest(name=name):
                    def fail_write(path: Path, content: str) -> None:
                        if path.name == name:
                            raise OSError("disk full")
                        writer(path, content)

                    with patch.object(client_artifacts, "write_private_text", side_effect=fail_write):
                        with self.assertRaisesRegex(OSError, "disk full"):
                            client_artifacts.render_client_profiles(env, out_dir=root)
                    self.assertEqual(self.snapshot(client_dir), before)
                    self.assertEqual(list(client_dir.parent.glob(".client-stage-*")), [])

    def test_invalid_payloads_are_rejected_before_publication(self) -> None:
        env = self.make_env()
        cases = (
            ("render_xray_client_profile", "{bad-json"),
            ("render_xray_client_profile", "[]"),
            ("render_vless_uri", "not-a-uri"),
            ("render_hysteria2_uri", "https://not-a-vpn"),
            ("render_windows_route_bypass_script", ""),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            before = self.snapshot(client_dir)
            for renderer, payload in cases:
                with self.subTest(renderer=renderer, payload=payload):
                    with patch.object(client_artifacts, renderer, return_value=payload):
                        with self.assertRaises((ValueError, AppError)):
                            client_artifacts.render_client_profiles(env, out_dir=root)
                    self.assertEqual(self.snapshot(client_dir), before)

    def test_incomplete_staged_write_is_rejected(self) -> None:
        env = self.make_env()
        writer = client_artifacts.write_private_text
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            before = self.snapshot(client_dir)
            with patch.object(client_artifacts, "write_private_text", side_effect=lambda path, payload: writer(path, payload[:7])):
                with self.assertRaisesRegex(AppError, "incomplete"):
                    client_artifacts.render_client_profiles(env, out_dir=root)
            self.assertEqual(self.snapshot(client_dir), before)

    def test_each_publication_failure_rolls_back_entire_set_and_uri(self) -> None:
        env = self.make_env()
        replace = Path.replace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            before = self.snapshot(client_dir)
            changed_env = dict(env, RU_REALITY_SHORT_ID="0102030405060708")
            for name in (*client_artifacts.GENERATED_CLIENT_FILE_NAMES, "NEXT-STEPS.txt"):
                with self.subTest(name=name):
                    def fail_publish(path: Path, target: Path) -> Path:
                        if "new" in path.parts and path.name == name:
                            raise OSError("replace failed")
                        return replace(path, target)

                    with patch.object(Path, "replace", fail_publish):
                        with self.assertRaisesRegex(OSError, "replace failed"):
                            client_artifacts.render_client_profiles(changed_env, out_dir=root)
                    self.assertEqual(self.snapshot(client_dir), before)
                    self.assertEqual(list(client_dir.parent.glob(".client-stage-*")), [])

    def test_primary_uri_remains_present_until_atomic_replace(self) -> None:
        env = self.make_env()
        replace = Path.replace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            uri_path = client_dir / "vless-uri.txt"
            uri = uri_path.read_bytes()

            def check_replace(path: Path, target: Path) -> Path:
                self.assertEqual(uri_path.read_bytes(), uri)
                return replace(path, target)

            with patch.object(Path, "replace", check_replace):
                client_artifacts.render_client_profiles(env, out_dir=root)
            self.assertEqual(uri_path.read_bytes(), uri)

    def test_interrupted_publication_restores_previous_set(self) -> None:
        env = self.make_env()
        replace = Path.replace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            before = self.snapshot(client_dir)

            def interrupt(path: Path, target: Path) -> Path:
                if "new" in path.parts and path.name == "NEXT-STEPS.txt":
                    raise KeyboardInterrupt("interrupted publication")
                return replace(path, target)

            with patch.object(Path, "replace", interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    client_artifacts.render_client_profiles(dict(env, RU_REALITY_SHORT_ID="0102030405060708"), out_dir=root)
            self.assertEqual(self.snapshot(client_dir), before)
            self.assertEqual(list(client_dir.parent.glob(".client-stage-*")), [])

    def test_failed_fresh_publication_does_not_leave_partial_profiles(self) -> None:
        env = self.make_env()
        replace = Path.replace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def fail_publish(path: Path, target: Path) -> Path:
                if "new" in path.parts and path.name == "NEXT-STEPS.txt":
                    raise OSError("publish failed")
                return replace(path, target)

            with patch.object(Path, "replace", fail_publish):
                with self.assertRaisesRegex(OSError, "publish failed"):
                    client_artifacts.render_client_profiles(env, out_dir=root)
            self.assertEqual(self.snapshot(root / "demo" / "client"), {})

    def test_stale_cleanup_failure_restores_files_and_generated_directories(self) -> None:
        env = self.make_env()
        replace = Path.replace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            directory = client_dir / "android-v2rayng-xray.json"
            directory.unlink()
            directory.mkdir()
            (directory / "keep.txt").write_bytes(b"previous directory")
            for name in client_artifacts.STALE_CLIENT_ARTIFACT_NAMES:
                (client_dir / name).write_bytes(b"previous stale file")
            before = self.snapshot(client_dir)

            def fail_stale(path: Path, target: Path) -> Path:
                if path == client_dir / client_artifacts.STALE_CLIENT_ARTIFACT_NAMES[-1]:
                    raise OSError("cleanup failed")
                return replace(path, target)

            with patch.object(Path, "replace", fail_stale):
                with self.assertRaisesRegex(OSError, "cleanup failed"):
                    client_artifacts.render_client_profiles(env, out_dir=root)
            self.assertEqual(self.snapshot(client_dir), before)

    def test_rollback_failure_retains_backup_and_reports_its_path(self) -> None:
        env = self.make_env()
        replace = Path.replace
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            old_uri = (client_dir / "vless-uri.txt").read_bytes()

            def fail_replace(path: Path, target: Path) -> Path:
                if path.name == "NEXT-STEPS.txt" and "new" in path.parts:
                    raise OSError("publish failed")
                if path.name == "vless-uri.txt" and "previous" in path.parts:
                    raise OSError("rollback failed")
                return replace(path, target)

            with patch.object(Path, "replace", fail_replace):
                with self.assertRaisesRegex(AppError, "rollback incomplete") as raised:
                    client_artifacts.render_client_profiles(env, out_dir=root)
            backups = list(client_dir.parent.glob(".client-stage-*"))
            self.assertEqual(len(backups), 1)
            self.assertIn(str(backups[0]), str(raised.exception))
            self.assertEqual((backups[0] / "previous" / "client" / "vless-uri.txt").read_bytes(), old_uri)

    def test_concurrent_publication_is_rejected_without_touching_artifacts(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            before = self.snapshot(client_dir)
            with client_artifacts._client_artifact_lock(client_dir):
                with self.assertRaisesRegex(AppError, "another process"):
                    client_artifacts.render_client_profiles(env, out_dir=root)
            self.assertEqual(self.snapshot(client_dir), before)
            client_artifacts.render_client_profiles(env, out_dir=root)

    def test_success_preserves_operator_state_and_primary_uri(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client_dir = self.seed_artifacts(env, root)
            before = self.snapshot(client_dir)
            client_artifacts.render_client_profiles(env, out_dir=root)
            self.assertEqual(self.snapshot(client_dir), before)

    def test_route_helper_only_targets_server_endpoints_not_cidr_excludes(self) -> None:
        env = self.make_env()
        env["CLIENT_ROUTE_EXCLUDE_V4"] = "192.0.2.0/24,192.0.2.77/32"
        env["CLIENT_ROUTE_EXCLUDE_V6"] = "2001:db8::/48"
        script = client_artifacts.render_windows_route_bypass_script(env)
        self.assertIn('$ServerIps = @("203.0.113.10", "198.51.100.20")', script)
        self.assertNotIn("192.0.2.", script)
        self.assertNotIn("2001:db8", script)
        profile = json.loads(client_artifacts.render_client_profile(env, auto_redirect=False))
        self.assertEqual(profile["inbounds"][0]["route_exclude_address"][-3:], ["192.0.2.0/24", "192.0.2.77/32", "2001:db8::/48"])

    def test_single_ipv6_server_helper_uses_host_prefix_and_does_not_include_exit(self) -> None:
        env = generate_default_env("demo", topology="single", gateway_location="foreign")
        env["GATEWAY_PUBLIC_IP"] = "2001:db8::42"
        script = client_artifacts.render_windows_route_bypass_script(env)
        self.assertIn('$ServerIps = @("2001:db8::42")', script)
        self.assertIn("{ 32 } else { 128 }", script)
        self.assertNotIn('$prefix = "$ip/32"', script)

    @unittest.skipUnless(shutil.which("powershell") or shutil.which("pwsh"), "PowerShell parser unavailable")
    def test_powershell_parser_and_pure_route_decisions_without_executing_helper(self) -> None:
        # Parse the full helper, but execute ONLY pure functions. No generated entrypoint is invoked.
        harness = r"""
        $ErrorActionPreference = 'Stop'
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile('__PATH__', [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw ($errors | Out-String) }
        function Get-NetRoute { throw 'Network cmdlet must never run in this test' }
        function New-NetRoute { throw 'Network cmdlet must never run in this test' }
        function Remove-NetRoute { throw 'Network cmdlet must never run in this test' }
        $fields = $ast.Find({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$RouteFields' }, $true)
        . ([scriptblock]::Create($fields.Extent.Text))
        foreach ($name in @('Test-OwnedRoute', 'Get-RouteRecord', 'Get-RouteAction')) {
          $definition = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
          . ([scriptblock]::Create($definition.Extent.Text))
        }
        function Assert-Equal($Actual, $Expected) { if ($Actual -cne $Expected) { throw "$Actual != $Expected" } }
        $route = [pscustomobject]@{ DestinationPrefix='203.0.113.10/32'; InterfaceIndex=4; InterfaceAlias='Ethernet'; NextHop='192.168.1.1'; RouteMetric=1; Protocol='NetMgmt'; Publish='No' }
        $record = Get-RouteRecord $route
        $record = $record | ConvertTo-Json | ConvertFrom-Json
        Assert-Equal (Test-OwnedRoute $route $record) $true
        $enumRoute = $route | Select-Object -Property $RouteFields
        $enumRoute.Protocol = [DayOfWeek]::Monday
        $enumRoute.Publish = [ConsoleColor]::DarkBlue
        $oldEnumRecord = ($enumRoute | Select-Object -Property $RouteFields) | ConvertTo-Json | ConvertFrom-Json
        Assert-Equal ([string]$oldEnumRecord.Protocol -ceq [string]$enumRoute.Protocol) $false
        Assert-Equal ([string]$oldEnumRecord.Publish -ceq [string]$enumRoute.Publish) $false
        Assert-Equal (Test-OwnedRoute $enumRoute $oldEnumRecord) $false
        $enumRecord = (Get-RouteRecord $enumRoute) | ConvertTo-Json | ConvertFrom-Json
        Assert-Equal (Test-OwnedRoute $enumRoute $enumRecord) $true
        foreach ($field in $RouteFields) {
          Assert-Equal ($enumRecord.$field -is [string]) $true
          Assert-Equal $enumRecord.$field ([string]$enumRoute.$field)
        }
        Assert-Equal (Get-RouteAction @($enumRoute) $enumRecord $true) 'remove'
        Assert-Equal (Get-RouteAction @() $null $false) 'create'
        Assert-Equal (Get-RouteAction @() $record $true) 'preserve'
        Assert-Equal (Get-RouteAction @($route) $null $true) 'preserve'
        Assert-Equal (Get-RouteAction @($route) $null $false) 'preserve'
        Assert-Equal (Get-RouteAction @($route) $record $false) 'preserve'
        Assert-Equal (Get-RouteAction @($route) $record $true) 'remove'
        foreach ($field in $RouteFields) {
          $modified = $record | Select-Object -Property $RouteFields
          $modified.$field = 'changed'
          Assert-Equal (Test-OwnedRoute $route $modified) $false
          Assert-Equal (Get-RouteAction @($route) $modified $true) 'preserve'
          $modified.$field = $null
          Assert-Equal (Test-OwnedRoute $route $modified) $false
        }
        $foreign = $record | Select-Object -Property $RouteFields
        $foreign.NextHop = '192.168.1.2'
        $existing = @($foreign, $route)
        Assert-Equal (Get-RouteAction $existing $record $true) 'remove'
        $removals = @($existing | Where-Object { Test-OwnedRoute $_ $record })
        Assert-Equal $removals.Count 1
        Assert-Equal $removals[0].NextHop '192.168.1.1'
        Write-Output 'route-decisions-ok'
        """
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "helper.ps1"
            script_path.write_text(client_artifacts.render_windows_route_bypass_script(self.make_env()), encoding="utf-8")
            command = harness.replace("__PATH__", str(script_path).replace("'", "''"))
            encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
            result = subprocess.run(
                [shutil.which("powershell") or shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("route-decisions-ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
