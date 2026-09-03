from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.config import generate_default_env, render_env_text
from vpn_installer.install_support import load_runtime_env, main as install_support_main
from vpn_installer.manifest import render_node_env_text
from vpn_installer.render import write_node_rendered_files
from vpn_installer.topology import NODE_EXIT, NODE_GATEWAY, TOPOLOGY_DUAL, TOPOLOGY_SINGLE, TopologySpec


class InstallSupportTests(unittest.TestCase):
    def make_env(self, topology: str = TOPOLOGY_DUAL, location: str = "ru") -> dict[str, str]:
        env = generate_default_env("demo", topology=topology, gateway_location=location)
        gateway_ip = "203.0.113.10" if location == "ru" else "198.51.100.10"
        env["GATEWAY_PUBLIC_IP"] = gateway_ip
        if topology == TOPOLOGY_DUAL:
            env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        return env

    def test_render_node_writes_flat_gateway_artifacts(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            output_dir = tmp_path / "out"
            env_path.write_text(render_env_text(env), encoding="utf-8")
            rc = install_support_main(["render-node", "--node", NODE_GATEWAY, "--env-file", str(env_path), "--output-dir", str(output_dir)])
            self.assertEqual(rc, 0)
            payload = json.loads((output_dir / "sing-box.json").read_text(encoding="utf-8"))
            xray_payload = json.loads((output_dir / "xray.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["route"]["final"], "to-foreign")
            self.assertNotIn("multiplex", payload["inbounds"][0])
            self.assertEqual(payload["inbounds"][0]["listen_port"], 2080)
            self.assertEqual(xray_payload["inbounds"][0]["port"], 443)
            self.assertTrue((output_dir / "vpn-stack-agent.py").is_file())
            self.assertFalse((output_dir / "guard.sh").exists())
            self.assertTrue((output_dir / "admin_apply.py").is_file())
            self.assertTrue((output_dir / "admin_web.py").is_file())
            self.assertTrue((output_dir / "vpn-stack-xray.service").is_file())
            self.assertTrue((output_dir / "vpn-stack-admin.service").is_file())
            self.assertFalse((output_dir / "vpn-stack-sync.service").exists())
            self.assertTrue((output_dir / "vpn-stack-health.service").is_file())
            self.assertFalse((output_dir / "vpn-stack-guard.service").exists())
            self.assertFalse((output_dir / "vpn-stack-subscription.service").exists())

    def test_render_node_preserves_explicit_gateway_port(self) -> None:
        env = self.make_env()
        env["RU_LISTEN_PORT"] = "8443"
        env["RU_REALITY_MAX_TIME_DIFFERENCE"] = "24h"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            output_dir = tmp_path / "out"
            env_path.write_text(render_env_text(env), encoding="utf-8")
            rc = install_support_main(["render-node", "--node", NODE_GATEWAY, "--env-file", str(env_path), "--output-dir", str(output_dir)])
            self.assertEqual(rc, 0)
            router_payload = json.loads((output_dir / "sing-box.json").read_text(encoding="utf-8"))
            xray_payload = json.loads((output_dir / "xray.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [inbound["listen_port"] for inbound in router_payload["inbounds"]],
                [2080, 8443, 19091, 19093, 19094],
            )
        self.assertEqual(xray_payload["inbounds"][0]["port"], 8443)
        self.assertNotIn("maxTimeDiff", xray_payload["inbounds"][0]["streamSettings"]["realitySettings"])

    def test_render_node_applies_exit_wan_override(self) -> None:
        env = self.make_env()
        env["WAN_INTERFACE"] = ""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            output_dir = tmp_path / "out"
            env_path.write_text(render_env_text(env), encoding="utf-8")
            rc = install_support_main(
                [
                    "render-node",
                    "--node",
                    NODE_EXIT,
                    "--env-file",
                    str(env_path),
                    "--output-dir",
                    str(output_dir),
                    "--set",
                    "WAN_INTERFACE=ens7",
                ]
            )
            self.assertEqual(rc, 0)
            nftables = (output_dir / "nftables.conf").read_text(encoding="utf-8")
            self.assertIn('oifname "ens7"', nftables)

    def test_render_node_matrix_delegates_capability_outputs(self) -> None:
        cases = (
            (TOPOLOGY_SINGLE, "ru", NODE_GATEWAY),
            (TOPOLOGY_SINGLE, "foreign", NODE_GATEWAY),
            (TOPOLOGY_DUAL, "ru", NODE_GATEWAY),
            (TOPOLOGY_DUAL, "ru", NODE_EXIT),
        )
        for topology, location, node_id in cases:
            with self.subTest(topology=topology, location=location, node=node_id):
                env = self.make_env(topology, location)
                plan = TopologySpec.from_env(env).plan(node_id)
                with tempfile.TemporaryDirectory() as tmp:
                    tmp_path = Path(tmp)
                    env_path = tmp_path / "demo.env"
                    output_dir = tmp_path / "out"
                    env_path.write_text(render_env_text(env), encoding="utf-8")
                    rc = install_support_main(
                        ["render-node", "--node", node_id, "--env-file", str(env_path), "--output-dir", str(output_dir)]
                    )
                    self.assertEqual(rc, 0)
                    manifest = json.loads((output_dir / "render-manifest.json").read_text(encoding="utf-8"))
                    output_names = {path.name for path in output_dir.iterdir()}

                self.assertEqual(manifest["schema_version"], 5)
                self.assertEqual(manifest["install_plan"]["schema_version"], 5)
                self.assertEqual(manifest["node"]["id"], node_id)
                self.assertEqual(manifest["node"]["location"], plan.location)
                self.assertEqual(manifest["node"]["capabilities"], sorted(plan.capabilities))
                self.assertEqual(manifest["install_plan"]["required_services"], list(plan.required_services))
                self.assertEqual("xray.json" in output_names, plan.requires_xray)
                self.assertEqual(f"{env.get('WG_INTERFACE', 'wg0')}.conf" in output_names, plan.requires_wireguard)
                self.assertEqual("vpn-stack-transport.service" in output_names, "transport" in plan.required_services)

    def test_minimal_node_env_round_trip_preserves_owned_identities(self) -> None:
        cases = (
            (TOPOLOGY_SINGLE, "ru", NODE_GATEWAY),
            (TOPOLOGY_SINGLE, "foreign", NODE_GATEWAY),
            (TOPOLOGY_DUAL, "ru", NODE_GATEWAY),
            (TOPOLOGY_DUAL, "ru", NODE_EXIT),
        )
        for topology, location, node_id in cases:
            with self.subTest(topology=topology, location=location, node=node_id):
                env = self.make_env(topology, location)
                projected = render_node_env_text(env, node_id)
                with tempfile.TemporaryDirectory() as tmp:
                    env_path = Path(tmp) / "node.env"
                    env_path.write_text(projected, encoding="utf-8")
                    with patch(
                        "vpn_installer.config.generate_default_env",
                        side_effect=AssertionError("target-side node render must not generate defaults"),
                    ):
                        loaded = load_runtime_env(env_path)

                self.assertEqual(render_node_env_text(loaded, node_id), projected)
                if node_id == NODE_GATEWAY:
                    self.assertEqual(loaded["PUBLIC_HY2_CERTIFICATE_B64"], env["PUBLIC_HY2_CERTIFICATE_B64"])
                    self.assertEqual(loaded["PUBLIC_HY2_PRIVATE_KEY_B64"], env["PUBLIC_HY2_PRIVATE_KEY_B64"])
                if topology == TOPOLOGY_DUAL and node_id == NODE_GATEWAY:
                    self.assertEqual(
                        loaded["INTERSERVER_HY2_PUBLIC_KEY_SHA256"],
                        env["INTERSERVER_HY2_PUBLIC_KEY_SHA256"],
                    )
                if node_id == NODE_EXIT:
                    self.assertEqual(
                        loaded["INTERSERVER_HY2_PRIVATE_KEY_B64"],
                        env["INTERSERVER_HY2_PRIVATE_KEY_B64"],
                    )

    def test_minimal_node_env_rejects_cross_node_secret(self) -> None:
        env = self.make_env(TOPOLOGY_DUAL, "ru")
        projected = render_node_env_text(env, NODE_GATEWAY)
        projected += 'WG_FOREIGN_PRIVATE_KEY="must-not-cross-node-boundary"\n'
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "node.env"
            env_path.write_text(projected, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "canonical capability projection"):
                load_runtime_env(env_path)

    def test_minimal_node_env_rejects_descriptor_drift(self) -> None:
        env = self.make_env(TOPOLOGY_SINGLE, "foreign")
        projected = render_node_env_text(env, NODE_GATEWAY).replace('NODE_LOCATION="foreign"', 'NODE_LOCATION="ru"')
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "node.env"
            env_path.write_text(projected, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "location does not match"):
                load_runtime_env(env_path)

    def test_minimal_dual_node_env_renders_byte_identical_bundle(self) -> None:
        env = self.make_env(TOPOLOGY_DUAL, "ru")
        for node_id in (NODE_GATEWAY, NODE_EXIT):
            with self.subTest(node=node_id), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                full_dir = root / "full"
                projected_dir = root / "projected"
                node_env_path = root / "node.env"
                node_env_path.write_text(render_node_env_text(env, node_id), encoding="utf-8")

                write_node_rendered_files(env, node_id, full_dir)
                write_node_rendered_files(load_runtime_env(node_env_path), node_id, projected_dir)

                full_files = {path.name: path.read_bytes() for path in full_dir.iterdir() if path.is_file()}
                projected_files = {path.name: path.read_bytes() for path in projected_dir.iterdir() if path.is_file()}
                self.assertEqual(projected_files, full_files)

    def test_render_node_rejects_removed_role_name(self) -> None:
        env = self.make_env()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            env_path.write_text(render_env_text(env), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported node"):
                install_support_main(
                    ["render-node", "--node", "ru-gateway", "--env-file", str(env_path), "--output-dir", str(tmp_path / "out")]
                )

    def test_render_node_cli_writes_current_manifest(self) -> None:
        env = self.make_env(TOPOLOGY_SINGLE, "foreign")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_path = tmp_path / "demo.env"
            output_dir = tmp_path / "out"
            env_path.write_text(render_env_text(env), encoding="utf-8")
            rc = install_support_main(
                [
                    "render-node",
                    "--node",
                    "gateway",
                    "--env-file",
                    str(env_path),
                    "--output-dir",
                    str(output_dir),
                ]
            )
            self.assertEqual(rc, 0)
            manifest = json.loads((output_dir / "render-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 5)
            self.assertEqual(manifest["install_plan"]["schema_version"], 5)
            self.assertEqual(manifest["node"]["location"], "foreign")
            self.assertFalse((output_dir / "wg0.conf").exists())
            self.assertFalse((output_dir / "vpn-stack-transport.service").exists())


if __name__ == "__main__":
    unittest.main()
