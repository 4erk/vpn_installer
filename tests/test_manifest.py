from __future__ import annotations

import json
import unittest

from vpn_installer.config import generate_default_env, render_env_text
from vpn_installer.manifest import artifact_specs, finalize_node_files, project_node_env, render_manifest, render_node_env_text
from vpn_installer.topology import NODE_EXIT, NODE_GATEWAY, TOPOLOGY_DUAL, TOPOLOGY_SINGLE, TopologySpec


class ManifestTopologyTests(unittest.TestCase):
    def make_env(self, topology: str, location: str = "ru") -> dict[str, str]:
        env = generate_default_env("demo", topology=topology, gateway_location=location)
        gateway_ip = "203.0.113.10" if location == "ru" else "198.51.100.10"
        env["GATEWAY_PUBLIC_IP"] = gateway_ip
        if topology == TOPOLOGY_DUAL:
            env["EXIT_PUBLIC_IP"] = "198.51.100.20"
        return env

    def rendered_files(self, env: dict[str, str], node_id: str) -> dict[str, str]:
        plan = TopologySpec.from_env(env).plan(node_id)
        files = {
            "sing-box.json": "{}\n",
            "sing-box.service": "[Unit]\n[Service]\n",
        }
        if plan.requires_xray:
            files["xray.json"] = "{}\n"
            files["vpn-stack-xray.service"] = "[Unit]\n[Service]\n"
        if plan.has_interserver:
            files[f"{env['WG_INTERFACE']}.conf"] = "[Interface]\nPrivateKey = test\n"
            files["interserver_transport.py"] = "# transport\n"
            files["topology.py"] = "# topology\n"
        if "transport" in plan.required_services:
            files["vpn-stack-transport.service"] = "[Unit]\n[Service]\n"
        return files

    def test_current_schema_matrix_is_capability_driven(self) -> None:
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
                files = finalize_node_files(env, plan, self.rendered_files(env, node_id))
                manifest = json.loads(files["render-manifest.json"])
                install_plan = json.loads(files["install-plan.json"])

                self.assertEqual(manifest["schema_version"], 5)
                self.assertEqual(manifest["install_plan"]["schema_version"], 5)
                self.assertEqual(manifest["platform"], manifest["install_plan"]["platform"])
                self.assertEqual(manifest["platform"]["os_id"], "ubuntu")
                self.assertEqual(manifest["topology"], topology)
                self.assertEqual(manifest["node_id"], node_id)
                self.assertEqual(manifest["location"], plan.location)
                self.assertEqual(manifest["capabilities"], sorted(plan.capabilities))
                self.assertEqual(manifest["required_services"], list(plan.required_services))
                self.assertEqual(manifest["node"]["id"], node_id)
                self.assertEqual(manifest["node"]["location"], plan.location)
                self.assertEqual(manifest["node"]["capabilities"], sorted(plan.capabilities))
                self.assertEqual(manifest["node"]["required_services"], list(plan.required_services))
                self.assertEqual(manifest["install_plan"]["required_services"], list(plan.required_services))
                self.assertEqual(manifest["install_plan"]["node"], manifest["node"])
                self.assertEqual(install_plan, manifest["install_plan"])
                self.assertIn("node.env", files)
                self.assertEqual(manifest["artifacts"]["node.env"]["install_path"], "/etc/vpn-stack/deployment.env")
                self.assertEqual("xray" in manifest["binaries"], plan.requires_xray)
                self.assertEqual(any(name.endswith(".conf") and name.startswith("wg") for name in manifest["artifacts"]), plan.requires_wireguard)
                self.assertEqual("vpn-stack-transport.service" in manifest["artifacts"], "transport" in plan.required_services)

                if topology == TOPOLOGY_SINGLE:
                    self.assertNotIn("interserver", manifest["install_plan"]["package_sets"])
                    self.assertEqual(manifest["assets"], {})
                else:
                    self.assertIn("interserver", manifest["install_plan"]["package_sets"])
                packages = set(manifest["install_plan"]["packages"])
                self.assertIn("iproute2", packages)
                self.assertEqual("unzip" in packages, plan.requires_xray)
                self.assertEqual("wireguard-tools" in packages, plan.has_interserver)
                self.assertEqual("iperf3" in packages, plan.has_interserver)

    def test_disabled_journal_limit_is_absent_from_artifact_contract(self) -> None:
        env = self.make_env(TOPOLOGY_SINGLE, "foreign")
        env["JOURNAL_LIMIT_ENABLED"] = "0"
        files = finalize_node_files(
            env,
            NODE_GATEWAY,
            self.rendered_files(env, NODE_GATEWAY),
        )
        manifest = json.loads(files["render-manifest.json"])
        self.assertNotIn("journald-vpn-stack.conf", manifest["artifacts"])
        self.assertNotIn("journald-vpn-stack.conf", manifest["install_plan"]["artifacts"])

    def test_admin_contract_exists_only_on_dual_gateway(self) -> None:
        single = self.make_env(TOPOLOGY_SINGLE)
        dual = self.make_env(TOPOLOGY_DUAL)
        single_plan = TopologySpec.from_env(single).plan(NODE_GATEWAY)
        dual_plan = TopologySpec.from_env(dual).plan(NODE_GATEWAY)
        single_projected = project_node_env(single, single_plan)
        dual_projected = project_node_env(dual, dual_plan)
        self.assertNotIn("admin", single_plan.required_services)
        self.assertNotIn("ADMIN_WEB_USERNAME", single_projected)
        self.assertNotIn("admin_web.py", artifact_specs(single_plan, env=single))
        self.assertIn("admin", dual_plan.required_services)
        self.assertIn("ADMIN_WEB_USERNAME", dual_projected)
        self.assertIn("admin_web.py", artifact_specs(dual_plan, env=dual))

    def test_node_env_projection_excludes_other_node_private_secrets(self) -> None:
        env = self.make_env(TOPOLOGY_DUAL)
        env.update(
            {
                "WG_RU_PRIVATE_KEY": "gateway-wg-private",
                "WG_FOREIGN_PRIVATE_KEY": "exit-wg-private",
                "WG_RU_PUBLIC_KEY": "gateway-wg-public",
                "WG_FOREIGN_PUBLIC_KEY": "exit-wg-public",
                "INTERSERVER_HY2_PRIVATE_KEY_B64": "exit-hy2-private",
                "INTERSERVER_HY2_CERTIFICATE_B64": "exit-hy2-cert",
                "RU_REALITY_PRIVATE_KEY": "gateway-reality-private",
                "PUBLIC_HY2_PRIVATE_KEY_B64": "gateway-public-hy2-private",
                "CLIENT_UUID": "gateway-client-id",
                "ADMIN_WEB_PASSWORD": "gateway-admin-password",
            }
        )

        gateway = project_node_env(env, NODE_GATEWAY)
        self.assertEqual(gateway["WG_RU_PRIVATE_KEY"], "gateway-wg-private")
        self.assertEqual(gateway["WG_FOREIGN_PUBLIC_KEY"], "exit-wg-public")
        self.assertNotIn("WG_FOREIGN_PRIVATE_KEY", gateway)
        self.assertNotIn("INTERSERVER_HY2_PRIVATE_KEY_B64", gateway)

        exit_env = project_node_env(env, NODE_EXIT)
        self.assertEqual(exit_env["WG_FOREIGN_PRIVATE_KEY"], "exit-wg-private")
        self.assertEqual(exit_env["WG_RU_PUBLIC_KEY"], "gateway-wg-public")
        self.assertEqual(exit_env["INTERSERVER_HY2_PRIVATE_KEY_B64"], "exit-hy2-private")
        for forbidden in (
            "WG_RU_PRIVATE_KEY",
            "RU_REALITY_PRIVATE_KEY",
            "PUBLIC_HY2_PRIVATE_KEY_B64",
            "CLIENT_UUID",
            "ADMIN_WEB_PASSWORD",
        ):
            self.assertNotIn(forbidden, exit_env)
        self.assertNotIn("RU_PUBLIC_IP", gateway)
        self.assertNotIn("FOREIGN_PUBLIC_IP", gateway)
        self.assertNotIn("RU_PUBLIC_IP", exit_env)
        self.assertNotIn("FOREIGN_PUBLIC_IP", exit_env)

    def test_single_projection_drops_all_interserver_state(self) -> None:
        env = self.make_env(TOPOLOGY_SINGLE, "foreign")
        env.update(
            {
                "WG_RU_PRIVATE_KEY": "must-not-leak",
                "WG_FOREIGN_PRIVATE_KEY": "must-not-leak",
                "WG_PRESHARED_KEY": "must-not-leak",
                "INTERSERVER_HY2_PRIVATE_KEY_B64": "must-not-leak",
            }
        )
        projected = project_node_env(env, NODE_GATEWAY)
        self.assertEqual(projected["NODE_LOCATION"], "foreign")
        self.assertFalse(any(key.startswith("WG_") for key in projected))
        self.assertFalse(any(key.startswith("INTERSERVER_") for key in projected))
        self.assertNotIn("RULESET_DIR", projected)
        self.assertNotIn("RU_FORCE_DIRECT_DOMAIN", projected)
        self.assertNotIn("GLOBAL_DOH_SERVER", projected)

    def test_gateway_release_identity_ignores_exit_private_secret(self) -> None:
        first = self.make_env(TOPOLOGY_DUAL)
        second = first.copy()
        second["WG_FOREIGN_PRIVATE_KEY"] = "rotated-exit-only-secret"
        files = self.rendered_files(first, NODE_GATEWAY)
        first_manifest = json.loads(render_manifest(render_env_text(first), NODE_GATEWAY, files))
        second_manifest = json.loads(render_manifest(render_env_text(second), NODE_GATEWAY, files))
        self.assertEqual(first_manifest["node_env_sha256"], second_manifest["node_env_sha256"])
        self.assertEqual(first_manifest["release_id"], second_manifest["release_id"])
        self.assertNotEqual(first_manifest["env_sha256"], second_manifest["env_sha256"])

    def test_removed_role_name_is_rejected(self) -> None:
        env = self.make_env(TOPOLOGY_DUAL)
        with self.assertRaisesRegex(ValueError, "unsupported node"):
            render_manifest(render_env_text(env), "ru-gateway", self.rendered_files(env, NODE_GATEWAY))

    def test_unknown_artifact_is_rejected(self) -> None:
        env = self.make_env(TOPOLOGY_SINGLE)
        with self.assertRaisesRegex(ValueError, "unknown.conf"):
            render_manifest(render_env_text(env), NODE_GATEWAY, {"unknown.conf": "value\n"})

    def test_dynamic_wireguard_artifact_is_compatible_only_for_dual_nodes(self) -> None:
        wireguard = {"tunnel42.conf": "[Interface]\nPrivateKey = test\n"}
        dual = self.make_env(TOPOLOGY_DUAL)
        single = self.make_env(TOPOLOGY_SINGLE)

        dual_manifest = json.loads(render_manifest(render_env_text(dual), NODE_GATEWAY, wireguard))
        single_manifest = json.loads(render_manifest(render_env_text(single), NODE_GATEWAY, wireguard))

        self.assertEqual(dual_manifest["artifacts"]["tunnel42.conf"]["install_path"], "/etc/wireguard/tunnel42.conf")
        self.assertNotIn("tunnel42.conf", single_manifest["artifacts"])

    def test_finalizer_rejects_cross_capability_artifacts(self) -> None:
        env = self.make_env(TOPOLOGY_SINGLE)
        files = self.rendered_files(env, NODE_GATEWAY)
        files["interserver_transport.py"] = "# must not ship to single\n"

        with self.assertRaisesRegex(ValueError, "not supported by node capabilities: interserver_transport.py"):
            finalize_node_files(env, NODE_GATEWAY, files)


if __name__ == "__main__":
    unittest.main()
