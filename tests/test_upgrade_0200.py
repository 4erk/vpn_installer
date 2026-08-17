from __future__ import annotations

import unittest

from vpn_installer.config import generate_default_env
from vpn_installer.topology import CONFIG_SCHEMA_VERSION, DUAL_ONLY_ENV_KEYS, NODE_GATEWAY
from vpn_installer.upgrade_0200 import (
    SOURCE_DIAGNOSTICS_SCHEMA,
    SOURCE_STATE_SCHEMA,
    Upgrade0200Error,
    previous_node_plan,
    transition_metadata,
    upgrade_diagnostics_snapshot,
    upgrade_env,
    upgrade_state,
)


def env_0200(*, topology: str = "dual") -> dict[str, str]:
    env = generate_default_env("demo", topology=topology, gateway_location="ru")
    env["CONFIG_SCHEMA"] = "2"
    env["GATEWAY_PUBLIC_IP"] = "203.0.113.10"
    if topology == "dual":
        env["EXIT_PUBLIC_IP"] = "198.51.100.20"
    env["ADMIN_WEB_ENABLED"] = "1"
    return env


class Upgrade0200Tests(unittest.TestCase):
    def test_dual_env_upgrade_is_exact_and_enables_dual_web_capability(self) -> None:
        source = env_0200()
        upgraded = upgrade_env(source)
        self.assertEqual(upgraded["CONFIG_SCHEMA"], str(CONFIG_SCHEMA_VERSION))
        self.assertNotIn("ADMIN_WEB_ENABLED", upgraded)
        self.assertIn("web-admin", previous_node_plan(source, NODE_GATEWAY).capabilities)

    def test_single_env_upgrade_removes_all_dual_dependencies(self) -> None:
        source = env_0200(topology="single")
        upgraded = upgrade_env(source)
        self.assertFalse(DUAL_ONLY_ENV_KEYS & upgraded.keys())
        self.assertIn("web-admin", previous_node_plan(source, NODE_GATEWAY).capabilities)

    def test_dual_gateway_node_upgrade_moves_wan_interface_to_exit_ownership(self) -> None:
        gateway = env_0200()
        gateway.update(
            {
                "NODE_ID": NODE_GATEWAY,
                "NODE_LOCATION": "ru",
                "NODE_PUBLIC_IP": gateway["GATEWAY_PUBLIC_IP"],
                "WAN_INTERFACE": "eth0",
            }
        )
        deployment = env_0200()
        deployment["WAN_INTERFACE"] = "eth0"

        self.assertNotIn("WAN_INTERFACE", upgrade_env(gateway))
        self.assertEqual(upgrade_env(deployment)["WAN_INTERFACE"], "eth0")

    def test_pre_0200_aliases_and_wrong_schema_are_rejected(self) -> None:
        source = env_0200()
        source["RU_PUBLIC_IP"] = source["GATEWAY_PUBLIC_IP"]
        with self.assertRaisesRegex(Upgrade0200Error, "pre-0.20.0"):
            upgrade_env(source)
        source = env_0200()
        source["CONFIG_SCHEMA"] = "1"
        with self.assertRaisesRegex(Upgrade0200Error, "CONFIG_SCHEMA=2"):
            upgrade_env(source)

    def test_state_upgrade_accepts_only_schema_two_canonical_nodes(self) -> None:
        payload = {
            "schema_version": SOURCE_STATE_SCHEMA,
            "topology": "single",
            "updated_at": "2026-08-17T00:00:00Z",
            "nodes": {NODE_GATEWAY: {"public_ip": "203.0.113.10"}},
        }
        upgraded = upgrade_state(payload)
        self.assertEqual(upgraded["schema_version"], CONFIG_SCHEMA_VERSION)
        self.assertNotIn("migration", upgraded)
        with self.assertRaises(Upgrade0200Error):
            upgrade_state({**payload, "nodes": {"ru-gateway": {}}})

    def test_diagnostics_upgrade_is_release_and_schema_bounded(self) -> None:
        payload = {
            "schema_version": SOURCE_DIAGNOSTICS_SCHEMA,
            "release": {"version": "0.20.0"},
            "role": "ru-gateway",
            "migration": {"state": "native"},
        }
        upgraded = upgrade_diagnostics_snapshot(payload, target_schema=5)
        self.assertEqual(upgraded["schema_version"], 5)
        self.assertNotIn("role", upgraded)
        self.assertNotIn("migration", upgraded)
        with self.assertRaises(Upgrade0200Error):
            upgrade_diagnostics_snapshot({**payload, "release": {"version": "0.19.9"}}, target_schema=5)

    def test_transition_declares_its_removal_release(self) -> None:
        self.assertEqual(transition_metadata(), {"from": "0.20.0", "to_schema": "3", "remove_in": "0.20.2"})


if __name__ == "__main__":
    unittest.main()
