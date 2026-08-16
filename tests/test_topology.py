from __future__ import annotations

import unittest

from vpn_installer.topology import (
    CAP_INTERSERVER_CLIENT,
    CAP_INTERSERVER_SERVER,
    CAP_LOCAL_EGRESS,
    CAP_WEB_ADMIN,
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TOPOLOGY_SINGLE,
    TopologySpec,
    execution_node_ids,
    normalize_node_id,
)
from vpn_installer.migration import migrate_env


class TopologyTests(unittest.TestCase):
    def test_existing_dual_env_is_inferred_at_the_legacy_boundary(self) -> None:
        topology = TopologySpec.from_env(
            migrate_env({"RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"}).env
        )
        self.assertEqual(topology.mode, TOPOLOGY_DUAL)
        self.assertEqual(topology.gateway.public_ip, "203.0.113.10")
        self.assertEqual(topology.exit.public_ip, "198.51.100.20")

    def test_single_ru_has_no_interserver_capability(self) -> None:
        topology = TopologySpec.from_env(
            {
                "TOPOLOGY": "single",
                "GATEWAY_LOCATION": "ru",
                "GATEWAY_PUBLIC_IP": "203.0.113.10",
            }
        )
        plan = topology.plan(NODE_GATEWAY)
        self.assertEqual(topology.gateway.location, LOCATION_RU)
        self.assertIn(CAP_LOCAL_EGRESS, plan.capabilities)
        self.assertNotIn(CAP_INTERSERVER_CLIENT, plan.capabilities)
        self.assertFalse(plan.requires_wireguard)
        self.assertNotIn("wireguard", plan.required_services)
        self.assertNotIn("transport", plan.required_services)

    def test_single_foreign_is_a_gateway_not_an_exit(self) -> None:
        topology = TopologySpec.from_env(
            {
                "TOPOLOGY": "single",
                "GATEWAY_LOCATION": "foreign",
                "GATEWAY_PUBLIC_IP": "198.51.100.20",
            }
        )
        self.assertEqual(topology.gateway.location, LOCATION_FOREIGN)
        self.assertEqual(tuple(node.node_id for node in topology.nodes), (NODE_GATEWAY,))
        self.assertTrue(topology.plan(NODE_GATEWAY).requires_xray)

    def test_dual_compiles_gateway_and_exit_capabilities(self) -> None:
        topology = TopologySpec.from_env(
            {
                "TOPOLOGY": "dual",
                "GATEWAY_LOCATION": "ru",
                "GATEWAY_PUBLIC_IP": "203.0.113.10",
                "EXIT_PUBLIC_IP": "198.51.100.20",
            }
        )
        self.assertIn(CAP_INTERSERVER_CLIENT, topology.plan(NODE_GATEWAY).capabilities)
        self.assertIn(CAP_INTERSERVER_SERVER, topology.plan(NODE_EXIT).capabilities)
        self.assertTrue(topology.plan(NODE_EXIT).requires_wireguard)

    def test_admin_capability_is_compiled_only_when_enabled(self) -> None:
        enabled = TopologySpec.from_env(
            {"TOPOLOGY": "single", "GATEWAY_LOCATION": "ru", "GATEWAY_PUBLIC_IP": "203.0.113.10"}
        )
        disabled = TopologySpec.from_env(
            {
                "TOPOLOGY": "single",
                "GATEWAY_LOCATION": "ru",
                "GATEWAY_PUBLIC_IP": "203.0.113.10",
                "ADMIN_WEB_ENABLED": "0",
            }
        )

        self.assertIn(CAP_WEB_ADMIN, enabled.plan(NODE_GATEWAY).capabilities)
        self.assertIn("admin", enabled.plan(NODE_GATEWAY).required_services)
        self.assertNotIn(CAP_WEB_ADMIN, disabled.plan(NODE_GATEWAY).capabilities)
        self.assertNotIn("admin", disabled.plan(NODE_GATEWAY).required_services)
        self.assertEqual(disabled.canonical_env_values()["ADMIN_WEB_ENABLED"], "0")

    def test_route_egresses_are_topology_derived(self) -> None:
        single = TopologySpec.from_env(
            {"TOPOLOGY": "single", "GATEWAY_LOCATION": "foreign", "GATEWAY_PUBLIC_IP": "198.51.100.20"}
        )
        dual = TopologySpec.from_env(
            {
                "TOPOLOGY": "dual",
                "GATEWAY_LOCATION": "ru",
                "GATEWAY_PUBLIC_IP": "203.0.113.10",
                "EXIT_PUBLIC_IP": "198.51.100.20",
            }
        )

        self.assertEqual(single.route_egresses, ("local-egress",))
        self.assertEqual(dual.route_egresses, ("direct-ru", "to-foreign"))

    def test_dual_rejects_an_invalid_location_pair(self) -> None:
        with self.assertRaisesRegex(ValueError, "RU gateway"):
            TopologySpec.from_env(
                {
                    "TOPOLOGY": "dual",
                    "GATEWAY_LOCATION": "foreign",
                    "GATEWAY_PUBLIC_IP": "198.51.100.20",
                    "EXIT_PUBLIC_IP": "203.0.113.10",
                }
            )

    def test_canonical_topology_fails_closed_on_ambiguous_or_invalid_addresses(self) -> None:
        with self.assertRaisesRegex(ValueError, "TOPOLOGY is required"):
            TopologySpec.from_env({"GATEWAY_LOCATION": "ru", "GATEWAY_PUBLIC_IP": "203.0.113.10"})
        with self.assertRaisesRegex(ValueError, "GATEWAY_LOCATION is required"):
            TopologySpec.from_env({"TOPOLOGY": "single", "GATEWAY_PUBLIC_IP": "203.0.113.10"})
        with self.assertRaisesRegex(ValueError, "invalid public IP"):
            TopologySpec.from_env(
                {"TOPOLOGY": "single", "GATEWAY_LOCATION": "ru", "GATEWAY_PUBLIC_IP": "not-an-ip"}
            )
        with self.assertRaisesRegex(ValueError, "cannot contain EXIT_PUBLIC_IP"):
            TopologySpec.from_env(
                {
                    "TOPOLOGY": "single",
                    "GATEWAY_LOCATION": "ru",
                    "GATEWAY_PUBLIC_IP": "203.0.113.10",
                    "EXIT_PUBLIC_IP": "198.51.100.20",
                }
            )
        with self.assertRaisesRegex(ValueError, "distinct gateway and exit"):
            TopologySpec.from_env(
                {
                    "TOPOLOGY": "dual",
                    "GATEWAY_LOCATION": "ru",
                    "GATEWAY_PUBLIC_IP": "203.0.113.10",
                    "EXIT_PUBLIC_IP": "203.0.113.10",
                }
            )

    def test_execution_order_is_egress_first_and_removal_is_gateway_first(self) -> None:
        topology = TopologySpec.from_env(
            migrate_env({"RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"}).env
        )
        self.assertEqual(execution_node_ids("install", topology), [NODE_EXIT, NODE_GATEWAY])
        self.assertEqual(execution_node_ids("remove", topology), [NODE_GATEWAY, NODE_EXIT])

    def test_legacy_role_aliases_are_normalized_only_at_the_boundary(self) -> None:
        self.assertEqual(normalize_node_id("ru-gateway"), NODE_GATEWAY)
        self.assertEqual(normalize_node_id("foreign-exit"), NODE_EXIT)

    def test_canonical_env_does_not_emit_legacy_address_keys(self) -> None:
        topology = TopologySpec.from_env(
            migrate_env({"RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"}).env
        )
        values = topology.canonical_env_values()
        self.assertEqual(values["CONFIG_SCHEMA"], "2")
        self.assertNotIn("RU_PUBLIC_IP", values)
        self.assertNotIn("FOREIGN_PUBLIC_IP", values)


if __name__ == "__main__":
    unittest.main()
