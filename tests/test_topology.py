from __future__ import annotations

import unittest

from vpn_installer.topology import (
    CAP_INTERSERVER_CLIENT,
    CAP_INTERSERVER_SERVER,
    CAP_LOCAL_EGRESS,
    CAP_WEB_ADMIN,
    CONFIG_SCHEMA_VERSION,
    LOCATION_FOREIGN,
    LOCATION_RU,
    NODE_EXIT,
    NODE_GATEWAY,
    TOPOLOGY_DUAL,
    TopologySpec,
    execution_node_ids,
    normalize_node_id,
    requested_node_ids,
)


def dual_topology() -> TopologySpec:
    return TopologySpec.from_env(
        {
            "TOPOLOGY": "dual",
            "GATEWAY_LOCATION": "ru",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "EXIT_PUBLIC_IP": "198.51.100.20",
        }
    )


class TopologyTests(unittest.TestCase):
    def test_single_has_one_local_egress_and_no_dual_capabilities(self) -> None:
        for location, address in ((LOCATION_RU, "203.0.113.10"), (LOCATION_FOREIGN, "198.51.100.20")):
            with self.subTest(location=location):
                topology = TopologySpec.from_env(
                    {"TOPOLOGY": "single", "GATEWAY_LOCATION": location, "GATEWAY_PUBLIC_IP": address}
                )
                plan = topology.plan(NODE_GATEWAY)
                self.assertEqual(tuple(node.node_id for node in topology.nodes), (NODE_GATEWAY,))
                self.assertEqual(topology.route_egresses, ("local-egress",))
                self.assertIn(CAP_LOCAL_EGRESS, plan.capabilities)
                self.assertNotIn(CAP_INTERSERVER_CLIENT, plan.capabilities)
                self.assertNotIn(CAP_WEB_ADMIN, plan.capabilities)
                self.assertFalse(plan.requires_wireguard)
                self.assertNotIn("wireguard", plan.required_services)
                self.assertNotIn("admin", plan.required_services)

    def test_dual_compiles_interserver_and_web_capabilities(self) -> None:
        topology = dual_topology()
        gateway = topology.plan(NODE_GATEWAY)
        exit_plan = topology.plan(NODE_EXIT)
        self.assertIn(CAP_INTERSERVER_CLIENT, gateway.capabilities)
        self.assertIn(CAP_WEB_ADMIN, gateway.capabilities)
        self.assertIn(CAP_INTERSERVER_SERVER, exit_plan.capabilities)
        self.assertIn("admin", gateway.required_services)
        self.assertTrue(exit_plan.requires_wireguard)
        self.assertEqual(topology.route_egresses, ("direct-ru", "to-foreign"))

    def test_canonical_values_do_not_emit_absent_exit_or_old_fields(self) -> None:
        topology = TopologySpec.from_env(
            {"TOPOLOGY": "single", "GATEWAY_LOCATION": "foreign", "GATEWAY_PUBLIC_IP": "198.51.100.20"}
        )
        values = topology.canonical_env_values()
        self.assertEqual(values["CONFIG_SCHEMA"], str(CONFIG_SCHEMA_VERSION))
        self.assertNotIn("EXIT_PUBLIC_IP", values)
        self.assertNotIn("ADMIN_WEB_ENABLED", values)
        self.assertNotIn("RU_PUBLIC_IP", values)

    def test_canonical_topology_fails_closed(self) -> None:
        cases = (
            ({"GATEWAY_LOCATION": "ru", "GATEWAY_PUBLIC_IP": "203.0.113.10"}, "TOPOLOGY is required"),
            ({"TOPOLOGY": "single", "GATEWAY_PUBLIC_IP": "203.0.113.10"}, "GATEWAY_LOCATION is required"),
            ({"TOPOLOGY": "single", "GATEWAY_LOCATION": "ru", "GATEWAY_PUBLIC_IP": "bad"}, "invalid public IP"),
            (
                {
                    "TOPOLOGY": "single",
                    "GATEWAY_LOCATION": "ru",
                    "GATEWAY_PUBLIC_IP": "203.0.113.10",
                    "EXIT_PUBLIC_IP": "198.51.100.20",
                },
                "cannot contain EXIT_PUBLIC_IP",
            ),
            (
                {
                    "TOPOLOGY": "dual",
                    "GATEWAY_LOCATION": "foreign",
                    "GATEWAY_PUBLIC_IP": "198.51.100.20",
                    "EXIT_PUBLIC_IP": "203.0.113.10",
                },
                "RU gateway",
            ),
        )
        for env, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                TopologySpec.from_env(env)

    def test_node_names_are_strict(self) -> None:
        self.assertEqual(normalize_node_id("gateway"), NODE_GATEWAY)
        self.assertEqual(normalize_node_id("exit"), NODE_EXIT)
        with self.assertRaisesRegex(ValueError, "unsupported node"):
            normalize_node_id("ru-gateway")

    def test_selection_and_execution_order_are_canonical(self) -> None:
        topology = dual_topology()
        self.assertEqual(requested_node_ids("all"), [NODE_GATEWAY, NODE_EXIT])
        self.assertEqual(execution_node_ids("install", topology), [NODE_EXIT, NODE_GATEWAY])
        self.assertEqual(execution_node_ids("remove", topology), [NODE_GATEWAY, NODE_EXIT])
        self.assertEqual(execution_node_ids("reinstall", topology, (NODE_GATEWAY,)), [NODE_GATEWAY])


if __name__ == "__main__":
    unittest.main()
