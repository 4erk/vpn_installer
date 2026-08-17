from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import state
from vpn_installer.models import RemoteTarget
from vpn_installer.topology import CONFIG_SCHEMA_VERSION, NODE_EXIT, NODE_GATEWAY


class StateTests(unittest.TestCase):
    def test_write_state_does_not_store_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(state, "STATE_DIR", Path(tmp)):
            target = RemoteTarget(
                node_id=NODE_GATEWAY,
                public_ip="203.0.113.10",
                ssh_host="203.0.113.10",
                auth_mode="password",
                ssh_password="secret",
                save_ssh_password=True,
            )
            state.write_state("demo", [target], topology="single")
            payload = state.load_state("demo")
        self.assertEqual(payload["schema_version"], CONFIG_SCHEMA_VERSION)
        self.assertEqual(payload["nodes"][NODE_GATEWAY]["auth_mode"], "password")
        self.assertNotIn("ssh_password", payload["nodes"][NODE_GATEWAY])
        self.assertNotIn("save_ssh_password", payload["nodes"][NODE_GATEWAY])

    def test_write_state_preserves_other_dual_node(self) -> None:
        existing = {
            "schema_version": CONFIG_SCHEMA_VERSION,
            "topology": "dual",
            "nodes": {
                NODE_EXIT: {
                    "location": "foreign",
                    "public_ip": "198.51.100.20",
                    "ssh_host": "198.51.100.20",
                    "ssh_port": "22",
                    "ssh_user": "root",
                    "auth_mode": "key",
                    "identity_path": "",
                }
            },
        }
        gateway = RemoteTarget(node_id=NODE_GATEWAY, location="ru", public_ip="203.0.113.10", ssh_host="203.0.113.10")
        with tempfile.TemporaryDirectory() as tmp, patch.object(state, "STATE_DIR", Path(tmp)):
            state.write_state("demo", [gateway], existing_state=existing, topology="dual")
            payload = state.load_state("demo")
        self.assertEqual(set(payload["nodes"]), {NODE_GATEWAY, NODE_EXIT})

    def test_single_state_drops_stale_exit(self) -> None:
        existing = {"schema_version": CONFIG_SCHEMA_VERSION, "topology": "dual", "nodes": {NODE_EXIT: {"public_ip": "198.51.100.20"}}}
        gateway = RemoteTarget(node_id=NODE_GATEWAY, location="foreign", public_ip="203.0.113.10", ssh_host="203.0.113.10")
        with tempfile.TemporaryDirectory() as tmp, patch.object(state, "STATE_DIR", Path(tmp)):
            state.write_state("demo", [gateway], existing_state=existing, topology="single")
            payload = state.load_state("demo")
        self.assertEqual(payload["topology"], "single")
        self.assertEqual(set(payload["nodes"]), {NODE_GATEWAY})

    def test_native_state_fails_closed_on_invalid_shape(self) -> None:
        cases = (
            {"schema_version": 99, "topology": "single", "nodes": {}},
            {"schema_version": CONFIG_SCHEMA_VERSION, "topology": "single", "nodes": {NODE_EXIT: {}}},
            {"schema_version": CONFIG_SCHEMA_VERSION, "topology": "mystery", "nodes": {}},
            {"schema_version": CONFIG_SCHEMA_VERSION, "topology": "dual", "nodes": []},
        )
        for index, payload in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp, patch.object(state, "STATE_DIR", Path(tmp)):
                (Path(tmp) / "demo.json").write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ValueError):
                    state.load_state("demo")

    def test_missing_state_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(state, "STATE_DIR", Path(tmp)):
            self.assertEqual(state.load_state("missing"), {})


if __name__ == "__main__":
    unittest.main()
