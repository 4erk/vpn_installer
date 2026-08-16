from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer import state
from vpn_installer.topology import NODE_EXIT, NODE_GATEWAY


class StateTests(unittest.TestCase):
    def test_write_state_does_not_store_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(state, "STATE_DIR", Path(tmp)):
                target = RemoteTarget(
                    role=ROLE_RU,
                    public_ip="203.0.113.10",
                    ssh_host="203.0.113.10",
                    ssh_port=22,
                    ssh_user="root",
                    auth_mode="password",
                    ssh_password="secret",
                )
                state.write_state("demo", [target])
                payload = state.load_state("demo")
        self.assertEqual(payload["nodes"][NODE_GATEWAY]["auth_mode"], "password")
        self.assertNotIn("ssh_password", payload["nodes"][NODE_GATEWAY])
        self.assertNotIn(ROLE_RU, payload)

    def test_load_state_reads_legacy_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            legacy = state_dir / "legacy.env"
            legacy.write_text(
                "\n".join(
                    [
                        "RU_PUBLIC_IP=\"203.0.113.10\"",
                        "RU_SSH_HOST=\"203.0.113.10\"",
                        "RU_SSH_PORT=\"22\"",
                        "RU_SSH_USER=\"root\"",
                        "RU_AUTH_MODE=\"password\"",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            with patch.object(state, "STATE_DIR", state_dir):
                payload = state.load_state("legacy")
        self.assertEqual(payload["nodes"][NODE_GATEWAY]["ssh_user"], "root")
        self.assertEqual(payload["nodes"][NODE_GATEWAY]["auth_mode"], "password")

    def test_load_legacy_state_without_auth_mode_requires_fresh_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            (state_dir / "legacy.env").write_text(
                'RU_PUBLIC_IP="203.0.113.10"\nRU_SSH_HOST="203.0.113.10"\nRU_SSH_PORT="22"\nRU_SSH_USER="root"\n',
                encoding="utf-8",
            )
            with patch.object(state, "STATE_DIR", state_dir):
                payload = state.load_state("legacy")
        self.assertEqual(payload["nodes"][NODE_GATEWAY]["auth_mode"], "")

    def test_load_state_returns_empty_when_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(state, "STATE_DIR", Path(tmp)):
                self.assertEqual(state.load_state("missing"), {})

    def test_native_state_fails_closed_on_unknown_schema_or_topology_drift(self) -> None:
        cases = (
            '{"schema_version":99,"topology":"single","nodes":{}}\n',
            '{"schema_version":2,"topology":"single","nodes":{"exit":{}}}\n',
            '{"schema_version":2,"topology":"mystery","nodes":{}}\n',
            '{"schema_version":2,"topology":"dual","nodes":[]}\n',
        )
        for index, payload in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                state_dir = Path(tmp)
                (state_dir / "demo.json").write_text(payload, encoding="utf-8")
                with patch.object(state, "STATE_DIR", state_dir):
                    with self.assertRaises(ValueError):
                        state.load_state("demo")

    def test_write_state_preserves_existing_other_role(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(state, "STATE_DIR", Path(tmp)):
                target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_host="203.0.113.10", ssh_port=22, ssh_user="root")
                state.write_state(
                    "demo",
                    [target],
                    existing_state={
                        ROLE_FOREIGN: {
                            "public_ip": "198.51.100.20",
                            "ssh_host": "198.51.100.20",
                            "ssh_port": "22",
                            "ssh_user": "root",
                            "auth_mode": "key",
                            "identity_path": "",
                        }
                    },
                )
                payload = state.load_state("demo")
        self.assertEqual(payload["nodes"][NODE_EXIT]["public_ip"], "198.51.100.20")

    def test_load_legacy_json_maps_roles_at_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            (state_dir / "demo.json").write_text(
                '{"updated_at":"old","ru-gateway":{"public_ip":"203.0.113.10"},'
                '"foreign-exit":{"public_ip":"198.51.100.20"}}\n',
                encoding="utf-8",
            )
            with patch.object(state, "STATE_DIR", state_dir):
                payload = state.load_state("demo")
        self.assertEqual(payload["nodes"][NODE_GATEWAY]["public_ip"], "203.0.113.10")
        self.assertEqual(payload["nodes"][NODE_EXIT]["public_ip"], "198.51.100.20")
        self.assertEqual(payload["migration"]["legacy_inputs"], [ROLE_RU, ROLE_FOREIGN])

    def test_single_state_never_persists_stale_exit_node(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(state, "STATE_DIR", Path(tmp)):
                gateway = RemoteTarget(role=ROLE_RU, location="foreign", public_ip="203.0.113.10", ssh_host="203.0.113.10")
                state.write_state(
                    "demo",
                    [gateway],
                    existing_state={"topology": "dual", "nodes": {NODE_EXIT: {"public_ip": "198.51.100.20"}}},
                    topology="single",
                )
                payload = state.load_state("demo")

        self.assertEqual(payload["topology"], "single")
        self.assertEqual(set(payload["nodes"]), {NODE_GATEWAY})


if __name__ == "__main__":
    unittest.main()
