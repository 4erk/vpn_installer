from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer import state


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
        self.assertEqual(payload[ROLE_RU]["auth_mode"], "password")
        self.assertNotIn("ssh_password", payload[ROLE_RU])

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
                        "RU_AUTH_MODE=\"key\"",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            with patch.object(state, "STATE_DIR", state_dir):
                payload = state.load_state("legacy")
        self.assertEqual(payload[ROLE_RU]["ssh_user"], "root")

    def test_load_state_returns_empty_when_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(state, "STATE_DIR", Path(tmp)):
                self.assertEqual(state.load_state("missing"), {})

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
        self.assertEqual(payload[ROLE_FOREIGN]["public_ip"], "198.51.100.20")


if __name__ == "__main__":
    unittest.main()
