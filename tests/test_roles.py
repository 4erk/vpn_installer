from __future__ import annotations

import unittest

from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget
from vpn_installer.roles import execution_roles, requested_roles


class RoleTests(unittest.TestCase):
    def test_execution_roles_install_foreign_then_ru(self) -> None:
        self.assertEqual(execution_roles("install", [ROLE_RU, ROLE_FOREIGN]), [ROLE_FOREIGN, ROLE_RU])

    def test_execution_roles_remove_ru_then_foreign(self) -> None:
        self.assertEqual(execution_roles("remove", [ROLE_RU, ROLE_FOREIGN]), [ROLE_RU, ROLE_FOREIGN])

    def test_requested_roles_all(self) -> None:
        self.assertEqual(requested_roles("all"), [ROLE_RU, ROLE_FOREIGN])

    def test_requested_roles_accepts_canonical_and_legacy_names(self) -> None:
        self.assertEqual(requested_roles("gateway"), [ROLE_RU])
        self.assertEqual(requested_roles("exit"), [ROLE_FOREIGN])
        self.assertEqual(requested_roles(ROLE_RU), [ROLE_RU])

    def test_remote_target_label_accepts_canonical_node_id(self) -> None:
        self.assertEqual(RemoteTarget(role="gateway", location="ru").label, "Сервер входа")
        self.assertEqual(RemoteTarget(role="exit", location="foreign").label, "Сервер выхода")
        self.assertEqual(RemoteTarget(role="gateway", location="foreign").label, "VPN-шлюз (зарубежный сервер)")


if __name__ == "__main__":
    unittest.main()
