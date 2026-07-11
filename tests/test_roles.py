from __future__ import annotations

import unittest

from vpn_installer.models import ROLE_FOREIGN, ROLE_RU
from vpn_installer.roles import execution_roles, requested_roles


class RoleTests(unittest.TestCase):
    def test_execution_roles_install_foreign_then_ru(self) -> None:
        self.assertEqual(execution_roles("install", [ROLE_RU, ROLE_FOREIGN]), [ROLE_FOREIGN, ROLE_RU])

    def test_execution_roles_remove_ru_then_foreign(self) -> None:
        self.assertEqual(execution_roles("remove", [ROLE_RU, ROLE_FOREIGN]), [ROLE_RU, ROLE_FOREIGN])

    def test_requested_roles_all(self) -> None:
        self.assertEqual(requested_roles("all"), [ROLE_RU, ROLE_FOREIGN])


if __name__ == "__main__":
    unittest.main()
