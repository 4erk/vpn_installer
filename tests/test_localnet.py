from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vpn_installer.localnet import (
    ALLOW_TUNNELED_ROUTE_ENV,
    LocalRoute,
    assert_server_route_not_self_tunneled,
    local_route_check_supported,
    local_route_to_server,
    route_uses_self_tunnel,
    valid_ip,
    windows_route_to_ip,
)
from vpn_installer.models import AppError, ROLE_RU, RemoteTarget


class LocalNetTests(unittest.TestCase):
    def test_valid_ip_normalizes_ipv4(self) -> None:
        self.assertEqual(valid_ip(" 203.0.113.10 "), "203.0.113.10")

    def test_route_uses_self_tunnel_matches_configured_tun_name(self) -> None:
        route = LocalRoute(target_ip="203.0.113.10", interface_alias="singbox_tun")
        self.assertTrue(route_uses_self_tunnel(route, client_tun_name="singbox_tun"))

    def test_route_uses_self_tunnel_matches_common_client_aliases(self) -> None:
        route = LocalRoute(target_ip="203.0.113.10", interface_alias="Hiddify Tunnel")
        self.assertTrue(route_uses_self_tunnel(route, client_tun_name="tun0"))

    def test_route_uses_self_tunnel_accepts_lan_route(self) -> None:
        route = LocalRoute(target_ip="203.0.113.10", interface_alias="Беспроводная сеть")
        self.assertFalse(route_uses_self_tunnel(route, client_tun_name="singbox_tun"))

    def test_windows_route_to_ip_parses_powershell_json(self) -> None:
        completed = SimpleNamespace(
            returncode=0,
            stdout='{"interface_alias":"singbox_tun","next_hop":"172.18.0.2","source_address":"172.18.0.1"}',
        )
        with patch("vpn_installer.localnet.subprocess.run", return_value=completed):
            route = windows_route_to_ip("203.0.113.10")
        self.assertEqual(route, LocalRoute(target_ip="203.0.113.10", interface_alias="singbox_tun", next_hop="172.18.0.2", source_address="172.18.0.1"))

    def test_windows_route_to_ip_ignores_invalid_ip_and_bad_json(self) -> None:
        self.assertIsNone(windows_route_to_ip("not-an-ip"))
        with patch("vpn_installer.localnet.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="not-json")):
            self.assertIsNone(windows_route_to_ip("203.0.113.10"))

    def test_local_route_to_server_skips_unsupported_platform(self) -> None:
        with patch("vpn_installer.localnet.os.name", "posix"):
            self.assertFalse(local_route_check_supported())
            self.assertIsNone(local_route_to_server(RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10")))

    def test_assert_server_route_blocks_self_tunnel_unless_overridden(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10")
        route = LocalRoute(target_ip="203.0.113.10", interface_alias="singbox_tun")
        with patch("vpn_installer.localnet.local_route_to_server", return_value=route):
            with self.assertRaises(AppError):
                assert_server_route_not_self_tunneled(target, {"CLIENT_TUN_NAME": "singbox_tun"})
        with patch("vpn_installer.localnet.local_route_to_server", return_value=route), patch.dict("vpn_installer.localnet.os.environ", {ALLOW_TUNNELED_ROUTE_ENV: "1"}):
            self.assertEqual(assert_server_route_not_self_tunneled(target, {"CLIENT_TUN_NAME": "singbox_tun"}), route)

    def test_assert_server_route_allows_lan_route(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10")
        route = LocalRoute(target_ip="203.0.113.10", interface_alias="Беспроводная сеть")
        with patch("vpn_installer.localnet.local_route_to_server", return_value=route):
            self.assertEqual(assert_server_route_not_self_tunneled(target, {"CLIENT_TUN_NAME": "singbox_tun"}), route)

    def test_assert_server_route_allows_explicitly_bound_management_path(self) -> None:
        target = RemoteTarget(role=ROLE_RU, public_ip="203.0.113.10", ssh_bind_address="192.168.0.101")
        route = LocalRoute(target_ip="203.0.113.10", interface_alias="singbox_tun")
        with patch("vpn_installer.localnet.local_route_to_server", return_value=route):
            self.assertEqual(assert_server_route_not_self_tunneled(target, {"CLIENT_TUN_NAME": "singbox_tun"}), route)


if __name__ == "__main__":
    unittest.main()
