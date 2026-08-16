from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from vpn_installer import admin_tunnel, cli


class CliTests(unittest.TestCase):
    def test_zero_arg_calls_menu(self) -> None:
        with patch("vpn_installer.cli.menu_workflow", return_value=0) as mocked:
            self.assertEqual(cli.main([]), 0)
        mocked.assert_called_once()

    def test_install_help_parser_exists(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["install", "--deployment", "demo"])
        self.assertEqual(args.deployment, "demo")

    def test_install_dispatches_explicit_single_topology(self) -> None:
        with patch("vpn_installer.cli.install_workflow", return_value=0) as mocked:
            self.assertEqual(
                cli.main(
                    [
                        "install",
                        "--deployment",
                        "demo",
                        "--topology",
                        "single",
                        "--gateway-location",
                        "foreign",
                        "--non-interactive",
                        "--yes",
                    ]
                ),
                0,
            )
        mocked.assert_called_once_with(
            "demo",
            non_interactive=True,
            yes=True,
            topology_mode="single",
            gateway_location="foreign",
        )

    def test_parser_uses_public_platform_entrypoint(self) -> None:
        with patch("vpn_installer.cli.cli_entrypoint", return_value=r".\vpn.cmd"):
            parser = cli.build_parser()
        self.assertEqual(parser.prog, r".\vpn.cmd")

    def test_audit_dispatch(self) -> None:
        with patch("vpn_installer.audit.runner.main", return_value=0) as mocked:
            self.assertEqual(cli.main(["audit", "quick"]), 0)
        mocked.assert_called_once()

    def test_audit_dispatch_forwards_flags(self) -> None:
        with patch("vpn_installer.audit.runner.main", return_value=7) as mocked:
            self.assertEqual(cli.main(["audit", "--json", "--keep-docker", "docker"]), 7)
        mocked.assert_called_once_with(["--json", "--keep-docker", "docker"])

    def test_audit_interop_dispatch(self) -> None:
        with patch("vpn_installer.audit.runner.main", return_value=0) as mocked:
            self.assertEqual(cli.main(["audit", "interop"]), 0)
        mocked.assert_called_once_with(["interop"])

    def test_cleanup_local_parser_flags(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["cleanup-local", "--deployment", "demo", "--drop-env", "--drop-runtime"])
        self.assertTrue(args.drop_env)
        self.assertTrue(args.drop_runtime)

    def test_reinstall_parser_keeps_deprecated_role_alias(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["reinstall", "--deployment", "demo", "--role", "ru-gateway"])
        self.assertEqual(args.role, "ru-gateway")

    def test_reinstall_parser_uses_canonical_node(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["reinstall", "--deployment", "demo", "--node", "gateway"])
        self.assertEqual(args.node, "gateway")
        self.assertEqual(cli.selected_node(args), "gateway")

    def test_node_and_deprecated_role_are_mutually_exclusive(self) -> None:
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["status", "--node", "gateway", "--role", "ru-gateway"])

    def test_reinstall_dispatch_forwards_unattended_flags(self) -> None:
        with patch("vpn_installer.cli.remote_action_workflow", return_value=0) as mocked:
            self.assertEqual(
                cli.main(["reinstall", "--deployment", "demo", "--node", "all", "--non-interactive", "--yes"]),
                0,
            )
        mocked.assert_called_once_with("demo", "all", "reinstall", non_interactive=True, yes=True)

    def test_status_dispatch_forwards_non_interactive(self) -> None:
        with patch("vpn_installer.cli.status_workflow", return_value=0) as mocked:
            self.assertEqual(cli.main(["status", "--deployment", "demo", "--node", "all", "--non-interactive"]), 0)
        mocked.assert_called_once_with("demo", "all", non_interactive=True)

    def test_admin_dispatches_loopback_ssh_tunnel(self) -> None:
        with patch("vpn_installer.cli.admin_tunnel_workflow", return_value=0) as mocked:
            self.assertEqual(
                cli.main(["admin", "--deployment", "demo", "--local-port", "18080", "--open-browser", "--non-interactive"]),
                0,
            )
        mocked.assert_called_once_with("demo", local_port=18080, open_browser=True, non_interactive=True)

    def test_admin_tunnel_uses_gateway_ssh_transport_and_loopback_forward(self) -> None:
        env = {
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "foreign",
            "GATEWAY_PUBLIC_IP": "198.51.100.20",
            "ADMIN_WEB_ENABLED": "1",
            "ADMIN_WEB_PORT": "11333",
        }
        target = object()
        transport = MagicMock()
        transport.is_active.return_value = True
        client = MagicMock()
        client.get_transport.return_value = transport
        server = MagicMock()
        server.serve_forever.side_effect = KeyboardInterrupt

        with patch(
            "vpn_installer.workflows.prepare_remote_session",
            return_value=("demo", None, env, {}, [target], {}),
        ) as prepare, patch("vpn_installer.admin_tunnel.paramiko_connect", return_value=client) as connect, patch(
            "vpn_installer.admin_tunnel._ForwardServer", return_value=server
        ) as forward:
            self.assertEqual(admin_tunnel.admin_tunnel_workflow("demo", non_interactive=True), 0)

        self.assertEqual(prepare.call_args.kwargs["roles"], ["ru-gateway"])
        connect.assert_called_once_with(target)
        forward.assert_called_once_with(11333, transport, 11333)
        server.server_close.assert_called_once_with()
        client.close.assert_called_once_with()

    def test_admin_tunnel_rejects_disabled_capability_before_ssh(self) -> None:
        env = {
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "ru",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "ADMIN_WEB_ENABLED": "0",
        }
        with patch(
            "vpn_installer.workflows.prepare_remote_session",
            return_value=("demo", None, env, {}, [object()], {}),
        ), patch("vpn_installer.admin_tunnel.paramiko_connect") as connect:
            with self.assertRaisesRegex(cli.AppError, "Web-admin отключён"):
                admin_tunnel.admin_tunnel_workflow("demo")
        connect.assert_not_called()

    def test_android_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.android_diagnose", return_value=0) as mocked:
            self.assertEqual(cli.main(["android-diagnose", "--serial", "ABC123", "--logcat-lines", "50"]), 0)
        mocked.assert_called_once_with(serial="ABC123", package_name="app.hiddify.com", logcat_lines=50)

    def test_path_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.diagnose_path_workflow", return_value=0) as mocked:
            self.assertEqual(cli.main(["diagnose", "path", "--deployment", "demo", "--node", "all", "--iperf", "--non-interactive"]), 0)
        mocked.assert_called_once_with("demo", "all", iperf=True, non_interactive=True)

    def test_client_log_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.diagnose_client_log_workflow", return_value=1) as mocked:
            self.assertEqual(cli.main(["diagnose", "client-log", "--path", "client.log", "--deployment", "demo", "--node", "gateway"]), 1)
        mocked.assert_called_once_with("client.log", deployment="demo", role="gateway")

    def test_routes_accepts_single_topology_local_egress(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            ["routes", "add", "--deployment", "demo", "--value", "example.com", "--outbound", "local-egress"]
        )
        self.assertEqual(args.outbound, "local-egress")

    def test_routes_single_topology_infers_its_only_egress(self) -> None:
        env = {
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "foreign",
            "GATEWAY_PUBLIC_IP": "198.51.100.20",
        }
        self.assertEqual(cli.resolve_route_outbound(env, None), "local-egress")

    def test_routes_rejects_unavailable_explicit_egress_clearly(self) -> None:
        env = {
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "ru",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
        }
        with self.assertRaisesRegex(cli.AppError, "недоступен.*local-egress"):
            cli.resolve_route_outbound(env, "to-foreign")

    def test_routes_dual_requires_explicit_egress(self) -> None:
        env = {
            "TOPOLOGY": "dual",
            "GATEWAY_LOCATION": "ru",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "EXIT_PUBLIC_IP": "198.51.100.20",
        }
        with self.assertRaisesRegex(cli.AppError, "укажи --outbound: direct-ru, to-foreign"):
            cli.resolve_route_outbound(env, None)

    def test_routes_dispatch_infers_single_egress_before_existing_workflow(self) -> None:
        env = {
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "foreign",
            "GATEWAY_PUBLIC_IP": "198.51.100.20",
        }
        with patch("vpn_installer.cli.select_existing_deployment", return_value="demo"), patch(
            "vpn_installer.cli.load_existing_deployment_env", return_value=(None, env)
        ), patch("vpn_installer.cli.routes_workflow", return_value=0) as mocked:
            self.assertEqual(
                cli.main(["routes", "add", "--deployment", "demo", "--value", "example.com", "--non-interactive"]),
                0,
            )
        mocked.assert_called_once_with(
            "demo",
            "add",
            value="example.com",
            outbound="local-egress",
            rule_type="domain",
            include_subdomains=False,
            rule_id="",
            non_interactive=True,
        )

    def test_routes_remain_available_when_only_web_ui_is_disabled(self) -> None:
        env = {
            "TOPOLOGY": "single",
            "GATEWAY_LOCATION": "ru",
            "GATEWAY_PUBLIC_IP": "203.0.113.10",
            "ADMIN_WEB_ENABLED": "0",
        }
        with patch("vpn_installer.cli.select_existing_deployment", return_value="demo"), patch(
            "vpn_installer.cli.load_existing_deployment_env", return_value=(None, env)
        ), patch("vpn_installer.cli.routes_workflow", return_value=0) as routes:
            self.assertEqual(cli.main(["routes", "list", "--deployment", "demo"]), 0)
        routes.assert_called_once()

    def test_front_diagnose_dispatch(self) -> None:
        with patch("vpn_installer.cli.diagnose_front_workflow", return_value=1) as mocked:
            self.assertEqual(cli.main(["diagnose", "front", "--deployment", "demo", "--source-ip", "203.0.113.44", "--minutes", "60", "--non-interactive"]), 1)
        mocked.assert_called_once_with("demo", source_ip="203.0.113.44", minutes=60, non_interactive=True)

    def test_verify_live_dispatch(self) -> None:
        with patch("vpn_installer.cli.verify_live_workflow", return_value=0) as mocked:
            self.assertEqual(cli.main(["verify", "live", "--deployment", "demo", "--non-interactive"]), 0)
        mocked.assert_called_once_with("demo", non_interactive=True, throughput_seconds=30)

    def test_verify_live_dispatches_explicit_performance_window(self) -> None:
        with patch("vpn_installer.cli.verify_live_workflow", return_value=0) as mocked:
            self.assertEqual(
                cli.main(["verify", "live", "--deployment", "demo", "--throughput-seconds", "30", "--non-interactive"]),
                0,
            )
        mocked.assert_called_once_with("demo", non_interactive=True, throughput_seconds=30)


if __name__ == "__main__":
    unittest.main()
