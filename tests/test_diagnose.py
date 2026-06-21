from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import diagnose
from vpn_installer.models import ROLE_FOREIGN, ROLE_RU, RemoteTarget


class DiagnoseTests(unittest.TestCase):
    def test_path_script_collects_route_and_loss_diagnostics(self) -> None:
        script = diagnose._path_script(ROLE_RU, "wg0")
        self.assertIn("tc -s qdisc show dev", script)
        self.assertIn("mtr -rwzc 20", script)
        self.assertIn("curl -4kLsS", script)
        self.assertIn("peer_wg", script)
        self.assertIn("10.74.0.2", script)
        self.assertIn("section recent_xray_grouped", script)
        self.assertIn("vpn-stack-xray.service", script)
        self.assertIn("accepted_destinations=", script)
        self.assertIn("timeout_destinations=", script)

    def test_diagnose_path_writes_reports_for_targets(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        foreign = RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example", ssh_user="root")
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with (
                patch.object(diagnose, "OUT_DIR", out_dir),
                patch.object(
                    diagnose,
                    "prepare_remote_session",
                    return_value=("demo", Path("deployments/demo.env"), {"WG_INTERFACE": "wgx"}, {}, [ru, foreign], {}),
                ) as prepare_mock,
                patch.object(diagnose, "ssh_capture", side_effect=["ru-report", "foreign-report"]) as ssh_mock,
            ):
                self.assertEqual(diagnose.diagnose_path_workflow("demo", "all"), 0)
                reports = sorted(out_dir.glob("diagnostics/*/*.txt"))
                self.assertEqual([path.name for path in reports], ["foreign-exit.txt", "ru-gateway.txt"])
                self.assertEqual(reports[0].read_text(encoding="utf-8"), "foreign-report")
                self.assertEqual(reports[1].read_text(encoding="utf-8"), "ru-report")

        prepare_mock.assert_called_once()
        self.assertEqual(ssh_mock.call_count, 2)

    def test_iperf_smoke_requires_both_roles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(diagnose, "warn") as warn_mock:
            diagnose._run_iperf_smoke(Path(tmp), [RemoteTarget(role=ROLE_RU)])
        warn_mock.assert_called_once()

    def test_iperf_smoke_opens_and_cleans_temporary_wg_rules(self) -> None:
        ru = RemoteTarget(role=ROLE_RU, ssh_host="ru.example", ssh_user="root")
        foreign = RemoteTarget(role=ROLE_FOREIGN, ssh_host="foreign.example", ssh_user="root")
        with tempfile.TemporaryDirectory() as tmp, patch.object(diagnose.time, "sleep"), patch.object(diagnose, "ssh_capture", return_value="ok") as ssh_mock:
            diagnose._run_iperf_smoke(Path(tmp), [ru, foreign])
            outputs = sorted(Path(tmp).glob("iperf-*.txt"))

        self.assertEqual(len(outputs), 4)
        commands = "\n".join(call.args[1] for call in ssh_mock.call_args_list)
        self.assertIn("vpnstack-diag-iperf", commands)
        self.assertIn("systemd-run --unit=vpnstack-iperf3", commands)
        self.assertIn("iperf3 -c 10.74.0.2", commands)
        self.assertIn("nft delete rule inet vpnstack input handle", commands)


if __name__ == "__main__":
    unittest.main()
