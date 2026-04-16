from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import android
from vpn_installer.models import AppError


class AndroidTests(unittest.TestCase):
    def test_parse_adb_devices(self) -> None:
        output = "\n".join(
            [
                "List of devices attached",
                "ABC123 device product:demo model:Pixel_8 device:husky transport_id:2",
                "XYZ999 unauthorized usb:1-1 transport_id:7",
            ]
        )
        devices = android.parse_adb_devices(output)
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0]["serial"], "ABC123")
        self.assertEqual(devices[0]["state"], "device")
        self.assertEqual(devices[0]["meta"]["model"], "Pixel_8")
        self.assertEqual(devices[1]["state"], "unauthorized")

    def test_select_adb_device_requires_ready_state(self) -> None:
        with self.assertRaises(AppError):
            android.select_adb_device([{"serial": "ABC", "state": "offline", "meta": {}}], None)

    def test_extract_vpn_interfaces(self) -> None:
        ip_brief = "\n".join(
            [
                "lo               UNKNOWN        127.0.0.1/8 ::1/128",
                "wlan0            UP             192.168.1.2/24",
                "tun0             UNKNOWN        172.19.0.2/30",
                "ipsec0           UNKNOWN        10.0.0.2/32",
            ]
        )
        self.assertEqual(android.extract_vpn_interfaces(ip_brief), ["tun0", "ipsec0"])

    def test_analyze_android_state_reports_missing_tunnel(self) -> None:
        result = android.analyze_android_state(
            package_name=android.DEFAULT_HIDDIFY_PACKAGE,
            package_list_text="package:app.hiddify.com\n",
            ip_brief_text="lo UNKNOWN 127.0.0.1/8\nwlan0 UP 192.168.1.2/24\n",
            route_text="default via 192.168.1.1 dev wlan0\n",
            connectivity_text="No active VPN\n",
            activity_services_text="",
            private_dns_mode="hostname",
            logcat_filtered="",
        )
        self.assertTrue(result["package_installed"])
        self.assertEqual(result["vpn_interfaces"], [])
        self.assertTrue(result["issues"])

    def test_android_diagnose_writes_summary(self) -> None:
        def fake_run_command(args, *, capture_output=False, input_text=None, cwd=None, env=None, check=True):  # noqa: ARG001
            import subprocess

            key = tuple(args)
            stdout = responses.get(key, "")
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

        responses = {
            ("adb.exe", "start-server"): "",
            ("adb.exe", "devices", "-l"): "List of devices attached\nABC123 device model:Pixel_8 transport_id:2\n",
            ("adb.exe", "-s", "ABC123", "shell", "getprop"): "[ro.product.model]: [Pixel 8]\n",
            ("adb.exe", "-s", "ABC123", "shell", "ip", "-brief", "addr"): "tun0 UNKNOWN 172.19.0.2/30\nwlan0 UP 192.168.1.2/24\n",
            ("adb.exe", "-s", "ABC123", "shell", "ip", "rule"): "0: from all lookup local\n",
            ("adb.exe", "-s", "ABC123", "shell", "sh", "-lc", "ip route show table all; echo; ip -6 route show table all"): "default dev tun0 table 100\n",
            ("adb.exe", "-s", "ABC123", "shell", "dumpsys", "connectivity"): "VPN package: app.hiddify.com\n",
            ("adb.exe", "-s", "ABC123", "shell", "dumpsys", "activity", "services", "app.hiddify.com"): "ServiceRecord{ app.hiddify.com }\n",
            ("adb.exe", "-s", "ABC123", "shell", "dumpsys", "package", "app.hiddify.com"): "Package [app.hiddify.com]\n",
            ("adb.exe", "-s", "ABC123", "shell", "pm", "list", "packages", "app.hiddify.com"): "package:app.hiddify.com\n",
            ("adb.exe", "-s", "ABC123", "shell", "settings", "get", "global", "private_dns_mode"): "off\n",
            ("adb.exe", "-s", "ABC123", "shell", "settings", "get", "global", "private_dns_specifier"): "null\n",
            ("adb.exe", "-s", "ABC123", "logcat", "-d", "-v", "threadtime", "-t", "50"): "04-16 10:00:00.000 Hiddify VPN started on tun0\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("vpn_installer.android.find_adb_executable", return_value="adb.exe"), patch("vpn_installer.android.run_command", side_effect=fake_run_command), patch.object(android, "OUT_DIR", Path(tmp) / "out"):
                rc = android.android_diagnose(serial=None, logcat_lines=50)
            self.assertEqual(rc, 0)
            summaries = list((Path(tmp) / "out" / "android").rglob("summary.json"))
            self.assertEqual(len(summaries), 1)
            self.assertIn("ABC123", summaries[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
