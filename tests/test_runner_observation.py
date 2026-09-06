from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer.runner_observation import _endpoint, observe, process_sockets
from vpn_installer.vless_verify import render_vless_runner


BASH = ("C:/Program Files/Git/bin/bash.exe" if Path("C:/Program Files/Git/bin/bash.exe").is_file()
        else shutil.which("bash") if sys.platform != "win32" else None)


class RunnerObservationTests(unittest.TestCase):
    @unittest.skipUnless(Path("/proc/net/tcp").exists(), "Linux procfs is required for process socket attribution")
    def test_real_process_socket_is_attributed_by_inode(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)
            port = listener.getsockname()[1]
            child = subprocess.Popen([sys.executable, "-c", "import socket,time,sys; s=socket.create_connection(('127.0.0.1',int(sys.argv[1]))); time.sleep(10)", str(port)])
            try:
                peer, address = listener.accept()
                with peer:
                    self.assertEqual(process_sockets(Path("/proc") / str(child.pid), ("127.0.0.1", port)), {f"127.0.0.1:{address[1]}"})
            finally:
                child.terminate()
                child.wait(timeout=3)

    def test_proc_endpoint_decodes_ipv4_ipv6_and_mapped_ipv4(self) -> None:
        self.assertEqual(_endpoint("0100007F:01BB"), ("127.0.0.1", 443))
        self.assertEqual(_endpoint("00000000000000000000000001000000:01BB"), ("::1", 443))
        self.assertEqual(_endpoint("0000000000000000FFFF00000100007F:01BB"), ("127.0.0.1", 443))

    def test_socket_selection_requires_owned_inode_and_remote_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / "fd").mkdir()
            (proc / "net").mkdir()
            (proc / "fd" / "3").touch()
            (proc / "net" / "tcp").write_text(
                "header\n0: 0100007F:C350 0200007F:01BB 01 0:0 0:0 0 0 0 123\n"
                "1: 0100007F:C351 0200007F:01BB 01 0:0 0:0 0 0 0 456\n"
                "2: 0100007F:C352 0200007F:0016 01 0:0 0:0 0 0 0 123\n",
                encoding="ascii",
            )
            with patch("vpn_installer.runner_observation.os.readlink", return_value="socket:[123]"):
                self.assertEqual(process_sockets(proc, ("127.0.0.2", 443)), {"127.0.0.1:50000"})

    def test_observation_preserves_closed_flow_and_stops_on_explicit_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            proc = root / "123"
            proc.mkdir()
            (proc / "stat").write_text("123 (name with space) " + " ".join(["0"] * 19 + ["12345"]))
            stop = root / "stop"
            with patch("vpn_installer.runner_observation.process_sockets", return_value={"127.0.0.1:50000"}), patch("vpn_installer.runner_observation.time.sleep", side_effect=lambda _: stop.touch()):
                result = observe(123, {"outbounds": [{"type": "vless", "server": "127.0.0.2", "server_port": 443}]}, stop, proc_root=root)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["flows"], ["127.0.0.1:50000"])

    def test_non_tcp_profile_is_not_applicable(self) -> None:
        self.assertEqual(observe(123, {"outbounds": [{"type": "hysteria2"}]}, Path("unused"))["status"], "not_applicable")

    def test_identity_change_during_last_sample_discards_socket_evidence(self) -> None:
        for change in ("reused", "exited"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                proc = root / "123"
                proc.mkdir()
                stat = proc / "stat"
                stat.write_text("123 (name) " + " ".join(["0"] * 19 + ["12345"]))
                stop = root / "stop"

                def sample(_proc, _destination):
                    if change == "reused":
                        stat.write_text("123 (name) " + " ".join(["0"] * 19 + ["54321"]))
                    else:
                        stat.unlink()
                    stop.touch()
                    return {"127.0.0.1:50000"}

                with patch("vpn_installer.runner_observation.process_sockets", side_effect=sample):
                    with self.assertRaisesRegex(RuntimeError, "identity|exited"):
                        observe(123, {"outbounds": [{"type": "vless", "server": "127.0.0.2", "server_port": 443}]}, stop, proc_root=root)

    @unittest.skipUnless(BASH, "Bash is required for observer shutdown regression")
    def test_observer_shutdown_is_bounded_on_normal_and_cleanup_paths(self) -> None:
        script = render_vless_runner(listen_port=18080)
        helper = ""
        if "stop_observer() {" in script:
            helper = "stop_observer() {" + script.split("stop_observer() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        normal = script.split('throughput_source_failure_counts_csv=$(IFS=,; printf', 1)[1].split("\n", 1)[1].split('\npython3 - "$ru_ip"', 1)[0]
        cleanup = script.split("cleanup() {", 1)[1].split('    if [[ -n "${watchdog_pid:-}"', 1)[0]
        for name, body in (("normal", normal), ("cleanup", cleanup)):
            for mode in ("stuck", "graceful", "term", "kill", "failed"):
                with self.subTest(path=name, mode=mode), tempfile.TemporaryDirectory() as temp:
                    harness = r'''
set -uo pipefail
work_dir=.
observer_pid=4242
polls=0
live=1
mode=$1
kill() {
    printf '%s\n' "$*" >> signals
    if [[ "$1" == -0 ]]; then
        [[ "$mode" == graceful || "$mode" == failed ]] && live=0
        (( live ))
        return
    fi
    if [[ "$1" == -TERM && "$mode" == term || "$1" == -KILL && "$mode" == kill ]]; then
        live=0
    fi
    return 0
}
sleep() { polls=$((polls + 1)); (( polls < 100 )) || exit 91; }
wait() {
    (( live )) && printf 'wait-on-live-observer\n' > waited-live
    [[ "$mode" != failed ]]
}
'''
                    original = {"status": "ok", "flows": ["127.0.0.1:50000"]}
                    Path(temp, "runner-sockets.json").write_text(json.dumps(original))
                    result = subprocess.run([BASH, "--noprofile", "--norc", "-c", harness + helper + body, "observer-test", mode], cwd=temp, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(Path(temp, "waited-live").exists())
                    signals = Path(temp, "signals").read_text()
                    evidence = json.loads(Path(temp, "runner-sockets.json").read_text())
                    if mode == "graceful":
                        self.assertNotIn("-TERM", signals)
                        self.assertNotIn("-KILL", signals)
                        self.assertEqual(evidence, original)
                    else:
                        if mode != "failed":
                            self.assertIn("-TERM 4242", signals)
                        if mode in {"stuck", "kill"}:
                            self.assertIn("-KILL 4242", signals)
                        self.assertEqual(evidence["status"], "error")
                        self.assertEqual(evidence["flows"], [])

    def test_runner_report_keeps_missing_or_truncated_observer_output_inconclusive(self) -> None:
        script = render_vless_runner(listen_port=18080)
        reporting = script.rsplit("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
        source = reporting.split("bytes_downloaded =", 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, "runner-sockets.json")
            for contents in (None, "", "{", "not-json"):
                with self.subTest(contents=contents):
                    if contents is not None:
                        path.write_text(contents)
                    namespace = {}
                    with patch("pathlib.Path", return_value=path):
                        exec(source, namespace)
                    self.assertEqual(namespace["runner_sockets"]["status"], "error")
                    self.assertEqual(namespace["runner_sockets"]["flows"], [])

    def test_runner_contains_single_canonical_observer_source(self) -> None:
        script = render_vless_runner(listen_port=18080)
        source = script.split("<<'OBSERVER_PY' &\n", 1)[1].split("\nOBSERVER_PY", 1)[0]
        compile(source, "runner-observer", "exec")
        self.assertIn('"runner_sockets":', script)
        self.assertNotIn("__SOCKET_OBSERVER__", script)


if __name__ == "__main__":
    unittest.main()
