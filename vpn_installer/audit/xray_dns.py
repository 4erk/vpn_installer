from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from ..common import ROOT_DIR
from ..manifest import XRAY_LINUX_AMD64_BINARY_SHA256, XRAY_LINUX_AMD64_SHA256, XRAY_VERSION
from .runner import AUDIT_IMAGE, AUDIT_ROOT, AuditFailure, AuditRunner, write_bytes

PROBE_TIMEOUT_SECONDS = 20


def ensure_xray_binary(runner: AuditRunner) -> Path:
    cache = AUDIT_ROOT / "binaries" / f"xray-{XRAY_LINUX_AMD64_BINARY_SHA256}"
    if cache.is_file():
        if hashlib.sha256(cache.read_bytes()).hexdigest() != XRAY_LINUX_AMD64_BINARY_SHA256:
            raise AuditFailure("cached production Xray binary hash mismatch")
        return cache
    work = runner.work_dir / "xray-dns-port"
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "xray.zip"
    runner.run_command("download-dns-xray-release", [
        "curl", "--fail", "--silent", "--show-error", "--location", "--connect-timeout", "10", "--max-time", "60",
        f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-linux-64.zip", "--output", str(archive),
    ], timeout_seconds=65)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != XRAY_LINUX_AMD64_SHA256:
        raise AuditFailure("production Xray archive hash mismatch")
    with zipfile.ZipFile(archive) as bundle:
        binary = bundle.read("xray")
    if hashlib.sha256(binary).hexdigest() != XRAY_LINUX_AMD64_BINARY_SHA256:
        raise AuditFailure("production Xray binary hash mismatch")
    staged = work / "xray"
    write_bytes(staged, binary)
    staged.chmod(0o755)
    cache.parent.mkdir(parents=True, exist_ok=True)
    staged.replace(cache)
    return cache


def test_xray_dns_port(runner: AuditRunner) -> dict:
    """Exercise the rendered DNS URL with the pinned binary, without egress."""
    binary = ensure_xray_binary(runner)
    runner.ensure_audit_image()
    base_image = runner.docker("inspect-dns-base-image", ["image", "inspect", "--format", "{{.Id}}", AUDIT_IMAGE]).stdout.strip()
    with runner.docker_container(
        f"xray-dns-{runner.run_id}", base_image, network="none", extra_args=["--cap-drop=ALL"],
    ) as container:
        runner.docker_exec(container, "mkdir -p /work")
        runner.docker_copy(container, binary, "/work/xray")
        runner.docker_copy(container, ROOT_DIR / "vpn_installer", "/work/vpn_installer")
        runner.docker_copy(container, ROOT_DIR / "tests" / "xray_dns_probe.py", "/work/probe.py")
        completed = runner.docker_exec(
            container, "PYTHONPATH=/work python3 /work/probe.py", timeout_seconds=PROBE_TIMEOUT_SECONDS,
        )
        result = json.loads(completed.stdout)
        if result.get("status") != "passed":
            raise AuditFailure(f"Xray DNS runtime probe did not pass: {result}")
        return result


if __name__ == "__main__":
    runner = AuditRunner("xray-dns-port", json_output=True)
    runner.record("docker-xray-dns-port", lambda: test_xray_dns_port(runner))
    runner.write_summary()
    raise SystemExit(runner.exit_code)
