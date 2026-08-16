from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..common import INSTALL_SCRIPT_PATH, OUT_DIR, ROOT_DIR, RUNTIME_SITE_PACKAGES, ensure_file_parent
from ..config import generate_default_env, load_env_file, render_env_text
from ..manifest import SING_BOX_LINUX_AMD64_ARCHIVE_SHA256, SING_BOX_LINUX_AMD64_BINARY_SHA256, SING_BOX_VERSION

AUDIT_ROOT = OUT_DIR / "audit"
AUDIT_SINGBOX_REQUIRED_VERSION = SING_BOX_VERSION
AUDIT_SINGBOX_LINUX_AMD64_SHA256 = SING_BOX_LINUX_AMD64_ARCHIVE_SHA256
AUDIT_SINGBOX_LINUX_AMD64_BINARY_SHA256 = SING_BOX_LINUX_AMD64_BINARY_SHA256
AUDIT_IMAGE = f"vpn-installer-audit-base:sing-box-{AUDIT_SINGBOX_REQUIRED_VERSION}"
AUDIT_COMMAND_TIMEOUT_SECONDS = 120
AUDIT_DOCKER_TIMEOUT_SECONDS = 45
AUDIT_IMAGE_BUILD_TIMEOUT_SECONDS = 600
VALID_GEOSITE_SRS_BASE64 = "U1JTAnjaYmRgYmBkgAAOGCOLubSI6z8DIAAA//8KOAJr"
VALID_GEOIP_SRS_BASE64 = "U1JTAnjaYmRgY2SAAEaW0wyFDCDi/38GQAAAAP//GVUEiA=="
VALID_GEOSITE_SRS = base64.b64decode(VALID_GEOSITE_SRS_BASE64)
VALID_GEOIP_SRS = base64.b64decode(VALID_GEOIP_SRS_BASE64)
VPN_CMD = ROOT_DIR / "vpn.cmd"
VPN_SH = ROOT_DIR / "vpn.sh"
REPO_FILES_FOR_BOOTSTRAP = [
    "vpn.cmd",
    "vpn.ps1",
    "vpn.sh",
    "install.sh",
    "vpn_installer",
    "deployments",
]


class AuditFailure(RuntimeError):
    pass


@dataclass
class TestResult:
    name: str
    status: str
    duration_sec: float
    details: str = ""
    artifacts: dict[str, str] = field(default_factory=dict)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_text(path: Path, content: str) -> None:
    ensure_file_parent(path)
    path.write_text(content, encoding="utf-8", newline="\n")


def write_bytes(path: Path, content: bytes) -> None:
    ensure_file_parent(path)
    path.write_bytes(content)


def powershell_executable() -> str:
    for name in ("powershell", "pwsh"):
        if shutil.which(name):
            return name
    raise AuditFailure("Не найден PowerShell.")


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise AuditFailure(f"Не найдена команда: {name}")


def python_cmd() -> list[str]:
    return [sys.executable]


def process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        process_query_limited_information = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        queried = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(queried) and exit_code.value == 259
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


@contextmanager
def audit_run_lock(run_id: str, audit_root: Path | None = None):
    lock_path = ensure_dir(audit_root or AUDIT_ROOT) / ".run.lock"
    payload = {"pid": os.getpid(), "run_id": run_id, "started_at": utc_stamp()}
    for _attempt in range(3):
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                owner = json.loads(lock_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                owner = {}
            owner_pid = int(owner.get("pid", 0) or 0)
            if process_is_running(owner_pid):
                owner_run = str(owner.get("run_id", "unknown"))
                raise AuditFailure(f"audit already running: {owner_run} (pid {owner_pid})")
            lock_path.unlink(missing_ok=True)
            continue
        else:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False)
                handle.write("\n")
            break
    else:
        raise AuditFailure("could not acquire audit lock")

    try:
        yield
    finally:
        try:
            owner = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            owner = {}
        if owner.get("pid") == payload["pid"] and owner.get("run_id") == run_id:
            lock_path.unlink(missing_ok=True)


class AuditRunner:
    def __init__(self, mode: str, keep_docker: bool = False, json_output: bool = False) -> None:
        self.mode = mode
        self.keep_docker = keep_docker
        self.json_output = json_output
        self.started_at = utc_stamp()
        self.run_id = f"{run_stamp()}-{mode}"
        self.run_dir = ensure_dir(AUDIT_ROOT / self.run_id)
        self.logs_dir = ensure_dir(self.run_dir / "logs")
        self.work_dir = ensure_dir(self.run_dir / "work")
        self.results: list[TestResult] = []
        self.failures = 0
        self.base_image_ready = False

    @property
    def outcome(self) -> str:
        if self.failures or any(result.status == "failed" for result in self.results):
            return "failed"
        if any(result.status == "skipped" for result in self.results):
            return "incomplete"
        return "passed"

    @property
    def success(self) -> bool:
        return self.outcome == "passed"

    @property
    def exit_code(self) -> int:
        if self.outcome == "failed":
            return 1
        if self.outcome == "incomplete":
            return 2
        return 0

    def note(self, message: str) -> None:
        print(message)

    def summary_path(self) -> Path:
        return self.run_dir / "summary.json"

    def write_summary(self) -> None:
        outcome = self.outcome
        complete = not any(result.status == "skipped" for result in self.results)
        payload = {
            "mode": self.mode,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "completed_at": utc_stamp(),
            "outcome": outcome,
            "success": outcome == "passed",
            "complete": complete,
            "results": [asdict(result) for result in self.results],
        }
        write_text(self.summary_path(), json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        if self.json_output:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return
        print(f"\nИтог: {outcome.upper()}")
        print(f"Summary: {self.summary_path()}")
        for result in self.results:
            print(f"- {result.name}: {result.status}")

    def run(self) -> int:
        import importlib

        docker_checks = importlib.import_module("vpn_installer.audit.docker")
        lab_checks = importlib.import_module("vpn_installer.audit.lab")
        quick_checks = importlib.import_module("vpn_installer.audit.quick")

        try:
            with audit_run_lock(self.run_id, self.run_dir.parent):
                if self.mode == "quick":
                    quick_checks.run(self)
                elif self.mode == "docker":
                    docker_checks.run(self)
                elif self.mode == "lab":
                    lab_checks.run(self)
                elif self.mode == "interop":
                    quick_checks.run_interop(self)
                elif self.mode == "all":
                    quick_checks.run(self)
                    docker_checks.run(self)
                    lab_checks.run(self)
                else:
                    raise AuditFailure(f"Неизвестный режим: {self.mode}")
        except Exception as exc:  # noqa: BLE001
            self.failures += 1
            self.note(f"FAIL: {exc}")
            self.results.append(
                TestResult(
                    name=f"{self.mode}-runner",
                    status="failed",
                    duration_sec=0.0,
                    details=str(exc),
                    artifacts={},
                )
            )
        finally:
            self.write_summary()
        return self.exit_code

    def record(self, name: str, fn: Callable[[], dict[str, str] | str | None]) -> None:
        self.note(f"\n== {name} ==")
        started = time.monotonic()
        status = "passed"
        details = ""
        artifacts: dict[str, str] = {}
        try:
            returned = fn()
            if isinstance(returned, dict):
                artifacts = {key: str(value) for key, value in returned.items()}
            elif isinstance(returned, str):
                details = returned
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            details = str(exc)
            self.failures += 1
            self.note(f"FAIL: {exc}")
        else:
            self.note("OK")
        self.results.append(
            TestResult(
                name=name,
                status=status,
                duration_sec=round(time.monotonic() - started, 3),
                details=details,
                artifacts=artifacts,
            )
        )

    def skip(self, name: str, reason: str) -> None:
        self.note(f"\n== {name} ==")
        self.note(f"SKIP: {reason}")
        self.results.append(
            TestResult(
                name=name,
                status="skipped",
                duration_sec=0.0,
                details=reason,
                artifacts={},
            )
        )

    def run_command(
        self,
        name: str,
        args: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        expect_code: int = 0,
        expected_codes: set[int] | None = None,
        timeout_seconds: int = AUDIT_COMMAND_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        test_dir = ensure_dir(self.logs_dir / re.sub(r"[^A-Za-z0-9._-]+", "-", name))
        stdout_path = test_dir / "stdout.log"
        stderr_path = test_dir / "stderr.log"
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        repo_pythonpath = str(ROOT_DIR)
        pythonpath_parts = [repo_pythonpath]
        if RUNTIME_SITE_PACKAGES.exists():
            pythonpath_parts.append(str(RUNTIME_SITE_PACKAGES))
        if merged_env.get("PYTHONPATH"):
            pythonpath_parts.append(merged_env["PYTHONPATH"])
        merged_env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)
        try:
            completed = subprocess.run(
                args,
                cwd=str(cwd or ROOT_DIR),
                env=merged_env,
                input=input_text,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
            write_text(stdout_path, stdout)
            write_text(stderr_path, stderr)
            raise AuditFailure(
                f"{name}: timeout after {timeout_seconds}s.\nstdout: {stdout_path}\nstderr: {stderr_path}"
            ) from exc
        write_text(stdout_path, completed.stdout)
        write_text(stderr_path, completed.stderr)
        allowed_codes = expected_codes or {expect_code}
        if completed.returncode not in allowed_codes:
            raise AuditFailure(
                f"{name}: код {completed.returncode}, ожидался один из {sorted(allowed_codes)}.\n"
                f"stdout: {stdout_path}\nstderr: {stderr_path}"
            )
        return completed

    def run_bash(
        self,
        name: str,
        script: str,
        *,
        cwd: Path | None = None,
        expect_code: int = 0,
        env: dict[str, str] | None = None,
        expected_codes: set[int] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        require_command("bash")
        return self.run_command(
            name,
            ["bash", "-lc", script],
            cwd=cwd,
            env=env,
            expect_code=expect_code,
            expected_codes=expected_codes,
        )

    def run_powershell(
        self,
        name: str,
        script_or_path: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        expect_code: int = 0,
        expected_codes: set[int] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        exe = powershell_executable()
        return self.run_command(
            name,
            [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", *script_or_path],
            cwd=cwd,
            env=env,
            expect_code=expect_code,
            expected_codes=expected_codes,
        )

    def docker(
        self,
        name: str,
        args: list[str],
        *,
        expect_code: int = 0,
        expected_codes: set[int] | None = None,
        cwd: Path | None = None,
        timeout_seconds: int = AUDIT_DOCKER_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        require_command("docker")
        return self.run_command(
            f"docker-{name}",
            ["docker", *args],
            cwd=cwd,
            expect_code=expect_code,
            expected_codes=expected_codes,
            timeout_seconds=timeout_seconds,
        )

    def ensure_audit_image(self) -> None:
        if self.base_image_ready:
            return
        inspect = subprocess.run(["docker", "image", "inspect", AUDIT_IMAGE], capture_output=True, text=True, check=False, timeout=AUDIT_DOCKER_TIMEOUT_SECONDS)
        if inspect.returncode == 0:
            version = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    AUDIT_IMAGE,
                    "bash",
                    "-lc",
                    f"python3 -c 'import cryptography' && echo '{AUDIT_SINGBOX_LINUX_AMD64_BINARY_SHA256}  /usr/local/bin/sing-box' | sha256sum -c - >/dev/null && sing-box version | awk 'NR == 1 {{print $3}}'",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=AUDIT_DOCKER_TIMEOUT_SECONDS,
            )
            if version.returncode == 0 and version.stdout.strip() == AUDIT_SINGBOX_REQUIRED_VERSION:
                self.base_image_ready = True
                return
            self.note(f"AUDIT_IMAGE {AUDIT_IMAGE} содержит sing-box {version.stdout.strip() or 'unknown'}, пересобираю.")
        build_dir = ensure_dir(self.work_dir / "audit-image")
        dockerfile = textwrap.dedent(
            f"""\
            FROM ubuntu:24.04
            ENV DEBIAN_FRONTEND=noninteractive
            RUN apt-get update && apt-get install -y \
                ca-certificates \
                cloud-init \
                curl \
                dnsmasq \
                gnupg \
                iproute2 \
                iputils-ping \
                jq \
                netcat-openbsd \
                nftables \
                procps \
                python3 \
                python3-cryptography \
                tar \
                wireguard-tools \
                && rm -rf /var/lib/apt/lists/*
            RUN set -eux; \
                curl -fsSL --connect-timeout 10 --max-time 120 \
                  https://github.com/SagerNet/sing-box/releases/download/v{AUDIT_SINGBOX_REQUIRED_VERSION}/sing-box-{AUDIT_SINGBOX_REQUIRED_VERSION}-linux-amd64.tar.gz \
                  -o /tmp/sing-box.tar.gz; \
                echo '{AUDIT_SINGBOX_LINUX_AMD64_SHA256}  /tmp/sing-box.tar.gz' | sha256sum -c -; \
                tar -xzf /tmp/sing-box.tar.gz -C /tmp; \
                echo '{AUDIT_SINGBOX_LINUX_AMD64_BINARY_SHA256}  /tmp/sing-box-{AUDIT_SINGBOX_REQUIRED_VERSION}-linux-amd64/sing-box' | sha256sum -c -; \
                install -m 0755 /tmp/sing-box-{AUDIT_SINGBOX_REQUIRED_VERSION}-linux-amd64/sing-box /usr/local/bin/sing-box; \
                rm -rf /tmp/sing-box.tar.gz /tmp/sing-box-{AUDIT_SINGBOX_REQUIRED_VERSION}-linux-amd64; \
                sing-box version >/tmp/singbox-version.txt
            CMD ["sleep", "infinity"]
            """
        )
        write_text(build_dir / "Dockerfile", dockerfile)
        self.docker(
            "build-audit-image",
            ["build", "-t", AUDIT_IMAGE, str(build_dir)],
            timeout_seconds=AUDIT_IMAGE_BUILD_TIMEOUT_SECONDS,
        )
        self.base_image_ready = True

    def create_env(self, name: str, overrides: dict[str, str] | None = None) -> tuple[Path, dict[str, str]]:
        deploy_name = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{self.run_id}-{name}").strip("-")
        env = generate_default_env(deploy_name)
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        env["WAN_INTERFACE"] = "eth1"
        if overrides:
            env.update(overrides)
        env_path = self.work_dir / "env" / f"{deploy_name}.env"
        write_text(env_path, render_env_text(env))
        return env_path, env

    def parse_cloud_init_payload(self, yaml_path: Path) -> tuple[dict[str, bytes], str]:
        files: dict[str, bytes] = {}
        current_path: str | None = None
        runcmd = ""
        for line in yaml_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("  - path: "):
                current_path = line.split(": ", 1)[1].strip()
            elif current_path and line.strip().startswith("content: "):
                payload = line.split("content: ", 1)[1].strip()
                files[current_path] = base64.b64decode(payload.encode("ascii"))
                current_path = None
            elif line.strip().startswith("- [bash, -lc, "):
                match = re.search(r'- \[bash, -lc, "(.*)"\]', line.strip())
                if match:
                    runcmd = match.group(1)
        if "/root/vpn-stack/install.sh" not in files or "/root/vpn-stack/deployment.env" not in files:
            raise AuditFailure(f"Cloud-init payload {yaml_path} не содержит install.sh/deployment.env")
        if not runcmd:
            raise AuditFailure(f"Cloud-init payload {yaml_path} не содержит runcmd")
        return files, runcmd

    @contextmanager
    def temp_repo_copy(self, name: str):
        target = ensure_dir(self.work_dir / name)
        for rel in REPO_FILES_FOR_BOOTSTRAP:
            source = ROOT_DIR / rel
            destination = target / rel
            if source.is_dir():
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.copytree(source, destination)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
        yield target

    def ensure_quick_env(self) -> tuple[Path, Path]:
        env_path, _ = self.create_env("quick")
        env = load_env_file(env_path)
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        env["WAN_INTERFACE"] = "eth1"
        write_text(env_path, render_env_text(env))
        return env_path, OUT_DIR / env["DEPLOY_NAME"]

    def seed_foreign_block_cache(self, deploy_name: str) -> Path:
        assets_dir = ensure_dir(OUT_DIR / deploy_name / "assets")
        if not (assets_dir / "ru-ipv4.zone").exists():
            write_text(assets_dir / "ru-ipv4.zone", "203.0.113.0/24\n")
        if not (assets_dir / "ru-ipv6.zone").exists():
            write_text(assets_dir / "ru-ipv6.zone", "2001:db8::/32\n")
        return assets_dir

    def cleanup_stale_lab_resources(self) -> None:
        containers = subprocess.run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                "label=vpn-installer.audit=1",
                "--format",
                '{{.Names}}|{{.Label "vpn-installer.audit.run"}}',
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=AUDIT_DOCKER_TIMEOUT_SECONDS,
        )
        for row in containers.stdout.splitlines():
            name, _, run_id = row.partition("|")
            if name and run_id != self.run_id:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, check=False, timeout=AUDIT_DOCKER_TIMEOUT_SECONDS)
        networks = subprocess.run(
            [
                "docker",
                "network",
                "ls",
                "--filter",
                "label=vpn-installer.audit=1",
                "--format",
                '{{.Name}}|{{.Label "vpn-installer.audit.run"}}',
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=AUDIT_DOCKER_TIMEOUT_SECONDS,
        )
        for row in networks.stdout.splitlines():
            name, _, run_id = row.partition("|")
            if name and run_id != self.run_id:
                subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True, check=False, timeout=AUDIT_DOCKER_TIMEOUT_SECONDS)

    def docker_copy(self, container: str, source: Path, destination: str) -> None:
        self.docker("cp", ["cp", str(source), f"{container}:{destination}"])

    def docker_cp_from(self, container: str, source: str, destination: Path) -> None:
        self.docker("cp-from", ["cp", f"{container}:{source}", str(destination)])

    @contextmanager
    def docker_container(
        self,
        name: str,
        image: str,
        *,
        privileged: bool = False,
        network: str | None = None,
        ip: str | None = None,
        extra_args: list[str] | None = None,
    ):
        if image == AUDIT_IMAGE:
            self.ensure_audit_image()
        args = [
            "create",
            "--name",
            name,
            "--label",
            "vpn-installer.audit=1",
            "--label",
            f"vpn-installer.audit.run={self.run_id}",
        ]
        if privileged:
            args.append("--privileged")
        if network:
            args.extend(["--network", network])
        if ip:
            args.extend(["--ip", ip])
        if extra_args:
            args.extend(extra_args)
        args.extend([image, "sleep", "infinity"])
        self.docker(f"create-{name}", args)
        try:
            self.docker(f"start-{name}", ["start", name])
            yield name
        finally:
            if not self.keep_docker:
                self._docker_cleanup(f"rm-{name}", ["rm", "-f", name])

    def docker_exec(
        self,
        container: str,
        script: str,
        *,
        expect_code: int = 0,
        expected_codes: set[int] | None = None,
        timeout_seconds: int = AUDIT_DOCKER_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        return self.docker(
            f"exec-{container}",
            ["exec", container, "bash", "-lc", script],
            expect_code=expect_code,
            expected_codes=expected_codes,
            timeout_seconds=timeout_seconds,
        )

    @contextmanager
    def docker_network(self, name: str, subnet: str | None = None, gateway: str | None = None):
        args = [
            "network",
            "create",
            "--label",
            "vpn-installer.audit=1",
            "--label",
            f"vpn-installer.audit.run={self.run_id}",
            "--driver",
            "bridge",
        ]
        if subnet is not None:
            args.extend(["--subnet", subnet])
        if gateway is not None:
            args.extend(["--gateway", gateway])
        args.append(name)
        self.docker(
            f"network-create-{name}",
            args,
        )
        try:
            yield name
        finally:
            if not self.keep_docker:
                self._docker_cleanup(f"network-rm-{name}", ["network", "rm", name])

    def docker_network_connect(self, network: str, container: str, ip: str) -> None:
        self.docker(f"network-connect-{network}-{container}", ["network", "connect", "--ip", ip, network, container])

    def lab_curl(self, container: str, url: str, *, expect_codes: set[int] | None = None) -> subprocess.CompletedProcess[str]:
        host = url.split("://", 1)[-1].split("/", 1)[0].replace(":", "_")
        return self.docker(
            f"curl-{container}-{host}",
            ["exec", container, "bash", "-lc", f"curl --silent --show-error --fail --max-time 10 --socks5-hostname 127.0.0.1:1080 {url}"],
            expect_code=0,
            expected_codes=expect_codes or {0},
        )

    def _docker_cleanup(self, name: str, args: list[str]) -> None:
        completed = self.docker(name, args, expect_code=0, expected_codes={0, 1})
        output = f"{completed.stdout}\n{completed.stderr}".lower()
        if completed.returncode == 1 and not any(token in output for token in ("not found", "already in progress")):
            raise AuditFailure(f"{name}: cleanup failed unexpectedly.\nstdout/stderr saved in logs.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Локальный аудит и Docker regression/lab для vpn-installer.")
    parser.add_argument("mode", choices=["quick", "docker", "lab", "interop", "all"], help="Какой контур проверок запускать.")
    parser.add_argument("--json", action="store_true", help="Печатать итоговую summary в JSON.")
    parser.add_argument("--keep-docker", action="store_true", help="Не удалять Docker-контейнеры и сети после тестов.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    runner = AuditRunner(args.mode, keep_docker=args.keep_docker, json_output=args.json)
    return runner.run()
