#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT_DIR / "scripts"
OUT_DIR = ROOT_DIR / "out"
AUDIT_ROOT = OUT_DIR / "audit"
INSTALL_SCRIPT = ROOT_DIR / "install.sh"
BOOTSTRAP_PS1 = ROOT_DIR / "bootstrap.ps1"
BOOTSTRAP_SH = ROOT_DIR / "bootstrap.sh"
MANAGE_PS1 = ROOT_DIR / "manage.ps1"
MANAGE_SH = ROOT_DIR / "manage.sh"
ORCHESTRATE_SCRIPT = SCRIPTS_DIR / "orchestrate.py"
AUDIT_IMAGE = "vpn-installer-audit-base:1"
REPO_FILES_FOR_BOOTSTRAP = ["bootstrap.ps1", "bootstrap.sh", "manage.ps1", "manage.sh", "install.sh", "scripts", "deployments"]

LAB_FRONT_SUBNET = "198.18.0.0/24"
LAB_RU_SUBNET = "203.0.113.0/24"
LAB_GLOBAL_SUBNET = "198.51.100.0/24"
LAB_FRONT_GATEWAY = "198.18.0.1"
LAB_RU_GATEWAY = "203.0.113.1"
LAB_GLOBAL_GATEWAY = "198.51.100.1"
LAB_IPS = {
    "ru": "198.18.0.10",
    "foreign": "198.18.0.20",
    "client": "198.18.0.30",
    "dns": "198.18.0.53",
    "ru_web": "203.0.113.80",
    "global_web": "198.51.100.80",
    "foreign_wan": "198.51.100.20",
    "ru_lan": "203.0.113.10",
}

sys.path.insert(0, str(SCRIPTS_DIR))
import orchestrate  # noqa: E402


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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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

    def note(self, message: str) -> None:
        print(message)

    def cleanup_stale_lab_resources(self) -> None:
        container_prefixes = ("ru-", "foreign-", "client-", "dns-", "ruweb-", "globalweb-")
        network_prefixes = ("audit-front-", "audit-ru-", "audit-global-")
        containers = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True, check=False)
        for name in containers.stdout.splitlines():
            if name.endswith("-lab") and name.startswith(container_prefixes):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, check=False)
        networks = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True, check=False)
        for name in networks.stdout.splitlines():
            if name.endswith("-lab") and name.startswith(network_prefixes):
                subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True, check=False)

    def summary_path(self) -> Path:
        return self.run_dir / "summary.json"

    def write_summary(self) -> None:
        payload = {
            "mode": self.mode,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "completed_at": utc_stamp(),
            "success": self.failures == 0,
            "results": [asdict(result) for result in self.results],
        }
        write_text(self.summary_path(), json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        if self.json_output:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"\nИтог: {'OK' if self.failures == 0 else 'FAIL'}")
            print(f"Summary: {self.summary_path()}")
            for result in self.results:
                print(f"- {result.name}: {result.status}")

    def run(self) -> int:
        try:
            if self.mode == "quick":
                self.run_quick()
            elif self.mode == "docker":
                self.run_docker()
            elif self.mode == "lab":
                self.run_lab()
            elif self.mode == "all":
                self.run_quick()
                self.run_docker()
                self.run_lab()
            else:
                raise AuditFailure(f"Неизвестный режим: {self.mode}")
        finally:
            self.write_summary()
        return 0 if self.failures == 0 else 1

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
    ) -> subprocess.CompletedProcess[str]:
        test_dir = ensure_dir(self.logs_dir / re.sub(r"[^A-Za-z0-9._-]+", "-", name))
        stdout_path = test_dir / "stdout.log"
        stderr_path = test_dir / "stderr.log"
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        completed = subprocess.run(
            args,
            cwd=str(cwd or ROOT_DIR),
            env=merged_env,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )
        write_text(stdout_path, completed.stdout)
        write_text(stderr_path, completed.stderr)
        allowed_codes = expected_codes or {expect_code}
        if completed.returncode not in allowed_codes:
            raise AuditFailure(
                f"{name}: код {completed.returncode}, ожидался один из {sorted(allowed_codes)}.\n"
                f"stdout: {stdout_path}\nstderr: {stderr_path}"
            )
        return completed

    def run_bash(self, name: str, script: str, *, cwd: Path | None = None, expect_code: int = 0, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        require_command("bash")
        return self.run_command(name, ["bash", "-lc", script], cwd=cwd, env=env, expect_code=expect_code)

    def run_powershell(self, name: str, script_or_path: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, expect_code: int = 0) -> subprocess.CompletedProcess[str]:
        exe = powershell_executable()
        return self.run_command(name, [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", *script_or_path], cwd=cwd, env=env, expect_code=expect_code)

    def docker(
        self,
        name: str,
        args: list[str],
        *,
        expect_code: int = 0,
        expected_codes: set[int] | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        require_command("docker")
        return self.run_command(
            f"docker-{name}",
            ["docker", *args],
            cwd=cwd,
            expect_code=expect_code,
            expected_codes=expected_codes,
        )

    def ensure_audit_image(self) -> None:
        if self.base_image_ready:
            return
        inspect = subprocess.run(["docker", "image", "inspect", AUDIT_IMAGE], capture_output=True, text=True, check=False)
        if inspect.returncode == 0:
            self.base_image_ready = True
            return
        build_dir = ensure_dir(self.work_dir / "audit-image")
        dockerfile = textwrap.dedent(
            """\
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
                tar \
                wireguard-tools \
                && rm -rf /var/lib/apt/lists/*
            RUN bash -lc 'curl -fsSL https://sing-box.sagernet.org/installation/tools/install.sh | bash && sing-box version >/tmp/singbox-version.txt'
            CMD ["sleep", "infinity"]
            """
        )
        write_text(build_dir / "Dockerfile", dockerfile)
        self.docker("build-audit-image", ["build", "-t", AUDIT_IMAGE, str(build_dir)])
        self.base_image_ready = True

    def create_env(self, name: str, overrides: dict[str, str] | None = None) -> tuple[Path, dict[str, str]]:
        deploy_name = orchestrate.sanitize_name(f"{self.run_id}-{name}")
        env = orchestrate.generate_default_env(deploy_name)
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        env["WAN_INTERFACE"] = "eth1"
        if overrides:
            env.update(overrides)
        env_path = self.work_dir / "env" / f"{deploy_name}.env"
        write_text(env_path, orchestrate.render_env_text(env))
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
        self.run_command("init-env-sanity", python_cmd() + [str(ORCHESTRATE_SCRIPT), "init-env", str(env_path)], expect_code=0)
        env = orchestrate.load_env_file(env_path)
        env["RU_PUBLIC_IP"] = "203.0.113.10"
        env["FOREIGN_PUBLIC_IP"] = "198.51.100.20"
        env["WAN_INTERFACE"] = "eth1"
        write_text(env_path, orchestrate.render_env_text(env))
        return env_path, OUT_DIR / env["DEPLOY_NAME"]

    def seed_foreign_block_cache(self, deploy_name: str) -> Path:
        assets_dir = ensure_dir(OUT_DIR / deploy_name / "assets")
        if not (assets_dir / "ru-ipv4.zone").exists():
            write_text(assets_dir / "ru-ipv4.zone", "203.0.113.0/24\n")
        if not (assets_dir / "ru-ipv6.zone").exists():
            write_text(assets_dir / "ru-ipv6.zone", "2001:db8::/32\n")
        return assets_dir

    def run_quick(self) -> None:
        require_command("docker")
        self.ensure_audit_image()
        env_path, out_dir = self.ensure_quick_env()
        self.seed_foreign_block_cache(out_dir.name)

        self.record("quick-bash-syntax", lambda: self.run_bash("bash-syntax", "bash -n install.sh") or None)
        self.record("quick-py-compile", lambda: self.run_command("py-compile", python_cmd() + ["-m", "py_compile", str(ORCHESTRATE_SCRIPT)]) or None)
        self.record(
            "quick-bootstrap-ps1-help",
            lambda: self.run_powershell("bootstrap-ps1-help", ["-File", str(BOOTSTRAP_PS1), "--help"]) or None,
        )
        self.record(
            "quick-bootstrap-sh-help",
            lambda: self.run_bash("bootstrap-sh-help", "bash ./bootstrap.sh --help", cwd=ROOT_DIR) or None,
        )
        self.record(
            "quick-manage-ps1-help",
            lambda: self.run_powershell("manage-ps1-help", ["-File", str(MANAGE_PS1), "--help"]) or None,
        )
        self.record(
            "quick-manage-sh-help",
            lambda: self.run_bash("manage-sh-help", "bash ./manage.sh --help", cwd=ROOT_DIR) or None,
        )
        self.record(
            "quick-orchestrate-help",
            lambda: self.run_command("orchestrate-help", python_cmd() + [str(ORCHESTRATE_SCRIPT), "--help"]) or None,
        )
        self.record(
            "quick-render-all",
            lambda: self.run_command("render-all", python_cmd() + [str(ORCHESTRATE_SCRIPT), "render-all", str(env_path)]) or {"out_dir": str(out_dir)},
        )
        self.record(
            "quick-render-config",
            lambda: self.run_command("render-config", python_cmd() + [str(ORCHESTRATE_SCRIPT), "render-config", str(env_path)]) or None,
        )
        self.record(
            "quick-gen-client-profiles",
            lambda: self.run_command("gen-client-profiles", python_cmd() + [str(ORCHESTRATE_SCRIPT), "gen-client-profiles", str(env_path)]) or None,
        )
        self.record(
            "quick-render-cloud-init",
            lambda: self.run_command("render-cloud-init", python_cmd() + [str(ORCHESTRATE_SCRIPT), "render-cloud-init", str(env_path)]) or None,
        )
        self.record(
            "quick-package-bundle",
            lambda: self.run_command("package-bundle", python_cmd() + [str(ORCHESTRATE_SCRIPT), "package-bundle", str(env_path)]) or None,
        )
        self.record("quick-validate-json", lambda: self.test_validate_json(out_dir))
        self.record("quick-validate-bundle", lambda: self.test_validate_bundle(out_dir))
        self.record("quick-singbox-check", lambda: self.test_singbox_check(out_dir))
        self.record("quick-cloud-init-schema", lambda: self.test_cloud_init_schema(out_dir))
        self.record("quick-cloud-init-render-only", lambda: self.test_cloud_init_render_only(out_dir))
        self.record("quick-bundle-render-only", lambda: self.test_bundle_render_only(out_dir))
        self.record("quick-bootstrap-clean-room", self.test_bootstrap_clean_room)
        self.record("quick-bootstrap-sh-no-python", self.test_linux_bootstrap_no_python)
        self.record("quick-bootstrap-sh-python", self.test_linux_bootstrap_with_python)

    def run_docker(self) -> None:
        require_command("docker")
        self.ensure_audit_image()
        self.record("docker-unmanaged-remove-purge-render-only", self.test_unmanaged_remove_purge_render_only)
        self.record("docker-asset-fail-fast", self.test_asset_fail_fast)
        self.record("docker-status-readonly-role", self.test_status_readonly_role)
        self.record("docker-remote-action-reinstall-role", lambda: self.test_remote_action_role("reinstall"))
        self.record("docker-remote-action-remove-role", lambda: self.test_remote_action_role("remove"))
        self.record("docker-remote-action-purge-role", lambda: self.test_remote_action_role("purge"))

    def run_lab(self) -> None:
        require_command("docker")
        self.ensure_audit_image()
        self.record("lab-dataplane", self.test_lab_dataplane)

    def test_validate_json(self, out_dir: Path) -> dict[str, str]:
        json_paths = [
            out_dir / "preview" / "ru" / "sing-box.json",
            out_dir / "preview" / "foreign" / "sing-box.json",
            out_dir / "client" / "hiddify-cross-platform.json",
            out_dir / "client" / "linux-sing-box.json",
        ]
        for path in json_paths:
            if not path.is_file():
                raise AuditFailure(f"Не найден JSON-артефакт: {path}")
            json.loads(path.read_text(encoding="utf-8"))
        return {"validated": ", ".join(str(path) for path in json_paths)}

    def test_validate_bundle(self, out_dir: Path) -> dict[str, str]:
        bundle_dir = out_dir / "bundle"
        tarballs = [bundle_dir / "ru-gateway.tar.gz", bundle_dir / "foreign-exit.tar.gz"]
        expected = {
            "ru-gateway.tar.gz": {"install.sh", "deployment.env", "assets/geosite-ru.srs", "assets/geoip-ru.srs"},
            "foreign-exit.tar.gz": {"install.sh", "deployment.env", "assets/ru-ipv4.zone", "assets/ru-ipv6.zone"},
        }
        for tarball in tarballs:
            if not tarball.is_file():
                raise AuditFailure(f"Не найден bundle: {tarball}")
            with tarfile.open(tarball, "r:gz") as archive:
                names = {member.name.lstrip("./") for member in archive.getmembers() if member.name not in {".", "./"}}
            missing = sorted(expected[tarball.name] - names)
            if missing:
                raise AuditFailure(f"Bundle {tarball.name} не содержит: {', '.join(missing)}")
        return {"bundle_dir": str(bundle_dir)}

    def docker_copy(self, container: str, source: Path, destination: str) -> None:
        self.docker("cp", ["cp", str(source), f"{container}:{destination}"])

    def docker_cp_from(self, container: str, source: str, destination: Path) -> None:
        self.docker("cp-from", ["cp", f"{container}:{source}", str(destination)])

    @contextmanager
    def docker_container(self, name: str, image: str, *, privileged: bool = False, network: str | None = None, ip: str | None = None, extra_args: list[str] | None = None):
        args = ["create", "--name", name, "--label", "vpn-installer.audit=1"]
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
                self.docker(f"rm-{name}", ["rm", "-f", name], expect_code=0)

    def docker_exec(self, container: str, script: str, *, expect_code: int = 0) -> subprocess.CompletedProcess[str]:
        return self.docker(f"exec-{container}", ["exec", container, "bash", "-lc", script], expect_code=expect_code)

    @contextmanager
    def docker_network(self, name: str, subnet: str, gateway: str):
        self.docker(f"network-create-{name}", ["network", "create", "--label", "vpn-installer.audit=1", "--driver", "bridge", "--subnet", subnet, "--gateway", gateway, name])
        try:
            yield name
        finally:
            if not self.keep_docker:
                self.docker(f"network-rm-{name}", ["network", "rm", name], expect_code=0)

    def test_singbox_check(self, out_dir: Path) -> dict[str, str]:
        container = f"audit-singbox-{self.run_id}"
        configs = [
            out_dir / "preview" / "ru" / "sing-box.json",
            out_dir / "preview" / "foreign" / "sing-box.json",
            out_dir / "client" / "linux-sing-box.json",
            out_dir / "client" / "hiddify-cross-platform.json",
        ]
        with self.docker_container(container, AUDIT_IMAGE):
            self.docker_exec(container, "mkdir -p /work /var/lib/vpn-stack/rules")
            for asset in ("geosite-ru.srs", "geoip-ru.srs"):
                self.docker_copy(container, out_dir / "assets" / asset, f"/var/lib/vpn-stack/rules/{asset}")
            for path in configs:
                self.docker_copy(container, path, f"/work/{path.name}")
                self.docker_exec(container, f"sing-box check -c /work/{path.name}")
        return {"checked_configs": ", ".join(path.name for path in configs)}

    def test_cloud_init_schema(self, out_dir: Path) -> dict[str, str]:
        container = f"audit-cloudinit-{self.run_id}"
        with self.docker_container(container, AUDIT_IMAGE):
            self.docker_exec(container, "mkdir -p /work")
            for role in ("ru", "foreign"):
                yaml_path = out_dir / "cloud-init" / f"{role}.yaml"
                self.docker_copy(container, yaml_path, f"/work/{role}.yaml")
                self.docker_exec(container, f"cloud-init schema --config-file /work/{role}.yaml")
        return {"cloud_init_dir": str(out_dir / "cloud-init")}

    def test_cloud_init_render_only(self, out_dir: Path) -> dict[str, str]:
        artifacts_dir = ensure_dir(self.work_dir / "cloud-init-render")
        for role in ("ru", "foreign"):
            yaml_path = out_dir / "cloud-init" / f"{role}.yaml"
            files, _runcmd = self.parse_cloud_init_payload(yaml_path)
            role_dir = ensure_dir(artifacts_dir / role)
            for file_path, content in files.items():
                relative = Path(file_path.lstrip("/"))
                write_bytes(role_dir / relative, content)
            output_dir = role_dir / "rendered"
            role_name = "ru-gateway" if role == "ru" else "foreign-exit"
            self.run_bash(
                f"cloud-init-render-{role}",
                f"bash ./install.sh --role {role_name} --env-file ./deployment.env --assets-dir ./assets --render-only --output-dir ./rendered",
                cwd=role_dir / "root" / "vpn-stack",
            )
            output_dir = role_dir / "root" / "vpn-stack" / "rendered"
            if not (output_dir / "sing-box.json").is_file():
                raise AuditFailure(f"Cloud-init payload {role} не отрендерил sing-box.json")
        return {"artifacts_dir": str(artifacts_dir)}

    def test_bundle_render_only(self, out_dir: Path) -> dict[str, str]:
        container = f"audit-bundle-{self.run_id}"
        with self.docker_container(container, AUDIT_IMAGE):
            self.docker_exec(container, "mkdir -p /work")
            for role in ("ru-gateway", "foreign-exit"):
                tarball = out_dir / "bundle" / f"{role}.tar.gz"
                self.docker_copy(container, tarball, f"/work/{role}.tar.gz")
                self.docker_exec(
                    container,
                    textwrap.dedent(
                        f"""\
                        set -euo pipefail
                        mkdir -p /work/{role}
                        tar -xzf /work/{role}.tar.gz -C /work/{role}
                        cd /work/{role}
                        bash ./install.sh --role {role} --env-file ./deployment.env --assets-dir ./assets --render-only --output-dir /work/{role}/preview
                        test -s /work/{role}/preview/sing-box.json
                        """
                    ),
                )
        return {"bundle_dir": str(out_dir / "bundle")}

    def test_bootstrap_clean_room(self) -> dict[str, str]:
        if os.name != "nt":
            return {"skipped": "bootstrap.ps1 clean-room проверяется только на Windows"}
        with self.temp_repo_copy("bootstrap-clean-room") as repo_copy:
            portable_downloads = ROOT_DIR / ".runtime" / "downloads"
            env = os.environ.copy()
            if portable_downloads.is_dir():
                zips = sorted(portable_downloads.glob("python-*-embeddable-*.zip"))
                if zips:
                    env["VPN_BOOTSTRAP_PYTHON_URL"] = zips[-1].resolve().as_uri()
            self.run_powershell(
                "bootstrap-clean-room",
                ["-File", str(repo_copy / "bootstrap.ps1"), "--help"],
                cwd=repo_copy,
                env=env,
            )
            portable = repo_copy / ".runtime" / "python" / "windows" / "python.exe"
            if not portable.is_file():
                raise AuditFailure("Clean-room bootstrap не поднял portable Python")
            return {"repo_copy": str(repo_copy), "portable_python": str(portable)}

    def test_linux_bootstrap_no_python(self) -> dict[str, str]:
        repo_copy = ensure_dir(self.work_dir / "linux-bootstrap-no-python")
        for rel in ("bootstrap.sh", "scripts"):
            source = ROOT_DIR / rel
            destination = repo_copy / rel
            if source.is_dir():
                shutil.copytree(source, destination, dirs_exist_ok=True)
            else:
                shutil.copy2(source, destination)
        container = f"audit-linux-nopy-{self.run_id}"
        with self.docker_container(container, "ubuntu:24.04"):
            self.docker_exec(container, "mkdir -p /work")
            self.docker_copy(container, repo_copy / "bootstrap.sh", "/work/bootstrap.sh")
            self.docker_copy(container, repo_copy / "scripts", "/work/scripts")
            self.docker_exec(
                container,
                "cd /work && chmod +x ./bootstrap.sh && set +e && ./bootstrap.sh --help >/tmp/out 2>/tmp/err; rc=$?; set -e; test \"$rc\" -eq 1; grep -q 'Python 3 не найден' /tmp/err",
            )
        return {"status": "graceful-fail"}

    def test_linux_bootstrap_with_python(self) -> dict[str, str]:
        repo_copy = ensure_dir(self.work_dir / "linux-bootstrap-python")
        for rel in ("bootstrap.sh", "scripts"):
            source = ROOT_DIR / rel
            destination = repo_copy / rel
            if source.is_dir():
                shutil.copytree(source, destination, dirs_exist_ok=True)
            else:
                shutil.copy2(source, destination)
        container = f"audit-linux-py-{self.run_id}"
        with self.docker_container(container, "python:3.13"):
            self.docker_exec(container, "mkdir -p /work")
            self.docker_copy(container, repo_copy / "bootstrap.sh", "/work/bootstrap.sh")
            self.docker_copy(container, repo_copy / "scripts", "/work/scripts")
            self.docker_exec(container, "cd /work && chmod +x ./bootstrap.sh && ./bootstrap.sh --help | sed -n '1,4p' | grep -q 'usage: orchestrate.py bootstrap'")
        return {"status": "help-ok"}

    def test_unmanaged_remove_purge_render_only(self) -> dict[str, str]:
        env_path, _env = self.create_env("unmanaged")
        container = f"audit-unmanaged-{self.run_id}"
        with self.docker_container(container, "ubuntu:24.04"):
            self.docker_exec(container, "mkdir -p /work")
            self.docker_copy(container, INSTALL_SCRIPT, "/work/install.sh")
            self.docker_copy(container, env_path, "/work/deployment.env")
            self.docker_exec(
                container,
                textwrap.dedent(
                    """\
                    set -euo pipefail
                    chmod +x /work/install.sh
                    echo dummy >/etc/nftables.conf
                    if /work/install.sh --role ru-gateway --action remove >/tmp/remove.out 2>/tmp/remove.err; then
                      exit 31
                    fi
                    grep -q "metadata not found" /tmp/remove.err
                    test "$(cat /etc/nftables.conf)" = dummy
                    if /work/install.sh --role ru-gateway --action purge >/tmp/purge.out 2>/tmp/purge.err; then
                      exit 32
                    fi
                    grep -q "metadata not found" /tmp/purge.err
                    test "$(cat /etc/nftables.conf)" = dummy
                    mkdir -p /work/out
                    /work/install.sh --role ru-gateway --env-file /work/deployment.env --render-only --output-dir /work/out/ru >/dev/null
                    test -s /work/out/ru/sing-box.json
                    /work/install.sh --role foreign-exit --env-file /work/deployment.env --render-only --output-dir /work/out/foreign >/dev/null
                    test -s /work/out/foreign/sing-box.json
                    """
                ),
            )
        return {"container": container}

    def test_asset_fail_fast(self) -> dict[str, str]:
        env_path, env = self.create_env(
            "asset-fail-fast",
            {
                "RU_GEOSITE_URL": "http://127.0.0.1:9/geosite-ru.srs",
                "RU_GEOIP_URL": "http://127.0.0.1:9/geoip-ru.srs",
                "FOREIGN_RU_IPV4_LIST_URL": "http://127.0.0.1:9/ru-ipv4.zone",
                "FOREIGN_RU_IPV6_LIST_URL": "http://127.0.0.1:9/ru-ipv6.zone",
            },
        )
        first = self.run_command(
            "asset-fail-fast-first",
            python_cmd() + [str(ORCHESTRATE_SCRIPT), "render-all", str(env_path)],
            expect_code=1,
        )
        if "Не удалось получить обязательные assets" not in (first.stderr + first.stdout):
            raise AuditFailure("Не сработал fail-fast по обязательным assets")
        out_dir = OUT_DIR / env["DEPLOY_NAME"] / "assets"
        ensure_dir(out_dir)
        write_text(out_dir / "geosite-ru.srs", "dummy")
        write_text(out_dir / "geoip-ru.srs", "dummy")
        write_text(out_dir / "ru-ipv4.zone", "203.0.113.0/24")
        write_text(out_dir / "ru-ipv6.zone", "2001:db8::/32")
        second = self.run_command(
            "asset-fail-fast-second",
            python_cmd() + [str(ORCHESTRATE_SCRIPT), "render-all", str(env_path)],
            expect_code=0,
        )
        combined = second.stdout + second.stderr
        if "не удалось обновить, оставляю локальную копию" not in combined:
            raise AuditFailure("Не появился warning о повторном использовании локального cache")
        return {"env_path": str(env_path)}

    def prepare_mock_orchestrate_state(self, action: str) -> tuple[Path, Path]:
        env_path, env = self.create_env(
            f"mock-{action}",
            {"WG_INTERFACE": "wg-test", "RU_PUBLIC_IP": "203.0.113.10", "FOREIGN_PUBLIC_IP": "198.51.100.20"},
        )
        state_dir = ensure_dir(self.work_dir / f"state-{action}")
        state_path = state_dir / f"{env['DEPLOY_NAME']}.json"
        write_text(
            state_path,
            json.dumps(
                {
                    "updated_at": "2026-04-11T00:00:00Z",
                    orchestrate.ROLE_RU: {
                        "public_ip": "203.0.113.10",
                        "ssh_host": "ru.example",
                        "ssh_port": "22",
                        "ssh_user": "root",
                        "identity_path": "",
                    },
                    orchestrate.ROLE_FOREIGN: {
                        "public_ip": "198.51.100.20",
                        "ssh_host": "foreign.example",
                        "ssh_port": "22",
                        "ssh_user": "root",
                        "identity_path": "",
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
        )
        return env_path, state_path

    def write_mock_ssh_scripts(self, base_dir: Path, *, allow_foreign: bool = False) -> tuple[Path, Path]:
        fakebin = ensure_dir(base_dir / "fakebin")
        ssh_script = textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            printf 'ssh|%s\\n' "$*" >> /work/calls.log
            host=""
            for arg in "$@"; do
              case "$arg" in
                *@*.*)
                  host="${arg#*@}"
                  break
                  ;;
              esac
            done
            if [[ "$host" == "ru.example" ]]; then
              cat <<'EOF'
            login_user=root
            is_root=1
            has_sudo=1
            os_id=ubuntu
            os_version=24.04
            hostname=ru-host
            default_iface=eth0
            installed=1
            deployment_name=mock
            role=ru-gateway
            installed_at=2026-04-11T00:00:00Z
            sing_box=active
            nftables=active
            wireguard=active
            sync_timer=active
            EOF
              exit 0
            fi
            if [[ "$host" == "foreign.example" ]]; then
            """
        )
        if allow_foreign:
            ssh_script += textwrap.dedent(
                """\
                  cat <<'EOF'
                login_user=root
                is_root=1
                has_sudo=1
                os_id=ubuntu
                os_version=24.04
                hostname=foreign-host
                default_iface=eth0
                installed=1
                deployment_name=mock
                role=foreign-exit
                installed_at=2026-04-11T00:00:00Z
                sing_box=inactive
                nftables=active
                wireguard=active
                sync_timer=active
                EOF
                  exit 0
                """
            )
        else:
            ssh_script += "  exit 93\n"
        ssh_script += textwrap.dedent(
            """\
            fi
            echo "unexpected host: ${host:-missing}" >&2
            exit 92
            """
        )
        scp_script = textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            printf 'scp|%s\\n' "$*" >> /work/calls.log
            exit 0
            """
        )
        ssh_path = fakebin / "ssh"
        scp_path = fakebin / "scp"
        write_text(ssh_path, ssh_script)
        write_text(scp_path, scp_script)
        ssh_path.chmod(0o755)
        scp_path.chmod(0o755)
        return ssh_path, scp_path

    def test_status_readonly_role(self) -> dict[str, str]:
        env_path, state_path = self.prepare_mock_orchestrate_state("status")
        temp_repo = ensure_dir(self.work_dir / "mock-status")
        deploy_dir = ensure_dir(temp_repo / "deployments")
        state_dir = ensure_dir(temp_repo / "state")
        shutil.copy2(env_path, deploy_dir / env_path.name)
        shutil.copy2(state_path, state_dir / state_path.name)
        self.write_mock_ssh_scripts(temp_repo)
        container = f"audit-status-{self.run_id}"
        with self.docker_container(container, "python:3.13"):
            self.docker_exec(container, "mkdir -p /work/scripts /work/deployments /work/state /work/fakebin")
            self.docker_copy(container, ORCHESTRATE_SCRIPT, "/work/scripts/orchestrate.py")
            self.docker_copy(container, deploy_dir / env_path.name, f"/work/deployments/{env_path.name}")
            self.docker_copy(container, state_dir / state_path.name, f"/work/state/{state_path.name}")
            self.docker_copy(container, temp_repo / "fakebin" / "ssh", "/work/fakebin/ssh")
            self.docker_copy(container, temp_repo / "fakebin" / "scp", "/work/fakebin/scp")
            self.docker_exec(
                container,
                textwrap.dedent(
                    f"""\
                    set -euo pipefail
                    chmod +x /work/fakebin/ssh /work/fakebin/scp
                    : > /work/calls.log
                    env_before=$(stat -c %Y /work/deployments/{env_path.name})
                    state_before=$(stat -c %Y /work/state/{state_path.name})
                    PATH=/work/fakebin:$PATH python3 /work/scripts/orchestrate.py status --deployment {env_path.stem} --role ru-gateway >/work/status.out
                    env_after=$(stat -c %Y /work/deployments/{env_path.name})
                    state_after=$(stat -c %Y /work/state/{state_path.name})
                    test "$env_before" = "$env_after"
                    test "$state_before" = "$state_after"
                    grep -q "ru.example" /work/calls.log
                    if grep -q "foreign.example" /work/calls.log; then
                      exit 41
                    fi
                    grep -q "wg-quick@wg-test" /work/calls.log
                    """
                ),
            )
        return {"deployment": env_path.stem}

    def test_remote_action_role(self, action: str) -> dict[str, str]:
        env_path, state_path = self.prepare_mock_orchestrate_state(action)
        temp_repo = ensure_dir(self.work_dir / f"mock-{action}")
        deploy_dir = ensure_dir(temp_repo / "deployments")
        state_dir = ensure_dir(temp_repo / "state")
        shutil.copy2(env_path, deploy_dir / env_path.name)
        shutil.copy2(state_path, state_dir / state_path.name)
        self.write_mock_ssh_scripts(temp_repo)
        driver = textwrap.dedent(
            f"""\
            import argparse
            import sys

            sys.path.insert(0, "/work/scripts")
            import orchestrate as orch

            answers = iter([True, False])

            def fake_prompt_yes_no(label: str, default: bool = True) -> bool:
                return next(answers)

            orch.prompt_yes_no = fake_prompt_yes_no
            ns = argparse.Namespace(deployment="{env_path.stem}", role="ru-gateway", action="{action}")
            rc = orch.cmd_remote_action(ns)
            print(f"rc={{rc}}")
            """
        )
        driver_path = temp_repo / "driver.py"
        write_text(driver_path, driver)
        container = f"audit-{action}-{self.run_id}"
        with self.docker_container(container, "python:3.13"):
            self.docker_exec(container, "mkdir -p /work/scripts /work/deployments /work/state /work/fakebin")
            self.docker_copy(container, ORCHESTRATE_SCRIPT, "/work/scripts/orchestrate.py")
            self.docker_copy(container, deploy_dir / env_path.name, f"/work/deployments/{env_path.name}")
            self.docker_copy(container, state_dir / state_path.name, f"/work/state/{state_path.name}")
            self.docker_copy(container, temp_repo / "fakebin" / "ssh", "/work/fakebin/ssh")
            self.docker_copy(container, temp_repo / "fakebin" / "scp", "/work/fakebin/scp")
            self.docker_copy(container, driver_path, "/work/driver.py")
            self.docker_exec(
                container,
                textwrap.dedent(
                    """\
                    set -euo pipefail
                    chmod +x /work/fakebin/ssh /work/fakebin/scp
                    : > /work/calls.log
                    PATH=/work/fakebin:$PATH python3 /work/driver.py >/work/driver.out
                    grep -q "Остановлено пользователем" /work/driver.out
                    grep -q "rc=0" /work/driver.out
                    grep -q "ru.example" /work/calls.log
                    if grep -q "foreign.example" /work/calls.log; then
                      exit 42
                    fi
                    grep -q "wg-quick@wg-test" /work/calls.log
                    """
                ),
            )
        return {"action": action, "deployment": env_path.stem}

    def build_lab_client_config(self, env: dict[str, str]) -> str:
        payload = {
            "log": {"level": "info", "timestamp": True},
            "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "0.0.0.0", "listen_port": 1080}],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "ru-gateway",
                    "server": LAB_IPS["ru"],
                    "server_port": int(env["RU_LISTEN_PORT"]),
                    "uuid": env["CLIENT_UUID"],
                    "flow": "",
                },
                {"type": "block", "tag": "block"},
            ],
            "route": {
                "auto_detect_interface": True,
                "rules": [{"ip_version": 6, "action": "route", "outbound": "block"}],
                "final": "ru-gateway",
            },
        }
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"

    def build_lab_ru_config(self, env: dict[str, str]) -> str:
        payload = json.loads(orchestrate.render_ru_singbox(env))
        payload["dns"]["servers"] = [
            {"type": "udp", "tag": "dns-ru-direct", "server": LAB_IPS["dns"], "server_port": 53},
            {"type": "udp", "tag": "dns-global", "server": LAB_IPS["dns"], "server_port": 53},
        ]
        payload["dns"]["final"] = "dns-global"
        payload["inbounds"][0]["listen"] = "0.0.0.0"
        payload["inbounds"][0]["listen_port"] = int(env["RU_LISTEN_PORT"])
        payload["inbounds"][0].pop("tls", None)
        payload["inbounds"][0]["users"][0]["flow"] = ""
        for outbound in payload.get("outbounds", []):
            if outbound.get("tag") == "to-foreign":
                outbound["bind_interface"] = env["WG_INTERFACE"]
                outbound.pop("routing_mark", None)
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"

    def build_lab_web_server(self, name: str) -> str:
        return textwrap.dedent(
            f"""\
            import http.server
            import socketserver

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    body = f"server={name}\\nsource={{self.client_address[0]}}\\npath={{self.path}}\\n".encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, fmt, *args):
                    return

            with socketserver.TCPServer(("0.0.0.0", 80), Handler) as server:
                server.serve_forever()
            """
        )

    def build_lab_dnsmasq(self) -> str:
        return textwrap.dedent(
            f"""\
            no-daemon
            log-queries
            log-facility=-
            port=53
            bind-interfaces
            address=/ya.ru/{LAB_IPS["ru_web"]}
            address=/example.com/{LAB_IPS["global_web"]}
            address=/blocked-ru.example/{LAB_IPS["ru_web"]}
            """
        )

    def docker_network_connect(self, network: str, container: str, ip: str) -> None:
        self.docker(f"network-connect-{network}-{container}", ["network", "connect", "--ip", ip, network, container])

    def lab_curl(
        self,
        container: str,
        url: str,
        *,
        expect_codes: set[int] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        host = url.split("://", 1)[-1].split("/", 1)[0].replace(":", "_")
        if expect_codes is None:
            expect_codes = {0}
        return self.docker(
            f"curl-{container}-{host}",
            ["exec", container, "bash", "-lc", f"curl --silent --show-error --fail --max-time 10 --socks5-hostname 127.0.0.1:1080 {url}"],
            expect_code=0,
            expected_codes=expect_codes,
        )

    def test_lab_dataplane(self) -> dict[str, str]:
        self.cleanup_stale_lab_resources()
        env_path, env = self.create_env(
            "lab",
            {
                "RU_PUBLIC_IP": LAB_IPS["ru"],
                "FOREIGN_PUBLIC_IP": LAB_IPS["foreign"],
                "RU_LISTEN_PORT": "8443",
                "WAN_INTERFACE": "eth1",
                "WG_INTERFACE": "wg0",
            },
        )
        out_dir = OUT_DIR / env["DEPLOY_NAME"]
        self.seed_foreign_block_cache(env["DEPLOY_NAME"])
        self.run_command("lab-render-all", python_cmd() + [str(ORCHESTRATE_SCRIPT), "render-all", str(env_path)])
        env = orchestrate.load_env_file(env_path)

        front = f"audit-front-{self.run_id}"
        ru_lan = f"audit-ru-{self.run_id}"
        global_lan = f"audit-global-{self.run_id}"

        with self.docker_network(front, LAB_FRONT_SUBNET, LAB_FRONT_GATEWAY), self.docker_network(ru_lan, LAB_RU_SUBNET, LAB_RU_GATEWAY), self.docker_network(global_lan, LAB_GLOBAL_SUBNET, LAB_GLOBAL_GATEWAY):
            with self.docker_container(f"ru-{self.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["ru"]) as ru_container, \
                self.docker_container(f"foreign-{self.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["foreign"]) as foreign_container, \
                self.docker_container(f"client-{self.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["client"]) as client_container, \
                self.docker_container(f"dns-{self.run_id}", AUDIT_IMAGE, privileged=True, network=front, ip=LAB_IPS["dns"]) as dns_container, \
                self.docker_container(f"ruweb-{self.run_id}", AUDIT_IMAGE, privileged=True, network=ru_lan, ip=LAB_IPS["ru_web"]) as ru_web_container, \
                self.docker_container(f"globalweb-{self.run_id}", AUDIT_IMAGE, privileged=True, network=global_lan, ip=LAB_IPS["global_web"]) as global_web_container:
                self.docker_network_connect(ru_lan, ru_container, LAB_IPS["ru_lan"])
                self.docker_network_connect(global_lan, foreign_container, LAB_IPS["foreign_wan"])

                ru_wg = self.work_dir / "lab" / "wg0-ru.conf"
                foreign_wg = self.work_dir / "lab" / "wg0-foreign.conf"
                ru_nft = self.work_dir / "lab" / "ru.nft"
                foreign_nft = self.work_dir / "lab" / "foreign.nft"
                ru_cfg = self.work_dir / "lab" / "ru-singbox.json"
                client_cfg = self.work_dir / "lab" / "client-singbox.json"
                ru_assets = self.work_dir / "lab" / "ru-assets"
                dns_conf = self.work_dir / "lab" / "dnsmasq.conf"
                ru_web = self.work_dir / "lab" / "ru-web.py"
                global_web = self.work_dir / "lab" / "global-web.py"
                ensure_dir(ru_assets)
                shutil.copy2(out_dir / "assets" / "geosite-ru.srs", ru_assets / "geosite-ru.srs")
                shutil.copy2(out_dir / "assets" / "geoip-ru.srs", ru_assets / "geoip-ru.srs")
                write_text(ru_wg, orchestrate.render_ru_wg(env))
                write_text(foreign_wg, orchestrate.render_foreign_wg(env))
                write_text(ru_nft, orchestrate.render_ru_firewall_nftables(env))
                write_text(foreign_nft, orchestrate.render_foreign_nftables(env, "eth1"))
                write_text(ru_cfg, self.build_lab_ru_config(env))
                write_text(client_cfg, self.build_lab_client_config(env))
                write_text(dns_conf, self.build_lab_dnsmasq())
                write_text(ru_web, self.build_lab_web_server("ru-web"))
                write_text(global_web, self.build_lab_web_server("global-web"))

                for container, local, remote in [
                    (ru_container, ru_wg, "/opt/wg0.conf"),
                    (foreign_container, foreign_wg, "/opt/wg0.conf"),
                    (ru_container, ru_nft, "/opt/nftables.conf"),
                    (foreign_container, foreign_nft, "/opt/nftables.conf"),
                    (ru_container, ru_cfg, "/opt/ru-singbox.json"),
                    (client_container, client_cfg, "/opt/client-singbox.json"),
                    (dns_container, dns_conf, "/opt/dnsmasq.conf"),
                    (ru_web_container, ru_web, "/opt/web.py"),
                    (global_web_container, global_web, "/opt/web.py"),
                ]:
                    self.docker_copy(container, local, remote)
                self.docker_exec(ru_container, "mkdir -p /var/lib/vpn-stack/rules")
                for asset_name in ("geosite-ru.srs", "geoip-ru.srs"):
                    self.docker_copy(ru_container, ru_assets / asset_name, f"/var/lib/vpn-stack/rules/{asset_name}")

                self.docker_exec(dns_container, "nohup dnsmasq --conf-file=/opt/dnsmasq.conf >/opt/dns.log 2>&1 &")
                self.docker_exec(ru_web_container, "nohup python3 /opt/web.py >/opt/web.log 2>&1 &")
                self.docker_exec(global_web_container, "nohup python3 /opt/web.py >/opt/web.log 2>&1 &")
                self.docker_exec(foreign_container, "sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 >/dev/null")
                self.docker_exec(ru_container, "sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null")
                self.docker_exec(foreign_container, "wg-quick up /opt/wg0.conf")
                self.docker_exec(ru_container, "wg-quick up /opt/wg0.conf")
                self.docker_exec(foreign_container, "nft -f /opt/nftables.conf && nft add element inet vpnstack ru_ipv4 { 203.0.113.0/24 }")
                self.docker_exec(ru_container, "nft -f /opt/nftables.conf")
                self.docker_exec(ru_container, "nohup sing-box run -c /opt/ru-singbox.json >/opt/ru-singbox.log 2>&1 &")
                self.docker_exec(client_container, "nohup sing-box run -c /opt/client-singbox.json >/opt/client-singbox.log 2>&1 &")
                self.docker_exec(client_container, "for i in $(seq 1 20); do nc -z 127.0.0.1 1080 && exit 0; sleep 1; done; exit 1")

                ru_resp = self.lab_curl(client_container, "http://ya.ru/").stdout
                if "server=ru-web" not in ru_resp or f"source={LAB_IPS['ru_lan']}" not in ru_resp:
                    raise AuditFailure(f"RU dataplane не подтверждён:\n{ru_resp}")

                global_resp = self.lab_curl(client_container, "http://example.com/").stdout
                if "server=global-web" not in global_resp or f"source={LAB_IPS['foreign_wan']}" not in global_resp:
                    raise AuditFailure(f"Global dataplane через foreign не подтверждён:\n{global_resp}")

                blocked = self.lab_curl(client_container, "http://blocked-ru.example/", expect_codes={7, 22, 28, 52, 56, 97})
                if blocked.returncode == 0:
                    raise AuditFailure("foreign RU-block не сработал для blocked-ru.example")

                self.docker("stop-foreign", ["stop", foreign_container])

                failed_global = self.lab_curl(client_container, "http://example.com/", expect_codes={7, 22, 28, 52, 56, 97})
                if failed_global.returncode == 0:
                    raise AuditFailure("При падении foreign global трафик не упал fail-closed")

                ru_after = self.lab_curl(client_container, "http://ya.ru/").stdout
                if "server=ru-web" not in ru_after or f"source={LAB_IPS['ru_lan']}" not in ru_after:
                    raise AuditFailure("После падения foreign RU трафик перестал ходить напрямую")
        return {"lab_env": str(env_path)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Локальный аудит и Docker regression/lab для vpn-installer.")
    parser.add_argument("mode", choices=["quick", "docker", "lab", "all"], help="Какой контур проверок запускать.")
    parser.add_argument("--json", action="store_true", help="Печатать итоговую summary в JSON.")
    parser.add_argument("--keep-docker", action="store_true", help="Не удалять Docker-контейнеры и сети после тестов.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    runner = AuditRunner(args.mode, keep_docker=args.keep_docker, json_output=args.json)
    return runner.run()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.", file=sys.stderr)
        raise SystemExit(130)
