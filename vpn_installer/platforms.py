from __future__ import annotations

import json
import os
import platform as stdlib_platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence


PLATFORM_SCHEMA_VERSION = 1
SUPPORTED_ARCHITECTURES = frozenset({"x86_64"})

BASE_REQUIREMENTS = (
    "ca-certificates",
    "download-client",
    "filesystem-tools",
    "iproute-tools",
    "kernel-module-tools",
    "log-rotation",
    "nftables",
    "python-runtime",
    "dns-cache",
    "system-tools",
    "sysctl-tools",
    "tar-extractor",
)
PUBLIC_FRONT_REQUIREMENTS = ("zip-extractor",)
INTERSERVER_REQUIREMENTS = (
    "icmp-tools",
    "throughput-tools",
    "wireguard-tools",
)

DEB_PACKAGE_MAP = {
    "ca-certificates": "ca-certificates",
    "download-client": "curl",
    "filesystem-tools": "e2fsprogs",
    "iproute-tools": "iproute2",
    "kernel-module-tools": "kmod",
    "log-rotation": "logrotate",
    "nftables": "nftables",
    "python-runtime": "python3",
    "dns-cache": "dnsmasq-base",
    "system-tools": "util-linux",
    "sysctl-tools": "procps",
    "tar-extractor": "tar",
    "zip-extractor": "unzip",
    "icmp-tools": "iputils-ping",
    "throughput-tools": "iperf3",
    "wireguard-tools": "wireguard-tools",
}

RPM_PACKAGE_MAP = {
    "ca-certificates": "ca-certificates",
    "download-client": "curl",
    "filesystem-tools": "e2fsprogs",
    "iproute-tools": "iproute",
    "kernel-module-tools": "kmod",
    "log-rotation": "logrotate",
    "nftables": "nftables",
    "python-runtime": "python3",
    "dns-cache": "dnsmasq",
    "system-tools": "util-linux",
    "sysctl-tools": "procps-ng",
    "tar-extractor": "tar",
    "zip-extractor": "unzip",
    "icmp-tools": "iputils",
    "throughput-tools": "iperf3",
    "wireguard-tools": "wireguard-tools",
    "selinux-policy-tools": "policycoreutils-python-utils",
}
RPM_EL9_PACKAGE_MAP = {**RPM_PACKAGE_MAP, "download-client": "curl-minimal"}

_TRANSIENT_PACKAGE_NETWORK_ERROR = re.compile(
    r"(?:Curl error \((?:5|6|7|28|35)\)|mirrorlist|timed? out|temporary failure|could not resolve)",
    re.IGNORECASE,
)

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]*$")


class PlatformError(ValueError):
    pass


@dataclass(frozen=True)
class HostFacts:
    os_id: str
    os_version: str
    architecture: str
    id_like: tuple[str, ...] = ()
    init_system: str = ""
    security_mode: str = "unknown"
    host_firewall: str = "none"

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "HostFacts":
        raw_like = value.get("os_id_like", value.get("id_like", ()))
        if isinstance(raw_like, str):
            id_like = tuple(part.lower() for part in raw_like.replace(",", " ").split() if part)
        elif isinstance(raw_like, (list, tuple)):
            id_like = tuple(str(part).strip().lower() for part in raw_like if str(part).strip())
        else:
            id_like = ()
        return cls(
            os_id=str(value.get("os_id", "")).strip().lower(),
            os_version=str(value.get("os_version", "")).strip(),
            architecture=normalize_architecture(str(value.get("architecture", "")).strip()),
            id_like=id_like,
            init_system=str(value.get("init_system", "")).strip().lower(),
            security_mode=str(value.get("security_mode", "unknown")).strip().lower() or "unknown",
            host_firewall=str(value.get("host_firewall", "none")).strip().lower() or "none",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "os_id": self.os_id,
            "os_version": self.os_version,
            "architecture": self.architecture,
            "id_like": list(self.id_like),
            "init_system": self.init_system,
            "security_mode": self.security_mode,
            "host_firewall": self.host_firewall,
        }


@dataclass(frozen=True)
class PlatformSpec:
    os_id: str
    os_version: str
    family: str
    architecture: str
    package_provider: str
    init_system: str
    resolver_provider: str
    firewall_provider: str
    security_module: str

    @property
    def package_map(self) -> Mapping[str, str]:
        if self.family == "deb":
            return DEB_PACKAGE_MAP
        if self.family == "rpm":
            if self.os_id in {"almalinux", "rocky"} and self.os_version.split(".", 1)[0] == "9":
                return RPM_EL9_PACKAGE_MAP
            return RPM_PACKAGE_MAP
        raise PlatformError(f"unsupported platform family: {self.family}")

    def resolve_packages(self, requirements: Iterable[str]) -> list[str]:
        requested = tuple(dict.fromkeys(str(item) for item in requirements))
        unknown = sorted(set(requested) - set(self.package_map))
        if unknown:
            raise PlatformError(f"unknown logical package requirements: {', '.join(unknown)}")
        return sorted({self.package_map[item] for item in requested})

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": PLATFORM_SCHEMA_VERSION,
            "os_id": self.os_id,
            "os_version": self.os_version,
            "family": self.family,
            "architecture": self.architecture,
            "package_provider": self.package_provider,
            "init_system": self.init_system,
            "resolver_provider": self.resolver_provider,
            "firewall_provider": self.firewall_provider,
            "security_module": self.security_module,
        }

    @classmethod
    def from_dict(cls, value: object) -> "PlatformSpec":
        if not isinstance(value, Mapping):
            raise PlatformError("platform descriptor must be an object")
        expected_keys = {
            "schema_version",
            "os_id",
            "os_version",
            "family",
            "architecture",
            "package_provider",
            "init_system",
            "resolver_provider",
            "firewall_provider",
            "security_module",
        }
        if set(value) != expected_keys:
            raise PlatformError(
                f"platform descriptor fields must be exact; missing={sorted(expected_keys - set(value))}, "
                f"unknown={sorted(set(value) - expected_keys)}"
            )
        if value.get("schema_version") != PLATFORM_SCHEMA_VERSION:
            raise PlatformError(f"unsupported platform schema: {value.get('schema_version')!r}")
        declared = cls(
            os_id=str(value["os_id"]),
            os_version=str(value["os_version"]),
            family=str(value["family"]),
            architecture=normalize_architecture(str(value["architecture"])),
            package_provider=str(value["package_provider"]),
            init_system=str(value["init_system"]),
            resolver_provider=str(value["resolver_provider"]),
            firewall_provider=str(value["firewall_provider"]),
            security_module=str(value["security_module"]),
        )
        canonical = resolve_platform(
            HostFacts(declared.os_id, declared.os_version, declared.architecture, init_system="systemd")
        )
        if declared != canonical:
            raise PlatformError("platform descriptor differs from the supported platform catalog")
        return declared


@dataclass(frozen=True)
class _PlatformDefinition:
    versions: frozenset[str]
    family: str
    package_provider: str
    security_module: str
    major_versions: bool = False

    def accepts(self, version: str) -> bool:
        candidate = version.split(".", 1)[0] if self.major_versions else version
        return candidate in self.versions


SUPPORTED_PLATFORMS: Mapping[str, _PlatformDefinition] = {
    "ubuntu": _PlatformDefinition(frozenset({"22.04", "24.04", "26.04"}), "deb", "apt", "apparmor"),
    "debian": _PlatformDefinition(frozenset({"12", "13"}), "deb", "apt", "apparmor"),
    "almalinux": _PlatformDefinition(frozenset({"9", "10"}), "rpm", "dnf4", "selinux", major_versions=True),
    "rocky": _PlatformDefinition(frozenset({"9", "10"}), "rpm", "dnf4", "selinux", major_versions=True),
    "fedora": _PlatformDefinition(frozenset({"43", "44"}), "rpm", "dnf5", "selinux"),
}


def normalize_architecture(value: str) -> str:
    normalized = value.strip().lower()
    return {"amd64": "x86_64", "x64": "x86_64"}.get(normalized, normalized)


def resolve_platform(facts: HostFacts) -> PlatformSpec:
    definition = SUPPORTED_PLATFORMS.get(facts.os_id)
    if definition is None or not definition.accepts(facts.os_version):
        supported = ", ".join(
            f"{name} {'/'.join(sorted(item.versions))}" for name, item in SUPPORTED_PLATFORMS.items()
        )
        observed = f"{facts.os_id or '<unknown>'} {facts.os_version or '<unknown>'}"
        raise PlatformError(f"unsupported server platform {observed}; supported: {supported}")
    architecture = normalize_architecture(facts.architecture)
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise PlatformError(
            f"unsupported server architecture {architecture or '<unknown>'}; supported: "
            f"{', '.join(sorted(SUPPORTED_ARCHITECTURES))}"
        )
    if facts.init_system != "systemd":
        raise PlatformError(f"unsupported init system {facts.init_system or '<unknown>'}; systemd is required")
    return PlatformSpec(
        os_id=facts.os_id,
        os_version=facts.os_version,
        family=definition.family,
        architecture=architecture,
        package_provider=definition.package_provider,
        init_system="systemd",
        resolver_provider="dnsmasq",
        firewall_provider="nftables",
        security_module=definition.security_module,
    )


def default_build_platform() -> PlatformSpec:
    return resolve_platform(HostFacts("ubuntu", "24.04", "x86_64", init_system="systemd"))


def _os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PlatformError(f"cannot read {path}: {exc}") from exc
    for line in lines:
        key, separator, raw = line.partition("=")
        if not separator:
            continue
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def _init_system() -> str:
    if Path("/run/systemd/system").is_dir():
        return "systemd"
    try:
        command = Path("/proc/1/comm").read_text(encoding="utf-8").strip()
    except OSError:
        command = ""
    return "systemd" if command == "systemd" else command or "unknown"


def _security_mode() -> str:
    enforce = Path("/sys/fs/selinux/enforce")
    try:
        return "selinux-enforcing" if enforce.read_text(encoding="utf-8").strip() == "1" else "selinux-permissive"
    except OSError:
        return "apparmor" if Path("/sys/module/apparmor/parameters/enabled").exists() else "none"


def _host_firewall() -> str:
    try:
        if shutil.which("firewall-cmd"):
            completed = subprocess.run(
                ["systemctl", "is-active", "firewalld.service"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
            state = completed.stdout.strip().lower()
            if completed.returncode == 0:
                return "firewalld"
            explicitly_inactive = (
                completed.returncode == 3 and state in {"inactive", "failed"}
            ) or (
                completed.returncode == 4 and state in {"inactive", "unknown"}
            )
            if not explicitly_inactive:
                return "unknown"
        if shutil.which("ufw"):
            completed = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
            if completed.returncode != 0:
                return "unknown"
            status = completed.stdout.strip().lower()
            if status.startswith("status: active"):
                return "ufw"
            if not status.startswith("status: inactive"):
                return "unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "unknown"
    return "none"


def detect_host_facts(path: Path = Path("/etc/os-release")) -> HostFacts:
    release = _os_release(path)
    return HostFacts(
        os_id=release.get("ID", "").lower(),
        os_version=release.get("VERSION_ID", ""),
        architecture=normalize_architecture(stdlib_platform.machine()),
        id_like=tuple(part.lower() for part in release.get("ID_LIKE", "").split() if part),
        init_system=_init_system(),
        security_mode=_security_mode(),
        host_firewall=_host_firewall(),
    )


def current_platform() -> PlatformSpec:
    return resolve_platform(detect_host_facts())


def install_platform(facts: HostFacts | None = None) -> PlatformSpec:
    observed = facts or detect_host_facts()
    spec = resolve_platform(observed)
    if observed.host_firewall != "none":
        raise PlatformError(
            f"active or unknown host firewall {observed.host_firewall!r}; "
            "disable ufw/firewalld and verify nftables ownership before installation"
        )
    return spec


def require_host_matches(expected: PlatformSpec, facts: HostFacts | None = None) -> None:
    actual = install_platform(facts)
    if actual != expected:
        raise PlatformError(
            "rendered platform does not match this host: "
            f"expected={json.dumps(expected.to_dict(), sort_keys=True)}, "
            f"actual={json.dumps(actual.to_dict(), sort_keys=True)}"
        )


def requirements_for(
    *,
    public_front: bool,
    interserver: bool,
    platform: PlatformSpec | None = None,
) -> tuple[str, ...]:
    requirements = list(BASE_REQUIREMENTS)
    if public_front:
        requirements.extend(PUBLIC_FRONT_REQUIREMENTS)
    if interserver:
        requirements.extend(INTERSERVER_REQUIREMENTS)
    if platform is not None and platform.security_module == "selinux":
        requirements.append("selinux-policy-tools")
    return tuple(dict.fromkeys(requirements))


RunCommand = Callable[..., subprocess.CompletedProcess[str]]


def _run_checked(
    command: Sequence[str],
    *,
    runner: RunCommand = subprocess.run,
    env: Mapping[str, str] | None = None,
    allowed_codes: frozenset[int] = frozenset({0}),
    timeout: int = 900,
    transient_retries: int = 0,
) -> subprocess.CompletedProcess[str]:
    for attempt in range(transient_retries + 1):
        completed = runner(
            list(command),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=dict(env) if env is not None else None,
        )
        if completed.returncode in allowed_codes:
            return completed
        detail = (completed.stderr or completed.stdout).strip()
        if attempt < transient_retries and _TRANSIENT_PACKAGE_NETWORK_ERROR.search(detail):
            time.sleep(2)
            continue
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}: {detail[:500]}")
    raise AssertionError("unreachable package command state")


def _validate_packages(packages: Iterable[str]) -> list[str]:
    values = sorted(set(packages))
    if not all(_PACKAGE_NAME.fullmatch(value) for value in values):
        raise PlatformError("package plan contains an unsafe package name")
    return values


def install_packages(
    spec: PlatformSpec,
    packages: Iterable[str],
    *,
    runner: RunCommand = subprocess.run,
) -> None:
    values = _validate_packages(packages)
    if not values:
        return
    if spec.package_provider == "apt":
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        _run_checked(["apt-get", "update"], runner=runner, env=env)
        _run_checked(
            ["apt-get", "install", "-y", "--no-install-recommends", *values],
            runner=runner,
            env=env,
        )
        _run_checked(["apt-get", "clean"], runner=runner, env=env)
        return
    if spec.package_provider in {"dnf4", "dnf5"}:
        executable = "dnf5" if spec.package_provider == "dnf5" else "dnf"
        _run_checked(
            [executable, "-y", "--setopt=install_weak_deps=False", "install", *values],
            runner=runner,
            transient_retries=1,
        )
        _run_checked([executable, "clean", "all"], runner=runner)
        return
    raise PlatformError(f"unsupported package provider: {spec.package_provider}")


def prepare_host_platform(
    spec: PlatformSpec,
    release_dir: Path,
    *,
    runner: RunCommand = subprocess.run,
) -> None:
    require_host_matches(spec)
    if spec.security_module != "selinux":
        return

    from .dns_cache import DNS_CACHE_PORT

    contexts = (
        ("bin_t", "/etc/vpn-stack/releases(/.*)?/bin(/.*)?"),
        ("dnsmasq_etc_t", r"/etc/vpn-stack/releases(/.*)?/dnsmasq-vpn-stack\.conf"),
    )
    # Validate every conflict before the first host-policy mutation.
    port_listing = _run_checked(["semanage", "port", "-l"], runner=runner, timeout=30)
    owners = _selinux_port_owners(port_listing.stdout, DNS_CACHE_PORT)
    context_listing = _run_checked(
        ["semanage", "fcontext", "-l", "-C"], runner=runner, timeout=30,
        env={**os.environ, "LC_ALL": "C"},
    )
    patterns = {pattern for _context, pattern in contexts}
    context_owners: dict[str, str] = {}
    for line in context_listing.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] not in patterns:
            continue
        if len(parts) != 4 or parts[1:3] != ["all", "files"] or len(parts[-1].split(":")) < 4 or parts[0] in context_owners:
            raise PlatformError(f"ambiguous SELinux file context: {parts[0]}")
        context_owners[parts[0]] = parts[-1].split(":")[2]
    operations: list[tuple[list[str], list[str]]] = []
    for context, pattern in contexts:
        owner = context_owners.get(pattern)
        if owner is not None and owner != context:
            raise PlatformError(f"SELinux file context {pattern} is owned by {owner}; refusing to reassign it")
        if owner is None:
            operations.append((["semanage", "fcontext", "-a", "-t", context, pattern], ["semanage", "fcontext", "-d", pattern]))
    for protocol in ("tcp", "udp"):
        owner = owners.get(protocol)
        if owner is not None and owner != "dns_port_t":
            raise PlatformError(
                f"SELinux {protocol}/{DNS_CACHE_PORT} is already owned by {owner}; refusing to reassign it"
            )
        if owner is None:
            operations.append((
                ["semanage", "port", "-a", "-t", "dns_port_t", "-p", protocol, str(DNS_CACHE_PORT)],
                ["semanage", "port", "-d", "-p", protocol, str(DNS_CACHE_PORT)],
            ))
    applied: list[list[str]] = []
    try:
        for command, undo in operations:
            _run_checked(command, runner=runner, timeout=30)
            applied.append(undo)
        _run_checked([
            "restorecon",
            "-RF",
            str(release_dir / "bin"),
            str(release_dir / "dnsmasq-vpn-stack.conf"),
        ], runner=runner, timeout=60)
    except Exception as exc:
        failures = []
        for command in reversed(applied):
            try:
                _run_checked(command, runner=runner, timeout=30)
            except Exception as rollback_error:
                failures.append(str(rollback_error))
        if failures:
            raise PlatformError(f"SELinux preparation failed: {exc}; cleanup incomplete: {'; '.join(failures)}") from exc
        raise


def _selinux_port_owners(output: str, port: int) -> dict[str, str]:
    owners: dict[str, str] = {}
    for line in output.splitlines():
        match = re.match(r"^(\S+)\s+(tcp|udp)\s+(.+)$", line.strip())
        if match is None:
            continue
        context, protocol, raw_ranges = match.groups()
        for raw_range in raw_ranges.split(","):
            bounds = raw_range.strip().split("-", 1)
            if not all(value.strip().isdigit() for value in bounds):
                continue
            start = int(bounds[0])
            end = int(bounds[-1])
            if start <= port <= end:
                existing = owners.setdefault(protocol, context)
                if existing != context:
                    raise PlatformError(f"SELinux {protocol}/{port} has multiple owners")
    return owners


def _update_lines(output: str) -> list[str]:
    return [
        line
        for line in output.splitlines()
        if line.strip() and not line.startswith(("Listing", "Last metadata", "Obsoleting", "Security:"))
    ]


def maintenance_snapshot(
    spec: PlatformSpec,
    *,
    runner: RunCommand = subprocess.run,
) -> dict[str, object]:
    if spec.package_provider == "apt":
        result = _run_checked(["apt", "list", "--upgradable"], runner=runner, timeout=30)
        lines = [line for line in _update_lines(result.stdout) if "/" in line]
        return {
            "provider": "apt",
            "upgradable": len(lines),
            "security_upgradable": sum("security" in line.lower() for line in lines),
            "reboot_required": Path("/var/run/reboot-required").exists(),
        }
    executable = "dnf5" if spec.package_provider == "dnf5" else "dnf"
    result = _run_checked(
        [executable, "-q", "check-upgrade"],
        runner=runner,
        allowed_codes=frozenset({0, 100}),
        timeout=60,
    )
    lines = [line for line in _update_lines(result.stdout) if len(line.split()) >= 3]
    security = _run_checked(
        [executable, "-q", "updateinfo", "list", "--updates", "--security"],
        runner=runner,
        allowed_codes=frozenset({0, 100}),
        timeout=60,
    )
    security_lines = [line for line in _update_lines(security.stdout) if len(line.split()) >= 3]
    return {
        "provider": spec.package_provider,
        "upgradable": len(lines),
        "security_upgradable": len(security_lines),
        "reboot_required": None,
    }


def apply_updates(
    spec: PlatformSpec,
    *,
    runner: RunCommand = subprocess.run,
) -> None:
    if spec.package_provider == "apt":
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        _run_checked(["apt-get", "update"], runner=runner, env=env)
        _run_checked(
            ["apt-get", "-y", "--with-new-pkgs", "upgrade"],
            runner=runner,
            env=env,
        )
        return
    executable = "dnf5" if spec.package_provider == "dnf5" else "dnf"
    _run_checked([executable, "-y", "upgrade", "--refresh"], runner=runner)
