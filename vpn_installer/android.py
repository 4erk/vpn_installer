from __future__ import annotations

import os
import re
from pathlib import Path

from .common import OUT_DIR, command_exists, ensure_directories, print_header, run_command, utc_now, warn, write_json, write_text
from .models import AppError

DEFAULT_HIDDIFY_PACKAGE = "app.hiddify.com"
ADB_DEVICE_RE = re.compile(r"^(?P<serial>\S+)\s+(?P<state>device|offline|unauthorized)(?:\s+(?P<meta>.*))?$")
VPN_IFACE_PREFIXES = ("tun", "ppp", "ipsec", "vpn")


def find_adb_executable() -> str | None:
    env_adb = os.environ.get("ADB")
    if env_adb and Path(env_adb).is_file():
        return env_adb

    if command_exists("adb"):
        return "adb"

    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" / "platform-tools" / "adb.exe",
        Path(os.environ.get("ANDROID_SDK_ROOT", "")) / "platform-tools" / "adb.exe",
        Path(os.environ.get("ANDROID_HOME", "")) / "platform-tools" / "adb.exe",
        Path("C:/Android/platform-tools/adb.exe"),
        Path("C:/platform-tools/adb.exe"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def parse_adb_devices(output: str) -> list[dict[str, object]]:
    devices: list[dict[str, object]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("List of devices"):
            continue
        match = ADB_DEVICE_RE.match(line)
        if not match:
            continue
        meta: dict[str, str] = {}
        meta_raw = match.group("meta") or ""
        for token in meta_raw.split():
            if ":" not in token:
                continue
            key, value = token.split(":", 1)
            meta[key] = value
        devices.append(
            {
                "serial": match.group("serial"),
                "state": match.group("state"),
                "meta": meta,
            }
        )
    return devices


def select_adb_device(devices: list[dict[str, object]], serial: str | None) -> dict[str, object]:
    if serial:
        for device in devices:
            if device["serial"] == serial:
                if device["state"] != "device":
                    raise AppError(f"ADB-устройство {serial} найдено, но состояние не ready: {device['state']}")
                return device
        raise AppError(f"ADB-устройство с serial {serial} не найдено.")

    ready = [device for device in devices if device["state"] == "device"]
    blocked = [device for device in devices if device["state"] != "device"]
    if len(ready) == 1:
        return ready[0]
    if len(ready) > 1:
        serials = ", ".join(str(device["serial"]) for device in ready)
        raise AppError(f"Найдено несколько Android-устройств: {serials}. Укажи --serial.")
    if blocked:
        details = ", ".join(f"{device['serial']} ({device['state']})" for device in blocked)
        raise AppError(f"ADB видит устройство, но оно не ready: {details}. Проверь USB debugging и подтверждение RSA.")
    raise AppError("ADB не видит Android-устройство по USB.")


def adb_command(adb: str, serial: str, *args: str, capture_output: bool = True, check: bool = True):
    base = [adb, "-s", serial, *args]
    return run_command(base, capture_output=capture_output, check=check)


def collect_adb_output(adb: str, serial: str, relative_path: Path, args: list[str], *, out_dir: Path, check: bool = False) -> str:
    completed = adb_command(adb, serial, *args, capture_output=True, check=check)
    text = completed.stdout or ""
    if completed.stderr:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "[stderr]\n" + completed.stderr
    write_text(out_dir / relative_path, text)
    return text


def extract_vpn_interfaces(ip_brief_text: str) -> list[str]:
    interfaces: list[str] = []
    for raw_line in ip_brief_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        iface = line.split()[0]
        if iface.startswith(VPN_IFACE_PREFIXES):
            interfaces.append(iface)
    return interfaces


def filter_relevant_logcat(logcat_text: str, package_name: str) -> str:
    patterns = [package_name.lower(), "hiddify", "vpn", "vpnservice", "tun", "sing-box"]
    lines = []
    for raw_line in logcat_text.splitlines():
        lowered = raw_line.lower()
        if any(pattern in lowered for pattern in patterns):
            lines.append(raw_line)
    return "\n".join(lines).strip() + ("\n" if lines else "")


def analyze_android_state(
    *,
    package_name: str,
    package_list_text: str,
    ip_brief_text: str,
    route_text: str,
    connectivity_text: str,
    activity_services_text: str,
    private_dns_mode: str,
    logcat_filtered: str,
) -> dict[str, object]:
    package_installed = package_name in package_list_text
    vpn_interfaces = extract_vpn_interfaces(ip_brief_text)
    vpn_route_present = any(iface in route_text for iface in vpn_interfaces)
    connectivity_mentions_package = package_name.lower() in connectivity_text.lower() or " vpn " in f" {connectivity_text.lower()} "
    activity_mentions_package = package_name.lower() in activity_services_text.lower()
    issues: list[str] = []

    if not package_installed:
        issues.append("На телефоне не найден пакет Hiddify.")
    if not vpn_interfaces:
        issues.append("Android не показывает tun/vpn-интерфейс. Похоже, VPNService реально не поднял туннель.")
    if vpn_interfaces and not vpn_route_present:
        issues.append("VPN-интерфейс есть, но в таблицах маршрутизации его почти не видно.")
    if not connectivity_mentions_package:
        issues.append("В dumpsys connectivity нет явного признака, что Hiddify зарегистрирован как активный VPN.")
    if not activity_mentions_package:
        issues.append("В dumpsys activity services Hiddify не виден как активный foreground service.")
    if private_dns_mode and private_dns_mode not in {"off", "null", "unset"}:
        issues.append(f"На телефоне включён Private DNS ({private_dns_mode}). Обычно это не ломает VPN, но может мешать диагностике DNS.")
    if not logcat_filtered.strip():
        issues.append("В отфильтрованном logcat нет строк про Hiddify/VPN/tun. Это часто бывает, если логи уже очищены или приложение почти ничего не пишет в logcat.")

    return {
        "package_installed": package_installed,
        "vpn_interfaces": vpn_interfaces,
        "vpn_route_present": vpn_route_present,
        "connectivity_mentions_package": connectivity_mentions_package,
        "activity_mentions_package": activity_mentions_package,
        "private_dns_mode": private_dns_mode,
        "issues": issues,
    }


def android_diagnose(
    *,
    serial: str | None = None,
    package_name: str = DEFAULT_HIDDIFY_PACKAGE,
    logcat_lines: int = 400,
) -> int:
    ensure_directories()
    adb = find_adb_executable()
    if not adb:
        raise AppError("adb не найден. Установи Android Platform Tools или укажи путь через переменную ADB.")

    run_command([adb, "start-server"], capture_output=True, check=False)
    devices_output = run_command([adb, "devices", "-l"], capture_output=True).stdout
    devices = parse_adb_devices(devices_output)
    selected = select_adb_device(devices, serial)
    device_serial = str(selected["serial"])

    run_id = f"{utc_now().replace(':', '').replace('-', '').replace('Z', '')}-android-{device_serial}"
    out_dir = OUT_DIR / "android" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    write_text(out_dir / "adb-devices.txt", devices_output)

    shell_commands = {
        "device/getprop.txt": ["shell", "getprop"],
        "device/ip-brief-addr.txt": ["shell", "ip", "-brief", "addr"],
        "device/ip-rule.txt": ["shell", "ip", "rule"],
        "device/ip-route-all.txt": ["shell", "sh", "-lc", "ip route show table all; echo; ip -6 route show table all"],
        "device/connectivity.txt": ["shell", "dumpsys", "connectivity"],
        "device/activity-services.txt": ["shell", "dumpsys", "activity", "services", package_name],
        "device/package.txt": ["shell", "dumpsys", "package", package_name],
        "device/package-list.txt": ["shell", "pm", "list", "packages", package_name],
        "device/private-dns-mode.txt": ["shell", "settings", "get", "global", "private_dns_mode"],
        "device/private-dns-specifier.txt": ["shell", "settings", "get", "global", "private_dns_specifier"],
    }

    collected: dict[str, str] = {}
    for path_name, args in shell_commands.items():
        collected[path_name] = collect_adb_output(adb, device_serial, Path(path_name), args, out_dir=out_dir)

    raw_logcat = adb_command(
        adb,
        device_serial,
        "logcat",
        "-d",
        "-v",
        "threadtime",
        "-t",
        str(logcat_lines),
        capture_output=True,
        check=False,
    ).stdout
    write_text(out_dir / "device" / "logcat-raw.txt", raw_logcat)
    filtered_logcat = filter_relevant_logcat(raw_logcat, package_name)
    write_text(out_dir / "device" / "logcat-filtered.txt", filtered_logcat)

    analysis = analyze_android_state(
        package_name=package_name,
        package_list_text=collected["device/package-list.txt"],
        ip_brief_text=collected["device/ip-brief-addr.txt"],
        route_text=collected["device/ip-route-all.txt"],
        connectivity_text=collected["device/connectivity.txt"],
        activity_services_text=collected["device/activity-services.txt"],
        private_dns_mode=collected["device/private-dns-mode.txt"].strip(),
        logcat_filtered=filtered_logcat,
    )

    summary = {
        "run_id": run_id,
        "adb": adb,
        "serial": device_serial,
        "package_name": package_name,
        "analysis": analysis,
        "artifacts": {
            "adb_devices": str(out_dir / "adb-devices.txt"),
            "getprop": str(out_dir / "device" / "getprop.txt"),
            "ip_brief": str(out_dir / "device" / "ip-brief-addr.txt"),
            "ip_rule": str(out_dir / "device" / "ip-rule.txt"),
            "ip_route_all": str(out_dir / "device" / "ip-route-all.txt"),
            "connectivity": str(out_dir / "device" / "connectivity.txt"),
            "activity_services": str(out_dir / "device" / "activity-services.txt"),
            "package": str(out_dir / "device" / "package.txt"),
            "private_dns_mode": str(out_dir / "device" / "private-dns-mode.txt"),
            "logcat_filtered": str(out_dir / "device" / "logcat-filtered.txt"),
        },
    }
    write_json(out_dir / "summary.json", summary)

    print_header("Android / Hiddify диагностика")
    print(f"ADB: {adb}")
    print(f"Устройство: {device_serial}")
    print(f"Пакет Hiddify: {package_name}")
    print(f"VPN-интерфейсы: {', '.join(analysis['vpn_interfaces']) or '-'}")
    print(f"Private DNS: {analysis['private_dns_mode'] or '-'}")
    if analysis["issues"]:
        print("Что выглядит подозрительно:")
        for issue in analysis["issues"]:
            print(f"- {issue}")
    else:
        print("Явных системных признаков утечки не найдено. Дальше уже смотреть поведение конкретных приложений и Hiddify logs.")
    print(f"Summary: {out_dir / 'summary.json'}")
    print(f"Логи и дампы: {out_dir}")
    if not analysis["package_installed"]:
        warn("Hiddify не найден как установленный пакет. Проверь package name или саму установку приложения.")
    return 0
