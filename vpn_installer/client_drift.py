from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class ClientDriftFinding:
    path: Path
    issue: str


def default_candidate_paths() -> list[Path]:
    candidates: list[Path] = []
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        hiddify_configs = Path(appdata) / "Hiddify" / "hiddify" / "configs"
        candidates.extend(sorted(hiddify_configs.glob("*.json")) if hiddify_configs.is_dir() else [])
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        downloads = Path(userprofile) / "Downloads"
        if downloads.is_dir():
            candidates.extend(sorted(downloads.glob("hiddify*.json")))
            for v2ray_dir in sorted(downloads.glob("v2rayN*")):
                if not v2ray_dir.is_dir():
                    continue
                for pattern in ("**/guiConfigs/*.json", "**/config*.json", "**/*.txt"):
                    candidates.extend(sorted(v2ray_dir.glob(pattern)))
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def _walk_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _as_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _inspect_json(path: Path, payload: Any, env: dict[str, str]) -> list[ClientDriftFinding]:
    findings: list[ClientDriftFinding] = []
    ru_ip = env.get("RU_PUBLIC_IP", "").strip()
    expected_port = _as_int(env.get("RU_LISTEN_PORT", ""))
    expected_uuid = env.get("CLIENT_UUID", "").strip()
    expected_public_key = env.get("RU_REALITY_PUBLIC_KEY", "").strip()
    expected_short_id = env.get("RU_REALITY_SHORT_ID", "").strip()
    if not ru_ip or expected_port is None:
        return findings
    for item in _walk_dicts(payload):
        server = str(item.get("server") or item.get("address") or "")
        uuid_value = str(item.get("uuid") or item.get("id") or "")
        public_key = str(item.get("public_key") or item.get("publicKey") or "")
        short_id = str(item.get("short_id") or item.get("shortId") or "")
        is_current_profile = server == ru_ip or uuid_value == expected_uuid or public_key == expected_public_key
        if not is_current_profile:
            continue
        port = _as_int(item.get("server_port", item.get("port")))
        if server == ru_ip and port is not None and port != expected_port:
            findings.append(ClientDriftFinding(path, f"устаревший порт клиента: {port}, ожидается {expected_port}"))
        if uuid_value and expected_uuid and uuid_value != expected_uuid:
            findings.append(ClientDriftFinding(path, "устаревший CLIENT_UUID в клиентском профиле"))
        if public_key and expected_public_key and public_key != expected_public_key:
            findings.append(ClientDriftFinding(path, "устаревший REALITY public key в клиентском профиле"))
        if short_id and expected_short_id and short_id != expected_short_id:
            findings.append(ClientDriftFinding(path, "устаревший REALITY short_id в клиентском профиле"))
    return findings


def _inspect_text(path: Path, text: str, env: dict[str, str]) -> list[ClientDriftFinding]:
    ru_ip = re.escape(env.get("RU_PUBLIC_IP", "").strip())
    expected_port = env.get("RU_LISTEN_PORT", "").strip()
    if not ru_ip or not expected_port:
        return []
    findings: list[ClientDriftFinding] = []
    for match in re.finditer(rf"vless://[^@\s]+@{ru_ip}:(\d+)", text):
        port = match.group(1)
        if port != expected_port:
            findings.append(ClientDriftFinding(path, f"устаревший VLESS URI порт: {port}, ожидается {expected_port}"))
    return findings


def find_client_drift(env: dict[str, str], paths: Iterable[Path] | None = None) -> list[ClientDriftFinding]:
    findings: list[ClientDriftFinding] = []
    for path in paths if paths is not None else default_candidate_paths():
        try:
            if path.stat().st_size > 5 * 1024 * 1024:
                continue
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                findings.extend(_inspect_json(path, json.loads(text), env))
            except json.JSONDecodeError:
                findings.extend(_inspect_text(path, text, env))
        else:
            findings.extend(_inspect_text(path, text, env))
    unique: list[ClientDriftFinding] = []
    seen: set[tuple[Path, str]] = set()
    for finding in findings:
        key = (finding.path, finding.issue)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
