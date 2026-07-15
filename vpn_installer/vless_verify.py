from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse


@dataclass(frozen=True)
class VlessUri:
    uuid: str
    host: str
    port: int
    server_name: str
    public_key: str
    short_id: str
    fingerprint: str
    flow: str


def parse_vless_uri(raw_value: str) -> VlessUri:
    parsed = urlparse(raw_value.strip())
    if parsed.scheme != "vless" or not parsed.username or not parsed.hostname or not parsed.port:
        raise ValueError("invalid VLESS URI")
    query = parse_qs(parsed.query)
    if query.get("security", [""])[0] != "reality" or query.get("type", [""])[0] != "tcp":
        raise ValueError("VLESS URI must use Reality over TCP")
    required = {key: query.get(key, [""])[0] for key in ("sni", "pbk", "sid", "fp", "flow")}
    if not all(required.values()):
        raise ValueError("VLESS URI has incomplete Reality parameters")
    return VlessUri(
        uuid=unquote(parsed.username),
        host=parsed.hostname,
        port=parsed.port,
        server_name=required["sni"],
        public_key=required["pbk"],
        short_id=required["sid"],
        fingerprint=required["fp"],
        flow=required["flow"],
    )


def render_ephemeral_singbox_client(uri: VlessUri, *, listen_port: int) -> str:
    payload = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": listen_port, "tag": "verify-in"}],
        "outbounds": [
            {
                "type": "vless",
                "tag": "ru-gateway",
                "server": uri.host,
                "server_port": uri.port,
                "uuid": uri.uuid,
                "flow": uri.flow,
                "tls": {
                    "enabled": True,
                    "server_name": uri.server_name,
                    "utls": {"enabled": True, "fingerprint": uri.fingerprint},
                    "reality": {"enabled": True, "public_key": uri.public_key, "short_id": uri.short_id},
                },
            }
        ],
        "route": {"final": "ru-gateway"},
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
