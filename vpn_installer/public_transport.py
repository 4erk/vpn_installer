from __future__ import annotations

import base64
import hashlib
import hmac
import ssl
import uuid
from typing import Any

from .interserver_transport import HY2_SERVER_NAME, decode_transport_pem
from .topology import CAP_PUBLIC_FRONT, NODE_GATEWAY, NodePlan, TopologySpec

PUBLIC_HY2_INBOUND_TAG = "public-hy2-in"
PUBLIC_HY2_OUTBOUND_TAG = "ru-gateway-quic"
def _public_gateway_plan(env: dict[str, str]) -> NodePlan:
    plan = TopologySpec.from_env(env).plan(NODE_GATEWAY)
    if CAP_PUBLIC_FRONT not in plan.capabilities:
        raise ValueError("gateway topology does not provide the public-front capability")
    return plan


def derive_public_hy2_password(client_uuid: str) -> str:
    """Derive a transport-specific credential from the existing client identity."""

    try:
        root_key = uuid.UUID(client_uuid).bytes
    except (AttributeError, ValueError) as exc:
        raise ValueError("invalid client UUID") from exc
    token = hmac.new(root_key, b"vpn-stack/public/hysteria2/auth/v1", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")


def public_hy2_certificate_fingerprint(env: dict[str, str]) -> str:
    _public_gateway_plan(env)
    certificate_pem = "\n".join(decode_transport_pem(env["PUBLIC_HY2_CERTIFICATE_B64"], "certificate")) + "\n"
    certificate_der = ssl.PEM_cert_to_DER_cert(certificate_pem)
    digest = hashlib.sha256(certificate_der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def render_public_hy2_inbound(env: dict[str, str]) -> dict[str, Any]:
    _public_gateway_plan(env)
    return {
        "type": "hysteria2",
        "tag": PUBLIC_HY2_INBOUND_TAG,
        "listen": "0.0.0.0",
        "listen_port": int(env["RU_LISTEN_PORT"]),
        "users": [{"password": derive_public_hy2_password(env["CLIENT_UUID"])}],
        "tls": {
            "enabled": True,
            "certificate": decode_transport_pem(env["PUBLIC_HY2_CERTIFICATE_B64"], "certificate"),
            "key": decode_transport_pem(env["PUBLIC_HY2_PRIVATE_KEY_B64"], "private key"),
        },
    }


def render_public_hy2_outbound(env: dict[str, str], *, tag: str = PUBLIC_HY2_OUTBOUND_TAG) -> dict[str, Any]:
    gateway = _public_gateway_plan(env)
    return {
        "type": "hysteria2",
        "tag": tag,
        "server": gateway.public_ip,
        "server_port": int(env["RU_LISTEN_PORT"]),
        "password": derive_public_hy2_password(env["CLIENT_UUID"]),
        "tls": {
            "enabled": True,
            "server_name": HY2_SERVER_NAME,
            "certificate_public_key_sha256": [env["PUBLIC_HY2_PUBLIC_KEY_SHA256"]],
        },
    }
