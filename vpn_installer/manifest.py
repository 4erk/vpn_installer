from __future__ import annotations

import json
from datetime import datetime, timezone

from . import VERSION
from .diagnostics import sha256_text
from .routing_policy import POLICY_VERSION


def render_manifest(env_text: str, role: str, rendered_files: dict[str, str]) -> str:
    artifacts = {name: sha256_text(content) for name, content in sorted(rendered_files.items())}
    manifest = {
        "schema_version": 1,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "role": role,
        "env_sha256": sha256_text(env_text),
        "config_sha256": artifacts.get("sing-box.json", ""),
        "policy_version": POLICY_VERSION,
        "artifact_sha256": artifacts,
    }
    return json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
