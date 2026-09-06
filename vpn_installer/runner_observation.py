"""Attribute a temporary verifier's TCP sockets without packet capture."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import time
from pathlib import Path


def _endpoint(value: str) -> tuple[str, int]:
    address, port = value.split(":")
    packed = bytes.fromhex(address)
    packed = b"".join(packed[offset:offset + 4][::-1] for offset in range(0, len(packed), 4))
    ip = ipaddress.ip_address(packed)
    return str(getattr(ip, "ipv4_mapped", None) or ip), int(port, 16)


def process_sockets(proc: Path, destination: tuple[str, int]) -> set[str]:
    owned = set()
    for fd in (proc / "fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            owned.add(target[8:-1])
    result = set()
    for protocol in ("tcp", "tcp6"):
        path = proc / "net" / protocol
        if not path.exists():
            continue
        for row in path.read_text(encoding="ascii").splitlines()[1:]:
            fields = row.split()
            if len(fields) < 10 or fields[9] not in owned or _endpoint(fields[2]) != destination:
                continue
            address, port = _endpoint(fields[1])
            result.add(f"[{address}]:{port}" if ":" in address else f"{address}:{port}")
    return result


def observe(pid: int, config: dict, stop: Path, *, proc_root: Path = Path("/proc")) -> dict:
    outbounds = [outbound for outbound in config.get("outbounds", []) if outbound.get("type") == "vless"]
    if not outbounds:
        return {"status": "not_applicable", "reason": "profile has no VLESS TCP outbound", "flows": []}
    if len(outbounds) != 1:
        raise ValueError("expected one public VLESS outbound")
    destination = (str(ipaddress.ip_address(outbounds[0]["server"])), int(outbounds[0]["server_port"]))
    proc = proc_root / str(pid)
    identity = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]

    def check_identity() -> None:
        try:
            current = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
        except FileNotFoundError as exc:
            raise RuntimeError("verifier process exited during observation") from exc
        if current != identity:
            raise RuntimeError("verifier process identity changed")

    flows: set[str] = set()
    # A missed short-lived socket yields inconclusive correlation, never an
    # attribution based only on the shared source address.
    while not stop.exists():
        try:
            check_identity()
            sample = process_sockets(proc, destination)
            check_identity()
            flows.update(sample)
        except FileNotFoundError as exc:
            raise RuntimeError("verifier process exited during observation") from exc
        if len(flows) > 4096:
            raise RuntimeError("verifier socket evidence exceeded its bound")
        time.sleep(0.05)
    check_identity()
    return {"status": "ok", "flows": sorted(flows), "destination": list(destination)}


def main() -> int:
    try:
        result = observe(int(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text()), Path(sys.argv[3]))
    except (OSError, ValueError, KeyError, IndexError, RuntimeError) as exc:
        result = {"status": "error", "reason": str(exc)[:240], "flows": []}
    print(json.dumps(result))
    return int(result["status"] == "error")


if __name__ == "__main__":
    raise SystemExit(main())
