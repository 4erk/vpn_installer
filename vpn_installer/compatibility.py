from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Mapping

from . import VERSION
from .common import cli_entrypoint


COMPATIBLE_INSTALLED_MIN = "0.21.1"
COMPATIBLE_INSTALLED_MAX = VERSION

_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class CompatibilityError(ValueError):
    pass


@total_ordering
@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: object) -> "Version":
        value = str(raw).strip()
        match = _VERSION_PATTERN.fullmatch(value)
        if not match:
            raise CompatibilityError(f"invalid release version: {value or '<empty>'}")
        return cls(*(int(part) for part in match.groups()))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)


@dataclass(frozen=True)
class CompatibilityWindow:
    minimum: Version
    maximum: Version

    @classmethod
    def current(cls) -> "CompatibilityWindow":
        return cls(
            minimum=Version.parse(COMPATIBLE_INSTALLED_MIN),
            maximum=Version.parse(COMPATIBLE_INSTALLED_MAX),
        )

    @classmethod
    def from_manifest(cls, payload: object) -> "CompatibilityWindow":
        if not isinstance(payload, Mapping):
            raise CompatibilityError("manifest update compatibility must be an object")
        transitions = payload.get("transitions")
        if not isinstance(transitions, list):
            raise CompatibilityError("manifest update compatibility transitions must be an array")
        return cls(
            minimum=Version.parse(payload.get("installed_min", "")),
            maximum=Version.parse(payload.get("installed_max", "")),
        )

    def __post_init__(self) -> None:
        if self.minimum > self.maximum:
            raise CompatibilityError("compatible version range is inverted")

    def accepts(self, version: Version | str) -> bool:
        candidate = version if isinstance(version, Version) else Version.parse(version)
        return self.minimum <= candidate <= self.maximum

    def require(self, version: Version | str) -> Version:
        candidate = version if isinstance(version, Version) else Version.parse(version)
        if not self.accepts(candidate):
            raise CompatibilityError(incompatible_update_message(str(candidate), window=self))
        return candidate

    def to_manifest(self) -> dict[str, object]:
        return {
            "installed_min": str(self.minimum),
            "installed_max": str(self.maximum),
            "transitions": [
                {
                    "from": str(self.minimum),
                    "to": str(self.maximum),
                }
            ] if self.minimum != self.maximum else [],
        }


def installed_version(manifest: Mapping[str, object]) -> Version:
    return Version.parse(manifest.get("version", ""))


def incompatible_update_message(
    installed: str,
    *,
    window: CompatibilityWindow | None = None,
) -> str:
    supported = window or CompatibilityWindow.current()
    entrypoint = cli_entrypoint()
    return (
        f"installed release {installed} cannot be updated by {VERSION}; supported installed versions: "
        f"{supported.minimum}..{supported.maximum}. Use {entrypoint} from tag {installed} to remove or purge "
        "that release, then install the current release."
    )


def require_compatible_installed(manifest: Mapping[str, object]) -> Version:
    version = installed_version(manifest)
    return CompatibilityWindow.current().require(version)
