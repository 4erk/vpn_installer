from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

BUCKETS = (
    "dns_failed",
    "domain_to_foreign_timeout",
    "ipv4_literal_timeout",
    "ipv6_literal_timeout",
    "blocked_private_fake",
    "client_reset_eof",
    "invalid_reality",
    "disabled_invalid",
)


@dataclass(frozen=True)
class ClassifiedLogLine:
    bucket: str
    destination: str = ""
    source: str = ""


_OPEN_CONNECTION_RE = re.compile(r"open connection to (?P<dst>\[[^\]]+\]:\d+|[^ ]+) using outbound/(?:direct|block)\[(?P<tag>[^\]]+)\]")
_OUTBOUND_CONNECTION_RE = re.compile(r"outbound/(?:direct|block)\[(?P<tag>[^\]]+)\]: outbound connection to (?P<dst>\[[^\]]+\]:\d+|[^ ]+)")
_ACCEPTED_RE = re.compile(r"accepted tcp:(?P<dst>\[[^\]]+\]:\d+|[^ ]+)")
_SOURCE_RE = re.compile(r"(?:from|process connection from) (?P<src>\[[^\]]+\]|[^: ]+):\d+")


def _destination(line: str) -> str:
    for pattern in (_OPEN_CONNECTION_RE, _OUTBOUND_CONNECTION_RE, _ACCEPTED_RE):
        match = pattern.search(line)
        if match:
            return match.group("dst")
    dns_match = re.search(r"lookup failed for ([^: ]+):", line)
    if dns_match:
        return dns_match.group(1)
    return ""


def _source(line: str) -> str:
    match = _SOURCE_RE.search(line)
    return match.group("src") if match else ""


def _is_ipv6_destination(destination: str) -> bool:
    return destination.startswith("[")


def classify_line(line: str) -> ClassifiedLogLine | None:
    if "accepted tcp:disabled.invalid" in line:
        return ClassifiedLogLine("disabled_invalid", _destination(line), _source(line))
    if "REALITY: processed invalid connection" in line:
        return ClassifiedLogLine("invalid_reality", _destination(line), _source(line))
    if "dns: lookup failed" in line or "lookup failed for " in line:
        return ClassifiedLogLine("dns_failed", _destination(line), _source(line))
    if "outbound/block[blocked]" in line or "using outbound/block[blocked]" in line:
        return ClassifiedLogLine("blocked_private_fake", _destination(line), _source(line))
    if "i/o timeout" in line or "context deadline exceeded" in line:
        destination = _destination(line)
        if "to-foreign-ipv6-literal" in line or _is_ipv6_destination(destination):
            return ClassifiedLogLine("ipv6_literal_timeout", destination, _source(line))
        if "to-foreign-ip-literal" in line:
            return ClassifiedLogLine("ipv4_literal_timeout", destination, _source(line))
        if "to-foreign" in line:
            return ClassifiedLogLine("domain_to_foreign_timeout", destination, _source(line))
    if "mux connection closed" in line or "EOF" in line or "connection reset" in line:
        return ClassifiedLogLine("client_reset_eof", _destination(line), _source(line))
    return None


def summarize_lines(lines: list[str], *, top_n: int = 12) -> dict[str, object]:
    counts: Counter[str] = Counter()
    destinations: dict[str, Counter[str]] = {bucket: Counter() for bucket in BUCKETS}
    sources: dict[str, Counter[str]] = {bucket: Counter() for bucket in BUCKETS}
    samples: dict[str, str] = {}
    for line in lines:
        classified = classify_line(line)
        if classified is None:
            continue
        counts[classified.bucket] += 1
        samples.setdefault(classified.bucket, line.strip()[:240])
        if classified.destination:
            destinations[classified.bucket][classified.destination] += 1
        if classified.source:
            sources[classified.bucket][classified.source] += 1
    return {
        "counts": {bucket: counts.get(bucket, 0) for bucket in BUCKETS},
        "top_destinations": {
            bucket: dict(counter.most_common(top_n))
            for bucket, counter in destinations.items()
            if counter
        },
        "top_sources": {
            bucket: dict(counter.most_common(top_n))
            for bucket, counter in sources.items()
            if counter
        },
        "samples": samples,
    }
