from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable


BUCKETS = (
    "client_front_connect_failed",
    "dns_timeout",
    "dns_nxdomain",
    "dns_failed",
    "transport_unavailable",
    "upstream_refused",
    "domain_to_foreign_timeout",
    "ipv4_literal_timeout",
    "ipv6_literal_timeout",
    "direct_ru_timeout",
    "blocked_private_fake",
    "client_reset_eof",
    "invalid_reality",
    "disabled_invalid",
    "unclassified_error",
)

_OPEN_CONNECTION_RE = re.compile(r"open connection to (?P<dst>\[[^\]]+\]:\d+|[^ ]+) using outbound/[^\[]+\[(?P<tag>[^\]]+)\]")
_OUTBOUND_CONNECTION_RE = re.compile(r"outbound/[^\[]+\[(?P<tag>[^\]]+)\]: outbound connection to (?P<dst>\[[^\]]+\]:\d+|[^ ]+)")
_ACCEPTED_RE = re.compile(r"accepted (?:tcp|udp):(?P<dst>\[[^\]]+\]:\d+|[^ ]+)")
_SOURCE_ENDPOINT_RE = re.compile(r"(?:from|process connection from) (?P<endpoint>\S+)")
_DNS_LOOKUP_FAILED_RE = re.compile(r"dns: lookup failed for (?P<dst>[^: ]+):")
_DNS_EXCHANGE_FAILED_RE = re.compile(r"dns: exchange failed for (?P<dst>[^ ]+)\. IN (?P<qtype>[A-Z0-9]+):")
_ROUTER_LOOKUP_RE = re.compile(r"router: lookup (?P<dst>[^: ]+):")
_PROXY_DIAL_FAILED_RE = re.compile(r"using outbound/vless\[[^\]]+\]: dial tcp (?P<dst>\[[^\]]+\]:\d+|[^: ]+:\d+): i/o timeout")
_PROXY_READ_FAILED_RE = re.compile(r"using outbound/vless\[[^\]]+\]: read tcp [^ ]+->(?P<dst>\[[^\]]+\]:\d+|[^: ]+:\d+):")
_LOG_EVENT_ID_RE = re.compile(r"\b(?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\[(?P<event_id>\d+)\b")
_INBOUND_DESTINATION_RE = re.compile(r"inbound/[^\[]+\[[^\]]+\]: inbound (?:packet )?connection to (?P<dst>\[[^\]]+\]:\d+|[^ ]+)")
_DNS_LOOKUP_SUCCEED_RE = re.compile(r"dns: lookup succeed for (?P<dst>[^: ]+):")
_CANCELLATION_TOKENS = (
    "context canceled",
    "context cancelled",
    "canceled by remote with error code 0",
    "cancelled by remote with error code 0",
    "operation canceled",
    "operation cancelled",
    "operation was canceled",
    "operation was cancelled",
    "write on closed stream",
)


@dataclass(frozen=True)
class ClassifiedLogLine:
    bucket: str
    destination: str = ""
    source: str = ""
    event_id: str = ""


def normalize_source(value: str) -> str:
    candidate = value.strip().strip("[]")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def split_endpoint(value: str) -> tuple[str, int | None]:
    endpoint = value.strip().rstrip(",;")
    if endpoint.startswith(("tcp:", "udp:")):
        endpoint = endpoint.split(":", 1)[1]
    if endpoint.startswith("["):
        closing = endpoint.find("]")
        host = endpoint[1:closing] if closing >= 0 else endpoint[1:]
        suffix = endpoint[closing + 1 :] if closing >= 0 else ""
        port = suffix[1:] if suffix.startswith(":") else ""
    else:
        host, separator, port = endpoint.rpartition(":")
        if not separator:
            host, port = endpoint, ""
    return normalize_source(host), int(port) if port.isdigit() else None


def source_endpoint_from_line(line: str) -> tuple[str, int | None]:
    match = _SOURCE_ENDPOINT_RE.search(line)
    return split_endpoint(match.group("endpoint")) if match else ("", None)


def source_from_line(line: str) -> str:
    return source_endpoint_from_line(line)[0]


def accepted_destination_from_line(line: str) -> str:
    match = _ACCEPTED_RE.search(line)
    return match.group("dst") if match else ""


def event_id_from_line(line: str) -> str:
    match = _LOG_EVENT_ID_RE.search(line)
    return match.group("event_id") if match else ""


def _destination(line: str) -> str:
    for pattern in (_PROXY_DIAL_FAILED_RE, _PROXY_READ_FAILED_RE, _OPEN_CONNECTION_RE, _OUTBOUND_CONNECTION_RE, _ACCEPTED_RE):
        match = pattern.search(line)
        if match:
            return match.group("dst")
    match = _DNS_LOOKUP_FAILED_RE.search(line)
    if match:
        return match.group("dst")
    match = _DNS_EXCHANGE_FAILED_RE.search(line)
    if match:
        return f"{match.group('dst')}:{match.group('qtype')}"
    match = _ROUTER_LOOKUP_RE.search(line)
    if match:
        return match.group("dst")
    return ""


def _outbound_tag(line: str) -> str:
    for pattern in (_OPEN_CONNECTION_RE, _OUTBOUND_CONNECTION_RE):
        match = pattern.search(line)
        if match:
            return match.group("tag")
    return ""


def _destination_ip_version(destination: str) -> int | None:
    host = destination
    if host.startswith("["):
        host = host[1 : host.find("]")]
    elif host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(host).version
    except ValueError:
        return None


def _destination_port(destination: str) -> str:
    if destination.startswith("["):
        suffix = destination[destination.find("]") + 1 :]
        return suffix[1:] if suffix.startswith(":") and suffix[1:].isdigit() else ""
    if destination.count(":") == 1:
        _host, port = destination.rsplit(":", 1)
        return port if port.isdigit() else ""
    return ""


def _trace_destination(event_destination: str, fallback_destination: str) -> str:
    if not event_destination:
        return fallback_destination
    if _destination_port(event_destination):
        return event_destination
    port = _destination_port(fallback_destination)
    return f"{event_destination}:{port}" if port else event_destination


def classify_line(line: str) -> ClassifiedLogLine | None:
    destination = _destination(line)
    source = source_from_line(line)
    event_id = event_id_from_line(line)
    lower_line = line.lower()
    if "accepted tcp:disabled.invalid" in line:
        return ClassifiedLogLine("disabled_invalid", destination, source, event_id)
    if "REALITY: processed invalid connection" in line:
        return ClassifiedLogLine("invalid_reality", destination, source, event_id)
    if any(token in lower_line for token in _CANCELLATION_TOKENS):
        return ClassifiedLogLine("client_reset_eof", destination, source, event_id)
    if "using outbound/vless[" in line and any(token in line for token in ("dial tcp", "wsarecv", "connected host has failed to respond")):
        return ClassifiedLogLine("client_front_connect_failed", destination, source, event_id)
    if "quic: transport closed" in lower_line:
        return ClassifiedLogLine("transport_unavailable", destination, source, event_id)
    dns_failure = any(token in line for token in ("dns: exchange failed", "exchange failed for ", "dns: lookup failed", "lookup failed for ", "router: lookup "))
    if dns_failure and any(token in line for token in ("context deadline exceeded", "i/o timeout")):
        return ClassifiedLogLine("dns_timeout", destination, source, event_id)
    if dns_failure and "NXDOMAIN" in line.upper():
        return ClassifiedLogLine("dns_nxdomain", destination, source, event_id)
    if dns_failure:
        return ClassifiedLogLine("dns_failed", destination, source, event_id)
    if any(token in line for token in ("outbound/block[blocked]", "using outbound/block[blocked]", "connection rejected")):
        return ClassifiedLogLine("blocked_private_fake", destination, source, event_id)
    if "i/o timeout" in line or "context deadline exceeded" in line:
        outbound = _outbound_tag(line)
        if outbound == "direct-ru":
            return ClassifiedLogLine("direct_ru_timeout", destination, source, event_id)
        version = _destination_ip_version(destination)
        if version == 6:
            return ClassifiedLogLine("ipv6_literal_timeout", destination, source, event_id)
        if version == 4:
            return ClassifiedLogLine("ipv4_literal_timeout", destination, source, event_id)
        if outbound.startswith("to-foreign"):
            return ClassifiedLogLine("domain_to_foreign_timeout", destination, source, event_id)
    if "connect: connection refused" in lower_line:
        return ClassifiedLogLine("upstream_refused", destination, source, event_id)
    if any(token in line for token in ("mux connection closed", "EOF", "connection reset")):
        return ClassifiedLogLine("client_reset_eof", destination, source, event_id)
    if "ERROR" in line:
        return ClassifiedLogLine("unclassified_error", destination, source, event_id)
    return None


def _event_destinations(lines: Iterable[str]) -> dict[str, str]:
    destinations: dict[str, str] = {}
    for line in lines:
        event_id = event_id_from_line(line)
        if not event_id:
            continue
        for pattern in (_INBOUND_DESTINATION_RE, _DNS_LOOKUP_SUCCEED_RE):
            match = pattern.search(line)
            if match:
                candidate = match.group("dst")
                existing = destinations.get(event_id, "")
                if not existing or _destination_port(candidate) or not _destination_port(existing):
                    destinations[event_id] = candidate
                break
    return destinations


def summarize_lines(lines: Iterable[str], *, top_n: int = 12) -> dict[str, Any]:
    materialized = list(lines)
    event_destinations = _event_destinations(materialized)
    counts: Counter[str] = Counter()
    destinations: dict[str, Counter[str]] = {bucket: Counter() for bucket in BUCKETS}
    sources: dict[str, Counter[str]] = {bucket: Counter() for bucket in BUCKETS}
    samples: dict[str, str] = {}
    seen_events: set[tuple[str, str]] = set()
    for line in materialized:
        item = classify_line(line)
        if item is None:
            continue
        event_key = (item.bucket, item.event_id)
        if item.event_id and event_key in seen_events:
            continue
        if item.event_id:
            seen_events.add(event_key)
        counts[item.bucket] += 1
        samples.setdefault(item.bucket, line.strip()[:320])
        destination = _trace_destination(event_destinations.get(item.event_id, ""), item.destination)
        if destination:
            destinations[item.bucket][destination] += 1
        if item.source:
            sources[item.bucket][item.source] += 1
    return {
        "counts": {bucket: counts.get(bucket, 0) for bucket in BUCKETS},
        "top_destinations": {bucket: dict(counter.most_common(top_n)) for bucket, counter in destinations.items() if counter},
        "top_sources": {bucket: dict(counter.most_common(top_n)) for bucket, counter in sources.items() if counter},
        "samples": samples,
    }
