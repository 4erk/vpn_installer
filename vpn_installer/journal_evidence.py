from __future__ import annotations

import json
import math
import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class JournalRunner(Protocol):
    def __call__(self, args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]: ...


def journal_record_message(record: Mapping[str, Any]) -> str:
    raw_message = record.get("MESSAGE", "")
    if isinstance(raw_message, str):
        message = raw_message
    elif isinstance(raw_message, list):
        try:
            message = bytes(raw_message).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return ""
    else:
        return ""
    return ANSI_ESCAPE_RE.sub("", message)


def journal_command_error(result: subprocess.CompletedProcess[str]) -> str:
    if result.stderr.strip():
        return result.stderr.strip()[:240]
    if result.returncode == 0 or (result.returncode == 1 and not result.stdout.strip()):
        return ""
    return f"journalctl exited with {result.returncode}"


def journal_retained_range(headers: str) -> dict[str, Any]:
    """Find the contiguous system-journal sequence ending in the active file."""
    records = [part for part in headers.split("File path: ")[1:] if part.strip()]
    if not records or len(records) > 128 or len(headers) > 256_000:
        raise ValueError("journal header inventory is empty or exceeds its bound")
    files = []
    try:
        for record in records:
            fields = dict(line.split(": ", 1) for line in record.splitlines()[1:] if ": " in line)
            count = int(fields["Entry objects"])
            if count == 0:
                continue
            head = int(fields["Head sequential number"].split()[0])
            tail = int(fields["Tail sequential number"].split()[0])
            since = int(fields["Head realtime timestamp"].rsplit("(", 1)[1].rstrip(")"), 16) / 1_000_000
            until = int(fields["Tail realtime timestamp"].rsplit("(", 1)[1].rstrip(")"), 16) / 1_000_000
            sequence = fields["Sequential number ID"]
            if not re.fullmatch(r"[0-9a-f]{32}", sequence) or head <= 0 or count != tail - head + 1 or not 0 < since <= until:
                raise ValueError("journal sequence or timestamps are inconsistent")
            files.append({"head": head, "tail": tail, "since": since, "until": until, "sequence": sequence, "state": fields["State"]})
    except (KeyError, IndexError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"journal header inventory is incomplete: {exc}") from exc
    active = [item for item in files if item["state"] == "ONLINE"]
    if len(active) != 1:
        raise ValueError("a unique active system journal is unavailable")
    first = active[0]
    while True:
        previous = [item for item in files if item["sequence"] == first["sequence"] and item["tail"] + 1 == first["head"]]
        if len(previous) != 1 or previous[0]["until"] > first["since"]:
            break
        first = previous[0]
    return {"since_epoch": first["since"], "sequence_id": first["sequence"], "files": len(files)}


def parse_journal_events(
    result: subprocess.CompletedProcess[str], *, include_unit: bool = True,
) -> tuple[list[tuple[float, str]], int]:
    """Keep valid positive records even when their query or sibling records failed."""
    events: list[tuple[float, str]] = []
    malformed = 0
    for raw_line in result.stdout.splitlines():
        try:
            record = json.loads(raw_line)
            if not isinstance(record, Mapping):
                raise ValueError("journal record is not an object")
            raw_timestamp = record["__REALTIME_TIMESTAMP"]
            if isinstance(raw_timestamp, bool) or not isinstance(raw_timestamp, (str, int)):
                raise ValueError("journal timestamp is not an integer")
            timestamp = int(raw_timestamp) / 1_000_000
            if not 0 < timestamp < 253402300800:
                raise ValueError("journal timestamp is outside the datetime range")
            message = journal_record_message(record)
            if not message:
                raise ValueError("journal message is empty or malformed")
            if include_unit:
                unit = str(record.get("_SYSTEMD_UNIT") or record.get("SYSLOG_IDENTIFIER") or "unknown")
                message = f"[unit={unit}] {message}"
        except (KeyError, TypeError, ValueError, OverflowError):
            malformed += 1
            continue
        events.append((timestamp, message))
    return events, malformed


def _valid_epoch(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value < 253402300800 and math.isfinite(value)


def journal_coverage(*, runner: JournalRunner, since: float, until: float) -> dict[str, Any]:
    """Acquire retained sequence and loss evidence for an explicit reusable interval."""
    coverage: dict[str, Any] = {
        "method": "system-journal-sequence", "since_epoch": None, "discarded_at": [],
        "query_since_epoch": since, "query_until_epoch": until, "error": "",
    }
    try:
        if not _valid_epoch(since) or not _valid_epoch(until) or since > until:
            raise ValueError("journal coverage interval is invalid")
        result = runner(["env", "LC_ALL=C", "journalctl", "--system", "--header", "--no-pager"], timeout=10)
        if result.returncode or journal_command_error(result):
            raise ValueError(journal_command_error(result) or f"journalctl exited with {result.returncode}")
        coverage.update(journal_retained_range(result.stdout))
        # Sequence continuity cannot recover records discarded by journald's rate limiter.
        suppressed = runner([
            "journalctl", "--system", "-u", "systemd-journald.service", "--since", f"@{since:.6f}",
            "--until", f"@{until:.6f}", "--no-pager", "--all", "--output=json", "--lines=257",
            "--grep=Suppressed [0-9]+ messages|Missed [0-9]+ messages",
        ], timeout=5)
        if error := journal_command_error(suppressed):
            raise ValueError(error)
        discarded, malformed = parse_journal_events(suppressed)
        if malformed or len(discarded) > 256:
            raise ValueError("journal loss evidence is incomplete")
        coverage["discarded_at"] = [timestamp for timestamp, _line in discarded]
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        coverage["error"] = str(exc)[:240]
    return coverage


def journal_window_error(
    coverage: Mapping[str, Any], *, since: float | None, until: float,
    query_since: float, query_until: float, collector_error: str = "",
) -> str:
    """Validate totals against both the actual query and the retained loss evidence."""
    if collector_error:
        return collector_error
    if not all(_valid_epoch(value) for value in (since, until, query_since, query_until)) or since > until or query_since > query_until:
        return "requested or collected journal interval is invalid"
    if since < query_since:
        return "requested start precedes collected journal interval"
    if until > query_until:
        return "requested end exceeds collected journal interval"
    if coverage.get("error"):
        return str(coverage["error"])
    retained_since = coverage.get("since_epoch")
    if not _valid_epoch(retained_since) or since < retained_since:
        return "requested start precedes retained journal sequence"
    loss_since, loss_until = coverage.get("query_since_epoch"), coverage.get("query_until_epoch")
    if not _valid_epoch(loss_since) or not _valid_epoch(loss_until) or loss_since > since or loss_until < until:
        return "requested window exceeds collected journal loss-evidence interval"
    discarded = coverage.get("discarded_at")
    if not isinstance(discarded, (list, tuple)) or not all(_valid_epoch(value) for value in discarded):
        return "journal loss evidence is incomplete"
    if any(since <= timestamp <= until for timestamp in discarded):
        return "journald reported discarded messages in this window"
    return ""


def journal_event_snapshot(
    *, runner: JournalRunner, pattern: str, window_starts: Mapping[str, float | None],
    query_since: float, cutoff: float, coverage: Mapping[str, Any] | None = None,
    matches: tuple[str, ...], timeout: int = 20, include_unit: bool = True,
) -> dict[str, Any]:
    """Collect bounded journal records; unknown totals retain observed lower bounds."""
    if not _valid_epoch(query_since) or not _valid_epoch(cutoff) or query_since > cutoff:
        raise ValueError("journal query interval is invalid")
    args = [
        "journalctl", "--system", *matches, "--since", f"@{query_since:.6f}",
        "--until", f"@{cutoff:.6f}", "--no-pager", "--all", "--output=json", f"--grep={pattern}",
    ]
    try:
        result = runner(args, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        output = getattr(exc, "stdout", "") or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        result = subprocess.CompletedProcess(args, 127, output, str(exc))
    error = journal_command_error(result)
    parsed, malformed = parse_journal_events(result, include_unit=include_unit)
    if malformed:
        error = "; ".join(filter(None, (error, f"journalctl returned {malformed} malformed JSON record(s)")))
    events = [
        {"epoch": timestamp, "timestamp": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(), "message": message}
        for timestamp, message in parsed if query_since <= timestamp <= cutoff
    ]
    evidence = dict(coverage) if coverage is not None else journal_coverage(runner=runner, since=query_since, until=cutoff)
    counts: dict[str, int | None] = {}
    observed: dict[str, int | None] = {}
    windows = {}
    until_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
    for name, since in window_starts.items():
        window_error = journal_window_error(
            evidence, since=since, until=cutoff, query_since=query_since, query_until=cutoff, collector_error=error,
        )
        valid_start = _valid_epoch(since) and since <= cutoff
        observed[name] = sum(event["epoch"] >= since for event in events) if valid_start else None
        counts[name] = observed[name] if not window_error else None
        windows[name] = {
            "since": datetime.fromtimestamp(since, timezone.utc).isoformat() if valid_start else None,
            "until": until_iso, "scope": "unavailable" if window_error else "complete",
            "coverage_error": window_error,
        }
    return {
        "counts": counts, "observed_counts": observed, "windows": windows, "coverage": evidence,
        "query_since": datetime.fromtimestamp(query_since, timezone.utc).isoformat(), "query_until": until_iso,
        "query_since_epoch": query_since, "query_until_epoch": cutoff,
        "observed_at": until_iso, "collector_error": error, "events": events,
    }


def kernel_event_snapshot(
    *, runner: JournalRunner, pattern: str, window_starts: Mapping[str, float | None],
    query_since: float, cutoff: float, coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return journal_event_snapshot(
        runner=runner, pattern=pattern, window_starts=window_starts, query_since=query_since,
        cutoff=cutoff, coverage=coverage, matches=("_TRANSPORT=kernel",), include_unit=False,
    )


def journal_snapshot_error(value: object, *, window: str) -> str:
    """Require complete evidence before consuming a full-query window's counters."""
    if not isinstance(value, Mapping):
        return "journal evidence was not collected"
    error = value.get("collector_error")
    coverage = value.get("coverage")
    windows = value.get("windows")
    counts = value.get("counts")
    if not isinstance(error, str) or not isinstance(coverage, Mapping) or not isinstance(windows, Mapping) or not isinstance(counts, Mapping):
        return "journal evidence is incomplete"
    if error:
        return error
    state = windows.get(window)
    if not isinstance(state, Mapping):
        return "journal window was not collected"
    if state.get("scope") != "complete" or state.get("coverage_error") != "":
        return str(state.get("coverage_error") or "journal window is incomplete")
    count = counts.get(window)
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return "journal window count is unavailable"
    since, until = value.get("query_since_epoch"), value.get("query_until_epoch")
    return journal_window_error(coverage, since=since, until=until, query_since=since, query_until=until)
