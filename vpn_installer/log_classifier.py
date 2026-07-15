from __future__ import annotations

# The installed agent and local diagnostics intentionally share one classifier.
# Keeping this compatibility module avoids a second set of regexes.
from .server_agent import BUCKETS, ClassifiedLogLine, classify_line, summarize_lines

__all__ = ["BUCKETS", "ClassifiedLogLine", "classify_line", "summarize_lines"]
