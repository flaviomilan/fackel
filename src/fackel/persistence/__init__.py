"""Persistence for the core domain model.

The :class:`InformationStore` is an append-only JSONL repository scoped
to a single scan.  It keeps three streams on disk:

- ``executions.jsonl`` — one :class:`~fackel.domain.ToolExecution` per line.
- ``records.jsonl``    — one :class:`~fackel.domain.InformationRecord`
  snapshot per line; the freshest line per ``fingerprint`` wins on read.
- ``timeline.jsonl``   — one :class:`~fackel.domain.TimelineEvent` per line.

A scan-scoped :class:`contextvars.ContextVar` (``current_store``) lets
graph nodes — whose signature is fixed by LangGraph — pick up the
correct store without explicit threading.
"""

from __future__ import annotations

from .diff import ScanDiff, diff_scans, format_diff, list_scans, load_scan
from .store import (
    InformationStore,
    bind_store_for_scan,
    current_store,
    get_current_store,
)

__all__ = [
    "InformationStore",
    "ScanDiff",
    "bind_store_for_scan",
    "current_store",
    "diff_scans",
    "format_diff",
    "get_current_store",
    "list_scans",
    "load_scan",
]
