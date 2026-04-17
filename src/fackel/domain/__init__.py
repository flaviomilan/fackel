"""Core domain model — see ``.github/instructions/project-architecture.instructions.md``.

This package defines the canonical concepts used across the project:

- :class:`InformationType` — semantic catalog of fact categories.
- :class:`InformationCandidate` — transient extraction (not persisted).
- :class:`InformationRecord` — persisted, deduplicated, normalized fact.
- :class:`TimelineEvent` — append-only history entry per record.
- :class:`ToolExecution` — immutable record of a single tool invocation.
- :func:`fingerprint` — stable identity hash for deduplication.
"""

from __future__ import annotations

from .fingerprint import edge_fingerprint, fingerprint
from .models import (
    Edge,
    EdgeCandidate,
    InformationCandidate,
    InformationRecord,
    RecordStatus,
    RelationshipType,
    TimelineEvent,
    TimelineEventType,
    ToolExecution,
    ToolExecutionStatus,
)
from .types import InformationType

__all__ = [
    "Edge",
    "EdgeCandidate",
    "InformationCandidate",
    "InformationRecord",
    "InformationType",
    "RecordStatus",
    "RelationshipType",
    "TimelineEvent",
    "TimelineEventType",
    "ToolExecution",
    "ToolExecutionStatus",
    "edge_fingerprint",
    "fingerprint",
]
