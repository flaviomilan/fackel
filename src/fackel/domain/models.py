"""Domain models — normalized, infrastructure-agnostic representations.

Rules (from persistence-rules.instructions.md):
- InformationRecord is the current known state of a fact.
- InformationTimelineEvent is append-only; never update or delete events.
- ToolExecution is immutable once created.
- Deduplication is fingerprint-based, never tool-based.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .enums import InformationStatus, InformationType


@dataclass(frozen=True)
class ToolExecution:
    """Immutable record of a single tool invocation.

    Stores raw output and execution metadata only.
    Does NOT contain normalized information.
    """

    tool_name: str
    params: dict[str, Any]
    raw_output: str
    executed_at: datetime
    duration_ms: int
    error: str | None = None


@dataclass
class InformationRecord:
    """Normalized, deduplicated fact extracted from tool outputs.

    Identity is based on `fingerprint` — a stable hash of
    (information_type, normalized_value). Multiple ToolExecutions
    may reference the same InformationRecord.
    """

    fingerprint: str
    information_type: InformationType
    normalized_value: str
    original_value: str
    status: InformationStatus
    first_seen_at: datetime
    last_seen_at: datetime
    sources: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def make_fingerprint(information_type: InformationType, normalized_value: str) -> str:
        raw = f"{information_type}:{normalized_value}".encode()
        return hashlib.sha256(raw).hexdigest()


@dataclass
class InformationTimelineEvent:
    """Append-only history entry for an InformationRecord.

    Allowed event types: created, updated, resolved, masked, reintroduced.
    """

    record_fingerprint: str
    event_type: str
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanTarget:
    """A single target queued for processing.

    A target is either an IP address or a domain.
    `parent` tracks which earlier target led to its discovery,
    enabling a full provenance chain.
    """

    value: str
    target_type: str  # "ip" | "domain"
    parent: str | None = None
