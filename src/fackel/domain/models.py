"""Pydantic models for the core domain concepts.

All models are :class:`pydantic.BaseModel` so callers get cheap
validation and JSON-roundtrip support — required for the JSONL
persistence layer.

Timestamps are always UTC (architecture rule §6).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .fingerprint import edge_fingerprint as _edge_fingerprint
from .fingerprint import fingerprint as _fingerprint
from .types import InformationType


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ToolExecutionStatus(StrEnum):
    """Outcome of a single tool invocation."""

    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class ToolExecution(BaseModel):
    """Immutable record of one tool invocation.

    Stores raw output and metadata only — never normalized information.
    """

    model_config = ConfigDict(frozen=True)

    execution_id: str = Field(description="UUID for this invocation")
    scan_id: str = Field(description="Scan that produced this execution")
    phase: str = Field(description="Phase name (osint, port_scan, vuln_scan, …)")
    tool_name: str = Field(description="Name of the tool invoked")
    params: dict[str, Any] = Field(default_factory=dict)
    raw_output: str = Field(default="", description="Stringified raw tool output")
    status: ToolExecutionStatus = ToolExecutionStatus.OK
    started_at: datetime = Field(default_factory=_utc_now)
    duration_ms: int | None = Field(default=None, description="Wall-clock runtime in ms")


class InformationCandidate(BaseModel):
    """Transient, non-persisted extraction from a tool output.

    Translators emit candidates; the persistence layer turns them into
    :class:`InformationRecord` instances after deduplication.
    """

    model_config = ConfigDict(frozen=True)

    type: InformationType
    normalized_value: str = Field(description="Comparison key (lower-case, trimmed, …)")
    original_value: str = Field(description="Value as reported by the tool")
    attributes: dict[str, Any] = Field(default_factory=dict)
    source_execution_id: str = Field(description="ToolExecution that produced the candidate")
    source_tool: str = Field(description="Name of the producing tool")
    phase: str = Field(description="Phase that produced the candidate")

    @property
    def fingerprint(self) -> str:
        """Stable identity for this candidate."""
        return _fingerprint(self.type, self.normalized_value)


class RecordStatus(StrEnum):
    """Lifecycle status of an :class:`InformationRecord`."""

    ACTIVE = "active"
    RESOLVED = "resolved"
    MASKED = "masked"
    OUTDATED = "outdated"


class InformationRecord(BaseModel):
    """Persisted, deduplicated, normalized fact.

    Identity is the fingerprint; values are append-only by design — the
    only mutable fields are :attr:`last_seen_at`, :attr:`status`,
    :attr:`source_executions` and :attr:`attributes`.  History lives in
    :class:`TimelineEvent` records keyed by ``record_fingerprint``.
    """

    fingerprint: str = Field(description="Stable identity hash")
    type: InformationType
    normalized_value: str
    original_value: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    status: RecordStatus = RecordStatus.ACTIVE
    first_seen_at: datetime
    last_seen_at: datetime
    source_executions: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    source_phases: list[str] = Field(default_factory=list)
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Provenance confidence (source trust x corroboration); set by the store",
    )


class TimelineEventType(StrEnum):
    """Classification of an append-only timeline entry."""

    CREATED = "created"
    REOBSERVED = "reobserved"
    UPDATED = "updated"
    RESOLVED = "resolved"
    MASKED = "masked"
    REINTRODUCED = "reintroduced"


class TimelineEvent(BaseModel):
    """Append-only history entry for an :class:`InformationRecord`."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    record_fingerprint: str
    event_type: TimelineEventType
    occurred_at: datetime = Field(default_factory=_utc_now)
    scan_id: str
    phase: str
    source_execution_id: str
    notes: str = ""
    delta: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional structured diff (e.g. attribute changes)",
    )


class RelationshipType(StrEnum):
    """Directed relationship between two :class:`InformationRecord` nodes.

    These edges turn the flat record set into a knowledge graph, enabling
    pivoting, relationship queries, and visualisation.  Endpoints are
    referenced by record fingerprint.
    """

    SUBDOMAIN_OF = "subdomain_of"  # subdomain -> apex domain
    RESOLVES_TO = "resolves_to"  # domain/subdomain -> ip
    HOSTED_ON = "hosted_on"  # service/host -> ip
    BELONGS_TO_ASN = "belongs_to_asn"  # ip -> ASN/org
    SHARES_CERT_WITH = "shares_cert_with"  # host <-> host (same cert)
    ISSUED_FOR = "issued_for"  # certificate -> domain
    RUNS_SERVICE = "runs_service"  # ip -> open port / service
    HAS_TECH = "has_tech"  # host -> technology fingerprint
    HAS_VULNERABILITY = "has_vulnerability"  # host/ip -> vulnerability
    OWNED_BY = "owned_by"  # domain/asn -> organization
    HAS_EMAIL = "has_email"  # organization/domain -> email
    EMPLOYS = "employs"  # organization -> person


class EdgeCandidate(BaseModel):
    """Transient relationship extracted by a translator (not persisted).

    The persistence layer deduplicates candidates into :class:`Edge`
    snapshots, mirroring the record candidate/record split.
    """

    model_config = ConfigDict(frozen=True)

    source_fingerprint: str = Field(description="Fingerprint of the source record")
    target_fingerprint: str = Field(description="Fingerprint of the target record")
    type: RelationshipType
    attributes: dict[str, Any] = Field(default_factory=dict)
    source_tool: str = Field(default="", description="Tool that produced the edge")
    phase: str = Field(default="", description="Phase that produced the edge")

    @property
    def edge_id(self) -> str:
        """Stable identity for this edge."""
        return _edge_fingerprint(self.source_fingerprint, self.type.value, self.target_fingerprint)


class Edge(BaseModel):
    """Persisted, deduplicated directed relationship in the knowledge graph."""

    model_config = ConfigDict(frozen=True)

    edge_id: str = Field(description="Stable identity hash of (source, type, target)")
    source_fingerprint: str
    target_fingerprint: str
    type: RelationshipType
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
    source_tools: list[str] = Field(default_factory=list)
    source_phases: list[str] = Field(default_factory=list)
