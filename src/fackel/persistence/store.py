"""JSONL-backed :class:`InformationStore`.

Single-writer-per-scan; safe for sequential graph execution.  No
file-locking is performed because the orchestrator runs one scan per
process and each scan owns its own directory.
"""

from __future__ import annotations

import contextvars
import json
import logging
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fackel.confidence import score_confidence
from fackel.domain import (
    Edge,
    EdgeCandidate,
    InformationCandidate,
    InformationRecord,
    InformationType,
    RecordStatus,
    RelationshipType,
    TimelineEvent,
    TimelineEventType,
    ToolExecution,
)

logger = logging.getLogger(__name__)


_EXECUTIONS_FILE = "executions.jsonl"
_RECORDS_FILE = "records.jsonl"
_TIMELINE_FILE = "timeline.jsonl"
_EDGES_FILE = "edges.jsonl"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _serialize(payload: Any) -> str:
    """Serialise *payload* to a single JSON line (no trailing newline)."""
    data = payload.model_dump(mode="json") if hasattr(payload, "model_dump") else payload
    return json.dumps(data, separators=(",", ":"), default=str)


class InformationStore:
    """Append-only JSONL store for a single scan.

    All write operations are serialised through an internal
    :class:`threading.Lock` so concurrent specialist agents within the
    same scan can safely call into the store.
    """

    def __init__(self, scan_id: str, base_dir: Path) -> None:
        self.scan_id = scan_id
        self.scan_dir = base_dir / scan_id
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self._executions_path = self.scan_dir / _EXECUTIONS_FILE
        self._records_path = self.scan_dir / _RECORDS_FILE
        self._timeline_path = self.scan_dir / _TIMELINE_FILE
        self._edges_path = self.scan_dir / _EDGES_FILE
        self._lock = threading.Lock()
        self._records: dict[str, InformationRecord] = {}
        self._edges: dict[str, Edge] = {}
        self._executed_tools: set[str] = set()
        self._load_existing_records()
        self._load_existing_edges()
        self._load_executed_tools()

    # ------------------------------------------------------------------
    # Loading

    def _load_existing_records(self) -> None:
        """Hydrate the in-memory record cache from the JSONL snapshot."""
        if not self._records_path.exists():
            return
        try:
            with self._records_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    raw = json.loads(line)
                    record = InformationRecord.model_validate(raw)
                    self._records[record.fingerprint] = record
        except (OSError, json.JSONDecodeError, ValueError):
            logger.warning(
                "store: failed to hydrate records for scan %s — starting empty",
                self.scan_id,
                exc_info=True,
            )
            self._records.clear()

    def _load_existing_edges(self) -> None:
        """Hydrate the in-memory edge cache from the JSONL snapshot."""
        if not self._edges_path.exists():
            return
        try:
            with self._edges_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    edge = Edge.model_validate(json.loads(line))
                    self._edges[edge.edge_id] = edge
        except (OSError, json.JSONDecodeError, ValueError):
            logger.warning(
                "store: failed to hydrate edges for scan %s — starting empty",
                self.scan_id,
                exc_info=True,
            )
            self._edges.clear()

    def _load_executed_tools(self) -> None:
        """Hydrate the set of already-executed tool names from the snapshot."""
        if not self._executions_path.exists():
            return
        try:
            with self._executions_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    name = json.loads(line).get("tool_name")
                    if name:
                        self._executed_tools.add(str(name))
        except (OSError, json.JSONDecodeError, ValueError):
            logger.warning(
                "store: failed to hydrate executed tools for scan %s",
                self.scan_id,
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Writers

    def record_execution(self, execution: ToolExecution) -> None:
        """Append a :class:`ToolExecution` to ``executions.jsonl``."""
        with self._lock:
            self._executed_tools.add(execution.tool_name)
            self._append(self._executions_path, execution)

    def ingest(
        self,
        candidates: list[InformationCandidate],
        *,
        phase: str,
    ) -> list[InformationRecord]:
        """Deduplicate *candidates* into :class:`InformationRecord` snapshots.

        For each candidate:

        - If a record with the same fingerprint exists, it is *updated*
          (``last_seen_at`` bumped, source lists extended, attributes
          merged) and a ``REOBSERVED`` :class:`TimelineEvent` is appended.
        - Otherwise, a new record is created and a ``CREATED`` event is
          appended.

        Returns the list of resulting records (one per unique fingerprint
        seen in this batch), in insertion order.
        """
        seen: dict[str, InformationRecord] = {}
        with self._lock:
            for candidate in candidates:
                fp = candidate.fingerprint
                if fp in seen:
                    # Same fingerprint twice in the same batch — already merged.
                    continue
                existing = self._records.get(fp)
                if existing is None:
                    record = self._create_record(candidate, phase)
                    event_type = TimelineEventType.CREATED
                else:
                    record = self._update_record(existing, candidate, phase)
                    # UPDATED when the re-observation actually changed the record
                    # (new source, confidence shift, attributes); else REOBSERVED.
                    changed = (
                        existing.attributes != record.attributes
                        or existing.confidence != record.confidence
                        or existing.status != record.status
                        or set(existing.source_tools) != set(record.source_tools)
                    )
                    event_type = (
                        TimelineEventType.UPDATED if changed else TimelineEventType.REOBSERVED
                    )
                self._records[fp] = record
                self._append(self._records_path, record)
                self._append(
                    self._timeline_path,
                    TimelineEvent(
                        event_id=uuid.uuid4().hex,
                        record_fingerprint=fp,
                        event_type=event_type,
                        scan_id=self.scan_id,
                        phase=phase,
                        source_execution_id=candidate.source_execution_id,
                    ),
                )
                seen[fp] = record
        return list(seen.values())

    def ingest_edges(
        self,
        candidates: list[EdgeCandidate],
        *,
        phase: str,
    ) -> list[Edge]:
        """Deduplicate edge *candidates* into :class:`Edge` snapshots.

        Mirrors :meth:`ingest`: an edge seen again bumps ``last_seen_at`` and
        extends its source-tool/phase lists; a new edge is created.  Returns
        the resulting edges (one per unique ``edge_id`` in this batch).
        """
        seen: dict[str, Edge] = {}
        with self._lock:
            for candidate in candidates:
                eid = candidate.edge_id
                if eid in seen:
                    continue
                existing = self._edges.get(eid)
                edge = (
                    self._create_edge(candidate, phase)
                    if existing is None
                    else self._update_edge(existing, candidate, phase)
                )
                self._edges[eid] = edge
                self._append(self._edges_path, edge)
                seen[eid] = edge
        return list(seen.values())

    # ------------------------------------------------------------------
    # Readers

    def all_records(self) -> list[InformationRecord]:
        """Return all known records (in fingerprint-insertion order)."""
        with self._lock:
            return list(self._records.values())

    def records_by_phase(self, phase: str) -> list[InformationRecord]:
        """Return records that were ever observed in *phase*."""
        with self._lock:
            return [r for r in self._records.values() if phase in r.source_phases]

    def records_by_type(self, info_type: InformationType) -> list[InformationRecord]:
        """Return records whose semantic type equals *info_type*."""
        with self._lock:
            return [r for r in self._records.values() if r.type == info_type]

    def all_edges(self) -> list[Edge]:
        """Return all relationship edges (in insertion order)."""
        with self._lock:
            return list(self._edges.values())

    def edges_by_type(self, rel_type: RelationshipType) -> list[Edge]:
        """Return edges whose relationship type equals *rel_type*."""
        with self._lock:
            return [e for e in self._edges.values() if e.type == rel_type]

    def neighbors(self, fingerprint: str) -> list[Edge]:
        """Return edges incident to *fingerprint* (as source or target)."""
        with self._lock:
            return [
                e
                for e in self._edges.values()
                if fingerprint in (e.source_fingerprint, e.target_fingerprint)
            ]

    def tools_executed(self) -> set[str]:
        """Return the set of tool names executed so far in this scan."""
        with self._lock:
            return set(self._executed_tools)

    # ------------------------------------------------------------------
    # Internals

    @staticmethod
    def _create_record(candidate: InformationCandidate, phase: str) -> InformationRecord:
        now = _utc_now()
        tools = [candidate.source_tool]
        return InformationRecord(
            fingerprint=candidate.fingerprint,
            type=candidate.type,
            normalized_value=candidate.normalized_value,
            original_value=candidate.original_value,
            attributes=dict(candidate.attributes),
            status=RecordStatus.ACTIVE,
            first_seen_at=now,
            last_seen_at=now,
            source_executions=[candidate.source_execution_id],
            source_tools=tools,
            source_phases=[phase],
            confidence=score_confidence(tools),
        )

    @staticmethod
    def _update_record(
        existing: InformationRecord,
        candidate: InformationCandidate,
        phase: str,
    ) -> InformationRecord:
        merged_attrs = {**existing.attributes, **candidate.attributes}
        executions = list(existing.source_executions)
        if candidate.source_execution_id not in executions:
            executions.append(candidate.source_execution_id)
        tools = list(existing.source_tools)
        if candidate.source_tool not in tools:
            tools.append(candidate.source_tool)
        phases = list(existing.source_phases)
        if phase not in phases:
            phases.append(phase)
        return existing.model_copy(
            update={
                "attributes": merged_attrs,
                "last_seen_at": _utc_now(),
                "source_executions": executions,
                "source_tools": tools,
                "source_phases": phases,
                "confidence": score_confidence(tools),
            }
        )

    @staticmethod
    def _create_edge(candidate: EdgeCandidate, phase: str) -> Edge:
        now = _utc_now()
        return Edge(
            edge_id=candidate.edge_id,
            source_fingerprint=candidate.source_fingerprint,
            target_fingerprint=candidate.target_fingerprint,
            type=candidate.type,
            attributes=dict(candidate.attributes),
            first_seen_at=now,
            last_seen_at=now,
            source_tools=[candidate.source_tool] if candidate.source_tool else [],
            source_phases=[phase],
        )

    @staticmethod
    def _update_edge(existing: Edge, candidate: EdgeCandidate, phase: str) -> Edge:
        merged_attrs = {**existing.attributes, **candidate.attributes}
        tools = list(existing.source_tools)
        if candidate.source_tool and candidate.source_tool not in tools:
            tools.append(candidate.source_tool)
        phases = list(existing.source_phases)
        if phase not in phases:
            phases.append(phase)
        return existing.model_copy(
            update={
                "attributes": merged_attrs,
                "last_seen_at": _utc_now(),
                "source_tools": tools,
                "source_phases": phases,
            }
        )

    @staticmethod
    def _append(path: Path, payload: Any) -> None:
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(_serialize(payload))
                fh.write("\n")
        except OSError:
            logger.warning("store: failed to append to %s", path, exc_info=True)


# ----------------------------------------------------------------------
# Per-scan binding via contextvar (mirrors ``current_scan_id``)


current_store: contextvars.ContextVar[InformationStore | None] = contextvars.ContextVar(
    "fackel_current_information_store",
    default=None,
)


def get_current_store() -> InformationStore | None:
    """Return the store bound to the current scan, if any."""
    return current_store.get()


class bind_store_for_scan:  # noqa: N801 — context-manager naming preferred
    """Context manager that binds an :class:`InformationStore` for the scan.

    Mirrors the ``current_scan_id`` ContextVar pattern in
    :mod:`fackel.agents.orchestrator.streaming` so graph nodes — whose
    signature is fixed — can pick up the store without explicit
    parameter threading.
    """

    def __init__(self, scan_id: str, base_dir: Path) -> None:
        self.store = InformationStore(scan_id, base_dir)
        self._token: contextvars.Token[InformationStore | None] | None = None

    def __enter__(self) -> InformationStore:
        self._token = current_store.set(self.store)
        return self.store

    def __exit__(self, *exc: object) -> None:
        if self._token is not None:
            current_store.reset(self._token)
            self._token = None
