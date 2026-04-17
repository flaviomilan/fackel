"""Cross-scan diffing — the basis for continuous monitoring.

Compares two :class:`InformationStore` snapshots (e.g. last week's scan vs
today's) and reports what changed: entities/relationships that **appeared**,
**disappeared** (resolved), or **changed** (new sources, confidence shift,
attribute updates).  Powers ``fackel diff`` and change alerting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from fackel.domain import Edge, InformationRecord
from fackel.persistence.store import InformationStore


@dataclass
class ScanDiff:
    """Structured difference between two scans (A = baseline, B = current)."""

    scan_a: str
    scan_b: str
    added_records: list[InformationRecord] = field(default_factory=list)
    removed_records: list[InformationRecord] = field(default_factory=list)
    changed_records: list[tuple[InformationRecord, InformationRecord]] = field(default_factory=list)
    added_edges: list[Edge] = field(default_factory=list)
    removed_edges: list[Edge] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added_records
            or self.removed_records
            or self.changed_records
            or self.added_edges
            or self.removed_edges
        )


def _record_changed(old: InformationRecord, new: InformationRecord) -> bool:
    """True if a record meaningfully changed between scans."""
    return (
        old.status != new.status
        or old.confidence != new.confidence
        or old.attributes != new.attributes
        or set(old.source_tools) != set(new.source_tools)
    )


def diff_scans(baseline: InformationStore, current: InformationStore) -> ScanDiff:
    """Compute the difference between two scan stores (baseline → current)."""
    a_recs = {r.fingerprint: r for r in baseline.all_records()}
    b_recs = {r.fingerprint: r for r in current.all_records()}

    added = [b_recs[fp] for fp in b_recs.keys() - a_recs.keys()]
    removed = [a_recs[fp] for fp in a_recs.keys() - b_recs.keys()]
    changed = [
        (a_recs[fp], b_recs[fp])
        for fp in a_recs.keys() & b_recs.keys()
        if _record_changed(a_recs[fp], b_recs[fp])
    ]

    a_edges = {e.edge_id: e for e in baseline.all_edges()}
    b_edges = {e.edge_id: e for e in current.all_edges()}
    added_edges = [b_edges[k] for k in b_edges.keys() - a_edges.keys()]
    removed_edges = [a_edges[k] for k in a_edges.keys() - b_edges.keys()]

    return ScanDiff(
        scan_a=baseline.scan_id,
        scan_b=current.scan_id,
        added_records=added,
        removed_records=removed,
        changed_records=changed,
        added_edges=added_edges,
        removed_edges=removed_edges,
    )


def load_scan(scan_id: str, base_dir: Path) -> InformationStore:
    """Load a prior scan's store read-only (hydrates records + edges)."""
    return InformationStore(scan_id, base_dir)


def list_scans(base_dir: Path) -> list[str]:
    """Return scan ids (sub-directories with a records file) under *base_dir*."""
    if not base_dir.exists():
        return []
    return sorted(
        p.name for p in base_dir.iterdir() if p.is_dir() and (p / "records.jsonl").exists()
    )


def format_diff(diff: ScanDiff) -> str:
    """Render a human-readable change summary."""
    lines = [f"Scan diff: {diff.scan_a} -> {diff.scan_b}"]
    if not diff.has_changes:
        lines.append("  No changes detected.")
        return "\n".join(lines)

    def _fmt(record: InformationRecord) -> str:
        return f"[{record.type.value}] {record.normalized_value} (confidence={record.confidence})"

    if diff.added_records:
        lines.append(f"\n  + New ({len(diff.added_records)}):")
        lines += [f"    + {_fmt(r)}" for r in diff.added_records]
    if diff.removed_records:
        lines.append(f"\n  - Resolved/gone ({len(diff.removed_records)}):")
        lines += [f"    - {_fmt(r)}" for r in diff.removed_records]
    if diff.changed_records:
        lines.append(f"\n  ~ Changed ({len(diff.changed_records)}):")
        for old, new in diff.changed_records:
            detail = ""
            if old.confidence != new.confidence:
                detail = f" confidence {old.confidence} -> {new.confidence}"
            lines.append(f"    ~ {_fmt(new)}{detail}")
    if diff.added_edges or diff.removed_edges:
        lines.append(f"\n  Relationships: +{len(diff.added_edges)} / -{len(diff.removed_edges)}")
    return "\n".join(lines)
