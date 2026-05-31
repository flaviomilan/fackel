"""Recall / precision / cost metrics for a finished scan.

Compares the normalized values a scan persisted (per :class:`InformationType`)
against a ground-truth fixture and reports precision, recall, and F1 — the core
signal for tracking whether changes improve or regress discovery quality.

Cost is reported as a deterministic *proxy* (tool executions, distinct tools,
record count) rather than a fabricated monetary figure, since Fackel does not
centrally meter token spend.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from fackel.domain import InformationType
from fackel.persistence.store import InformationStore


@dataclass(frozen=True)
class PRF:
    """Precision / recall / F1 with the underlying confusion counts."""

    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int


@dataclass(frozen=True)
class ScanMetrics:
    """Per-type and aggregate (micro-averaged) discovery metrics for a scan."""

    per_type: dict[str, PRF]
    overall: PRF
    cost: dict[str, int]


def _norm(values: Iterable[str]) -> set[str]:
    """Case-fold and strip so comparison is robust to incidental formatting."""
    return {v.strip().lower() for v in values if v and v.strip()}


def prf(found: Iterable[str], expected: Iterable[str]) -> PRF:
    """Precision/recall/F1 of *found* against *expected* (set comparison).

    Empty *expected* with empty *found* is a perfect score (1.0); a non-empty
    *found* against empty *expected* yields precision 0.
    """
    f, e = _norm(found), _norm(expected)
    tp = len(f & e)
    fp = len(f - e)
    fn = len(e - f)
    if tp == 0 and fp == 0 and fn == 0:
        return PRF(1.0, 1.0, 1.0, 0, 0, 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return PRF(round(precision, 3), round(recall, 3), round(f1, 3), tp, fp, fn)


def scan_cost_proxy(store: InformationStore) -> dict[str, int]:
    """Deterministic cost proxy: record count, distinct source tools, executions."""
    records = store.all_records()
    distinct_tools = {t for r in records for t in r.source_tools}
    executions = {e for r in records for e in r.source_executions}
    return {
        "records": len(records),
        "distinct_tools": len(distinct_tools),
        "executions": len(executions),
    }


def evaluate_store(
    store: InformationStore,
    ground_truth: Mapping[InformationType | str, Iterable[str]],
) -> ScanMetrics:
    """Score a finished scan's store against *ground_truth*.

    *ground_truth* maps each :class:`InformationType` (or its string value) to the
    set of expected normalized values.  Per-type PRF is computed for every type in
    the ground truth; ``overall`` is micro-averaged across all types.
    """
    per_type: dict[str, PRF] = {}
    g_tp = g_fp = g_fn = 0
    for raw_type, expected in ground_truth.items():
        info_type = raw_type if isinstance(raw_type, InformationType) else InformationType(raw_type)
        found = [r.normalized_value for r in store.records_by_type(info_type)]
        result = prf(found, expected)
        per_type[info_type.value] = result
        g_tp += result.tp
        g_fp += result.fp
        g_fn += result.fn

    # Micro-averaged overall from summed confusion counts.
    precision = g_tp / (g_tp + g_fp) if (g_tp + g_fp) else 1.0
    recall = g_tp / (g_tp + g_fn) if (g_tp + g_fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    overall = PRF(round(precision, 3), round(recall, 3), round(f1, 3), g_tp, g_fp, g_fn)

    return ScanMetrics(per_type=per_type, overall=overall, cost=scan_cost_proxy(store))
