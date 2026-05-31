"""Evaluation harness — measure scan reliability (recall / precision / cost).

Deterministic, offline metrics computed from a finished scan's
:class:`~fackel.persistence.store.InformationStore` against a ground-truth
fixture.  Used to track recall/precision regressions over time without hitting
external services.
"""

from fackel.eval.metrics import (
    ScanMetrics,
    evaluate_store,
    prf,
    scan_cost_proxy,
)

__all__ = ["ScanMetrics", "evaluate_store", "prf", "scan_cost_proxy"]
