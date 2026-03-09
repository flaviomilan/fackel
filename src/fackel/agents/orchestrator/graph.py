"""Orchestrator LangGraph definition.

Flow::

    osint ──→ approval_gate ──→ port_scan ─┬──→ vuln_scan ──→ triage ──→ report ──→ END
          ↘ (passive / no targets)         │                           ↗
           ───────────── report ───────────│── (skip_downstream) ─────
                                           └──→ triage ──→ report ──→ END

    The approval_gate uses ``interrupt()`` for Human-in-the-Loop and
    redirects via ``Command(goto=...)`` — approved goes to port_scan,
    rejected skips to report.

    After port_scan, an LLM-as-a-judge evaluation decides whether to
    proceed to vuln_scan (default) or skip straight to triage when
    the port scan produced no actionable data.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from fackel.settings import get_settings

from .nodes import (
    approval_gate,
    osint_node,
    port_scan_node,
    report_node,
    route_after_osint,
    route_after_port_scan,
    triage_node,
    vuln_scan_node,
)
from .state import ScanState

_checkpointer: SqliteSaver | None = None
_checkpointer_cm: Any = None  # context manager returned by from_conn_string


def _get_checkpointer() -> SqliteSaver:
    """Return the SQLite checkpointer, creating it lazily on first call.

    Uses ``from_conn_string`` for proper connection-pool management —
    the library handles ``check_same_thread=False`` and WAL mode
    internally, avoiding manual ``sqlite3.connect`` lifetime issues.

    The context manager is entered immediately and its reference kept in
    ``_checkpointer_cm`` so ``_reset_graph()`` can close it cleanly.
    """
    global _checkpointer, _checkpointer_cm
    if _checkpointer is None:
        db_path = get_settings().checkpoint_db
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        _checkpointer_cm = SqliteSaver.from_conn_string(db_path)
        _checkpointer = _checkpointer_cm.__enter__()
    return _checkpointer


def build_graph() -> CompiledStateGraph:  # type: ignore[type-arg]
    """Construct and compile the orchestrator StateGraph."""
    graph = StateGraph(ScanState)

    graph.add_node("osint", osint_node)
    graph.add_node("approval_gate", approval_gate)
    graph.add_node("port_scan", port_scan_node)
    graph.add_node("vuln_scan", vuln_scan_node)
    graph.add_node("triage", triage_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("osint")

    graph.add_conditional_edges(
        "osint",
        route_after_osint,
        {"approval_gate": "approval_gate", "report": "report"},
    )

    graph.add_conditional_edges(
        "port_scan",
        route_after_port_scan,
        {"vuln_scan": "vuln_scan", "triage": "triage"},
    )
    graph.add_edge("vuln_scan", "triage")
    graph.add_edge("triage", "report")
    graph.add_edge("report", END)

    return graph.compile(checkpointer=_get_checkpointer())


def _reset_graph() -> None:
    """Reset module-level graph state (checkpointer + main.py cache).

    Intended for tests that need a fresh graph between runs.
    Properly closes the context manager returned by ``from_conn_string``.
    """
    global _checkpointer, _checkpointer_cm
    if _checkpointer_cm is not None:
        with suppress(Exception):
            _checkpointer_cm.__exit__(None, None, None)
        _checkpointer_cm = None
    _checkpointer = None
