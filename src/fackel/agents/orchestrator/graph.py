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
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from fackel.settings import get_settings

from .nodes import (
    approval_gate,
    dispatch_osint_specialists,
    dispatch_vuln_specialists,
    osint_collect_node,
    osint_node,
    osint_specialist_node,
    port_scan_node,
    report_node,
    review_node,
    route_after_osint,
    route_after_port_scan,
    triage_node,
    vuln_collect_node,
    vuln_dispatch_node,
    vuln_scan_node,
    vuln_specialist_node,
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
    """Construct and compile the orchestrator StateGraph.

    OSINT runs either as parallel specialist sub-agents (``Send`` fan-out →
    ``osint_collect``) or as a single monolithic agent, per
    ``FACKEL_OSINT_SPECIALISTS``.  Both converge on ``route_after_osint``.

    Vuln scanning likewise runs as a parallel specialist fan-out (``vuln_dispatch``
    → ``Send`` → ``vuln_specialist`` → ``vuln_collect``) per ``FACKEL_VULN_SPECIALISTS``,
    or as the monolithic ``vuln_scan`` agent.  ``route_after_port_scan`` picks the
    entry node; per-tool HITL approval forces the monolithic path.
    """
    graph = StateGraph(ScanState)

    graph.add_node("approval_gate", approval_gate)
    graph.add_node("port_scan", port_scan_node)
    # The monolithic vuln agent is always present: it is the fallback when
    # specialists are disabled and the forced path under per-tool HITL approval.
    graph.add_node("vuln_scan", vuln_scan_node)
    graph.add_node("triage", triage_node)
    graph.add_node("report", report_node)
    graph.add_node("review", review_node)

    if get_settings().osint_specialists:
        # Parallel fan-out: START dispatches one Send per specialist; they run
        # concurrently, then fan in at osint_collect (single post-barrier node).
        graph.add_node("osint_specialist", osint_specialist_node)
        graph.add_node("osint_collect", osint_collect_node)
        graph.add_conditional_edges(START, dispatch_osint_specialists, ["osint_specialist"])
        graph.add_edge("osint_specialist", "osint_collect")
        graph.add_conditional_edges(
            "osint_collect",
            route_after_osint,
            {"approval_gate": "approval_gate", "report": "report"},
        )
    else:
        graph.add_node("osint", osint_node)
        graph.set_entry_point("osint")
        graph.add_conditional_edges(
            "osint",
            route_after_osint,
            {"approval_gate": "approval_gate", "report": "report"},
        )

    if get_settings().vuln_specialists:
        # Parallel fan-out: vuln_dispatch builds shared context, then one Send per
        # specialist runs concurrently and fans in at vuln_collect.  route_after_
        # port_scan still picks the monolithic vuln_scan node under HITL approval.
        graph.add_node("vuln_dispatch", vuln_dispatch_node)
        graph.add_node("vuln_specialist", vuln_specialist_node)
        graph.add_node("vuln_collect", vuln_collect_node)
        graph.add_conditional_edges(
            "port_scan",
            route_after_port_scan,
            {"vuln_dispatch": "vuln_dispatch", "vuln_scan": "vuln_scan", "triage": "triage"},
        )
        graph.add_conditional_edges("vuln_dispatch", dispatch_vuln_specialists, ["vuln_specialist"])
        graph.add_edge("vuln_specialist", "vuln_collect")
        graph.add_edge("vuln_collect", "triage")
    else:
        graph.add_conditional_edges(
            "port_scan",
            route_after_port_scan,
            {"vuln_scan": "vuln_scan", "triage": "triage"},
        )
    graph.add_edge("vuln_scan", "triage")
    graph.add_edge("triage", "report")
    graph.add_edge("report", "review")
    graph.add_edge("review", END)

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
