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

import sqlite3
from pathlib import Path

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

_CHECKPOINT_DB = get_settings().checkpoint_db

Path(_CHECKPOINT_DB).parent.mkdir(parents=True, exist_ok=True)

_checkpointer = SqliteSaver(sqlite3.connect(_CHECKPOINT_DB, check_same_thread=False))


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

    return graph.compile(checkpointer=_checkpointer)
