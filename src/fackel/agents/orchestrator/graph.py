"""Orchestrator LangGraph definition.

Flow::

    osint_guidance ──→ osint ──→ approval_gate ──→ port_scan_guidance ──→ port_scan
          ↘ (passive / no targets)                                      │
           ───────────── report ───────────────────────────────────────  │
                                                                        │
    ┌───────────────────────────────────────────────────────────────────┘
    ├──→ vuln_scan_guidance ──→ vuln_scan ──→ triage ──→ report ──→ END
    │                                                    ↗
    └──→ triage ────────────────────────────────────────

    Guidance gates (osint_guidance, port_scan_guidance, vuln_scan_guidance)
    use ``interrupt()`` to optionally collect operator instructions.  When
    guidance is disabled (the default), they return immediately.

    The approval_gate uses ``interrupt()`` for Human-in-the-Loop and
    redirects via ``Command(goto=...)`` — approved goes to port_scan_guidance,
    rejected skips to report.

    After port_scan, an LLM-as-a-judge evaluation decides whether to
    proceed to vuln_scan_guidance (default) or skip straight to triage
    when the port scan produced no actionable data.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from .nodes import (
    approval_gate,
    osint_guidance,
    osint_node,
    port_scan_guidance,
    port_scan_node,
    report_node,
    route_after_osint,
    route_after_port_scan,
    triage_node,
    vuln_scan_guidance,
    vuln_scan_node,
)
from .state import ScanState

_DEFAULT_CHECKPOINT_DIR = Path.home() / ".fackel"
_CHECKPOINT_DB = os.getenv(
    "FACKEL_CHECKPOINT_DB",
    str(_DEFAULT_CHECKPOINT_DIR / "checkpoints.db"),
)

_db_path = Path(_CHECKPOINT_DB)
_db_path.parent.mkdir(parents=True, exist_ok=True)
# Restrict checkpoint DB/dir permissions — contains scan state, targets, findings.
_db_path.parent.chmod(0o700)

_checkpointer = SqliteSaver(sqlite3.connect(_CHECKPOINT_DB, check_same_thread=False))

# Set restrictive permissions on the DB file itself once it exists.
if _db_path.exists():
    _db_path.chmod(0o600)


def build_graph() -> CompiledStateGraph:  # type: ignore[type-arg]
    """Construct and compile the orchestrator StateGraph."""
    graph = StateGraph(ScanState)

    graph.add_node("osint_guidance", osint_guidance)
    graph.add_node("osint", osint_node)
    graph.add_node("approval_gate", approval_gate)
    graph.add_node("port_scan_guidance", port_scan_guidance)
    graph.add_node("port_scan", port_scan_node)
    graph.add_node("vuln_scan_guidance", vuln_scan_guidance)
    graph.add_node("vuln_scan", vuln_scan_node)
    graph.add_node("triage", triage_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("osint_guidance")
    graph.add_edge("osint_guidance", "osint")

    graph.add_conditional_edges(
        "osint",
        route_after_osint,
        {"approval_gate": "approval_gate", "report": "report"},
    )

    graph.add_edge("port_scan_guidance", "port_scan")

    graph.add_conditional_edges(
        "port_scan",
        route_after_port_scan,
        {"vuln_scan": "vuln_scan_guidance", "triage": "triage"},
    )

    graph.add_edge("vuln_scan_guidance", "vuln_scan")
    graph.add_edge("vuln_scan", "triage")
    graph.add_edge("triage", "report")
    graph.add_edge("report", END)

    return graph.compile(checkpointer=_checkpointer)
