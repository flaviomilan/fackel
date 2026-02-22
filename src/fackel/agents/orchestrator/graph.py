"""Orchestrator LangGraph definition.

Flow::

    osint ──→ approval_gate ──→ port_scan ──→ vuln_scan ──→ triage ──→ report ──→ END
          ↘ (passive / no IPs)                                        ↗
           ───────────────── report ─────────────────────────────────

    The approval_gate uses ``interrupt()`` for Human-in-the-Loop and
    redirects via ``Command(goto=...)`` — approved goes to port_scan,
    rejected skips to report.
"""

from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from .nodes import (
    approval_gate,
    osint_node,
    port_scan_node,
    report_node,
    route_after_osint,
    triage_node,
    vuln_scan_node,
)
from .state import ScanState

# In-memory checkpointer — enables state persistence across nodes,
# resume-after-failure, and replay.  Swap for a persistent store
# (e.g. SqliteSaver) when needed.
_checkpointer = MemorySaver()


def build_graph():
    """Construct and compile the orchestrator StateGraph."""
    graph = StateGraph(ScanState)

    graph.add_node("osint", osint_node)
    graph.add_node("approval_gate", approval_gate)
    graph.add_node("port_scan", port_scan_node)
    graph.add_node("vuln_scan", vuln_scan_node)
    graph.add_node("triage", triage_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("osint")

    # After OSINT: active + IPs → approval gate; else → report
    graph.add_conditional_edges(
        "osint",
        route_after_osint,
        {"approval_gate": "approval_gate", "report": "report"},
    )

    # approval_gate returns Command(goto=...) — no explicit edges needed.
    # port_scan → vuln_scan → triage → report (linear active chain)
    graph.add_edge("port_scan", "vuln_scan")
    graph.add_edge("vuln_scan", "triage")
    graph.add_edge("triage", "report")
    graph.add_edge("report", END)

    return graph.compile(checkpointer=_checkpointer)
