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

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

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

# In-memory checkpointer — enables state persistence across nodes,
# resume-after-failure, and replay.  Swap for a persistent store
# (e.g. SqliteSaver) when needed.
_checkpointer = MemorySaver()


def build_graph() -> CompiledStateGraph:
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
    # port_scan → judge-routed → vuln_scan | triage
    graph.add_conditional_edges(
        "port_scan",
        route_after_port_scan,
        {"vuln_scan": "vuln_scan", "triage": "triage"},
    )
    graph.add_edge("vuln_scan", "triage")
    graph.add_edge("triage", "report")
    graph.add_edge("report", END)

    return graph.compile(checkpointer=_checkpointer)
