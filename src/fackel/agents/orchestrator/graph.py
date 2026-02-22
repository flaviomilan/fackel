"""Orchestrator LangGraph definition.

Flow::

    osint ──→ [port_scan] ──→ report ──→ END
          conditional edge:
          active_scan=True → port_scan
          active_scan=False → report
"""

from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from .nodes import osint_node, port_scan_node, report_node, route_after_osint
from .state import ScanState

# In-memory checkpointer — enables state persistence across nodes,
# resume-after-failure, and replay.  Swap for a persistent store
# (e.g. SqliteSaver) when needed.
_checkpointer = MemorySaver()


def build_graph():
    """Construct and compile the orchestrator StateGraph."""
    graph = StateGraph(ScanState)

    graph.add_node("osint", osint_node)
    graph.add_node("port_scan", port_scan_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("osint")

    graph.add_conditional_edges(
        "osint",
        route_after_osint,
        {"port_scan": "port_scan", "report": "report"},
    )
    graph.add_edge("port_scan", "report")
    graph.add_edge("report", END)

    return graph.compile(checkpointer=_checkpointer)
