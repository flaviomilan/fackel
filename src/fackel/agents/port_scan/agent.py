"""Port scan specialist — ReAct agent for active network scanning.

The LLM chooses which scanners to run and how to interpret their output.
Current MVP tools: naabu_scan (fast discovery), nmap_port_scan (deep analysis).
"""

from __future__ import annotations

from langgraph.graph.state import CompiledStateGraph

from fackel.agents.config import build_react_agent
from fackel.tools.scanning.naabu_tool import naabu_scan
from fackel.tools.scanning.nmap_scanner import nmap_port_scan

TOOLS = [naabu_scan, nmap_port_scan]


def build(
    model_name: str | None = None,
    *,
    approve_tools: bool = False,
) -> CompiledStateGraph:  # type: ignore[type-arg]
    """Return a compiled ReAct port-scan agent.

    Parameters
    ----------
    approve_tools:
        When ``True``, wraps active scanning tools with
        ``HumanInTheLoopMiddleware`` so each tool call requires explicit
        human approval before execution.
    """
    agent = build_react_agent(
        "port_scan",
        TOOLS,
        "tools/port_scanning",
        "contracts/nmap",
        approve_tools=approve_tools,
        model_name=model_name,
    )
    if agent is None:  # pragma: no cover - phase tools are always available
        raise RuntimeError("agent build returned no agent (no tools available)")
    return agent
