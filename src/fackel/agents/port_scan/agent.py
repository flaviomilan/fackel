"""Port scan specialist — ReAct agent for active network scanning.

The LLM chooses which scanners to run and how to interpret their output.
Current MVP tools: naabu_scan (fast discovery), nmap_port_scan (deep analysis).
"""

from __future__ import annotations

import logging

from langchain.agents import create_agent
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph

from fackel.agents.config import build_llm, default_middleware
from fackel.prompts import compose_prompt
from fackel.tooling import available_binaries
from fackel.tools.scanning.naabu_tool import naabu_scan
from fackel.tools.scanning.nmap_scanner import nmap_port_scan

logger = logging.getLogger(__name__)

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
    available, missing_bins = available_binaries(TOOLS)
    for name, binary in missing_bins:
        logger.info("port_scan: skipping tool %s (binary %s not in PATH)", name, binary)
    llm = build_llm("port_scan", model_name=model_name)
    return create_agent(
        llm,
        available,
        system_prompt=compose_prompt(
            "port_scan",
            "tools/port_scanning",
            "contracts/nmap",
        ),
        middleware=default_middleware(approve_tools=approve_tools),
        checkpointer=MemorySaver() if approve_tools else None,
        name="port_scan",
    )
