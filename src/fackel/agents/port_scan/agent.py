"""Port scan specialist — ReAct agent for active network scanning.

The LLM chooses which scanners to run and how to interpret their output.
Current MVP tools: naabu_scan (fast discovery), nmap_port_scan (deep analysis).
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from tools.naabu_tool import naabu_scan
from tools.nmap_scanner import nmap_port_scan

SYSTEM_PROMPT = """\
You are an active port-scanning agent for the Fackel pentest framework.

## Task
Scan target IP addresses for open ports and running services.

## Strategy
1. Use **naabu_scan** first for fast TCP port discovery on each target.
2. Then use **nmap_port_scan** for detailed service and version detection.

## Guidelines
- Focus on IPv4 addresses.  Skip IPv6 unless explicitly requested.
- When scanning multiple IPs, scan each one individually.
- If a tool fails, report the error and move on to the next target.
- End with a **structured summary** of open ports and services per host.
"""

TOOLS = [naabu_scan, nmap_port_scan]


def build(model_name: str | None = None):
    """Return a compiled ReAct port-scan agent."""
    llm = ChatOpenAI(model=model_name or get_model("port_scan"))
    return create_react_agent(llm, TOOLS, prompt=SYSTEM_PROMPT)
