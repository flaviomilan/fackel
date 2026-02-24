"""Port scan specialist — ReAct agent for active network scanning.

The LLM chooses which scanners to run and how to interpret their output.
Current MVP tools: naabu_scan (fast discovery), nmap_port_scan (deep analysis).
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt
from tools.scanning.naabu_tool import naabu_scan
from tools.scanning.nmap_scanner import nmap_port_scan

TOOLS = [naabu_scan, nmap_port_scan]


def build(model_name: str | None = None):
    """Return a compiled ReAct port-scan agent."""
    llm = ChatOpenAI(model=model_name or get_model("port_scan"))
    return create_react_agent(llm, TOOLS, prompt=load_prompt("port_scan"))
