"""Vulnerability scan specialist — ReAct agent for infrastructure vuln scanning.

The LLM uses Nuclei to detect CVEs, misconfigurations, exposed panels,
and technologies on discovered hosts.  It chooses severity filters and
interprets results autonomously.
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt
from tools.nuclei_tool import nuclei_scan

TOOLS = [nuclei_scan]


def build(model_name: str | None = None):
    """Return a compiled ReAct vulnerability scan agent."""
    llm = ChatOpenAI(model=model_name or get_model("vuln_scan"))
    return create_react_agent(llm, TOOLS, prompt=load_prompt("vuln_scan"))
