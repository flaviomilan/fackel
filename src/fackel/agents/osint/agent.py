"""OSINT specialist — ReAct agent for passive reconnaissance.

The LLM decides which tools to invoke and interprets results.
Current MVP tools: dns_resolve.  Adding more (whois, shodan passive,
virustotal, etc.) only requires appending to ``TOOLS``.
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt
from tools.dns_resolver import dns_resolve

TOOLS = [dns_resolve]


def build(model_name: str | None = None):
    """Return a compiled ReAct OSINT agent."""
    llm = ChatOpenAI(model=model_name or get_model("osint"))
    return create_react_agent(llm, TOOLS, prompt=load_prompt("osint"))
