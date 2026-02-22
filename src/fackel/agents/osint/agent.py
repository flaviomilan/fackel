"""OSINT specialist — ReAct agent for passive reconnaissance.

The LLM decides which tools to invoke and interprets results.
Tools available: dns_resolve, whois_lookup, shodan_lookup.
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt
from tools.dns_resolver import dns_resolve
from tools.shodan_tool import shodan_lookup
from tools.whois import whois_lookup

TOOLS = [dns_resolve, whois_lookup, shodan_lookup]


def build(model_name: str | None = None):
    """Return a compiled ReAct OSINT agent."""
    llm = ChatOpenAI(model=model_name or get_model("osint"))
    return create_react_agent(llm, TOOLS, prompt=load_prompt("osint"))
