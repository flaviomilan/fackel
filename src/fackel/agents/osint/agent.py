"""OSINT specialist — ReAct agent for passive reconnaissance.

The LLM decides which tools to invoke and interprets results.
Current MVP tools: dns_resolve.  Adding more (whois, shodan passive,
virustotal, etc.) only requires appending to ``TOOLS``.
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from tools.dns_resolver import dns_resolve

SYSTEM_PROMPT = """\
You are a passive OSINT reconnaissance agent for the Fackel pentest framework.

## Task
Given a target (domain or IP), discover associated infrastructure using
only passive techniques.

## Guidelines
- Use dns_resolve to discover IP addresses for domains.
- If the target is already an IP, validate it with dns_resolve and note it.
- Never perform active scanning (no port probes, no HTTP requests).
- End with a **structured summary** listing every discovered IP and domain.
"""

TOOLS = [dns_resolve]


def build(model_name: str | None = None):
    """Return a compiled ReAct OSINT agent."""
    llm = ChatOpenAI(model=model_name or get_model("osint"))
    return create_react_agent(llm, TOOLS, prompt=SYSTEM_PROMPT)
