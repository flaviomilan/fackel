"""OSINT specialist — ReAct agent for passive reconnaissance.

The LLM decides which tools to invoke and interprets results.
Tools: dns_resolve, whois_lookup, shodan_lookup, dnsdumpster_lookup,
       virustotal_subdomain_enum, crtsh_subdomain_enum, reverse_dns_lookup.
"""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt
from tools.crtsh_tool import crtsh_subdomain_enum
from tools.dns_resolver import dns_resolve
from tools.dnsdumpster_tool import dnsdumpster_lookup
from tools.reverse_dns_tool import reverse_dns_lookup
from tools.shodan_tool import shodan_lookup
from tools.virustotal_tool import virustotal_subdomain_enum
from tools.whois import whois_lookup

TOOLS = [
    dns_resolve,
    whois_lookup,
    shodan_lookup,
    dnsdumpster_lookup,
    virustotal_subdomain_enum,
    crtsh_subdomain_enum,
    reverse_dns_lookup,
]


def build(model_name: str | None = None):
    """Return a compiled ReAct OSINT agent."""
    llm = ChatOpenAI(model=model_name or get_model("osint"))
    return create_react_agent(llm, TOOLS, prompt=load_prompt("osint"))
