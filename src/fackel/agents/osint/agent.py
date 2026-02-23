"""OSINT specialist — ReAct agent for passive reconnaissance.

The LLM decides which tools to invoke and interprets results.
Tools that require API keys are automatically excluded when the key
is not configured (see ``fackel.provider_keys``).
"""

from __future__ import annotations

import logging

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt
from fackel.provider_keys import filter_tools
from tools.censys_tool import censys_lookup
from tools.crtsh_tool import crtsh_subdomain_enum
from tools.dns_resolver import dns_resolve
from tools.dnsdumpster_tool import dnsdumpster_lookup
from tools.email_analyzer import analyze_email
from tools.job_search import job_search
from tools.reverse_dns_tool import reverse_dns_lookup
from tools.shodan_tool import shodan_lookup
from tools.subfinder_tool import subfinder_enum
from tools.virustotal_tool import virustotal_subdomain_enum
from tools.whois import whois_lookup

logger = logging.getLogger(__name__)

TOOLS = [
    dns_resolve,
    whois_lookup,
    shodan_lookup,
    censys_lookup,
    dnsdumpster_lookup,
    virustotal_subdomain_enum,
    crtsh_subdomain_enum,
    subfinder_enum,
    reverse_dns_lookup,
    job_search,
    analyze_email,
]


def build(model_name: str | None = None):
    """Return a compiled ReAct OSINT agent.

    Tools whose provider API key is missing are silently removed so the
    LLM never wastes a call on a tool that would only return an error.
    """
    available, skipped = filter_tools(TOOLS)
    for name, provider, _vars in skipped:
        logger.info("osint: skipping tool %s (%s key not configured)", name, provider)
    llm = ChatOpenAI(model=model_name or get_model("osint"))
    return create_react_agent(llm, available, prompt=load_prompt("osint"))
