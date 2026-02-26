"""OSINT specialist — ReAct agent for passive reconnaissance.

The LLM decides which tools to invoke and interprets results.
Tools that require API keys are automatically excluded when the key
is not configured (see ``fackel.provider_keys``).
"""

from __future__ import annotations

import logging

from langchain.agents import create_agent
from langgraph.graph.state import CompiledStateGraph

from fackel.agents.config import build_llm, default_middleware
from fackel.agents.prompts import load_prompt
from fackel.provider_keys import filter_tools
from tools.osint.email_analyzer import analyze_email
from tools.osint.job_search import job_search
from tools.osint.trufflehog_tool import trufflehog_scan
from tools.recon.amass_tool import amass_enum
from tools.recon.bgpview_tool import bgp_lookup
from tools.recon.censys_tool import censys_lookup
from tools.recon.cloudbrute_tool import cloudbrute_enum
from tools.recon.crtsh_tool import crtsh_subdomain_enum
from tools.recon.dns_resolver import dns_resolve
from tools.recon.dnsdumpster_tool import dnsdumpster_lookup
from tools.recon.fofa_tool import fofa_search
from tools.recon.gau_tool import gau_urls
from tools.recon.ipinfo_tool import ipinfo_lookup
from tools.recon.linkfinder_tool import linkfinder_extract
from tools.recon.otx_tool import otx_passive_dns
from tools.recon.paramspider_tool import paramspider_crawl
from tools.recon.reverse_dns_tool import reverse_dns_lookup
from tools.recon.securitytrails_tool import securitytrails_history
from tools.recon.shodan_tool import shodan_lookup
from tools.recon.subfinder_tool import subfinder_enum
from tools.recon.subzy_tool import subzy_check
from tools.recon.tlscert_tool import tlscert_lookup
from tools.recon.urlscan_tool import urlscan_search
from tools.recon.virustotal_tool import virustotal_subdomain_enum
from tools.recon.whatweb_tool import whatweb_scan
from tools.recon.whois import whois_lookup
from tools.scanning.httpx_tool import httpx_scan

logger = logging.getLogger(__name__)

TOOLS = [
    dns_resolve,
    whois_lookup,
    shodan_lookup,
    censys_lookup,
    fofa_search,
    dnsdumpster_lookup,
    virustotal_subdomain_enum,
    crtsh_subdomain_enum,
    subfinder_enum,
    amass_enum,
    subzy_check,
    gau_urls,
    paramspider_crawl,
    reverse_dns_lookup,
    ipinfo_lookup,
    bgp_lookup,
    cloudbrute_enum,
    httpx_scan,
    whatweb_scan,
    linkfinder_extract,
    tlscert_lookup,
    securitytrails_history,
    urlscan_search,
    otx_passive_dns,
    trufflehog_scan,
    job_search,
    analyze_email,
]


def build(model_name: str | None = None) -> CompiledStateGraph:  # type: ignore[type-arg]
    """Return a compiled ReAct OSINT agent.

    Tools whose provider API key is missing are silently removed so the
    LLM never wastes a call on a tool that would only return an error.
    """
    available, skipped = filter_tools(TOOLS)
    for name, provider, _vars in skipped:
        logger.info("osint: skipping tool %s (%s key not configured)", name, provider)
    llm = build_llm("osint", model_name=model_name)
    return create_agent(
        llm,
        available,
        system_prompt=load_prompt("osint"),
        middleware=default_middleware(),
        name="osint",
    )
