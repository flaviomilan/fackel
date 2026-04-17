"""OSINT specialist — ReAct agent for passive reconnaissance.

The LLM decides which tools to invoke and interprets results.
Tools that require API keys are automatically excluded when the key
is not configured (see ``fackel.provider_keys``).
"""

from __future__ import annotations

import functools
import logging

from langchain.agents import create_agent
from langgraph.graph.state import CompiledStateGraph

from fackel.agents.config import build_llm, default_middleware
from fackel.prompts import compose_prompt
from fackel.provider_keys import filter_tools
from fackel.tooling import available_binaries
from fackel.tools.osint.email_analyzer import analyze_email
from fackel.tools.osint.github_repos import github_repo_discovery
from fackel.tools.osint.hunter_tool import hunter_email_search
from fackel.tools.osint.job_search import job_search
from fackel.tools.osint.js_secret_scanner import js_secret_scan
from fackel.tools.osint.trufflehog_tool import trufflehog_scan
from fackel.tools.recon.amass_tool import amass_enum
from fackel.tools.recon.bgpview_tool import bgp_lookup
from fackel.tools.recon.censys_tool import censys_lookup
from fackel.tools.recon.cloudbrute_tool import cloudbrute_enum
from fackel.tools.recon.crtsh_tool import crtsh_subdomain_enum
from fackel.tools.recon.dns_resolver import dns_resolve
from fackel.tools.recon.dnsdumpster_tool import dnsdumpster_lookup
from fackel.tools.recon.dnsx_tool import dnsx_resolve
from fackel.tools.recon.fofa_tool import fofa_search
from fackel.tools.recon.gau_tool import gau_urls
from fackel.tools.recon.internetdb_tool import internetdb_lookup
from fackel.tools.recon.ipinfo_tool import ipinfo_lookup
from fackel.tools.recon.linkfinder_tool import linkfinder_extract
from fackel.tools.recon.otx_tool import otx_passive_dns
from fackel.tools.recon.paramspider_tool import paramspider_crawl
from fackel.tools.recon.reverse_dns_tool import reverse_dns_lookup
from fackel.tools.recon.securitytrails_tool import securitytrails_history
from fackel.tools.recon.shodan_tool import shodan_lookup
from fackel.tools.recon.subfinder_tool import subfinder_enum
from fackel.tools.recon.subzy_tool import subzy_check
from fackel.tools.recon.tlscert_tool import tlscert_lookup
from fackel.tools.recon.urlscan_tool import urlscan_search
from fackel.tools.recon.virustotal_tool import virustotal_subdomain_enum
from fackel.tools.recon.whatweb_tool import whatweb_scan
from fackel.tools.recon.whois import whois_lookup
from fackel.tools.scanning.httpx_tool import httpx_scan

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
    dnsx_resolve,
    subzy_check,
    gau_urls,
    paramspider_crawl,
    reverse_dns_lookup,
    ipinfo_lookup,
    internetdb_lookup,
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
    js_secret_scan,
    job_search,
    hunter_email_search,
    analyze_email,
    github_repo_discovery,
]


@functools.lru_cache(maxsize=4)
def build(model_name: str | None = None) -> CompiledStateGraph:  # type: ignore[type-arg]
    """Return a compiled ReAct OSINT agent (cached per model).

    Compiling a ReAct agent is non-trivial, and the agent is stateless across
    invocations (conversation state is passed in at ``invoke``/``stream`` time),
    so the compiled graph is cached and reused — cleared by
    ``reset_orchestrator()`` when tool/key availability may have changed.

    Tools whose provider API key is missing are silently removed so the
    LLM never wastes a call on a tool that would only return an error.
    """
    available, skipped = filter_tools(TOOLS)
    for name, provider, _vars in skipped:
        logger.info("osint: skipping tool %s (%s key not configured)", name, provider)
    available, missing_bins = available_binaries(available)
    for name, binary in missing_bins:
        logger.info("osint: skipping tool %s (binary %s not in PATH)", name, binary)
    llm = build_llm("osint", model_name=model_name)
    return create_agent(
        llm,
        available,
        # The OSINT skill is self-contained — playbook, signals/anomalies, and
        # quality bar are folded into skills/osint.md, and per-tool parameter
        # details are already visible to the LLM via each tool's schema. No
        # supplementary sections are composed, keeping the prompt lean in both
        # the full and compact profiles.
        system_prompt=compose_prompt("osint"),
        middleware=default_middleware(),
        name="osint",
    )
