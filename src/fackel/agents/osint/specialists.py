"""OSINT specialist sub-agents.

Instead of one monolithic agent juggling all 31 OSINT tools (context overload,
lossy single summary), OSINT runs as a set of **focused specialists**, each with
a narrow toolset and a domain-specific task.  Every specialist persists its
structured output to the same :class:`InformationStore`, so the knowledge graph
(and therefore the report) accumulates the full picture regardless of how the
work is split.

Specialisation is enforced two ways: each agent physically holds only its
domain's tools, and its task message restricts it to that domain.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Any

from langchain.agents import create_agent

from fackel.agents.config import build_llm, default_middleware
from fackel.agents.osint.agent import TOOLS as _OSINT_TOOLS
from fackel.prompts import compose_prompt
from fackel.provider_keys import filter_tools
from fackel.tooling import available_binaries

logger = logging.getLogger(__name__)

_BY_NAME: dict[str, Any] = {getattr(t, "name", ""): t for t in _OSINT_TOOLS}


@dataclass(frozen=True)
class Specialist:
    """A focused OSINT sub-agent: a domain, a task focus, and its tools."""

    name: str
    focus: str
    tool_names: tuple[str, ...]

    @property
    def tools(self) -> list[Any]:
        return [_BY_NAME[n] for n in self.tool_names if n in _BY_NAME]


SPECIALISTS: list[Specialist] = [
    Specialist(
        "dns_infra",
        "DNS resolution, WHOIS, reverse DNS, ASN / IP classification, IP "
        "reputation (scan-noise + abuse), and passive open-port / CVE data per IP",
        (
            "dns_resolve",
            "whois_lookup",
            "reverse_dns_lookup",
            "ipinfo_lookup",
            "bgp_lookup",
            "greynoise_lookup",
            "abuseipdb_lookup",
            "internetdb_lookup",
            "dnsx_resolve",
        ),
    ),
    Specialist(
        "subdomains",
        "subdomain enumeration from all sources, resolution + wildcard filtering, "
        "takeover detection, and TLS SAN harvesting",
        (
            "subfinder_enum",
            "amass_enum",
            "chaos_enum",
            "crtsh_subdomain_enum",
            "dnsdumpster_lookup",
            "virustotal_subdomain_enum",
            "dnsx_resolve",
            "subzy_check",
            "tlscert_lookup",
        ),
    ),
    Specialist(
        "scan_dbs",
        "passive scan databases (Shodan/Censys/FOFA/Netlas) and historical / cached intel",
        (
            "shodan_lookup",
            "censys_lookup",
            "fofa_search",
            "netlas_lookup",
            "securitytrails_history",
            "urlscan_search",
            "otx_passive_dns",
        ),
    ),
    Specialist(
        "web_tech",
        "HTTP/TLS fingerprinting and web technology detection",
        ("httpx_scan", "whatweb_scan"),
    ),
    Specialist(
        "surface_urls",
        "URL / endpoint / parameter discovery, public document dorking, and "
        "cloud resource enumeration",
        (
            "gau_urls",
            "paramspider_crawl",
            "linkfinder_extract",
            "document_search",
            "cloudbrute_enum",
        ),
    ),
    Specialist(
        "secrets_code",
        "public code discovery and secret/credential exposure",
        ("github_repo_discovery", "trufflehog_scan", "js_secret_scan"),
    ),
    Specialist(
        "people",
        "people, email, breach exposure, and organisation intelligence",
        ("hunter_email_search", "analyze_email", "breach_lookup", "job_search"),
    ),
    Specialist(
        "social",
        "username and social-account discovery across web platforms (semi-passive; opt-in)",
        ("maigret_scan",),
    ),
]


SPECIALISTS_BY_NAME: dict[str, Specialist] = {s.name: s for s in SPECIALISTS}


@functools.lru_cache(maxsize=32)
def build_specialist(spec: Specialist, model_name: str | None = None) -> Any | None:
    """Build a focused ReAct agent for *spec*, or ``None`` if it has no usable tools.

    Cached per ``(spec, model)`` and reused across scans (the compiled agent is
    stateless); cleared by ``reset_orchestrator()``.  Tools whose API key or
    binary is unavailable are dropped (same gating as the full OSINT agent); a
    specialist left with no tools is skipped entirely.
    """
    available, _skipped = filter_tools(spec.tools)
    available, _missing = available_binaries(available)
    if not available:
        return None
    llm = build_llm("osint", model_name=model_name)
    return create_agent(
        llm,
        available,
        system_prompt=compose_prompt("osint"),
        middleware=default_middleware(),
        name=f"osint_{spec.name}",
    )


def _specialist_task(spec: Specialist, target: str) -> str:
    return (
        f"You are the **{spec.name}** OSINT specialist for the target: {target}.\n"
        f"Focus exclusively on: {spec.focus}.\n"
        "Use only your available tools (do not attempt anything outside your "
        "domain), be thorough, then produce a concise structured summary of your "
        "findings."
    )
