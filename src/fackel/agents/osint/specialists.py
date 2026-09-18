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
from typing import Any

from fackel.agents._specialist import Specialist, specialist_task
from fackel.agents.config import build_react_agent
from fackel.agents.osint.agent import TOOLS as _OSINT_TOOLS

_BY_NAME: dict[str, Any] = {getattr(t, "name", ""): t for t in _OSINT_TOOLS}


def _spec(name: str, focus: str, tool_names: tuple[str, ...]) -> Specialist:
    return Specialist(name, focus, tool_names, _BY_NAME)


SPECIALISTS: list[Specialist] = [
    _spec(
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
    _spec(
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
    _spec(
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
    _spec(
        "web_tech",
        "HTTP/TLS fingerprinting and web technology detection",
        ("httpx_scan", "whatweb_scan"),
    ),
    _spec(
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
    _spec(
        "secrets_code",
        "public code discovery and secret/credential exposure",
        ("github_repo_discovery", "trufflehog_scan", "js_secret_scan"),
    ),
    _spec(
        "people",
        "people, email, breach exposure, and organisation intelligence",
        ("hunter_email_search", "analyze_email", "breach_lookup", "job_search"),
    ),
    _spec(
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
    return build_react_agent(
        "osint",
        spec.tools,
        name=f"osint_{spec.name}",
        model_name=model_name,
        require_tools=True,
        log_skips=False,
    )


def _specialist_task(spec: Specialist, target: str) -> str:
    return specialist_task(spec.name, spec.focus, "OSINT", target=target)
