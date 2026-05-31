"""Vuln-scan specialist sub-agents.

Instead of one monolithic agent juggling all vuln/scanning tools, the active
scan can run as a set of **focused specialists**, each with a narrow toolset and
a domain-specific task, fanned out in parallel via LangGraph ``Send``.

Tools are grouped so that aggressive brute-forcers (``feroxbuster``/``ffuf``) and
the heavy injection scanners share a single agent — they run *sequentially within*
that specialist rather than as separate parallel branches all hammering the target
at once.  Every specialist persists its output to the same :class:`InformationStore`,
so the report accumulates the full picture regardless of how the work is split.

Specialisation is enforced two ways: each agent physically holds only its domain's
tools, and its task message restricts it to that domain.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Any

from langchain.agents import create_agent

from fackel.agents.config import build_llm, default_middleware
from fackel.agents.vuln_scan.agent import _VULN_PROMPT_SECTIONS
from fackel.agents.vuln_scan.agent import TOOLS as _VULN_TOOLS
from fackel.prompts import compose_prompt
from fackel.provider_keys import filter_tools
from fackel.tooling import available_binaries

logger = logging.getLogger(__name__)

_BY_NAME: dict[str, Any] = {getattr(t, "name", ""): t for t in _VULN_TOOLS}


@dataclass(frozen=True)
class VulnSpecialist:
    """A focused vuln-scan sub-agent: a domain, a task focus, and its tools."""

    name: str
    focus: str
    tool_names: tuple[str, ...]

    @property
    def tools(self) -> list[Any]:
        return [_BY_NAME[n] for n in self.tool_names if n in _BY_NAME]


VULN_SPECIALISTS: list[VulnSpecialist] = [
    VulnSpecialist(
        "surface",
        "HTTP/TLS probing, WAF detection, crawling, content/endpoint discovery and "
        "cloud-bucket enumeration (run brute-forcers sparingly and one at a time)",
        (
            "httpx_scan",
            "wafw00f_detect",
            "katana_crawl",
            "extract_webpage_content",
            "feroxbuster_scan",
            "ffuf_scan",
            "s3scanner_scan",
        ),
    ),
    VulnSpecialist(
        "nuclei",
        "template-based vulnerability detection, prioritising templates for the "
        "technologies fingerprinted during OSINT",
        ("nuclei_scan",),
    ),
    VulnSpecialist(
        "web_injection",
        "injection and request-manipulation classes: SQLi, XSS, SSTI, SSRF, open "
        "redirect, and CORS misconfiguration",
        (
            "sqlmap_scan",
            "dalfox_scan",
            "ssti_scan",
            "ssrf_detect",
            "open_redirect_scan",
            "corsy_scan",
        ),
    ),
    VulnSpecialist(
        "app_config",
        "application- and configuration-level issues: WordPress, security headers, "
        "JWT weaknesses, and GraphQL exposure",
        ("wpscan_scan", "security_headers_audit", "jwt_analyzer", "graphql_scan"),
    ),
    VulnSpecialist(
        "tls",
        "TLS/SSL configuration and cryptographic weaknesses",
        ("testssl_scan",),
    ),
]


VULN_SPECIALISTS_BY_NAME: dict[str, VulnSpecialist] = {s.name: s for s in VULN_SPECIALISTS}


@functools.lru_cache(maxsize=32)
def build_vuln_specialist(spec: VulnSpecialist, model_name: str | None = None) -> Any | None:
    """Build a focused ReAct agent for *spec*, or ``None`` if it has no usable tools.

    Cached per ``(spec, model)`` and reused across scans (the compiled agent is
    stateless); cleared by ``reset_orchestrator()``.  Tools whose API key or binary
    is unavailable are dropped (same gating as the full vuln agent); a specialist
    left with no tools is skipped entirely.

    The parallel path never enables per-tool HITL approval (the monolithic agent is
    used instead when approval is on), so these specialists carry no approval
    middleware or checkpointer.
    """
    available, _skipped = filter_tools(spec.tools)
    available, _missing = available_binaries(available)
    if not available:
        return None
    llm = build_llm("vuln_scan", model_name=model_name)
    return create_agent(
        llm,
        available,
        system_prompt=compose_prompt("vuln_scan", *_VULN_PROMPT_SECTIONS),
        middleware=default_middleware(),
        name=f"vuln_{spec.name}",
    )


def _vuln_specialist_task(spec: VulnSpecialist, base_prompt: str) -> str:
    """Combine the shared per-run context with this specialist's focus."""
    return (
        f"{base_prompt}\n\n"
        f"You are the **{spec.name}** vulnerability-scan specialist.\n"
        f"Focus exclusively on: {spec.focus}.\n"
        "Use only your available tools (do not attempt anything outside your domain), "
        "be thorough, then produce a concise structured summary of your findings."
    )
