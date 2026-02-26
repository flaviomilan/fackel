"""Shared helpers for orchestrator graph nodes.

Contains utility functions used across multiple node modules:
target preparation, finding construction, and evaluation emission.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fackel.formatting import find_evaluation, is_ipv6

from .. import streaming
from ..state import Finding, ScanState

logger = logging.getLogger(__name__)

SUBDOMAIN_CAP = 30

DEFAULT_VULN_SCAN_STRATEGY = (
    "\nScan the DOMAIN first (nuclei with empty severity for full template "
    "coverage). Then scan the most interesting subdomains (www, web apps, "
    "APIs, panels). Then per-IP checks. Prioritise breadth — it's better "
    "to scan more targets shallowly than fewer targets deeply."
)

IP_CLASS_HINTS: dict[str, str] = {
    "cdn": " → CDN proxy, skip deep scanning (ports are the CDN's, not the origin)",
    "cloud": " → cloud-hosted, scan normally",
    "direct_host": " → direct infrastructure, HIGH PRIORITY",
}


def make_finding(
    phase: str,
    title: str,
    detail: str,
    *,
    severity: Literal["critical", "high", "medium", "low", "info"] = "info",
    source_tool: str = "",
    confidence: float = 1.0,
) -> Finding:
    """Build a typed ``Finding`` dict."""
    return Finding(
        phase=phase,
        title=title,
        detail=detail,
        severity=severity,
        source_tool=source_tool,
        confidence=confidence,
    )


def get_phase_evaluation(state: ScanState, phase: str) -> dict[str, Any] | None:
    """Retrieve the latest LLM-as-a-judge evaluation for *phase* from state."""
    return find_evaluation(state.get("phase_evaluations", []), phase)


def prepare_scan_targets(state: ScanState) -> tuple[list[str], list[str]]:
    """Filter IPv6 addresses and return ``(ipv4_ips, subdomains)``."""
    all_ips = state.get("discovered_ips", [])
    ips = [ip for ip in all_ips if not is_ipv6(ip)]
    dropped = len(all_ips) - len(ips)
    if dropped:
        logger.info("dropping %d IPv6 address(es) — not yet supported", dropped)
    subdomains = state.get("discovered_subdomains", [])
    return ips, subdomains


def emit_evaluation(phase: str, evaluation: Any) -> None:
    """Emit a quality-evaluation event for *phase*."""
    streaming.emit(
        phase,
        "evaluation",
        {
            "score": evaluation.score,
            "completeness": evaluation.completeness,
            "recommendation": evaluation.recommendation,
        },
    )
