"""Shared helpers for orchestrator graph nodes.

Contains utility functions used across multiple node modules:
target preparation, finding construction, and evaluation emission.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fackel.agents.prompts import load_template
from fackel.formatting import find_evaluation, is_ipv6

from .. import streaming
from ..state import Finding, ScanState

logger = logging.getLogger(__name__)

SUBDOMAIN_CAP = 30


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


def get_phase_guidance(state: ScanState, phase: str) -> str:
    """Return operator guidance for *phase*, or empty string if none."""
    return (state.get("phase_guidance") or {}).get(phase, "")


def append_guidance(parts: list[str], guidance: str) -> None:
    """Append operator guidance to prompt parts if non-empty."""
    if guidance:
        parts.append("\n" + load_template("guidance_suffix").format(guidance=guidance))


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
