"""ScanState — typed shared context for the orchestrator graph.

Findings are structured dicts (not free-text) so downstream consumers
(report, triage, API, scoring) can process them deterministically.
"""

from __future__ import annotations

from operator import add
from typing import Annotated, Any, Literal

from typing_extensions import TypedDict


class Finding(TypedDict, total=False):
    """A single structured finding produced by an agent phase.

    Required keys: phase, title, detail.
    Optional keys carry machine-readable metadata for scoring / filtering.
    """

    phase: str
    """Which agent produced this finding (osint, port_scan, vuln_scan, triage)."""

    title: str
    """Short human-readable label (e.g. "Port Scan Summary")."""

    detail: str
    """Full Markdown content — the agent's analysis text."""

    severity: Literal["critical", "high", "medium", "low", "info"]
    """Overall severity: critical | high | medium | low | info."""

    source_tool: str
    """Primary tool that produced the data (e.g. "nuclei_scan")."""

    confidence: float
    """0.0 - 1.0.  How confident the agent is in this finding."""


class ScanState(TypedDict):
    target: str
    """Original target (domain or IP) provided by the user."""

    active_scan: bool
    """Whether active scanning phases are permitted."""

    discovered_ips: list[str]
    """IP addresses discovered during OSINT (fed into port_scan)."""

    discovered_subdomains: list[str]
    """Subdomains discovered during OSINT (fed into port_scan and vuln_scan)."""

    findings: Annotated[list[Finding], add]
    """Structured findings accumulated across phases (append-only reducer)."""

    unassessed_areas: Annotated[list[dict[str, Any]], add]
    """Technologies/opportunities detected but not covered by any specialist."""

    phase_evaluations: Annotated[list[dict[str, Any]], add]
    """LLM-as-a-judge quality assessments accumulated after each active phase."""

    ip_classifications: Annotated[list[dict[str, Any]], add]
    """Per-IP infrastructure classification (cdn / cloud / direct_host / isp)."""

    tech_fingerprints: Annotated[list[dict[str, Any]], add]
    """HTTP tech fingerprints per target (server, technologies, CDN, WAF)."""

    risk_score: dict
    """Exposure risk score: {score, exposure_type, factors}."""

    report: str
    """Final rendered Markdown report."""
