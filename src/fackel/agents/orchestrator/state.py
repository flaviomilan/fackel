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


def _finding_fingerprint(f: Finding) -> str:
    """Stable fingerprint for deduplication: phase + title + detail prefix."""
    return f"{f.get('phase', '')}:{f.get('title', '')}:{f.get('detail', '')[:120]}"


def merge_findings(old: list[Finding], new: list[Finding]) -> list[Finding]:
    """Append-with-dedup reducer for findings.

    Merges *new* into *old*, skipping entries whose fingerprint
    (``phase:title:detail[:120]``) already exists.  Later duplicates with a
    higher severity or confidence silently win via replacement.
    """
    seen: dict[str, int] = {}
    merged = list(old)
    for idx, f in enumerate(merged):
        seen[_finding_fingerprint(f)] = idx

    for f in new:
        fp = _finding_fingerprint(f)
        if fp in seen:
            # Keep the version with higher severity/confidence
            existing = merged[seen[fp]]
            if f.get("confidence", 0.0) > existing.get("confidence", 0.0):
                merged[seen[fp]] = f
        else:
            seen[fp] = len(merged)
            merged.append(f)
    return merged


class ScanState(TypedDict):
    scan_id: str
    """Scan correlation id; set on the result by ``run`` (not an input channel)."""

    target: str
    """Original target (domain or IP) provided by the user."""

    active_scan: bool
    """Whether active scanning phases are permitted."""

    discovered_ips: list[str]
    """IP addresses discovered during OSINT (fed into port_scan)."""

    discovered_subdomains: list[str]
    """Subdomains discovered during OSINT (fed into port_scan and vuln_scan)."""

    findings: Annotated[list[Finding], merge_findings]
    """Structured findings accumulated across phases (dedup-merge reducer)."""

    unassessed_areas: Annotated[list[dict[str, Any]], add]
    """Technologies/opportunities detected but not covered by any specialist."""

    phase_evaluations: Annotated[list[dict[str, Any]], add]
    """LLM-as-a-judge quality assessments accumulated after each active phase.

    Append-only history: phases that retry append a new evaluation entry
    rather than overwriting the previous one.  **Always** read this list
    via :func:`fackel.formatting.find_evaluation` (or the convenience
    wrapper :func:`.nodes._helpers.get_phase_evaluation`) so callers
    transparently get the latest entry for a given phase.  Never index
    by position — the order across phases is not guaranteed.
    """

    ip_classifications: Annotated[list[dict[str, Any]], add]
    """Per-IP infrastructure classification (cdn / cloud / direct_host / isp)."""

    tech_fingerprints: Annotated[list[dict[str, Any]], add]
    """HTTP tech fingerprints per target (server, technologies, CDN, WAF)."""

    osint_messages: Annotated[list[Any], add]
    """Fan-in channel: each parallel OSINT specialist node appends its message
    log here (``Send`` map-reduce); the ``osint_collect`` node consumes the union."""

    vuln_messages: Annotated[list[Any], add]
    """Fan-in channel: each parallel vuln-scan specialist node appends its message
    log here (``Send`` map-reduce); the ``vuln_collect`` node consumes the union."""

    vuln_base_prompt: str
    """Per-run vuln-scan context (targets, fingerprints, port-scan strategy) built
    once by ``vuln_dispatch`` and passed to each parallel specialist."""

    risk_score: dict[str, Any]
    """Exposure risk score: {score, exposure_type, factors}."""

    report: str
    """Final rendered Markdown report."""

    asset_inventory: str
    """Deterministic, complete Markdown inventory of every discovered record
    (built from the knowledge graph by the report node; appended to the
    archival report so no discovered data is lost)."""
