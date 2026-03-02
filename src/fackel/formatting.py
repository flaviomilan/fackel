"""Shared formatting helpers for agent findings and structured context.

Centralises findings-to-Markdown serialization and tech-fingerprint
formatting that was previously duplicated across ``report/agent.py``,
``triage/agent.py``, and ``orchestrator/nodes.py``.
"""

from __future__ import annotations

from typing import Any

PHASE_LABELS: dict[str, str] = {
    "osint": "OSINT",
    "approval": "Approval",
    "port_scan": "Port Scan",
    "vuln_scan": "Vulnerability Scan",
    "triage": "Triage",
    "report": "Report",
}

PHASE_ORDER: tuple[str, ...] = ("osint", "port_scan", "vuln_scan", "triage")
"""Canonical ordering of scan phases (excluding report)."""


def serialize_findings(
    findings: list[dict[str, Any]],
    *,
    include_severity: bool = False,
) -> str:
    """Convert a list of Finding dicts into Markdown sections.

    Parameters
    ----------
    findings:
        List of ``Finding`` dicts with keys: phase, title, detail,
        (optional) severity, source_tool, confidence.
    include_severity:
        When True, append a ``[severity: …]`` tag to the heading.
    """
    sections: list[str] = []
    for f in findings:
        if isinstance(f, dict):
            header = f.get("title", f.get("phase", "Finding"))
            detail = f.get("detail", "")
            if include_severity:
                sev = f.get("severity", "")
                sev_tag = f" [severity: {sev}]" if sev else ""
                sections.append(f"## {header}{sev_tag}\n\n{detail}")
            else:
                sections.append(f"## {header}\n\n{detail}")
        else:
            sections.append(str(f))  # type: ignore[unreachable]
    return "\n\n---\n\n".join(sections) if sections else "No findings collected."


def format_tech_fingerprint(fp: dict[str, Any], *, bold_host: bool = False) -> str:
    """Format a single tech fingerprint dict into a one-line summary.

    Parameters
    ----------
    fp:
        Dict with keys: host/target, server, technologies, cdn, waf.
    bold_host:
        Wrap the host in Markdown bold (``**host**``) for Markdown contexts.
    """
    host = fp.get("host", fp.get("target", "?"))
    server = fp.get("server", "")
    techs = fp.get("technologies", [])
    cdn = fp.get("cdn", False)
    waf = fp.get("waf", "")

    host_label = f"**{host}**" if bold_host else host
    line = f"- {host_label}: server={server or '?'}"
    if techs:
        line += f", tech=[{', '.join(str(t) for t in techs[:8])}]"
    if cdn:
        line += ", CDN=yes"
    if waf:
        line += f", WAF={waf}"
    return line


def find_evaluation(
    evaluations: list[dict[str, Any]],
    phase: str,
) -> dict[str, Any] | None:
    """Find the latest evaluation dict for a given phase (reverse search)."""
    for ev in reversed(evaluations):
        if isinstance(ev, dict) and ev.get("phase") == phase:
            return ev
    return None


def is_ipv6(ip: str) -> bool:
    """Return True if *ip* looks like an IPv6 address (contains a colon)."""
    return ":" in ip
