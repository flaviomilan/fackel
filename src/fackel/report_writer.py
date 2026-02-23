"""Comprehensive Markdown report builder.

Assembles a detailed report from the full orchestrator state, including
verbatim phase summaries, quality evaluations, and the LLM-synthesized
executive report.  Unlike the LLM report (which is intentionally concise),
this output preserves **all** raw detail for archival and audit purposes.
"""

from __future__ import annotations

from datetime import datetime, timezone


def build_full_report(state: dict) -> str:
    """Build a comprehensive Markdown document from the completed scan state.

    Parameters
    ----------
    state:
        The final ``ScanState`` dict returned by the orchestrator.

    Returns
    -------
    str
        A Markdown string ready to be written to disk.
    """
    target = state.get("target", "unknown")
    active_scan = state.get("active_scan", False)
    ips = state.get("discovered_ips", [])
    subdomains = state.get("discovered_subdomains", [])
    findings: list[dict] = state.get("findings", [])
    evaluations: list[dict] = state.get("phase_evaluations", [])
    unassessed: list[dict] = state.get("unassessed_areas", [])
    llm_report: str = state.get("report", "")
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections: list[str] = []

    # ── Header ─────────────────────────────────────────────────────────
    sections.append(f"# Penetration Test Report — {target}\n")
    sections.append(f"| Field | Value |")
    sections.append(f"|-------|-------|")
    sections.append(f"| **Target** | `{target}` |")
    sections.append(f"| **Date** | {now} |")
    sections.append(f"| **Active Scan** | {'Yes' if active_scan else 'No'} |")
    sections.append(f"| **IPv4 Discovered** | {len([ip for ip in ips if ':' not in ip])} |")
    sections.append(f"| **IPv6 Discovered** | {len([ip for ip in ips if ':' in ip])} |")
    sections.append(f"| **Subdomains Discovered** | {len(subdomains)} |")
    sections.append("")

    # ── Table of Contents ──────────────────────────────────────────────
    sections.append("## Table of Contents\n")
    sections.append("1. [Executive Summary](#1-executive-summary)")
    sections.append("2. [Discovered Assets](#2-discovered-assets)")
    toc_idx = 3
    phase_order = ["osint", "port_scan", "vuln_scan", "triage"]
    phase_labels = {
        "osint": "OSINT",
        "port_scan": "Port Scan",
        "vuln_scan": "Vulnerability Scan",
        "triage": "Triage",
    }
    for phase in phase_order:
        phase_findings = [f for f in findings if f.get("phase") == phase]
        if phase_findings:
            label = phase_labels.get(phase, phase)
            anchor = f"{toc_idx}-{label.lower().replace(' ', '-')}"
            sections.append(f"{toc_idx}. [{label}](#{anchor})")
            toc_idx += 1
    if evaluations:
        sections.append(f"{toc_idx}. [Phase Quality Assessments](#{toc_idx}-phase-quality-assessments)")
        toc_idx += 1
    if unassessed:
        sections.append(f"{toc_idx}. [Unassessed Areas](#{toc_idx}-unassessed-areas)")
        toc_idx += 1
    sections.append(f"{toc_idx}. [Full LLM Report](#{toc_idx}-full-llm-report)")
    sections.append("")

    # ── 1. Executive Summary ───────────────────────────────────────────
    sections.append("---\n")
    sections.append("## 1. Executive Summary\n")
    # Extract the exec summary from the LLM report if possible.
    exec_summary = _extract_section(llm_report, "Executive Summary")
    if exec_summary:
        sections.append(exec_summary)
    else:
        sections.append(
            "The automated assessment covered OSINT reconnaissance"
            + (", active port scanning, and vulnerability scanning." if active_scan else ".")
            + f" A total of {len(findings)} phase findings were collected."
        )
    sections.append("")

    # ── 2. Discovered Assets ───────────────────────────────────────────
    sections.append("---\n")
    sections.append("## 2. Discovered Assets\n")
    sections.append("### IP Addresses\n")
    if ips:
        sections.append("| IP Address | Type |")
        sections.append("|------------|------|")
        for ip in ips:
            ip_type = "IPv6" if ":" in ip else "IPv4"
            sections.append(f"| `{ip}` | {ip_type} |")
    else:
        sections.append("_No IP addresses discovered._")
    sections.append("")

    sections.append("### Subdomains\n")
    if subdomains:
        for sub in subdomains:
            sections.append(f"- `{sub}`")
    else:
        sections.append("_No subdomains discovered._")
    sections.append("")

    # ── Phase findings (verbatim) ──────────────────────────────────────
    section_idx = 3
    for phase in phase_order:
        phase_findings = [f for f in findings if f.get("phase") == phase]
        if not phase_findings:
            continue

        label = phase_labels.get(phase, phase)
        sections.append("---\n")
        sections.append(f"## {section_idx}. {label}\n")

        for f in phase_findings:
            detail = f.get("detail", "No details available.")
            severity = f.get("severity", "")
            source = f.get("source_tool", "")

            meta_parts = []
            if severity:
                meta_parts.append(f"**Severity:** {severity}")
            if source:
                meta_parts.append(f"**Source:** {source}")
            if meta_parts:
                sections.append(" | ".join(meta_parts) + "\n")

            sections.append(detail)
            sections.append("")

        # Append evaluation inline if available for this phase.
        phase_eval = _find_evaluation(evaluations, phase)
        if phase_eval:
            sections.append(f"### {label} — Quality Assessment\n")
            sections.append(_format_evaluation(phase_eval))
            sections.append("")

        section_idx += 1

    # ── Phase Quality Assessments (collected) ──────────────────────────
    if evaluations:
        sections.append("---\n")
        sections.append(f"## {section_idx}. Phase Quality Assessments\n")
        sections.append(
            "| Phase | Completeness | Score | Recommendation |"
        )
        sections.append("|-------|-------------|-------|----------------|")
        for ev in evaluations:
            if not isinstance(ev, dict):
                continue
            phase = ev.get("phase", "?")
            completeness = ev.get("completeness", "?")
            score = ev.get("score", 0)
            rec = ev.get("recommendation", "?")
            sections.append(f"| {phase} | {completeness} | {score:.1f} | {rec} |")
        sections.append("")

        for ev in evaluations:
            if not isinstance(ev, dict):
                continue
            sections.append(f"### {ev.get('phase', '?')}\n")
            sections.append(_format_evaluation(ev))
            sections.append("")

        section_idx += 1

    # ── Unassessed Areas ───────────────────────────────────────────────
    if unassessed:
        sections.append("---\n")
        sections.append(f"## {section_idx}. Unassessed Areas\n")
        sections.append("| Technology | Detected By | Reason | Recommendation |")
        sections.append("|-----------|-------------|--------|----------------|")
        for area in unassessed:
            if not isinstance(area, dict):
                continue
            tech = area.get("technology", "?")
            detected = area.get("detected_by", "?")
            reason = area.get("reason", "")
            rec = area.get("recommendation", "")
            sections.append(f"| {tech} | {detected} | {reason} | {rec} |")
        sections.append("")
        section_idx += 1

    # ── Full LLM Report ────────────────────────────────────────────────
    sections.append("---\n")
    sections.append(f"## {section_idx}. Full LLM Report\n")
    sections.append(
        "> The section below is the complete report generated by the LLM "
        "from the accumulated findings.\n"
    )
    if llm_report.strip():
        sections.append(llm_report.strip())
    else:
        sections.append("_No LLM report was generated._")
    sections.append("")

    # ── Footer ─────────────────────────────────────────────────────────
    sections.append("---\n")
    sections.append(f"*Generated by Fackel on {now}*")

    return "\n".join(sections)


# ── Helpers ────────────────────────────────────────────────────────────────


def _extract_section(markdown: str, heading: str) -> str | None:
    """Extract content under a specific heading from markdown text."""
    lines = markdown.splitlines()
    capturing = False
    captured: list[str] = []

    for line in lines:
        stripped = line.strip()
        # Detect heading at any level
        if stripped.startswith("#") and heading.lower() in stripped.lower():
            capturing = True
            continue
        if capturing:
            # Stop at next heading of same or higher level
            if stripped.startswith("#"):
                break
            captured.append(line)

    text = "\n".join(captured).strip()
    return text if text else None


def _find_evaluation(evaluations: list[dict], phase: str) -> dict | None:
    """Find the latest evaluation dict for a given phase."""
    for ev in reversed(evaluations):
        if isinstance(ev, dict) and ev.get("phase") == phase:
            return ev
    return None


def _format_evaluation(ev: dict) -> str:
    """Render a single phase evaluation as Markdown."""
    parts: list[str] = []
    completeness = ev.get("completeness", "?")
    score = ev.get("score", 0)
    rec = ev.get("recommendation", "?")
    reasoning = ev.get("reasoning", "")
    gaps = ev.get("gaps", [])
    key_findings = ev.get("key_findings", [])

    parts.append(f"- **Completeness:** {completeness} (score: {score:.1f})")
    parts.append(f"- **Recommendation:** {rec}")

    if reasoning:
        parts.append(f"- **Reasoning:** {reasoning}")

    if key_findings:
        parts.append("- **Key findings:**")
        for kf in key_findings:
            parts.append(f"  - {kf}")

    if gaps:
        parts.append("- **Gaps identified:**")
        for gap in gaps:
            parts.append(f"  - {gap}")

    return "\n".join(parts)
