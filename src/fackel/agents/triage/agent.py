"""Triage specialist — analyses scan findings to identify coverage gaps.

Uses structured output to produce a typed assessment of detected technologies
and areas that could not be evaluated due to missing specialist agents.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt

logger = logging.getLogger(__name__)


class UnassessedArea(BaseModel):
    """A technology or attack surface detected but not covered by any specialist."""

    technology: str = Field(description="Name and version of the detected technology")
    detected_by: str = Field(description="Which tool/template detected it")
    reason: str = Field(description="Why this area needs specialist analysis")
    recommendation: str = Field(description="What a manual audit should focus on")


class RiskScore(BaseModel):
    """Quantitative exposure risk score with evidence-backed reasoning."""

    score: float = Field(ge=0.0, le=10.0, description="Overall risk score 0-10")
    exposure_type: Literal["critical", "high", "moderate", "low", "minimal"] = Field(
        description="Risk classification derived from score"
    )
    factors: list[str] = Field(
        default_factory=list,
        description="Evidence-backed reasons contributing to the score",
    )


class TriageResult(BaseModel):
    """Structured output from the triage analysis."""

    technologies_detected: list[str] = Field(
        description="All technologies identified across all findings"
    )
    unassessed_areas: list[UnassessedArea] = Field(
        default_factory=list,
        description="Technologies detected but not covered by available specialists",
    )
    risk_score: RiskScore = Field(
        description="Quantitative exposure risk assessment with evidence",
    )
    summary: str = Field(description="Brief overall assessment of scan coverage")


def run_triage(
    findings: list[dict[str, Any]],
    *,
    ip_classifications: list[dict[str, Any]] | None = None,
    tech_fingerprints: list[dict[str, Any]] | None = None,
    phase_evaluations: list[dict[str, Any]] | None = None,
    model_name: str | None = None,
) -> TriageResult:
    """Analyse accumulated findings and return a structured triage result.

    Parameters
    ----------
    findings:
        List of ``Finding`` dicts with keys: phase, title, detail,
        (optional) severity, source_tool, confidence.
    ip_classifications:
        Per-IP infrastructure classification (cdn / cloud / direct_host / isp).
    tech_fingerprints:
        HTTP tech fingerprints per target (server, technologies, CDN, WAF).
    phase_evaluations:
        LLM-as-a-judge quality assessments from prior phases.
    """
    llm = ChatOpenAI(model=model_name or get_model("triage"))
    structured_llm = llm.with_structured_output(TriageResult)

    # Serialise structured findings into text for the LLM.
    context = _serialize_findings(findings)

    # Append structured state context for evidence-backed risk scoring.
    structured_sections = _serialize_structured_context(
        ip_classifications=ip_classifications or [],
        tech_fingerprints=tech_fingerprints or [],
        phase_evaluations=phase_evaluations or [],
    )
    if structured_sections:
        context = f"{context}\n\n---\n\n{structured_sections}"

    try:
        return structured_llm.invoke(
            [
                SystemMessage(content=load_prompt("triage")),
                HumanMessage(content=f"Analyse these scan findings:\n\n{context}"),
            ]
        )
    except Exception:
        logger.exception("Triage LLM call failed — returning fallback result")
        return TriageResult(
            technologies_detected=[],
            unassessed_areas=[],
            risk_score=RiskScore(
                score=0.0,
                exposure_type="minimal",
                factors=["Triage analysis failed — score unavailable"],
            ),
            summary="Triage analysis could not be completed due to an LLM error. "
            "Review the raw findings manually.",
        )


def _serialize_findings(findings: list[dict[str, Any]]) -> str:
    """Convert a list of Finding dicts into Markdown sections for the LLM."""
    sections: list[str] = []
    for f in findings:
        if isinstance(f, dict):
            header = f.get("title", f.get("phase", "Finding"))
            detail = f.get("detail", "")
            sections.append(f"## {header}\n\n{detail}")
        else:
            sections.append(str(f))
    return "\n\n---\n\n".join(sections) if sections else "No findings collected."


def _serialize_structured_context(
    *,
    ip_classifications: list[dict[str, Any]],
    tech_fingerprints: list[dict[str, Any]],
    phase_evaluations: list[dict[str, Any]],
) -> str:
    """Serialize structured state data into Markdown for the triage LLM.

    This gives the triage agent access to machine-readable data that may
    not appear verbatim in the textual findings — enabling evidence-backed
    risk scoring.
    """
    parts: list[str] = []

    if ip_classifications:
        lines = ["## IP Infrastructure Classification\n"]
        for c in ip_classifications:
            ip = c.get("ip", "?")
            ip_class = c.get("ip_class", "unknown")
            org = c.get("org", "")
            anycast = c.get("anycast", False)
            line = f"- **{ip}**: class={ip_class}, org={org}"
            if anycast:
                line += ", anycast=yes"
            lines.append(line)
        parts.append("\n".join(lines))

    if tech_fingerprints:
        lines = ["## Technology Fingerprints\n"]
        for fp in tech_fingerprints[:10]:
            host = fp.get("host", fp.get("target", "?"))
            server = fp.get("server", "")
            techs = fp.get("technologies", [])
            cdn = fp.get("cdn", False)
            waf = fp.get("waf", "")
            line = f"- **{host}**: server={server or '?'}"
            if techs:
                line += f", tech=[{', '.join(str(t) for t in techs[:8])}]"
            if cdn:
                line += ", CDN=yes"
            if waf:
                line += f", WAF={waf}"
            lines.append(line)
        parts.append("\n".join(lines))

    if phase_evaluations:
        lines = ["## Phase Quality Evaluations\n"]
        for ev in phase_evaluations:
            if not isinstance(ev, dict):
                continue
            phase = ev.get("phase", "?")
            completeness = ev.get("completeness", "?")
            score = ev.get("score", 0)
            gaps = ev.get("gaps", [])
            line = f"- **{phase}**: {completeness} (score: {score:.1f})"
            if gaps:
                line += f" — gaps: {'; '.join(gaps)}"
            lines.append(line)
        parts.append("\n".join(lines))

    return "\n\n---\n\n".join(parts)
