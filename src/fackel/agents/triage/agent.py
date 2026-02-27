"""Triage specialist — analyses scan findings to identify coverage gaps.

Uses ``create_agent`` with ``response_format`` to produce a typed assessment
of detected technologies and areas that could not be evaluated due to
missing specialist agents.  The structured output is returned via the
agent's ``structured_response`` state key.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field

from fackel.agents.config import build_llm
from fackel.agents.prompts import load_prompt, load_template
from fackel.formatting import format_tech_fingerprint, serialize_findings

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


def build(model_name: str | None = None) -> CompiledStateGraph:  # type: ignore[type-arg]
    """Return a compiled triage agent with ``response_format=TriageResult``.

    The agent has no tools — it performs a single structured LLM call to
    analyse accumulated findings and produce a typed assessment.
    """
    llm = build_llm("triage", model_name=model_name)
    return create_agent(
        llm,
        [],
        system_prompt=load_prompt("triage"),
        response_format=TriageResult,
        name="triage",
    )


def run_triage(
    findings: list[dict[str, Any]],
    *,
    ip_classifications: list[dict[str, Any]] | None = None,
    tech_fingerprints: list[dict[str, Any]] | None = None,
    phase_evaluations: list[dict[str, Any]] | None = None,
    model_name: str | None = None,
    config: RunnableConfig | None = None,
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
    config:
        Optional ``RunnableConfig`` for observability trace nesting.
    """
    agent = build(model_name)

    context = _serialize_findings(findings)

    structured_sections = _serialize_structured_context(
        ip_classifications=ip_classifications or [],
        tech_fingerprints=tech_fingerprints or [],
        phase_evaluations=phase_evaluations or [],
    )
    if structured_sections:
        context = f"{context}\n\n---\n\n{structured_sections}"

    try:
        result = agent.invoke(
            {
                "messages": [
                    HumanMessage(content=load_template("triage_task").format(context=context))
                ]
            },
            config=config,
        )
        structured: TriageResult | None = result.get("structured_response")
        if structured is None:
            logger.warning("Triage agent returned no structured_response — using fallback")
            return _fallback_result("No structured response returned by agent.")
        return structured
    except Exception:
        logger.exception("Triage LLM call failed — returning fallback result")
        return _fallback_result(
            "Triage analysis could not be completed due to an LLM error. "
            "Review the raw findings manually.",
        )


def _fallback_result(summary: str) -> TriageResult:
    """Build a minimal TriageResult when the LLM call fails."""
    return TriageResult(
        technologies_detected=[],
        unassessed_areas=[],
        risk_score=RiskScore(
            score=0.0,
            exposure_type="minimal",
            factors=["Triage analysis failed — score unavailable"],
        ),
        summary=summary,
    )


def _serialize_findings(findings: list[dict[str, Any]]) -> str:
    """Convert a list of Finding dicts into Markdown sections for the LLM."""
    return serialize_findings(findings)


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
            lines.append(format_tech_fingerprint(fp, bold_host=True))
        parts.append("\n".join(lines))

    if phase_evaluations:
        lines = ["## Phase Quality Evaluations\n"]
        for ev in phase_evaluations:
            if not isinstance(ev, dict):
                continue  # type: ignore[unreachable]
            phase = ev.get("phase", "?")
            completeness = ev.get("completeness", "?")
            try:
                score = float(ev.get("score", 0))
            except (TypeError, ValueError):
                score = 0.0
            gaps = ev.get("gaps", [])
            line = f"- **{phase}**: {completeness} (score: {score:.1f})"
            if gaps:
                line += f" — gaps: {'; '.join(gaps)}"
            lines.append(line)
        parts.append("\n".join(lines))

    return "\n\n---\n\n".join(parts)
