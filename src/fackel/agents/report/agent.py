"""Report specialist — LLM-based pentest report generation.

No tools needed: the LLM synthesises accumulated findings into a
professional Markdown report in a single call.
"""

from __future__ import annotations

import logging
from typing import Any, cast

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig

from fackel.agents.config import build_llm
from fackel.agents.prompts import load_prompt
from fackel.formatting import serialize_findings

logger = logging.getLogger(__name__)


def generate_report(
    target: str,
    active_scan: bool,
    findings: list[dict[str, Any]],
    unassessed_areas: list[dict[str, Any]] | None = None,
    phase_evaluations: list[dict[str, Any]] | None = None,
    risk_score: dict[str, Any] | None = None,
    model_name: str | None = None,
    config: RunnableConfig | None = None,
) -> str:
    """Render a Markdown pentest report from accumulated agent findings.

    Parameters
    ----------
    findings:
        List of ``Finding`` dicts with keys: phase, title, detail,
        (optional) severity, source_tool, confidence.
    phase_evaluations:
        LLM-as-a-judge quality assessments for active-scan phases.
        Each dict has: phase, completeness, score, key_findings, gaps, reasoning.
    risk_score:
        Exposure risk assessment: {score, exposure_type, factors}.
    config:
        Optional ``RunnableConfig`` for observability trace nesting.
    """
    llm = build_llm("report", model_name=model_name)

    context = serialize_findings(findings, include_severity=True)

    parts = [
        f"Target: {target}",
        f"Active scanning: {'enabled' if active_scan else 'disabled'}",
        f"\nAgent findings:\n\n{context}",
    ]

    if unassessed_areas:
        areas_text = "\n".join(
            f"- **{a['technology']}** (detected by {a['detected_by']}): "
            f"{a['reason']}. Recommendation: {a['recommendation']}"
            for a in unassessed_areas
        )
        parts.append(f"\nUnassessed Areas:\n\n{areas_text}")

    if phase_evaluations:
        eval_lines = []
        for ev in phase_evaluations:
            if not isinstance(ev, dict):
                continue  # type: ignore[unreachable]
            phase = ev.get("phase", "?")
            completeness = ev.get("completeness", "?")
            try:
                score = float(ev.get("score", 0))
            except (TypeError, ValueError):
                score = 0.0
            reasoning = ev.get("reasoning", "")
            gaps = ev.get("gaps", [])
            line = f"- **{phase}**: {completeness} (score: {score:.1f})"
            if reasoning:
                line += f" — {reasoning}"
            if gaps:
                line += f"\n  Gaps: {'; '.join(gaps)}"
            eval_lines.append(line)
        if eval_lines:
            parts.append(
                "\nPhase Quality Assessments (from automated judge):\n\n" + "\n".join(eval_lines)
            )

    if risk_score and isinstance(risk_score, dict):
        rs_score = risk_score.get("score", 0)
        rs_type = risk_score.get("exposure_type", "unknown")
        rs_factors = risk_score.get("factors", [])
        risk_lines = [
            f"\nExposure Risk Score: **{rs_score:.1f}/10** ({rs_type})",
        ]
        if rs_factors:
            risk_lines.append("Risk Factors:")
            for factor in rs_factors:
                risk_lines.append(f"- {factor}")
        parts.append("\n".join(risk_lines))

    try:
        response = llm.invoke(
            [
                SystemMessage(content=load_prompt("report")),
                HumanMessage(content="\n".join(parts)),
            ],
            config=config,
        )
        return cast(str, response.content)
    except Exception:
        logger.exception("Report LLM call failed — returning raw findings as fallback")
        return (
            f"# Penetration Test Report — {target}\n\n"
            "**Note:** The LLM report generation failed. "
            "Raw findings are included below for manual review.\n\n" + "\n\n---\n\n".join(parts)
        )
