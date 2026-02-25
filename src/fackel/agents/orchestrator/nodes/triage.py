"""Triage graph node — structured analysis of coverage gaps and risk scoring."""

from __future__ import annotations

from typing import Any

from langchain_core.runnables import RunnableConfig

from .. import streaming
from ..state import ScanState
from ._helpers import make_finding


def triage_node(state: ScanState, config: RunnableConfig) -> dict[str, Any]:
    """Analyse findings and identify unassessed areas via structured LLM output.

    Passes structured state context (IP classifications, tech fingerprints,
    phase evaluations) alongside textual findings so the triage LLM can
    produce evidence-backed risk scores from machine-readable data.
    """
    from fackel.agents.triage.agent import run_triage

    streaming.emit("triage", "start", {})
    result = run_triage(
        state.get("findings", []),  # type: ignore[arg-type]
        ip_classifications=state.get("ip_classifications", []),
        tech_fingerprints=state.get("tech_fingerprints", []),
        phase_evaluations=state.get("phase_evaluations", []),
        config=config,
    )
    return _build_triage_result(result)


def _build_triage_result(result: Any) -> dict[str, Any]:
    """Build state update from triage analysis result."""
    unassessed = [
        {
            "technology": area.technology,
            "detected_by": area.detected_by,
            "reason": area.reason,
            "recommendation": area.recommendation,
        }
        for area in result.unassessed_areas
    ]

    risk = result.risk_score
    risk_dict = {
        "score": risk.score,
        "exposure_type": risk.exposure_type,
        "factors": list(risk.factors),
    }

    triage_detail = _format_triage_summary(result, risk, unassessed)
    streaming.emit("triage", "summary", {"content": triage_detail})
    streaming.emit(
        "triage",
        "done",
        {
            "technologies": result.technologies_detected,
            "unassessed_count": len(unassessed),
            "risk_score": risk.score,
            "risk_exposure_type": risk.exposure_type,
        },
    )

    return {
        "findings": [make_finding("triage", "Triage Summary", triage_detail)],
        "unassessed_areas": unassessed,
        "risk_score": risk_dict,
    }


def _format_triage_summary(result: Any, risk: Any, unassessed: list[dict[str, Any]]) -> str:
    """Format the triage summary as Markdown."""
    parts = [f"## Triage Summary\n\n{result.summary}"]
    parts.append(f"\n**Risk Score:** {risk.score:.1f}/10 ({risk.exposure_type})")
    if risk.factors:
        parts.append("\n**Risk Factors:**\n" + "\n".join(f"- {f}" for f in risk.factors))
    if result.technologies_detected:
        techs = ", ".join(result.technologies_detected)
        parts.append(f"\n**Technologies detected:** {techs}")
    if unassessed:
        names = ", ".join(a["technology"] for a in unassessed)
        parts.append(f"\n**Unassessed areas:** {names}")
    return "\n".join(parts)
