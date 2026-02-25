"""Phase output evaluator — LLM-as-a-judge for quality-gated routing.

After each active-scan phase, a lightweight structured LLM call evaluates
the agent's output.  The resulting ``PhaseEvaluation`` drives:

- **Routing** — skip or adapt downstream phases when data is insufficient.
- **Context enrichment** — pass quality signals to the next agent.
- **Report honesty** — surface gaps and limitations in the final report.
"""

from __future__ import annotations

import logging
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from fackel.agents.config import get_model
from fackel.agents.prompts import load_prompt

logger = logging.getLogger(__name__)


class PhaseEvaluation(BaseModel):
    """Structured quality assessment of a scan phase's output."""

    phase: str = Field(description="Phase evaluated (e.g. port_scan, vuln_scan)")
    completeness: Literal["complete", "partial", "empty"] = Field(
        description=(
            "Coverage level: complete (all targets covered), "
            "partial (some gaps), empty (no meaningful data)"
        ),
    )
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="Quality score: 0.0 (no useful output) to 1.0 (thorough coverage)",
    )
    key_findings: list[str] = Field(
        default_factory=list,
        description="Brief factual bullets of the most important discoveries",
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="Actionable items that are missing or incomplete",
    )
    recommendation: Literal["proceed", "adapt", "skip_downstream"] = Field(
        description="Routing advice for the next phase",
    )
    reasoning: str = Field(
        description="One-paragraph explanation of the assessment",
    )


def _fallback_evaluation(phase: str, reason: str) -> PhaseEvaluation:
    """Return a safe default when the judge LLM call fails."""
    return PhaseEvaluation(
        phase=phase,
        completeness="partial",
        score=0.5,
        key_findings=[],
        gaps=[reason],
        recommendation="proceed",
        reasoning=f"Evaluation unavailable: {reason}. Proceeding with default routing.",
    )


def evaluate_phase(
    phase: str,
    agent_summary: str,
    targets: list[str],
    *,
    model_name: str | None = None,
) -> PhaseEvaluation:
    """Evaluate a phase's output quality via LLM-as-a-judge.

    Returns a structured ``PhaseEvaluation`` that downstream nodes and
    routing functions use to adapt the pipeline.  Never raises — returns
    a safe fallback on any LLM failure.
    """
    try:
        llm = ChatOpenAI(
            model=model_name or get_model("judge"),
            temperature=0,
        )
        structured_llm = llm.with_structured_output(PhaseEvaluation)

        context = (
            f"Phase: {phase}\n"
            f"Targets: {', '.join(targets) if targets else 'none'}\n\n"
            f"Agent output:\n{agent_summary}"
        )

        result = structured_llm.invoke(
            [
                SystemMessage(content=load_prompt("judge")),
                HumanMessage(content=context),
            ]
        )
        logger.info(
            "judge: %s → %s (score=%.1f, rec=%s)",
            phase,
            result.completeness,
            result.score,
            result.recommendation,
        )
        return result
    except Exception:
        logger.warning(
            "judge: evaluation failed for %s — using fallback",
            phase,
            exc_info=True,
        )
        return _fallback_evaluation(phase, "LLM evaluation call failed")
